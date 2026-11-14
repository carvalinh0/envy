//! Secret storage.
//!
//! [`SecretVault`] is the abstraction the rest of the program depends on. A value keeps its
//! previous versions so it can be rolled back. Production uses [`KeyringVault`] (the
//! operating system keyring); tests and tooling can use [`MemoryVault`]. Both hold flat
//! entries through [`CredentialStore`] and therefore share one layout:
//!
//! | Entry | Namespace | User |
//! | :-- | :-- | :-- |
//! | Active value | [`Namespace::Values`] (service `envy`) | `{project}/{environment}/{key}` |
//! | Older version `n` | [`Namespace::History`] (service `envy-history`) | `{project}/{environment}/{key}#{n}` |
//! | Index of versions | [`Namespace::History`] | `{project}/{environment}/{key}#index` |
//!
//! The active value is the entry every release before the history wrote, so older binaries
//! keep reading and writing it. They do not know the index: a value they overwrite keeps
//! the date of the version it replaced, and a value they delete leaves its versions behind,
//! which a later `envy rollback` can restore. A version user always ends in `#` followed
//! by digits and the index in `#index`, so neither is mistaken for the other even when a
//! variable name contains `#`.

#[cfg(test)]
pub(crate) mod conformance;
mod file;

pub use file::EncryptedFileVault;

use std::{collections::HashMap, sync::Mutex};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::schema::Secret;

/// Versions kept when the manifest does not say otherwise (`"history": {"keep": 5}`).
pub const DEFAULT_KEEP: usize = 5;
/// The index of versions is one keyring entry, and the Windows Credential Manager limits an
/// entry to 2560 bytes; 20 versions stay far below it.
pub const MAX_KEEP: usize = 20;

/// Where a flat entry lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    Values,
    History,
}

/// Flat `namespace + user -> value` storage, the shape of an operating system keyring.
pub trait CredentialStore {
    fn read(&self, namespace: Namespace, user: &str) -> Result<Option<Secret>>;
    fn write(&self, namespace: Namespace, user: &str, value: &Secret) -> Result<()>;
    /// Returns `true` when something was actually removed.
    fn remove(&self, namespace: Namespace, user: &str) -> Result<bool>;
}

/// One stored value of a variable. Values are read with [`SecretVault::get_version`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub number: u32,
    /// Unknown for a value written by a release without history.
    pub created_at: Option<DateTime<Utc>>,
    pub active: bool,
}

/// How a write is recorded: when it happened and how many older versions survive it.
#[derive(Debug, Clone, Copy)]
pub struct Change {
    pub at: DateTime<Utc>,
    pub keep: usize,
}

/// Identifies one stored value: `(project id, environment, variable)`.
pub trait SecretVault {
    /// The active value.
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>>;
    /// Makes `value` the active one. The value it replaces becomes a version, and only the
    /// newest `change.keep` versions are kept (`0` keeps none).
    fn set(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        value: &Secret,
        change: Change,
    ) -> Result<()>;
    /// Removes the active value and every version. Returns `true` when an active value
    /// was removed.
    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool>;
    /// The active version first (when there is one), then the older ones, newest first.
    fn history(&self, project: &str, environment: &str, key: &str) -> Result<Vec<Version>>;
    fn get_version(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        number: u32,
    ) -> Result<Option<Secret>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    n: u32,
    /// Unix seconds. Short field names keep the index small (see [`MAX_KEEP`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    /// Stamp of the active value, when it was written by a release with history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<Stamp>,
    /// Older versions, newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    previous: Vec<Stamp>,
}

impl Index {
    fn next_number(&self) -> u32 {
        self.current
            .iter()
            .chain(&self.previous)
            .map(|stamp| stamp.n)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// The stamp of the active value; a value without one gets the next free number.
    fn active_stamp(&self) -> Stamp {
        self.current.unwrap_or(Stamp {
            n: self.next_number(),
            at: None,
        })
    }
}

fn slot(project: &str, environment: &str, key: &str) -> String {
    format!("{project}/{environment}/{key}")
}

fn version_user(slot: &str, number: u32) -> String {
    format!("{slot}#{number}")
}

fn index_user(slot: &str) -> String {
    format!("{slot}#index")
}

fn read_index<S: CredentialStore + ?Sized>(store: &S, slot: &str) -> Result<Index> {
    match store.read(Namespace::History, &index_user(slot))? {
        Some(raw) => serde_json::from_str(raw.expose_secret())
            .with_context(|| format!("The history index of '{slot}' is corrupted")),
        None => Ok(Index::default()),
    }
}

fn write_index<S: CredentialStore + ?Sized>(store: &S, slot: &str, index: &Index) -> Result<()> {
    let raw = Secret::new(serde_json::to_string(index)?);
    store.write(Namespace::History, &index_user(slot), &raw)
}

fn to_version(stamp: Stamp, active: bool) -> Version {
    Version {
        number: stamp.n,
        created_at: stamp.at.and_then(|at| DateTime::from_timestamp(at, 0)),
        active,
    }
}

/// Every [`CredentialStore`] is a vault with history. The writes are ordered so that an
/// interruption can duplicate a version but never lose one: the replaced value is archived
/// and the index updated before the active value is overwritten.
impl<S: CredentialStore> SecretVault for S {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>> {
        self.read(Namespace::Values, &slot(project, environment, key))
    }

    fn set(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        value: &Secret,
        change: Change,
    ) -> Result<()> {
        let slot = slot(project, environment, key);
        let mut index = read_index(self, &slot)?;

        if change.keep > 0
            && let Some(replaced) = self.read(Namespace::Values, &slot)?
        {
            let stamp = index.active_stamp();
            self.write(Namespace::History, &version_user(&slot, stamp.n), &replaced)?;
            index.previous.insert(0, stamp);
        }
        index.current = Some(Stamp {
            n: index.next_number(),
            at: Some(change.at.timestamp()),
        });
        let dropped = index
            .previous
            .split_off(change.keep.min(index.previous.len()));

        write_index(self, &slot, &index)?;
        self.write(Namespace::Values, &slot, value)?;
        for stamp in dropped {
            self.remove(Namespace::History, &version_user(&slot, stamp.n))?;
        }
        Ok(())
    }

    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool> {
        let slot = slot(project, environment, key);
        let removed = self.remove(Namespace::Values, &slot)?;
        for stamp in read_index(self, &slot)?.previous {
            self.remove(Namespace::History, &version_user(&slot, stamp.n))?;
        }
        self.remove(Namespace::History, &index_user(&slot))?;
        Ok(removed)
    }

    fn history(&self, project: &str, environment: &str, key: &str) -> Result<Vec<Version>> {
        let slot = slot(project, environment, key);
        let index = read_index(self, &slot)?;
        let mut versions = Vec::with_capacity(index.previous.len() + 1);
        if self.read(Namespace::Values, &slot)?.is_some() {
            versions.push(to_version(index.active_stamp(), true));
        }
        versions.extend(index.previous.iter().map(|stamp| to_version(*stamp, false)));
        Ok(versions)
    }

    fn get_version(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        number: u32,
    ) -> Result<Option<Secret>> {
        let slot = slot(project, environment, key);
        let index = read_index(self, &slot)?;
        if index.active_stamp().n == number {
            return self.read(Namespace::Values, &slot);
        }
        if index.previous.iter().any(|stamp| stamp.n == number) {
            return self.read(Namespace::History, &version_user(&slot, number));
        }
        Ok(None)
    }
}

/// Vault backed by the operating system keyring (Secret Service, Keychain, Credential Manager).
pub struct KeyringVault {
    service: String,
}

impl KeyringVault {
    pub const DEFAULT_SERVICE: &'static str = "envy";

    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn service(&self, namespace: Namespace) -> String {
        match namespace {
            Namespace::Values => self.service.clone(),
            Namespace::History => format!("{}-history", self.service),
        }
    }

    fn entry(&self, namespace: Namespace, user: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service(namespace), user)
            .context("Could not access the OS keyring")
    }
}

impl Default for KeyringVault {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SERVICE)
    }
}

impl CredentialStore for KeyringVault {
    fn read(&self, namespace: Namespace, user: &str) -> Result<Option<Secret>> {
        match self.entry(namespace, user)?.get_password() {
            Ok(value) => Ok(Some(Secret::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err).context(format!("Could not read '{user}' from the OS keyring")),
        }
    }

    fn write(&self, namespace: Namespace, user: &str, value: &Secret) -> Result<()> {
        self.entry(namespace, user)?
            .set_password(value.expose_secret())
            .context(format!("Could not store '{user}' in the OS keyring"))
    }

    fn remove(&self, namespace: Namespace, user: &str) -> Result<bool> {
        match self.entry(namespace, user)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(err).context(format!("Could not remove '{user}' from the OS keyring")),
        }
    }
}

/// Stands in for a backend this build does not have yet (`--backend file`). Commands that
/// never touch a value (`version`, `update`, `diff`, ...) keep working; the others fail
/// with a clear message instead of silently falling back to another backend.
pub struct UnavailableVault {
    pub backend: &'static str,
}

impl UnavailableVault {
    fn fail<T>(&self) -> Result<T> {
        anyhow::bail!(
            "The {} backend is not available in this version of Envy. Use the keyring (the default).",
            self.backend
        )
    }
}

impl SecretVault for UnavailableVault {
    fn get(&self, _: &str, _: &str, _: &str) -> Result<Option<Secret>> {
        self.fail()
    }

    fn set(&self, _: &str, _: &str, _: &str, _: &Secret, _: Change) -> Result<()> {
        self.fail()
    }

    fn delete(&self, _: &str, _: &str, _: &str) -> Result<bool> {
        self.fail()
    }

    fn history(&self, _: &str, _: &str, _: &str) -> Result<Vec<Version>> {
        self.fail()
    }

    fn get_version(&self, _: &str, _: &str, _: &str, _: u32) -> Result<Option<Secret>> {
        self.fail()
    }
}

/// Volatile vault. Nothing is persisted; values are wiped when dropped.
#[derive(Default)]
pub struct MemoryVault {
    entries: Mutex<HashMap<(Namespace, String), Secret>>,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of active values (versions are not counted).
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().expect("vault lock");
        entries
            .keys()
            .filter(|(namespace, _)| *namespace == Namespace::Values)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CredentialStore for MemoryVault {
    fn read(&self, namespace: Namespace, user: &str) -> Result<Option<Secret>> {
        let entries = self.entries.lock().expect("vault lock");
        Ok(entries.get(&(namespace, user.to_string())).cloned())
    }

    fn write(&self, namespace: Namespace, user: &str, value: &Secret) -> Result<()> {
        let mut entries = self.entries.lock().expect("vault lock");
        entries.insert((namespace, user.to_string()), value.clone());
        Ok(())
    }

    fn remove(&self, namespace: Namespace, user: &str) -> Result<bool> {
        let mut entries = self.entries.lock().expect("vault lock");
        Ok(entries.remove(&(namespace, user.to_string())).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_vault_passes_the_conformance_suite() {
        conformance::run(MemoryVault::new);
    }

    fn change(seconds: i64) -> Change {
        Change {
            at: DateTime::from_timestamp(seconds, 0).unwrap(),
            keep: DEFAULT_KEEP,
        }
    }

    /// What every release before the history did: one entry, no index.
    fn legacy_write(vault: &MemoryVault, value: &str) {
        vault
            .write(Namespace::Values, "p/dev/K", &Secret::new(value))
            .unwrap();
    }

    fn value_of(vault: &MemoryVault, number: u32) -> Option<String> {
        vault
            .get_version("p", "dev", "K", number)
            .unwrap()
            .map(|s| s.expose_secret().to_string())
    }

    #[test]
    fn a_value_from_an_older_release_is_read_and_becomes_version_1() {
        let vault = MemoryVault::new();
        legacy_write(&vault, "legacy");
        assert_eq!(
            vault.get("p", "dev", "K").unwrap().unwrap().expose_secret(),
            "legacy"
        );
        assert_eq!(
            vault.history("p", "dev", "K").unwrap(),
            vec![Version {
                number: 1,
                created_at: None,
                active: true
            }]
        );

        vault
            .set("p", "dev", "K", &Secret::new("new"), change(50))
            .unwrap();
        let history = vault.history("p", "dev", "K").unwrap();
        assert_eq!(history[0].number, 2);
        assert_eq!(history[1].created_at, None, "its date is unknown");
        assert_eq!(value_of(&vault, 1).as_deref(), Some("legacy"));
    }

    #[test]
    fn a_value_overwritten_by_an_older_release_is_still_archived() {
        let vault = MemoryVault::new();
        vault
            .set("p", "dev", "K", &Secret::new("v1"), change(10))
            .unwrap();
        legacy_write(&vault, "from-old-binary");
        vault
            .set("p", "dev", "K", &Secret::new("v3"), change(30))
            .unwrap();
        assert_eq!(value_of(&vault, 1).as_deref(), Some("from-old-binary"));
        assert_eq!(value_of(&vault, 2).as_deref(), Some("v3"));
    }

    #[test]
    fn versions_survive_a_delete_by_an_older_release() {
        let vault = MemoryVault::new();
        vault
            .set("p", "dev", "K", &Secret::new("v1"), change(10))
            .unwrap();
        vault
            .set("p", "dev", "K", &Secret::new("v2"), change(20))
            .unwrap();
        vault.remove(Namespace::Values, "p/dev/K").unwrap();

        assert!(vault.get("p", "dev", "K").unwrap().is_none());
        let history = vault.history("p", "dev", "K").unwrap();
        assert_eq!(history.len(), 1);
        assert!(!history[0].active);
        assert_eq!(value_of(&vault, 1).as_deref(), Some("v1"));

        vault
            .set("p", "dev", "K", &Secret::new("v3"), change(30))
            .unwrap();
        assert_eq!(vault.history("p", "dev", "K").unwrap()[0].number, 3);
    }

    #[test]
    fn versions_are_not_counted_as_values() {
        let vault = MemoryVault::new();
        vault
            .set("p", "dev", "K", &Secret::new("v1"), change(10))
            .unwrap();
        vault
            .set("p", "dev", "K", &Secret::new("v2"), change(20))
            .unwrap();
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn an_unavailable_backend_fails_every_access_with_its_name() {
        let vault = UnavailableVault { backend: "file" };
        let err = vault.get("p", "dev", "K").unwrap_err().to_string();
        assert!(err.contains("The file backend is not available"), "{err}");
        assert!(vault.delete("p", "dev", "K").is_err());
    }

    #[test]
    fn the_keyring_keeps_active_values_where_older_releases_read_them() {
        let vault = KeyringVault::default();
        assert_eq!(vault.service(Namespace::Values), "envy");
        assert_eq!(vault.service(Namespace::History), "envy-history");
        assert_eq!(slot("p", "dev", "K"), "p/dev/K");
    }

    #[test]
    fn the_index_fits_a_windows_credential_with_the_maximum_history() {
        let index = Index {
            current: Some(Stamp {
                n: u32::MAX,
                at: Some(i64::from(u32::MAX)),
            }),
            previous: vec![
                Stamp {
                    n: u32::MAX,
                    at: Some(i64::from(u32::MAX)),
                };
                MAX_KEEP
            ],
        };
        // The Credential Manager may store the text as UTF-16, so count two bytes per char.
        assert!(serde_json::to_string(&index).unwrap().len() * 2 < 2560);
    }

    #[test]
    fn version_and_index_users_never_collide() {
        // `K#1` is a legal variable name: its index must not be version 1 of `K`.
        let slot_k = slot("p", "dev", "K");
        let slot_k1 = slot("p", "dev", "K#1");
        assert_ne!(version_user(&slot_k, 1), index_user(&slot_k1));
        assert_ne!(index_user(&slot_k), version_user(&slot_k1, 1));
    }
}
