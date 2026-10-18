//! Secret storage.
//!
//! [`SecretVault`] is the abstraction the rest of the program depends on.
//! Production uses [`KeyringVault`] (the operating system keyring); tests and
//! tooling can use [`MemoryVault`].

use std::{collections::HashMap, sync::Mutex};

use anyhow::{Context, Result};

use crate::schema::Secret;

/// Identifies one stored value: `(project id, environment, variable)`.
pub trait SecretVault {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>>;
    fn set(&self, project: &str, environment: &str, key: &str, value: &Secret) -> Result<()>;
    /// Returns `true` when something was actually removed.
    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool>;
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

    fn entry(&self, project: &str, environment: &str, key: &str) -> Result<keyring::Entry> {
        let user = format!("{project}/{environment}/{key}");
        keyring::Entry::new(&self.service, &user).context("Could not access the OS keyring")
    }
}

impl Default for KeyringVault {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SERVICE)
    }
}

impl SecretVault for KeyringVault {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>> {
        match self.entry(project, environment, key)?.get_password() {
            Ok(value) => Ok(Some(Secret::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err).context(format!("Could not read '{key}' from the OS keyring")),
        }
    }

    fn set(&self, project: &str, environment: &str, key: &str, value: &Secret) -> Result<()> {
        self.entry(project, environment, key)?
            .set_password(value.expose_secret())
            .context(format!("Could not store '{key}' in the OS keyring"))
    }

    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool> {
        match self.entry(project, environment, key)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(err).context(format!("Could not remove '{key}' from the OS keyring")),
        }
    }
}

type VaultKey = (String, String, String);

/// Volatile vault. Nothing is persisted; values are wiped when dropped.
#[derive(Default)]
pub struct MemoryVault {
    entries: Mutex<HashMap<VaultKey, Secret>>,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(project: &str, environment: &str, key: &str) -> VaultKey {
        (
            project.to_string(),
            environment.to_string(),
            key.to_string(),
        )
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("vault lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SecretVault for MemoryVault {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>> {
        let entries = self.entries.lock().expect("vault lock");
        Ok(entries.get(&Self::key(project, environment, key)).cloned())
    }

    fn set(&self, project: &str, environment: &str, key: &str, value: &Secret) -> Result<()> {
        let mut entries = self.entries.lock().expect("vault lock");
        entries.insert(Self::key(project, environment, key), value.clone());
        Ok(())
    }

    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool> {
        let mut entries = self.entries.lock().expect("vault lock");
        Ok(entries
            .remove(&Self::key(project, environment, key))
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_vault_round_trip() {
        let vault = MemoryVault::new();
        assert!(vault.get("p", "dev", "K").unwrap().is_none());

        vault.set("p", "dev", "K", &Secret::new("v")).unwrap();
        assert_eq!(
            vault.get("p", "dev", "K").unwrap().unwrap().expose_secret(),
            "v"
        );

        assert!(vault.delete("p", "dev", "K").unwrap());
        assert!(!vault.delete("p", "dev", "K").unwrap());
        assert!(vault.is_empty());
    }

    #[test]
    fn memory_vault_isolates_projects_and_environments() {
        let vault = MemoryVault::new();
        vault.set("p1", "dev", "K", &Secret::new("a")).unwrap();
        vault.set("p2", "dev", "K", &Secret::new("b")).unwrap();
        vault.set("p1", "prod", "K", &Secret::new("c")).unwrap();

        assert_eq!(
            vault
                .get("p1", "dev", "K")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "a"
        );
        assert_eq!(
            vault
                .get("p2", "dev", "K")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "b"
        );
        assert_eq!(
            vault
                .get("p1", "prod", "K")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "c"
        );
        assert_eq!(vault.len(), 3);
    }

    #[test]
    fn memory_vault_overwrites() {
        let vault = MemoryVault::new();
        vault.set("p", "dev", "K", &Secret::new("old")).unwrap();
        vault.set("p", "dev", "K", &Secret::new("new")).unwrap();
        assert_eq!(
            vault.get("p", "dev", "K").unwrap().unwrap().expose_secret(),
            "new"
        );
        assert_eq!(vault.len(), 1);
    }
}
