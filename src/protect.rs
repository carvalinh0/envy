//! Password-protected environments.
//!
//! A value of a protected environment is stored as `envy:sealed:v1:` followed by
//! base64(salt | nonce | ciphertext): the key is Argon2id(password, salt) and the cipher
//! AES-256-GCM. Every value carries its salt, so reading needs only the password. The
//! password check is a sealed constant kept in the environment's reserved slot, the empty
//! variable name that no manifest can declare; new values reuse its salt, so a single key
//! derivation unlocks the whole environment.
//!
//! Reads decide by the stored value: a sealed value always needs the password, even after
//! an older release dropped `protected` from the manifest. Writes decide by the manifest.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use anyhow::{Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version as Argon2Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

use crate::{
    envy::Envy,
    prompt::Prompter,
    schema::Secret,
    vault::{Change, SecretVault, Version},
};

/// Reserved variable name holding the password check of an environment.
pub const CHECK_SLOT: &str = "";
const PREFIX: &str = "envy:sealed:v1:";
const AAD: &[u8] = b"envy-sealed-v1";
const CHECK_TEXT: &str = "envy protected environment";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

type Salt = [u8; SALT_LEN];
type DerivedKey = Zeroizing<[u8; 32]>;

pub fn is_sealed(value: &Secret) -> bool {
    value.expose_secret().starts_with(PREFIX)
}

/// Variables of `environment` whose values are stored for the project without encryption,
/// such as values set before a teammate protected the environment.
pub fn unsealed(vault: &dyn SecretVault, envy: &Envy, environment: &str) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for key in envy.effective_schema(environment)?.into_keys() {
        if vault
            .get(&envy.id, environment, &key)?
            .is_some_and(|value| !is_sealed(&value))
        {
            keys.push(key);
        }
    }
    Ok(keys)
}

fn derive(password: &Secret, salt: &Salt) -> Result<DerivedKey> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Argon2Version::V0x13, Params::DEFAULT)
        .hash_password_into(password.expose_secret().as_bytes(), salt, key.as_mut())
        .map_err(|err| anyhow!("Could not derive the key of the password: {err}"))?;
    Ok(key)
}

fn cipher(key: &DerivedKey) -> Aes256Gcm {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(**key))
}

fn seal(key: &DerivedKey, salt: &Salt, value: &Secret) -> Result<Secret> {
    let nonce = Nonce::generate();
    let ciphertext = cipher(key)
        .encrypt(
            &nonce,
            Payload {
                msg: value.expose_secret().as_bytes(),
                aad: AAD,
            },
        )
        .map_err(|_| anyhow!("Could not encrypt the value"))?;
    let mut payload = Zeroizing::new(Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len()));
    payload.extend_from_slice(salt);
    payload.extend_from_slice(nonce.as_slice());
    payload.extend_from_slice(&ciphertext);
    Ok(Secret::new(format!(
        "{PREFIX}{}",
        STANDARD.encode(&payload)
    )))
}

/// The salt of a sealed value and the rest of its payload.
fn split(value: &Secret) -> Option<(Salt, Vec<u8>)> {
    let encoded = value.expose_secret().strip_prefix(PREFIX)?;
    let payload = STANDARD.decode(encoded).ok()?;
    if payload.len() < SALT_LEN + NONCE_LEN {
        return None;
    }
    let salt = payload[..SALT_LEN].try_into().ok()?;
    Some((salt, payload[SALT_LEN..].to_vec()))
}

fn open_with(key: &DerivedKey, sealed: &[u8]) -> Option<Secret> {
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce).ok()?;
    let plaintext = Zeroizing::new(
        cipher(key)
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: AAD,
                },
            )
            .ok()?,
    );
    String::from_utf8(plaintext.to_vec()).ok().map(Secret::new)
}

/// Asks for the password once per run and caches the keys derived from it.
struct Unlocker<'a> {
    prompter: &'a dyn Prompter,
    /// `ENVY_PROTECT_PASSWORD`, for CI.
    preset: Option<&'a Secret>,
    password: RefCell<Option<Secret>>,
    keys: RefCell<HashMap<Salt, DerivedKey>>,
}

impl Unlocker<'_> {
    fn password(&self, environment: &str) -> Result<Secret> {
        if let Some(password) = self.password.borrow().as_ref() {
            return Ok(password.clone());
        }
        let password = match self.preset {
            Some(preset) => preset.clone(),
            None => self.prompter.ask_secret(&format!(
                "Password of the protected environment '{environment}'"
            ))?,
        };
        if password.expose_secret().is_empty() {
            bail!("The environment '{environment}' is protected and needs its password.");
        }
        *self.password.borrow_mut() = Some(password.clone());
        Ok(password)
    }

    fn new_password(&self, environment: &str) -> Result<Secret> {
        if let Some(preset) = self.preset {
            return Ok(preset.clone());
        }
        let first = self
            .prompter
            .ask_secret(&format!("New password for '{environment}'"))?;
        if first.expose_secret().is_empty() {
            bail!("The password can't be empty.");
        }
        let again = self
            .prompter
            .ask_secret(&format!("Repeat the password for '{environment}'"))?;
        if first.expose_secret() != again.expose_secret() {
            bail!("The passwords do not match.");
        }
        *self.password.borrow_mut() = Some(first.clone());
        Ok(first)
    }

    fn key(&self, password: &Secret, salt: &Salt) -> Result<DerivedKey> {
        if let Some(key) = self.keys.borrow().get(salt) {
            return Ok(key.clone());
        }
        let key = derive(password, salt)?;
        self.keys.borrow_mut().insert(*salt, key.clone());
        Ok(key)
    }
}

/// A [`SecretVault`] that encrypts the writes to protected environments and decrypts sealed
/// values on read. Commands use it instead of the raw vault whenever values flow through.
pub struct ProtectedVault<'a> {
    inner: &'a dyn SecretVault,
    project: String,
    protected: BTreeSet<String>,
    /// `false` returns sealed values as they are stored, for commands that only need to
    /// know whether a value exists (`envy ls` without `--show`), so they ask no password.
    reveal: bool,
    unlocker: Unlocker<'a>,
}

impl<'a> ProtectedVault<'a> {
    pub fn new(
        inner: &'a dyn SecretVault,
        envy: &Envy,
        prompter: &'a dyn Prompter,
        preset: Option<&'a Secret>,
        reveal: bool,
    ) -> Self {
        Self {
            inner,
            project: envy.id.clone(),
            protected: envy.protected.clone(),
            reveal,
            unlocker: Unlocker {
                prompter,
                preset,
                password: RefCell::new(None),
                keys: RefCell::new(HashMap::new()),
            },
        }
    }

    /// Checks the password of `environment`, or sets one (asking twice) when it has none.
    pub fn ensure_password(&self, environment: &str) -> Result<()> {
        self.unlock_for_writing(environment).map(|_| ())
    }

    /// The key and salt for new values of `environment`. Checks the password against the
    /// environment's password check, or creates the check when the environment has none.
    fn unlock_for_writing(&self, environment: &str) -> Result<(DerivedKey, Salt)> {
        let check = self.inner.get(&self.project, environment, CHECK_SLOT)?;
        let Some((salt, sealed)) = check.as_ref().and_then(split) else {
            return self.create_check(environment);
        };
        let password = self.unlocker.password(environment)?;
        let key = self.unlocker.key(&password, &salt)?;
        match open_with(&key, &sealed) {
            Some(text) if text.expose_secret() == CHECK_TEXT => Ok((key, salt)),
            _ => bail!("Wrong password for the protected environment '{environment}'."),
        }
    }

    fn create_check(&self, environment: &str) -> Result<(DerivedKey, Salt)> {
        let password = self.unlocker.new_password(environment)?;
        let salt = Salt::generate();
        let key = self.unlocker.key(&password, &salt)?;
        let check = seal(&key, &salt, &Secret::new(CHECK_TEXT))?;
        // The check keeps no versions, so its date is never shown.
        let change = Change {
            at: chrono::DateTime::UNIX_EPOCH,
            keep: 0,
        };
        self.inner
            .set(&self.project, environment, CHECK_SLOT, &check, change)?;
        Ok((key, salt))
    }

    fn open(&self, environment: &str, key_name: &str, value: Secret) -> Result<Secret> {
        if !self.reveal || !is_sealed(&value) {
            return Ok(value);
        }
        let failure = || {
            anyhow!(
                "Could not decrypt '{key_name}' in '{environment}': wrong password or corrupted value."
            )
        };
        let (salt, sealed) = split(&value).ok_or_else(failure)?;
        let password = self.unlocker.password(environment)?;
        let key = self.unlocker.key(&password, &salt)?;
        open_with(&key, &sealed).ok_or_else(failure)
    }
}

impl SecretVault for ProtectedVault<'_> {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>> {
        self.inner
            .get(project, environment, key)?
            .map(|value| self.open(environment, key, value))
            .transpose()
    }

    fn set(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        value: &Secret,
        change: Change,
    ) -> Result<()> {
        if project != self.project || !self.protected.contains(environment) {
            return self.inner.set(project, environment, key, value, change);
        }
        let (derived, salt) = self.unlock_for_writing(environment)?;
        let sealed = seal(&derived, &salt, value)?;
        self.inner.set(project, environment, key, &sealed, change)
    }

    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool> {
        self.inner.delete(project, environment, key)
    }

    fn history(&self, project: &str, environment: &str, key: &str) -> Result<Vec<Version>> {
        self.inner.history(project, environment, key)
    }

    fn get_version(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        number: u32,
    ) -> Result<Option<Secret>> {
        self.inner
            .get_version(project, environment, key, number)?
            .map(|value| self.open(environment, key, value))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::vault::MemoryVault;

    #[derive(Default)]
    struct Answers(RefCell<Vec<&'static str>>);

    impl Prompter for Answers {
        fn ask_secret(&self, _label: &str) -> Result<Secret> {
            let mut answers = self.0.borrow_mut();
            if answers.is_empty() {
                bail!("no answer left");
            }
            Ok(Secret::new(answers.remove(0)))
        }
    }

    fn protected_envy() -> Envy {
        let mut envy = Envy::new("P".into(), None).unwrap();
        envy.id = "p".into();
        envy.schemas.insert("prod".into(), Default::default());
        envy.protected.insert("prod".into());
        envy
    }

    fn change() -> Change {
        Change {
            at: chrono::DateTime::UNIX_EPOCH,
            keep: 5,
        }
    }

    #[test]
    fn values_of_protected_environments_are_stored_sealed() {
        let inner = MemoryVault::new();
        let envy = protected_envy();
        let prompter = Answers(RefCell::new(vec!["pw", "pw"]));
        let vault = ProtectedVault::new(&inner, &envy, &prompter, None, true);

        vault
            .set("p", "prod", "TOKEN", &Secret::new("s3cr3t"), change())
            .unwrap();
        let stored = inner.get("p", "prod", "TOKEN").unwrap().unwrap();
        assert!(is_sealed(&stored));
        assert!(!stored.expose_secret().contains("s3cr3t"));
        assert_eq!(
            vault
                .get("p", "prod", "TOKEN")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "s3cr3t"
        );
    }

    #[test]
    fn a_new_reader_needs_the_password_and_a_wrong_one_is_rejected() {
        let inner = MemoryVault::new();
        let envy = protected_envy();
        let setup = Answers(RefCell::new(vec!["pw", "pw"]));
        ProtectedVault::new(&inner, &envy, &setup, None, true)
            .set("p", "prod", "TOKEN", &Secret::new("s3cr3t"), change())
            .unwrap();

        let wrong = Secret::new("nope");
        let reader = ProtectedVault::new(&inner, &envy, &setup, Some(&wrong), true);
        let err = reader.get("p", "prod", "TOKEN").unwrap_err().to_string();
        assert!(err.contains("Could not decrypt 'TOKEN' in 'prod'"), "{err}");
        assert!(!err.contains("s3cr3t"));

        let err = reader
            .set("p", "prod", "OTHER", &Secret::new("x"), change())
            .unwrap_err()
            .to_string();
        assert!(err.contains("Wrong password"), "{err}");

        let right = Secret::new("pw");
        let reader = ProtectedVault::new(&inner, &envy, &setup, Some(&right), true);
        assert_eq!(
            reader
                .get("p", "prod", "TOKEN")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "s3cr3t"
        );
    }

    #[test]
    fn a_sealed_value_needs_the_password_even_without_the_manifest_flag() {
        let inner = MemoryVault::new();
        let envy = protected_envy();
        let setup = Answers(RefCell::new(vec!["pw", "pw"]));
        ProtectedVault::new(&inner, &envy, &setup, None, true)
            .set("p", "prod", "TOKEN", &Secret::new("s3cr3t"), change())
            .unwrap();

        let mut dropped = envy.clone();
        dropped.protected.clear();
        let no_answers = Answers::default();
        let err = ProtectedVault::new(&inner, &dropped, &no_answers, None, true)
            .get("p", "prod", "TOKEN")
            .unwrap_err();
        assert!(err.to_string().contains("no answer left"), "{err}");
    }

    #[test]
    fn hidden_reads_ask_no_password() {
        let inner = MemoryVault::new();
        let envy = protected_envy();
        let setup = Answers(RefCell::new(vec!["pw", "pw"]));
        ProtectedVault::new(&inner, &envy, &setup, None, true)
            .set("p", "prod", "TOKEN", &Secret::new("s3cr3t"), change())
            .unwrap();

        let no_answers = Answers::default();
        let value = ProtectedVault::new(&inner, &envy, &no_answers, None, false)
            .get("p", "prod", "TOKEN")
            .unwrap()
            .unwrap();
        assert!(is_sealed(&value));
    }

    #[test]
    fn the_new_password_must_be_typed_twice() {
        let inner = MemoryVault::new();
        let envy = protected_envy();
        let prompter = Answers(RefCell::new(vec!["pw", "typo"]));
        let err = ProtectedVault::new(&inner, &envy, &prompter, None, true)
            .set("p", "prod", "TOKEN", &Secret::new("s3cr3t"), change())
            .unwrap_err();
        assert!(err.to_string().contains("do not match"), "{err}");
        assert!(inner.is_empty());
    }

    #[test]
    fn unprotected_environments_are_stored_as_they_are() {
        let inner = MemoryVault::new();
        let mut envy = protected_envy();
        envy.schemas.insert("dev".into(), Default::default());
        let no_answers = Answers::default();
        ProtectedVault::new(&inner, &envy, &no_answers, None, true)
            .set("p", "dev", "PORT", &Secret::new("80"), change())
            .unwrap();
        assert_eq!(
            inner
                .get("p", "dev", "PORT")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "80"
        );
    }

    #[test]
    fn tampered_values_are_rejected() {
        let inner = MemoryVault::new();
        let envy = protected_envy();
        let setup = Answers(RefCell::new(vec!["pw", "pw"]));
        let vault = ProtectedVault::new(&inner, &envy, &setup, None, true);
        vault
            .set("p", "prod", "TOKEN", &Secret::new("s3cr3t"), change())
            .unwrap();
        let stored = inner.get("p", "prod", "TOKEN").unwrap().unwrap();
        let mut bytes = STANDARD
            .decode(stored.expose_secret().strip_prefix(PREFIX).unwrap())
            .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = Secret::new(format!("{PREFIX}{}", STANDARD.encode(bytes)));
        inner
            .set("p", "prod", "TOKEN", &tampered, change())
            .unwrap();
        assert!(vault.get("p", "prod", "TOKEN").is_err());
    }
}
