//! The identity of a member of an Envy server (ADR 0002): a 32-byte seed from which an
//! X25519 key (keys are wrapped for it) and an Ed25519 key (everything the member writes is
//! signed with it) are derived. The seed never leaves the client: it lives in the OS keyring,
//! or in `ENVY_IDENTITY` for CI.

use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    keys::{self, Key32, encode},
    schema::Secret,
    vault::{CredentialStore, Namespace},
};

const EXPORT_PREFIX: &str = "envy-identity-v1:";

pub struct Identity {
    /// The member name on the server; the export carries it so CI needs one variable.
    pub name: String,
    seed: Key32,
}

/// Never prints the seed.
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({}, <REDACTED>)", self.name)
    }
}

/// The public half of an identity, as the server and the other members see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeys {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}

impl Identity {
    pub fn generate(name: &str) -> Self {
        Self {
            name: name.to_string(),
            seed: keys::random_key(),
        }
    }

    /// Reads the text printed by [`Identity::export`] (`ENVY_IDENTITY`).
    pub fn parse(text: &str) -> Result<Self> {
        let bad =
            || anyhow::anyhow!("This is not an Envy identity (it starts with {EXPORT_PREFIX}).");
        let rest = text.trim().strip_prefix(EXPORT_PREFIX).ok_or_else(bad)?;
        let (name, encoded) = rest.split_once(':').ok_or_else(bad)?;
        let bytes = zeroize::Zeroizing::new(STANDARD.decode(encoded).map_err(|_| bad())?);
        let seed = keys::to_key(&bytes).ok_or_else(bad)?;
        Ok(Self {
            name: name.to_string(),
            seed,
        })
    }

    /// `envy-identity-v1:<member name>:<seed in base64>`.
    pub fn export(&self) -> Secret {
        Secret::new(format!(
            "{EXPORT_PREFIX}{}:{}",
            self.name,
            STANDARD.encode(self.seed.as_ref())
        ))
    }

    pub fn x25519(&self) -> StaticSecret {
        StaticSecret::from(*keys::hkdf(
            &[],
            self.seed.as_ref(),
            b"envy-member-x25519-v1",
        ))
    }

    fn signing(&self) -> SigningKey {
        SigningKey::from_bytes(&keys::hkdf(
            &[],
            self.seed.as_ref(),
            b"envy-member-ed25519-v1",
        ))
    }

    pub fn public(&self) -> PublicKeys {
        PublicKeys {
            x25519: PublicKey::from(&self.x25519()).to_bytes(),
            ed25519: self.signing().verifying_key().to_bytes(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing().sign(message).to_bytes()
    }
}

impl PublicKeys {
    /// What people compare out of band: 16 bytes of a hash of both keys, in groups of four
    /// hex digits.
    pub fn fingerprint(&self) -> String {
        let digest = Sha3_256::digest(encode(&[
            b"envy-fingerprint-v1",
            &self.x25519,
            &self.ed25519,
        ]));
        let hex = keys::hex(&digest[..16]);
        let groups: Vec<&str> = (0..hex.len()).step_by(4).map(|i| &hex[i..i + 4]).collect();
        groups.join("-")
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.ed25519) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        key.verify_strict(message, &signature).is_ok()
    }

    pub fn x25519_key(&self) -> PublicKey {
        PublicKey::from(self.x25519)
    }
}

/// The identity used with the server at `url`: `ENVY_IDENTITY` when set, otherwise the one
/// stored in the keyring.
pub fn load(
    store: &dyn CredentialStore,
    url: &str,
    preset: Option<&Secret>,
) -> Result<Option<Identity>> {
    if let Some(preset) = preset {
        return Identity::parse(preset.expose_secret()).map(Some);
    }
    match store.read(Namespace::Identity, url)? {
        Some(stored) => Identity::parse(stored.expose_secret()).map(Some),
        None => Ok(None),
    }
}

pub fn save(store: &dyn CredentialStore, url: &str, identity: &Identity) -> Result<()> {
    if store.read(Namespace::Identity, url)?.is_some() {
        bail!("There is already an identity for {url} on this machine.");
    }
    store.write(Namespace::Identity, url, &identity.export())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryVault;

    #[test]
    fn an_identity_survives_export_and_parse() {
        let identity = Identity::generate("ana");
        let again = Identity::parse(identity.export().expose_secret()).unwrap();
        assert_eq!(identity.public(), again.public());
        assert_eq!(again.name, "ana");
        assert!(Identity::parse("envy-identity-v1:abc").is_err());
        assert!(Identity::parse("something else").is_err());
    }

    #[test]
    fn debug_output_hides_the_seed() {
        let identity = Identity::generate("ana");
        let shown = format!("{identity:?}");
        assert_eq!(shown, "Identity(ana, <REDACTED>)");
    }

    #[test]
    fn signatures_verify_only_with_the_right_key_and_message() {
        let identity = Identity::generate("ana");
        let signature = identity.sign(b"hello");
        assert!(identity.public().verify(b"hello", &signature));
        assert!(!identity.public().verify(b"hullo", &signature));
        assert!(
            !Identity::generate("ana")
                .public()
                .verify(b"hello", &signature)
        );
        assert!(!identity.public().verify(b"hello", &[0; 10]));
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let identity = Identity::generate("ana");
        let fingerprint = identity.public().fingerprint();
        assert_eq!(fingerprint.len(), 39, "{fingerprint}");
        assert_eq!(fingerprint, identity.public().fingerprint());
        assert_ne!(
            fingerprint,
            Identity::generate("ana").public().fingerprint()
        );
    }

    #[test]
    fn the_variable_wins_over_the_keyring() {
        let store = MemoryVault::new();
        assert!(load(&store, "https://s", None).unwrap().is_none());

        let stored = Identity::generate("ana");
        save(&store, "https://s", &stored).unwrap();
        assert!(save(&store, "https://s", &Identity::generate("ana")).is_err());
        let loaded = load(&store, "https://s", None).unwrap().unwrap();
        assert_eq!(loaded.public(), stored.public());

        let preset = Identity::generate("ana");
        let from_env = load(&store, "https://s", Some(&preset.export()))
            .unwrap()
            .unwrap();
        assert_eq!(from_env.public(), preset.public());
    }
}
