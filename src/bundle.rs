//! Encrypted bundles used by `envy export` / `envy import`.
//!
//! A bundle is encrypted with AES-256-GCM using a random 256-bit key generated at export
//! time. The key is shown only once; it is never stored next to the bundle.

use std::collections::BTreeMap;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const FORMAT_VERSION: u8 = 1;
const AAD: &[u8] = b"envy-bundle-v1";

/// Scope label used in the file name when every environment is exported.
pub const ALL_SCOPE: &str = "all";

/// `environment -> variable -> value`
pub type BundleEntries = BTreeMap<String, BTreeMap<String, Zeroizing<String>>>;

#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub project_id: String,
    pub project_name: String,
    pub scope: String,
    pub entries: BundleEntries,
}

impl Bundle {
    pub fn value_count(&self) -> usize {
        self.entries.values().map(BTreeMap::len).sum()
    }

    /// `[project_name.scope].envy`, sanitised so it is safe as a file name.
    pub fn file_name(&self) -> String {
        let clean = |s: &str| -> String {
            s.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect()
        };
        format!("{}.{}.envy", clean(&self.project_name), clean(&self.scope))
    }
}

/// The random key that opens a bundle (base64). Wiped from memory on drop.
pub struct BundleKey(Zeroizing<String>);

impl BundleKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

pub trait BundleCodec {
    /// Encrypts `bundle`, returning the file content and the freshly generated key.
    fn seal(&self, bundle: &Bundle) -> Result<(Vec<u8>, BundleKey)>;
    /// Decrypts the file content with `key`.
    fn open(&self, data: &[u8], key: &str) -> Result<Bundle>;
}

#[derive(Debug, Default)]
pub struct AesGcmCodec;

impl BundleCodec for AesGcmCodec {
    fn seal(&self, bundle: &Bundle) -> Result<(Vec<u8>, BundleKey)> {
        let plaintext = Zeroizing::new(serde_json::to_vec(bundle)?);

        let key = Key::<Aes256Gcm>::generate();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::generate();
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("Could not encrypt the bundle"))?;

        let envelope = Envelope {
            version: FORMAT_VERSION,
            nonce: STANDARD.encode(nonce.as_slice()),
            ciphertext: STANDARD.encode(ciphertext),
        };
        let encoded_key = BundleKey(Zeroizing::new(STANDARD.encode(key.as_slice())));

        Ok((serde_json::to_vec_pretty(&envelope)?, encoded_key))
    }

    fn open(&self, data: &[u8], key: &str) -> Result<Bundle> {
        let envelope: Envelope =
            serde_json::from_slice(data).context("The file is not a valid Envy bundle.")?;
        if envelope.version != FORMAT_VERSION {
            bail!("Unsupported bundle version {}.", envelope.version);
        }

        let key_bytes = Zeroizing::new(
            STANDARD
                .decode(key.trim())
                .context("The key is not valid base64.")?,
        );
        let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("The key must have 256 bits."))?;
        let nonce_bytes = STANDARD
            .decode(&envelope.nonce)
            .context("Corrupted bundle nonce.")?;
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("Corrupted bundle nonce."))?;
        let ciphertext = STANDARD
            .decode(&envelope.ciphertext)
            .context("Corrupted bundle data.")?;

        let plaintext = Zeroizing::new(
            Aes256Gcm::new(&key)
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: AAD,
                    },
                )
                .map_err(|_| anyhow::anyhow!("Wrong key or corrupted bundle."))?,
        );

        serde_json::from_slice(&plaintext).context("The bundle content is invalid.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Bundle {
        let mut entries = BundleEntries::new();
        entries
            .entry("dev".into())
            .or_default()
            .insert("TOKEN".into(), Zeroizing::new("super-secret".into()));
        Bundle {
            project_id: "id-1".into(),
            project_name: "My Project".into(),
            scope: "dev".into(),
            entries,
        }
    }

    #[test]
    fn seal_and_open_round_trip() {
        let codec = AesGcmCodec;
        let (data, key) = codec.seal(&sample()).unwrap();
        let opened = codec.open(&data, key.as_str()).unwrap();
        assert_eq!(opened.project_id, "id-1");
        assert_eq!(opened.entries["dev"]["TOKEN"].as_str(), "super-secret");
        assert_eq!(opened.value_count(), 1);
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let (data, _) = AesGcmCodec.seal(&sample()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(!text.contains("super-secret"));
        assert!(!text.contains("TOKEN"));
    }

    #[test]
    fn every_seal_uses_a_new_key_and_nonce() {
        let (a, key_a) = AesGcmCodec.seal(&sample()).unwrap();
        let (b, key_b) = AesGcmCodec.seal(&sample()).unwrap();
        assert_ne!(key_a.as_str(), key_b.as_str());
        assert_ne!(a, b);
    }

    #[test]
    fn key_has_256_bits() {
        let (_, key) = AesGcmCodec.seal(&sample()).unwrap();
        assert_eq!(STANDARD.decode(key.as_str()).unwrap().len(), 32);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (data, _) = AesGcmCodec.seal(&sample()).unwrap();
        let (_, other) = AesGcmCodec.seal(&sample()).unwrap();
        let err = AesGcmCodec.open(&data, other.as_str()).err().unwrap();
        assert!(err.to_string().contains("Wrong key"));
    }

    #[test]
    fn malformed_key_is_rejected() {
        let (data, _) = AesGcmCodec.seal(&sample()).unwrap();
        assert!(AesGcmCodec.open(&data, "%%%").is_err());
        assert!(AesGcmCodec.open(&data, "c2hvcnQ=").is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let (data, key) = AesGcmCodec.seal(&sample()).unwrap();
        let mut envelope: Envelope = serde_json::from_slice(&data).unwrap();
        let mut raw = STANDARD.decode(&envelope.ciphertext).unwrap();
        raw[0] ^= 0xff;
        envelope.ciphertext = STANDARD.encode(raw);
        let tampered = serde_json::to_vec(&envelope).unwrap();
        assert!(AesGcmCodec.open(&tampered, key.as_str()).is_err());
    }

    #[test]
    fn garbage_is_not_a_bundle() {
        assert!(AesGcmCodec.open(b"hello", "aaaa").is_err());
    }

    #[test]
    fn file_name_is_sanitised() {
        let bundle = Bundle {
            project_name: "My / Project".into(),
            ..sample()
        };
        assert_eq!(bundle.file_name(), "My---Project.dev.envy");
    }
}
