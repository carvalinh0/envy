//! The pieces of ADR 0001 shared by every encrypted backend: sealed blobs, the purposes of
//! wrapped keys, and the associated data of records, wraps and the name index. The file
//! backend and the remote backend both use them, so a record means the same in both.

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::keys::{self, Key32, encode, int};

/// Bytes encrypted with XChaCha20-Poly1305, both fields in base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub nonce: String,
    pub ciphertext: String,
}

/// What a wrapped key protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    /// The DEK of one environment.
    Dek,
    /// The project's name key.
    Names,
}

impl Purpose {
    pub(crate) fn label(self) -> &'static [u8] {
        match self {
            Purpose::Dek => b"dek",
            Purpose::Names => b"names",
        }
    }
}

/// `(purpose, environment, key id)`: which key a wrap holds. The name key has no environment.
pub(crate) type KeySlot = (Purpose, String, u32);

pub(crate) fn names_slot() -> KeySlot {
    (Purpose::Names, String::new(), 1)
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(crate) fn unb64(text: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(text)
        .map_err(|_| anyhow!("The stored data is corrupted (invalid base64)."))
}

pub(crate) fn index_aad(project: &str) -> Vec<u8> {
    encode(&[b"envy-index-v1", project.as_bytes()])
}

pub(crate) fn wrap_aad(project: &str, (purpose, env, key_id): &KeySlot, member: &str) -> Vec<u8> {
    encode(&[
        b"envy-wrap-v1",
        project.as_bytes(),
        purpose.label(),
        env.as_bytes(),
        &int(i64::from(*key_id)),
        member.as_bytes(),
    ])
}

/// Where a record belongs; its AAD binds the ciphertext to all of it.
pub(crate) struct RecordId<'a> {
    pub env: &'a str,
    pub key: &'a str,
    pub version: u32,
    pub key_id: u32,
    pub created_at: i64,
}

pub(crate) fn record_aad(project: &str, id: &RecordId) -> Vec<u8> {
    encode(&[
        b"envy-record-v1",
        project.as_bytes(),
        id.env.as_bytes(),
        id.key.as_bytes(),
        &int(i64::from(id.version)),
        &int(i64::from(id.key_id)),
        &int(id.created_at),
    ])
}

pub(crate) fn seal_to(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let (nonce, ciphertext) = keys::seal(key, aad, plaintext)?;
    Ok(Sealed {
        nonce: b64(&nonce),
        ciphertext: b64(&ciphertext),
    })
}

pub(crate) fn open_from(
    key: &Key32,
    aad: &[u8],
    sealed: &Sealed,
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let nonce = unb64(&sealed.nonce).ok()?;
    let ciphertext = unb64(&sealed.ciphertext).ok()?;
    keys::open(key, aad, &nonce, &ciphertext)
}
