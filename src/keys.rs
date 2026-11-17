//! The cryptography of the encrypted vaults (ADR 0001): the canonical encoding of every AAD
//! and HMAC input, the password-derived KEK, XChaCha20-Poly1305, the HMAC of variable names,
//! the X25519 wraps and the padding of values. Only ready-made primitives are used.

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use hkdf::SimpleHkdf;
use hmac::{Mac, SimpleHmac};
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::schema::Secret;

pub type Key32 = Zeroizing<[u8; 32]>;
pub const NONCE_LEN: usize = 24;
/// Values are padded to a multiple of this, so a stored size only reveals a size class.
pub const PAD_TO: usize = 256;

/// Each field framed by its length (4 bytes, big endian). The first field is a versioned
/// domain label, so bytes valid in one context never verify in another.
pub fn encode(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 4).sum());
    for field in fields {
        let len = u32::try_from(field.len()).expect("fields are far below 4 GiB");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// An integer as a field of [`encode`].
pub fn int(value: i64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn random_key() -> Key32 {
    Zeroizing::new(<[u8; 32]>::generate())
}

pub fn random_salt() -> [u8; 16] {
    <[u8; 16]>::generate()
}

/// Argon2id parameters stored next to a vault, so they can be raised later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m: Params::DEFAULT_M_COST,
            t: Params::DEFAULT_T_COST,
            p: Params::DEFAULT_P_COST,
        }
    }
}

pub fn derive_kek(password: &Secret, salt: &[u8], params: KdfParams) -> Result<Key32> {
    let params = Params::new(params.m, params.t, params.p, Some(32))
        .map_err(|err| anyhow!("Invalid key derivation parameters: {err}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.expose_secret().as_bytes(), salt, key.as_mut())
        .map_err(|err| anyhow!("Could not derive the key of the password: {err}"))?;
    Ok(key)
}

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(**key).into())
}

/// Encrypts with a random nonce; returns `(nonce, ciphertext)`.
pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = XNonce::generate();
    let ciphertext = cipher(key)
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("Could not encrypt"))?;
    Ok((nonce.into(), ciphertext))
}

/// `None` when the key, the AAD or the ciphertext is wrong.
pub fn open(
    key: &Key32,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let nonce = XNonce::try_from(nonce).ok()?;
    cipher(key)
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// HMAC-SHA3-256 of `(environment, variable)` under the project's name key, in hex.
pub fn name_tag(names: &Key32, environment: &str, variable: &str) -> String {
    let mut mac =
        <SimpleHmac<Sha3_256>>::new_from_slice(names.as_ref()).expect("HMAC takes any key");
    mac.update(&encode(&[
        b"envy-name-v1",
        environment.as_bytes(),
        variable.as_bytes(),
    ]));
    hex(&mac.finalize().into_bytes())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> Key32 {
    let mut out = Zeroizing::new([0u8; 32]);
    SimpleHkdf::<Sha3_256>::new(Some(salt), ikm)
        .expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF length");
    out
}

/// The X25519 key pair of a recovery key.
pub fn recovery_secret(entropy: &[u8; 32]) -> StaticSecret {
    let bytes = hkdf(&[], entropy, b"envy-recovery-x25519-v1");
    StaticSecret::from(*bytes)
}

/// A key wrapped for an X25519 recipient: `(ephemeral public key, nonce, ciphertext)`.
pub type X25519Wrap = ([u8; 32], [u8; NONCE_LEN], Vec<u8>);

fn wrap_key(shared: &[u8; 32], epk: &[u8; 32], recipient: &[u8; 32]) -> Key32 {
    let salt = [epk.as_slice(), recipient.as_slice()].concat();
    hkdf(&salt, shared, b"envy-wrap-x25519-v1")
}

pub fn x25519_wrap(recipient: &PublicKey, aad: &[u8], key: &Key32) -> Result<X25519Wrap> {
    let ephemeral = StaticSecret::from(*random_key());
    let epk = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(recipient);
    if !shared.was_contributory() {
        return Err(anyhow!("Invalid public key"));
    }
    let wrapping = wrap_key(shared.as_bytes(), &epk, recipient.as_bytes());
    let (nonce, wrapped) = seal(&wrapping, aad, key.as_ref())?;
    Ok((epk, nonce, wrapped))
}

pub fn x25519_unwrap(
    secret: &StaticSecret,
    epk: &[u8],
    aad: &[u8],
    nonce: &[u8],
    wrapped: &[u8],
) -> Option<Key32> {
    let epk: [u8; 32] = epk.try_into().ok()?;
    let shared = secret.diffie_hellman(&PublicKey::from(epk));
    if !shared.was_contributory() {
        return None;
    }
    let mine = PublicKey::from(secret).to_bytes();
    let wrapping = wrap_key(shared.as_bytes(), &epk, &mine);
    to_key(&open(&wrapping, aad, nonce, wrapped)?)
}

pub fn to_key(bytes: &[u8]) -> Option<Key32> {
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(Zeroizing::new(array))
}

/// The value's length (4 bytes, big endian), its bytes, then zeros up to [`PAD_TO`].
pub fn pad(value: &Secret) -> Zeroizing<Vec<u8>> {
    let bytes = value.expose_secret().as_bytes();
    let total = (bytes.len() + 4).div_ceil(PAD_TO) * PAD_TO;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    let len = u32::try_from(bytes.len()).expect("values are far below 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    out.resize(total, 0);
    out
}

pub fn unpad(padded: &[u8]) -> Option<Secret> {
    let len = u32::from_be_bytes(padded.get(..4)?.try_into().ok()?) as usize;
    let bytes = padded.get(4..4 + len)?;
    std::str::from_utf8(bytes).ok().map(Secret::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_encoding_is_unambiguous() {
        let a = encode(&[b"x", b"ab", b"c"]);
        let b = encode(&[b"x", b"a", b"bc"]);
        assert_ne!(a, b);
        assert_eq!(&a[..5], &[0, 0, 0, 1, b'x']);
    }

    #[test]
    fn sealed_bytes_only_open_with_the_same_key_and_aad() {
        let key = random_key();
        let (nonce, ciphertext) = seal(&key, b"aad", b"hello").unwrap();
        assert_eq!(
            open(&key, b"aad", &nonce, &ciphertext).unwrap().as_slice(),
            b"hello"
        );
        assert!(open(&key, b"other", &nonce, &ciphertext).is_none());
        assert!(open(&random_key(), b"aad", &nonce, &ciphertext).is_none());
    }

    #[test]
    fn name_tags_depend_on_key_environment_and_name() {
        let names = random_key();
        let tag = name_tag(&names, "dev", "TOKEN");
        assert_eq!(tag.len(), 64);
        assert_eq!(tag, name_tag(&names, "dev", "TOKEN"));
        assert_ne!(tag, name_tag(&names, "prod", "TOKEN"));
        assert_ne!(tag, name_tag(&names, "devT", "OKEN"));
        assert_ne!(tag, name_tag(&random_key(), "dev", "TOKEN"));
    }

    #[test]
    fn a_recovery_wrap_only_opens_with_the_recovery_key() {
        let secret = recovery_secret(&[7; 32]);
        let public = PublicKey::from(&secret);
        let dek = random_key();
        let (epk, nonce, wrapped) = x25519_wrap(&public, b"aad", &dek).unwrap();

        let opened = x25519_unwrap(&secret, &epk, b"aad", &nonce, &wrapped).unwrap();
        assert_eq!(*opened, *dek);
        assert!(
            x25519_unwrap(&recovery_secret(&[8; 32]), &epk, b"aad", &nonce, &wrapped).is_none()
        );
        assert!(x25519_unwrap(&secret, &epk, b"other", &nonce, &wrapped).is_none());
    }

    #[test]
    fn the_recovery_key_pair_is_derived_from_the_entropy() {
        let a = PublicKey::from(&recovery_secret(&[1; 32]));
        let b = PublicKey::from(&recovery_secret(&[1; 32]));
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn padding_hides_the_exact_size() {
        for (value, size) in [
            ("", 256),
            ("abc", 256),
            (&"x".repeat(252), 256),
            (&"x".repeat(253), 512),
        ] {
            let padded = pad(&Secret::new(value));
            assert_eq!(padded.len(), size, "{}", value.len());
            assert_eq!(unpad(&padded).unwrap().expose_secret(), value);
        }
        assert!(unpad(&[0, 0, 1, 0]).is_none(), "a length past the end");
    }

    #[test]
    fn the_kek_depends_on_password_and_salt() {
        let params = KdfParams { m: 64, t: 1, p: 1 };
        let a = derive_kek(&Secret::new("pw"), &[1; 16], params).unwrap();
        assert_eq!(
            *a,
            *derive_kek(&Secret::new("pw"), &[1; 16], params).unwrap()
        );
        assert_ne!(
            *a,
            *derive_kek(&Secret::new("pw"), &[2; 16], params).unwrap()
        );
        assert_ne!(
            *a,
            *derive_kek(&Secret::new("pw2"), &[1; 16], params).unwrap()
        );
    }
}
