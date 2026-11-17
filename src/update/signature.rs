//! The minisign signature of a release archive, checked before the archive replaces the
//! running executable. The release workflow signs every archive with the key below and a
//! trusted comment naming the tag and the archive, so a valid signature of another release
//! (an older one, with known bugs) can't be passed off as this one.

use anyhow::{Result, anyhow, bail};
use minisign_verify::{PublicKey, Signature};

/// The public key of the releases (key id `FFEFC84D5F45A95F`). Its secret half is the
/// `MINISIGN_SECRET_KEY` secret of the repository; changing it needs a release signed with the
/// old key that carries the new one.
pub const RELEASE_KEY: &str = "RWRfqUVfTcjv/06FBkCOswn6uHfKptnnu9z6h0mEaGqnqHS6bJHSqNeR";

/// The trusted comment the release workflow signs with each archive.
pub fn trusted_comment(tag: &str, asset: &str) -> String {
    format!("envy-release {tag} {asset}")
}

/// The signature file of `asset`, published next to it.
pub fn signature_name(asset: &str) -> String {
    format!("{asset}.minisig")
}

/// Checks that `signature` is the release key's signature of `archive`, made for `asset` of
/// release `tag`.
pub fn verify(
    public_key: &str,
    archive: &[u8],
    signature: &[u8],
    tag: &str,
    asset: &str,
) -> Result<()> {
    let key = PublicKey::from_base64(public_key)
        .map_err(|_| anyhow!("The release key built into Envy is not valid."))?;
    let invalid = || anyhow!("The signature of {asset} is not valid; nothing was installed.");
    let text = std::str::from_utf8(signature).map_err(|_| invalid())?;
    let signature = Signature::decode(text).map_err(|_| invalid())?;
    key.verify(archive, &signature, true)
        .map_err(|_| invalid())?;
    if signature.trusted_comment() != trusted_comment(tag, asset) {
        bail!("The signature of {asset} was made for another release; nothing was installed.");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    /// A key pair made with the minisign library and an archive signed by the minisign 0.12
    /// command line (prehashed), as the release workflow does.
    const CLI_KEY: &str = "RWSiiASFatyQSuWMFN0jsn7dAkgvVQH6Pwzgf8TMhYNugCqHks/yjMfi";
    const CLI_ARCHIVE: &[u8] = b"envy release archive\n";
    const CLI_ASSET: &str = "envy-v9.9.9-x86_64-unknown-linux-gnu.tar.gz";
    const CLI_SIGNATURE: &str = "untrusted comment: signature from minisign secret key
RUSiiASFatyQSn6aMDbpWJCKZhBT23GhM5+pfXeZs66uHX2DHBJWJo11ZYiytJPpEDYpLXoUsGrleC2gZJvjLdsPvfGo7TU3Fwo=
trusted comment: envy-release v9.9.9 envy-v9.9.9-x86_64-unknown-linux-gnu.tar.gz
iSgKCiTiggBIAEVfLjSpUqkboTeVLp4qj+UcdY3ATpIuXbo7pCLWm+Gao6e9d2GadYVYqgKPUf4OO55sPwRABQ==
";

    /// Signs like minisign's legacy format, for tests that need their own archives.
    pub struct TestSigner(SigningKey);

    impl TestSigner {
        pub fn new(seed: u8) -> Self {
            Self(SigningKey::from_bytes(&[seed; 32]))
        }

        fn key_id(&self) -> [u8; 8] {
            [self.0.verifying_key().to_bytes()[0]; 8]
        }

        pub fn public_key(&self) -> String {
            let key = self.0.verifying_key().to_bytes();
            STANDARD.encode([b"Ed".as_slice(), &self.key_id(), &key].concat())
        }

        pub fn sign(&self, archive: &[u8], comment: &str) -> Vec<u8> {
            let signature = self.0.sign(archive).to_bytes();
            let line = [b"Ed".as_slice(), &self.key_id(), &signature].concat();
            let global = self
                .0
                .sign(&[signature.as_slice(), comment.as_bytes()].concat())
                .to_bytes();
            format!(
                "untrusted comment: test\n{}\ntrusted comment: {comment}\n{}\n",
                STANDARD.encode(line),
                STANDARD.encode(global)
            )
            .into_bytes()
        }
    }

    #[test]
    fn a_signature_of_the_minisign_command_line_verifies() {
        verify(
            CLI_KEY,
            CLI_ARCHIVE,
            CLI_SIGNATURE.as_bytes(),
            "v9.9.9",
            CLI_ASSET,
        )
        .unwrap();
    }

    #[test]
    fn the_release_key_parses() {
        assert!(PublicKey::from_base64(RELEASE_KEY).is_ok());
    }

    #[test]
    fn a_changed_archive_or_another_key_is_refused() {
        let sig = CLI_SIGNATURE.as_bytes();
        let changed = b"envy release archive?\n";
        assert!(verify(CLI_KEY, changed, sig, "v9.9.9", CLI_ASSET).is_err());
        let other = TestSigner::new(1).public_key();
        assert!(verify(&other, CLI_ARCHIVE, sig, "v9.9.9", CLI_ASSET).is_err());
        assert!(verify(CLI_KEY, CLI_ARCHIVE, b"garbage", "v9.9.9", CLI_ASSET).is_err());
    }

    #[test]
    fn a_signature_of_another_release_is_refused() {
        let err = verify(
            CLI_KEY,
            CLI_ARCHIVE,
            CLI_SIGNATURE.as_bytes(),
            "v9.9.10",
            "envy-v9.9.10-x86_64-unknown-linux-gnu.tar.gz",
        )
        .unwrap_err();
        assert!(err.to_string().contains("another release"), "{err}");
    }

    #[test]
    fn the_test_signer_makes_valid_signatures() {
        let signer = TestSigner::new(7);
        let sig = signer.sign(b"archive", &trusted_comment("v1.0.0", "a.tar.gz"));
        verify(&signer.public_key(), b"archive", &sig, "v1.0.0", "a.tar.gz").unwrap();
    }
}
