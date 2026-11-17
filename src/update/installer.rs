//! Installing a new version over the running one.
//!
//! The installation method is preserved: a binary that lives in Cargo's bin folder is updated
//! with `cargo install`; any other copy is replaced with the prebuilt binary of the release.
//! If `cargo install` fails the prebuilt binary is used instead. A prebuilt binary is only
//! installed when its archive carries the minisign signature of the release key.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};

use super::{
    release::{ReleaseSource, asset_name, binary_name},
    signature::{self, RELEASE_KEY, signature_name},
};
use crate::{runner::ProcessRunner, update::archive::extract_binary};

const CRATE: &str = "dot-envy";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMethod {
    /// `cargo install` built the new version.
    Cargo,
    /// The prebuilt binary of the release replaced the current one.
    Binary,
    /// `cargo install` failed, so the prebuilt binary was used.
    BinaryAfterCargoFailed,
}

pub trait SelfUpdater {
    /// Installs the release `tag` over the running executable.
    fn apply(&self, tag: &str, releases: &dyn ReleaseSource) -> Result<UpdateMethod>;
}

pub struct SystemUpdater<'a> {
    exe: PathBuf,
    cargo_bin_dir: Option<PathBuf>,
    target: Option<&'static str>,
    runner: &'a dyn ProcessRunner,
    /// The minisign public key the archives must be signed with.
    release_key: String,
}

impl<'a> SystemUpdater<'a> {
    pub fn new(
        exe: PathBuf,
        cargo_bin_dir: Option<PathBuf>,
        target: Option<&'static str>,
        runner: &'a dyn ProcessRunner,
    ) -> Self {
        Self {
            exe,
            cargo_bin_dir,
            target,
            runner,
            release_key: RELEASE_KEY.to_string(),
        }
    }

    /// Trusts archives signed with `key` instead of [`RELEASE_KEY`] (tests, forks).
    pub fn with_release_key(mut self, key: &str) -> Self {
        self.release_key = key.to_string();
        self
    }

    /// Describes the running executable, Cargo's bin folder and the platform.
    pub fn from_environment(runner: &'a dyn ProcessRunner) -> Self {
        let exe = std::env::current_exe()
            .and_then(fs::canonicalize)
            .unwrap_or_default();
        Self::new(
            exe,
            cargo_bin_dir(),
            super::release::current_target().ok(),
            runner,
        )
    }

    fn installed_with_cargo(&self) -> bool {
        match (&self.cargo_bin_dir, self.exe.parent()) {
            (Some(bin), Some(dir)) => dir == bin,
            _ => false,
        }
    }

    fn install_binary(&self, tag: &str, releases: &dyn ReleaseSource) -> Result<()> {
        let target = self.target.ok_or_else(|| {
            anyhow!("There is no prebuilt binary for this platform. Use `cargo install {CRATE}`.")
        })?;
        if self.exe.as_os_str().is_empty() {
            return Err(anyhow!(
                "Could not find the path of the running executable."
            ));
        }

        let asset = asset_name(tag, target);
        let bytes = releases.download(tag, &asset)?;
        let signature = releases
            .download(tag, &signature_name(&asset))
            .with_context(|| {
                format!("The release {tag} has no signature for {asset}; nothing was installed.")
            })?;
        signature::verify(&self.release_key, &bytes, &signature, tag, &asset)?;
        let binary = extract_binary(&asset, &bytes, binary_name(target))?;
        replace_executable(&self.exe, &binary)
    }
}

impl SelfUpdater for SystemUpdater<'_> {
    fn apply(&self, tag: &str, releases: &dyn ReleaseSource) -> Result<UpdateMethod> {
        if self.installed_with_cargo() {
            let version = tag.trim_start_matches('v').to_string();
            let args = ["install", CRATE, "--version", version.as_str()].map(String::from);
            if matches!(self.runner.run("cargo", &args, &[]), Ok(0)) {
                return Ok(UpdateMethod::Cargo);
            }
            self.install_binary(tag, releases)?;
            return Ok(UpdateMethod::BinaryAfterCargoFailed);
        }

        self.install_binary(tag, releases)?;
        Ok(UpdateMethod::Binary)
    }
}

/// `$CARGO_HOME/bin`, or `~/.cargo/bin`.
fn cargo_bin_dir() -> Option<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|home| PathBuf::from(home).join(".cargo"))
        })?;
    let bin = home.join("bin");
    Some(fs::canonicalize(&bin).unwrap_or(bin))
}

/// Writes `new` next to `target` and moves it into place, so a failure never leaves a
/// half-written executable behind.
pub fn replace_executable(target: &Path, new: &[u8]) -> Result<()> {
    let dir = target
        .parent()
        .ok_or_else(|| anyhow!("Invalid executable path {}", target.display()))?;
    let staged = dir.join(".envy-update.tmp");

    let result = stage_and_swap(target, &staged, new);
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result.with_context(|| {
        format!(
            "Could not replace {} (do you have permission to write there?)",
            target.display()
        )
    })
}

fn stage_and_swap(target: &Path, staged: &Path, new: &[u8]) -> Result<()> {
    fs::write(staged, new)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(staged, fs::Permissions::from_mode(0o755))?;
        fs::rename(staged, target)?;
    }

    #[cfg(windows)]
    {
        // A running .exe can be renamed but not overwritten.
        let old = target.with_extension("old");
        let _ = fs::remove_file(&old);
        fs::rename(target, &old)?;
        if let Err(err) = fs::rename(staged, target) {
            let _ = fs::rename(&old, target);
            return Err(err.into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use super::*;
    use crate::{
        schema::Secret,
        update::{
            archive::tests::tar_gz,
            signature::{signature_name, tests::TestSigner, trusted_comment},
        },
    };

    #[derive(Default)]
    struct FakeReleases {
        assets: HashMap<String, Vec<u8>>,
        downloads: RefCell<Vec<String>>,
    }

    impl ReleaseSource for FakeReleases {
        fn latest_tag(&self) -> Result<String> {
            Ok("v1.0.0".into())
        }

        fn download(&self, _tag: &str, asset: &str) -> Result<Vec<u8>> {
            self.downloads.borrow_mut().push(asset.to_string());
            self.assets
                .get(asset)
                .cloned()
                .ok_or_else(|| anyhow!("404 {asset}"))
        }
    }

    struct FakeRunner {
        outcome: Result<i32, String>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        fn new(outcome: Result<i32, &str>) -> Self {
            Self {
                outcome: outcome.map_err(str::to_string),
                calls: RefCell::default(),
            }
        }
    }

    impl ProcessRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String], _envs: &[(String, Secret)]) -> Result<i32> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().cloned());
            self.calls.borrow_mut().push(call);
            self.outcome.clone().map_err(|e| anyhow!(e))
        }
    }

    const TARGET: &str = "x86_64-unknown-linux-gnu";

    fn release_signer() -> TestSigner {
        TestSigner::new(9)
    }

    /// A release whose archive is signed by `signer`.
    fn signed_release(binary: &[u8], signer: &TestSigner) -> FakeReleases {
        let asset = asset_name("v1.0.0", TARGET);
        let archive = tar_gz(&[("envy-v1.0.0-x86_64-unknown-linux-gnu/envy", binary)]);
        let signature = signer.sign(&archive, &trusted_comment("v1.0.0", &asset));
        FakeReleases {
            assets: HashMap::from([(signature_name(&asset), signature), (asset, archive)]),
            ..Default::default()
        }
    }

    fn releases_with(binary: &[u8]) -> FakeReleases {
        signed_release(binary, &release_signer())
    }

    /// An updater that trusts the test release key.
    fn updater<'a>(
        exe: PathBuf,
        cargo: Option<PathBuf>,
        runner: &'a FakeRunner,
    ) -> SystemUpdater<'a> {
        SystemUpdater::new(exe, cargo, Some(TARGET), runner)
            .with_release_key(&release_signer().public_key())
    }

    #[test]
    fn an_unsigned_release_is_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");
        let mut releases = releases_with(b"NEW");
        releases
            .assets
            .retain(|name, _| !name.ends_with(".minisig"));
        let runner = FakeRunner::new(Ok(0));
        let err = updater(exe.clone(), None, &runner)
            .apply("v1.0.0", &releases)
            .unwrap_err();
        assert!(err.to_string().contains("no signature"), "{err:#}");
        assert_eq!(fs::read(&exe).unwrap(), b"OLD");
    }

    #[test]
    fn a_release_signed_by_another_key_is_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");
        let releases = signed_release(b"NEW", &TestSigner::new(66));
        let runner = FakeRunner::new(Ok(0));
        let err = updater(exe.clone(), None, &runner)
            .apply("v1.0.0", &releases)
            .unwrap_err();
        assert!(err.to_string().contains("not valid"), "{err:#}");
        assert_eq!(fs::read(&exe).unwrap(), b"OLD");
    }

    fn installed(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"OLD").unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn replace_executable_swaps_the_content_and_keeps_it_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");

        replace_executable(&exe, b"NEW").unwrap();

        assert_eq!(fs::read(&exe).unwrap(), b"NEW");
        assert_eq!(
            fs::metadata(&exe).unwrap().permissions().mode() & 0o111,
            0o111
        );
        assert!(!dir.path().join(".envy-update.tmp").exists());
    }

    #[test]
    fn replace_executable_reports_an_unwritable_location() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("missing-dir").join("envy");
        let err = replace_executable(&exe, b"NEW").unwrap_err();
        assert!(err.to_string().contains("Could not replace"), "{err}");
    }

    #[test]
    fn binary_install_downloads_extracts_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");
        let runner = FakeRunner::new(Ok(0));
        let releases = releases_with(b"NEW-BINARY");
        let updater = updater(exe.clone(), None, &runner);

        let method = updater.apply("v1.0.0", &releases).unwrap();

        assert_eq!(method, UpdateMethod::Binary);
        assert_eq!(fs::read(&exe).unwrap(), b"NEW-BINARY");
        assert!(runner.calls.borrow().is_empty(), "cargo must not run");
        assert_eq!(
            *releases.downloads.borrow(),
            vec![
                "envy-v1.0.0-x86_64-unknown-linux-gnu.tar.gz",
                "envy-v1.0.0-x86_64-unknown-linux-gnu.tar.gz.minisig"
            ]
        );
    }

    #[test]
    fn a_cargo_install_is_updated_with_cargo() {
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");
        let runner = FakeRunner::new(Ok(0));
        let releases = releases_with(b"NEW");
        let updater = updater(exe.clone(), Some(dir.path().to_path_buf()), &runner);

        let method = updater.apply("v1.2.3", &releases).unwrap();

        assert_eq!(method, UpdateMethod::Cargo);
        assert_eq!(
            runner.calls.borrow()[0],
            vec!["cargo", "install", "dot-envy", "--version", "1.2.3"]
        );
        assert!(
            releases.downloads.borrow().is_empty(),
            "nothing is downloaded"
        );
        assert_eq!(fs::read(&exe).unwrap(), b"OLD", "cargo owns the file");
    }

    #[test]
    fn falls_back_to_the_binary_when_cargo_fails() {
        for outcome in [Ok(101), Err("cargo not found")] {
            let dir = tempfile::tempdir().unwrap();
            let exe = installed(dir.path(), "envy");
            let runner = FakeRunner::new(outcome);
            let releases = releases_with(b"NEW");
            let updater = updater(exe.clone(), Some(dir.path().to_path_buf()), &runner);

            let method = updater.apply("v1.0.0", &releases).unwrap();

            assert_eq!(method, UpdateMethod::BinaryAfterCargoFailed);
            assert_eq!(fs::read(&exe).unwrap(), b"NEW");
        }
    }

    #[test]
    fn a_failed_download_leaves_the_current_binary_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");
        let runner = FakeRunner::new(Ok(0));
        let updater = updater(exe.clone(), None, &runner);

        let err = updater
            .apply("v1.0.0", &FakeReleases::default())
            .unwrap_err();

        assert!(err.to_string().contains("404"), "{err}");
        assert_eq!(fs::read(&exe).unwrap(), b"OLD");
    }

    #[test]
    fn a_corrupted_archive_leaves_the_current_binary_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");
        let runner = FakeRunner::new(Ok(0));
        let asset = asset_name("v1.0.0", TARGET);
        let signature = release_signer().sign(b"garbage", &trusted_comment("v1.0.0", &asset));
        let releases = FakeReleases {
            assets: HashMap::from([
                (signature_name(&asset), signature),
                (asset, b"garbage".to_vec()),
            ]),
            ..Default::default()
        };
        let updater = updater(exe.clone(), None, &runner);

        let err = updater.apply("v1.0.0", &releases).unwrap_err();
        assert!(err.to_string().contains("corrupted"), "{err:#}");
        assert_eq!(fs::read(&exe).unwrap(), b"OLD");
    }

    #[test]
    fn unsupported_platforms_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let exe = installed(dir.path(), "envy");
        let runner = FakeRunner::new(Ok(0));
        let updater = SystemUpdater::new(exe, None, None, &runner);

        let err = updater
            .apply("v1.0.0", &FakeReleases::default())
            .unwrap_err();
        assert!(err.to_string().contains("no prebuilt binary"), "{err}");
    }

    #[test]
    fn cargo_detection_compares_the_executable_folder() {
        let runner = FakeRunner::new(Ok(0));
        let in_cargo = SystemUpdater::new(
            PathBuf::from("/home/u/.cargo/bin/envy"),
            Some(PathBuf::from("/home/u/.cargo/bin")),
            Some(TARGET),
            &runner,
        );
        let elsewhere = SystemUpdater::new(
            PathBuf::from("/home/u/.local/bin/envy"),
            Some(PathBuf::from("/home/u/.cargo/bin")),
            Some(TARGET),
            &runner,
        );
        let unknown = SystemUpdater::new(PathBuf::from("/x/envy"), None, Some(TARGET), &runner);

        assert!(in_cargo.installed_with_cargo());
        assert!(!elsewhere.installed_with_cargo());
        assert!(!unknown.installed_with_cargo());
    }
}
