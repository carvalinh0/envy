//! Runtime configuration.
//!
//! `FILE_NAME` (name of the manifest) and `SCHEMA_PATH` (written to the `$schema` key of new
//! manifests) are embedded at build time from this repository's own `envy.json` (see
//! `build.rs`), so installed binaries need no setup. An environment variable with the same
//! name overrides the embedded value, which is handy for development and tests.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};

use crate::workspace;

/// Name of the file that stores the active environment (kept out of Git).
pub const STATE_FILE_NAME: &str = ".envy-state";

const BUILT_FILE_NAME: Option<&str> = option_env!("ENVY_DEFAULT_FILE_NAME");
const BUILT_SCHEMA_PATH: Option<&str> = option_env!("ENVY_DEFAULT_SCHEMA_PATH");

#[derive(Debug, Clone)]
pub struct Config {
    /// Directory where Envy was started: the current directory, or the one given with `-C`.
    /// `envy init` creates the project here and `envy check --recursive` searches from here.
    pub start_dir: PathBuf,
    /// Directory of the project: where the manifest, state and `.env` files live. After
    /// [`Config::discover`] it is the nearest directory, from `start_dir` up to the
    /// repository root, that has a manifest.
    pub base_dir: PathBuf,
    /// Name of the manifest file (e.g. `envy.json`).
    pub file_name: String,
    /// Path/URL written to the `$schema` key of new manifests.
    pub schema_path: String,
    /// Whether `envy version` may look for a newer release (`ENVY_NO_UPDATE_CHECK` disables it).
    pub update_notice: bool,
}

impl Config {
    pub fn new(base_dir: impl Into<PathBuf>, file_name: &str, schema_path: &str) -> Self {
        let base_dir = base_dir.into();
        Self {
            start_dir: base_dir.clone(),
            base_dir,
            file_name: file_name.to_string(),
            schema_path: schema_path.to_string(),
            update_notice: true,
        }
    }

    /// Builds the configuration from the environment, the build-time defaults and the
    /// current directory (or `directory`, relative to it, when given with `-C`).
    pub fn from_env(directory: Option<&Path>) -> Result<Self> {
        let file_name = resolve(
            "FILE_NAME",
            std::env::var("FILE_NAME").ok(),
            BUILT_FILE_NAME,
        )?;
        let schema_path = resolve(
            "SCHEMA_PATH",
            std::env::var("SCHEMA_PATH").ok(),
            BUILT_SCHEMA_PATH,
        )?;
        let current_dir = std::env::current_dir()
            .map_err(|err| anyhow!("Could not read the current directory: {err}"))?;
        let base_dir = match directory {
            Some(directory) => {
                let dir = current_dir.join(directory);
                if !dir.is_dir() {
                    bail!("'{}' is not a directory", directory.display());
                }
                dir
            }
            None => current_dir,
        };
        let mut config = Self::new(base_dir, &file_name, &schema_path);
        config.update_notice = update_notice_enabled(std::env::var("ENVY_NO_UPDATE_CHECK").ok());
        Ok(config)
    }

    /// Moves `base_dir` to the nearest project at or above `start_dir`. Without one it is
    /// left at `start_dir`, so commands report that the manifest does not exist.
    pub fn discover(mut self) -> Self {
        if let Some(dir) = workspace::find_project_dir(&self.start_dir, &self.file_name) {
            self.base_dir = dir;
        }
        self
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.base_dir.join(&self.file_name)
    }

    pub fn state_path(&self) -> PathBuf {
        self.base_dir.join(STATE_FILE_NAME)
    }
}

/// `ENVY_NO_UPDATE_CHECK` set to anything non-empty disables the notice in `envy version`.
fn update_notice_enabled(no_update_check: Option<String>) -> bool {
    no_update_check.is_none_or(|value| value.is_empty())
}

/// The environment variable wins, then the build-time default. Empty values count as unset.
fn resolve(name: &str, from_env: Option<String>, built: Option<&str>) -> Result<String> {
    from_env
        .filter(|value| !value.is_empty())
        .or_else(|| built.filter(|value| !value.is_empty()).map(str::to_string))
        .ok_or_else(|| {
            anyhow!("{name} is not defined (neither in the environment nor at build time)")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_relative_to_base_dir() {
        let cfg = Config::new("/tmp/project", "envy.json", "schemas/v1.json");
        assert_eq!(cfg.manifest_path(), PathBuf::from("/tmp/project/envy.json"));
        assert_eq!(cfg.state_path(), PathBuf::from("/tmp/project/.envy-state"));
    }

    #[test]
    fn discover_moves_to_the_nearest_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let deep = dir.path().join("services/api/src");
        std::fs::create_dir_all(&deep).unwrap();

        let cfg = Config::new(&deep, "envy.json", "s").discover();
        assert_eq!(cfg.base_dir, deep, "without a manifest nothing changes");

        std::fs::write(dir.path().join("services/api/envy.json"), "{}").unwrap();
        let cfg = Config::new(&deep, "envy.json", "s").discover();
        assert_eq!(cfg.start_dir, deep);
        assert_eq!(cfg.base_dir, dir.path().join("services/api"));
        assert_eq!(
            cfg.state_path(),
            dir.path().join("services/api/.envy-state")
        );
    }

    #[test]
    fn environment_variable_overrides_the_build_default() {
        let value = resolve("X", Some("from-env".into()), Some("built")).unwrap();
        assert_eq!(value, "from-env");
    }

    #[test]
    fn build_default_is_used_without_an_environment_variable() {
        assert_eq!(resolve("X", None, Some("built")).unwrap(), "built");
        assert_eq!(
            resolve("X", Some(String::new()), Some("built")).unwrap(),
            "built"
        );
    }

    #[test]
    fn the_update_notice_can_be_disabled() {
        assert!(update_notice_enabled(None));
        assert!(update_notice_enabled(Some(String::new())));
        assert!(!update_notice_enabled(Some("1".into())));
        assert!(Config::new("/x", "envy.json", "s").update_notice);
    }

    #[test]
    fn missing_everywhere_is_an_error() {
        let err = resolve("FILE_NAME", None, None).unwrap_err();
        assert!(err.to_string().starts_with("FILE_NAME is not defined"));
        assert!(resolve("X", Some(String::new()), Some("")).is_err());
    }

    #[test]
    fn the_build_embeds_the_values_of_envy_json() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../envy.json")).unwrap();
        let env = if cfg!(debug_assertions) {
            "development"
        } else {
            "production"
        };
        assert_eq!(
            BUILT_FILE_NAME,
            manifest["schemas"][env]["FILE_NAME"]["default"].as_str()
        );
        assert_eq!(
            BUILT_SCHEMA_PATH,
            manifest["schemas"][env]["SCHEMA_PATH"]["default"].as_str()
        );
    }
}
