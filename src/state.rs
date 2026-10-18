//! Local state: which environment is currently active.
//!
//! The state lives in a local file that should not be committed to Git.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub trait StateStore {
    fn active(&self) -> Result<Option<String>>;
    fn set_active(&self, environment: &str) -> Result<()>;
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    active: Option<String>,
}

pub struct FileState {
    path: PathBuf,
}

impl FileState {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl StateStore for FileState {
    fn active(&self) -> Result<Option<String>> {
        if !self.path.is_file() {
            return Ok(None);
        }
        let content = fs::read_to_string(&self.path)
            .with_context(|| format!("Could not read {}", self.path.display()))?;
        let state: StateFile = serde_json::from_str(&content).with_context(|| {
            format!(
                "{} is corrupted, remove it and run `envy switch`.",
                self.path.display()
            )
        })?;
        Ok(state.active.filter(|name| !name.is_empty()))
    }

    fn set_active(&self, environment: &str) -> Result<()> {
        let state = StateFile {
            active: Some(environment.to_string()),
        };
        fs::write(&self.path, serde_json::to_string_pretty(&state)?)
            .with_context(|| format!("Could not write {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_file_means_no_active_environment() {
        let dir = tempfile::tempdir().unwrap();
        let state = FileState::new(dir.path().join(".envy-state"));
        assert_eq!(state.active().unwrap(), None);
    }

    #[test]
    fn active_environment_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".envy-state");
        FileState::new(&path).set_active("dev").unwrap();
        assert_eq!(
            FileState::new(&path).active().unwrap(),
            Some("dev".to_string())
        );
        FileState::new(&path).set_active("prod").unwrap();
        assert_eq!(
            FileState::new(&path).active().unwrap(),
            Some("prod".to_string())
        );
    }

    #[test]
    fn corrupted_file_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".envy-state");
        fs::write(&path, "not json").unwrap();
        assert!(FileState::new(&path).active().is_err());
    }
}
