//! Which backend holds each project's values.
//!
//! The choice belongs to each user, never to the repository: `envy migrate` writes it to
//! `{data dir}/backends.json`. `--backend` and `ENVY_BACKEND` win over it, and a project
//! with no choice uses the keyring, exactly like the releases before backends existed.
//! [`Backends`] routes every vault call by project id, so a workspace member and its root
//! may live in different backends.

use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    cli::Backend,
    remote::client::RemoteVault,
    schema::Secret,
    vault::{Change, CredentialStore, EncryptedFileVault, SecretVault, Version},
};

pub trait BackendStore {
    fn chosen(&self, project: &str) -> Result<Option<Backend>>;
    /// `None` forgets the choice, so the project goes back to the default.
    fn choose(&self, project: &str, backend: Option<Backend>) -> Result<()>;
    /// The server of a project, recorded by `envy login`.
    fn remote_url(&self, project: &str) -> Result<Option<String>>;
    fn set_remote_url(&self, project: &str, url: Option<&str>) -> Result<()>;
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Choices {
    #[serde(default)]
    projects: BTreeMap<String, Backend>,
    /// Added in 4.0; older files have none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    remotes: BTreeMap<String, String>,
}

/// The choices of the user, in their data folder.
pub struct FileBackends {
    path: Option<PathBuf>,
}

impl FileBackends {
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        Self {
            path: data_dir.map(|dir| dir.join("backends.json")),
        }
    }

    fn load(&self) -> Result<Choices> {
        let Some(path) = self.path.as_ref().filter(|path| path.is_file()) else {
            return Ok(Choices::default());
        };
        let content = fs::read_to_string(path)
            .with_context(|| format!("Could not read {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("{} is corrupted; fix or remove it.", path.display()))
    }
}

impl FileBackends {
    fn save(&self, change: impl FnOnce(&mut Choices)) -> Result<()> {
        let Some(path) = &self.path else {
            bail!(
                "Envy found no folder for its data (set HOME, or LOCALAPPDATA on Windows), so it can't remember the backend."
            );
        };
        let mut choices = self.load()?;
        change(&mut choices);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("Could not create {}", dir.display()))?;
        }
        fs::write(path, serde_json::to_string_pretty(&choices)?)
            .with_context(|| format!("Could not write {}", path.display()))
    }
}

impl BackendStore for FileBackends {
    fn chosen(&self, project: &str) -> Result<Option<Backend>> {
        Ok(self.load()?.projects.get(project).copied())
    }

    fn choose(&self, project: &str, backend: Option<Backend>) -> Result<()> {
        self.save(|choices| {
            match backend {
                Some(backend) => choices.projects.insert(project.to_string(), backend),
                None => choices.projects.remove(project),
            };
        })
    }

    fn remote_url(&self, project: &str) -> Result<Option<String>> {
        Ok(self.load()?.remotes.get(project).cloned())
    }

    fn set_remote_url(&self, project: &str, url: Option<&str>) -> Result<()> {
        self.save(|choices| {
            match url {
                Some(url) => choices.remotes.insert(project.to_string(), url.to_string()),
                None => choices.remotes.remove(project),
            };
        })
    }
}

/// Every backend, and the rule that picks one per project. It is itself a vault, so the
/// commands and the resolver need not know where a value lives.
pub struct Backends<'a> {
    pub keyring: &'a dyn SecretVault,
    pub file: &'a EncryptedFileVault<'a>,
    pub remote: &'a RemoteVault<'a>,
    /// Where `envy login` keeps the member identities (the OS keyring).
    pub identities: &'a dyn CredentialStore,
    pub choices: &'a dyn BackendStore,
    /// `--backend` or `ENVY_BACKEND`.
    pub forced: Option<Backend>,
}

impl Backends<'_> {
    pub fn current(&self, project: &str) -> Result<Backend> {
        if let Some(forced) = self.forced {
            return Ok(forced);
        }
        Ok(self.choices.chosen(project)?.unwrap_or(Backend::Keyring))
    }

    pub fn vault(&self, backend: Backend) -> &dyn SecretVault {
        match backend {
            Backend::Keyring => self.keyring,
            Backend::File => self.file,
            Backend::Remote => self.remote,
        }
    }

    fn route(&self, project: &str) -> Result<&dyn SecretVault> {
        Ok(self.vault(self.current(project)?))
    }
}

impl SecretVault for Backends<'_> {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>> {
        self.route(project)?.get(project, environment, key)
    }

    fn set(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        value: &Secret,
        change: Change,
    ) -> Result<()> {
        self.route(project)?
            .set(project, environment, key, value, change)
    }

    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool> {
        self.route(project)?.delete(project, environment, key)
    }

    fn history(&self, project: &str, environment: &str, key: &str) -> Result<Vec<Version>> {
        self.route(project)?.history(project, environment, key)
    }

    fn get_version(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        number: u32,
    ) -> Result<Option<Secret>> {
        self.route(project)?
            .get_version(project, environment, key, number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choices_are_remembered_per_project() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileBackends::new(Some(dir.path().to_path_buf()));
        assert_eq!(store.chosen("a").unwrap(), None);

        store.choose("a", Some(Backend::File)).unwrap();
        store.choose("b", Some(Backend::Keyring)).unwrap();
        assert_eq!(store.chosen("a").unwrap(), Some(Backend::File));
        assert_eq!(store.chosen("b").unwrap(), Some(Backend::Keyring));

        store.choose("a", None).unwrap();
        assert_eq!(store.chosen("a").unwrap(), None);
        let saved = fs::read_to_string(dir.path().join("backends.json")).unwrap();
        assert!(saved.contains("\"b\": \"keyring\""), "{saved}");
    }

    #[test]
    fn without_a_data_folder_nothing_is_chosen_and_nothing_can_be() {
        let store = FileBackends::new(None);
        assert_eq!(store.chosen("a").unwrap(), None);
        assert!(store.choose("a", Some(Backend::File)).is_err());
    }
}
