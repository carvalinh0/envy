//! The `.envy` manifest (`envy.json`): project identity, version, checksum and the
//! typed schema of every environment.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::schema::EnvironmentTypes;

/// Environment whose variables are shared by every other environment.
pub const GLOBAL_ENV: &str = "global";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VarDetail {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

pub type Schema = BTreeMap<String, VarDetail>;

/// Makes a manifest the root of a monorepo: the projects matched by `members` inherit its
/// environments and variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    /// Paths relative to the root, with `*`, `?` and `**` wildcards (e.g. `services/*`).
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envy {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub id: String,
    pub name: String,
    pub version: i32,
    pub checksum: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceConfig>,
    pub schemas: BTreeMap<String, Schema>,
    /// Workspace root this project inherits from. Found at runtime, never written to disk.
    #[serde(skip)]
    pub parent: Option<Box<Envy>>,
}

impl Envy {
    pub fn new(name: String, schema_path: Option<String>) -> Result<Self> {
        let mut envy = Self {
            schema: schema_path,
            id: Uuid::new_v4().to_string(),
            name,
            version: 1,
            checksum: String::new(),
            workspace: None,
            schemas: BTreeMap::new(),
            parent: None,
        };

        envy.checksum = envy.compute_checksum()?;
        Ok(envy)
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Could not read {}", path.display()))?;

        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}, check its structure.", path.display()))
    }

    /// Writes the formatted manifest to `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).with_context(|| format!("Could not write {}", path.display()))
    }

    /// SHA3-256 of every field that makes up the manifest, except the checksum itself.
    pub fn compute_checksum(&self) -> Result<String> {
        let base = (
            &self.schema,
            &self.id,
            &self.name,
            &self.version,
            &self.schemas,
        );
        // Manifests without a workspace hash exactly as before the field existed, so their
        // checksums stay valid.
        let bytes = match &self.workspace {
            None => serde_json::to_vec(&base)?,
            Some(workspace) => serde_json::to_vec(&(base, workspace))?,
        };

        let digest = Sha3_256::digest(&bytes);
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// `true` when the stored checksum matches the content (no manual/external edits).
    pub fn is_checksum_valid(&self) -> Result<bool> {
        Ok(self.checksum == self.compute_checksum()?)
    }

    /// Registers a structural change: bumps the version and recalculates the checksum.
    pub fn commit_change(&mut self) -> Result<()> {
        self.version += 1;
        self.checksum = self.compute_checksum()?;
        Ok(())
    }

    /// Detects manual/external edits. When found, bumps the version and refreshes the
    /// checksum. Returns whether anything changed.
    pub fn sync(&mut self) -> Result<bool> {
        if self.is_checksum_valid()? {
            return Ok(false);
        }
        self.commit_change()?;
        Ok(true)
    }

    /// Whether the environment is declared here or inherited from the workspace root.
    pub fn has_environment(&self, environment: &str) -> bool {
        self.schemas.contains_key(environment)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.has_environment(environment))
    }

    /// Own and inherited environments, sorted and without repetitions.
    pub fn environment_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.schemas.keys().map(String::as_str).collect();
        if let Some(parent) = &self.parent {
            names.extend(parent.environment_names());
        }
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Whether `key` is declared for `environment` by the workspace root (and not by this
    /// project), so it can only be changed from the root.
    pub fn is_inherited(&self, environment: &str, key: &str) -> bool {
        let own = self
            .schemas
            .get(environment)
            .is_some_and(|s| s.contains_key(key));
        !own && self
            .parent
            .as_ref()
            .and_then(|parent| parent.effective_schema(environment).ok())
            .is_some_and(|schema| schema.contains_key(key))
    }

    /// Creates an empty environment and bumps the version. An environment inherited from
    /// the workspace root can be created to add or override variables for this project.
    pub fn add_environment(&mut self, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("The environment name can't be empty.");
        }
        if self.schemas.contains_key(name) {
            bail!("The environment '{name}' already exists.");
        }
        self.schemas.insert(name.to_string(), Schema::new());
        self.commit_change()
    }

    /// Variables of an environment. From the weakest to the strongest layer: the workspace
    /// root's `global`, the root's environment, this project's `global` and this project's
    /// environment. A later layer replaces the declaration of an earlier one.
    pub fn effective_schema(&self, environment: &str) -> Result<Schema> {
        if !self.has_environment(environment) {
            bail!("There's no environment called '{environment}'");
        }

        let mut merged = match &self.parent {
            Some(parent) => parent.inheritable_schema(environment),
            None => Schema::new(),
        };
        if environment != GLOBAL_ENV
            && let Some(global) = self.schemas.get(GLOBAL_ENV)
        {
            merged.extend(global.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        if let Some(own) = self.schemas.get(environment) {
            merged.extend(own.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        Ok(merged)
    }

    /// What a workspace member inherits for `environment`: the environment (merged with
    /// `global`) when the root declares it, otherwise only the root's `global`.
    fn inheritable_schema(&self, environment: &str) -> Schema {
        self.effective_schema(environment)
            .or_else(|_| self.effective_schema(GLOBAL_ENV))
            .unwrap_or_default()
    }

    /// Declaration of `key` for `environment`, falling back to `global`.
    pub fn declaration(&self, environment: &str, key: &str) -> Result<VarDetail> {
        match self.effective_schema(environment)?.remove(key) {
            Some(detail) => Ok(detail),
            None => bail!("There's no variable called '{key}' in environment '{environment}'."),
        }
    }

    /// Removes `key` from the environment's own schema and bumps the version.
    pub fn remove_variable(&mut self, environment: &str, key: &str) -> Result<()> {
        let Some(schema) = self.schemas.get_mut(environment) else {
            bail!("There's no environment called '{environment}'");
        };
        if schema.remove(key).is_none() {
            bail!("There's no variable called '{key}' in environment '{environment}'.");
        }
        self.commit_change()
    }

    /// Renames `old` to `new` inside the environment's own schema and bumps the version.
    pub fn rename_variable(&mut self, environment: &str, old: &str, new: &str) -> Result<()> {
        if new.trim().is_empty() {
            bail!("The new variable name can't be empty.");
        }
        let Some(schema) = self.schemas.get_mut(environment) else {
            bail!("There's no environment called '{environment}'");
        };
        if schema.contains_key(new) {
            bail!("The variable '{new}' already exists in environment '{environment}'.");
        }
        let Some(detail) = schema.remove(old) else {
            bail!("There's no variable called '{old}' in environment '{environment}'.");
        };
        schema.insert(new.to_string(), detail);
        self.commit_change()
    }

    /// Structural validation of the manifest.
    pub fn check_schema(&self, environment: Option<&str>, variable: Option<&str>) -> Result<()> {
        if self.id.is_empty() {
            bail!("Project's id can't be empty!")
        }
        if self.version <= 0 {
            bail!("Project's version can't be 0!")
        }
        if self.checksum.is_empty() {
            bail!("Project's checksum can't be empty!")
        }
        if let Some(workspace) = &self.workspace {
            Self::check_workspace(workspace)?;
        }

        let envs_to_check: Vec<(&String, &Schema)> = match environment {
            Some(env_name) => match self.schemas.get_key_value(env_name) {
                Some((name, schema)) => vec![(name, schema)],
                None => bail!("There's no environment called '{env_name}'"),
            },
            None => self.schemas.iter().collect(),
        };

        for (env_name, schema) in envs_to_check {
            if env_name.is_empty() {
                bail!("There is an empty environment name in the manifest.");
            }

            let vars_to_check: Vec<(&String, &VarDetail)> = match variable {
                Some(var_name) => match schema.get_key_value(var_name) {
                    Some((name, detail)) => vec![(name, detail)],
                    None => bail!(
                        "There's no variable called '{var_name}' in environment '{env_name}'."
                    ),
                },
                None => schema.iter().collect(),
            };

            for (key, detail) in vars_to_check {
                Self::check_variable(env_name, key, detail)?;
            }
        }

        Ok(())
    }

    fn check_workspace(workspace: &WorkspaceConfig) -> Result<()> {
        for member in &workspace.members {
            if member.trim().is_empty() {
                bail!("There is an empty path in workspace.members.");
            }
            if member.starts_with('/') || member.contains('\\') || member.contains(':') {
                bail!(
                    "The workspace member '{member}' must be a relative path with '/' separators."
                );
            }
            if member.split('/').any(|segment| segment == "..") {
                bail!(
                    "The workspace member '{member}' can not point outside the workspace ('..')."
                );
            }
        }
        Ok(())
    }

    fn check_variable(env_name: &str, key: &str, detail: &VarDetail) -> Result<()> {
        if key.is_empty() {
            bail!("There is an empty key inside '{env_name}' environment.");
        }

        if detail.kind.is_empty() {
            bail!("You need to specify a type in '{key}' (environment '{env_name}').");
        }
        let kind = EnvironmentTypes::parse_type(&detail.kind)
            .with_context(|| format!("Invalid type in '{key}' (environment '{env_name}')"))?;

        let Some(default) = &detail.default else {
            return Ok(());
        };

        if default.is_empty() {
            bail!("Key '{key}' in '{env_name}' can not have empty default values.");
        }
        if kind == EnvironmentTypes::Secret {
            bail!(
                "Key '{key}' in '{env_name}' is a secret and can not have a default value, \
                 it would be committed to Git."
            );
        }
        EnvironmentTypes::validate(default, kind).map_err(|err| {
            anyhow::anyhow!("The default of '{key}' in '{env_name}' is not a valid {kind}: {err}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(kind: &str, default: Option<&str>) -> VarDetail {
        VarDetail {
            kind: kind.to_string(),
            default: default.map(str::to_string),
        }
    }

    fn sample() -> Envy {
        let mut envy = Envy::new("Sample".into(), Some("schemas/v1.json".into())).unwrap();
        envy.schemas.insert(
            "dev".into(),
            Schema::from([
                ("PORT".to_string(), var("port", Some("3000"))),
                ("DB_URL".to_string(), var("url", None)),
            ]),
        );
        envy.schemas.insert(
            "prod".into(),
            Schema::from([("DB_URL".to_string(), var("url", None))]),
        );
        envy.schemas.insert(
            GLOBAL_ENV.into(),
            Schema::from([("APP".to_string(), var("string", Some("envy")))]),
        );
        envy.checksum = envy.compute_checksum().unwrap();
        envy
    }

    fn bare(version: i32, id: &str, checksum: &str) -> Envy {
        Envy {
            schema: None,
            id: id.to_string(),
            name: String::new(),
            version,
            checksum: checksum.to_string(),
            workspace: None,
            schemas: BTreeMap::new(),
            parent: None,
        }
    }

    #[test]
    fn empty_project_id() {
        let err = bare(1, "", "").check_schema(None, None).unwrap_err();
        assert_eq!(err.to_string(), "Project's id can't be empty!");
    }

    #[test]
    fn project_version_equals_zero() {
        let err = bare(0, "id", "").check_schema(None, None).unwrap_err();
        assert_eq!(err.to_string(), "Project's version can't be 0!");
    }

    #[test]
    fn empty_project_checksum() {
        let err = bare(1, "id", "").check_schema(None, None).unwrap_err();
        assert_eq!(err.to_string(), "Project's checksum can't be empty!");
    }

    #[test]
    fn empty_environment_name() {
        let mut envy = sample();
        envy.schemas.insert(String::new(), Schema::new());
        let err = envy.check_schema(None, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "There is an empty environment name in the manifest."
        );
    }

    #[test]
    fn empty_environment_key() {
        let mut envy = sample();
        envy.schemas.insert(
            "test".into(),
            Schema::from([(String::new(), var("string", None))]),
        );
        let err = envy.check_schema(None, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "There is an empty key inside 'test' environment."
        );
    }

    #[test]
    fn empty_default_value() {
        let mut envy = sample();
        envy.schemas.insert(
            "test".into(),
            Schema::from([("MY_VAR".into(), var("string", Some("")))]),
        );
        let err = envy.check_schema(None, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Key 'MY_VAR' in 'test' can not have empty default values."
        );
    }

    #[test]
    fn empty_type() {
        let mut envy = sample();
        envy.schemas.insert(
            "test".into(),
            Schema::from([("MY_VAR".into(), var("", None))]),
        );
        let err = envy.check_schema(None, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "You need to specify a type in 'MY_VAR' (environment 'test')."
        );
    }

    #[test]
    fn unknown_type() {
        let mut envy = sample();
        envy.schemas.insert(
            "test".into(),
            Schema::from([("MY_VAR".into(), var("text", None))]),
        );
        let err = envy.check_schema(None, None).unwrap_err();
        assert!(format!("{err:#}").contains("'text' is not a valid type."));
    }

    #[test]
    fn default_must_match_the_type() {
        let mut envy = sample();
        envy.schemas.insert(
            "test".into(),
            Schema::from([("PORT".into(), var("port", Some("abc")))]),
        );
        let err = envy.check_schema(None, None).unwrap_err();
        assert!(err.to_string().contains("not a valid port"));
    }

    #[test]
    fn secrets_can_not_have_defaults() {
        let mut envy = sample();
        envy.schemas.insert(
            "test".into(),
            Schema::from([("TOKEN".into(), var("secret", Some("x")))]),
        );
        let err = envy.check_schema(None, None).unwrap_err();
        assert!(err.to_string().contains("can not have a default value"));
    }

    #[test]
    fn environment_does_not_exist() {
        let err = sample().check_schema(Some("nope"), None).unwrap_err();
        assert_eq!(err.to_string(), "There's no environment called 'nope'");
    }

    #[test]
    fn environment_secret_does_not_exist() {
        let err = sample()
            .check_schema(Some("dev"), Some("NOPE"))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "There's no variable called 'NOPE' in environment 'dev'."
        );
    }

    #[test]
    fn valid_manifest_passes() {
        let envy = sample();
        envy.check_schema(None, None).unwrap();
        envy.check_schema(Some("dev"), None).unwrap();
        envy.check_schema(Some("dev"), Some("PORT")).unwrap();
    }

    #[test]
    fn file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("envy.json");
        fs::write(&path, "").unwrap();
        let err = Envy::load_from_file(&path).unwrap_err();
        assert!(err.to_string().contains("Failed to parse"));
    }

    #[test]
    fn file_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let err = Envy::load_from_file(&dir.path().join("missing.json")).unwrap_err();
        assert!(err.to_string().contains("Could not read"));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("envy.json");
        let envy = sample();
        envy.save(&path).unwrap();
        let loaded = Envy::load_from_file(&path).unwrap();
        assert_eq!(loaded.id, envy.id);
        assert_eq!(loaded.schemas, envy.schemas);
        assert!(loaded.is_checksum_valid().unwrap());
    }

    #[test]
    fn new_manifest_has_valid_checksum_and_version_one() {
        let envy = Envy::new("P".into(), None).unwrap();
        assert_eq!(envy.version, 1);
        assert!(envy.is_checksum_valid().unwrap());
        assert!(!envy.id.is_empty());
    }

    #[test]
    fn checksum_changes_with_content() {
        let mut envy = sample();
        let before = envy.compute_checksum().unwrap();
        envy.name = "Other".into();
        assert_ne!(before, envy.compute_checksum().unwrap());
    }

    #[test]
    fn sync_detects_manual_edits_and_bumps_version() {
        let mut envy = sample();
        assert!(!envy.sync().unwrap());
        assert_eq!(envy.version, 1);

        envy.schemas
            .get_mut("dev")
            .unwrap()
            .insert("NEW".into(), var("string", None));
        assert!(envy.sync().unwrap());
        assert_eq!(envy.version, 2);
        assert!(envy.is_checksum_valid().unwrap());
        assert!(!envy.sync().unwrap());
    }

    #[test]
    fn effective_schema_merges_global_and_lets_environment_override() {
        let mut envy = sample();
        envy.schemas
            .get_mut("dev")
            .unwrap()
            .insert("APP".into(), var("string", Some("override")));
        let merged = envy.effective_schema("dev").unwrap();
        assert_eq!(merged["APP"].default.as_deref(), Some("override"));
        assert!(merged.contains_key("PORT"));
        assert_eq!(
            envy.effective_schema("prod").unwrap()["APP"]
                .default
                .as_deref(),
            Some("envy")
        );
        assert_eq!(envy.effective_schema(GLOBAL_ENV).unwrap().len(), 1);
        assert!(envy.effective_schema("nope").is_err());
    }

    #[test]
    fn declaration_falls_back_to_global() {
        let envy = sample();
        assert_eq!(envy.declaration("dev", "APP").unwrap().kind, "string");
        assert!(envy.declaration("dev", "NOPE").is_err());
    }

    #[test]
    fn add_environment_bumps_version() {
        let mut envy = sample();
        envy.add_environment("staging").unwrap();
        assert!(envy.has_environment("staging"));
        assert_eq!(envy.version, 2);
        assert!(envy.is_checksum_valid().unwrap());
        assert!(envy.add_environment("staging").is_err());
        assert!(envy.add_environment("  ").is_err());
    }

    #[test]
    fn remove_variable_bumps_version() {
        let mut envy = sample();
        envy.remove_variable("dev", "PORT").unwrap();
        assert!(!envy.schemas["dev"].contains_key("PORT"));
        assert_eq!(envy.version, 2);
        assert!(envy.remove_variable("dev", "PORT").is_err());
        assert!(envy.remove_variable("nope", "PORT").is_err());
    }

    #[test]
    fn rename_variable_keeps_the_declaration() {
        let mut envy = sample();
        envy.rename_variable("dev", "PORT", "HTTP_PORT").unwrap();
        assert_eq!(
            envy.schemas["dev"]["HTTP_PORT"].default.as_deref(),
            Some("3000")
        );
        assert!(!envy.schemas["dev"].contains_key("PORT"));
        assert_eq!(envy.version, 2);
    }

    #[test]
    fn rename_variable_rejects_bad_requests() {
        let mut envy = sample();
        assert!(envy.rename_variable("dev", "PORT", "DB_URL").is_err());
        assert!(envy.rename_variable("dev", "NOPE", "X").is_err());
        assert!(envy.rename_variable("nope", "PORT", "X").is_err());
        assert!(envy.rename_variable("dev", "PORT", "").is_err());
        assert_eq!(envy.version, 1);
    }

    fn member_of(root: Envy) -> Envy {
        let mut member = Envy::new("Member".into(), None).unwrap();
        member.schemas.insert(
            "dev".into(),
            Schema::from([("PORT".to_string(), var("port", Some("4000")))]),
        );
        member.parent = Some(Box::new(root));
        member
    }

    #[test]
    fn a_member_inherits_the_environments_and_variables_of_the_root() {
        let member = member_of(sample());

        assert!(member.has_environment("dev"));
        assert!(member.has_environment("prod"));
        assert_eq!(member.environment_names(), vec!["dev", GLOBAL_ENV, "prod"]);

        let dev = member.effective_schema("dev").unwrap();
        assert_eq!(dev["PORT"].default.as_deref(), Some("4000"), "own wins");
        assert!(dev.contains_key("DB_URL"));
        assert!(dev.contains_key("APP"));

        let prod = member.effective_schema("prod").unwrap();
        assert_eq!(prod.keys().collect::<Vec<_>>(), vec!["APP", "DB_URL"]);
        assert!(member.effective_schema("nope").is_err());

        assert!(member.is_inherited("dev", "DB_URL"));
        assert!(!member.is_inherited("dev", "PORT"));
        assert!(!member.is_inherited("dev", "NOPE"));
    }

    #[test]
    fn the_root_global_reaches_environments_the_root_does_not_declare() {
        let mut member = member_of(sample());
        member.schemas.insert("qa".into(), Schema::new());
        let qa = member.effective_schema("qa").unwrap();
        assert_eq!(qa.keys().collect::<Vec<_>>(), vec!["APP"]);
    }

    #[test]
    fn a_member_can_create_an_inherited_environment_to_override_it() {
        let mut member = member_of(sample());
        member.add_environment("prod").unwrap();
        assert!(member.add_environment("prod").is_err());
    }

    #[test]
    fn the_parent_is_never_saved_nor_part_of_the_checksum() {
        let mut alone = Envy::new("Member".into(), None).unwrap();
        let before = alone.compute_checksum().unwrap();
        alone.parent = Some(Box::new(sample()));
        assert_eq!(alone.compute_checksum().unwrap(), before);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("envy.json");
        alone.save(&path).unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("parent"));
    }

    #[test]
    fn manifests_without_a_workspace_keep_their_checksum() {
        // Checksum of `sample()` before the workspace field existed: the hash of the
        // (schema, id, name, version, schemas) tuple.
        let envy = sample();
        let legacy = {
            let payload = (
                &envy.schema,
                &envy.id,
                &envy.name,
                &envy.version,
                &envy.schemas,
            );
            let digest = Sha3_256::digest(serde_json::to_vec(&payload).unwrap());
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(envy.compute_checksum().unwrap(), legacy);

        let mut root = sample();
        root.workspace = Some(WorkspaceConfig {
            members: vec!["services/*".into()],
        });
        assert_ne!(root.compute_checksum().unwrap(), legacy);
    }

    #[test]
    fn workspace_members_are_validated() {
        let mut root = sample();
        for (member, message) in [
            ("", "empty path"),
            ("/abs", "relative path"),
            ("a\\b", "relative path"),
            ("../other", "outside the workspace"),
            ("a/../../b", "outside the workspace"),
        ] {
            root.workspace = Some(WorkspaceConfig {
                members: vec![member.into()],
            });
            let err = root.check_schema(None, None).unwrap_err().to_string();
            assert!(err.contains(message), "{member}: {err}");
        }
        root.workspace = Some(WorkspaceConfig {
            members: vec!["services/*".into(), "apps/web".into()],
        });
        root.check_schema(None, None).unwrap();

        let json = serde_json::to_string(&root).unwrap();
        let loaded: Envy = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.workspace, root.workspace);
    }
}
