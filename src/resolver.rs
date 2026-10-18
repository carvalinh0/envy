//! Computes the effective value of every variable of an environment.
//!
//! Precedence: vault value of the environment, then vault value of `global`
//! (when `global` declares the variable), then the same two lookups in the vault of the
//! workspace root (for a workspace member), then the default written in the manifest.
//! A value stored for the project always wins over a value stored for the workspace.

use anyhow::Result;

use crate::{
    envy::{Envy, GLOBAL_ENV},
    schema::{EnvironmentTypes, Secret},
    vault::SecretVault,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Vault,
    /// The vault of the workspace root.
    Workspace,
    Default,
}

pub struct Resolved {
    pub key: String,
    pub kind: EnvironmentTypes,
    pub value: Option<Secret>,
    pub source: Option<Source>,
}

pub struct Resolver<'a> {
    envy: &'a Envy,
    vault: &'a dyn SecretVault,
}

impl<'a> Resolver<'a> {
    pub fn new(envy: &'a Envy, vault: &'a dyn SecretVault) -> Self {
        Self { envy, vault }
    }

    pub fn resolve_all(&self, environment: &str) -> Result<Vec<Resolved>> {
        let schema = self.envy.effective_schema(environment)?;
        let mut resolved = Vec::with_capacity(schema.len());

        for (key, detail) in &schema {
            let kind = EnvironmentTypes::parse_type(&detail.kind)?;

            let mut found = self
                .lookup(self.envy, environment, key, true)?
                .map(|v| (v, Source::Vault));
            if found.is_none()
                && let Some(parent) = &self.envy.parent
            {
                found = self
                    .lookup(parent, environment, key, false)?
                    .map(|v| (v, Source::Workspace));
            }

            let (value, source) = match (found, &detail.default) {
                (Some((v, source)), _) => (Some(v), Some(source)),
                (None, Some(default)) => {
                    (Some(Secret::new(default.clone())), Some(Source::Default))
                }
                (None, None) => (None, None),
            };

            resolved.push(Resolved {
                key: key.clone(),
                kind,
                value,
                source,
            });
        }

        Ok(resolved)
    }

    /// Value stored for `project` in the environment, then in `global` when `global`
    /// declares the variable. The workspace root (`current == false`) is only asked for
    /// environments it declares, since it can hold no value for the others.
    fn lookup(
        &self,
        project: &Envy,
        environment: &str,
        key: &str,
        current: bool,
    ) -> Result<Option<Secret>> {
        if (current || project.schemas.contains_key(environment))
            && let Some(value) = self.vault.get(&project.id, environment, key)?
        {
            return Ok(Some(value));
        }
        let global_declares = environment != GLOBAL_ENV
            && project
                .effective_schema(GLOBAL_ENV)
                .is_ok_and(|global| global.contains_key(key));
        if global_declares {
            return self.vault.get(&project.id, GLOBAL_ENV, key);
        }
        Ok(None)
    }

    /// Human readable problems (missing or invalid values). Values are never included.
    /// `only` restricts the report to a single variable.
    pub fn problems(&self, environment: &str, only: Option<&str>) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        for item in self.resolve_all(environment)? {
            if only.is_some_and(|key| key != item.key) {
                continue;
            }
            match &item.value {
                None => problems.push(format!(
                    "Missing value for '{}' in '{environment}'.",
                    item.key
                )),
                Some(value) => {
                    if let Err(err) = EnvironmentTypes::validate(value.expose_secret(), item.kind) {
                        problems.push(format!(
                            "Invalid value for '{}' in '{environment}' (expected {}): {err}",
                            item.key, item.kind
                        ));
                    }
                }
            }
        }
        Ok(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        envy::{Schema, VarDetail},
        vault::MemoryVault,
    };

    fn var(kind: &str, default: Option<&str>) -> VarDetail {
        VarDetail {
            kind: kind.into(),
            default: default.map(str::to_string),
        }
    }

    fn envy() -> Envy {
        let mut envy = Envy::new("T".into(), None).unwrap();
        envy.id = "pid".into();
        envy.schemas.insert(
            "dev".into(),
            Schema::from([
                ("PORT".to_string(), var("port", Some("3000"))),
                ("TOKEN".to_string(), var("secret", None)),
            ]),
        );
        envy.schemas.insert(
            GLOBAL_ENV.into(),
            Schema::from([("REGION".to_string(), var("string", None))]),
        );
        envy
    }

    fn value_of(items: &[Resolved], key: &str) -> Option<String> {
        items
            .iter()
            .find(|i| i.key == key)
            .and_then(|i| i.value.as_ref().map(|v| v.expose_secret().to_string()))
    }

    #[test]
    fn default_is_used_when_the_vault_is_empty() {
        let vault = MemoryVault::new();
        let envy = envy();
        let items = Resolver::new(&envy, &vault).resolve_all("dev").unwrap();
        assert_eq!(value_of(&items, "PORT").as_deref(), Some("3000"));
        assert_eq!(
            items.iter().find(|i| i.key == "PORT").unwrap().source,
            Some(Source::Default)
        );
        assert_eq!(value_of(&items, "TOKEN"), None);
    }

    #[test]
    fn vault_overrides_the_default() {
        let vault = MemoryVault::new();
        vault
            .set("pid", "dev", "PORT", &Secret::new("4000"))
            .unwrap();
        let envy = envy();
        let items = Resolver::new(&envy, &vault).resolve_all("dev").unwrap();
        assert_eq!(value_of(&items, "PORT").as_deref(), Some("4000"));
    }

    #[test]
    fn global_vault_value_is_inherited() {
        let vault = MemoryVault::new();
        vault
            .set("pid", GLOBAL_ENV, "REGION", &Secret::new("sa-east-1"))
            .unwrap();
        let envy = envy();
        let items = Resolver::new(&envy, &vault).resolve_all("dev").unwrap();
        assert_eq!(value_of(&items, "REGION").as_deref(), Some("sa-east-1"));

        vault
            .set("pid", "dev", "REGION", &Secret::new("us-east-1"))
            .unwrap();
        let items = Resolver::new(&envy, &vault).resolve_all("dev").unwrap();
        assert_eq!(value_of(&items, "REGION").as_deref(), Some("us-east-1"));
    }

    #[test]
    fn problems_report_missing_and_invalid_values_without_leaking() {
        let vault = MemoryVault::new();
        vault
            .set("pid", "dev", "PORT", &Secret::new("hunter2"))
            .unwrap();
        let envy = envy();
        let problems = Resolver::new(&envy, &vault).problems("dev", None).unwrap();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(
            problems
                .iter()
                .any(|p| p.contains("Missing value for 'TOKEN'"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("Missing value for 'REGION'"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("Invalid value for 'PORT'"))
        );
        assert!(problems.iter().all(|p| !p.contains("hunter2")));
    }

    #[test]
    fn problems_can_be_limited_to_one_variable() {
        let vault = MemoryVault::new();
        let envy = envy();
        let problems = Resolver::new(&envy, &vault)
            .problems("dev", Some("TOKEN"))
            .unwrap();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("'TOKEN'"));
    }

    fn member() -> Envy {
        let mut member = Envy::new("M".into(), None).unwrap();
        member.id = "member".into();
        member.schemas.insert(
            "dev".into(),
            Schema::from([("PORT".to_string(), var("port", Some("4000")))]),
        );
        member.parent = Some(Box::new(envy()));
        member
    }

    #[test]
    fn a_member_reads_the_values_of_the_workspace_root() {
        let vault = MemoryVault::new();
        vault
            .set("pid", "dev", "TOKEN", &Secret::new("root-token"))
            .unwrap();
        vault
            .set("pid", GLOBAL_ENV, "REGION", &Secret::new("sa-east-1"))
            .unwrap();
        let member = member();
        let items = Resolver::new(&member, &vault).resolve_all("dev").unwrap();

        assert_eq!(value_of(&items, "TOKEN").as_deref(), Some("root-token"));
        assert_eq!(value_of(&items, "REGION").as_deref(), Some("sa-east-1"));
        assert_eq!(value_of(&items, "PORT").as_deref(), Some("4000"));
        let token = items.iter().find(|i| i.key == "TOKEN").unwrap();
        assert_eq!(token.source, Some(Source::Workspace));
    }

    #[test]
    fn the_values_of_the_member_win_over_the_workspace() {
        let vault = MemoryVault::new();
        vault
            .set("pid", "dev", "TOKEN", &Secret::new("root-token"))
            .unwrap();
        vault
            .set("pid", GLOBAL_ENV, "REGION", &Secret::new("root-region"))
            .unwrap();
        vault
            .set("member", "dev", "TOKEN", &Secret::new("own-token"))
            .unwrap();
        // `envy set global REGION` in the member: REGION is declared only by the root.
        vault
            .set("member", GLOBAL_ENV, "REGION", &Secret::new("own-region"))
            .unwrap();
        let member = member();
        let items = Resolver::new(&member, &vault).resolve_all("dev").unwrap();

        assert_eq!(value_of(&items, "TOKEN").as_deref(), Some("own-token"));
        assert_eq!(value_of(&items, "REGION").as_deref(), Some("own-region"));
        assert_eq!(
            items.iter().find(|i| i.key == "TOKEN").unwrap().source,
            Some(Source::Vault)
        );
    }

    #[test]
    fn a_member_resolves_an_environment_only_the_root_declares() {
        let vault = MemoryVault::new();
        let mut root = envy();
        root.schemas.insert(
            "prod".into(),
            Schema::from([("DB".to_string(), var("url", None))]),
        );
        vault
            .set("pid", "prod", "DB", &Secret::new("postgres://db"))
            .unwrap();
        let mut member = member();
        member.parent = Some(Box::new(root));

        let items = Resolver::new(&member, &vault).resolve_all("prod").unwrap();
        assert_eq!(value_of(&items, "DB").as_deref(), Some("postgres://db"));
        assert!(items.iter().any(|i| i.key == "REGION"));
        assert!(!items.iter().any(|i| i.key == "PORT"));
    }

    #[test]
    fn unknown_environment_is_an_error() {
        let vault = MemoryVault::new();
        let envy = envy();
        assert!(Resolver::new(&envy, &vault).resolve_all("nope").is_err());
    }
}
