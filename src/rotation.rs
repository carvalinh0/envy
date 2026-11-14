//! `rotate.every`: warns about values that are older than their rotation period. Envy never
//! changes a value by itself; the date comes from the vault's history.

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::{
    clock,
    envy::{Envy, GLOBAL_ENV},
    vault::{SecretVault, Version},
};

/// One message per variable of `environment` that is due, for the values stored for the
/// project (in the environment or in `global`).
pub fn overdue(
    envy: &Envy,
    vault: &dyn SecretVault,
    environment: &str,
    now: DateTime<Utc>,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    for (key, detail) in envy.effective_schema(environment)? {
        let Some(rotate) = &detail.rotate else {
            continue;
        };
        let every = clock::parse_duration(&rotate.every)?;
        let Some(version) = active_version(envy, vault, environment, &key)? else {
            continue;
        };
        match version.created_at {
            None => warnings.push(format!(
                "'{key}' in '{environment}' has no recorded change date (stored by an older Envy); rotate it every {}.",
                rotate.every
            )),
            Some(at) if now - at > every => warnings.push(format!(
                "'{key}' in '{environment}' was last changed {} ago; rotate it every {}.",
                clock::describe(now - at),
                rotate.every
            )),
            Some(_) => {}
        }
    }
    Ok(warnings)
}

fn active_version(
    envy: &Envy,
    vault: &dyn SecretVault,
    environment: &str,
    key: &str,
) -> Result<Option<Version>> {
    for source in [environment, GLOBAL_ENV] {
        let history = vault.history(&envy.id, source, key)?;
        if let Some(active) = history.into_iter().find(|version| version.active) {
            return Ok(Some(active));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::{
        envy::{RotatePolicy, Schema, VarDetail},
        schema::Secret,
        vault::{Change, MemoryVault},
    };

    fn envy() -> Envy {
        let mut envy = Envy::new("P".into(), None).unwrap();
        envy.id = "p".into();
        let rotated = |every: &str| VarDetail {
            kind: "secret".into(),
            default: None,
            rotate: Some(RotatePolicy {
                every: every.into(),
            }),
        };
        envy.schemas.insert(
            "prod".into(),
            Schema::from([
                ("OLD".to_string(), rotated("30d")),
                ("FRESH".to_string(), rotated("30d")),
                ("MISSING".to_string(), rotated("30d")),
                (
                    "NO_POLICY".to_string(),
                    VarDetail {
                        kind: "secret".into(),
                        default: None,
                        rotate: None,
                    },
                ),
            ]),
        );
        envy
    }

    #[test]
    fn only_values_older_than_their_period_are_reported() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let vault = MemoryVault::new();
        let store = |key: &str, age: Duration| {
            let change = Change {
                at: now - age,
                keep: 5,
            };
            vault
                .set("p", "prod", key, &Secret::new("v"), change)
                .unwrap();
        };
        store("OLD", Duration::days(45));
        store("FRESH", Duration::days(3));
        store("NO_POLICY", Duration::days(400));

        let warnings = overdue(&envy(), &vault, "prod", now).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("'OLD' in 'prod' was last changed 45 day(s) ago"));
    }
}
