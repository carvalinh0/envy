use std::io::Write;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};

use super::vault::{new_password, new_recovery_key};
use crate::{
    cli::{Backend, MigrateArgs},
    context::Context,
    envy::Envy,
    protect::CHECK_SLOT,
    vault::{Change, SecretVault},
};

/// Copies every value and its versions, checks the copy, and only then switches the project
/// to the new backend. The source is only emptied with `--remove-source`.
pub fn run(ctx: &Context, args: &MigrateArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let from = ctx.backends.current(&envy.id)?;
    let to = args.to;
    if from == to {
        bail!("This project already uses the {} backend.", to.name());
    }
    if to == Backend::Remote {
        bail!("The remote backend is not available in this version of Envy.");
    }
    if to == Backend::File && !ctx.backends.file.exists(&envy.id) {
        create_file_vault(ctx, &envy, out)?;
    }

    let (source, target) = (ctx.backends.vault(from), ctx.backends.vault(to));
    let now = ctx.clock.now();
    let mut copied = Vec::new();
    for (environment, key) in slots(&envy)? {
        let moved = Move {
            project: &envy.id,
            environment: &environment,
            key: &key,
        };
        if moved.copy(source, target, envy.history_keep(), now)? {
            copied.push((environment, key));
        }
    }

    let choice = (to != Backend::Keyring).then_some(to);
    ctx.backends.choices.choose(&envy.id, choice)?;
    if args.remove_source {
        for (environment, key) in &copied {
            source.delete(&envy.id, environment, key)?;
        }
    }

    let values = copied.iter().filter(|(_, key)| key != CHECK_SLOT).count();
    ctx.record(
        &envy,
        "migrate",
        None,
        vec![format!("{} -> {}", from.name(), to.name())],
    )?;
    writeln!(
        out,
        "Copied {values} value(s) and their history from the {} backend to the {} backend; this project now uses the {} backend on this machine.",
        from.name(),
        to.name(),
        to.name()
    )?;
    if !args.remove_source {
        writeln!(
            out,
            "The {} backend still holds them: run again with --remove-source to delete them there.",
            from.name()
        )?;
    }
    Ok(())
}

fn create_file_vault(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<()> {
    writeln!(out, "Creating the file vault of '{}'.", envy.name)?;
    let password = new_password(ctx, true)?;
    let recovery = new_recovery_key(ctx, out)?;
    ctx.backends.file.create(&envy.id, &password, &recovery)?;
    ctx.record(envy, "vault-create", None, Vec::new())
}

/// Every stored value a project can have: each variable of each environment, plus the
/// password check of protected environments.
fn slots(envy: &Envy) -> Result<Vec<(String, String)>> {
    let mut slots = Vec::new();
    for environment in envy.environment_names() {
        slots.push((environment.to_string(), CHECK_SLOT.to_string()));
        for key in envy.effective_schema(environment)?.into_keys() {
            slots.push((environment.to_string(), key));
        }
    }
    Ok(slots)
}

struct Move<'a> {
    project: &'a str,
    environment: &'a str,
    key: &'a str,
}

impl Move<'_> {
    /// Replays the versions oldest first, so the active value ends up active. Returns
    /// `false` when there is no active value: versions left behind by a deleted value are
    /// not moved.
    fn copy(
        &self,
        source: &dyn SecretVault,
        target: &dyn SecretVault,
        keep: usize,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let (project, environment, key) = (self.project, self.environment, self.key);
        let history = source.history(project, environment, key)?;
        if !history.iter().any(|version| version.active) {
            return Ok(false);
        }
        for version in history.iter().rev() {
            let Some(value) = source.get_version(project, environment, key, version.number)? else {
                continue;
            };
            let change = Change {
                at: version.created_at.unwrap_or(now),
                keep,
            };
            target.set(project, environment, key, &value, change)?;
        }

        let expected = source.get(project, environment, key)?;
        let arrived = target.get(project, environment, key)?;
        if expected.as_ref().map(|v| v.expose_secret())
            != arrived.as_ref().map(|v| v.expose_secret())
        {
            bail!(
                "'{key}' in '{environment}' did not arrive intact; the project still uses its current backend."
            );
        }
        Ok(true)
    }
}
