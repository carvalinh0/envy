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
    // The current backend is read in full before the new one is created, so a source that
    // can't be read (no keyring) leaves nothing half made. `--fresh` never reads it.
    let source = ctx.backends.vault(from);
    let slots = if args.fresh {
        Vec::new()
    } else {
        readable_slots(source, &envy)?
    };
    let keep_existing = match to {
        Backend::Remote => prepare_remote(ctx, &envy, out)?,
        Backend::File if !ctx.backends.file.exists(&envy.id) => {
            create_file_vault(ctx, &envy, out)?;
            false
        }
        _ => false,
    };

    let target = ctx.backends.vault(to);
    let now = ctx.clock.now();
    let mut copied = Vec::new();
    let mut kept = Vec::new();
    for (environment, key) in slots {
        let moved = Move {
            project: &envy.id,
            environment: &environment,
            key: &key,
        };
        match moved.copy(source, target, envy.history_keep(), now, keep_existing)? {
            Outcome::Copied => copied.push((environment, key)),
            Outcome::Kept => kept.push(format!("{environment}/{key}")),
            Outcome::Empty => {}
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
    if !kept.is_empty() {
        writeln!(
            out,
            "Kept the server's values of {} (this machine's copies were not sent).",
            kept.join(", ")
        )?;
    }
    if !args.remove_source && !args.fresh {
        writeln!(
            out,
            "The {} backend still holds them: run again with --remove-source to delete them there.",
            from.name()
        )?;
    }
    Ok(())
}

/// Creates the project on its server, or reports that it exists already. Returns whether it
/// existed: then only the values the server does not have are sent, so a teammate's newer
/// values are never overwritten by an old local copy.
fn prepare_remote(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<bool> {
    let remote = ctx.backends.remote;
    let url = remote.url(&envy.id)?;
    if remote.project_exists(&envy.id)? {
        writeln!(
            out,
            "{url} already has this project: only the values it does not have are copied."
        )?;
        return Ok(true);
    }
    writeln!(out, "Creating '{}' on {url}.", envy.name)?;
    let recovery = new_recovery_key(ctx, out)?;
    remote.create_project(&envy.id, &recovery)?;
    ctx.record(envy, "remote-create", None, vec![url])?;
    Ok(false)
}

fn create_file_vault(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<()> {
    writeln!(out, "Creating the file vault of '{}'.", envy.name)?;
    let password = new_password(ctx, true)?;
    let recovery = new_recovery_key(ctx, out)?;
    ctx.backends.file.create(&envy.id, &password, &recovery)?;
    ctx.record(envy, "vault-create", None, Vec::new())
}

/// The slots of the project, after checking the current backend answers for each of them.
fn readable_slots(source: &dyn SecretVault, envy: &Envy) -> Result<Vec<(String, String)>> {
    let slots = slots(envy)?;
    for (environment, key) in &slots {
        source.history(&envy.id, environment, key)?;
    }
    Ok(slots)
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

enum Outcome {
    Copied,
    /// The target already had a value and keeps it.
    Kept,
    /// Nothing to copy.
    Empty,
}

struct Move<'a> {
    project: &'a str,
    environment: &'a str,
    key: &'a str,
}

impl Move<'_> {
    /// Replays the versions oldest first, so the active value ends up active. A variable
    /// with no active value is not moved (versions left behind by a deleted value stay), and
    /// with `keep_existing` neither is one the target already has.
    fn copy(
        &self,
        source: &dyn SecretVault,
        target: &dyn SecretVault,
        keep: usize,
        now: DateTime<Utc>,
        keep_existing: bool,
    ) -> Result<Outcome> {
        let (project, environment, key) = (self.project, self.environment, self.key);
        let history = source.history(project, environment, key)?;
        if !history.iter().any(|version| version.active) {
            return Ok(Outcome::Empty);
        }
        if keep_existing && target.get(project, environment, key)?.is_some() {
            return Ok(Outcome::Kept);
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
        Ok(Outcome::Copied)
    }
}
