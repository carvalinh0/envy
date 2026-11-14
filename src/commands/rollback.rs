use std::io::Write;

use anyhow::{Result, anyhow, bail};

use crate::{cli::RollbackArgs, context::Context, schema::EnvironmentTypes, vault::Version};

/// Stores an older value as a new version, so a rollback is itself kept in the history and
/// can be undone with another rollback.
pub fn run(ctx: &Context, args: &RollbackArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, args.environment.as_deref())?;
    let key = &args.secret;
    let kind = EnvironmentTypes::parse_type(&envy.declaration(&environment, key)?.kind)?;

    let versions = ctx.vault.history(&envy.id, &environment, key)?;
    let target = pick(&versions, args.to)
        .map_err(|reason| anyhow!("Can't roll '{key}' back in '{environment}': {reason}"))?;

    let Some(value) = ctx.vault.get_version(&envy.id, &environment, key, target)? else {
        bail!("Version {target} of '{key}' is no longer stored.");
    };
    if let Err(err) = EnvironmentTypes::validate(value.expose_secret(), kind) {
        bail!("Version {target} of '{key}' is not a valid {kind} anymore: {err}");
    }

    ctx.vault
        .set(&envy.id, &environment, key, &value, ctx.change(&envy))?;
    writeln!(
        out,
        "Restored version {target} of '{key}' in '{environment}'. `envy history {key}` lists the versions."
    )?;
    Ok(())
}

/// The requested version, or the newest one that is not active.
fn pick(versions: &[Version], requested: Option<u32>) -> Result<u32, String> {
    let Some(number) = requested else {
        return versions
            .iter()
            .find(|version| !version.active)
            .map(|version| version.number)
            .ok_or_else(|| "it has no earlier version.".to_string());
    };
    match versions.iter().find(|version| version.number == number) {
        Some(version) if version.active => Err(format!("version {number} is already active.")),
        Some(_) => Ok(number),
        None => Err(format!(
            "there is no version {number} (see `envy history`)."
        )),
    }
}
