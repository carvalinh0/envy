use std::io::Write;

use anyhow::{Result, anyhow, bail};

use crate::{
    cli::SetArgs,
    context::Context,
    schema::{EnvironmentTypes, Secret},
    vault::SecretVault,
};

pub fn run(ctx: &Context, args: &SetArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, Some(&args.environment))?;

    let declaration = envy.declaration(&environment, &args.secret)?;
    let kind = EnvironmentTypes::parse_type(&declaration.kind)?;
    let value = match &args.value {
        Some(value) => Secret::new(value.clone()),
        None => piped_value(ctx)?,
    };
    EnvironmentTypes::validate(value.expose_secret(), kind).map_err(|err| {
        anyhow!(
            "Invalid value for '{}' (expected {kind}): {err}",
            args.secret
        )
    })?;

    ctx.secrets(&envy).set(
        &envy.id,
        &environment,
        &args.secret,
        &value,
        ctx.change(&envy),
    )?;
    ctx.record(&envy, "set", Some(&environment), vec![args.secret.clone()])?;
    writeln!(out, "Stored '{}' in '{environment}'.", args.secret)?;
    Ok(())
}

/// The value piped by a script. `echo` and most tools end their output with a line break that
/// is not part of the value. Empty input is refused: it usually means the command that should
/// have produced the value failed, and storing it would replace a working value.
fn piped_value(ctx: &Context) -> Result<Secret> {
    let piped = ctx.prompter.read_stdin()?;
    let text = piped.expose_secret();
    let value = text
        .strip_suffix('\n')
        .map_or(text, |line| line.strip_suffix('\r').unwrap_or(line));
    if value.is_empty() {
        bail!("Nothing was piped to `envy set --stdin`; the stored value was not changed.");
    }
    Ok(Secret::new(value))
}
