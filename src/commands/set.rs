use std::io::Write;

use anyhow::{Result, anyhow};

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
    EnvironmentTypes::validate(&args.value, kind).map_err(|err| {
        anyhow!(
            "Invalid value for '{}' (expected {kind}): {err}",
            args.secret
        )
    })?;

    ctx.secrets(&envy).set(
        &envy.id,
        &environment,
        &args.secret,
        &Secret::new(args.value.clone()),
        ctx.change(&envy),
    )?;
    ctx.record(&envy, "set", Some(&environment), vec![args.secret.clone()])?;
    writeln!(out, "Stored '{}' in '{environment}'.", args.secret)?;
    Ok(())
}
