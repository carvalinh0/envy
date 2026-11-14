use std::{fs, io::Write};

use anyhow::{Context as _, Result, bail};

use crate::{
    cli::ImportArgs,
    context::Context,
    schema::{EnvironmentTypes, Secret},
    vault::SecretVault,
};

pub fn run(ctx: &Context, args: &ImportArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;

    let path = ctx.config.base_dir.join(&args.path);
    let data = fs::read(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let bundle = ctx.codec.open(&data, &args.key)?;

    if let Some(expires_at) = bundle.expires_at
        && expires_at <= ctx.clock.now()
    {
        bail!(
            "This bundle expired on {}. Ask for a new export.",
            expires_at.format("%Y-%m-%d %H:%M UTC")
        );
    }
    if bundle.project_id != envy.id {
        bail!(
            "This bundle belongs to another project ('{}'), not to '{}'.",
            bundle.project_name,
            envy.name
        );
    }

    let vault = ctx.secrets(&envy);
    let mut imported = Vec::new();
    let mut skipped = 0usize;

    for (environment, variables) in &bundle.entries {
        for (key, value) in variables {
            let valid = envy
                .declaration(environment, key)
                .ok()
                .and_then(|decl| EnvironmentTypes::parse_type(&decl.kind).ok())
                .is_some_and(|kind| EnvironmentTypes::validate(value, kind).is_ok());

            if !valid {
                writeln!(
                    out,
                    "Skipped '{key}' in '{environment}': not declared in the schema or invalid."
                )?;
                skipped += 1;
                continue;
            }
            vault.set(
                &envy.id,
                environment,
                key,
                &Secret::new(value.as_str()),
                ctx.change(&envy),
            )?;
            imported.push(format!("{environment}/{key}"));
        }
    }

    writeln!(
        out,
        "Imported {} value(s) into the vault ({skipped} skipped).",
        imported.len()
    )?;
    if !imported.is_empty() {
        ctx.record(&envy, "import", None, imported)?;
    }
    Ok(())
}
