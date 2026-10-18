use std::{fs, io::Write};

use anyhow::{Context as _, Result, bail};

use crate::{
    cli::ImportArgs,
    context::Context,
    schema::{EnvironmentTypes, Secret},
};

pub fn run(ctx: &Context, args: &ImportArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;

    let path = ctx.config.base_dir.join(&args.path);
    let data = fs::read(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let bundle = ctx.codec.open(&data, &args.key)?;

    if bundle.project_id != envy.id {
        bail!(
            "This bundle belongs to another project ('{}'), not to '{}'.",
            bundle.project_name,
            envy.name
        );
    }

    let mut imported = 0usize;
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
            ctx.vault
                .set(&envy.id, environment, key, &Secret::new(value.as_str()))?;
            imported += 1;
        }
    }

    writeln!(
        out,
        "Imported {imported} value(s) into the vault ({skipped} skipped)."
    )?;
    Ok(())
}
