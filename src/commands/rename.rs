use std::io::Write;

use anyhow::{Result, bail};

use crate::{cli::RenameArgs, context::Context};

pub fn run(ctx: &Context, args: &RenameArgs, out: &mut dyn Write) -> Result<()> {
    let mut envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, args.environment.as_deref())?;
    if envy.is_inherited(&environment, &args.old_name) {
        bail!(
            "'{}' is declared by the workspace root, rename it there (`envy -C <root> ...`).",
            args.old_name
        );
    }

    envy.rename_variable(&environment, &args.old_name, &args.new_name)?;

    if let Some(value) = ctx.vault.get(&envy.id, &environment, &args.old_name)? {
        ctx.vault
            .set(&envy.id, &environment, &args.new_name, &value)?;
        ctx.vault.delete(&envy.id, &environment, &args.old_name)?;
    }
    ctx.save_envy(&envy)?;

    writeln!(
        out,
        "Renamed '{}' to '{}' in '{environment}' (schema version {}).",
        args.old_name, args.new_name, envy.version
    )?;
    Ok(())
}
