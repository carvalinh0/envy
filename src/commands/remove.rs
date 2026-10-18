use std::io::Write;

use anyhow::{Result, bail};

use crate::{cli::RemoveArgs, context::Context};

pub fn run(ctx: &Context, args: &RemoveArgs, out: &mut dyn Write) -> Result<()> {
    let mut envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, args.environment.as_deref())?;
    if envy.is_inherited(&environment, &args.secret) {
        bail!(
            "'{}' is declared by the workspace root, remove it there (`envy -C <root> ...`).",
            args.secret
        );
    }

    envy.remove_variable(&environment, &args.secret)?;
    ctx.vault.delete(&envy.id, &environment, &args.secret)?;
    ctx.save_envy(&envy)?;

    writeln!(
        out,
        "Removed '{}' from '{environment}' (schema version {}).",
        args.secret, envy.version
    )?;
    Ok(())
}
