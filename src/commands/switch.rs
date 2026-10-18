use std::io::Write;

use anyhow::{Result, bail};

use crate::{cli::SwitchArgs, context::Context};

pub fn run(ctx: &Context, args: &SwitchArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    if !envy.has_environment(&args.environment) {
        bail!("There's no environment called '{}'", args.environment);
    }
    ctx.state.set_active(&args.environment)?;
    writeln!(out, "Active environment: {}", args.environment)?;
    Ok(())
}
