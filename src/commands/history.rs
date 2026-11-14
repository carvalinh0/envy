use std::io::Write;

use anyhow::{Result, bail};

use crate::{cli::HistoryArgs, context::Context, vault::Version};

pub fn run(ctx: &Context, args: &HistoryArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, args.environment.as_deref())?;
    envy.declaration(&environment, &args.secret)?;

    let versions = ctx.vault.history(&envy.id, &environment, &args.secret)?;
    if versions.is_empty() {
        bail!(
            "'{}' has no value stored for this project in '{environment}'.",
            args.secret
        );
    }

    writeln!(out, "VERSION  CHANGED")?;
    for version in &versions {
        writeln!(out, "{:<7}  {}", version.number, describe(version))?;
    }
    Ok(())
}

fn describe(version: &Version) -> String {
    let date = match version.created_at {
        Some(at) => at.format("%Y-%m-%d %H:%M UTC").to_string(),
        None => "unknown (stored by an older Envy)".to_string(),
    };
    if version.active {
        format!("{date}  (active)")
    } else {
        date
    }
}
