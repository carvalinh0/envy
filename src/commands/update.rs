use std::io::Write;

use anyhow::{Context as _, Result};

use crate::{
    context::Context,
    update::{UpdateMethod, Version},
};

pub fn run(ctx: &Context, out: &mut dyn Write) -> Result<()> {
    let current = Version::current()?;
    let tag = ctx
        .releases
        .latest_tag()
        .context("Could not check the latest release")?;
    let latest = Version::parse(&tag)?;

    if latest <= current {
        writeln!(out, "Envy {current} is already up to date.")?;
        return Ok(());
    }

    writeln!(out, "Updating Envy {current} -> {latest}...")?;
    match ctx.updater.apply(&tag, ctx.releases)? {
        UpdateMethod::Cargo => writeln!(out, "Updated to {latest} with cargo.")?,
        UpdateMethod::Binary => writeln!(out, "Updated to {latest}.")?,
        UpdateMethod::BinaryAfterCargoFailed => writeln!(
            out,
            "cargo install failed, updated to {latest} with the prebuilt binary."
        )?,
    }
    Ok(())
}
