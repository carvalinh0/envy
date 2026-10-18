use std::io::Write;

use anyhow::Result;

use crate::{context::Context, update::Version};

pub fn run(ctx: &Context, out: &mut dyn Write) -> Result<()> {
    writeln!(
        out,
        "{} {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )?;

    // The check is best effort: being offline or hitting a GitHub error is silently ignored.
    if ctx.config.update_notice
        && let Ok(tag) = ctx.releases.latest_tag()
        && let (Ok(latest), Ok(current)) = (Version::parse(&tag), Version::current())
        && latest > current
    {
        writeln!(
            out,
            "A new version is available: {latest} (you have {current}). Run `envy update` to install it."
        )?;
    }
    Ok(())
}
