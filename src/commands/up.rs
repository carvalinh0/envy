use std::io::Write;

use anyhow::Result;
use uuid::Uuid;

use crate::{cli::UpArgs, context::Context, envy::Envy};

pub fn run(ctx: &Context, args: &UpArgs, out: &mut dyn Write) -> Result<()> {
    let mut envy = ctx.load_envy()?;
    envy.check_schema(None, None)?;

    if args.new_id {
        return new_id(ctx, &mut envy, out);
    }

    if envy.sync()? {
        ctx.save_envy(&envy)?;
        writeln!(
            out,
            "Changes detected: schema bumped to version {}.",
            envy.version
        )?;
    } else {
        writeln!(out, "No changes detected (version {}).", envy.version)?;
    }
    ctx.warn_shared_id(&envy, out)
}

/// Gives the project its own id. The values stored for the old id are copied (not moved),
/// because the project it was copied from keeps using them. Versions are not copied.
fn new_id(ctx: &Context, envy: &mut Envy, out: &mut dyn Write) -> Result<()> {
    let old_id = envy.id.clone();
    let new_id = Uuid::new_v4().to_string();
    let change = ctx.change(envy);

    let mut copied = 0usize;
    for environment in envy.environment_names() {
        for key in envy.effective_schema(environment)?.keys() {
            if let Some(value) = ctx.vault.get(&old_id, environment, key)? {
                ctx.vault.set(&new_id, environment, key, &value, change)?;
                copied += 1;
            }
        }
    }

    envy.id = new_id;
    envy.commit_change()?;
    ctx.save_envy(envy)?;
    ctx.record(envy, "new-id", None, Vec::new())?;
    writeln!(
        out,
        "New project id: {} (schema version {}). Copied {copied} value(s) from the old id.",
        envy.id, envy.version
    )?;
    Ok(())
}
