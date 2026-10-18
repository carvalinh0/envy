use std::io::Write;

use anyhow::{Result, bail};

use crate::{cli::FillArgs, context::Context, resolver::Resolver, schema::EnvironmentTypes};

const MAX_ATTEMPTS: usize = 3;

pub fn run(ctx: &Context, args: &FillArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, args.environment.as_deref())?;

    let missing: Vec<_> = Resolver::new(&envy, ctx.vault)
        .resolve_all(&environment)?
        .into_iter()
        .filter(|item| item.value.is_none())
        .collect();

    if missing.is_empty() {
        writeln!(
            out,
            "Nothing to fill: every variable of '{environment}' has a value."
        )?;
        return Ok(());
    }

    let (mut filled, mut skipped) = (0usize, 0usize);
    for item in missing {
        let label = format!("{} ({}) [{environment}]", item.key, item.kind);
        let mut stored = false;

        for _ in 0..MAX_ATTEMPTS {
            let answer = ctx.prompter.ask_secret(&label)?;
            if answer.expose_secret().is_empty() {
                break;
            }
            match EnvironmentTypes::validate(answer.expose_secret(), item.kind) {
                Ok(()) => {
                    ctx.vault.set(&envy.id, &environment, &item.key, &answer)?;
                    stored = true;
                    break;
                }
                Err(err) => writeln!(
                    out,
                    "Invalid value for '{}' (expected {}): {err}",
                    item.key, item.kind
                )?,
            }
        }

        if stored {
            filled += 1;
        } else {
            skipped += 1;
        }
    }

    writeln!(out, "Filled {filled} variable(s), skipped {skipped}.")?;
    if skipped > 0 {
        bail!("{skipped} variable(s) of '{environment}' still have no value.");
    }
    Ok(())
}
