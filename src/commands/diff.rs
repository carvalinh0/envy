use std::io::Write;

use anyhow::Result;

use crate::{cli::DiffArgs, context::Context, resolver::Resolver};

pub fn run(ctx: &Context, args: &DiffArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;

    match (args.environment.as_deref(), args.other.as_deref()) {
        (Some(left), Some(right)) => {
            let left = ctx.target_environment(&envy, Some(left))?;
            let right = ctx.target_environment(&envy, Some(right))?;
            compare(ctx, &left, &right, out)
        }
        (first, None) => {
            let environment = ctx.target_environment(&envy, first)?;
            let missing: Vec<String> = Resolver::new(&envy, ctx.vault)
                .resolve_all(&environment)?
                .into_iter()
                .filter(|item| item.value.is_none())
                .map(|item| item.key)
                .collect();

            if missing.is_empty() {
                writeln!(out, "No missing keys in '{environment}'.")?;
            } else {
                writeln!(out, "Missing in '{environment}':")?;
                for key in missing {
                    writeln!(out, "  {key}")?;
                }
            }
            Ok(())
        }
        (None, Some(_)) => unreachable!("clap fills positional arguments in order"),
    }
}

fn compare(ctx: &Context, left: &str, right: &str, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let a = envy.effective_schema(left)?;
    let b = envy.effective_schema(right)?;

    let mut differences = 0usize;
    for (key, detail) in &a {
        match b.get(key) {
            None => {
                writeln!(out, "- {key} (only in '{left}')")?;
                differences += 1;
            }
            Some(other) if other.kind != detail.kind => {
                writeln!(
                    out,
                    "~ {key} (type {} in '{left}', {} in '{right}')",
                    detail.kind, other.kind
                )?;
                differences += 1;
            }
            Some(_) => {}
        }
    }
    for key in b.keys().filter(|key| !a.contains_key(*key)) {
        writeln!(out, "+ {key} (only in '{right}')")?;
        differences += 1;
    }

    if differences == 0 {
        writeln!(out, "'{left}' and '{right}' declare the same variables.")?;
    }
    Ok(())
}
