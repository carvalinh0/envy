use std::io::Write;

use anyhow::Result;

use crate::{cli::ListArgs, context::Context, resolver::Resolver, schema::Secret};

const UNSET: &str = "<unset>";

pub fn run(ctx: &Context, args: &ListArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, args.environment.as_deref())?;

    let rows: Vec<(String, String, String)> = Resolver::new(&envy, ctx.vault)
        .resolve_all(&environment)?
        .into_iter()
        .map(|item| {
            let value = match &item.value {
                None => UNSET.to_string(),
                Some(secret) if args.show => secret.expose_secret().to_string(),
                Some(secret) => mask(secret),
            };
            (item.key, item.kind.to_string(), value)
        })
        .collect();

    if rows.is_empty() {
        writeln!(out, "'{environment}' has no variables.")?;
        return Ok(());
    }

    let key_width = rows.iter().map(|r| r.0.len()).chain([3]).max().unwrap_or(3);
    let type_width = rows.iter().map(|r| r.1.len()).chain([4]).max().unwrap_or(4);

    writeln!(out, "{:<key_width$}  {:<type_width$}  VALUE", "KEY", "TYPE")?;
    for (key, kind, value) in rows {
        writeln!(out, "{key:<key_width$}  {kind:<type_width$}  {value}")?;
    }
    Ok(())
}

fn mask(secret: &Secret) -> String {
    secret.to_string()
}
