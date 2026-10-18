use std::{collections::BTreeMap, io::Write};

use anyhow::Result;

use crate::{cli::SchemaArgs, context::Context, envy::Schema};

pub fn run(ctx: &Context, args: &SchemaArgs, out: &mut dyn Write) -> Result<()> {
    let mut envy = ctx.load_envy()?;

    if let Some(name) = &args.name {
        envy.add_environment(name)?;
        ctx.save_envy(&envy)?;
        writeln!(
            out,
            "Created environment '{name}' (schema version {}).",
            envy.version
        )?;
        return Ok(());
    }

    writeln!(out, "{} (v{})", envy.name, envy.version)?;
    if let Some(workspace) = &envy.workspace {
        writeln!(out, "Workspace members: {}", workspace.members.join(", "))?;
    }
    print_schemas(&envy.schemas, out)?;

    if let Some(parent) = &envy.parent {
        writeln!(
            out,
            "\nInherited from the workspace '{}' (v{}):",
            parent.name, parent.version
        )?;
        print_schemas(&parent.schemas, out)?;
    }
    Ok(())
}

fn print_schemas(schemas: &BTreeMap<String, Schema>, out: &mut dyn Write) -> Result<()> {
    for (environment, schema) in schemas {
        writeln!(out, "[{environment}]")?;
        for (key, detail) in schema {
            match &detail.default {
                Some(default) => writeln!(out, "  {key}: {} = {default}", detail.kind)?,
                None => writeln!(out, "  {key}: {}", detail.kind)?,
            }
        }
    }
    Ok(())
}
