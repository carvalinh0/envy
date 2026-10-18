use std::{fs, io::Write, path::PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::{
    cli::InitArgs,
    context::Context,
    dotenv,
    envy::{Envy, VarDetail},
    schema::Secret,
    workspace,
};

/// `init` works in the directory Envy was started in (`start_dir`), never in a project
/// found above it, so a new workspace member can be created inside the root's tree.
pub fn run(ctx: &Context, args: &InitArgs, out: &mut dyn Write) -> Result<()> {
    let dir = &ctx.config.start_dir;
    let manifest = dir.join(&ctx.config.file_name);
    if manifest.exists() {
        bail!("{} already exists", ctx.config.file_name);
    }

    let mut envy = Envy::new(
        args.project_name.clone(),
        Some(ctx.config.schema_path.clone()),
    )?;

    let mut to_store: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut to_delete: Vec<PathBuf> = Vec::new();

    if !args.skip_scan {
        let discovery = dotenv::discover(dir)?;

        for path in &discovery.skipped {
            writeln!(
                out,
                "Skipped {}: it has no environment name (use .env.<environment>).",
                path.display()
            )?;
        }

        for file in discovery.files {
            let content = fs::read_to_string(&file.path)
                .with_context(|| format!("Could not read {}", file.path.display()))?;
            let pairs = dotenv::parse(&content)
                .with_context(|| format!("Could not parse {}", file.path.display()))?;

            let schema = envy.schemas.entry(file.environment.clone()).or_default();
            for (key, value) in &pairs {
                let kind = ctx.inferrer.infer(key, value);
                schema.entry(key.clone()).or_insert_with(|| VarDetail {
                    kind: kind.to_string(),
                    default: None,
                });
            }

            if file.is_example {
                writeln!(
                    out,
                    "Read the types of '{}' from {}.",
                    file.environment,
                    file.path.display()
                )?;
            } else {
                to_store.push((file.environment, pairs));
                if !args.nondestructive {
                    to_delete.push(file.path);
                }
            }
        }
    }

    envy.checksum = envy.compute_checksum()?;
    envy.check_schema(None, None)?;

    let mut stored = 0usize;
    for (environment, pairs) in &to_store {
        for (key, value) in pairs.iter().filter(|(_, v)| !v.is_empty()) {
            ctx.vault
                .set(&envy.id, environment, key, &Secret::new(value.clone()))?;
            stored += 1;
        }
    }

    envy.save(&manifest)
        .with_context(|| format!("Was not possible to create {}", ctx.config.file_name))?;

    for path in &to_delete {
        fs::remove_file(path).with_context(|| format!("Could not remove {}", path.display()))?;
    }

    writeln!(out, "Created {} for '{}'.", ctx.config.file_name, envy.name)?;
    if let Some((root_dir, root)) = workspace::find_root(dir, &ctx.config.file_name)? {
        writeln!(
            out,
            "It is a member of the workspace '{}' ({}) and inherits its variables.",
            root.name,
            root_dir.join(&ctx.config.file_name).display()
        )?;
    }
    if stored > 0 {
        writeln!(out, "Stored {stored} value(s) in the vault.")?;
    }
    if !to_delete.is_empty() {
        writeln!(
            out,
            "Removed {} .env file(s) from the folder.",
            to_delete.len()
        )?;
    }
    Ok(())
}
