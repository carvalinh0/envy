use std::{io::Write, path::PathBuf};

use anyhow::{Result, bail};

use crate::{
    cli::CheckArgs,
    context::Context,
    envy::{Envy, GLOBAL_ENV},
    resolver::Resolver,
    workspace,
};

pub fn run(ctx: &Context, args: &CheckArgs, out: &mut dyn Write) -> Result<()> {
    if args.recursive {
        return run_recursive(ctx, args.environment.as_deref(), out);
    }

    let envy = ctx.load_envy()?;
    let summary = check_project(
        ctx,
        &envy,
        args.environment.as_deref(),
        args.variable.as_deref(),
    )?;
    ctx.warn_shared_id(&envy, out)?;
    writeln!(out, "All good: {summary}.")?;
    Ok(())
}

/// Checks one project. Returns a summary on success; the problems are the error.
fn check_project(
    ctx: &Context,
    envy: &Envy,
    environment: Option<&str>,
    variable: Option<&str>,
) -> Result<String> {
    envy.check_schema(None, None)?;
    if let Some(parent) = &envy.parent {
        parent.check_schema(None, None)?;
    }
    if let Some(environment) = environment {
        if !envy.has_environment(environment) {
            bail!("There's no environment called '{environment}'");
        }
        if let Some(variable) = variable {
            envy.declaration(environment, variable)?;
        }
    }

    // global only provides shared variables, so it is not checked on its own
    // unless the user asks for it explicitly.
    let environments: Vec<&str> = match environment {
        Some(name) => vec![name],
        None => envy
            .environment_names()
            .into_iter()
            .filter(|name| *name != GLOBAL_ENV)
            .collect(),
    };

    let resolver = Resolver::new(envy, ctx.vault);
    let mut problems = Vec::new();
    let mut checked = 0usize;

    for environment in &environments {
        problems.extend(resolver.problems(environment, variable)?);
        checked += resolver.resolve_all(environment)?.len();
    }

    if !problems.is_empty() {
        bail!("{}", problems.join("\n"));
    }
    Ok(format!(
        "{checked} variable(s) checked in {} environment(s)",
        environments.len()
    ))
}

/// Checks every project under the start directory and fails if any of them fails, or if
/// two manifests share an id.
fn run_recursive(ctx: &Context, environment: Option<&str>, out: &mut dyn Write) -> Result<()> {
    let file_name = &ctx.config.file_name;
    let manifests = workspace::find_manifests(&ctx.config.start_dir, file_name)?;
    if manifests.is_empty() {
        bail!(
            "No {file_name} found under {}.",
            ctx.config.start_dir.display()
        );
    }

    let mut failed = 0usize;
    let mut skipped = 0usize;
    let mut ids: Vec<(PathBuf, String)> = Vec::new();

    for manifest in &manifests {
        let shown = ctx.display_path(manifest);
        let Some(dir) = manifest.parent() else {
            continue;
        };
        let result = workspace::load_project(dir, file_name).and_then(|envy| {
            ids.push((manifest.clone(), envy.id.clone()));
            match environment {
                Some(name) if !envy.has_environment(name) => Ok(None),
                _ => check_project(ctx, &envy, environment, None).map(Some),
            }
        });

        match result {
            Ok(Some(summary)) => writeln!(out, "ok    {shown}: {summary}")?,
            Ok(None) => {
                skipped += 1;
                writeln!(
                    out,
                    "skip  {shown}: no '{}' environment",
                    environment.unwrap_or_default()
                )?;
            }
            Err(err) => {
                failed += 1;
                writeln!(out, "FAIL  {shown}")?;
                for line in format!("{err:#}").lines() {
                    writeln!(out, "      {line}")?;
                }
            }
        }
    }

    let duplicated = workspace::duplicated_ids(&ids);
    for (id, paths) in &duplicated {
        writeln!(out, "FAIL  the id {id} is used by more than one manifest:")?;
        for path in paths {
            writeln!(out, "      {}", ctx.display_path(path))?;
        }
    }
    if !duplicated.is_empty() {
        writeln!(
            out,
            "      Run `envy up --new-id` in the copied project(s) to give them their own id."
        )?;
    }

    let checked = manifests.len() - failed - skipped;
    if failed > 0 || !duplicated.is_empty() {
        bail!(
            "{failed} of {} project(s) failed, {} duplicated id(s).",
            manifests.len(),
            duplicated.len()
        );
    }
    writeln!(
        out,
        "All good: {checked} project(s) checked, {skipped} skipped."
    )?;
    Ok(())
}
