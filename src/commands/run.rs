use anyhow::{Result, bail};

use crate::{cli::RunArgs, context::Context, resolver::Resolver};

/// Runs the command with the environment's variables injected; returns the child's exit code.
pub fn run(ctx: &Context, args: &RunArgs) -> Result<i32> {
    let envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, Some(&args.environment))?;

    let resolver = Resolver::new(&envy, ctx.vault);
    let problems = resolver.problems(&environment, None)?;
    if !problems.is_empty() {
        bail!("{}", problems.join("\n"));
    }

    let envs: Vec<_> = resolver
        .resolve_all(&environment)?
        .into_iter()
        .filter_map(|item| item.value.map(|value| (item.key, value)))
        .collect();

    let Some((program, rest)) = args.command.split_first() else {
        bail!("No command to run. Use `envy run <env> -- <command>`.");
    };
    ctx.runner.run(program, rest, &envs)
}
