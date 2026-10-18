//! Routes a parsed command to its handler.

use std::io::Write;

use anyhow::Result;

use crate::{cli::Commands, commands, context::Context};

/// Runs `command` and returns the process exit code (non-zero only for `run`; failures are errors).
pub fn dispatch(command: Commands, ctx: &Context, out: &mut dyn Write) -> Result<i32> {
    match command {
        Commands::Init(args) => commands::init::run(ctx, &args, out)?,
        Commands::Import(args) => commands::import::run(ctx, &args, out)?,
        Commands::Version => commands::version::run(ctx, out)?,
        Commands::Update => commands::update::run(ctx, out)?,
        Commands::Switch(args) => commands::switch::run(ctx, &args, out)?,
        Commands::Schema(args) => commands::schema::run(ctx, &args, out)?,
        Commands::Up(args) => commands::up::run(ctx, &args, out)?,
        Commands::Set(args) => commands::set::run(ctx, &args, out)?,
        Commands::Remove(args) => commands::remove::run(ctx, &args, out)?,
        Commands::Rename(args) => commands::rename::run(ctx, &args, out)?,
        Commands::Export(args) => commands::export::run(ctx, &args, out)?,
        Commands::Run(args) => return commands::run::run(ctx, &args),
        Commands::Fill(args) => commands::fill::run(ctx, &args, out)?,
        Commands::Check(args) => commands::check::run(ctx, &args, out)?,
        Commands::Diff(args) => commands::diff::run(ctx, &args, out)?,
        Commands::List(args) => commands::list::run(ctx, &args, out)?,
    }
    Ok(0)
}
