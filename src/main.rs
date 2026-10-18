use clap::Parser;

use dot_envy::{
    app,
    bundle::AesGcmCodec,
    cli::{Cli, Commands},
    config::Config,
    context::Context,
    inference::HeuristicInferrer,
    prompt::TerminalPrompter,
    runner::SystemRunner,
    state::FileState,
    update::{GithubReleases, SystemUpdater},
    vault::KeyringVault,
};

fn main() {
    let cli = Cli::parse();

    let code = match execute(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            1
        }
    };
    std::process::exit(code);
}

fn execute(cli: Cli) -> anyhow::Result<i32> {
    let config = Config::from_env(cli.directory.as_deref())?;
    // `init` always creates the project where it was asked to; every other command works
    // on the nearest project above the current directory.
    let config = match cli.command {
        Commands::Init(_) => config,
        _ => config.discover(),
    };
    let vault = KeyringVault::default();
    let state = FileState::new(config.state_path());
    let releases = GithubReleases::from_package()?;
    let updater = SystemUpdater::from_environment(&SystemRunner);
    let ctx = Context {
        config: &config,
        vault: &vault,
        state: &state,
        prompter: &TerminalPrompter,
        runner: &SystemRunner,
        codec: &AesGcmCodec,
        inferrer: &HeuristicInferrer,
        releases: &releases,
        updater: &updater,
    };

    app::dispatch(cli.command, &ctx, &mut std::io::stdout())
}
