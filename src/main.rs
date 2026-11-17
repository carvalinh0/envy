use clap::Parser;

use dot_envy::{
    app,
    audit::FileAudit,
    backends::{Backends, FileBackends},
    bundle::AesGcmCodec,
    cli::{Backend, Cli, Commands},
    clock::SystemClock,
    config::Config,
    context::Context,
    inference::HeuristicInferrer,
    prompt::TerminalPrompter,
    remote::{
        client::RemoteVault,
        transport::{HttpTransport, Transport},
    },
    runner::SystemRunner,
    state::FileState,
    update::{GithubReleases, SystemUpdater},
    vault::{CredentialStore, EncryptedFileVault, SecretVault},
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
    let forced = Backend::forced(cli.backend, std::env::var("ENVY_BACKEND").ok().as_deref())?;
    let (keyring, identities) = keyring();
    let file = EncryptedFileVault::new(
        config.data_dir.clone(),
        &TerminalPrompter,
        config.vault_password.as_ref(),
    );
    let choices = FileBackends::new(config.data_dir.clone());
    let remote = RemoteVault::new(
        &choices,
        config.server_url.clone(),
        identities.as_ref(),
        config.identity.as_ref(),
        config.data_dir.clone(),
        Box::new(|url: &str| -> anyhow::Result<Box<dyn Transport>> {
            Ok(Box::new(HttpTransport::new(url)?))
        }),
    );
    let backends = Backends {
        keyring: keyring.as_ref(),
        file: &file,
        remote: &remote,
        identities: identities.as_ref(),
        choices: &choices,
        forced,
    };
    let audit = FileAudit::new(config.data_dir.clone());
    let state = FileState::new(config.state_path());
    let releases = GithubReleases::from_package()?;
    let updater = SystemUpdater::from_environment(&SystemRunner);
    let ctx = Context {
        config: &config,
        vault: &backends,
        backends: &backends,
        state: &state,
        prompter: &TerminalPrompter,
        runner: &SystemRunner,
        codec: &AesGcmCodec,
        inferrer: &HeuristicInferrer,
        releases: &releases,
        updater: &updater,
        clock: &SystemClock,
        audit: &audit,
    };

    app::dispatch(cli.command, &ctx, &mut std::io::stdout())
}

/// The keyring as a vault and as the store of member identities. A build without it (the
/// server image) has neither: values need another backend and identities `ENVY_IDENTITY`.
#[cfg(feature = "keyring")]
fn keyring() -> (Box<dyn SecretVault>, Box<dyn CredentialStore>) {
    use dot_envy::vault::KeyringVault;
    (
        Box::new(KeyringVault::default()),
        Box::new(KeyringVault::default()),
    )
}

#[cfg(not(feature = "keyring"))]
fn keyring() -> (Box<dyn SecretVault>, Box<dyn CredentialStore>) {
    use dot_envy::vault::{MemoryVault, UnavailableVault};
    (
        Box::new(UnavailableVault { backend: "keyring" }),
        Box::new(MemoryVault::new()),
    )
}
