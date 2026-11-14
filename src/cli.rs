use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Validate, edit and securely share environment variables
#[derive(Debug, Parser)]
#[command(name = "envy", version, about, long_about = None)]
pub struct Cli {
    /// Run as if Envy was started in DIR
    #[arg(short = 'C', value_name = "DIR", global = true)]
    pub directory: Option<PathBuf>,

    /// Where the values are stored (default: keyring, or ENVY_BACKEND)
    #[arg(long, value_enum, global = true)]
    pub backend: Option<Backend>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Storage of the values. Only the keyring exists so far; the others are reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Backend {
    /// The operating system keyring
    Keyring,
    /// An encrypted file (not available yet)
    File,
    /// An Envy server (not available yet)
    Remote,
}

impl Backend {
    /// The flag wins, then `ENVY_BACKEND`, then the keyring. Nothing configured behaves
    /// exactly like the releases before backends could be chosen.
    pub fn resolve(flag: Option<Backend>, from_env: Option<&str>) -> Result<Backend> {
        if let Some(backend) = flag {
            return Ok(backend);
        }
        match from_env.filter(|value| !value.is_empty()) {
            None => Ok(Backend::Keyring),
            Some(value) => match Backend::from_str(value, true) {
                Ok(backend) => Ok(backend),
                Err(_) => {
                    bail!("ENVY_BACKEND='{value}' is not valid. Use keyring, file or remote.")
                }
            },
        }
    }
}

/// The main commands of the application
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a new project: create the manifest and store any .env files in the vault
    Init(InitArgs),

    /// Import an encrypted [project_name.scope].envy bundle into your local vault
    Import(ImportArgs),

    /// Shows the version
    Version,

    /// Switch the active environment context (e.g., dev, prod)
    Switch(SwitchArgs),

    /// Create a new schema (environment) and bump the version, or show the current schema
    Schema(SchemaArgs),

    /// Update Envy to the latest release
    Update,

    /// Detect manual or external changes in the manifest, recalculate the checksum and bump the version
    Up(UpArgs),

    /// Set a variable inside your local vault for the current project
    Set(SetArgs),

    /// Remove a variable from your local vault and from the schema, and bump the schema version
    #[command(name = "rm", visible_alias = "remove")]
    Remove(RemoveArgs),

    /// Rename a variable in the local vault and in the schema, and bump the schema version
    Rename(RenameArgs),

    /// Export your project secrets into an encrypted bundle
    Export(ExportArgs),

    /// Run a command with the environment variables injected into the child process
    Run(RunArgs),

    /// Interactively fill in the variables that have no value yet
    Fill(FillArgs),

    /// Check that every required variable is set and valid (exit code 1 otherwise)
    Check(CheckArgs),

    /// Show missing keys, or compare two environment schemas
    Diff(DiffArgs),

    /// List the project's variables (values are masked by default)
    #[command(name = "ls", visible_alias = "list")]
    List(ListArgs),

    /// Show the stored versions of a variable (values are never printed)
    History(HistoryArgs),

    /// Restore an earlier version of a variable (the current value stays in the history)
    Rollback(RollbackArgs),

    /// Show this project's local audit log and verify that it was not modified
    Audit,

    /// Require a password for an environment and encrypt the values stored for it
    Protect(ProtectArgs),

    /// Remove the password of an environment and decrypt the values stored for it
    Unprotect(ProtectArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    pub project_name: String,

    /// Keep the .env files in the folder instead of deleting them after storing them
    #[arg(long)]
    pub nondestructive: bool,

    /// Skip the .env file scan (existing .env files are left untouched)
    #[arg(long = "new")]
    pub skip_scan: bool,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Path to the .envy bundle
    pub path: PathBuf,
    /// Key printed by `envy export`
    pub key: String,
}

#[derive(Debug, Args)]
pub struct SwitchArgs {
    pub environment: String,
}

#[derive(Debug, Args)]
pub struct SchemaArgs {
    /// Name of the environment to create. Without it the current schema is shown.
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct UpArgs {
    /// Give the project a new id (for a manifest copied from another project). The values
    /// stored for the old id are copied to the new one.
    #[arg(long)]
    pub new_id: bool,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    pub environment: String,
    pub secret: String,
    pub value: String,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub secret: String,
    /// Environment to remove it from (defaults to the active one)
    #[arg(long = "from")]
    pub environment: Option<String>,
}

#[derive(Debug, Args)]
pub struct RenameArgs {
    pub old_name: String,
    pub new_name: String,
    /// Environment where the variable lives (defaults to the active one)
    #[arg(long = "in")]
    pub environment: Option<String>,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Export only this environment (and `global`). Without it every environment is exported.
    pub environment: Option<String>,
    /// Refuse to import the bundle after this long (e.g. 12h, 7d, 2w)
    #[arg(long, value_name = "DURATION")]
    pub ttl: Option<String>,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    pub environment: String,
    /// Command to run, after `--`
    #[arg(last = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct FillArgs {
    /// Defaults to the active environment
    pub environment: Option<String>,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    pub environment: Option<String>,
    #[arg(requires = "environment", conflicts_with = "recursive")]
    pub variable: Option<String>,
    /// Check every project under the current directory (skips hidden folders,
    /// node_modules, target, vendor, venv and __pycache__)
    #[arg(short, long)]
    pub recursive: bool,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    pub environment: Option<String>,
    pub other: Option<String>,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Defaults to the active environment
    pub environment: Option<String>,
    /// Print the real values instead of masking them
    #[arg(long)]
    pub show: bool,
}

#[derive(Debug, Args)]
pub struct HistoryArgs {
    pub secret: String,
    /// Environment where the variable lives (defaults to the active one)
    #[arg(long = "in")]
    pub environment: Option<String>,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    pub secret: String,
    /// Environment where the variable lives (defaults to the active one)
    #[arg(long = "in")]
    pub environment: Option<String>,
    /// Version to restore (defaults to the one before the active value)
    #[arg(long)]
    pub to: Option<u32>,
}

#[derive(Debug, Args)]
pub struct ProtectArgs {
    pub environment: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_wins_over_the_environment_variable() {
        assert_eq!(
            Backend::resolve(Some(Backend::File), Some("remote")).unwrap(),
            Backend::File
        );
        assert_eq!(
            Backend::resolve(None, Some("Remote")).unwrap(),
            Backend::Remote
        );
    }

    #[test]
    fn nothing_configured_means_the_keyring() {
        assert_eq!(Backend::resolve(None, None).unwrap(), Backend::Keyring);
        assert_eq!(Backend::resolve(None, Some("")).unwrap(), Backend::Keyring);
    }

    #[test]
    fn an_unknown_backend_is_an_error() {
        let err = Backend::resolve(None, Some("s3")).unwrap_err().to_string();
        assert!(err.contains("ENVY_BACKEND='s3'"), "{err}");
    }
}
