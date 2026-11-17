use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

/// Validate, edit and securely share environment variables
#[derive(Debug, Parser)]
#[command(name = "envy", version, about, long_about = None)]
pub struct Cli {
    /// Run as if Envy was started in DIR
    #[arg(short = 'C', value_name = "DIR", global = true)]
    pub directory: Option<PathBuf>,

    /// Store values here for every project, whatever `envy migrate` chose (also ENVY_BACKEND)
    #[arg(long, value_enum, global = true)]
    pub backend: Option<Backend>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Where the values of a project are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// The operating system keyring
    Keyring,
    /// An encrypted file in your data folder
    File,
    /// An Envy server (see `envy login`)
    Remote,
}

impl Backend {
    /// The backend forced for every project: the flag, then `ENVY_BACKEND`. `None` lets
    /// each project use the backend the user chose for it (the keyring by default).
    pub fn forced(flag: Option<Backend>, from_env: Option<&str>) -> Result<Option<Backend>> {
        if flag.is_some() {
            return Ok(flag);
        }
        match from_env.filter(|value| !value.is_empty()) {
            None => Ok(None),
            Some(value) => match Backend::from_str(value, true) {
                Ok(backend) => Ok(Some(backend)),
                Err(_) => {
                    bail!("ENVY_BACKEND='{value}' is not valid. Use keyring, file or remote.")
                }
            },
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Backend::Keyring => "keyring",
            Backend::File => "file",
            Backend::Remote => "remote",
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
    Audit(AuditArgs),

    /// Require a password for an environment and encrypt the values stored for it
    Protect(ProtectArgs),

    /// Remove the password of an environment and decrypt the values stored for it
    Unprotect(ProtectArgs),

    /// Move this project's values and their history to another backend
    Migrate(MigrateArgs),

    /// Manage the keys of this project on the file vault or the Envy server
    Vault(VaultArgs),

    /// Use an Envy server for this project: join it with an invite, or reconnect
    Login(LoginArgs),

    /// Stop using the Envy server for this project on this machine (the server keeps the values)
    Logout,

    /// Manage the members of the Envy server
    User(UserArgs),

    /// Run an Envy server (Linux builds with the `server` feature, or the Docker image)
    Serve(ServeArgs),
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
    /// Key printed by `envy export`. Leave it out to type it without echo, so it stays out
    /// of the shell history next to the file name
    pub key: Option<String>,
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
    /// The value. Other processes can read it while Envy runs: scripts should use --stdin
    #[arg(required_unless_present = "stdin")]
    pub value: Option<String>,
    /// Read the value from standard input (without its last line break)
    #[arg(long, conflicts_with = "value")]
    pub stdin: bool,
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

#[derive(Debug, Args)]
pub struct MigrateArgs {
    /// Backend that will hold the values
    #[arg(long, value_enum)]
    pub to: Backend,
    /// Delete the values from the current backend once they are copied and checked
    #[arg(long)]
    pub remove_source: bool,
    /// Start the new backend empty instead of copying (when the current one can't be read,
    /// like a machine without a keyring)
    #[arg(long, conflicts_with = "remove_source")]
    pub fresh: bool,
    /// With `--to remote`, for a project someone else created on the server: their
    /// fingerprint, checked with them through another channel. The creator receives every key
    #[arg(long, value_name = "FINGERPRINT")]
    pub creator: Option<String>,
}

#[derive(Debug, Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub action: VaultAction,
}

#[derive(Debug, Subcommand)]
pub enum VaultAction {
    /// Change the password of the file vault
    Password,
    /// Encrypt an environment again with a new key
    Rekey { environment: String },
    /// Regain the keys with the recovery key (and set a new password for a file vault)
    Recover,
    /// Replace the recovery key (the old one stops working)
    RecoveryKey,
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Show the log of the Envy server instead (admins only)
    #[arg(long)]
    pub server: bool,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Server URL (https://, or http:// for localhost). Defaults to "server" in the manifest.
    pub url: Option<String>,
    /// Join the server with the invite an admin created (`envy user add`)
    #[arg(long, conflicts_with = "root_token", requires = "name")]
    pub invite: Option<String>,
    /// Become the first admin with the root token printed by `envy serve --init`
    #[arg(long, requires = "name")]
    pub root_token: Option<String>,
    /// Member name to join with
    #[arg(long)]
    pub name: Option<String>,
    /// Print the new identity once instead of storing it in the keyring (for CI secrets)
    #[arg(long)]
    pub print_identity: bool,
}

#[derive(Debug, Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub action: UserAction,
}

#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// Invite a new member; prints a one-time invite
    Add {
        name: String,
        /// Let the member manage other members
        #[arg(long)]
        admin: bool,
    },
    /// Activate a member that joined, after comparing its fingerprint out of band
    Approve {
        name: String,
        /// The fingerprint the member saw when it joined
        #[arg(long)]
        fingerprint: String,
        /// Environment of this project it may use (repeat it); `*` means every one
        #[arg(long = "env", required = true)]
        environments: Vec<String>,
        /// Let it change values, not only read them
        #[arg(long)]
        write: bool,
    },
    /// Remove a member and replace the keys it could read
    Rm { name: String },
    /// List the members and their fingerprints
    List,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Folder of the database
    #[arg(long, default_value = "envy-data")]
    pub data: PathBuf,
    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1:8443")]
    pub listen: String,
    /// TLS certificate (PEM); with --tls-key the server speaks https
    #[arg(long, requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,
    /// TLS private key (PEM)
    #[arg(long, requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
    /// Plain HTTP on any address, for a TLS proxy in front (client addresses from X-Forwarded-For)
    #[arg(long)]
    pub behind_proxy: bool,
    /// Hours a login lasts
    #[arg(long, default_value_t = 12)]
    pub session_ttl: u32,
    /// Prepare an empty data folder and print the root token once
    #[arg(long)]
    pub init: bool,
    /// With --init: write the root token to this file instead of printing it
    #[arg(long, requires = "init")]
    pub init_output: Option<PathBuf>,
    /// Print a new root token for an existing server (to add an admin) and exit
    #[arg(long, conflicts_with = "init")]
    pub new_root_token: bool,
    /// Remove a project from the server and exit, freeing its id (its values are lost)
    #[arg(long, value_name = "ID", conflicts_with_all = ["init", "new_root_token"])]
    pub remove_project: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_wins_over_the_environment_variable() {
        assert_eq!(
            Backend::forced(Some(Backend::File), Some("remote")).unwrap(),
            Some(Backend::File)
        );
        assert_eq!(
            Backend::forced(None, Some("Remote")).unwrap(),
            Some(Backend::Remote)
        );
    }

    #[test]
    fn nothing_configured_forces_nothing() {
        assert_eq!(Backend::forced(None, None).unwrap(), None);
        assert_eq!(Backend::forced(None, Some("")).unwrap(), None);
    }

    #[test]
    fn an_unknown_backend_is_an_error() {
        let err = Backend::forced(None, Some("s3")).unwrap_err().to_string();
        assert!(err.contains("ENVY_BACKEND='s3'"), "{err}");
    }
}
