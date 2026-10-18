use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Validate, edit and securely share environment variables
#[derive(Debug, Parser)]
#[command(name = "envy", version, about, long_about = None)]
pub struct Cli {
    /// Run as if Envy was started in DIR
    #[arg(short = 'C', value_name = "DIR", global = true)]
    pub directory: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
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
