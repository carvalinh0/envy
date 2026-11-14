//! Everything a command needs, injected as abstractions (dependency inversion).

use std::{io::Write, path::Path};

use anyhow::{Result, anyhow, bail};

use crate::{
    audit::{AuditEvent, AuditLog},
    bundle::BundleCodec,
    clock::Clock,
    config::Config,
    envy::Envy,
    inference::TypeInferrer,
    prompt::Prompter,
    runner::ProcessRunner,
    state::StateStore,
    update::{ReleaseSource, SelfUpdater},
    vault::{Change, SecretVault},
    workspace,
};

pub struct Context<'a> {
    pub config: &'a Config,
    pub vault: &'a dyn SecretVault,
    pub state: &'a dyn StateStore,
    pub prompter: &'a dyn Prompter,
    pub runner: &'a dyn ProcessRunner,
    pub codec: &'a dyn BundleCodec,
    pub inferrer: &'a dyn TypeInferrer,
    pub releases: &'a dyn ReleaseSource,
    pub updater: &'a dyn SelfUpdater,
    pub clock: &'a dyn Clock,
    pub audit: &'a dyn AuditLog,
}

impl<'a> Context<'a> {
    /// A write made now, keeping as many versions as the manifest asks for.
    pub fn change(&self, envy: &Envy) -> Change {
        Change {
            at: self.clock.now(),
            keep: envy.history_keep(),
        }
    }

    /// Appends to the project's audit log. Only names go in, never values.
    pub fn record(
        &self,
        envy: &Envy,
        action: &str,
        environment: Option<&str>,
        keys: Vec<String>,
    ) -> Result<()> {
        let event = AuditEvent {
            at: self.clock.now(),
            user: self.config.user.clone(),
            action: action.to_string(),
            environment: environment.map(str::to_string),
            keys,
        };
        self.audit.record(&envy.id, &event)
    }

    /// Loads the project's manifest and, for a workspace member, the root it inherits from.
    pub fn load_envy(&self) -> Result<Envy> {
        let path = self.config.manifest_path();
        if !path.is_file() {
            bail!(
                "The file '{}' does not exist. Use `envy init` first.",
                self.config.file_name
            );
        }
        workspace::load_project(&self.config.base_dir, &self.config.file_name)
    }

    /// Warns about other manifests of the repository that use the same project id: they
    /// would silently read and write each other's secrets.
    pub fn warn_shared_id(&self, envy: &Envy, out: &mut dyn Write) -> Result<()> {
        let sharing =
            workspace::manifests_sharing_id(&self.config.base_dir, &self.config.file_name, envy)?;
        if sharing.is_empty() {
            return Ok(());
        }
        writeln!(
            out,
            "warning: {} other manifest(s) use the id of this project, so they share its secrets:",
            sharing.len()
        )?;
        for path in &sharing {
            writeln!(out, "  {}", self.display_path(path))?;
        }
        writeln!(
            out,
            "Run `envy up --new-id` in the project that was copied to give it its own id."
        )?;
        Ok(())
    }

    /// `path` relative to the directory Envy was started in, when it is inside it. Always
    /// with `/` separators, like the `workspace.members` patterns.
    pub fn display_path(&self, path: &Path) -> String {
        let shown = path
            .strip_prefix(&self.config.start_dir)
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .unwrap_or(path)
            .display()
            .to_string();
        if cfg!(windows) {
            shown.replace('\\', "/")
        } else {
            shown
        }
    }

    pub fn save_envy(&self, envy: &Envy) -> Result<()> {
        envy.save(&self.config.manifest_path())
    }

    /// The environment named explicitly, or else the active one. It must exist in the manifest.
    pub fn target_environment(&self, envy: &Envy, explicit: Option<&str>) -> Result<String> {
        let name = match explicit {
            Some(name) => name.to_string(),
            None => self.state.active()?.ok_or_else(|| {
                anyhow!(
                    "No active environment. Run `envy switch <env>` or pass the environment explicitly."
                )
            })?,
        };
        if !envy.has_environment(&name) {
            bail!("There's no environment called '{name}'");
        }
        Ok(name)
    }
}
