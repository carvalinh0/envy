use std::{fs, io::Write};

use anyhow::{Context as _, Result, bail};
use zeroize::Zeroizing;

use crate::{
    bundle::{ALL_SCOPE, Bundle, BundleEntries},
    cli::ExportArgs,
    context::Context,
    envy::GLOBAL_ENV,
};

pub fn run(ctx: &Context, args: &ExportArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;

    let (scope, environments): (String, Vec<String>) = match &args.environment {
        Some(name) => {
            let name = ctx.target_environment(&envy, Some(name))?;
            let mut list = vec![name.clone()];
            if name != GLOBAL_ENV && envy.has_environment(GLOBAL_ENV) {
                list.push(GLOBAL_ENV.to_string());
            }
            (name, list)
        }
        None => (
            ALL_SCOPE.to_string(),
            envy.environment_names()
                .into_iter()
                .map(str::to_string)
                .collect(),
        ),
    };

    // Only this project's own values are exported: a workspace member's bundle does not
    // carry the root's values (export them from the root).
    let mut entries = BundleEntries::new();
    for environment in &environments {
        for key in envy.effective_schema(environment)?.keys() {
            if let Some(value) = ctx.vault.get(&envy.id, environment, key)? {
                entries.entry(environment.clone()).or_default().insert(
                    key.clone(),
                    Zeroizing::new(value.expose_secret().to_string()),
                );
            }
        }
    }

    let bundle = Bundle {
        project_id: envy.id.clone(),
        project_name: envy.name.clone(),
        scope,
        entries,
    };
    if bundle.value_count() == 0 {
        bail!("There are no values in the vault to export.");
    }

    let path = ctx.config.base_dir.join(bundle.file_name());
    if path.exists() {
        bail!(
            "{} already exists, move or remove it first.",
            path.display()
        );
    }

    let (data, key) = ctx.codec.seal(&bundle)?;
    fs::write(&path, data).with_context(|| format!("Could not write {}", path.display()))?;

    writeln!(
        out,
        "Exported {} value(s) to {}",
        bundle.value_count(),
        path.display()
    )?;
    writeln!(
        out,
        "Key (shown only once, share it through a different channel): {}",
        key.as_str()
    )?;
    Ok(())
}
