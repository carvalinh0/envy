use std::io::Write;

use anyhow::Result;

use crate::{
    cli::ProtectArgs,
    context::Context,
    vault::{Change, SecretVault},
};

/// Also run by a teammate after pulling a manifest that protects an environment: it seals
/// the values stored on this machine even when the manifest already lists it.
pub fn run(ctx: &Context, args: &ProtectArgs, out: &mut dyn Write) -> Result<()> {
    let mut envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, Some(&args.environment))?;
    let added = envy.protect(&environment)?;

    let vault = ctx.secrets(&envy);
    vault.ensure_password(&environment)?;

    // Rewriting with no history drops the versions stored before the protection, which
    // would otherwise stay readable without the password.
    let rewrite = Change {
        keep: 0,
        ..ctx.change(&envy)
    };
    let mut sealed = Vec::new();
    for key in envy.effective_schema(&environment)?.keys() {
        match vault.get(&envy.id, &environment, key)? {
            Some(value) => {
                vault.set(&envy.id, &environment, key, &value, rewrite)?;
                sealed.push(key.clone());
            }
            None => {
                ctx.vault.delete(&envy.id, &environment, key)?;
            }
        }
    }

    if added {
        ctx.save_envy(&envy)?;
    }
    writeln!(
        out,
        "'{environment}' is protected: {} value(s) encrypted, history cleared.",
        sealed.len()
    )?;
    if added {
        writeln!(
            out,
            "Commit {} so the rest of the team protects it too (schema version {}).",
            ctx.config.file_name, envy.version
        )?;
    }
    ctx.record(&envy, "protect", Some(&environment), sealed)
}
