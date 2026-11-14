use std::io::Write;

use anyhow::Result;

use crate::{
    cli::ProtectArgs,
    context::Context,
    protect::CHECK_SLOT,
    vault::{Change, SecretVault},
};

/// Decrypts through [`Context::secrets`] and writes through the raw vault, so the values
/// land in plain text whatever the manifest says.
pub fn run(ctx: &Context, args: &ProtectArgs, out: &mut dyn Write) -> Result<()> {
    let mut envy = ctx.load_envy()?;
    let environment = ctx.target_environment(&envy, Some(&args.environment))?;

    let vault = ctx.secrets(&envy);
    let rewrite = Change {
        keep: 0,
        ..ctx.change(&envy)
    };
    let mut opened = Vec::new();
    for key in envy.effective_schema(&environment)?.keys() {
        if let Some(value) = vault.get(&envy.id, &environment, key)? {
            ctx.vault
                .set(&envy.id, &environment, key, &value, rewrite)?;
            opened.push(key.clone());
        }
    }
    ctx.vault.delete(&envy.id, &environment, CHECK_SLOT)?;

    if envy.unprotect(&environment)? {
        ctx.save_envy(&envy)?;
    }
    writeln!(
        out,
        "'{environment}' is no longer protected: {} value(s) decrypted.",
        opened.len()
    )?;
    ctx.record(&envy, "unprotect", Some(&environment), opened)
}
