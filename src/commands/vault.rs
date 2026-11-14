use std::io::Write;

use anyhow::{Result, bail};

use crate::{
    cli::{Backend, VaultAction, VaultArgs},
    context::Context,
    envy::Envy,
    keys,
    mnemonic::{self, Entropy, WORD_COUNT},
    schema::Secret,
};

/// Words of a new recovery key the user must type back.
const CONFIRMED_WORDS: usize = 3;

pub fn run(ctx: &Context, args: &VaultArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let backend = ctx.backends.current(&envy.id)?;
    if backend != Backend::File {
        bail!(
            "This project uses the {} backend; `envy vault` only manages the file backend (see `envy migrate --to file`).",
            backend.name()
        );
    }
    match &args.action {
        VaultAction::Password => password(ctx, &envy, out),
        VaultAction::Rekey { environment } => rekey(ctx, &envy, environment, out),
        VaultAction::Recover => recover(ctx, &envy, out),
        VaultAction::RecoveryKey => recovery_key(ctx, &envy, out),
    }
}

fn password(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<()> {
    let file = ctx.backends.file;
    file.unlock(&envy.id)?;
    let new = new_password(ctx, false)?;
    file.change_password(&envy.id, &new)?;
    ctx.record(envy, "vault-password", None, Vec::new())?;
    writeln!(out, "The file vault has a new password.")?;
    Ok(())
}

fn rekey(ctx: &Context, envy: &Envy, environment: &str, out: &mut dyn Write) -> Result<()> {
    let environment = ctx.target_environment(envy, Some(environment))?;
    let key_id = ctx.backends.file.rekey(&envy.id, &environment)?;
    ctx.record(envy, "vault-rekey", Some(&environment), Vec::new())?;
    writeln!(
        out,
        "'{environment}' is encrypted with a new key (key {key_id}), its history included."
    )?;
    Ok(())
}

fn recover(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<()> {
    let phrase = ctx
        .prompter
        .ask_secret(&format!("Recovery key ({WORD_COUNT} words)"))?;
    let entropy = mnemonic::decode(phrase.expose_secret())?;
    let file = ctx.backends.file;
    file.check_recovery(&envy.id, &entropy)?;
    let new = new_password(ctx, false)?;
    file.recover(&envy.id, &entropy, &new)?;
    ctx.record(envy, "vault-recover", None, Vec::new())?;
    writeln!(
        out,
        "The file vault is open again with a new password. Consider `envy vault recovery-key`: the recovery key was just typed on this machine."
    )?;
    Ok(())
}

fn recovery_key(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<()> {
    let file = ctx.backends.file;
    file.unlock(&envy.id)?;
    let entropy = new_recovery_key(ctx, out)?;
    file.replace_recovery(&envy.id, &entropy)?;
    ctx.record(envy, "vault-recovery-key", None, Vec::new())?;
    writeln!(
        out,
        "The new recovery key is in place; the old one no longer opens the vault."
    )?;
    Ok(())
}

/// A new password: `ENVY_VAULT_PASSWORD` when `allow_preset` and it is set, otherwise typed
/// twice.
pub(crate) fn new_password(ctx: &Context, allow_preset: bool) -> Result<Secret> {
    if allow_preset && let Some(preset) = &ctx.config.vault_password {
        return Ok(preset.clone());
    }
    let first = ctx.prompter.ask_secret("New password for the file vault")?;
    if first.expose_secret().is_empty() {
        bail!("The password can't be empty.");
    }
    let again = ctx.prompter.ask_secret("Repeat the password")?;
    if first.expose_secret() != again.expose_secret() {
        bail!("The passwords do not match.");
    }
    Ok(first)
}

/// Shows a new recovery key once and asks for some of its words back, so a key that was not
/// written down is caught before anything depends on it.
pub(crate) fn new_recovery_key(ctx: &Context, out: &mut dyn Write) -> Result<Entropy> {
    let entropy = keys::random_key();
    let phrase = mnemonic::encode(&entropy);
    let words: Vec<&str> = phrase.expose_secret().split(' ').collect();

    writeln!(
        out,
        "Recovery key: write these {WORD_COUNT} words down, in order, and keep them offline."
    )?;
    writeln!(
        out,
        "They are shown only once and open the vault if the password is lost."
    )?;
    for row in words.chunks(6).enumerate() {
        let (start, chunk) = (row.0 * 6, row.1);
        let line: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(i, word)| format!("{:>3}. {word:<9}", start + i + 1))
            .collect();
        writeln!(out, "{}", line.join(" ").trim_end())?;
    }
    out.flush()?;

    for position in positions_to_confirm() {
        let answer = ctx
            .prompter
            .ask_secret(&format!("Word #{} of the recovery key", position + 1))?;
        if answer.expose_secret().trim().to_lowercase() != words[position] {
            bail!(
                "That is not word #{} of the recovery key. Nothing was changed; run the command again.",
                position + 1
            );
        }
    }
    Ok(entropy)
}

fn positions_to_confirm() -> Vec<usize> {
    let mut positions = Vec::with_capacity(CONFIRMED_WORDS);
    for byte in keys::random_key().iter() {
        let position = usize::from(*byte) % WORD_COUNT;
        if !positions.contains(&position) {
            positions.push(position);
        }
        if positions.len() == CONFIRMED_WORDS {
            break;
        }
    }
    positions.sort_unstable();
    positions
}
