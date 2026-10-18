//! Interactive input.

use anyhow::{Context, Result};

use crate::schema::Secret;

pub trait Prompter {
    /// Asks for a value without echoing it. An empty answer means "skip".
    fn ask_secret(&self, label: &str) -> Result<Secret>;
}

pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn ask_secret(&self, label: &str) -> Result<Secret> {
        let value = rpassword::prompt_password(format!("{label}: "))
            .context("Could not read the value from the terminal")?;
        Ok(Secret::new(value))
    }
}
