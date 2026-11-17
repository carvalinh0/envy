//! Interactive input.

use std::io::{IsTerminal, Read};

use anyhow::{Context, Result, bail};

use crate::schema::Secret;

/// Why [`Prompter::read_stdin`] refuses a terminal.
pub const NOTHING_PIPED: &str = "Nothing is piped to Envy. Pipe the value \
     (`<command> | envy set <environment> <variable> --stdin`) or type it with `envy fill`.";

pub trait Prompter {
    /// Asks for a value without echoing it. An empty answer means "skip".
    fn ask_secret(&self, label: &str) -> Result<Secret>;

    /// Everything piped to standard input, so scripts never put a value on a command line,
    /// where other processes can read it. A terminal is refused: what is typed there is
    /// echoed. The default refuses, for prompters written before this existed.
    fn read_stdin(&self) -> Result<Secret> {
        bail!("This prompter can't read standard input")
    }
}

pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn ask_secret(&self, label: &str) -> Result<Secret> {
        let value = rpassword::prompt_password(format!("{label}: "))
            .context("Could not read the value from the terminal")?;
        Ok(Secret::new(value))
    }

    fn read_stdin(&self) -> Result<Secret> {
        let mut stdin = std::io::stdin();
        if stdin.is_terminal() {
            bail!(NOTHING_PIPED);
        }
        let mut value = String::new();
        stdin
            .read_to_string(&mut value)
            .context("Could not read the value from standard input")?;
        Ok(Secret::new(value))
    }
}
