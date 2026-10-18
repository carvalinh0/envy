//! Spawning child processes with injected environment variables.

use std::process::Command;

use anyhow::{Context, Result};

use crate::schema::Secret;

pub trait ProcessRunner {
    /// Runs `program`, returning its exit code.
    fn run(&self, program: &str, args: &[String], envs: &[(String, Secret)]) -> Result<i32>;
}

pub struct SystemRunner;

impl ProcessRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String], envs: &[(String, Secret)]) -> Result<i32> {
        let mut command = Command::new(program);
        command.args(args);
        for (key, value) in envs {
            command.env(key, value.expose_secret());
        }

        let status = command
            .status()
            .with_context(|| format!("Could not start '{program}'"))?;

        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return Ok(128 + signal);
            }
        }
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn propagates_the_exit_code() {
        let code = SystemRunner
            .run("sh", &["-c".into(), "exit 7".into()], &[])
            .unwrap();
        assert_eq!(code, 7);
    }

    #[test]
    fn injects_variables() {
        let envs = [("ENVY_TEST_VALUE".to_string(), Secret::new("42"))];
        let code = SystemRunner
            .run(
                "sh",
                &["-c".into(), "test \"$ENVY_TEST_VALUE\" = 42".into()],
                &envs,
            )
            .unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn missing_program_is_an_error() {
        assert!(SystemRunner.run("envy-no-such-program", &[], &[]).is_err());
    }
}
