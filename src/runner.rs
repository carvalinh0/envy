//! Spawning child processes with injected environment variables.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};

use crate::schema::Secret;

pub trait ProcessRunner {
    /// Runs `program`, returning its exit code.
    fn run(&self, program: &str, args: &[String], envs: &[(String, Secret)]) -> Result<i32>;
}

/// Envy's own credentials, read from its environment. The child gets the values of one
/// environment, not the keys to every environment (an identity reads all it was granted, the
/// passwords open every protected environment and the file vault), so they are removed unless
/// the manifest declares a variable with that name.
const CREDENTIALS: [&str; 3] = [
    "ENVY_IDENTITY",
    "ENVY_VAULT_PASSWORD",
    "ENVY_PROTECT_PASSWORD",
];

fn command(program: &str, args: &[String], envs: &[(String, Secret)]) -> Command {
    #[cfg(windows)]
    let mut command = Command::new(find_in_path(
        program,
        std::env::var_os("PATH"),
        std::env::var("PATHEXT").ok(),
    ));
    #[cfg(not(windows))]
    let mut command = Command::new(program);
    command.args(args);
    for name in CREDENTIALS {
        command.env_remove(name);
    }
    for (key, value) in envs {
        command.env(key, value.expose_secret());
    }
    command
}

pub struct SystemRunner;

impl ProcessRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String], envs: &[(String, Secret)]) -> Result<i32> {
        let status = command(program, args, envs)
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

/// Windows only finds `.exe` files by itself, so `npm` (really `npm.cmd`) would not start.
/// This looks the program up in `path` with each extension of `pathext`, like `cmd.exe`
/// does. A program with a folder or an extension is returned as given.
#[cfg_attr(not(windows), allow(dead_code))]
fn find_in_path(program: &str, path: Option<OsString>, pathext: Option<String>) -> PathBuf {
    let given = Path::new(program);
    if given.extension().is_some() || given.components().count() > 1 {
        return given.to_path_buf();
    }
    let Some(path) = path else {
        return given.to_path_buf();
    };
    let pathext = pathext.unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    for dir in std::env::split_paths(&path) {
        for extension in pathext.split(';').filter(|e| !e.is_empty()) {
            let candidate = dir.join(format!("{program}{extension}"));
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    given.to_path_buf()
}

#[cfg(test)]
mod environment_tests {
    use super::*;

    #[test]
    fn envys_own_credentials_never_reach_the_child() {
        let envs = vec![("API_TOKEN".to_string(), Secret::new("t"))];
        let command = command("node", &[], &envs);
        let set: Vec<_> = command.get_envs().collect();
        for name in CREDENTIALS {
            assert!(
                set.contains(&(std::ffi::OsStr::new(name), None)),
                "{name} is not removed"
            );
        }
        assert!(set.contains(&(
            std::ffi::OsStr::new("API_TOKEN"),
            Some(std::ffi::OsStr::new("t"))
        )));
    }

    #[test]
    fn a_declared_variable_with_the_same_name_still_reaches_it() {
        let envs = vec![("ENVY_IDENTITY".to_string(), Secret::new("declared"))];
        let command = command("node", &[], &envs);
        let identity = command
            .get_envs()
            .find(|(name, _)| *name == "ENVY_IDENTITY")
            .and_then(|(_, value)| value);
        assert_eq!(identity, Some(std::ffi::OsStr::new("declared")));
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::*;

    fn path_of(dirs: &[&Path]) -> Option<OsString> {
        Some(std::env::join_paths(dirs).unwrap())
    }

    #[test]
    fn finds_a_script_through_pathext() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(second.path().join("npm.CMD"), "").unwrap();
        std::fs::write(second.path().join("npm"), "").unwrap();

        let found = find_in_path(
            "npm",
            path_of(&[first.path(), second.path()]),
            Some(".EXE;.CMD".into()),
        );
        assert_eq!(found, second.path().join("npm.CMD"));
    }

    #[test]
    fn the_extension_order_of_pathext_wins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tool.EXE"), "").unwrap();
        std::fs::write(dir.path().join("tool.CMD"), "").unwrap();
        let found = find_in_path("tool", path_of(&[dir.path()]), Some(".EXE;.CMD".into()));
        assert_eq!(found, dir.path().join("tool.EXE"));
    }

    #[test]
    fn programs_with_an_extension_or_a_folder_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("node.exe.CMD"), "").unwrap();
        let path = path_of(&[dir.path()]);
        assert_eq!(
            find_in_path("node.exe", path.clone(), None),
            PathBuf::from("node.exe")
        );
        assert_eq!(
            find_in_path("bin/node", path, None),
            PathBuf::from("bin/node")
        );
    }

    #[test]
    fn unknown_programs_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            find_in_path("nope", path_of(&[dir.path()]), None),
            PathBuf::from("nope")
        );
        assert_eq!(find_in_path("nope", None, None), PathBuf::from("nope"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn propagates_the_exit_code() {
        let code = SystemRunner
            .run("cmd", &["/C".into(), "exit 7".into()], &[])
            .unwrap();
        assert_eq!(code, 7);
    }

    #[test]
    fn injects_variables() {
        let envs = [("ENVY_TEST_VALUE".to_string(), Secret::new("42"))];
        let script = "if ($env:ENVY_TEST_VALUE -eq '42') { exit 0 } else { exit 1 }";
        let code = SystemRunner
            .run(
                "powershell",
                &["-NoProfile".into(), "-Command".into(), script.into()],
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
