//! End-to-end tests of the compiled `envy` binary. They only use commands that do not
//! touch the OS keyring, so they also run on machines without a secret service.

use assert_cmd::Command;
use predicates::prelude::*;

/// Runs the binary with no configuration at all: the values embedded at build time are used.
fn envy(dir: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("envy").unwrap();
    cmd.current_dir(dir.path())
        .env_remove("FILE_NAME")
        .env_remove("SCHEMA_PATH")
        // The tests must not depend on (or hit) the network.
        .env("ENVY_NO_UPDATE_CHECK", "1");
    cmd
}

#[test]
fn version_flag_and_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("envy"));
    envy(&dir)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_every_command_of_the_readme() {
    let dir = tempfile::tempdir().unwrap();
    let assert = envy(&dir).arg("help").assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for command in [
        "init", "import", "version", "update", "switch", "schema", "up", "set", "rm", "rename",
        "export", "run", "fill", "check", "diff", "ls",
    ] {
        assert!(
            out.lines().any(|l| l.trim_start().starts_with(command)),
            "`{command}` is missing from the help:\n{out}"
        );
    }
}

#[test]
fn version_with_the_check_disabled_prints_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let assert = envy(&dir).arg("version").assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_eq!(out.lines().count(), 1, "{out}");
}

#[test]
fn works_without_any_configuration() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .args(["init", "Demo", "--new"])
        .assert()
        .success();
    assert!(dir.path().join("envy.json").is_file());
}

#[test]
fn schema_path_written_to_new_manifests_comes_from_envy_json() {
    let repo: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/envy.json")).unwrap(),
    )
    .unwrap();
    // `cargo test` builds the debug profile, which embeds the `development` values.
    let expected = repo["schemas"]["development"]["SCHEMA_PATH"]["default"]
        .as_str()
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .args(["init", "Demo", "--new"])
        .assert()
        .success();
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("envy.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["$schema"], expected);
}

#[test]
fn environment_variables_override_the_embedded_values() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .env("FILE_NAME", "custom.json")
        .env("SCHEMA_PATH", "https://example.com/schema.json")
        .args(["init", "Demo", "--new"])
        .assert()
        .success();

    assert!(!dir.path().join("envy.json").exists());
    let manifest = std::fs::read_to_string(dir.path().join("custom.json")).unwrap();
    assert!(
        manifest.contains("\"$schema\": \"https://example.com/schema.json\""),
        "{manifest}"
    );
}

#[test]
fn empty_environment_variables_fall_back_to_the_embedded_values() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .env("FILE_NAME", "")
        .env("SCHEMA_PATH", "")
        .args(["init", "Demo", "--new"])
        .assert()
        .success();
    assert!(dir.path().join("envy.json").is_file());
}

#[test]
fn commands_fail_with_exit_code_one_before_init() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .arg("check")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Use `envy init` first"));
}

#[test]
fn init_schema_switch_and_up_work_through_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .args(["init", "Demo", "--new"])
        .assert()
        .success();

    let manifest = std::fs::read_to_string(dir.path().join("envy.json")).unwrap();
    assert!(manifest.contains("\"name\": \"Demo\""), "{manifest}");
    assert!(manifest.contains("\"$schema\":"), "{manifest}");

    envy(&dir).args(["schema", "dev"]).assert().success();
    envy(&dir).args(["switch", "dev"]).assert().success();
    assert!(dir.path().join(".envy-state").is_file());
    envy(&dir)
        .arg("up")
        .assert()
        .success()
        .stdout(predicate::str::contains("No changes detected"));
    envy(&dir)
        .arg("schema")
        .assert()
        .success()
        .stdout(predicate::str::contains("[dev]"));
    envy(&dir)
        .args(["init", "Again", "--new"])
        .assert()
        .failure();
}

#[test]
fn check_on_a_manifest_without_variables_passes() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir)
        .args(["init", "Demo", "--new"])
        .assert()
        .success();
    envy(&dir).args(["schema", "dev"]).assert().success();
    envy(&dir)
        .args(["check", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("All good"));
}

#[test]
fn unknown_commands_are_rejected_by_the_parser() {
    let dir = tempfile::tempdir().unwrap();
    envy(&dir).arg("frobnicate").assert().failure().code(2);
}

#[cfg(unix)]
#[test]
fn the_repository_manifest_is_valid_for_its_own_schema() {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/envy.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["schemas"]["production"]["FILE_NAME"]["type"],
        "string"
    );
}

#[test]
fn the_project_is_found_from_a_subdirectory_and_with_dash_c() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    let api = dir.path().join("services/api");
    std::fs::create_dir_all(api.join("src")).unwrap();

    let mut cmd = envy(&dir);
    cmd.current_dir(&api)
        .args(["init", "Api", "--new"])
        .assert()
        .success();
    assert!(api.join("envy.json").is_file());

    let mut cmd = envy(&dir);
    cmd.current_dir(api.join("src"))
        .args(["schema", "dev"])
        .assert()
        .success();
    envy(&dir)
        .args(["-C", "services/api", "schema"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Api (v2)"))
        .stdout(predicate::str::contains("[dev]"));
    // `-C` is global, so it also works after the subcommand.
    envy(&dir)
        .args(["schema", "-C", "services/api/src"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Api (v2)"));
    envy(&dir)
        .args(["-C", "nope", "schema"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("'nope' is not a directory"));
}
