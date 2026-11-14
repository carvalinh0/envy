mod common;

use chrono::Duration;
use common::{Harness, PROJECT_ID};
use dot_envy::vault::SecretVault;

const FIRST: &str = "first-s3cr3t";
const SECOND: &str = "second-s3cr3t";

fn twice_set() -> Harness {
    let h = Harness::with_manifest();
    h.ok(&["set", "dev", "API_TOKEN", FIRST]);
    h.clock.advance(Duration::days(2));
    h.ok(&["set", "dev", "API_TOKEN", SECOND]);
    h
}

// ---------- history ----------

#[test]
fn history_lists_versions_newest_first_without_values() {
    let h = twice_set();
    let out = h.ok(&["history", "API_TOKEN", "--in", "dev"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(
        lines[1].starts_with("2 ") && lines[1].contains("(active)"),
        "{out}"
    );
    assert!(lines[1].contains("2027-01-17"), "{out}");
    assert!(
        lines[2].starts_with("1 ") && lines[2].contains("2027-01-15"),
        "{out}"
    );
    assert!(!out.contains(FIRST) && !out.contains(SECOND), "{out}");
}

#[test]
fn history_of_a_variable_without_value_is_an_error() {
    let h = Harness::with_manifest();
    let err = h.err(&["history", "API_TOKEN", "--in", "dev"]);
    assert!(err.contains("has no value stored"), "{err}");
    let err = h.err(&["history", "UNDECLARED", "--in", "dev"]);
    assert!(
        err.contains("There's no variable called 'UNDECLARED'"),
        "{err}"
    );
}

#[test]
fn the_manifest_decides_how_many_versions_are_kept() {
    let h = Harness::with_manifest();
    let mut envy = h.manifest();
    envy.history = Some(dot_envy::envy::HistoryConfig { keep: 1 });
    envy.sync().unwrap();
    envy.save(&h.config.manifest_path()).unwrap();

    for value in ["v1", "v2", "v3"] {
        h.ok(&["set", "dev", "API_TOKEN", value]);
    }
    let versions = h.vault.history(PROJECT_ID, "dev", "API_TOKEN").unwrap();
    let numbers: Vec<u32> = versions.iter().map(|v| v.number).collect();
    assert_eq!(numbers, vec![3, 2]);
}

#[test]
fn rm_also_removes_the_history() {
    let h = twice_set();
    h.ok(&["rm", "API_TOKEN", "--from", "dev"]);
    assert!(
        h.vault
            .history(PROJECT_ID, "dev", "API_TOKEN")
            .unwrap()
            .is_empty()
    );
}

// ---------- rollback ----------

#[test]
fn rollback_restores_the_previous_value_and_can_be_undone() {
    let h = twice_set();
    let out = h.ok(&["rollback", "API_TOKEN", "--in", "dev"]);
    assert!(out.contains("Restored version 1 of 'API_TOKEN'"), "{out}");
    assert!(!out.contains(FIRST), "{out}");
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(FIRST)
    );
    assert_eq!(
        h.vault
            .history(PROJECT_ID, "dev", "API_TOKEN")
            .unwrap()
            .len(),
        3,
        "the rollback is a new version"
    );

    h.ok(&["rollback", "API_TOKEN", "--in", "dev"]);
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(SECOND)
    );
}

#[test]
fn rollback_to_a_specific_version() {
    let h = twice_set();
    h.ok(&["set", "dev", "API_TOKEN", "third"]);
    h.ok(&["rollback", "API_TOKEN", "--in", "dev", "--to", "1"]);
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(FIRST)
    );
}

#[test]
fn rollback_rejects_impossible_targets() {
    let h = twice_set();
    let err = h.err(&["rollback", "API_TOKEN", "--in", "dev", "--to", "2"]);
    assert!(err.contains("version 2 is already active"), "{err}");
    let err = h.err(&["rollback", "API_TOKEN", "--in", "dev", "--to", "9"]);
    assert!(err.contains("there is no version 9"), "{err}");

    let fresh = Harness::with_manifest();
    fresh.ok(&["set", "dev", "API_TOKEN", FIRST]);
    let err = fresh.err(&["rollback", "API_TOKEN", "--in", "dev"]);
    assert!(err.contains("it has no earlier version"), "{err}");
}

#[test]
fn rollback_refuses_a_value_that_no_longer_matches_the_type() {
    let h = Harness::with_manifest();
    let mut envy = h.manifest();
    envy.schemas
        .get_mut("dev")
        .unwrap()
        .get_mut("PORT")
        .unwrap()
        .kind = "string".into();
    envy.sync().unwrap();
    envy.save(&h.config.manifest_path()).unwrap();
    h.ok(&["set", "dev", "PORT", "not-a-port"]);
    h.ok(&["set", "dev", "PORT", "8080"]);

    let mut envy = h.manifest();
    envy.schemas
        .get_mut("dev")
        .unwrap()
        .get_mut("PORT")
        .unwrap()
        .kind = "port".into();
    envy.sync().unwrap();
    envy.save(&h.config.manifest_path()).unwrap();

    let err = h.err(&["rollback", "PORT", "--in", "dev"]);
    assert!(err.contains("is not a valid port anymore"), "{err}");
    assert!(
        !err.contains("not-a-port"),
        "the value must not be echoed: {err}"
    );
    assert_eq!(h.stored(PROJECT_ID, "dev", "PORT").as_deref(), Some("8080"));
}
