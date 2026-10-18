mod common;

use common::Harness;

#[test]
fn schema_creates_an_environment_and_bumps_the_version() {
    let h = Harness::with_manifest();
    let out = h.ok(&["schema", "staging"]);
    assert!(out.contains("Created environment 'staging'"), "{out}");

    let envy = h.manifest();
    assert!(envy.has_environment("staging"));
    assert_eq!(envy.version, 2);
    assert!(envy.is_checksum_valid().unwrap());
}

#[test]
fn schema_rejects_duplicates_without_touching_the_file() {
    let h = Harness::with_manifest();
    let err = h.err(&["schema", "dev"]);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(h.manifest().version, 1);
}

#[test]
fn schema_without_arguments_prints_the_declarations() {
    let h = Harness::with_manifest();
    let out = h.ok(&["schema"]);
    assert!(out.contains("Sample (v1)"), "{out}");
    assert!(out.contains("[dev]"), "{out}");
    assert!(out.contains("PORT: port = 3000"), "{out}");
    assert!(out.contains("API_TOKEN: secret"), "{out}");
    assert!(out.contains("[global]"), "{out}");
    assert_eq!(
        h.manifest().version,
        1,
        "showing the schema must not modify it"
    );
}

#[test]
fn switch_stores_the_active_environment() {
    let h = Harness::with_manifest();
    let out = h.ok(&["switch", "prod"]);
    assert!(out.contains("Active environment: prod"), "{out}");
    assert!(h.exists(".envy-state"));
}

#[test]
fn switch_rejects_unknown_environments() {
    let h = Harness::with_manifest();
    let err = h.err(&["switch", "nope"]);
    assert!(
        err.contains("There's no environment called 'nope'"),
        "{err}"
    );
    assert!(!h.exists(".envy-state"));
}

#[test]
fn commands_use_the_active_environment_by_default() {
    let h = Harness::with_manifest();
    h.ok(&["switch", "dev"]);
    let out = h.ok(&["ls"]);
    for key in ["PORT", "DATABASE_URL", "API_TOKEN", "APP_NAME"] {
        assert!(out.contains(key), "{key} missing from:\n{out}");
    }
}

#[test]
fn without_an_active_environment_the_user_is_told_what_to_do() {
    let h = Harness::with_manifest();
    let err = h.err(&["ls"]);
    assert!(err.contains("No active environment"), "{err}");
    assert!(err.contains("envy switch"), "{err}");
}

#[test]
fn up_reports_no_changes_for_a_consistent_manifest() {
    let h = Harness::with_manifest();
    let out = h.ok(&["up"]);
    assert!(out.contains("No changes detected"), "{out}");
    assert_eq!(h.manifest().version, 1);
}

#[test]
fn up_detects_manual_edits_and_bumps_the_version() {
    let h = Harness::with_manifest();
    let text = std::fs::read_to_string(h.config.manifest_path()).unwrap();
    h.write("envy.json", &text.replace("\"PORT\"", "\"HTTP_PORT\""));
    assert!(!h.manifest().is_checksum_valid().unwrap());

    let out = h.ok(&["up"]);
    assert!(out.contains("version 2"), "{out}");

    let envy = h.manifest();
    assert_eq!(envy.version, 2);
    assert!(envy.is_checksum_valid().unwrap());
    assert!(envy.schemas["dev"].contains_key("HTTP_PORT"));

    assert!(h.ok(&["up"]).contains("No changes detected"));
    assert_eq!(h.manifest().version, 2);
}

#[test]
fn up_refuses_to_bless_an_invalid_manifest() {
    let h = Harness::with_manifest();
    let text = std::fs::read_to_string(h.config.manifest_path()).unwrap();
    h.write("envy.json", &text.replace("\"port\"", "\"text\""));
    let err = h.err(&["up"]);
    assert!(err.contains("not a valid type"), "{err}");
    assert!(!h.manifest().is_checksum_valid().unwrap());
}

#[test]
fn a_corrupted_manifest_is_reported_clearly() {
    let h = Harness::new();
    h.write("envy.json", "{ not json");
    let err = h.err(&["check"]);
    assert!(err.contains("Failed to parse"), "{err}");
}
