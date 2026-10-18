mod common;

use common::{Harness, PROJECT_ID, sample_envy};

const SECRET_VALUE: &str = "s3cr3t-value-123";

fn populated() -> Harness {
    let h = Harness::with_manifest();
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://u@localhost/db"]);
    h.ok(&["set", "dev", "API_TOKEN", SECRET_VALUE]);
    h.ok(&["set", "prod", "API_TOKEN", "prod-token"]);
    h.ok(&["set", "global", "APP_NAME", "shared-name"]);
    h
}

fn key_from(output: &str) -> String {
    output
        .lines()
        .find(|l| l.starts_with("Key"))
        .and_then(|l| l.rsplit(": ").next())
        .expect("the export must print the key")
        .trim()
        .to_string()
}

/// A second machine: same manifest (cloned from Git), empty vault.
fn teammate() -> Harness {
    let other = Harness::new();
    sample_envy().save(&other.config.manifest_path()).unwrap();
    other
}

#[test]
fn export_all_writes_an_encrypted_bundle_and_prints_the_key_once() {
    let h = populated();
    let out = h.ok(&["export"]);

    assert!(h.exists("Sample.all.envy"), "{out}");
    assert!(out.contains("Exported 4 value(s)"), "{out}");
    let key = key_from(&out);
    assert_eq!(key.len(), 44, "256 bits in base64: {key}");

    let file = std::fs::read_to_string(h.path("Sample.all.envy")).unwrap();
    for leaked in [
        SECRET_VALUE,
        "prod-token",
        "shared-name",
        "postgres://",
        "API_TOKEN",
        &key,
    ] {
        assert!(!file.contains(leaked), "the bundle leaks '{leaked}'");
    }
}

#[test]
fn export_one_environment_includes_global_and_nothing_else() {
    let h = populated();
    let out = h.ok(&["export", "dev"]);
    assert!(h.exists("Sample.dev.envy"));
    assert!(out.contains("Exported 3 value(s)"), "{out}");
}

#[test]
fn each_export_generates_a_new_key() {
    let h = populated();
    let first = key_from(&h.ok(&["export", "dev"]));
    std::fs::remove_file(h.path("Sample.dev.envy")).unwrap();
    let second = key_from(&h.ok(&["export", "dev"]));
    assert_ne!(first, second);
}

#[test]
fn export_refuses_to_overwrite_a_bundle() {
    let h = populated();
    h.ok(&["export", "dev"]);
    assert!(h.err(&["export", "dev"]).contains("already exists"));
}

#[test]
fn export_without_values_fails() {
    let h = Harness::with_manifest();
    assert!(h.err(&["export"]).contains("no values"));
    assert!(!h.exists("Sample.all.envy"));
}

#[test]
fn export_unknown_environment_fails() {
    let h = populated();
    assert!(
        h.err(&["export", "nope"])
            .contains("There's no environment called 'nope'")
    );
}

#[test]
fn import_restores_the_values_on_another_machine() {
    let h = populated();
    let key = key_from(&h.ok(&["export"]));

    let other = teammate();
    std::fs::copy(h.path("Sample.all.envy"), other.path("Sample.all.envy")).unwrap();
    let out = other.ok(&["import", "Sample.all.envy", &key]);

    assert!(out.contains("Imported 4 value(s)"), "{out}");
    assert_eq!(
        other.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(SECRET_VALUE)
    );
    assert_eq!(
        other.stored(PROJECT_ID, "prod", "API_TOKEN").as_deref(),
        Some("prod-token")
    );
    assert_eq!(
        other.stored(PROJECT_ID, "global", "APP_NAME").as_deref(),
        Some("shared-name")
    );
    other.ok(&["check", "dev"]);
    assert!(!out.contains(SECRET_VALUE));
}

#[test]
fn import_accepts_an_absolute_path() {
    let h = populated();
    let key = key_from(&h.ok(&["export", "dev"]));
    let other = teammate();
    let path = h.path("Sample.dev.envy");
    other.ok(&["import", path.to_str().unwrap(), &key]);
    assert_eq!(
        other.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(SECRET_VALUE)
    );
}

#[test]
fn import_with_the_wrong_key_changes_nothing() {
    let h = populated();
    h.ok(&["export"]);
    let wrong = key_from(&{
        let spare = populated();
        spare.ok(&["export"])
    });

    let other = teammate();
    std::fs::copy(h.path("Sample.all.envy"), other.path("Sample.all.envy")).unwrap();
    let err = other.err(&["import", "Sample.all.envy", &wrong]);
    assert!(err.contains("Wrong key"), "{err}");
    assert!(other.vault.is_empty());
}

#[test]
fn import_rejects_a_bundle_from_another_project() {
    let h = populated();
    let key = key_from(&h.ok(&["export"]));

    let other = Harness::new();
    let mut envy = sample_envy();
    envy.id = "another-project".into();
    envy.checksum = envy.compute_checksum().unwrap();
    envy.save(&other.config.manifest_path()).unwrap();
    std::fs::copy(h.path("Sample.all.envy"), other.path("Sample.all.envy")).unwrap();

    let err = other.err(&["import", "Sample.all.envy", &key]);
    assert!(err.contains("belongs to another project"), "{err}");
    assert!(other.vault.is_empty());
}

#[test]
fn import_skips_values_that_are_no_longer_declared() {
    let h = populated();
    let key = key_from(&h.ok(&["export", "dev"]));

    let other = teammate();
    let mut envy = other.manifest();
    envy.remove_variable("dev", "API_TOKEN").unwrap();
    envy.save(&other.config.manifest_path()).unwrap();
    std::fs::copy(h.path("Sample.dev.envy"), other.path("Sample.dev.envy")).unwrap();

    let out = other.ok(&["import", "Sample.dev.envy", &key]);
    assert!(out.contains("Skipped 'API_TOKEN' in 'dev'"), "{out}");
    assert!(
        out.contains("Imported 2 value(s)") && out.contains("1 skipped"),
        "{out}"
    );
    assert_eq!(other.stored(PROJECT_ID, "dev", "API_TOKEN"), None);
}

#[test]
fn import_of_a_missing_or_invalid_file_fails() {
    let other = teammate();
    assert!(
        other
            .err(&["import", "missing.envy", "aaaa"])
            .contains("Could not read")
    );
    other.write("garbage.envy", "hello");
    assert!(
        other
            .err(&["import", "garbage.envy", "aaaa"])
            .contains("not a valid Envy bundle")
    );
}
