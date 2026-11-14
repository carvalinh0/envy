//! Inputs written by releases before 3.0 must keep working: manifests, keyring entries and
//! bundles that know nothing about history, protection or expiry.

mod common;

use common::Harness;
use dot_envy::{
    envy::Envy,
    schema::Secret,
    vault::{CredentialStore, Namespace, SecretVault},
};

/// Checksums computed by the 2.x code before any 3.0 change.
const LEGACY: &str = r#"{"$schema":"./schemas/v1.json","id":"11111111-2222-3333-4444-555555555555","name":"Legacy","version":3,"checksum":"ae36b4d6f8533b7cf2c06ec91ba0de4f9581cbace2bfe1c79c1b5add95d3b178","schemas":{"dev":{"PORT":{"type":"port","default":"3000"},"API_TOKEN":{"type":"secret"}},"global":{"APP":{"type":"string","default":"envy"}}}}"#;
const LEGACY_ROOT: &str = r#"{"id":"11111111-2222-3333-4444-555555555555","name":"Root","version":2,"checksum":"ff137bf0fb98ff88d26b5df06e3f55484ffee212ef268ef83982f8b5879258cd","workspace":{"members":["services/*"]},"schemas":{"prod":{"DB":{"type":"url"}}}}"#;
const LEGACY_ID: &str = "11111111-2222-3333-4444-555555555555";

#[test]
fn manifests_written_by_older_releases_keep_their_checksum() {
    for json in [LEGACY, LEGACY_ROOT] {
        let envy: Envy = serde_json::from_str(json).unwrap();
        assert!(envy.is_checksum_valid().unwrap(), "{json}");
        let saved = serde_json::to_string(&envy).unwrap();
        for key in ["history", "protected"] {
            assert!(!saved.contains(key), "{key} must not appear: {saved}");
        }
    }
}

#[test]
fn a_new_key_changes_the_checksum() {
    let mut envy: Envy = serde_json::from_str(LEGACY).unwrap();
    envy.protected.insert("dev".into());
    assert!(!envy.is_checksum_valid().unwrap());
}

#[test]
fn an_older_project_works_without_changes() {
    let h = Harness::new();
    h.write("envy.json", LEGACY);
    let out = h.ok(&["up"]);
    assert!(out.contains("No changes detected (version 3)"), "{out}");

    // A value stored by an older release: one keyring entry, no history index.
    h.vault
        .write(
            Namespace::Values,
            &format!("{LEGACY_ID}/dev/API_TOKEN"),
            &Secret::new("legacy-token"),
        )
        .unwrap();
    assert!(h.ok(&["check", "dev"]).contains("All good"));

    let out = h.ok(&["history", "API_TOKEN", "--in", "dev"]);
    assert!(
        out.contains("unknown (stored by an older Envy)  (active)"),
        "{out}"
    );

    h.ok(&["set", "dev", "API_TOKEN", "new-token"]);
    h.ok(&["rollback", "API_TOKEN", "--in", "dev"]);
    assert_eq!(
        h.vault
            .get(LEGACY_ID, "dev", "API_TOKEN")
            .unwrap()
            .unwrap()
            .expose_secret(),
        "legacy-token"
    );
    assert_eq!(h.manifest().version, 3, "nothing rewrote the manifest");
}
