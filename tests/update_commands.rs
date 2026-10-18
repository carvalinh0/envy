mod common;

use common::Harness;
use dot_envy::update::UpdateMethod;

fn current_tag() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

// ---------- version notice ----------

#[test]
fn version_prints_only_the_version_when_up_to_date() {
    let h = Harness::new();
    h.releases.publish(&current_tag());
    let out = h.ok(&["version"]);
    assert_eq!(
        out.trim(),
        format!("dot-envy {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn version_announces_a_newer_release() {
    let h = Harness::new();
    h.releases.publish("v999.0.0");
    let out = h.ok(&["version"]);

    assert!(
        out.starts_with(&format!("dot-envy {}", env!("CARGO_PKG_VERSION"))),
        "{out}"
    );
    assert!(out.contains("A new version is available: 999.0.0"), "{out}");
    assert!(out.contains("envy update"), "{out}");
}

#[test]
fn version_does_not_announce_older_releases() {
    let h = Harness::new();
    h.releases.publish("v0.0.1");
    assert_eq!(h.ok(&["version"]).lines().count(), 1);
}

#[test]
fn version_ignores_unparsable_tags() {
    let h = Harness::new();
    h.releases.publish("nightly");
    assert_eq!(h.ok(&["version"]).lines().count(), 1);
}

#[test]
fn version_works_offline_without_complaining() {
    let h = Harness::new(); // nothing published: the lookup fails
    let out = h.ok(&["version"]);
    assert_eq!(out.lines().count(), 1, "{out}");
}

#[test]
fn version_can_skip_the_lookup_entirely() {
    let mut h = Harness::new();
    h.config.update_notice = false;
    h.releases.publish("v999.0.0");

    let out = h.ok(&["version"]);

    assert_eq!(out.lines().count(), 1, "{out}");
    assert_eq!(h.releases.queries.get(), 0, "no request may be made");
}

#[test]
fn version_does_not_need_a_manifest() {
    let h = Harness::new();
    assert!(!h.exists("envy.json"));
    h.ok(&["version"]);
}

// ---------- update ----------

#[test]
fn update_installs_a_newer_release() {
    let h = Harness::new();
    h.releases.publish("v999.1.2");

    let out = h.ok(&["update"]);

    assert_eq!(*h.updater.applied.borrow(), vec!["v999.1.2"]);
    assert!(
        out.contains(&format!(
            "Updating Envy {} -> 999.1.2",
            env!("CARGO_PKG_VERSION")
        )),
        "{out}"
    );
    assert!(out.contains("Updated to 999.1.2."), "{out}");
}

#[test]
fn update_reports_how_it_was_installed() {
    let h = Harness::new();
    h.releases.publish("v999.0.0");

    h.updater.method.set(UpdateMethod::Cargo);
    assert!(h.ok(&["update"]).contains("with cargo"));

    h.updater.method.set(UpdateMethod::BinaryAfterCargoFailed);
    assert!(h.ok(&["update"]).contains("cargo install failed"));
}

#[test]
fn update_does_nothing_when_already_up_to_date() {
    let h = Harness::new();
    h.releases.publish(&current_tag());

    let out = h.ok(&["update"]);

    assert!(out.contains("already up to date"), "{out}");
    assert!(h.updater.applied.borrow().is_empty());
}

#[test]
fn update_never_downgrades() {
    let h = Harness::new();
    h.releases.publish("v0.0.1");

    assert!(h.ok(&["update"]).contains("already up to date"));
    assert!(h.updater.applied.borrow().is_empty());
}

#[test]
fn update_fails_clearly_when_the_release_cannot_be_checked() {
    let h = Harness::new();
    let err = h.err(&["update"]);
    assert!(err.contains("Could not check the latest release"), "{err}");
    assert!(h.updater.applied.borrow().is_empty());
}

#[test]
fn update_rejects_a_release_with_an_unreadable_tag() {
    let h = Harness::new();
    h.releases.publish("nightly");
    let err = h.err(&["update"]);
    assert!(err.contains("not a MAJOR.MINOR.PATCH version"), "{err}");
    assert!(h.updater.applied.borrow().is_empty());
}

#[test]
fn update_propagates_installation_failures() {
    let h = Harness::new();
    h.releases.publish("v999.0.0");
    h.updater.fail.set(true);

    let err = h.err(&["update"]);

    assert!(err.contains("could not replace the executable"), "{err}");
}

#[test]
fn update_works_outside_a_project() {
    let h = Harness::new();
    h.releases.publish("v999.0.0");
    assert!(!h.exists("envy.json"));
    h.ok(&["update"]);
}

#[test]
fn update_does_not_touch_the_project_or_the_vault() {
    let h = Harness::with_manifest();
    h.ok(&["set", "dev", "PORT", "8080"]);
    let before = std::fs::read_to_string(h.config.manifest_path()).unwrap();
    h.releases.publish("v999.0.0");

    h.ok(&["update"]);

    assert_eq!(
        std::fs::read_to_string(h.config.manifest_path()).unwrap(),
        before
    );
    assert_eq!(h.vault.len(), 1);
}
