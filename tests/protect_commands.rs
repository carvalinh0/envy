mod common;

use common::{Harness, PROJECT_ID};
use dot_envy::{
    protect::{CHECK_SLOT, is_sealed},
    schema::Secret,
    vault::SecretVault,
};

const TOKEN: &str = "prod-s3cr3t-token";
const URL: &str = "postgres://u@prod/db";
const PASSWORD: &str = "correct horse";

fn with_prod_values() -> Harness {
    let h = Harness::with_manifest();
    h.ok(&["set", "prod", "API_TOKEN", TOKEN]);
    h.ok(&["set", "prod", "DATABASE_URL", URL]);
    h
}

fn protected() -> Harness {
    let h = with_prod_values();
    h.prompter.answers(&[PASSWORD, PASSWORD]);
    h.ok(&["protect", "prod"]);
    h
}

fn raw(h: &Harness, env: &str, key: &str) -> Option<Secret> {
    h.vault.get(PROJECT_ID, env, key).unwrap()
}

fn with_password(mut h: Harness, password: &str) -> Harness {
    h.config.protect_password = Some(Secret::new(password));
    h
}

#[test]
fn protect_encrypts_the_stored_values_and_clears_their_history() {
    let h = with_prod_values();
    h.ok(&["set", "prod", "API_TOKEN", TOKEN]);
    let version = h.manifest().version;

    h.prompter.answers(&[PASSWORD, PASSWORD]);
    let out = h.ok(&["protect", "prod"]);
    assert!(out.contains("2 value(s) encrypted"), "{out}");

    let envy = h.manifest();
    assert!(envy.is_protected("prod"));
    assert_eq!(envy.version, version + 1);
    for key in ["API_TOKEN", "DATABASE_URL"] {
        let stored = raw(&h, "prod", key).unwrap();
        assert!(is_sealed(&stored), "{key} must be sealed");
        assert!(!stored.expose_secret().contains("s3cr3t"));
        assert_eq!(h.vault.history(PROJECT_ID, "prod", key).unwrap().len(), 1);
    }
    assert!(raw(&h, "dev", "PORT").is_none_or(|v| !is_sealed(&v)));
}

#[test]
fn run_decrypts_with_the_password() {
    let h = with_password(protected(), PASSWORD);
    h.ok(&["run", "prod", "--", "node"]);
    let call = &h.runner.calls.borrow()[0];
    assert_eq!(call.envs["API_TOKEN"], TOKEN);
    assert_eq!(call.envs["DATABASE_URL"], URL);
}

#[test]
fn a_wrong_password_runs_nothing_and_leaks_nothing() {
    let h = with_password(protected(), "wrong");
    let err = h.err(&["run", "prod", "--", "node"]);
    assert!(err.contains("wrong password"), "{err}");
    assert!(!err.contains(TOKEN) && !err.contains(URL), "{err}");
    assert!(h.runner.calls.borrow().is_empty());
}

#[test]
fn the_password_is_asked_once_per_command() {
    let h = protected();
    h.prompter.asked.borrow_mut().clear();
    h.prompter.answers(&[PASSWORD]);
    h.ok(&["ls", "prod", "--show"]);
    assert_eq!(h.prompter.asked.borrow().len(), 1);
}

#[test]
fn masked_listing_asks_no_password() {
    let h = protected();
    h.prompter.asked.borrow_mut().clear();
    let out = h.ok(&["ls", "prod"]);
    assert!(
        out.contains("API_TOKEN") && out.contains("********"),
        "{out}"
    );
    assert!(h.prompter.asked.borrow().is_empty());
}

#[test]
fn new_values_of_a_protected_environment_are_sealed() {
    let h = with_password(protected(), PASSWORD);
    h.ok(&["set", "prod", "API_TOKEN", "rotated-s3cr3t"]);
    let stored = raw(&h, "prod", "API_TOKEN").unwrap();
    assert!(is_sealed(&stored));

    let err = with_password(protected(), "wrong").err(&["set", "prod", "API_TOKEN", "x"]);
    assert!(err.contains("Wrong password"), "{err}");
}

#[test]
fn rollback_works_inside_a_protected_environment() {
    let h = with_password(protected(), PASSWORD);
    h.ok(&["set", "prod", "API_TOKEN", "rotated-s3cr3t"]);
    h.ok(&["rollback", "API_TOKEN", "--in", "prod"]);
    h.ok(&["run", "prod", "--", "node"]);
    assert_eq!(h.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
}

#[test]
fn values_stay_sealed_when_an_older_release_drops_the_flag() {
    let h = protected();
    let mut envy = h.manifest();
    envy.protected.clear();
    envy.sync().unwrap();
    envy.save(&h.config.manifest_path()).unwrap();

    let err = h.err(&["run", "prod", "--", "node"]);
    assert!(err.contains("the test did not provide an answer"), "{err}");
    assert!(h.runner.calls.borrow().is_empty());
}

#[test]
fn check_warns_about_values_stored_before_the_environment_was_protected() {
    // A teammate pulls a manifest that protects prod, with plain values on their machine.
    let h = with_prod_values();
    let mut envy = h.manifest();
    envy.protected.insert("prod".into());
    envy.sync().unwrap();
    envy.save(&h.config.manifest_path()).unwrap();

    let out = h.ok(&["check", "prod"]);
    assert!(
        out.contains("'prod' is protected, but 2 value(s) are stored unencrypted"),
        "{out}"
    );

    let version = h.manifest().version;
    h.prompter.answers(&[PASSWORD, PASSWORD]);
    h.ok(&["protect", "prod"]);
    assert_eq!(
        h.manifest().version,
        version,
        "already listed: no new version"
    );
    let h = with_password(h, PASSWORD);
    assert!(!h.ok(&["check", "prod"]).contains("warning"));
}

#[test]
fn unprotect_decrypts_and_removes_the_password() {
    let h = with_password(protected(), PASSWORD);
    h.ok(&["unprotect", "prod"]);
    assert!(!h.manifest().is_protected("prod"));
    assert_eq!(
        h.stored(PROJECT_ID, "prod", "API_TOKEN").as_deref(),
        Some(TOKEN)
    );
    assert!(raw(&h, "prod", CHECK_SLOT).is_none());
}

#[test]
fn a_new_id_keeps_protected_values_readable() {
    let h = with_password(protected(), PASSWORD);
    h.ok(&["up", "--new-id"]);
    let new_id = h.manifest().id;
    assert_ne!(new_id, PROJECT_ID);
    h.ok(&["run", "prod", "--", "node"]);
    assert_eq!(h.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
    h.ok(&["set", "prod", "API_TOKEN", "after-new-id"]);
}

#[test]
fn protecting_an_unknown_environment_fails() {
    let h = Harness::with_manifest();
    let err = h.err(&["protect", "nope"]);
    assert!(
        err.contains("There's no environment called 'nope'"),
        "{err}"
    );
}
