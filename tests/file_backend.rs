mod common;

use common::{Harness, PROJECT_ID, recovery_words};
use dot_envy::{
    protect::is_sealed,
    schema::Secret,
    vault::{CredentialStore, Namespace, SecretVault},
};

const TOKEN: &str = "dev-s3cr3t-token";
const PASSWORD: &str = "vault password";

/// A project with values (and one older version) in the keyring.
fn in_keyring() -> Harness {
    let h = Harness::with_manifest();
    h.ok(&["set", "dev", "API_TOKEN", "old-token"]);
    h.ok(&["set", "dev", "API_TOKEN", TOKEN]);
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://u@localhost/db"]);
    h
}

fn with_password(mut h: Harness, password: &str) -> Harness {
    h.config.vault_password = Some(Secret::new(password));
    h
}

/// Migrated to the file backend, with `ENVY_VAULT_PASSWORD` set. Returns the output too.
fn in_file() -> (Harness, String) {
    let h = with_password(in_keyring(), PASSWORD);
    let out = h.ok(&["migrate", "--to", "file", "--remove-source"]);
    (h, out)
}

fn vault_file(h: &Harness) -> String {
    std::fs::read_to_string(h.data_dir().join(format!("vaults/{PROJECT_ID}.json"))).unwrap()
}

// ---------- migrate ----------

#[test]
fn migrating_creates_the_vault_and_moves_values_with_their_history() {
    let (h, out) = in_file();
    assert!(out.contains("Copied 2 value(s) and their history"), "{out}");
    assert_eq!(recovery_words(&out).len(), 24, "{out}");
    let asked = h.prompter.asked.borrow().clone();
    assert_eq!(asked.len(), 3, "only the three words are asked: {asked:?}");
    assert!(asked.iter().all(|label| label.starts_with("Word #")));

    assert!(h.vault.is_empty(), "--remove-source empties the keyring");
    let text = vault_file(&h);
    for leaked in [TOKEN, "old-token", "API_TOKEN", "postgres://"] {
        assert!(!text.contains(leaked), "{leaked} is in the file");
    }

    h.ok(&["run", "dev", "--", "node"]);
    assert_eq!(h.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
    let history = h.ok(&["history", "API_TOKEN", "--in", "dev"]);
    assert_eq!(
        history.lines().count(),
        3,
        "both versions came along: {history}"
    );
    h.ok(&["rollback", "API_TOKEN", "--in", "dev"]);
    h.ok(&["run", "dev", "--", "node"]);
    assert_eq!(h.runner.calls.borrow()[1].envs["API_TOKEN"], "old-token");
}

#[test]
fn without_remove_source_the_keyring_keeps_its_copy() {
    let h = with_password(in_keyring(), PASSWORD);
    let out = h.ok(&["migrate", "--to", "file"]);
    assert!(out.contains("run again with --remove-source"), "{out}");
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(TOKEN)
    );
}

#[test]
fn a_wrong_recovery_word_changes_nothing() {
    let other = with_password(in_keyring(), PASSWORD);
    other.prompter.misremember_words.set(true);
    let err = other.err(&["migrate", "--to", "file"]);
    assert!(err.contains("Nothing was changed"), "{err}");
    assert!(
        !other
            .data_dir()
            .join(format!("vaults/{PROJECT_ID}.json"))
            .exists()
    );
    assert_eq!(
        other.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(TOKEN)
    );
    assert!(
        other.ok(&["ls", "dev"]).contains("API_TOKEN"),
        "still in the keyring"
    );
}

#[test]
fn the_new_password_is_typed_twice_without_the_variable() {
    let h = in_keyring();
    h.prompter.answers(&[PASSWORD, "typo"]);
    let err = h.err(&["migrate", "--to", "file"]);
    assert!(err.contains("The passwords do not match"), "{err}");

    let h = in_keyring();
    h.prompter.answers(&[PASSWORD, PASSWORD]);
    h.ok(&["migrate", "--to", "file"]);
    h.prompter.answers(&[PASSWORD]);
    h.ok(&["check", "dev"]);
}

#[test]
fn migrating_back_to_the_keyring_restores_everything() {
    let (h, _) = in_file();
    let out = h.ok(&["migrate", "--to", "keyring", "--remove-source"]);
    assert!(out.contains("now uses the keyring backend"), "{out}");
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(TOKEN)
    );
    assert_eq!(
        h.vault
            .history(PROJECT_ID, "dev", "API_TOKEN")
            .unwrap()
            .len(),
        2
    );
    let choices = std::fs::read_to_string(h.data_dir().join("backends.json")).unwrap();
    assert!(!choices.contains(PROJECT_ID), "{choices}");
}

#[test]
fn impossible_migrations_are_refused() {
    let (h, _) = in_file();
    let err = h.err(&["migrate", "--to", "file"]);
    assert!(err.contains("already uses the file backend"), "{err}");
    let err = h.err(&["migrate", "--to", "remote"]);
    assert!(err.contains("remote backend is not available"), "{err}");
}

#[test]
fn the_flag_wins_over_the_choice_of_the_project() {
    let (h, _) = in_file();
    let out = h.ok(&["--backend", "keyring", "ls", "dev"]);
    assert!(
        out.contains("<unset>"),
        "the keyring is empty after the move: {out}"
    );
}

#[test]
fn a_missing_vault_file_fails_instead_of_falling_back() {
    let (h, _) = in_file();
    std::fs::remove_file(h.data_dir().join(format!("vaults/{PROJECT_ID}.json"))).unwrap();
    h.vault
        .write(
            Namespace::Values,
            &format!("{PROJECT_ID}/dev/API_TOKEN"),
            &Secret::new("stale"),
        )
        .unwrap();
    let err = h.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("has no file vault on this machine"), "{err}");
    assert!(h.runner.calls.borrow().is_empty());
}

#[test]
fn protected_values_stay_sealed_in_the_file() {
    let h = with_password(in_keyring(), PASSWORD);
    h.prompter.answers(&["env-pw", "env-pw"]);
    h.ok(&["protect", "dev"]);
    h.ok(&["migrate", "--to", "file", "--remove-source"]);

    let stored = h.ok(&["--backend", "file", "ls", "dev"]);
    assert!(stored.contains("********"), "{stored}");
    let file = dot_envy::vault::EncryptedFileVault::new(
        Some(h.data_dir()),
        &h.prompter,
        h.config.vault_password.as_ref(),
    );
    let raw = file.get(PROJECT_ID, "dev", "API_TOKEN").unwrap().unwrap();
    assert!(is_sealed(&raw), "sealed values are moved as they are");

    h.prompter.answers(&["env-pw"]);
    h.ok(&["run", "dev", "--", "node"]);
    assert_eq!(h.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
}

#[test]
fn a_member_on_the_file_backend_still_inherits_from_a_root_in_the_keyring() {
    let mut h = Harness::new();
    h.git_init();
    let mut root = dot_envy::envy::Envy::new("Root".into(), None).unwrap();
    root.id = "root-id".into();
    root.workspace = Some(dot_envy::envy::WorkspaceConfig {
        members: vec!["api".into()],
    });
    root.schemas.insert(
        "dev".into(),
        dot_envy::envy::Schema::from([("SHARED".to_string(), common::var("string", None))]),
    );
    root.checksum = root.compute_checksum().unwrap();
    h.save_manifest(".", &root);
    let mut member = common::sample_envy();
    member.checksum = member.compute_checksum().unwrap();
    h.save_manifest("api", &member);

    h.ok(&["set", "dev", "SHARED", "from-root"]);
    h.cd("api");
    let h = with_password(h, PASSWORD);
    h.ok(&["set", "dev", "API_TOKEN", TOKEN]);
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://u@localhost/db"]);
    h.ok(&["migrate", "--to", "file", "--remove-source"]);

    h.ok(&["run", "dev", "--", "node"]);
    let envs = h.runner.calls.borrow()[0].envs.clone();
    assert_eq!(envs["SHARED"], "from-root");
    assert_eq!(envs["API_TOKEN"], TOKEN);
}

// ---------- vault ----------

#[test]
fn vault_commands_need_the_file_backend() {
    let h = in_keyring();
    let err = h.err(&["vault", "password"]);
    assert!(
        err.contains("This project uses the keyring backend"),
        "{err}"
    );
}

#[test]
fn a_new_password_replaces_the_old_one() {
    let (h, _) = in_file();
    h.prompter.answers(&["new password", "new password"]);
    h.ok(&["vault", "password"]);

    let err = h.err(&["ls", "dev", "--show"]);
    assert!(err.contains("Wrong password for the file vault"), "{err}");
    let h = with_password(h, "new password");
    assert!(h.ok(&["ls", "dev", "--show"]).contains(TOKEN));
}

#[test]
fn rekey_keeps_every_value_readable() {
    let (h, _) = in_file();
    let before = vault_file(&h);
    let out = h.ok(&["vault", "rekey", "dev"]);
    assert!(out.contains("new key (key 2)"), "{out}");
    assert_ne!(before, vault_file(&h));
    assert!(h.ok(&["ls", "dev", "--show"]).contains(TOKEN));
    h.ok(&["rollback", "API_TOKEN", "--in", "dev"]);
}

#[test]
fn the_recovery_key_opens_the_vault_after_the_password_is_lost() {
    let (h, out) = in_file();
    let words = recovery_words(&out).join(" ");
    // The password in the environment is wrong; recovering never asks for it.
    let h = with_password(h, "forgotten");

    h.prompter
        .answers(&[&words, "fresh password", "fresh password"]);
    let out = h.ok(&["vault", "recover"]);
    assert!(out.contains("open again with a new password"), "{out}");

    let h = with_password(h, "fresh password");
    assert!(h.ok(&["ls", "dev", "--show"]).contains(TOKEN));
    let actions: Vec<String> = h
        .audit_events(PROJECT_ID)
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(actions.contains(&"vault-create".to_string()), "{actions:?}");
    assert!(
        actions.contains(&"vault-recover".to_string()),
        "{actions:?}"
    );
}

#[test]
fn a_wrong_recovery_key_is_refused() {
    let (h, _) = in_file();
    let wrong = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    h.prompter.answers(&[wrong]);
    let err = h.err(&["vault", "recover"]);
    assert!(err.contains("does not belong to this project"), "{err}");
}

#[test]
fn a_new_recovery_key_retires_the_old_one() {
    let (h, first) = in_file();
    let out = h.ok(&["vault", "recovery-key"]);
    let old = recovery_words(&first).join(" ");
    let new = recovery_words(&out).join(" ");
    assert_ne!(old, new);

    h.prompter.answers(&[&old]);
    let err = h.err(&["vault", "recover"]);
    assert!(err.contains("does not belong to this project"), "{err}");
    h.prompter.answers(&[&new, "p2", "p2"]);
    h.ok(&["vault", "recover"]);
}
