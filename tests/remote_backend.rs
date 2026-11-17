mod common;

use common::{Harness, PROJECT_ID, SERVER, recovery_words};
use dot_envy::{
    remote::protocol::{MemberKeys, MemberStatus},
    schema::Secret,
};

const TOKEN: &str = "dev-s3cr3t-token";
const PROD_TOKEN: &str = "prod-s3cr3t-token";

fn line_after(output: &str, marker: &str) -> String {
    let start = output.find(marker).expect(marker) + marker.len();
    output[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// The first admin, with the sample project's values moved to the server.
fn admin() -> (Harness, String) {
    let h = Harness::with_manifest();
    h.ok(&["set", "dev", "API_TOKEN", TOKEN]);
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://u@localhost/db"]);
    h.ok(&["set", "prod", "API_TOKEN", PROD_TOKEN]);
    h.ok(&["set", "prod", "DATABASE_URL", "postgres://u@prod/db"]);
    let root = h.root_token.clone();
    let out = h.ok(&["login", SERVER, "--root-token", &root, "--name", "admin"]);
    assert!(out.contains("Joined as 'admin'"), "{out}");
    let out = h.ok(&["migrate", "--to", "remote", "--remove-source"]);
    (h, out)
}

/// A teammate on another machine with the same manifest, invited and joined.
fn invited(admin: &Harness, name: &str) -> (Harness, String) {
    let other = Harness::sharing(admin);
    common::sample_envy()
        .save(&other.config.manifest_path())
        .unwrap();
    let out = admin.ok(&["user", "add", name]);
    let invite = out.lines().nth(1).unwrap().trim().to_string();
    let out = other.ok(&["login", SERVER, "--invite", &invite, "--name", name]);
    let fingerprint = line_after(&out, "Fingerprint: ");
    (other, fingerprint)
}

fn fingerprint_of(h: &Harness, name: &str) -> String {
    let member = h.server.store().member(name).unwrap().unwrap();
    member.keys.unwrap().decode().unwrap().fingerprint()
}

/// A teammate moves its copy of the project to the server, after checking who created it.
fn join_project(h: &Harness, creator: &str) -> String {
    let fingerprint = fingerprint_of(h, creator);
    h.ok(&["migrate", "--to", "remote", "--creator", &fingerprint])
}

fn project_state(h: &Harness) -> String {
    let state = h.server.store().project(PROJECT_ID).unwrap().unwrap();
    serde_json::to_string(&state).unwrap()
}

// ---------- the first admin ----------

#[test]
fn values_move_to_the_server_and_it_only_sees_ciphertext() {
    let (h, out) = admin();
    assert!(
        out.contains("Creating 'Sample' on https://envy.test"),
        "{out}"
    );
    assert_eq!(recovery_words(&out).len(), 24);
    assert!(h.vault.is_empty(), "--remove-source emptied the keyring");

    let stored = project_state(&h);
    for leaked in [
        TOKEN,
        PROD_TOKEN,
        "API_TOKEN",
        "DATABASE_URL",
        "postgres://",
    ] {
        assert!(!stored.contains(leaked), "the server can read {leaked}");
    }

    h.ok(&["run", "dev", "--", "node"]);
    assert_eq!(h.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
    h.ok(&["set", "dev", "API_TOKEN", "rotated"]);
    assert_eq!(
        h.ok(&["history", "API_TOKEN", "--in", "dev"])
            .lines()
            .count(),
        3
    );
    h.ok(&["rollback", "API_TOKEN", "--in", "dev"]);
    assert!(h.ok(&["ls", "dev", "--show"]).contains(TOKEN));
}

#[test]
fn the_root_token_works_once() {
    let (h, _) = admin();
    let other = Harness::sharing(&h);
    common::sample_envy()
        .save(&other.config.manifest_path())
        .unwrap();
    let root = h.root_token.clone();
    let err = other.err(&["login", SERVER, "--root-token", &root, "--name", "second"]);
    assert!(err.contains("The root token is not valid"), "{err}");
}

#[test]
fn a_root_token_only_goes_to_a_url_given_on_the_command_line() {
    let h = Harness::with_manifest();
    let mut envy = common::sample_envy();
    envy.server = Some(SERVER.into());
    envy.save(&h.config.manifest_path()).unwrap();
    let root = h.root_token.clone();
    let err = h.err(&["login", "--root-token", &root, "--name", "admin"]);
    assert!(err.contains("envy login <url> --root-token"), "{err}");
    assert!(!err.contains(&root), "{err}");
    h.ok(&["login", SERVER, "--root-token", &root, "--name", "admin"]);
}

#[test]
fn login_needs_an_identity_and_https() {
    let h = Harness::with_manifest();
    let err = h.err(&["login", SERVER]);
    assert!(err.contains("This machine has no identity"), "{err}");
    let err = h.err(&["login", "http://envy.example"]);
    assert!(err.contains("must use https://"), "{err}");
    let err = h.err(&["migrate", "--to", "remote"]);
    assert!(err.contains("Run `envy login <url>`"), "{err}");
}

// ---------- members ----------

#[test]
fn joining_a_project_someone_else_created_needs_its_fingerprint() {
    let (admin, _) = admin();
    let (ana, fingerprint) = invited(&admin, "ana");
    admin.ok(&[
        "user",
        "approve",
        "ana",
        "--fingerprint",
        &fingerprint,
        "--env",
        "dev",
    ]);
    ana.ok(&["set", "dev", "API_TOKEN", "ana-local-s3cr3t"]);

    let creator = fingerprint_of(&admin, "admin");
    let err = ana.err(&["migrate", "--to", "remote"]);
    assert!(err.contains("created by 'admin'"), "{err}");
    assert!(err.contains(&creator), "{err}");
    let err = ana.err(&["migrate", "--to", "remote", "--creator", "0000 1111"]);
    assert!(err.contains("not the fingerprint"), "{err}");
    assert!(!err.contains("ana-local-s3cr3t"), "{err}");
    assert!(
        !project_state(&admin).contains("ana-local"),
        "nothing was sent"
    );

    ana.ok(&["migrate", "--to", "remote", "--creator", &creator]);
    ana.ok(&["run", "dev", "--", "node"]);
    assert_eq!(ana.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
}

#[test]
fn creator_is_only_for_a_project_that_exists() {
    let h = Harness::with_manifest();
    let root = h.root_token.clone();
    h.ok(&["login", SERVER, "--root-token", &root, "--name", "admin"]);
    let err = h.err(&["migrate", "--to", "remote", "--creator", "0000"]);
    assert!(err.contains("has no project"), "{err}");
}

#[test]
fn an_approved_member_reads_only_the_environments_it_was_given() {
    let (admin, _) = admin();
    let (ana, fingerprint) = invited(&admin, "ana");

    let err = ana.err(&["migrate", "--to", "remote"]);
    assert!(err.contains("waiting for an admin to approve"), "{err}");

    admin.ok(&[
        "user",
        "approve",
        "ana",
        "--fingerprint",
        &fingerprint,
        "--env",
        "dev",
    ]);
    let out = join_project(&ana, "admin");
    assert!(out.contains("already has this project"), "{out}");

    ana.ok(&["run", "dev", "--", "node"]);
    assert_eq!(ana.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);

    let err = ana.err(&["run", "prod", "--", "node"]);
    assert!(err.contains("no access to 'prod'"), "{err}");
    let err = ana.err(&["set", "dev", "API_TOKEN", "x"]);
    assert!(err.contains("'ana' can't write 'dev'"), "{err}");
}

#[test]
fn approval_needs_the_right_fingerprint() {
    let (admin, _) = admin();
    let (_ana, _) = invited(&admin, "ana");
    let wrong = "0000-0000-0000-0000-0000-0000-0000-0000";
    let err = admin.err(&[
        "user",
        "approve",
        "ana",
        "--fingerprint",
        wrong,
        "--env",
        "dev",
    ]);
    assert!(err.contains("fingerprint does not match"), "{err}");
    let out = admin.ok(&["user", "list"]);
    assert!(
        out.lines()
            .any(|l| l.starts_with("ana") && l.contains("pending")),
        "{out}"
    );
}

#[test]
fn a_writer_shares_new_environments_with_the_readers() {
    let (admin, _) = admin();
    let (ana, fingerprint) = invited(&admin, "ana");
    admin.ok(&[
        "user",
        "approve",
        "ana",
        "--fingerprint",
        &fingerprint,
        "--env",
        "*",
        "--write",
    ]);
    join_project(&ana, "admin");

    // `global` has no key yet: ana creates it, and the admin can read it.
    ana.ok(&["set", "global", "APP_NAME", "shared"]);
    assert!(admin.ok(&["ls", "global", "--show"]).contains("shared"));
}

#[test]
fn removing_a_member_rekeys_what_it_could_read() {
    let (admin, _) = admin();
    let (ana, fingerprint) = invited(&admin, "ana");
    admin.ok(&[
        "user",
        "approve",
        "ana",
        "--fingerprint",
        &fingerprint,
        "--env",
        "dev",
    ]);
    join_project(&ana, "admin");
    let before = project_state(&admin);

    let out = admin.ok(&["user", "rm", "ana"]);
    assert!(out.contains("new key for 'dev'"), "{out}");
    assert!(out.contains("change their values too"), "{out}");
    assert_ne!(before, project_state(&admin));

    let err = ana.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("removed") || err.contains("expired"), "{err}");
    assert!(admin.ok(&["ls", "dev", "--show"]).contains(TOKEN));
}

// ---------- CI ----------

#[test]
fn ci_runs_with_an_identity_in_a_variable() {
    let (admin, _) = admin();
    let ci = Harness::sharing(&admin);
    common::sample_envy()
        .save(&ci.config.manifest_path())
        .unwrap();
    let invite = admin
        .ok(&["user", "add", "ci-prod"])
        .lines()
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let out = ci.ok(&[
        "login",
        SERVER,
        "--invite",
        &invite,
        "--name",
        "ci-prod",
        "--print-identity",
    ]);
    let identity = out.lines().nth(1).unwrap().trim().to_string();
    assert!(identity.starts_with("envy-identity-v1:ci-prod:"), "{out}");
    assert!(ci.vault.is_empty(), "nothing was stored on the machine");
    let fingerprint = line_after(&out, "Fingerprint: ");
    admin.ok(&[
        "user",
        "approve",
        "ci-prod",
        "--fingerprint",
        &fingerprint,
        "--env",
        "prod",
    ]);

    // A fresh runner: no login, only variables.
    let mut runner = Harness::sharing(&admin);
    common::sample_envy()
        .save(&runner.config.manifest_path())
        .unwrap();
    runner.config.identity = Some(Secret::new(identity));
    runner.config.server_url = Some(SERVER.into());
    runner.ok(&["--backend", "remote", "run", "prod", "--", "deploy"]);
    assert_eq!(
        runner.runner.calls.borrow()[0].envs["API_TOKEN"],
        PROD_TOKEN
    );
}

// ---------- keys ----------

#[test]
fn rekey_and_recovery_work_on_the_server() {
    let (h, out) = admin();
    let words = recovery_words(&out).join(" ");
    let out = h.ok(&["vault", "rekey", "dev"]);
    assert!(out.contains("new key (key 2)"), "{out}");
    assert!(h.ok(&["ls", "dev", "--show"]).contains(TOKEN));

    h.prompter.answers(&[&words]);
    h.ok(&["vault", "recover"]);
    let out = h.ok(&["vault", "recovery-key"]);
    h.prompter.answers(&[&words]);
    let err = h.err(&["vault", "recover"]);
    assert!(err.contains("does not belong to this project"), "{err}");
    let new = recovery_words(&out).join(" ");
    h.prompter.answers(&[&new]);
    h.ok(&["vault", "recover"]);

    let err = h.err(&["vault", "password"]);
    assert!(err.contains("has no password"), "{err}");
}

#[test]
fn the_server_log_shows_who_did_what() {
    let (h, _) = admin();
    h.ok(&["run", "dev", "--", "node"]);
    let out = h.ok(&["audit", "--server"]);
    assert!(out.contains("admin  project-create"), "{out}");
    assert!(out.contains("admin  commit  dev"), "{out}");
    assert!(out.contains("admin  read"), "{out}");
}

#[test]
fn logout_goes_back_to_the_keyring() {
    let (h, _) = admin();
    h.ok(&["logout"]);
    assert!(
        h.ok(&["ls", "dev"]).contains("<unset>"),
        "the keyring was emptied by the move"
    );
}

// ---------- a server that lies ----------

#[test]
fn an_older_state_served_again_is_refused() {
    let (h, _) = admin();
    let old = h.server.store().project(PROJECT_ID).unwrap().unwrap();
    h.ok(&["set", "dev", "API_TOKEN", "newer"]);
    let current = h.server.store().project(PROJECT_ID).unwrap().unwrap();
    assert!(
        h.server
            .store()
            .put_project(PROJECT_ID, Some(current.head.seq), &old)
            .unwrap()
    );

    let err = h.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("older state"), "{err}");
    assert!(h.runner.calls.borrow().is_empty());
}

#[test]
fn a_changed_member_key_is_refused() {
    let (h, _) = admin();
    let store = h.server.store();
    let mut member = store.member("admin").unwrap().unwrap();
    let forged = dot_envy::identity::Identity::generate("admin");
    member.keys = Some(MemberKeys::of(&forged.public()));
    assert_eq!(member.status, MemberStatus::Active);
    store.put_member(&member).unwrap();

    let err = h.err(&["ls", "dev", "--show"]);
    assert!(
        err.contains("changed on the server") || err.contains("signature"),
        "{err}"
    );
}

#[test]
fn a_tampered_value_is_refused() {
    let (h, _) = admin();
    let store = h.server.store();
    let mut state = store.project(PROJECT_ID).unwrap().unwrap();
    let seq = state.head.seq;
    let record = state.records.iter_mut().find(|r| r.env == "dev").unwrap();
    record.ciphertext = state_swap(&record.ciphertext);
    store.put_project(PROJECT_ID, Some(seq), &state).unwrap();

    let err = h.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("that no member signed"), "{err}");
}

fn state_swap(ciphertext: &str) -> String {
    let mut chars: Vec<char> = ciphertext.chars().collect();
    chars.swap(0, 1);
    if chars[0] == chars[1] {
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

#[test]
fn protected_values_stay_sealed_on_the_server() {
    let h = Harness::with_manifest();
    h.ok(&["set", "prod", "API_TOKEN", PROD_TOKEN]);
    h.ok(&["set", "prod", "DATABASE_URL", "postgres://u@prod/db"]);
    h.prompter.answers(&["env-pw", "env-pw"]);
    h.ok(&["protect", "prod"]);
    let root = h.root_token.clone();
    h.ok(&["login", SERVER, "--root-token", &root, "--name", "admin"]);
    h.ok(&["migrate", "--to", "remote", "--remove-source"]);

    h.prompter.answers(&["env-pw"]);
    h.ok(&["run", "prod", "--", "deploy"]);
    assert_eq!(h.runner.calls.borrow()[0].envs["API_TOKEN"], PROD_TOKEN);
}

/// The server adds "eve", with keys it controls, and a grant for her.
fn inject_eve(
    h: &Harness,
    eve: &dot_envy::identity::Identity,
    approver: &str,
    signed_by: &dot_envy::identity::Identity,
) {
    use dot_envy::{
        remote::protocol::{Access, grant_message},
        server::StoredMember,
    };
    let store = h.server.store();
    store
        .put_member(&StoredMember {
            name: "eve".into(),
            status: MemberStatus::Active,
            admin: true,
            keys: Some(MemberKeys::of(&eve.public())),
            invite_hash: None,
            invite_expires: 0,
        })
        .unwrap();
    let mut access = Access {
        member: "eve".into(),
        env: "*".into(),
        write: true,
        keys: MemberKeys::of(&eve.public()),
        approver: approver.into(),
        signature: String::new(),
    };
    let signature = signed_by.sign(&grant_message(PROJECT_ID, &access));
    access.signature = base64_of(&signature);
    store.set_access(PROJECT_ID, &access).unwrap();
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn wrapped_for(h: &Harness, member: &str) -> bool {
    let state = h.server.store().project(PROJECT_ID).unwrap().unwrap();
    state.wraps.iter().any(|w| w.member == member)
}

#[test]
fn keys_never_go_to_a_member_the_server_added() {
    let (h, _) = admin();
    // A grant eve signed herself: she is not in the chain that starts at the creator.
    let eve = dot_envy::identity::Identity::generate("eve");
    inject_eve(&h, &eve, "eve", &eve);
    h.ok(&["set", "global", "APP_NAME", "new-environment"]);
    assert!(!wrapped_for(&h, "eve"), "a self-signed grant was trusted");
}

#[test]
fn a_grant_with_a_forged_admin_signature_is_ignored() {
    let (h, _) = admin();
    let eve = dot_envy::identity::Identity::generate("eve");
    let forger = dot_envy::identity::Identity::generate("admin");
    inject_eve(&h, &eve, "admin", &forger);
    h.ok(&["vault", "rekey", "dev"]);
    assert!(!wrapped_for(&h, "eve"), "a forged grant was trusted");
    assert!(h.ok(&["ls", "dev", "--show"]).contains(TOKEN));
}

fn set_recovery(h: &Harness, recovery: dot_envy::remote::protocol::SignedRecovery) {
    let store = h.server.store();
    let mut state = store.project(PROJECT_ID).unwrap().unwrap();
    let seq = state.head.seq;
    state.recovery = recovery;
    assert!(store.put_project(PROJECT_ID, Some(seq), &state).unwrap());
}

#[test]
fn a_recovery_key_the_server_swapped_in_is_refused() {
    use dot_envy::remote::protocol::{SignedRecovery, recovery_message};
    let (h, _) = admin();
    let forger = dot_envy::identity::Identity::generate("admin");
    let mut forged = SignedRecovery {
        public: base64_of(&[9; 32]),
        signer: "admin".into(),
        signature: String::new(),
    };
    forged.signature = base64_of(&forger.sign(&recovery_message(PROJECT_ID, &forged)));
    set_recovery(&h, forged);

    let err = h.err(&["set", "global", "APP_NAME", "new-environment"]);
    assert!(err.contains("not set by a member trusted"), "{err}");
    assert!(!wrapped_for_env(&h, "global"));
}

#[test]
fn an_earlier_recovery_key_never_comes_back() {
    let (h, _) = admin();
    let old = h
        .server
        .store()
        .project(PROJECT_ID)
        .unwrap()
        .unwrap()
        .recovery;
    h.ok(&["vault", "recovery-key"]);
    h.ok(&["ls", "dev"]);
    set_recovery(&h, old);

    let err = h.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("earlier recovery key"), "{err}");
}

fn wrapped_for_env(h: &Harness, env: &str) -> bool {
    let state = h.server.store().project(PROJECT_ID).unwrap().unwrap();
    state.wraps.iter().any(|w| w.env == env)
}

#[test]
fn a_project_outlives_its_creator() {
    let (admin, _) = admin();
    // Bob: a second admin, given every environment by the creator.
    let bob = Harness::sharing(&admin);
    common::sample_envy()
        .save(&bob.config.manifest_path())
        .unwrap();
    let invite = admin
        .ok(&["user", "add", "bob", "--admin"])
        .lines()
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let out = bob.ok(&["login", SERVER, "--invite", &invite, "--name", "bob"]);
    let fingerprint = line_after(&out, "Fingerprint: ");
    admin.ok(&[
        "user",
        "approve",
        "bob",
        "--fingerprint",
        &fingerprint,
        "--env",
        "*",
        "--write",
    ]);
    join_project(&bob, "admin");

    // The creator leaves; bob replaces the keys it could read.
    let out = bob.ok(&["user", "rm", "admin"]);
    assert!(out.contains("new key for 'dev'"), "{out}");

    // Carol joins afterwards, on a machine that never saw the creator.
    let (carol, fingerprint) = invited(&bob, "carol");
    bob.ok(&[
        "user",
        "approve",
        "carol",
        "--fingerprint",
        &fingerprint,
        "--env",
        "dev",
    ]);
    join_project(&carol, "admin");
    carol.ok(&["run", "dev", "--", "node"]);
    assert_eq!(carol.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
}

#[test]
fn a_new_admin_and_the_recovery_key_rescue_a_project() {
    let (admin, out) = admin();
    let words = recovery_words(&out).join(" ");

    // Every admin lost their identity: the host issues a new root token.
    let rescue = Harness::sharing(&admin);
    common::sample_envy()
        .save(&rescue.config.manifest_path())
        .unwrap();
    let root = admin.server.new_root_token().unwrap();
    rescue.ok(&["login", SERVER, "--root-token", &root, "--name", "rescue"]);
    let err = rescue.err(&["--backend", "remote", "ls", "dev", "--show"]);
    assert!(
        err.contains("no keys of this project"),
        "an admin reads nothing: {err}"
    );

    let (dave, fingerprint) = invited(&rescue, "dave");
    rescue.ok(&[
        "user",
        "approve",
        "dave",
        "--fingerprint",
        &fingerprint,
        "--env",
        "*",
        "--write",
    ]);
    join_project(&dave, "admin");
    dave.prompter.answers(&[&words]);
    dave.ok(&["vault", "recover"]);
    dave.ok(&["run", "dev", "--", "node"]);
    assert_eq!(dave.runner.calls.borrow()[0].envs["API_TOKEN"], TOKEN);
}

/// The server adds eve and has her sign something; `change` edits the project with her key.
fn eve_signs(
    change: impl FnOnce(&mut dot_envy::server::ProjectState, &dot_envy::identity::Identity),
) -> Harness {
    let (h, _) = admin();
    let eve = dot_envy::identity::Identity::generate("eve");
    inject_eve(&h, &eve, "eve", &eve);
    let store = h.server.store();
    let mut state = store.project(PROJECT_ID).unwrap().unwrap();
    let seq = state.head.seq;
    change(&mut state, &eve);
    assert!(store.put_project(PROJECT_ID, Some(seq), &state).unwrap());
    h
}

#[test]
fn a_value_signed_by_a_member_the_server_added_is_refused() {
    use dot_envy::remote::protocol::record_message;
    let h = eve_signs(|state, eve| {
        let mut record = state
            .records
            .iter()
            .find(|r| r.env == "dev")
            .unwrap()
            .clone();
        record.version = 99;
        record.author = "eve".into();
        record.signature = base64_of(&eve.sign(&record_message(PROJECT_ID, &record)));
        state.records.push(record);
    });
    let err = h.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("not written by a member allowed to"), "{err}");
}

#[test]
fn a_state_signed_by_a_member_the_server_added_is_refused() {
    use dot_envy::remote::protocol::head_message;
    let h = eve_signs(|state, eve| {
        state.head.seq += 1;
        state.head.signer = "eve".into();
        state.head.signature = base64_of(&eve.sign(&head_message(PROJECT_ID, &state.head)));
    });
    let err = h.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("not written by a trusted member"), "{err}");
}

#[test]
fn a_key_given_by_a_member_the_server_added_is_refused() {
    use dot_envy::remote::protocol::wrap_message;
    let h = eve_signs(|state, eve| {
        let mut wrap = state
            .wraps
            .iter()
            .find(|w| w.member == "admin" && w.env == "dev")
            .unwrap()
            .clone();
        wrap.signer = "eve".into();
        wrap.signature = base64_of(&eve.sign(&wrap_message(PROJECT_ID, &wrap)));
        state
            .wraps
            .retain(|w| !(w.member == "admin" && w.env == "dev"));
        state.wraps.push(wrap);
    });
    let err = h.err(&["run", "dev", "--", "node"]);
    assert!(err.contains("not given by a member allowed to"), "{err}");
}
