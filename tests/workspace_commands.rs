//! Monorepos: finding the project from a subdirectory, workspace inheritance, duplicated
//! ids and `envy check --recursive`.

mod common;

use std::fs;

use common::{Harness, PROJECT_ID, sample_envy, var};
use dot_envy::{
    envy::{Envy, GLOBAL_ENV, Schema, WorkspaceConfig},
    schema::Secret,
    vault::SecretVault,
};

const ROOT_ID: &str = "root-id";
const API_ID: &str = "api-id";

fn root() -> Envy {
    let mut envy = Envy::new("Monorepo".into(), None).unwrap();
    envy.id = ROOT_ID.into();
    envy.workspace = Some(WorkspaceConfig {
        members: vec!["services/*".into()],
    });
    envy.schemas.insert(
        "dev".into(),
        Schema::from([("DATABASE_URL".to_string(), var("url", None))]),
    );
    envy.schemas.insert(
        "prod".into(),
        Schema::from([("DATABASE_URL".to_string(), var("url", None))]),
    );
    envy.schemas.insert(
        GLOBAL_ENV.into(),
        Schema::from([("REGION".to_string(), var("string", Some("sa-east-1")))]),
    );
    envy.checksum = envy.compute_checksum().unwrap();
    envy
}

fn service(id: &str, name: &str) -> Envy {
    let mut envy = Envy::new(name.into(), None).unwrap();
    envy.id = id.into();
    envy.schemas.insert(
        "dev".into(),
        Schema::from([
            ("PORT".to_string(), var("port", Some("3000"))),
            ("API_TOKEN".to_string(), var("secret", None)),
        ]),
    );
    envy.checksum = envy.compute_checksum().unwrap();
    envy
}

/// Root workspace with `services/api` as a member and `tools/cli` as a standalone project.
fn monorepo() -> Harness {
    let h = Harness::new();
    h.git_init();
    h.save_manifest(".", &root());
    h.save_manifest("services/api", &service(API_ID, "Api"));
    h.save_manifest("tools/cli", &service("cli-id", "Cli"));
    h
}

// ---------- discovery ----------

#[test]
fn commands_find_the_project_from_a_subdirectory() {
    let mut h = monorepo();
    h.cd("services/api/src/handlers");

    h.ok(&["set", "dev", "API_TOKEN", "tok"]);
    assert_eq!(h.stored(API_ID, "dev", "API_TOKEN").as_deref(), Some("tok"));

    h.ok(&["switch", "dev"]);
    assert!(h.exists("services/api/.envy-state"));
    assert!(!h.exists("services/api/src/handlers/.envy-state"));
}

#[test]
fn init_creates_the_project_where_it_was_started() {
    let mut h = monorepo();
    h.cd("services/billing");
    let out = h.ok(&["init", "Billing", "--new"]);
    assert!(h.exists("services/billing/envy.json"));
    assert!(out.contains("member of the workspace 'Monorepo'"), "{out}");

    // Started below an existing project, init still creates a new one there.
    h.cd("services/api/packages/sdk");
    h.ok(&["init", "Sdk", "--new"]);
    assert!(h.exists("services/api/packages/sdk/envy.json"));
}

// ---------- inheritance ----------

#[test]
fn a_member_runs_with_the_values_of_the_workspace() {
    let mut h = monorepo();
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://root/db"]);
    assert_eq!(
        h.stored(ROOT_ID, "dev", "DATABASE_URL").as_deref(),
        Some("postgres://root/db")
    );

    h.cd("services/api");
    h.ok(&["set", "dev", "API_TOKEN", "tok"]);
    h.ok(&["run", "dev", "--", "node", "server.js"]);

    let calls = h.runner.calls.borrow();
    let envs = &calls[0].envs;
    assert_eq!(envs["DATABASE_URL"], "postgres://root/db");
    assert_eq!(envs["REGION"], "sa-east-1");
    assert_eq!(envs["PORT"], "3000");
    assert_eq!(envs["API_TOKEN"], "tok");
}

#[test]
fn a_member_can_override_a_workspace_value_for_itself() {
    let mut h = monorepo();
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://root/db"]);
    h.cd("services/api");
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://api/db"]);

    assert_eq!(
        h.stored(API_ID, "dev", "DATABASE_URL").as_deref(),
        Some("postgres://api/db")
    );
    assert_eq!(
        h.stored(ROOT_ID, "dev", "DATABASE_URL").as_deref(),
        Some("postgres://root/db"),
        "the workspace value is untouched"
    );
    let out = h.ok(&["ls", "dev", "--show"]);
    assert!(out.contains("postgres://api/db"), "{out}");
}

#[test]
fn a_member_gets_the_environments_of_the_workspace() {
    let mut h = monorepo();
    h.ok(&["set", "prod", "DATABASE_URL", "postgres://prod/db"]);
    h.cd("services/api");

    h.ok(&["switch", "prod"]);
    let out = h.ok(&["check", "prod"]);
    assert!(out.contains("All good"), "{out}");

    let err = h.err(&["check"]);
    assert!(
        err.contains("Missing value for 'API_TOKEN' in 'dev'"),
        "{err}"
    );
    assert!(
        err.contains("Missing value for 'DATABASE_URL' in 'dev'"),
        "{err}"
    );
}

#[test]
fn a_standalone_project_inherits_nothing() {
    let mut h = monorepo();
    h.cd("tools/cli");
    assert!(
        h.err(&["check", "prod"])
            .contains("no environment called 'prod'")
    );
    let out = h.ok(&["ls", "dev"]);
    assert!(!out.contains("DATABASE_URL"), "{out}");
}

#[test]
fn inherited_variables_can_only_be_removed_or_renamed_in_the_root() {
    let mut h = monorepo();
    h.cd("services/api");
    let err = h.err(&["rm", "DATABASE_URL", "--from", "dev"]);
    assert!(err.contains("declared by the workspace root"), "{err}");
    let err = h.err(&["rename", "DATABASE_URL", "DB", "--in", "dev"]);
    assert!(err.contains("declared by the workspace root"), "{err}");
    assert!(h.manifest_at(".").schemas["dev"].contains_key("DATABASE_URL"));
}

#[test]
fn schema_shows_what_is_inherited() {
    let mut h = monorepo();
    let out = h.ok(&["schema"]);
    assert!(out.contains("Workspace members: services/*"), "{out}");

    h.cd("services/api");
    let out = h.ok(&["schema"]);
    assert!(
        out.contains("Inherited from the workspace 'Monorepo'"),
        "{out}"
    );
    assert!(out.contains("DATABASE_URL: url"), "{out}");
}

#[test]
fn a_member_can_add_an_environment_the_workspace_already_has() {
    let mut h = monorepo();
    h.cd("services/api");
    h.ok(&["schema", "prod"]);
    assert!(h.manifest_at("services/api").schemas.contains_key("prod"));
}

#[test]
fn export_of_a_member_only_carries_its_own_values() {
    let mut h = monorepo();
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://root/db"]);
    h.cd("services/api");
    h.ok(&["set", "dev", "API_TOKEN", "tok"]);
    let out = h.ok(&["export"]);
    assert!(out.contains("Exported 1 value(s)"), "{out}");
}

// ---------- duplicated ids ----------

#[test]
fn up_and_check_warn_about_a_copied_manifest() {
    let mut h = monorepo();
    h.ok(&["set", "prod", "DATABASE_URL", "postgres://prod/db"]);
    fs::create_dir_all(h.path("services/worker")).unwrap();
    fs::copy(
        h.path("services/api/envy.json"),
        h.path("services/worker/envy.json"),
    )
    .unwrap();
    h.vault
        .set(API_ID, "dev", "API_TOKEN", &Secret::new("tok"))
        .unwrap();

    h.cd("services/api");
    let out = h.ok(&["up"]);
    assert!(out.contains("warning: 1 other manifest(s)"), "{out}");
    assert!(out.contains("services/worker/envy.json"), "{out}");
    let out = h.ok(&["check", "prod"]);
    assert!(out.contains("warning:"), "{out}");

    h.cd("services/worker");
    let out = h.ok(&["up", "--new-id"]);
    assert!(out.contains("Copied 1 value(s)"), "{out}");

    let worker = h.manifest_at("services/worker");
    assert_ne!(worker.id, API_ID);
    assert_eq!(worker.version, 2);
    assert!(worker.is_checksum_valid().unwrap());
    assert_eq!(
        h.stored(&worker.id, "dev", "API_TOKEN").as_deref(),
        Some("tok")
    );
    assert_eq!(h.stored(API_ID, "dev", "API_TOKEN").as_deref(), Some("tok"));

    h.cd("services/api");
    assert!(!h.ok(&["up"]).contains("warning"));
}

// ---------- check --recursive ----------

#[test]
fn recursive_check_reports_every_project() {
    let h = monorepo();
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://root/db"]);
    h.ok(&["set", "prod", "DATABASE_URL", "postgres://prod/db"]);
    h.vault
        .set(API_ID, "dev", "API_TOKEN", &Secret::new("tok"))
        .unwrap();

    let (result, out) = h.run_output(&["check", "-r"]);
    let err = format!("{:#}", result.unwrap_err());
    assert!(err.contains("1 of 3 project(s) failed"), "{err}");
    assert!(out.contains("ok    envy.json"), "{out}");
    assert!(out.contains("ok    services/api/envy.json"), "{out}");
    assert!(out.contains("FAIL  tools/cli/envy.json"), "{out}");
    assert!(
        out.contains("      Missing value for 'API_TOKEN' in 'dev'."),
        "the problems are listed under the project: {out}"
    );
}

#[test]
fn recursive_check_fails_when_a_project_fails() {
    let h = monorepo();
    let err = h.err(&["check", "--recursive"]);
    assert!(err.contains("3 project(s) failed"), "{err}");
}

#[test]
fn recursive_check_passes_and_skips_projects_without_the_environment() {
    let h = monorepo();
    h.ok(&["set", "prod", "DATABASE_URL", "postgres://prod/db"]);
    let out = h.ok(&["check", "-r", "prod"]);
    assert!(out.contains("ok    services/api/envy.json"), "{out}");
    assert!(out.contains("skip  tools/cli/envy.json"), "{out}");
    assert!(out.contains("2 project(s) checked, 1 skipped"), "{out}");
}

#[test]
fn recursive_check_fails_on_duplicated_ids() {
    let h = Harness::new();
    h.git_init();
    h.save_manifest("a", &sample_envy());
    h.save_manifest("b", &sample_envy());
    h.vault
        .set(
            PROJECT_ID,
            "dev",
            "DATABASE_URL",
            &Secret::new("postgres://x/db"),
        )
        .unwrap();
    h.vault
        .set(PROJECT_ID, "dev", "API_TOKEN", &Secret::new("t"))
        .unwrap();
    h.vault
        .set(
            PROJECT_ID,
            "prod",
            "DATABASE_URL",
            &Secret::new("postgres://y/db"),
        )
        .unwrap();
    h.vault
        .set(PROJECT_ID, "prod", "API_TOKEN", &Secret::new("t"))
        .unwrap();

    let err = h.err(&["check", "-r"]);
    assert!(err.contains("1 duplicated id(s)"), "{err}");
}

#[test]
fn recursive_check_without_manifests_fails() {
    let h = Harness::new();
    h.git_init();
    assert!(h.err(&["check", "-r"]).contains("No envy.json found"));
}

#[test]
fn recursive_check_does_not_take_a_variable() {
    let h = monorepo();
    assert!(h.run(&["check", "-r", "dev", "PORT"]).is_err());
}
