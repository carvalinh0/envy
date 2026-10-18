mod common;

use common::{Harness, PROJECT_ID};

const SECRET_VALUE: &str = "s3cr3t-value-123";

fn ready() -> Harness {
    let h = Harness::with_manifest();
    h.ok(&["set", "dev", "DATABASE_URL", "postgres://u@localhost/db"]);
    h.ok(&["set", "dev", "API_TOKEN", SECRET_VALUE]);
    h
}

// ---------- set ----------

#[test]
fn set_stores_a_valid_value_in_the_vault() {
    let h = Harness::with_manifest();
    let out = h.ok(&["set", "dev", "PORT", "8080"]);
    assert!(out.contains("Stored 'PORT' in 'dev'"), "{out}");
    assert_eq!(h.stored(PROJECT_ID, "dev", "PORT").as_deref(), Some("8080"));
}

#[test]
fn set_typechecks_the_value() {
    let h = Harness::with_manifest();
    let err = h.err(&["set", "dev", "PORT", "not-a-port"]);
    assert!(
        err.contains("Invalid value for 'PORT' (expected port)"),
        "{err}"
    );
    assert!(
        !err.contains("not-a-port"),
        "the rejected value must not be echoed: {err}"
    );
    assert!(h.vault.is_empty());
}

#[test]
fn set_requires_a_declared_variable() {
    let h = Harness::with_manifest();
    let err = h.err(&["set", "dev", "UNDECLARED", "x"]);
    assert!(
        err.contains("There's no variable called 'UNDECLARED'"),
        "{err}"
    );
    assert!(h.vault.is_empty());
}

#[test]
fn set_requires_an_existing_environment() {
    let h = Harness::with_manifest();
    let err = h.err(&["set", "nope", "PORT", "80"]);
    assert!(
        err.contains("There's no environment called 'nope'"),
        "{err}"
    );
}

#[test]
fn set_accepts_variables_declared_in_global() {
    let h = Harness::with_manifest();
    h.ok(&["set", "dev", "APP_NAME", "dev-app"]);
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "APP_NAME").as_deref(),
        Some("dev-app")
    );
}

#[test]
fn set_never_prints_the_value() {
    let h = Harness::with_manifest();
    let out = h.ok(&["set", "dev", "API_TOKEN", SECRET_VALUE]);
    assert!(!out.contains(SECRET_VALUE), "{out}");
}

// ---------- ls ----------

#[test]
fn ls_masks_values_by_default() {
    let h = ready();
    let out = h.ok(&["ls", "dev"]);
    assert!(out.starts_with("KEY"), "{out}");
    assert!(!out.contains(SECRET_VALUE), "{out}");
    assert!(!out.contains("postgres://"), "{out}");
    assert!(!out.contains("3000"), "defaults are masked too: {out}");
    assert!(out.contains("********"), "{out}");
}

#[test]
fn ls_show_reveals_the_values() {
    let h = ready();
    let out = h.ok(&["ls", "dev", "--show"]);
    assert!(out.contains(SECRET_VALUE), "{out}");
    assert!(out.contains("3000"), "{out}");
    assert!(out.contains("postgres://u@localhost/db"), "{out}");
}

#[test]
fn ls_marks_unset_variables() {
    let h = Harness::with_manifest();
    let out = h.ok(&["ls", "dev"]);
    assert!(out.contains("<unset>"), "{out}");
}

#[test]
fn ls_includes_the_variables_inherited_from_global() {
    let h = Harness::with_manifest();
    let out = h.ok(&["ls", "prod", "--show"]);
    assert!(out.contains("APP_NAME"), "{out}");
    assert!(out.contains("envy"), "{out}");
}

#[test]
fn ls_reports_empty_environments() {
    let h = Harness::with_manifest();
    h.ok(&["schema", "empty"]);
    let out = h.ok(&["ls", "empty"]);
    assert!(
        out.contains("APP_NAME"),
        "global variables are inherited: {out}"
    );
}

#[test]
fn ls_unknown_environment_fails() {
    let h = Harness::with_manifest();
    assert!(
        h.err(&["ls", "nope"])
            .contains("There's no environment called 'nope'")
    );
}

// ---------- check ----------

#[test]
fn check_fails_listing_every_problem() {
    let h = Harness::with_manifest();
    let err = h.err(&["check"]);
    assert!(
        err.contains("Missing value for 'DATABASE_URL' in 'dev'"),
        "{err}"
    );
    assert!(
        err.contains("Missing value for 'API_TOKEN' in 'dev'"),
        "{err}"
    );
    assert!(
        err.contains("Missing value for 'DATABASE_URL' in 'prod'"),
        "{err}"
    );
    assert!(
        err.contains("Missing value for 'API_TOKEN' in 'prod'"),
        "{err}"
    );
}

#[test]
fn check_passes_when_everything_is_set() {
    let h = ready();
    let out = h.ok(&["check", "dev"]);
    assert!(out.contains("All good"), "{out}");
    assert!(!out.contains(SECRET_VALUE));
}

#[test]
fn check_one_environment_ignores_the_others() {
    let h = ready();
    h.ok(&["check", "dev"]);
    assert!(h.err(&["check", "prod"]).contains("'prod'"));
}

#[test]
fn check_one_variable() {
    let h = ready();
    h.ok(&["check", "dev", "PORT"]);
    let err = h.err(&["check", "prod", "API_TOKEN"]);
    assert!(
        err.contains("Missing value for 'API_TOKEN' in 'prod'"),
        "{err}"
    );
    assert!(!err.contains("DATABASE_URL"), "{err}");
}

#[test]
fn check_unknown_environment_or_variable() {
    let h = ready();
    assert!(
        h.err(&["check", "nope"])
            .contains("There's no environment called 'nope'")
    );
    assert!(
        h.err(&["check", "dev", "NOPE"])
            .contains("There's no variable called 'NOPE'")
    );
}

#[test]
fn check_variable_requires_an_environment() {
    let h = ready();
    assert!(h.run(&["check"]).is_err());
}

#[test]
fn check_uses_a_vault_value_over_the_default_and_validates_it() {
    let h = ready();
    use dot_envy::{schema::Secret, vault::SecretVault};
    h.vault
        .set(PROJECT_ID, "dev", "PORT", &Secret::new("oops"))
        .unwrap();
    let err = h.err(&["check", "dev"]);
    assert!(err.contains("Invalid value for 'PORT' in 'dev'"), "{err}");
    assert!(!err.contains("oops"), "{err}");
}

// ---------- diff ----------

#[test]
fn diff_lists_the_missing_keys_of_the_active_environment() {
    let h = Harness::with_manifest();
    h.ok(&["switch", "dev"]);
    let out = h.ok(&["diff"]);
    assert!(out.contains("Missing in 'dev'"), "{out}");
    assert!(
        out.contains("DATABASE_URL") && out.contains("API_TOKEN"),
        "{out}"
    );
    assert!(!out.contains("PORT"), "PORT has a default: {out}");
}

#[test]
fn diff_for_a_named_environment_and_when_nothing_is_missing() {
    let h = ready();
    assert!(h.ok(&["diff", "prod"]).contains("Missing in 'prod'"));
    assert!(h.ok(&["diff", "dev"]).contains("No missing keys in 'dev'"));
}

#[test]
fn diff_compares_two_environments() {
    let h = Harness::with_manifest();
    let out = h.ok(&["diff", "dev", "prod"]);
    assert!(out.contains("- PORT (only in 'dev')"), "{out}");
    assert!(!out.contains("DATABASE_URL"), "{out}");
}

#[test]
fn diff_reports_type_differences_and_additions() {
    let h = Harness::with_manifest();
    // Make prod.API_TOKEN a string and add a prod-only variable.
    let mut envy = h.manifest();
    envy.schemas
        .get_mut("prod")
        .unwrap()
        .get_mut("API_TOKEN")
        .unwrap()
        .kind = "string".into();
    envy.schemas.get_mut("prod").unwrap().insert(
        "EXTRA".into(),
        dot_envy::envy::VarDetail {
            kind: "string".into(),
            default: None,
        },
    );
    envy.sync().unwrap();
    envy.save(&h.config.manifest_path()).unwrap();

    let out = h.ok(&["diff", "dev", "prod"]);
    assert!(
        out.contains("~ API_TOKEN (type secret in 'dev', string in 'prod')"),
        "{out}"
    );
    assert!(out.contains("+ EXTRA (only in 'prod')"), "{out}");
}

#[test]
fn diff_of_identical_environments() {
    let h = Harness::with_manifest();
    assert!(
        h.ok(&["diff", "dev", "dev"])
            .contains("declare the same variables")
    );
}

// ---------- rm ----------

#[test]
fn rm_removes_from_schema_and_vault_and_bumps_the_version() {
    let h = ready();
    let out = h.ok(&["rm", "API_TOKEN", "--from", "dev"]);
    assert!(out.contains("Removed 'API_TOKEN' from 'dev'"), "{out}");

    let envy = h.manifest();
    assert!(!envy.schemas["dev"].contains_key("API_TOKEN"));
    assert_eq!(envy.version, 2);
    assert!(envy.is_checksum_valid().unwrap());
    assert_eq!(h.stored(PROJECT_ID, "dev", "API_TOKEN"), None);
    assert!(
        h.stored(PROJECT_ID, "dev", "DATABASE_URL").is_some(),
        "other values stay"
    );
}

#[test]
fn rm_defaults_to_the_active_environment_and_accepts_the_remove_alias() {
    let h = ready();
    h.ok(&["switch", "dev"]);
    h.ok(&["remove", "DATABASE_URL"]);
    assert!(!h.manifest().schemas["dev"].contains_key("DATABASE_URL"));
    assert!(h.manifest().schemas["prod"].contains_key("DATABASE_URL"));
}

#[test]
fn rm_rejects_unknown_variables_without_side_effects() {
    let h = ready();
    let err = h.err(&["rm", "NOPE", "--from", "dev"]);
    assert!(err.contains("There's no variable called 'NOPE'"), "{err}");
    assert_eq!(h.manifest().version, 1);
    assert_eq!(h.vault.len(), 2);
}

// ---------- rename ----------

#[test]
fn rename_moves_the_declaration_and_the_value() {
    let h = ready();
    let out = h.ok(&["rename", "API_TOKEN", "AUTH_TOKEN", "--in", "dev"]);
    assert!(out.contains("Renamed 'API_TOKEN' to 'AUTH_TOKEN'"), "{out}");

    let envy = h.manifest();
    assert!(envy.schemas["dev"].contains_key("AUTH_TOKEN"));
    assert!(!envy.schemas["dev"].contains_key("API_TOKEN"));
    assert_eq!(envy.version, 2);
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "AUTH_TOKEN").as_deref(),
        Some(SECRET_VALUE)
    );
    assert_eq!(h.stored(PROJECT_ID, "dev", "API_TOKEN"), None);
    assert!(h.ok(&["check", "dev"]).contains("All good"));
}

#[test]
fn rename_without_a_stored_value_only_changes_the_schema() {
    let h = Harness::with_manifest();
    h.ok(&["switch", "dev"]);
    h.ok(&["rename", "PORT", "HTTP_PORT"]);
    assert!(h.manifest().schemas["dev"].contains_key("HTTP_PORT"));
    assert!(h.vault.is_empty());
}

#[test]
fn rename_rejects_collisions_and_unknown_names() {
    let h = ready();
    assert!(
        h.err(&["rename", "API_TOKEN", "PORT", "--in", "dev"])
            .contains("already exists")
    );
    assert!(
        h.err(&["rename", "NOPE", "X", "--in", "dev"])
            .contains("There's no variable called 'NOPE'")
    );
    assert_eq!(h.manifest().version, 1);
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(SECRET_VALUE)
    );
}

// ---------- fill ----------

#[test]
fn fill_only_asks_for_the_missing_variables() {
    let h = Harness::with_manifest();
    h.prompter.answers(&[SECRET_VALUE, "postgres://u@h/db"]);
    let out = h.ok(&["fill", "dev"]);

    let asked = h.prompter.asked.borrow().clone();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert!(
        asked
            .iter()
            .all(|l| !l.starts_with("PORT") && !l.starts_with("APP_NAME")),
        "{asked:?}"
    );
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "DATABASE_URL").as_deref(),
        Some("postgres://u@h/db")
    );
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(SECRET_VALUE)
    );
    assert!(out.contains("Filled 2 variable(s), skipped 0"), "{out}");
    assert!(!out.contains(SECRET_VALUE));
    h.ok(&["check", "dev"]);
}

#[test]
fn fill_asks_again_after_an_invalid_value() {
    let h = Harness::with_manifest();
    h.prompter
        .answers(&[SECRET_VALUE, "not a url", "https://ok.example"]);
    let out = h.ok(&["fill", "dev"]);
    assert!(out.contains("Invalid value for 'DATABASE_URL'"), "{out}");
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "DATABASE_URL").as_deref(),
        Some("https://ok.example")
    );
}

#[test]
fn fill_gives_up_after_three_invalid_attempts() {
    let h = Harness::with_manifest();
    h.prompter.answers(&[SECRET_VALUE, "x", "y", "z"]);
    let err = h.err(&["fill", "dev"]);
    assert!(err.contains("still have no value"), "{err}");
    assert_eq!(h.stored(PROJECT_ID, "dev", "DATABASE_URL"), None);
    assert_eq!(
        h.stored(PROJECT_ID, "dev", "API_TOKEN").as_deref(),
        Some(SECRET_VALUE)
    );
}

#[test]
fn fill_skips_on_empty_answers() {
    let h = Harness::with_manifest();
    h.prompter.answers(&["", ""]);
    let err = h.err(&["fill", "dev"]);
    assert!(
        err.contains("2 variable(s) of 'dev' still have no value"),
        "{err}"
    );
    assert!(h.vault.is_empty());
}

#[test]
fn fill_has_nothing_to_do_when_everything_is_set() {
    let h = ready();
    let out = h.ok(&["fill", "dev"]);
    assert!(out.contains("Nothing to fill"), "{out}");
    assert!(h.prompter.asked.borrow().is_empty());
}

#[test]
fn fill_uses_the_active_environment() {
    let h = Harness::with_manifest();
    h.ok(&["switch", "prod"]);
    h.prompter.answers(&[SECRET_VALUE, "https://p.example"]);
    h.ok(&["fill"]);
    assert!(h.stored(PROJECT_ID, "prod", "DATABASE_URL").is_some());
}

// ---------- run ----------

#[test]
fn run_injects_stored_values_defaults_and_inherited_variables() {
    let h = ready();
    let (code, _) = h.run(&["run", "dev", "--", "npm", "run", "dev"]).unwrap();
    assert_eq!(code, 0);

    let calls = h.runner.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "npm");
    assert_eq!(calls[0].args, vec!["run", "dev"]);
    assert_eq!(calls[0].envs["PORT"], "3000");
    assert_eq!(calls[0].envs["API_TOKEN"], SECRET_VALUE);
    assert_eq!(calls[0].envs["DATABASE_URL"], "postgres://u@localhost/db");
    assert_eq!(calls[0].envs["APP_NAME"], "envy");
}

#[test]
fn run_propagates_the_exit_code_of_the_child() {
    let h = ready();
    h.runner.exit_code.set(42);
    let (code, _) = h.run(&["run", "dev", "--", "false"]).unwrap();
    assert_eq!(code, 42);
}

#[test]
fn run_refuses_to_start_when_values_are_missing() {
    let h = Harness::with_manifest();
    let err = h.err(&["run", "dev", "--", "npm", "start"]);
    assert!(
        err.contains("Missing value for 'API_TOKEN' in 'dev'"),
        "{err}"
    );
    assert!(h.runner.calls.borrow().is_empty());
}

#[test]
fn run_requires_a_command_after_the_separator() {
    let h = ready();
    assert!(h.run(&["run", "dev"]).is_err());
}

#[test]
fn run_passes_flags_of_the_child_command_through() {
    let h = ready();
    h.ok(&["run", "dev", "--", "node", "--inspect", "-e", "1"]);
    assert_eq!(
        h.runner.calls.borrow()[0].args,
        vec!["--inspect", "-e", "1"]
    );
}

// ---------- global inheritance ----------

#[test]
fn a_global_vault_value_is_inherited_by_every_environment() {
    let h = Harness::with_manifest();
    h.ok(&["set", "global", "APP_NAME", "shared"]);
    assert!(h.ok(&["ls", "dev", "--show"]).contains("shared"));
    assert!(h.ok(&["ls", "prod", "--show"]).contains("shared"));

    h.ok(&["set", "prod", "APP_NAME", "prod-only"]);
    let prod = h.ok(&["ls", "prod", "--show"]);
    assert!(
        prod.contains("prod-only") && !prod.contains("shared"),
        "{prod}"
    );
}
