mod common;

use common::Harness;

#[test]
fn version_prints_the_package_name_and_version() {
    let h = Harness::new();
    let out = h.ok(&["version"]);
    assert_eq!(
        out.trim(),
        format!("dot-envy {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn commands_other_than_init_need_a_manifest() {
    let h = Harness::new();
    for args in [
        &["check"][..],
        &["ls", "dev"],
        &["up"],
        &["schema"],
        &["switch", "dev"],
    ] {
        let err = h.err(args);
        assert!(err.contains("Use `envy init` first"), "{args:?}: {err}");
    }
}

#[test]
fn init_new_creates_an_empty_valid_manifest() {
    let h = Harness::new();
    h.ok(&["init", "My Project", "--new"]);

    let envy = h.manifest();
    assert_eq!(envy.name, "My Project");
    assert_eq!(envy.version, 1);
    assert_eq!(envy.schema.as_deref(), Some("schemas/v1.json"));
    assert!(envy.schemas.is_empty());
    assert!(envy.is_checksum_valid().unwrap());
    assert!(uuid::Uuid::parse_str(&envy.id).is_ok());
}

#[test]
fn init_refuses_to_overwrite_an_existing_manifest() {
    let h = Harness::new();
    h.ok(&["init", "One", "--new"]);
    let before = h.manifest().id;

    let err = h.err(&["init", "Two", "--new"]);
    assert!(err.contains("envy.json already exists"), "{err}");
    assert_eq!(h.manifest().id, before);
}

#[test]
fn init_new_leaves_env_files_untouched() {
    let h = Harness::new();
    h.write(".env.development", "PORT=3000\n");
    h.ok(&["init", "P", "--new"]);

    assert!(h.exists(".env.development"));
    assert!(h.manifest().schemas.is_empty());
    assert!(h.vault.is_empty());
}

#[test]
fn init_moves_env_files_into_the_vault() {
    let h = Harness::new();
    h.write(
        ".env.development",
        "PORT=3000\nAPI_TOKEN=dev-token\nDEBUG=true\nDATABASE_URL=postgres://u@localhost/db\nNAME=envy\n",
    );
    h.write(".env.production", "PORT=80\nAPI_TOKEN=prod-token\n");
    h.write(".env.example", "REGION=us-east-1\n");

    let out = h.ok(&["init", "P"]);
    let envy = h.manifest();
    let id = envy.id.clone();

    let dev = &envy.schemas["development"];
    assert_eq!(dev["PORT"].kind, "port");
    assert_eq!(dev["API_TOKEN"].kind, "secret");
    assert_eq!(dev["DEBUG"].kind, "boolean");
    assert_eq!(dev["DATABASE_URL"].kind, "url");
    assert_eq!(dev["NAME"].kind, "string");
    assert!(
        dev.values().all(|v| v.default.is_none()),
        "values must not become defaults"
    );
    assert_eq!(envy.schemas["production"]["PORT"].kind, "port");
    assert_eq!(envy.schemas["global"]["REGION"].kind, "string");
    assert!(envy.is_checksum_valid().unwrap());
    envy.check_schema(None, None).unwrap();

    assert_eq!(
        h.stored(&id, "development", "API_TOKEN").as_deref(),
        Some("dev-token")
    );
    assert_eq!(h.stored(&id, "production", "PORT").as_deref(), Some("80"));
    assert_eq!(
        h.stored(&id, "global", "REGION"),
        None,
        ".env.example values are never stored"
    );
    assert_eq!(h.vault.len(), 7);

    assert!(!h.exists(".env.development"));
    assert!(!h.exists(".env.production"));
    assert!(
        h.exists(".env.example"),
        "the example file is meant to be committed"
    );
    assert!(out.contains("Stored 7 value(s)"), "{out}");

    let manifest_text = std::fs::read_to_string(h.config.manifest_path()).unwrap();
    assert!(!manifest_text.contains("dev-token") && !manifest_text.contains("prod-token"));
}

#[test]
fn init_nondestructive_keeps_the_env_files() {
    let h = Harness::new();
    h.write(".env.development", "PORT=3000\n");
    h.ok(&["init", "P", "--nondestructive"]);

    assert!(h.exists(".env.development"));
    let id = h.manifest().id;
    assert_eq!(
        h.stored(&id, "development", "PORT").as_deref(),
        Some("3000")
    );
}

#[test]
fn init_reports_and_keeps_a_plain_env_file() {
    let h = Harness::new();
    h.write(".env", "PORT=3000\n");
    let out = h.ok(&["init", "P"]);

    assert!(h.exists(".env"));
    assert!(out.contains("Skipped"), "{out}");
    assert!(h.vault.is_empty());
}

#[test]
fn init_with_an_invalid_env_file_changes_nothing() {
    let h = Harness::new();
    h.write(".env.development", "PORT=3000\nthis is not valid\n");

    let err = h.err(&["init", "P"]);
    assert!(err.contains(".env.development"), "{err}");
    assert!(!h.exists("envy.json"));
    assert!(h.exists(".env.development"));
    assert!(h.vault.is_empty());
}

#[test]
fn init_skips_empty_values_in_the_vault_but_declares_them() {
    let h = Harness::new();
    h.write(".env.development", "EMPTY=\nPORT=3000\n");
    h.ok(&["init", "P"]);

    let id = h.manifest().id;
    assert!(h.manifest().schemas["development"].contains_key("EMPTY"));
    assert_eq!(h.stored(&id, "development", "EMPTY"), None);
    assert_eq!(h.vault.len(), 1);
}
