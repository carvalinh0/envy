//! Embeds Envy's own configuration at build time.
//!
//! `FILE_NAME` and `SCHEMA_PATH` are read from this repository's `envy.json`: the
//! `production` environment for release builds and `development` for any other profile.
//! Editing `envy.json` is enough for the next build (and therefore the next release)
//! to pick the new values up. They can still be overridden at runtime with environment
//! variables of the same name.

use std::{env, fs, path::PathBuf};

const KEYS: [&str; 2] = ["FILE_NAME", "SCHEMA_PATH"];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("set by Cargo"));
    let path = manifest_dir.join("envy.json");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", path.display());

    let environment = match env::var("PROFILE").as_deref() {
        Ok("release") => "production",
        _ => "development",
    };

    let Ok(content) = fs::read_to_string(&path) else {
        println!(
            "cargo:warning=envy.json not found, FILE_NAME and SCHEMA_PATH must be set at runtime"
        );
        return;
    };
    let manifest: serde_json::Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            println!(
                "cargo:warning=envy.json is not valid JSON ({err}), FILE_NAME and SCHEMA_PATH must be set at runtime"
            );
            return;
        }
    };

    for key in KEYS {
        match manifest["schemas"][environment][key]["default"].as_str() {
            Some(value) if !value.is_empty() => {
                println!("cargo:rustc-env=ENVY_DEFAULT_{key}={value}");
            }
            _ => println!(
                "cargo:warning=envy.json has no default for {key} in '{environment}', it must be set at runtime"
            ),
        }
    }
}
