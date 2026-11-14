//! Behaviour every [`SecretVault`] must have. Each backend's tests call [`run`] with a
//! constructor of an empty vault, so a new backend cannot drift from the others.

use chrono::{DateTime, Utc};

use super::{Change, SecretVault, Version};
use crate::schema::Secret;

pub(crate) fn run<V: SecretVault>(make: impl Fn() -> V) {
    // A failing assertion points at the line of its case, so the cases need no names.
    let cases: [fn(&dyn SecretVault); 10] = [
        missing_values_read_as_none,
        set_then_get,
        isolation,
        overwriting_keeps_the_old_value,
        only_keep_versions_survive,
        keep_zero_stores_no_history,
        delete_removes_everything,
        deleting_nothing_returns_false,
        unknown_versions_read_as_none,
        history_is_per_variable,
    ];
    for case in cases {
        case(&make());
    }
}

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}

fn change(seconds: i64, keep: usize) -> Change {
    Change {
        at: at(seconds),
        keep,
    }
}

fn read(vault: &dyn SecretVault, environment: &str, key: &str) -> Option<String> {
    vault
        .get("p", environment, key)
        .unwrap()
        .map(|s| s.expose_secret().to_string())
}

fn read_version(vault: &dyn SecretVault, key: &str, number: u32) -> Option<String> {
    vault
        .get_version("p", "dev", key, number)
        .unwrap()
        .map(|s| s.expose_secret().to_string())
}

fn store(vault: &dyn SecretVault, key: &str, value: &str, change: Change) {
    vault
        .set("p", "dev", key, &Secret::new(value), change)
        .unwrap();
}

fn missing_values_read_as_none(vault: &dyn SecretVault) {
    assert!(read(vault, "dev", "K").is_none());
    assert!(vault.history("p", "dev", "K").unwrap().is_empty());
}

fn set_then_get(vault: &dyn SecretVault) {
    store(vault, "K", "v", change(100, 5));
    assert_eq!(read(vault, "dev", "K").as_deref(), Some("v"));
    assert_eq!(
        vault.history("p", "dev", "K").unwrap(),
        vec![Version {
            number: 1,
            created_at: Some(at(100)),
            active: true
        }]
    );
}

fn isolation(vault: &dyn SecretVault) {
    let c = change(1, 5);
    vault.set("p1", "dev", "K", &Secret::new("a"), c).unwrap();
    vault.set("p2", "dev", "K", &Secret::new("b"), c).unwrap();
    vault.set("p1", "prod", "K", &Secret::new("c"), c).unwrap();
    let get = |p: &str, e: &str| {
        vault
            .get(p, e, "K")
            .unwrap()
            .unwrap()
            .expose_secret()
            .to_string()
    };
    assert_eq!(get("p1", "dev"), "a");
    assert_eq!(get("p2", "dev"), "b");
    assert_eq!(get("p1", "prod"), "c");
}

fn overwriting_keeps_the_old_value(vault: &dyn SecretVault) {
    store(vault, "K", "old", change(100, 5));
    store(vault, "K", "new", change(200, 5));

    assert_eq!(read(vault, "dev", "K").as_deref(), Some("new"));
    let history = vault.history("p", "dev", "K").unwrap();
    let numbers: Vec<(u32, bool)> = history.iter().map(|v| (v.number, v.active)).collect();
    assert_eq!(numbers, vec![(2, true), (1, false)]);
    assert_eq!(history[1].created_at, Some(at(100)));
    assert_eq!(read_version(vault, "K", 1).as_deref(), Some("old"));
    assert_eq!(read_version(vault, "K", 2).as_deref(), Some("new"));
}

fn only_keep_versions_survive(vault: &dyn SecretVault) {
    for (i, value) in ["v1", "v2", "v3", "v4"].iter().enumerate() {
        store(vault, "K", value, change(i as i64, 2));
    }
    let numbers: Vec<u32> = vault
        .history("p", "dev", "K")
        .unwrap()
        .iter()
        .map(|v| v.number)
        .collect();
    assert_eq!(numbers, vec![4, 3, 2]);
    assert!(
        read_version(vault, "K", 1).is_none(),
        "pruned versions are removed"
    );
    assert_eq!(read_version(vault, "K", 2).as_deref(), Some("v2"));
}

fn keep_zero_stores_no_history(vault: &dyn SecretVault) {
    store(vault, "K", "v1", change(1, 5));
    store(vault, "K", "v2", change(2, 0));
    let history = vault.history("p", "dev", "K").unwrap();
    assert_eq!(
        history.len(),
        1,
        "keep 0 also drops the versions already kept"
    );
    assert!(history[0].active);
    assert!(read_version(vault, "K", 1).is_none());
}

fn delete_removes_everything(vault: &dyn SecretVault) {
    store(vault, "K", "v1", change(1, 5));
    store(vault, "K", "v2", change(2, 5));
    assert!(vault.delete("p", "dev", "K").unwrap());
    assert!(read(vault, "dev", "K").is_none());
    assert!(vault.history("p", "dev", "K").unwrap().is_empty());
    assert!(read_version(vault, "K", 1).is_none());

    store(vault, "K", "again", change(3, 5));
    assert_eq!(vault.history("p", "dev", "K").unwrap().len(), 1);
}

fn deleting_nothing_returns_false(vault: &dyn SecretVault) {
    assert!(!vault.delete("p", "dev", "K").unwrap());
}

fn unknown_versions_read_as_none(vault: &dyn SecretVault) {
    store(vault, "K", "v1", change(1, 5));
    assert!(read_version(vault, "K", 7).is_none());
    assert!(read_version(vault, "OTHER", 1).is_none());
}

fn history_is_per_variable(vault: &dyn SecretVault) {
    store(vault, "A", "a1", change(1, 5));
    store(vault, "A", "a2", change(2, 5));
    store(vault, "B", "b1", change(3, 5));
    assert_eq!(vault.history("p", "dev", "A").unwrap().len(), 2);
    assert_eq!(vault.history("p", "dev", "B").unwrap().len(), 1);
}
