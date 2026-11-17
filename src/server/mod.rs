//! The Envy server (ADR 0002). [`ServerCore`] holds every rule (who may call what, the
//! checks on signatures and heads, sessions, invites, audit, rate limiting) and depends only
//! on a [`ServerStore`] and a clock, so it runs in every test. The SQLite store and the HTTP
//! listener (`envy serve`) are compiled with the `server` feature on Linux.

#[cfg(all(feature = "server", target_os = "linux"))]
pub mod http;
mod memory;
mod rules;
#[cfg(all(feature = "server", target_os = "linux"))]
pub mod sqlite;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use memory::MemoryStore;
pub use rules::ServerCore;

use crate::{
    remote::protocol::{
        Access, AuditEntry, MemberKeys, MemberStatus, SignedHead, SignedRecord, SignedRecovery,
        SignedWrap,
    },
    vault::format::Sealed,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMember {
    pub name: String,
    pub status: MemberStatus,
    pub admin: bool,
    pub keys: Option<MemberKeys>,
    /// SHA3-256 of the pending invite.
    pub invite_hash: Option<String>,
    pub invite_expires: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSession {
    /// SHA3-256 of the token: the token itself is never stored.
    pub token_hash: String,
    pub member: String,
    pub expires_at: i64,
}

/// Everything the server keeps about a project. None of it can be read without the keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectState {
    /// The creator's grant to itself, as sent when the project was created.
    pub creator: Access,
    pub recovery: SignedRecovery,
    pub head: SignedHead,
    pub index: Sealed,
    pub wraps: Vec<SignedWrap>,
    pub records: Vec<SignedRecord>,
}

/// The persistence of the server. Each call is atomic on its own; [`ServerStore::put_project`]
/// is the compare-and-swap that serialises writers of a project.
pub trait ServerStore: Send + Sync {
    fn meta(&self, key: &str) -> Result<Option<String>>;
    fn set_meta(&self, key: &str, value: Option<&str>) -> Result<()>;

    fn member(&self, name: &str) -> Result<Option<StoredMember>>;
    fn members(&self) -> Result<Vec<StoredMember>>;
    fn put_member(&self, member: &StoredMember) -> Result<()>;

    fn session(&self, token_hash: &str) -> Result<Option<StoredSession>>;
    fn put_session(&self, session: &StoredSession) -> Result<()>;
    fn delete_sessions(&self, member: &str) -> Result<()>;

    fn access(&self, project: &str) -> Result<Vec<Access>>;
    /// Every `(project, access)` of a member.
    fn access_of(&self, member: &str) -> Result<Vec<(String, Access)>>;
    fn set_access(&self, project: &str, access: &Access) -> Result<()>;
    fn delete_access(&self, member: &str) -> Result<()>;

    fn project(&self, id: &str) -> Result<Option<ProjectState>>;
    fn project_ids(&self) -> Result<Vec<String>>;
    /// Stores `state` only if the stored head still has `expected_seq` (`None`: the project
    /// must not exist yet). Returns whether it was stored.
    fn put_project(
        &self,
        id: &str,
        expected_seq: Option<u64>,
        state: &ProjectState,
    ) -> Result<bool>;

    fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
    fn audit(&self, project: Option<&str>) -> Result<Vec<AuditEntry>>;
}

/// Behaviour every [`ServerStore`] must have.
#[cfg(test)]
pub(crate) fn conformance(store: &dyn ServerStore) {
    use crate::remote::protocol::MemberStatus;

    assert_eq!(store.meta("k").unwrap(), None);
    store.set_meta("k", Some("v")).unwrap();
    store.set_meta("k", Some("w")).unwrap();
    assert_eq!(store.meta("k").unwrap().as_deref(), Some("w"));
    store.set_meta("k", None).unwrap();
    assert_eq!(store.meta("k").unwrap(), None);

    let mut ana = StoredMember {
        name: "ana".into(),
        status: MemberStatus::Invited,
        admin: false,
        keys: None,
        invite_hash: Some("h".into()),
        invite_expires: 5,
    };
    store.put_member(&ana).unwrap();
    ana.status = MemberStatus::Active;
    store.put_member(&ana).unwrap();
    assert_eq!(store.member("ana").unwrap(), Some(ana.clone()));
    assert_eq!(store.members().unwrap(), vec![ana]);

    let session = StoredSession {
        token_hash: "t".into(),
        member: "ana".into(),
        expires_at: i64::MAX,
    };
    store.put_session(&session).unwrap();
    assert_eq!(store.session("t").unwrap(), Some(session));
    store.delete_sessions("ana").unwrap();
    assert_eq!(store.session("t").unwrap(), None);

    let read = Access {
        member: "ana".into(),
        env: "dev".into(),
        write: false,
        keys: MemberKeys {
            x25519: "x".into(),
            ed25519: "e".into(),
        },
        approver: "admin".into(),
        signature: "s".into(),
    };
    store.set_access("p", &read).unwrap();
    store
        .set_access(
            "p",
            &Access {
                write: true,
                ..read.clone()
            },
        )
        .unwrap();
    assert_eq!(
        store.access("p").unwrap(),
        vec![Access {
            write: true,
            ..read.clone()
        }]
    );
    assert_eq!(store.access_of("ana").unwrap().len(), 1);
    store.delete_access("ana").unwrap();
    assert!(store.access("p").unwrap().is_empty());

    let state = ProjectState {
        creator: read.clone(),
        recovery: SignedRecovery::default(),
        head: SignedHead {
            seq: 1,
            ..SignedHead::default()
        },
        index: Sealed {
            nonce: String::new(),
            ciphertext: String::new(),
        },
        wraps: Vec::new(),
        records: Vec::new(),
    };
    assert!(store.put_project("p", None, &state).unwrap());
    assert!(
        !store.put_project("p", None, &state).unwrap(),
        "exists already"
    );
    let mut next = state.clone();
    next.head.seq = 2;
    assert!(
        !store.put_project("p", Some(7), &next).unwrap(),
        "stale sequence"
    );
    assert!(store.put_project("p", Some(1), &next).unwrap());
    assert_eq!(store.project("p").unwrap(), Some(next));
    assert_eq!(store.project_ids().unwrap(), vec!["p".to_string()]);

    let entry = |project: Option<&str>| AuditEntry {
        at: 1,
        member: "ana".into(),
        action: "read".into(),
        project: project.map(str::to_string),
        envs: vec!["dev".into()],
    };
    store.append_audit(&entry(Some("p"))).unwrap();
    store.append_audit(&entry(None)).unwrap();
    assert_eq!(store.audit(Some("p")).unwrap(), vec![entry(Some("p"))]);
    assert_eq!(store.audit(None).unwrap().len(), 2);
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "server", target_os = "linux"))]
    use super::ServerStore;

    #[test]
    fn the_memory_store_passes_the_conformance_suite() {
        super::conformance(&super::MemoryStore::default());
    }

    #[test]
    #[cfg(all(feature = "server", target_os = "linux"))]
    fn the_sqlite_store_passes_the_conformance_suite() {
        let dir = tempfile::tempdir().unwrap();
        let store = super::sqlite::SqliteStore::open(&dir.path().join("envy.db")).unwrap();
        super::conformance(&store);
        drop(store);
        let reopened = super::sqlite::SqliteStore::open(&dir.path().join("envy.db")).unwrap();
        assert_eq!(
            reopened.project_ids().unwrap(),
            vec!["p".to_string()],
            "it persists"
        );
    }
}
