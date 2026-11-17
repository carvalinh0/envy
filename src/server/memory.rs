//! A [`ServerStore`] in memory, for tests (like `MemoryVault` for the keyring).

use std::{collections::BTreeMap, sync::Mutex};

use anyhow::Result;

use super::{ProjectState, ServerStore, StoredMember, StoredSession};
use crate::remote::protocol::{Access, AuditEntry};

#[derive(Default)]
struct State {
    meta: BTreeMap<String, String>,
    members: BTreeMap<String, StoredMember>,
    sessions: BTreeMap<String, StoredSession>,
    access: Vec<(String, Access)>,
    projects: BTreeMap<String, ProjectState>,
    audit: Vec<AuditEntry>,
}

#[derive(Default)]
pub struct MemoryStore {
    state: Mutex<State>,
}

impl MemoryStore {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> Result<T> {
        Ok(f(&mut self.state.lock().expect("store lock")))
    }
}

impl ServerStore for MemoryStore {
    fn meta(&self, key: &str) -> Result<Option<String>> {
        self.with(|s| s.meta.get(key).cloned())
    }

    fn set_meta(&self, key: &str, value: Option<&str>) -> Result<()> {
        self.with(|s| match value {
            Some(value) => {
                s.meta.insert(key.into(), value.into());
            }
            None => {
                s.meta.remove(key);
            }
        })
    }

    fn member(&self, name: &str) -> Result<Option<StoredMember>> {
        self.with(|s| s.members.get(name).cloned())
    }

    fn members(&self) -> Result<Vec<StoredMember>> {
        self.with(|s| s.members.values().cloned().collect())
    }

    fn put_member(&self, member: &StoredMember) -> Result<()> {
        self.with(|s| {
            s.members.insert(member.name.clone(), member.clone());
        })
    }

    fn session(&self, token_hash: &str) -> Result<Option<StoredSession>> {
        self.with(|s| s.sessions.get(token_hash).cloned())
    }

    fn put_session(&self, session: &StoredSession) -> Result<()> {
        self.with(|s| {
            s.sessions
                .insert(session.token_hash.clone(), session.clone());
        })
    }

    fn delete_sessions(&self, member: &str) -> Result<()> {
        self.with(|s| s.sessions.retain(|_, session| session.member != member))
    }

    fn access(&self, project: &str) -> Result<Vec<Access>> {
        self.with(|s| {
            s.access
                .iter()
                .filter(|(p, _)| p == project)
                .map(|(_, access)| access.clone())
                .collect()
        })
    }

    fn access_of(&self, member: &str) -> Result<Vec<(String, Access)>> {
        self.with(|s| {
            s.access
                .iter()
                .filter(|(_, access)| access.member == member)
                .cloned()
                .collect()
        })
    }

    fn set_access(&self, project: &str, access: &Access) -> Result<()> {
        self.with(|s| {
            s.access.retain(|(p, a)| {
                !(p == project && a.member == access.member && a.env == access.env)
            });
            s.access.push((project.into(), access.clone()));
        })
    }

    fn delete_access(&self, member: &str) -> Result<()> {
        self.with(|s| s.access.retain(|(_, access)| access.member != member))
    }

    fn project(&self, id: &str) -> Result<Option<ProjectState>> {
        self.with(|s| s.projects.get(id).cloned())
    }

    fn project_ids(&self) -> Result<Vec<String>> {
        self.with(|s| s.projects.keys().cloned().collect())
    }

    fn put_project(
        &self,
        id: &str,
        expected_seq: Option<u64>,
        state: &ProjectState,
    ) -> Result<bool> {
        self.with(|s| {
            let current = s.projects.get(id).map(|project| project.head.seq);
            if current != expected_seq {
                return false;
            }
            s.projects.insert(id.into(), state.clone());
            true
        })
    }

    fn delete_project(&self, id: &str) -> Result<bool> {
        self.with(|s| {
            s.access.retain(|(project, _)| project != id);
            s.projects.remove(id).is_some()
        })
    }

    fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        self.with(|s| s.audit.push(entry.clone()))
    }

    fn audit(&self, project: Option<&str>) -> Result<Vec<AuditEntry>> {
        self.with(|s| {
            s.audit
                .iter()
                .filter(|entry| project.is_none() || entry.project.as_deref() == project)
                .cloned()
                .collect()
        })
    }
}
