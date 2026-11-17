//! The [`ServerStore`] of `envy serve`: one SQLite file. Members, projects and audit
//! entries are JSON documents in their rows; what the server must look up (sessions, access,
//! the head sequence) has its own columns. The compare-and-swap of a project is one
//! `UPDATE ... WHERE seq = ?`.

use std::{path::Path, sync::Mutex};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use super::{ProjectState, ServerStore, StoredMember, StoredSession};
use crate::remote::protocol::{Access, AuditEntry};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS members (name TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, member TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS access (
    project TEXT NOT NULL, member TEXT NOT NULL, env TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (project, member, env));
CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, seq INTEGER NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT, entry TEXT NOT NULL);
";

pub struct SqliteStore {
    connection: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)
            .with_context(|| format!("Could not open the database {}", path.display()))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        // The image has a read-only root and no /tmp: temporary tables stay in memory.
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self.connection.lock().expect("database lock");
        Ok(f(&connection)?)
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> rusqlite::Result<String> {
    serde_json::to_string(value)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> rusqlite::Result<T> {
    serde_json::from_str(text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

/// The whole signed grant is kept, so clients can verify it.
fn access_of_row(row: &rusqlite::Row) -> rusqlite::Result<Access> {
    from_json(&row.get::<_, String>("data")?)
}

impl ServerStore for SqliteStore {
    fn meta(&self, key: &str) -> Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()
        })
    }

    fn set_meta(&self, key: &str, value: Option<&str>) -> Result<()> {
        self.with(|c| {
            match value {
                Some(value) => c.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![key, value],
                )?,
                None => c.execute("DELETE FROM meta WHERE key = ?1", [key])?,
            };
            Ok(())
        })
    }

    fn member(&self, name: &str) -> Result<Option<StoredMember>> {
        self.with(|c| {
            let data: Option<String> = c
                .query_row("SELECT data FROM members WHERE name = ?1", [name], |row| {
                    row.get(0)
                })
                .optional()?;
            data.map(|data| from_json(&data)).transpose()
        })
    }

    fn members(&self) -> Result<Vec<StoredMember>> {
        self.with(|c| {
            let mut statement = c.prepare("SELECT data FROM members ORDER BY name")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.map(|data| from_json(&data?)).collect()
        })
    }

    fn put_member(&self, member: &StoredMember) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO members (name, data) VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET data = excluded.data",
                params![member.name, to_json(member)?],
            )?;
            Ok(())
        })
    }

    fn session(&self, token_hash: &str) -> Result<Option<StoredSession>> {
        self.with(|c| {
            c.query_row(
                "SELECT member, expires_at FROM sessions WHERE token_hash = ?1",
                [token_hash],
                |row| {
                    Ok(StoredSession {
                        token_hash: token_hash.to_string(),
                        member: row.get(0)?,
                        expires_at: row.get(1)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Also forgets the sessions that expired, so the table does not grow forever.
    fn put_session(&self, session: &StoredSession) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM sessions WHERE expires_at < strftime('%s', 'now')",
                [],
            )?;
            c.execute(
                "INSERT INTO sessions (token_hash, member, expires_at) VALUES (?1, ?2, ?3)",
                params![session.token_hash, session.member, session.expires_at],
            )?;
            Ok(())
        })
    }

    fn delete_sessions(&self, member: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM sessions WHERE member = ?1", [member])
                .map(|_| ())
        })
    }

    fn access(&self, project: &str) -> Result<Vec<Access>> {
        self.with(|c| {
            let mut statement =
                c.prepare("SELECT data FROM access WHERE project = ?1 ORDER BY member, env")?;
            let rows = statement.query_map([project], access_of_row)?;
            rows.collect()
        })
    }

    fn access_of(&self, member: &str) -> Result<Vec<(String, Access)>> {
        self.with(|c| {
            let mut statement = c.prepare(
                "SELECT project, data FROM access WHERE member = ?1 ORDER BY project, env",
            )?;
            let rows = statement.query_map([member], |row| {
                Ok((row.get("project")?, access_of_row(row)?))
            })?;
            rows.collect()
        })
    }

    fn set_access(&self, project: &str, access: &Access) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO access (project, member, env, data) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(project, member, env) DO UPDATE SET data = excluded.data",
                params![project, access.member, access.env, to_json(access)?],
            )?;
            Ok(())
        })
    }

    fn delete_access(&self, member: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM access WHERE member = ?1", [member])
                .map(|_| ())
        })
    }

    fn project(&self, id: &str) -> Result<Option<ProjectState>> {
        self.with(|c| {
            let state: Option<String> = c
                .query_row("SELECT state FROM projects WHERE id = ?1", [id], |row| {
                    row.get(0)
                })
                .optional()?;
            state.map(|state| from_json(&state)).transpose()
        })
    }

    fn project_ids(&self) -> Result<Vec<String>> {
        self.with(|c| {
            let mut statement = c.prepare("SELECT id FROM projects ORDER BY id")?;
            let rows = statement.query_map([], |row| row.get(0))?;
            rows.collect()
        })
    }

    fn put_project(
        &self,
        id: &str,
        expected_seq: Option<u64>,
        state: &ProjectState,
    ) -> Result<bool> {
        let seq = i64::try_from(state.head.seq)?;
        self.with(|c| {
            let changed = match expected_seq {
                None => c.execute(
                    "INSERT OR IGNORE INTO projects (id, seq, state) VALUES (?1, ?2, ?3)",
                    params![id, seq, to_json(state)?],
                )?,
                Some(expected) => c.execute(
                    "UPDATE projects SET seq = ?2, state = ?3 WHERE id = ?1 AND seq = ?4",
                    params![
                        id,
                        seq,
                        to_json(state)?,
                        i64::try_from(expected).unwrap_or(i64::MAX)
                    ],
                )?,
            };
            Ok(changed == 1)
        })
    }

    fn delete_project(&self, id: &str) -> Result<bool> {
        self.with(|c| {
            let transaction = c.unchecked_transaction()?;
            transaction.execute("DELETE FROM access WHERE project = ?1", [id])?;
            let removed = transaction.execute("DELETE FROM projects WHERE id = ?1", [id])?;
            transaction.commit()?;
            Ok(removed == 1)
        })
    }

    fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO audit (project, entry) VALUES (?1, ?2)",
                params![entry.project, to_json(entry)?],
            )?;
            Ok(())
        })
    }

    fn audit(&self, project: Option<&str>) -> Result<Vec<AuditEntry>> {
        self.with(|c| {
            let mut statement =
                c.prepare("SELECT entry FROM audit WHERE ?1 IS NULL OR project = ?1 ORDER BY id")?;
            let rows = statement.query_map([project], |row| row.get::<_, String>(0))?;
            rows.map(|entry| from_json(&entry?)).collect()
        })
    }
}
