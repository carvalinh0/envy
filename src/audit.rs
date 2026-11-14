//! Local audit log: who changed or exposed which variables, and when. Values never enter it.
//!
//! One JSON line per event in `{data dir}/audit/{project id}.jsonl`, outside the repository.
//! Each line carries the SHA3-256 of the line before it, so a line edited or removed in the
//! middle of the file is detected; the newest line is only covered once a later event is
//! written. The file belongs to the user, so this is a record, not a security boundary:
//! whoever can write the file can also rewrite the whole chain.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: DateTime<Utc>,
    pub user: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Line {
    #[serde(flatten)]
    event: AuditEvent,
    /// SHA3-256 of the previous line, empty for the first one.
    prev: String,
}

#[derive(Debug, Default)]
pub struct AuditTrail {
    /// The events before the first line that can't be trusted.
    pub events: Vec<AuditEvent>,
    /// First line (from 1) that can't be trusted: the chain broke on it or on the next one.
    pub broken_at: Option<usize>,
}

pub trait AuditLog {
    fn record(&self, project: &str, event: &AuditEvent) -> Result<()>;
    /// `None` when auditing is disabled.
    fn read(&self, project: &str) -> Result<Option<AuditTrail>>;
}

/// The log on disk. Without a directory (no user data folder could be found) auditing is
/// disabled instead of failing every command, so headless CI keeps working.
pub struct FileAudit {
    dir: Option<PathBuf>,
}

impl FileAudit {
    /// `data_dir` is the user's Envy data folder; the logs go to its `audit` subfolder.
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        Self {
            dir: data_dir.map(|dir| dir.join("audit")),
        }
    }

    fn path(&self, project: &str) -> Option<PathBuf> {
        self.dir
            .as_ref()
            .map(|dir| dir.join(format!("{}.jsonl", file_stem(project))))
    }
}

impl AuditLog for FileAudit {
    fn record(&self, project: &str, event: &AuditEvent) -> Result<()> {
        let Some(path) = self.path(project) else {
            return Ok(());
        };
        let previous = match fs::read_to_string(&path) {
            Ok(content) => content.lines().last().map(digest).unwrap_or_default(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("Could not read the audit log {}", path.display()));
            }
        };
        let line = serde_json::to_string(&Line {
            event: event.clone(),
            prev: previous,
        })?;

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("Could not create {}", dir.display()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Could not open the audit log {}", path.display()))?;
        writeln!(file, "{line}")
            .with_context(|| format!("Could not write the audit log {}", path.display()))
    }

    fn read(&self, project: &str) -> Result<Option<AuditTrail>> {
        let Some(path) = self.path(project) else {
            return Ok(None);
        };
        if !path.is_file() {
            return Ok(Some(AuditTrail::default()));
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Could not read the audit log {}", path.display()))?;
        Ok(Some(verify(&content)))
    }
}

fn verify(content: &str) -> AuditTrail {
    let mut trail = AuditTrail::default();
    let mut expected = String::new();
    for (number, text) in content.lines().enumerate() {
        match serde_json::from_str::<Line>(text) {
            Ok(line) if line.prev == expected => trail.events.push(line.event),
            _ => {
                // A mismatch on this line means this line or the one before it changed.
                if number > 0 {
                    trail.events.pop();
                }
                trail.broken_at = Some(number.max(1));
                break;
            }
        }
        expected = digest(text);
    }
    trail
}

fn digest(line: &str) -> String {
    Sha3_256::digest(line.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The project id is a UUID, but a hand-edited manifest may hold anything, and the id must
/// never escape the audit folder.
pub(crate) fn file_stem(project: &str) -> String {
    let plain = !project.is_empty()
        && project
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if plain {
        project.to_string()
    } else {
        digest(project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: &str) -> AuditEvent {
        AuditEvent {
            at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            user: "ana".into(),
            action: action.into(),
            environment: Some("dev".into()),
            keys: vec!["API_TOKEN".into()],
        }
    }

    #[test]
    fn events_are_appended_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let audit = FileAudit::new(Some(dir.path().to_path_buf()));
        assert!(audit.read("p").unwrap().unwrap().events.is_empty());

        audit.record("p", &event("set")).unwrap();
        audit.record("p", &event("run")).unwrap();
        audit.record("other", &event("set")).unwrap();

        let trail = audit.read("p").unwrap().unwrap();
        assert_eq!(trail.events, vec![event("set"), event("run")]);
        assert_eq!(trail.broken_at, None);
        assert!(dir.path().join("audit/p.jsonl").is_file());
    }

    #[test]
    fn editing_or_removing_a_line_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let audit = FileAudit::new(Some(dir.path().to_path_buf()));
        for action in ["set", "run", "export"] {
            audit.record("p", &event(action)).unwrap();
        }
        let path = dir.path().join("audit/p.jsonl");
        let original = fs::read_to_string(&path).unwrap();

        fs::write(&path, original.replace("\"run\"", "\"ls\"")).unwrap();
        let trail = audit.read("p").unwrap().unwrap();
        assert_eq!(trail.broken_at, Some(2), "the edited line is not trusted");
        assert_eq!(trail.events, vec![event("set")]);

        let lines: Vec<&str> = original.lines().collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        let trail = audit.read("p").unwrap().unwrap();
        assert_eq!(trail.broken_at, Some(1));
        assert!(trail.events.is_empty());
    }

    #[test]
    fn without_a_data_folder_auditing_is_disabled() {
        let audit = FileAudit::new(None);
        audit.record("p", &event("set")).unwrap();
        assert!(audit.read("p").unwrap().is_none());
    }

    #[test]
    fn odd_project_ids_stay_inside_the_audit_folder() {
        assert_eq!(file_stem("9f8a3b2c-1234"), "9f8a3b2c-1234");
        let stem = file_stem("../../etc/passwd");
        assert!(stem.chars().all(|c| c.is_ascii_hexdigit()), "{stem}");
    }
}
