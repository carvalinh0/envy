//! What client and server exchange (ADR 0002): one JSON request per call to `POST /v1/rpc`,
//! tagged by `op`, and the signed shapes of records, wraps and heads. The signed messages are
//! built here, so both sides verify exactly the same bytes.

use serde::{Deserialize, Serialize};

use crate::{
    identity::PublicKeys,
    keys::{encode, int},
    vault::format::{Purpose, Sealed, b64, unb64},
};

pub const RPC_PATH: &str = "/v1/rpc";
pub const HEALTH_PATH: &str = "/v1/health";
/// Requests above this are refused by the server.
pub const MAX_BODY: usize = 4 * 1024 * 1024;
/// The access of a member to every environment of a project.
pub const ALL_ENVIRONMENTS: &str = "*";
/// The member every key is also wrapped for: the project's recovery key.
pub const RECOVERY: &str = "recovery";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberKeys {
    pub x25519: String,
    pub ed25519: String,
}

impl MemberKeys {
    pub fn of(keys: &PublicKeys) -> Self {
        Self {
            x25519: b64(&keys.x25519),
            ed25519: b64(&keys.ed25519),
        }
    }

    pub fn decode(&self) -> Option<PublicKeys> {
        Some(PublicKeys {
            x25519: unb64(&self.x25519).ok()?.try_into().ok()?,
            ed25519: unb64(&self.ed25519).ok()?.try_into().ok()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Info,
    Bootstrap {
        root_token: String,
        name: String,
        keys: MemberKeys,
    },
    Join {
        invite: String,
        name: String,
        keys: MemberKeys,
    },
    Challenge {
        name: String,
    },
    Session {
        name: String,
        nonce: String,
        signature: String,
    },
    Members,
    MemberAdd {
        name: String,
        admin: bool,
    },
    MemberApprove {
        name: String,
        fingerprint: String,
    },
    MemberRemove {
        name: String,
    },
    Grant {
        project: String,
        access: Access,
    },
    ProjectCreate(Box<NewProject>),
    ProjectGet {
        project: String,
    },
    Commit(Box<Commit>),
    Audit {
        project: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProject {
    pub project: String,
    pub recovery: SignedRecovery,
    /// `seq = 1`, no entries, signed by the creator.
    pub head: SignedHead,
    pub wraps: Vec<SignedWrap>,
    pub index: Sealed,
    /// The creator's own access to every environment, signed by it.
    pub grant: Access,
}

/// A change to a project, applied atomically if the stored head still has `expected_seq`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Commit {
    pub project: String,
    pub expected_seq: u64,
    /// The new head, with `seq = expected_seq + 1`, signed by the caller.
    pub head: SignedHead,
    #[serde(default)]
    pub add_records: Vec<SignedRecord>,
    #[serde(default)]
    pub remove_records: Vec<RecordRef>,
    #[serde(default)]
    pub add_wraps: Vec<SignedWrap>,
    #[serde(default)]
    pub remove_wraps: Vec<WrapRef>,
    #[serde(default)]
    pub index: Option<Sealed>,
    #[serde(default)]
    pub recovery: Option<SignedRecovery>,
}

/// The public recovery key of a project, signed by the member that set it. Clients only wrap
/// keys for it when that member holds a trusted grant with write access to every environment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecovery {
    pub public: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRef {
    pub env: String,
    pub key: String,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapRef {
    pub purpose: Purpose,
    pub env: String,
    pub key_id: u32,
    pub member: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn new(status: u16, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub server_id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nonce {
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    Invited,
    Pending,
    Active,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    pub name: String,
    pub status: MemberStatus,
    pub admin: bool,
    pub keys: Option<MemberKeys>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub invite: String,
    pub expires_at: i64,
}

/// `(project, environment)` a removed member could read.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Removed {
    pub lost_access: Vec<(String, String)>,
}

/// A grant of access, signed by the member who gave it and bound to the keys of the member
/// who received it. Clients only wrap keys for grants signed by a member they pinned, so a
/// server can't add a recipient of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    pub member: String,
    pub env: String,
    pub write: bool,
    pub keys: MemberKeys,
    pub approver: String,
    pub signature: String,
}

/// What a member sees of a project: the full head and access list, its own wraps and the
/// recovery wraps, and the records of the environments it can read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectView {
    /// The creator's grant to itself, kept for good: the root of every trusted grant, even
    /// after the creator is removed.
    pub creator: Access,
    pub recovery: SignedRecovery,
    pub head: SignedHead,
    pub index: Sealed,
    pub access: Vec<Access>,
    pub wraps: Vec<SignedWrap>,
    pub records: Vec<SignedRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Done {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: i64,
    pub member: String,
    pub action: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub envs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    pub env: String,
    pub key: String,
    pub version: u32,
    pub key_id: u32,
    pub created_at: i64,
    pub nonce: String,
    pub ciphertext: String,
    pub author: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWrap {
    pub purpose: Purpose,
    pub env: String,
    pub key_id: u32,
    pub member: String,
    #[serde(default)]
    pub epk: Option<String>,
    pub nonce: String,
    pub wrapped: String,
    pub signer: String,
    pub signature: String,
}

impl SignedWrap {
    pub fn reference(&self) -> WrapRef {
        WrapRef {
            purpose: self.purpose,
            env: self.env.clone(),
            key_id: self.key_id,
            member: self.member.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HeadEntry {
    pub env: String,
    pub key: String,
    pub version: u32,
}

/// The active version of every variable of a project, signed by the last writer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    pub seq: u64,
    pub entries: Vec<HeadEntry>,
    pub signer: String,
    pub signature: String,
}

pub fn session_message(server_id: &str, name: &str, nonce: &str) -> Vec<u8> {
    encode(&[
        b"envy-session-v1",
        server_id.as_bytes(),
        name.as_bytes(),
        nonce.as_bytes(),
    ])
}

pub fn grant_message(project: &str, access: &Access) -> Vec<u8> {
    encode(&[
        b"envy-grant-v1",
        project.as_bytes(),
        access.member.as_bytes(),
        access.env.as_bytes(),
        &int(i64::from(access.write)),
        access.keys.x25519.as_bytes(),
        access.keys.ed25519.as_bytes(),
        access.approver.as_bytes(),
    ])
}

pub fn recovery_message(project: &str, recovery: &SignedRecovery) -> Vec<u8> {
    encode(&[
        b"envy-recovery-v1",
        project.as_bytes(),
        recovery.public.as_bytes(),
        recovery.signer.as_bytes(),
    ])
}

pub fn record_message(project: &str, record: &SignedRecord) -> Vec<u8> {
    encode(&[
        b"envy-record-sig-v1",
        project.as_bytes(),
        record.env.as_bytes(),
        record.key.as_bytes(),
        &int(i64::from(record.version)),
        &int(i64::from(record.key_id)),
        &int(record.created_at),
        record.nonce.as_bytes(),
        record.ciphertext.as_bytes(),
    ])
}

pub fn wrap_message(project: &str, wrap: &SignedWrap) -> Vec<u8> {
    encode(&[
        b"envy-wrap-sig-v1",
        project.as_bytes(),
        wrap.purpose.label(),
        wrap.env.as_bytes(),
        &int(i64::from(wrap.key_id)),
        wrap.member.as_bytes(),
        wrap.epk.as_deref().unwrap_or_default().as_bytes(),
        wrap.nonce.as_bytes(),
        wrap.wrapped.as_bytes(),
    ])
}

/// The entries are framed one by one after the sequence number, in their stored order
/// (sorted by environment, variable and version).
pub fn head_message(project: &str, head: &SignedHead) -> Vec<u8> {
    let seq = int(i64::try_from(head.seq).unwrap_or(i64::MAX));
    let mut fields: Vec<Vec<u8>> = vec![
        b"envy-head-v1".to_vec(),
        project.as_bytes().to_vec(),
        seq.to_vec(),
    ];
    for entry in &head.entries {
        fields.push(encode(&[
            entry.env.as_bytes(),
            entry.key.as_bytes(),
            &int(i64::from(entry.version)),
        ]));
    }
    let borrowed: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    encode(&borrowed)
}

/// Checks a signature in base64 against `keys`.
pub fn verify(keys: &PublicKeys, message: &[u8], signature: &str) -> bool {
    unb64(signature).is_ok_and(|signature| keys.verify(message, &signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(entries: &[(&str, &str, u32)]) -> SignedHead {
        SignedHead {
            seq: 3,
            entries: entries
                .iter()
                .map(|(env, key, version)| HeadEntry {
                    env: env.to_string(),
                    key: key.to_string(),
                    version: *version,
                })
                .collect(),
            ..SignedHead::default()
        }
    }

    #[test]
    fn head_messages_are_unambiguous() {
        let a = head_message("p", &head(&[("dev", "ab", 1), ("dev", "c", 1)]));
        let b = head_message("p", &head(&[("dev", "a", 1), ("dev", "bc", 1)]));
        assert_ne!(a, b);
        assert_ne!(
            a,
            head_message("q", &head(&[("dev", "ab", 1), ("dev", "c", 1)]))
        );
    }

    #[test]
    fn requests_are_tagged_by_operation() {
        let json = serde_json::to_string(&Request::Challenge { name: "ana".into() }).unwrap();
        assert_eq!(json, r#"{"op":"challenge","name":"ana"}"#);
        let parsed: Request = serde_json::from_str(r#"{"op":"members"}"#).unwrap();
        assert!(matches!(parsed, Request::Members));
    }
}
