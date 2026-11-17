//! The rules of the server. Every request is checked here, whatever transport carried it:
//! who the caller is, what they may read or write, and that every record, wrap and head they
//! send is signed with their key. Values and names stay encrypted; the core never sees a key.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Mutex,
};

use chrono::Duration;
use serde::Serialize;
use serde_json::Value;
use sha3::{Digest, Sha3_256};

use super::{ProjectState, ServerStore, StoredMember, StoredSession};
use crate::{
    clock::Clock,
    identity::PublicKeys,
    keys,
    remote::protocol::{
        ALL_ENVIRONMENTS, Access, ApiError, AuditEntry, Commit, Done, HeadEntry, Invite,
        MemberKeys, MemberStatus, MemberView, NewProject, Nonce, ProjectView, RECOVERY, Removed,
        Request, ServerInfo, SessionToken, SignedHead, SignedRecovery, SignedWrap, grant_message,
        head_message, record_message, recovery_message, session_message, verify, wrap_message,
    },
    vault::format::Purpose,
};

type Reply = Result<Value, ApiError>;

const SERVER_ID: &str = "server_id";
const ROOT_TOKEN: &str = "root_token";
/// Failed authentications allowed per client address within [`FAILURE_WINDOW`] seconds.
const MAX_FAILURES: usize = 10;
const FAILURE_WINDOW: i64 = 600;
const CHALLENGE_TTL: i64 = 120;
/// Challenges waiting for their signature. Anyone can ask for one, so they are capped.
const MAX_CHALLENGES: usize = 10_000;
const INVITE_TTL: i64 = 24 * 3600;

fn hash(text: &str) -> String {
    keys::hex(&Sha3_256::digest(text.as_bytes()))
}

fn random_token() -> String {
    keys::hex(keys::random_key().as_ref())
}

fn reply<T: Serialize>(value: T) -> Reply {
    serde_json::to_value(value).map_err(|_| internal())
}

fn done() -> Reply {
    reply(Done {})
}

fn internal() -> ApiError {
    ApiError::new(
        500,
        "internal",
        "The server could not complete the request.",
    )
}

/// Store errors go to the server's own log (stderr), never to the client: they could
/// describe the host.
fn stored<T>(result: anyhow::Result<T>) -> Result<T, ApiError> {
    result.map_err(|err| {
        eprintln!("envy serve: storage error: {err:#}");
        internal()
    })
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError::new(400, "bad_request", message)
}

fn unauthorized(message: impl Into<String>) -> ApiError {
    ApiError::new(401, "unauthorized", message)
}

fn forbidden(message: impl Into<String>) -> ApiError {
    ApiError::new(403, "forbidden", message)
}

fn not_found(message: impl Into<String>) -> ApiError {
    ApiError::new(404, "not_found", message)
}

fn conflict() -> ApiError {
    ApiError::new(
        409,
        "conflict",
        "The project changed since it was read; read it again.",
    )
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name != RECOVERY
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn decode_keys(keys: &MemberKeys) -> Result<PublicKeys, ApiError> {
    keys.decode()
        .ok_or_else(|| bad_request("The member keys are not valid."))
}

fn can_read(access: &[Access], member: &str, env: &str) -> bool {
    access
        .iter()
        .any(|a| a.member == member && (a.env == env || a.env == ALL_ENVIRONMENTS))
}

fn can_write(access: &[Access], member: &str, env: &str) -> bool {
    access
        .iter()
        .any(|a| a.member == member && a.write && (a.env == env || a.env == ALL_ENVIRONMENTS))
}

fn has_access(access: &[Access], member: &str) -> bool {
    access.iter().any(|a| a.member == member)
}

fn writes_anything(access: &[Access], member: &str) -> bool {
    access.iter().any(|a| a.member == member && a.write)
}

/// Environments whose active versions differ between two heads.
fn changed_envs(old: &SignedHead, new: &SignedHead) -> BTreeSet<String> {
    let before: BTreeSet<&HeadEntry> = old.entries.iter().collect();
    let after: BTreeSet<&HeadEntry> = new.entries.iter().collect();
    before
        .symmetric_difference(&after)
        .map(|entry| entry.env.clone())
        .collect()
}

pub struct ServerCore {
    store: Box<dyn ServerStore>,
    clock: Box<dyn Clock + Send + Sync>,
    session_ttl: Duration,
    /// `nonce -> (member name, expiry)`. Keyed by the nonce, so asking for a challenge never
    /// cancels one already handed to someone else for the same name.
    challenges: Mutex<HashMap<String, (String, i64)>>,
    failures: Mutex<HashMap<String, Vec<i64>>>,
}

impl ServerCore {
    pub fn new(
        store: Box<dyn ServerStore>,
        clock: Box<dyn Clock + Send + Sync>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            store,
            clock,
            session_ttl,
            challenges: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// The storage, for the host operator's commands.
    pub fn store(&self) -> &dyn ServerStore {
        self.store.as_ref()
    }

    fn now(&self) -> i64 {
        self.clock.now().timestamp()
    }

    /// Prepares an empty store and returns the root token, which is never stored in clear.
    pub fn init(&self) -> anyhow::Result<String> {
        if self.store.meta(SERVER_ID)?.is_some() || !self.store.members()?.is_empty() {
            anyhow::bail!("The data folder already holds an Envy server.");
        }
        self.store
            .set_meta(SERVER_ID, Some(&random_token()[..32]))?;
        self.new_root_token()
    }

    /// A root token for an existing server: it creates one more admin.
    pub fn new_root_token(&self) -> anyhow::Result<String> {
        if self.store.meta(SERVER_ID)?.is_none() {
            anyhow::bail!("The data folder holds no Envy server yet; run `envy serve --init`.");
        }
        let token = random_token();
        self.store.set_meta(ROOT_TOKEN, Some(&hash(&token)))?;
        Ok(token)
    }

    /// A request in JSON, as it arrives over HTTP. Returns the status and the JSON body.
    pub fn handle_json(&self, client: &str, token: Option<&str>, body: &[u8]) -> (u16, Vec<u8>) {
        let result = serde_json::from_slice::<Request>(body)
            .map_err(|_| bad_request("The request is not valid."))
            .and_then(|request| self.handle(client, token, request));
        let (status, value) = match result {
            Ok(value) => (200, value),
            Err(err) => (err.status, serde_json::to_value(&err).unwrap_or_default()),
        };
        (status, serde_json::to_vec(&value).unwrap_or_default())
    }

    pub fn handle(&self, client: &str, token: Option<&str>, request: Request) -> Reply {
        match request {
            Request::Info => self.info(),
            Request::Challenge { name } => self.challenge(&name),
            Request::Bootstrap {
                root_token,
                name,
                keys,
            } => self.limited(client, || self.bootstrap(&root_token, &name, &keys)),
            Request::Join { invite, name, keys } => {
                self.limited(client, || self.join(&invite, &name, &keys))
            }
            Request::Session {
                name,
                nonce,
                signature,
            } => self.limited(client, || self.session(&name, &nonce, &signature)),
            other => {
                let caller = self.caller(token)?;
                self.authenticated(&caller, other)
            }
        }
    }

    fn authenticated(&self, caller: &StoredMember, request: Request) -> Reply {
        match request {
            Request::ProjectCreate(new) => self.project_create(caller, *new),
            Request::ProjectGet { project } => self.project_get(caller, &project),
            Request::Commit(commit) => self.commit(caller, *commit),
            other => self.administration(caller, other),
        }
    }

    fn administration(&self, caller: &StoredMember, request: Request) -> Reply {
        match request {
            Request::Members => self.members(),
            Request::MemberAdd { name, admin } => self.member_add(caller, &name, admin),
            Request::MemberApprove { name, fingerprint } => {
                self.member_approve(caller, &name, &fingerprint)
            }
            Request::MemberRemove { name } => self.member_remove(caller, &name),
            Request::Grant { project, access } => self.grant(caller, &project, access),
            Request::Audit { project } => self.audit_log(caller, project.as_deref()),
            _ => Err(bad_request("Unknown operation.")),
        }
    }

    fn audit(
        &self,
        member: &str,
        action: &str,
        project: Option<&str>,
        envs: Vec<String>,
    ) -> Result<(), ApiError> {
        stored(self.store.append_audit(&AuditEntry {
            at: self.now(),
            member: member.into(),
            action: action.into(),
            project: project.map(str::to_string),
            envs,
        }))
    }

    /// Runs an authentication step, counting its failures per client address.
    fn limited(&self, client: &str, step: impl FnOnce() -> Reply) -> Reply {
        let now = self.now();
        {
            let mut failures = self.failures.lock().expect("failures lock");
            failures.retain(|_, recent| {
                recent.retain(|at| now - at < FAILURE_WINDOW);
                !recent.is_empty()
            });
            if failures
                .get(client)
                .is_some_and(|recent| recent.len() >= MAX_FAILURES)
            {
                return Err(ApiError::new(
                    429,
                    "too_many_attempts",
                    "Too many failed attempts; wait a few minutes.",
                ));
            }
        }
        let result = step();
        if result.as_ref().is_err_and(|err| err.status == 401) {
            let mut failures = self.failures.lock().expect("failures lock");
            failures.entry(client.to_string()).or_default().push(now);
        }
        result
    }

    fn server_id(&self) -> Result<String, ApiError> {
        stored(self.store.meta(SERVER_ID))?
            .ok_or_else(|| ApiError::new(503, "not_initialized", "The server is not initialised."))
    }

    fn info(&self) -> Reply {
        reply(ServerInfo {
            server_id: self.server_id()?,
            version: env!("CARGO_PKG_VERSION").into(),
            versioned_grants: true,
        })
    }

    fn caller(&self, token: Option<&str>) -> Result<StoredMember, ApiError> {
        let token = token.ok_or_else(|| unauthorized("Log in first."))?;
        let session = stored(self.store.session(&hash(token)))?
            .filter(|session| session.expires_at > self.now())
            .ok_or_else(|| unauthorized("The session expired; log in again."))?;
        let member = stored(self.store.member(&session.member))?
            .ok_or_else(|| unauthorized("The session expired; log in again."))?;
        match member.status {
            MemberStatus::Active => Ok(member),
            MemberStatus::Pending => Err(forbidden(
                "This member is waiting for an admin to approve it (`envy user approve`).",
            )),
            _ => Err(forbidden("This member was removed.")),
        }
    }

    fn require_admin(caller: &StoredMember) -> Result<(), ApiError> {
        if caller.admin {
            Ok(())
        } else {
            Err(forbidden("Only an admin can do this."))
        }
    }

    fn bootstrap(&self, root_token: &str, name: &str, keys: &MemberKeys) -> Reply {
        let expected = stored(self.store.meta(ROOT_TOKEN))?;
        if expected.as_deref() != Some(hash(root_token).as_str()) {
            return Err(unauthorized("The root token is not valid."));
        }
        if !valid_name(name) || stored(self.store.member(name))?.is_some() {
            return Err(bad_request(format!(
                "'{name}' can't be used as a member name."
            )));
        }
        decode_keys(keys)?;
        stored(self.store.put_member(&StoredMember {
            name: name.into(),
            status: MemberStatus::Active,
            admin: true,
            keys: Some(keys.clone()),
            invite_hash: None,
            invite_expires: 0,
        }))?;
        stored(self.store.set_meta(ROOT_TOKEN, None))?;
        self.audit(name, "bootstrap", None, Vec::new())?;
        done()
    }

    fn join(&self, invite: &str, name: &str, keys: &MemberKeys) -> Reply {
        let invalid = || unauthorized("The invite is not valid or expired.");
        let mut member = stored(self.store.member(name))?.ok_or_else(invalid)?;
        let matches = member.invite_hash.as_deref() == Some(hash(invite).as_str());
        if member.status != MemberStatus::Invited || !matches || member.invite_expires <= self.now()
        {
            return Err(invalid());
        }
        decode_keys(keys)?;
        member.status = MemberStatus::Pending;
        member.keys = Some(keys.clone());
        member.invite_hash = None;
        stored(self.store.put_member(&member))?;
        self.audit(name, "join", None, Vec::new())?;
        done()
    }

    fn challenge(&self, name: &str) -> Reply {
        if !valid_name(name) {
            return Err(bad_request("That is not a member name."));
        }
        let now = self.now();
        let mut challenges = self.challenges.lock().expect("challenges lock");
        challenges.retain(|_, (_, expires)| *expires > now);
        if challenges.len() >= MAX_CHALLENGES {
            return Err(ApiError::new(
                429,
                "too_many_attempts",
                "The server is busy; try again in a few minutes.",
            ));
        }
        let nonce = random_token();
        challenges.insert(nonce.clone(), (name.to_string(), now + CHALLENGE_TTL));
        reply(Nonce { nonce })
    }

    fn session(&self, name: &str, nonce: &str, signature: &str) -> Reply {
        let failed = || unauthorized("The signature is not valid; is this the right identity?");
        let issued = self
            .challenges
            .lock()
            .expect("challenges lock")
            .remove(nonce);
        let fresh =
            issued.is_some_and(|(asked_for, expires)| asked_for == name && expires > self.now());
        let member = stored(self.store.member(name))?;
        let (Some(member), true) = (member, fresh) else {
            return Err(failed());
        };
        let keys = decode_keys(member.keys.as_ref().ok_or_else(failed)?)?;
        if !verify(
            &keys,
            &session_message(&self.server_id()?, name, nonce),
            signature,
        ) {
            return Err(failed());
        }
        // Only someone holding the member's key learns that it was removed.
        if member.status == MemberStatus::Removed {
            return Err(forbidden("This member was removed from the server."));
        }
        let token = random_token();
        let expires_at = self.now() + self.session_ttl.num_seconds();
        stored(self.store.put_session(&StoredSession {
            token_hash: hash(&token),
            member: name.into(),
            expires_at,
        }))?;
        self.audit(name, "session", None, Vec::new())?;
        reply(SessionToken { token, expires_at })
    }

    fn members(&self) -> Reply {
        let members: Vec<MemberView> = stored(self.store.members())?
            .into_iter()
            .map(|m| MemberView {
                name: m.name,
                status: m.status,
                admin: m.admin,
                keys: m.keys,
            })
            .collect();
        reply(members)
    }

    fn member_add(&self, caller: &StoredMember, name: &str, admin: bool) -> Reply {
        Self::require_admin(caller)?;
        if !valid_name(name) || stored(self.store.member(name))?.is_some() {
            return Err(bad_request(format!(
                "'{name}' can't be used: names use letters, digits, '.', '_' or '-' and must be new."
            )));
        }
        let invite = random_token();
        let expires_at = self.now() + INVITE_TTL;
        stored(self.store.put_member(&StoredMember {
            name: name.into(),
            status: MemberStatus::Invited,
            admin,
            keys: None,
            invite_hash: Some(hash(&invite)),
            invite_expires: expires_at,
        }))?;
        self.audit(&caller.name, "member-add", None, vec![name.into()])?;
        reply(Invite { invite, expires_at })
    }

    fn member_approve(&self, caller: &StoredMember, name: &str, fingerprint: &str) -> Reply {
        Self::require_admin(caller)?;
        let mut member = stored(self.store.member(name))?
            .filter(|m| m.status == MemberStatus::Pending)
            .ok_or_else(|| not_found(format!("No member '{name}' is waiting for approval.")))?;
        let keys = decode_keys(member.keys.as_ref().ok_or_else(internal)?)?;
        if keys.fingerprint() != fingerprint.trim() {
            return Err(forbidden(format!(
                "The fingerprint does not match the key '{name}' registered. Do not approve it."
            )));
        }
        member.status = MemberStatus::Active;
        stored(self.store.put_member(&member))?;
        self.audit(&caller.name, "member-approve", None, vec![name.into()])?;
        done()
    }

    /// Revokes the member everywhere and drops the wraps addressed to it. The keys it could
    /// read must still be replaced, which only a client can do: the reply says where.
    fn member_remove(&self, caller: &StoredMember, name: &str) -> Reply {
        Self::require_admin(caller)?;
        let mut member = stored(self.store.member(name))?
            .filter(|m| m.status != MemberStatus::Removed)
            .ok_or_else(|| not_found(format!("There's no member called '{name}'.")))?;
        member.status = MemberStatus::Removed;
        member.invite_hash = None;
        stored(self.store.put_member(&member))?;
        stored(self.store.delete_sessions(name))?;
        let lost_access = stored(self.store.access_of(name))?
            .into_iter()
            .map(|(project, access)| (project, access.env))
            .collect();
        stored(self.store.delete_access(name))?;
        for project in stored(self.store.project_ids())? {
            self.drop_wraps_of(&project, name)?;
        }
        self.audit(&caller.name, "member-remove", None, vec![name.into()])?;
        reply(Removed { lost_access })
    }

    fn drop_wraps_of(&self, project: &str, member: &str) -> Result<(), ApiError> {
        let Some(mut state) = stored(self.store.project(project))? else {
            return Ok(());
        };
        let before = state.wraps.len();
        state.wraps.retain(|wrap| wrap.member != member);
        if state.wraps.len() != before {
            let seq = state.head.seq;
            stored(self.store.put_project(project, Some(seq), &state))?;
        }
        Ok(())
    }

    /// A grant must be signed by the caller and carry the keys the member registered, so
    /// clients can trust it without trusting the server.
    fn check_grant(
        &self,
        caller: &StoredMember,
        project: &str,
        access: &Access,
    ) -> Result<(), ApiError> {
        let member = stored(self.store.member(&access.member))?
            .filter(|m| m.status == MemberStatus::Active)
            .ok_or_else(|| not_found(format!("'{}' is not an active member.", access.member)))?;
        let signed = access.approver == caller.name
            && verify(
                &Self::keys_of(caller)?,
                &grant_message(project, access),
                &access.signature,
            );
        if access.env.is_empty() || member.keys.as_ref() != Some(&access.keys) || !signed {
            return Err(bad_request(
                "A grant must name an environment, carry the member's keys and be signed by the caller.",
            ));
        }
        Ok(())
    }

    fn grant(&self, caller: &StoredMember, project: &str, access: Access) -> Reply {
        Self::require_admin(caller)?;
        self.load(project)?;
        self.check_grant(caller, project, &access)?;
        stored(self.store.set_access(project, &access))?;
        let detail = format!(
            "{} {}{}",
            access.member,
            access.env,
            if access.write { " write" } else { "" }
        );
        self.audit(&caller.name, "grant", Some(project), vec![detail])?;
        done()
    }

    fn audit_log(&self, caller: &StoredMember, project: Option<&str>) -> Reply {
        Self::require_admin(caller)?;
        reply(stored(self.store.audit(project))?)
    }

    fn load(&self, project: &str) -> Result<ProjectState, ApiError> {
        stored(self.store.project(project))?
            .ok_or_else(|| not_found(format!("The server has no project '{project}'.")))
    }

    fn keys_of(member: &StoredMember) -> Result<PublicKeys, ApiError> {
        decode_keys(member.keys.as_ref().ok_or_else(internal)?)
    }

    fn check_head(
        caller: &StoredMember,
        keys: &PublicKeys,
        project: &str,
        head: &SignedHead,
        seq: u64,
    ) -> Result<(), ApiError> {
        if head.seq != seq || head.signer != caller.name {
            return Err(bad_request(
                "The head must be the next one, signed by the caller.",
            ));
        }
        if !verify(keys, &head_message(project, head), &head.signature) {
            return Err(bad_request("The signature of the head is not valid."));
        }
        Ok(())
    }

    /// Checks the wraps a caller adds: signed by it, for a known recipient, of keys it holds.
    fn check_wraps(
        &self,
        caller: &StoredMember,
        keys: &PublicKeys,
        project: &str,
        access: &[Access],
        wraps: &[SignedWrap],
    ) -> Result<(), ApiError> {
        for wrap in wraps {
            let signed = wrap.signer == caller.name
                && verify(keys, &wrap_message(project, wrap), &wrap.signature);
            let holds = match wrap.purpose {
                Purpose::Dek => can_read(access, &caller.name, &wrap.env),
                Purpose::Names => has_access(access, &caller.name),
            };
            // A reader may wrap keys for itself (recovery); giving a key to anyone else, or
            // replacing someone else's wrap, takes write access to it or being an admin. The
            // recovery wrap is never an admin's to replace: a bad one loses the project.
            let shares = wrap.member != caller.name
                && (!caller.admin || wrap.member == RECOVERY)
                && !match wrap.purpose {
                    Purpose::Dek => can_write(access, &caller.name, &wrap.env),
                    Purpose::Names => writes_anything(access, &caller.name),
                };
            if shares {
                return Err(forbidden(format!(
                    "'{}' can only wrap keys for itself.",
                    caller.name
                )));
            }
            let known = wrap.member == RECOVERY
                || stored(self.store.member(&wrap.member))?
                    .is_some_and(|m| m.status == MemberStatus::Active);
            if !signed || !holds || !known {
                return Err(forbidden(
                    "A wrap is not signed by the caller, or wraps a key it can't hold.",
                ));
            }
        }
        Ok(())
    }

    /// A recovery key is 32 bytes, set and signed by the caller.
    fn recovery_valid(
        caller: &StoredMember,
        keys: &PublicKeys,
        project: &str,
        recovery: &SignedRecovery,
    ) -> bool {
        let sized = crate::vault::format::unb64(&recovery.public).is_ok_and(|k| k.len() == 32);
        sized
            && recovery.signer == caller.name
            && verify(
                keys,
                &recovery_message(project, recovery),
                &recovery.signature,
            )
    }

    fn project_create(&self, caller: &StoredMember, new: NewProject) -> Reply {
        let NewProject {
            project,
            recovery,
            head,
            wraps,
            index,
            grant: creator,
        } = new;
        let project = project.as_str();
        if project.is_empty() || stored(self.store.project(project))?.is_some() {
            return Err(bad_request(format!(
                "The project '{project}' already exists."
            )));
        }
        let keys = Self::keys_of(caller)?;
        Self::check_head(caller, &keys, project, &head, 1)?;
        if !head.entries.is_empty() || !Self::recovery_valid(caller, &keys, project, &recovery) {
            return Err(bad_request(
                "A new project starts empty, with a recovery key signed by its creator.",
            ));
        }
        self.check_grant(caller, project, &creator)?;
        if creator.member != caller.name || creator.env != ALL_ENVIRONMENTS || !creator.write {
            return Err(bad_request(
                "The creator must grant itself every environment.",
            ));
        }
        self.check_wraps(
            caller,
            &keys,
            project,
            std::slice::from_ref(&creator),
            &wraps,
        )?;
        let state = ProjectState {
            creator: creator.clone(),
            recovery,
            head,
            index,
            wraps,
            records: Vec::new(),
        };
        if !stored(self.store.put_project(project, None, &state))? {
            return Err(conflict());
        }
        stored(self.store.set_access(project, &creator))?;
        self.audit(&caller.name, "project-create", Some(project), Vec::new())?;
        done()
    }

    fn project_get(&self, caller: &StoredMember, project: &str) -> Reply {
        let state = self.load(project)?;
        let access = stored(self.store.access(project))?;
        if !has_access(&access, &caller.name) && !caller.admin {
            return Err(forbidden(format!(
                "'{}' has no access to this project.",
                caller.name
            )));
        }
        let records = state
            .records
            .into_iter()
            .filter(|record| can_read(&access, &caller.name, &record.env))
            .collect::<Vec<_>>();
        let wraps = state
            .wraps
            .into_iter()
            .filter(|wrap| wrap.member == caller.name || wrap.member == RECOVERY)
            .collect();
        let envs: BTreeSet<String> = records.iter().map(|r| r.env.clone()).collect();
        self.audit(
            &caller.name,
            "read",
            Some(project),
            envs.into_iter().collect(),
        )?;
        reply(ProjectView {
            creator: state.creator,
            recovery: state.recovery,
            head: state.head,
            index: state.index,
            access,
            wraps,
            records,
        })
    }

    fn commit(&self, caller: &StoredMember, commit: Commit) -> Reply {
        let mut state = self.load(&commit.project)?;
        if state.head.seq != commit.expected_seq {
            return Err(conflict());
        }
        let keys = Self::keys_of(caller)?;
        let access = stored(self.store.access(&commit.project))?;
        Self::check_head(
            caller,
            &keys,
            &commit.project,
            &commit.head,
            commit.expected_seq + 1,
        )?;
        let touched = self.authorize(caller, &keys, &access, &state, &commit)?;
        apply(&mut state, commit.clone());
        if !consistent(&state) {
            return Err(bad_request(
                "The head points at a version that is not stored.",
            ));
        }
        if !stored(
            self.store
                .put_project(&commit.project, Some(commit.expected_seq), &state),
        )? {
            return Err(conflict());
        }
        self.audit(
            &caller.name,
            "commit",
            Some(&commit.project),
            touched.into_iter().collect(),
        )?;
        done()
    }

    /// Everything the caller changes must be within what it may write. Returns the
    /// environments it touches.
    fn authorize(
        &self,
        caller: &StoredMember,
        keys: &PublicKeys,
        access: &[Access],
        state: &ProjectState,
        commit: &Commit,
    ) -> Result<BTreeSet<String>, ApiError> {
        let mut touched = changed_envs(&state.head, &commit.head);
        touched.extend(commit.add_records.iter().map(|r| r.env.clone()));
        touched.extend(commit.remove_records.iter().map(|r| r.env.clone()));
        if let Some(env) = touched
            .iter()
            .find(|env| !can_write(access, &caller.name, env))
        {
            return Err(forbidden(format!("'{}' can't write '{env}'.", caller.name)));
        }
        for record in &commit.add_records {
            // A rekey sends a record again under the same version, removing the old one.
            let replaced = commit
                .remove_records
                .iter()
                .any(|x| x.env == record.env && x.key == record.key && x.version == record.version);
            let duplicate = !replaced
                && state.records.iter().any(|r| {
                    r.env == record.env && r.key == record.key && r.version == record.version
                });
            let signed = record.author == caller.name
                && verify(
                    keys,
                    &record_message(&commit.project, record),
                    &record.signature,
                );
            if duplicate || !signed {
                return Err(bad_request(
                    "A record is not signed by the caller or already exists.",
                ));
            }
        }
        self.check_wraps(caller, keys, &commit.project, access, &commit.add_wraps)?;
        // Removing a wrap can lose a key for good, so it takes write access, even for an admin.
        let manages = |env: &str| can_write(access, &caller.name, env);
        let removes_ok = commit.remove_wraps.iter().all(|w| match w.purpose {
            Purpose::Dek => manages(&w.env),
            Purpose::Names => manages(ALL_ENVIRONMENTS),
        });
        // Only a writer of every environment may replace the recovery key: it receives them all.
        let recovery_ok = commit.recovery.as_ref().is_none_or(|recovery| {
            can_write(access, &caller.name, ALL_ENVIRONMENTS)
                && Self::recovery_valid(caller, keys, &commit.project, recovery)
        });
        let index_ok = commit.index.is_none() || writes_anything(access, &caller.name);
        if !(removes_ok && recovery_ok && index_ok) {
            return Err(forbidden(format!(
                "'{}' can't change the keys of this project.",
                caller.name
            )));
        }
        Ok(touched)
    }
}

fn apply(state: &mut ProjectState, commit: Commit) {
    state.records.retain(|r| {
        !commit
            .remove_records
            .iter()
            .any(|x| x.env == r.env && x.key == r.key && x.version == r.version)
    });
    state.records.extend(commit.add_records);
    let replaced: Vec<_> = commit.add_wraps.iter().map(SignedWrap::reference).collect();
    state.wraps.retain(|w| {
        !commit.remove_wraps.contains(&w.reference()) && !replaced.contains(&w.reference())
    });
    state.wraps.extend(commit.add_wraps);
    if let Some(index) = commit.index {
        state.index = index;
    }
    if let Some(recovery) = commit.recovery {
        state.recovery = recovery;
    }
    state.head = commit.head;
}

/// Every active version named by the head is stored.
fn consistent(state: &ProjectState) -> bool {
    state.head.entries.iter().all(|entry| {
        state
            .records
            .iter()
            .any(|r| r.env == entry.env && r.key == entry.key && r.version == entry.version)
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::{
        identity::Identity,
        remote::protocol::{SessionToken, SignedRecord},
        server::MemoryStore,
        vault::format::{Sealed, b64},
    };

    struct ManualClock(Mutex<DateTime<Utc>>);

    impl Clock for ManualClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    struct Fixture {
        core: ServerCore,
        clock: &'static ManualClock,
        root: String,
    }

    fn fixture() -> Fixture {
        let clock: &'static ManualClock = Box::leak(Box::new(ManualClock(Mutex::new(
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        ))));
        struct Shared(&'static ManualClock);
        impl Clock for Shared {
            fn now(&self) -> DateTime<Utc> {
                self.0.now()
            }
        }
        let core = ServerCore::new(
            Box::new(MemoryStore::default()),
            Box::new(Shared(clock)),
            Duration::hours(12),
        );
        let root = core.init().unwrap();
        Fixture { core, clock, root }
    }

    impl Fixture {
        fn call(&self, token: Option<&str>, request: Request) -> Reply {
            self.core.handle("10.0.0.1", token, request)
        }

        fn advance(&self, by: Duration) {
            *self.clock.0.lock().unwrap() += by;
        }

        fn login(&self, identity: &Identity) -> String {
            let nonce: Nonce = serde_json::from_value(
                self.call(
                    None,
                    Request::Challenge {
                        name: identity.name.clone(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            let server_id = self.core.store().meta(SERVER_ID).unwrap().unwrap();
            let message = session_message(&server_id, &identity.name, &nonce.nonce);
            let session: SessionToken = serde_json::from_value(
                self.call(
                    None,
                    Request::Session {
                        name: identity.name.clone(),
                        nonce: nonce.nonce,
                        signature: b64(&identity.sign(&message)),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            session.token
        }

        /// The first admin, logged in.
        fn admin(&self) -> (Identity, String) {
            let admin = Identity::generate("admin");
            self.call(
                None,
                Request::Bootstrap {
                    root_token: self.root.clone(),
                    name: "admin".into(),
                    keys: MemberKeys::of(&admin.public()),
                },
            )
            .unwrap();
            let token = self.login(&admin);
            (admin, token)
        }

        /// An active member without access to anything.
        fn member(&self, admin_token: &str, name: &str) -> (Identity, String) {
            self.member_as(admin_token, name, false)
        }

        fn member_as(&self, admin_token: &str, name: &str, admin: bool) -> (Identity, String) {
            let invite: Invite = serde_json::from_value(
                self.call(
                    Some(admin_token),
                    Request::MemberAdd {
                        name: name.into(),
                        admin,
                    },
                )
                .unwrap(),
            )
            .unwrap();
            let identity = Identity::generate(name);
            self.call(
                None,
                Request::Join {
                    invite: invite.invite,
                    name: name.into(),
                    keys: MemberKeys::of(&identity.public()),
                },
            )
            .unwrap();
            let fingerprint = identity.public().fingerprint();
            self.call(
                Some(admin_token),
                Request::MemberApprove {
                    name: name.into(),
                    fingerprint,
                },
            )
            .unwrap();
            let token = self.login(&identity);
            (identity, token)
        }
    }

    fn head(identity: &Identity, project: &str, seq: u64, entries: Vec<HeadEntry>) -> SignedHead {
        let mut head = SignedHead {
            seq,
            entries,
            signer: identity.name.clone(),
            signature: String::new(),
        };
        head.signature = b64(&identity.sign(&head_message(project, &head)));
        head
    }

    fn record(author: &Identity, signer: &Identity, project: &str, version: u32) -> SignedRecord {
        let mut record = SignedRecord {
            env: "dev".into(),
            key: "tag".into(),
            version,
            key_id: 1,
            created_at: 0,
            nonce: "n".into(),
            ciphertext: "c".into(),
            author: author.name.clone(),
            signature: String::new(),
        };
        record.signature = b64(&signer.sign(&record_message(project, &record)));
        record
    }

    fn signed_grant(approver: &Identity, member: &Identity, env: &str, write: bool) -> Access {
        let mut access = Access {
            member: member.name.clone(),
            env: env.into(),
            write,
            keys: MemberKeys::of(&member.public()),
            approver: approver.name.clone(),
            signature: String::new(),
            version: 1,
        };
        access.signature = b64(&approver.sign(&grant_message("p", &access)));
        access
    }

    fn create(f: &Fixture, admin: &Identity, token: &str) {
        f.call(
            Some(token),
            Request::ProjectCreate(Box::new(NewProject {
                project: "p".into(),
                recovery: {
                    let mut recovery = SignedRecovery {
                        public: b64(&[7; 32]),
                        signer: admin.name.clone(),
                        signature: String::new(),
                    };
                    recovery.signature = b64(&admin.sign(&recovery_message("p", &recovery)));
                    recovery
                },
                head: head(admin, "p", 1, Vec::new()),
                wraps: Vec::new(),
                index: Sealed {
                    nonce: String::new(),
                    ciphertext: String::new(),
                },
                grant: signed_grant(admin, admin, ALL_ENVIRONMENTS, true),
            })),
        )
        .unwrap();
    }

    fn commit(writer: &Identity, expected_seq: u64, records: Vec<SignedRecord>) -> Request {
        let entries = records
            .iter()
            .map(|r| HeadEntry {
                env: r.env.clone(),
                key: r.key.clone(),
                version: r.version,
            })
            .collect();
        Request::Commit(Box::new(Commit {
            project: "p".into(),
            expected_seq,
            head: head(writer, "p", expected_seq + 1, entries),
            add_records: records,
            ..Commit::default()
        }))
    }

    fn status(reply: Reply) -> u16 {
        reply.err().map_or(200, |err| err.status)
    }

    #[test]
    fn failed_authentications_are_limited_per_address() {
        let f = fixture();
        let keys = MemberKeys::of(&Identity::generate("x").public());
        for _ in 0..MAX_FAILURES {
            let bad = Request::Bootstrap {
                root_token: "wrong".into(),
                name: "x".into(),
                keys: keys.clone(),
            };
            assert_eq!(status(f.call(None, bad)), 401);
        }
        let right = Request::Bootstrap {
            root_token: f.root.clone(),
            name: "x".into(),
            keys: keys.clone(),
        };
        assert_eq!(
            status(f.call(None, right)),
            429,
            "even the right token waits"
        );
        let other_address = f.core.handle(
            "10.0.0.2",
            None,
            Request::Bootstrap {
                root_token: f.root.clone(),
                name: "x".into(),
                keys,
            },
        );
        assert!(other_address.is_ok(), "another address is not blocked");
    }

    #[test]
    fn an_invite_works_once_and_expires() {
        let f = fixture();
        let (_, token) = f.admin();
        let invite = |name: &str| -> String {
            let reply = f.call(
                Some(&token),
                Request::MemberAdd {
                    name: name.into(),
                    admin: false,
                },
            );
            serde_json::from_value::<Invite>(reply.unwrap())
                .unwrap()
                .invite
        };
        let keys = MemberKeys::of(&Identity::generate("ana").public());
        let code = invite("ana");
        let join = |code: &str, name: &str| {
            f.call(
                None,
                Request::Join {
                    invite: code.into(),
                    name: name.into(),
                    keys: keys.clone(),
                },
            )
        };
        assert!(join(&code, "ana").is_ok());
        assert_eq!(status(join(&code, "ana")), 401, "used already");

        let late = invite("bob");
        f.advance(Duration::hours(25));
        assert_eq!(status(join(&late, "bob")), 401, "expired");
    }

    #[test]
    fn sessions_expire() {
        let f = fixture();
        let (_, token) = f.admin();
        assert!(f.call(Some(&token), Request::Members).is_ok());
        f.advance(Duration::hours(13));
        assert_eq!(status(f.call(Some(&token), Request::Members)), 401);
    }

    #[test]
    fn asking_for_a_challenge_does_not_cancel_someone_elses() {
        let f = fixture();
        let (admin, _) = f.admin();
        let nonce: Nonce = serde_json::from_value(
            f.call(
                None,
                Request::Challenge {
                    name: "admin".into(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        for _ in 0..MAX_FAILURES + 1 {
            let _ = f.core.handle(
                "10.6.6.6",
                None,
                Request::Challenge {
                    name: "admin".into(),
                },
            );
        }
        let server_id = f.core.store().meta(SERVER_ID).unwrap().unwrap();
        let signature = b64(&admin.sign(&session_message(&server_id, "admin", &nonce.nonce)));
        assert!(
            f.call(
                None,
                Request::Session {
                    name: "admin".into(),
                    nonce: nonce.nonce,
                    signature,
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn a_challenge_is_only_good_for_the_name_it_was_asked_for() {
        let f = fixture();
        let (admin, token) = f.admin();
        f.member(&token, "ana");
        let nonce: Nonce = serde_json::from_value(
            f.call(None, Request::Challenge { name: "ana".into() })
                .unwrap(),
        )
        .unwrap();
        let server_id = f.core.store().meta(SERVER_ID).unwrap().unwrap();
        let signature = b64(&admin.sign(&session_message(&server_id, "admin", &nonce.nonce)));
        let reply = f.call(
            None,
            Request::Session {
                name: "admin".into(),
                nonce: nonce.nonce,
                signature,
            },
        );
        assert_eq!(status(reply), 401);
    }

    #[test]
    fn challenges_are_bounded() {
        let f = fixture();
        assert_eq!(
            status(f.call(
                None,
                Request::Challenge {
                    name: "x".repeat(1000)
                }
            )),
            400,
            "not a member name"
        );
        for i in 0..MAX_CHALLENGES {
            f.call(
                None,
                Request::Challenge {
                    name: format!("m{i}"),
                },
            )
            .unwrap();
        }
        assert_eq!(
            status(f.call(
                None,
                Request::Challenge {
                    name: "late".into()
                }
            )),
            429
        );
        f.advance(Duration::seconds(CHALLENGE_TTL + 1));
        assert!(
            f.call(
                None,
                Request::Challenge {
                    name: "late".into()
                }
            )
            .is_ok(),
            "expired challenges make room"
        );
    }

    #[test]
    fn commits_need_the_current_head_write_access_and_the_writer_signature() {
        let f = fixture();
        let (admin, token) = f.admin();
        create(&f, &admin, &token);

        assert_eq!(
            status(f.call(
                Some(&token),
                commit(&admin, 5, vec![record(&admin, &admin, "p", 1)])
            )),
            409
        );

        let (ana, ana_token) = f.member(&token, "ana");
        let forged = record(&admin, &ana, "p", 1);
        assert_eq!(
            status(f.call(Some(&token), commit(&admin, 1, vec![forged]))),
            400,
            "signed by someone else"
        );

        let by_ana = commit(&ana, 1, vec![record(&ana, &ana, "p", 1)]);
        assert_eq!(
            status(f.call(Some(&ana_token), by_ana)),
            403,
            "no write access"
        );

        assert!(
            f.call(
                Some(&token),
                commit(&admin, 1, vec![record(&admin, &admin, "p", 1)])
            )
            .is_ok()
        );
        let replay = commit(&admin, 2, vec![record(&admin, &admin, "p", 1)]);
        assert_eq!(
            status(f.call(Some(&token), replay)),
            400,
            "a version can't be stored twice"
        );
    }

    #[test]
    fn readers_only_get_their_environments() {
        let f = fixture();
        let (admin, token) = f.admin();
        create(&f, &admin, &token);
        f.call(
            Some(&token),
            commit(&admin, 1, vec![record(&admin, &admin, "p", 1)]),
        )
        .unwrap();
        let (ana, ana_token) = f.member(&token, "ana");
        assert_eq!(
            status(f.call(
                Some(&ana_token),
                Request::ProjectGet {
                    project: "p".into()
                }
            )),
            403
        );

        let grant = Request::Grant {
            project: "p".into(),
            access: signed_grant(&admin, &ana, "prod", false),
        };
        f.call(Some(&token), grant).unwrap();
        let view: ProjectView = serde_json::from_value(
            f.call(
                Some(&ana_token),
                Request::ProjectGet {
                    project: "p".into(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            view.records.is_empty(),
            "dev records are not sent to a prod reader"
        );
        assert_eq!(
            view.head.entries.len(),
            1,
            "the head is metadata, sent whole"
        );
    }

    fn wrap(signer: &Identity, project: &str, member: &str) -> SignedWrap {
        let mut wrap = SignedWrap {
            purpose: Purpose::Dek,
            env: "dev".into(),
            key_id: 1,
            member: member.into(),
            epk: Some(b64(&[1; 32])),
            nonce: "n".into(),
            wrapped: "w".into(),
            signer: signer.name.clone(),
            signature: String::new(),
        };
        wrap.signature = b64(&signer.sign(&wrap_message(project, &wrap)));
        wrap
    }

    #[test]
    fn a_reader_can_only_wrap_keys_for_itself() {
        let f = fixture();
        let (admin, token) = f.admin();
        create(&f, &admin, &token);
        let (ana, ana_token) = f.member(&token, "ana");
        let grant = Request::Grant {
            project: "p".into(),
            access: signed_grant(&admin, &ana, "dev", false),
        };
        f.call(Some(&token), grant).unwrap();
        let with_wrap = |member: &str| {
            Request::Commit(Box::new(Commit {
                project: "p".into(),
                expected_seq: 1,
                head: head(&ana, "p", 2, Vec::new()),
                add_wraps: vec![wrap(&ana, "p", member)],
                ..Commit::default()
            }))
        };
        assert_eq!(status(f.call(Some(&ana_token), with_wrap("admin"))), 403);
        assert_eq!(status(f.call(Some(&ana_token), with_wrap(RECOVERY))), 403);
        assert!(f.call(Some(&ana_token), with_wrap("ana")).is_ok());
    }

    #[test]
    fn an_admin_cannot_strip_the_keys_of_environments_it_does_not_write() {
        let f = fixture();
        let (admin, token) = f.admin();
        create(&f, &admin, &token);
        let mut first = commit(&admin, 1, vec![record(&admin, &admin, "p", 1)]);
        if let Request::Commit(commit) = &mut first {
            commit.add_wraps = vec![wrap(&admin, "p", "admin"), wrap(&admin, "p", RECOVERY)];
        }
        f.call(Some(&token), first).unwrap();

        let (bob, bob_token) = f.member_as(&token, "bob", true);
        let strip = |member: &str| {
            Request::Commit(Box::new(Commit {
                project: "p".into(),
                expected_seq: 2,
                head: head(
                    &bob,
                    "p",
                    3,
                    vec![HeadEntry {
                        env: "dev".into(),
                        key: "tag".into(),
                        version: 1,
                    }],
                ),
                remove_wraps: vec![wrap(&admin, "p", member).reference()],
                ..Commit::default()
            }))
        };
        assert_eq!(status(f.call(Some(&bob_token), strip("admin"))), 403);
        assert_eq!(status(f.call(Some(&bob_token), strip(RECOVERY))), 403);

        // A reading admin still gives keys to members (`envy user approve`), but can't
        // replace the recovery wrap, which the whole project depends on.
        let grant = Request::Grant {
            project: "p".into(),
            access: signed_grant(&admin, &bob, "dev", false),
        };
        f.call(Some(&token), grant).unwrap();
        let replace = |member: &str| {
            Request::Commit(Box::new(Commit {
                project: "p".into(),
                expected_seq: 2,
                head: head(
                    &bob,
                    "p",
                    3,
                    vec![HeadEntry {
                        env: "dev".into(),
                        key: "tag".into(),
                        version: 1,
                    }],
                ),
                add_wraps: vec![wrap(&bob, "p", member)],
                ..Commit::default()
            }))
        };
        assert_eq!(status(f.call(Some(&bob_token), replace(RECOVERY))), 403);
        assert!(f.call(Some(&bob_token), replace("bob")).is_ok());
    }

    #[test]
    fn only_admins_manage_members() {
        let f = fixture();
        let (_, token) = f.admin();
        let (_, ana_token) = f.member(&token, "ana");
        let add = Request::MemberAdd {
            name: "bob".into(),
            admin: false,
        };
        assert_eq!(status(f.call(Some(&ana_token), add)), 403);
        assert_eq!(
            status(f.call(Some(&ana_token), Request::Audit { project: None })),
            403
        );
        let bad_name = Request::MemberAdd {
            name: "recovery".into(),
            admin: false,
        };
        assert_eq!(status(f.call(Some(&token), bad_name)), 400);
    }
}
