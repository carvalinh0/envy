//! [`RemoteVault`]: the values of a project on an Envy server (ADR 0002).
//!
//! The server only ever receives ciphertext. Everything it returns is checked before use:
//! records, wraps and heads must carry valid signatures of members whose keys this machine
//! pinned the first time it saw them, and a head older than one already seen is refused.
//! Writes are commits against the head that was read; a concurrent write makes the server
//! answer `409`, and the commit is rebuilt once on fresh data.

use std::{
    cell::{RefCell, RefMut},
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::PathBuf,
    rc::Rc,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::DateTime;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use x25519_dalek::PublicKey;

use super::{
    protocol::{
        ALL_ENVIRONMENTS, Access, ApiError, AuditEntry, Commit, Done, HeadEntry, Invite,
        MemberKeys, MemberStatus, MemberView, NewProject, Nonce, ProjectView, RECOVERY, RecordRef,
        Removed, Request, ServerInfo, SessionToken, SignedHead, SignedRecord, SignedRecovery,
        SignedWrap, WrapRef, grant_message, head_message, record_message, recovery_message,
        session_message, verify, wrap_message,
    },
    transport::Transport,
};
use crate::{
    backends::BackendStore,
    identity::{self, Identity, PublicKeys},
    keys::{self, Key32},
    schema::Secret,
    vault::{
        Change, CredentialStore, SecretVault, Version,
        format::{
            KeySlot, Purpose, RecordId, Sealed, b64, index_aad, names_slot, open_from, record_aad,
            seal_to, unb64, wrap_aad,
        },
    },
};

/// Opens a transport to a server URL.
pub type Connect<'a> = Box<dyn Fn(&str) -> Result<Box<dyn Transport>> + 'a>;

/// Whether `err` is a refusal of the server with this status.
pub fn is_status(err: &anyhow::Error, status: u16) -> bool {
    err.downcast_ref::<ApiError>()
        .is_some_and(|api| api.status == status)
}

fn anonymous<T: DeserializeOwned>(transport: &dyn Transport, request: &Request) -> Result<T> {
    Ok(serde_json::from_value(transport.call(None, request)?)?)
}

/// A connection to one server with a member identity; the session token is obtained on the
/// first authenticated call by signing a challenge.
pub struct Session {
    transport: Box<dyn Transport>,
    pub url: String,
    pub identity: Identity,
    server_id: String,
    token: RefCell<Option<String>>,
}

impl Session {
    fn token(&self) -> Result<String> {
        if let Some(token) = self.token.borrow().as_ref() {
            return Ok(token.clone());
        }
        let name = self.identity.name.clone();
        let challenge: Nonce =
            anonymous(&*self.transport, &Request::Challenge { name: name.clone() })?;
        let message = session_message(&self.server_id, &name, &challenge.nonce);
        let session: SessionToken = anonymous(
            &*self.transport,
            &Request::Session {
                name,
                nonce: challenge.nonce,
                signature: b64(&self.identity.sign(&message)),
            },
        )?;
        *self.token.borrow_mut() = Some(session.token.clone());
        Ok(session.token)
    }

    pub fn call<T: DeserializeOwned>(&self, request: &Request) -> Result<T> {
        let token = self.token()?;
        Ok(serde_json::from_value(
            self.transport.call(Some(&token), request)?,
        )?)
    }

    fn sign(&self, message: &[u8]) -> String {
        b64(&self.identity.sign(message))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ServerPins {
    server_id: String,
    #[serde(default)]
    members: BTreeMap<String, MemberKeys>,
    #[serde(default)]
    heads: BTreeMap<String, u64>,
    /// Members this machine saw removed. They never receive a key again, even if the server
    /// later presents them as active with an old grant.
    #[serde(default)]
    removed: BTreeSet<String>,
    /// The creator of each project, the root of the grants this machine trusts.
    #[serde(default)]
    creators: BTreeMap<String, String>,
    /// Every recovery key seen per project, the current one last. An earlier one is never
    /// accepted again.
    #[serde(default)]
    recoveries: BTreeMap<String, Vec<String>>,
}

/// What this machine learnt about each server: its id, the keys of its members and the
/// highest head of each project. Kept in the data folder; without one, only for this run.
struct Pins {
    path: Option<PathBuf>,
    memory: RefCell<BTreeMap<String, ServerPins>>,
}

impl Pins {
    fn load(&self) -> Result<BTreeMap<String, ServerPins>> {
        let Some(path) = self.path.as_ref().filter(|path| path.is_file()) else {
            return Ok(std::mem::take(&mut *self.memory.borrow_mut()));
        };
        let content = fs::read_to_string(path)
            .with_context(|| format!("Could not read {}", path.display()))?;
        serde_json::from_str(&content).with_context(|| format!("{} is corrupted", path.display()))
    }

    fn update<T>(&self, url: &str, change: impl FnOnce(&mut ServerPins) -> Result<T>) -> Result<T> {
        let mut all = self.load()?;
        let result = change(all.entry(url.to_string()).or_default())?;
        match &self.path {
            Some(path) => {
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir)
                        .with_context(|| format!("Could not create {}", dir.display()))?;
                }
                fs::write(path, serde_json::to_string_pretty(&all)?)
                    .with_context(|| format!("Could not write {}", path.display()))?;
            }
            None => *self.memory.borrow_mut() = all,
        }
        Ok(result)
    }
}

/// The members of a server as this machine trusts them.
struct Roster {
    views: Vec<MemberView>,
    /// Pinned keys of every member that has keys.
    keys: BTreeMap<String, PublicKeys>,
    /// Members this machine ever saw removed.
    removed: BTreeSet<String>,
}

/// A project as read from the server and checked, with the keys this member could open.
struct Opened {
    session: Rc<Session>,
    project: String,
    view: ProjectView,
    members: BTreeMap<String, PublicKeys>,
    removed: BTreeSet<String>,
    creator: String,
    keys: BTreeMap<KeySlot, Key32>,
    names: BTreeMap<String, String>,
}

impl Opened {
    fn me(&self) -> &str {
        &self.session.identity.name
    }

    fn names_key(&self) -> Result<&Key32> {
        self.keys.get(&names_slot()).ok_or_else(|| {
            anyhow!(
                "'{}' has no keys of this project yet: an admin must run `envy user approve {}`.",
                self.me(),
                self.me()
            )
        })
    }

    fn tag(&self, env: &str, key: &str) -> Result<String> {
        Ok(keys::name_tag(self.names_key()?, env, key))
    }

    fn versions<'r>(
        &'r self,
        env: &'r str,
        tag: &'r str,
    ) -> impl Iterator<Item = &'r SignedRecord> {
        self.view
            .records
            .iter()
            .filter(move |r| r.env == env && r.key == tag)
    }

    fn active_version(&self, env: &str, tag: &str) -> Option<u32> {
        self.view
            .head
            .entries
            .iter()
            .find(|e| e.env == env && e.key == tag)
            .map(|e| e.version)
    }

    fn current_key_id(&self, env: &str) -> Option<u32> {
        self.keys
            .keys()
            .filter(|(purpose, e, _)| *purpose == Purpose::Dek && e == env)
            .map(|(_, _, id)| *id)
            .max()
    }

    fn decrypt(&self, record: &SignedRecord) -> Result<Secret> {
        let dek = self
            .keys
            .get(&(Purpose::Dek, record.env.clone(), record.key_id))
            .ok_or_else(|| anyhow!("'{}' has no key for '{}'.", self.me(), record.env))?;
        let aad = record_aad(&self.project, &record_id(record));
        let sealed = Sealed {
            nonce: record.nonce.clone(),
            ciphertext: record.ciphertext.clone(),
        };
        open_from(dek, &aad, &sealed)
            .and_then(|padded| keys::unpad(&padded))
            .ok_or_else(|| anyhow!("A value of '{}' on the server does not open.", record.env))
    }

    /// A grant is genuine when its approver signed it with the pinned key and it is bound to
    /// the grantee's pinned keys.
    fn genuine(&self, access: &Access) -> Option<PublicKeys> {
        let keys = access.keys.decode()?;
        let signed = self.members.get(&access.approver).is_some_and(|approver| {
            verify(
                approver,
                &grant_message(&self.project, access),
                &access.signature,
            )
        });
        let matches_pin = self
            .members
            .get(&access.member)
            .is_none_or(|pinned| *pinned == keys);
        (signed && matches_pin && !self.removed.contains(&access.member)).then_some(keys)
    }

    /// The grants this machine trusts: the creator's grant to itself, then, until nothing
    /// changes, grants signed by a member that already holds a trusted grant with write
    /// access to the same environment. A member the server adds can't enter this chain: it
    /// can't sign as anyone in it.
    fn trusted_grants(&self) -> Vec<(&Access, PublicKeys)> {
        let mut trusted: Vec<(&Access, PublicKeys)> = Vec::new();
        loop {
            let before = trusted.len();
            for access in &self.view.access {
                if trusted.iter().any(|(t, _)| std::ptr::eq(*t, access)) {
                    continue;
                }
                // Anything the creator signed is trusted, even after the creator left: a removed
                // member can't log in to sign anything new.
                let root = access.approver == self.creator;
                let delegated = trusted.iter().any(|(t, _)| {
                    t.member == access.approver
                        && t.write
                        && (t.env == ALL_ENVIRONMENTS || t.env == access.env)
                });
                if let Some(keys) = self.genuine(access).filter(|_| root || delegated) {
                    trusted.push((access, keys));
                }
            }
            if trusted.len() == before {
                return trusted;
            }
        }
    }

    /// Who may receive the key of `env`: this member and the holders of trusted grants for
    /// it. The access list comes from the server, so nothing unsigned decides where a key goes.
    fn readers(&self, env: &str) -> Vec<(String, PublicKey)> {
        let mut readers = vec![(
            self.me().to_string(),
            self.session.identity.public().x25519_key(),
        )];
        for (access, keys) in self.trusted_grants() {
            let relevant = access.env == env || access.env == ALL_ENVIRONMENTS;
            if relevant && !readers.iter().any(|(name, _)| *name == access.member) {
                readers.push((access.member.clone(), keys.x25519_key()));
            }
        }
        readers
    }

    /// The project's recovery key, checked when the project was read.
    fn recovery(&self) -> Result<PublicKey> {
        let bytes: [u8; 32] = unb64(&self.view.recovery.public)?
            .try_into()
            .map_err(|_| anyhow!("The recovery key of this project is not valid."))?;
        Ok(PublicKey::from(bytes))
    }

    fn signed_recovery(&self, public: &PublicKey) -> SignedRecovery {
        let mut recovery = SignedRecovery {
            public: b64(public.as_bytes()),
            signer: self.me().to_string(),
            signature: String::new(),
        };
        recovery.signature = self
            .session
            .sign(&recovery_message(&self.project, &recovery));
        recovery
    }

    /// Whether the recovery key was set by a member trusted with every environment.
    fn recovery_trusted(&self) -> bool {
        let recovery = &self.view.recovery;
        let writer = recovery.signer == self.creator
            || self.trusted_grants().iter().any(|(access, _)| {
                access.member == recovery.signer && access.write && access.env == ALL_ENVIRONMENTS
            });
        let signed = self.members.get(&recovery.signer).is_some_and(|keys| {
            verify(
                keys,
                &recovery_message(&self.project, recovery),
                &recovery.signature,
            )
        });
        writer && signed
    }

    /// A wrap for the recovery key or for this member itself.
    fn wrap(&self, slot: &KeySlot, key: &Key32, member: &str) -> Result<SignedWrap> {
        let recipient = match member {
            RECOVERY => self.recovery()?,
            me if me == self.me() => self.session.identity.public().x25519_key(),
            other => bail!("The keys of '{other}' must come from a verified grant."),
        };
        self.wrap_for(slot, key, member, &recipient)
    }

    fn wrap_for(
        &self,
        slot: &KeySlot,
        key: &Key32,
        member: &str,
        recipient: &PublicKey,
    ) -> Result<SignedWrap> {
        let (epk, nonce, wrapped) =
            keys::x25519_wrap(recipient, &wrap_aad(&self.project, slot, member), key)?;
        let mut wrap = SignedWrap {
            purpose: slot.0,
            env: slot.1.clone(),
            key_id: slot.2,
            member: member.to_string(),
            epk: Some(b64(&epk)),
            nonce: b64(&nonce),
            wrapped: b64(&wrapped),
            signer: self.me().to_string(),
            signature: String::new(),
        };
        wrap.signature = self.session.sign(&wrap_message(&self.project, &wrap));
        Ok(wrap)
    }

    /// Wraps for every member that can read `env`, and for the recovery key.
    fn wraps_for_env(&self, slot: &KeySlot, key: &Key32, env: &str) -> Result<Vec<SignedWrap>> {
        let mut wraps = Vec::new();
        for (member, recipient) in self.readers(env) {
            wraps.push(self.wrap_for(slot, key, &member, &recipient)?);
        }
        wraps.push(self.wrap(slot, key, RECOVERY)?);
        Ok(wraps)
    }

    fn encrypt(&self, id: &RecordId, dek: &Key32, value: &Secret) -> Result<SignedRecord> {
        let sealed = seal_to(dek, &record_aad(&self.project, id), &keys::pad(value))?;
        let mut record = SignedRecord {
            env: id.env.to_string(),
            key: id.key.to_string(),
            version: id.version,
            key_id: id.key_id,
            created_at: id.created_at,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            author: self.me().to_string(),
            signature: String::new(),
        };
        record.signature = self.session.sign(&record_message(&self.project, &record));
        Ok(record)
    }

    fn head(&self, mut entries: Vec<HeadEntry>) -> SignedHead {
        entries.sort();
        let mut head = SignedHead {
            seq: self.view.head.seq + 1,
            entries,
            signer: self.me().to_string(),
            signature: String::new(),
        };
        head.signature = self.session.sign(&head_message(&self.project, &head));
        head
    }

    fn sealed_index(&self, names: &BTreeMap<String, String>) -> Result<Sealed> {
        seal_to(
            self.names_key()?,
            &index_aad(&self.project),
            &serde_json::to_vec(names)?,
        )
    }

    fn commit(&self) -> Commit {
        Commit {
            project: self.project.clone(),
            expected_seq: self.view.head.seq,
            head: self.head(self.view.head.entries.clone()),
            ..Commit::default()
        }
    }
}

/// The creator of `project`: pinned the first time this machine saw it (the member that
/// granted itself every environment), so a server can't later name another one.
fn creator_of(
    pins: &mut ServerPins,
    project: &str,
    view: &ProjectView,
    members: &BTreeMap<String, PublicKeys>,
) -> Result<String> {
    if let Some(creator) = pins.creators.get(project) {
        return Ok(creator.clone());
    }
    let grant = &view.creator;
    let self_signed = grant.member == grant.approver
        && grant.env == ALL_ENVIRONMENTS
        && grant.write
        && members.get(&grant.member).is_some_and(|keys| {
            grant.keys.decode() == Some(*keys)
                && verify(keys, &grant_message(project, grant), &grant.signature)
        });
    if !self_signed {
        bail!("The server does not show who created '{project}'. Nothing was used.");
    }
    pins.creators
        .insert(project.to_string(), grant.member.clone());
    Ok(grant.member.clone())
}

/// A grant of `env` to `member`, signed by the session's member and bound to the keys given.
fn grant(
    session: &Session,
    project: &str,
    (member, keys): (&str, &PublicKeys),
    env: &str,
    write: bool,
) -> Access {
    let mut access = Access {
        member: member.to_string(),
        env: env.to_string(),
        write,
        keys: MemberKeys::of(keys),
        approver: session.identity.name.clone(),
        signature: String::new(),
    };
    access.signature = session.sign(&grant_message(project, &access));
    access
}

fn record_id(record: &SignedRecord) -> RecordId<'_> {
    RecordId {
        env: &record.env,
        key: &record.key,
        version: record.version,
        key_id: record.key_id,
        created_at: record.created_at,
    }
}

fn signed_by(
    members: &BTreeMap<String, PublicKeys>,
    signer: &str,
    message: &[u8],
    signature: &str,
) -> bool {
    members
        .get(signer)
        .is_some_and(|keys| verify(keys, message, signature))
}

/// Checks every signature of a project against pinned keys.
fn check_view(
    project: &str,
    view: &ProjectView,
    members: &BTreeMap<String, PublicKeys>,
) -> Result<()> {
    let head = &view.head;
    if !signed_by(
        members,
        &head.signer,
        &head_message(project, head),
        &head.signature,
    ) {
        bail!("The server sent a head of '{project}' that no member signed. Nothing was used.");
    }
    if let Some(record) = view.records.iter().find(|r| {
        !signed_by(
            members,
            &r.author,
            &record_message(project, r),
            &r.signature,
        )
    }) {
        bail!(
            "The server sent a value of '{}' that no member signed. Nothing was used.",
            record.env
        );
    }
    if view
        .wraps
        .iter()
        .any(|w| !signed_by(members, &w.signer, &wrap_message(project, w), &w.signature))
    {
        bail!("The server sent a key of '{project}' that no member signed. Nothing was used.");
    }
    Ok(())
}

/// Keys of `slot` this member can open: its own wraps, or the recovery wraps with `secret`.
fn unwrap_for(
    project: &str,
    wraps: &[SignedWrap],
    member: &str,
    secret: &x25519_dalek::StaticSecret,
) -> Result<BTreeMap<KeySlot, Key32>> {
    let mut keys = BTreeMap::new();
    for wrap in wraps.iter().filter(|w| w.member == member) {
        let slot = (wrap.purpose, wrap.env.clone(), wrap.key_id);
        let aad = wrap_aad(project, &slot, member);
        let key = (|| {
            let epk = unb64(wrap.epk.as_deref()?).ok()?;
            let nonce = unb64(&wrap.nonce).ok()?;
            let wrapped = unb64(&wrap.wrapped).ok()?;
            keys::x25519_unwrap(secret, &epk, &aad, &nonce, &wrapped)
        })()
        .ok_or_else(|| anyhow!("A key of '{project}' addressed to '{member}' does not open."))?;
        keys.insert(slot, key);
    }
    Ok(keys)
}

pub struct RemoteVault<'a> {
    choices: &'a dyn BackendStore,
    /// `ENVY_SERVER`, for machines with no `envy login` (CI).
    default_url: Option<String>,
    identities: &'a dyn CredentialStore,
    /// `ENVY_IDENTITY`.
    preset_identity: Option<&'a Secret>,
    connect: Connect<'a>,
    pins: Pins,
    sessions: RefCell<HashMap<String, Rc<Session>>>,
    opened: RefCell<HashMap<String, Opened>>,
}

impl<'a> RemoteVault<'a> {
    pub fn new(
        choices: &'a dyn BackendStore,
        default_url: Option<String>,
        identities: &'a dyn CredentialStore,
        preset_identity: Option<&'a Secret>,
        data_dir: Option<PathBuf>,
        connect: Connect<'a>,
    ) -> Self {
        Self {
            choices,
            default_url,
            identities,
            preset_identity,
            connect,
            pins: Pins {
                path: data_dir.map(|dir| dir.join("remote").join("pins.json")),
                memory: RefCell::new(BTreeMap::new()),
            },
            sessions: RefCell::new(HashMap::new()),
            opened: RefCell::new(HashMap::new()),
        }
    }

    /// The server of `project`: chosen with `envy login`, else `ENVY_SERVER`.
    pub fn url(&self, project: &str) -> Result<String> {
        if let Some(url) = self.choices.remote_url(project)? {
            return Ok(url);
        }
        self.default_url.clone().ok_or_else(|| {
            anyhow!("This project has no Envy server on this machine. Run `envy login <url>`.")
        })
    }

    pub fn connect(&self, url: &str) -> Result<Box<dyn Transport>> {
        (self.connect)(url)
    }

    /// The id of the server at `url`, checked against the one pinned for that URL.
    pub fn server_id(&self, transport: &dyn Transport, url: &str) -> Result<String> {
        let info: ServerInfo = anonymous(transport, &Request::Info)?;
        self.pins.update(url, |pins| {
            if pins.server_id.is_empty() {
                pins.server_id = info.server_id.clone();
            } else if pins.server_id != info.server_id {
                bail!("{url} is not the Envy server this machine knew (its id changed). Nothing was sent.");
            }
            Ok(info.server_id)
        })
    }

    fn session(&self, url: &str) -> Result<Rc<Session>> {
        if let Some(session) = self.sessions.borrow().get(url) {
            return Ok(session.clone());
        }
        let identity = identity::load(self.identities, url, self.preset_identity)?.ok_or_else(|| {
            anyhow!("This machine has no identity for {url}. Run `envy login {url} --invite <code>`.")
        })?;
        let transport = self.connect(url)?;
        let server_id = self.server_id(&*transport, url)?;
        let session = Rc::new(Session {
            transport,
            url: url.to_string(),
            identity,
            server_id,
            token: RefCell::new(None),
        });
        self.sessions
            .borrow_mut()
            .insert(url.to_string(), session.clone());
        Ok(session)
    }

    pub fn session_for(&self, project: &str) -> Result<Rc<Session>> {
        self.session(&self.url(project)?)
    }

    /// The members of the server, with their keys pinned on first sight.
    fn pinned_members(&self, session: &Session) -> Result<Roster> {
        let members: Vec<MemberView> = session.call(&Request::Members)?;
        let (keys, removed) = self.pins.update(&session.url, |pins| {
            let mut keys = BTreeMap::new();
            for member in &members {
                if member.status == MemberStatus::Removed {
                    pins.removed.insert(member.name.clone());
                }
                let Some(current) = &member.keys else { continue };
                let pinned = pins.members.entry(member.name.clone()).or_insert_with(|| current.clone());
                if pinned != current {
                    bail!(
                        "The key of '{}' changed on the server. If that is expected, remove it from the pins in the data folder; otherwise do not trust this server.",
                        member.name
                    );
                }
                keys.insert(member.name.clone(), current.decode().ok_or_else(|| anyhow!("Invalid keys of '{}'.", member.name))?);
            }
            Ok((keys, pins.removed.clone()))
        })?;
        Ok(Roster {
            views: members,
            keys,
            removed,
        })
    }

    fn open(&self, project: &str) -> Result<RefMut<'_, Opened>> {
        if !self.opened.borrow().contains_key(project) {
            let opened = self.fetch(project)?;
            self.opened.borrow_mut().insert(project.to_string(), opened);
        }
        Ok(RefMut::map(self.opened.borrow_mut(), |all| {
            all.get_mut(project).expect("inserted above")
        }))
    }

    fn fetch(&self, project: &str) -> Result<Opened> {
        let session = self.session_for(project)?;
        let roster = self.pinned_members(&session)?;
        let view: ProjectView = session.call(&Request::ProjectGet {
            project: project.to_string(),
        })?;
        check_view(project, &view, &roster.keys)?;
        let creator = self.pins.update(&session.url, |pins| {
            let seen = pins.heads.entry(project.to_string()).or_insert(0);
            if view.head.seq < *seen {
                bail!(
                    "The server sent an older state of '{project}' than this machine saw (head {} < {}). Nothing was used.",
                    view.head.seq,
                    seen
                );
            }
            *seen = view.head.seq;
            creator_of(pins, project, &view, &roster.keys)
        })?;
        let keys = unwrap_for(
            project,
            &view.wraps,
            &session.identity.name,
            &session.identity.x25519(),
        )?;
        let names = match keys.get(&names_slot()) {
            Some(names_key) => open_from(names_key, &index_aad(project), &view.index)
                .and_then(|index| serde_json::from_slice(&index).ok())
                .ok_or_else(|| anyhow!("The name index of '{project}' does not open."))?,
            None => BTreeMap::new(),
        };
        let opened = Opened {
            session,
            project: project.to_string(),
            view,
            members: roster.keys,
            removed: roster.removed,
            creator,
            keys,
            names,
        };
        self.check_recovery(&opened)?;
        Ok(opened)
    }

    /// The recovery key receives every key of the project, so it must be one this machine
    /// already accepted, or a new one set by a trusted writer of every environment; a key
    /// replaced earlier never comes back.
    fn check_recovery(&self, opened: &Opened) -> Result<()> {
        let project = &opened.project;
        let current = opened.view.recovery.public.clone();
        let trusted = opened.recovery_trusted();
        self.pins.update(&opened.session.url, |pins| {
            let seen = pins.recoveries.entry(project.clone()).or_default();
            if seen.last() == Some(&current) {
                return Ok(());
            }
            if seen.contains(&current) {
                bail!("The server went back to an earlier recovery key of '{project}'. Nothing was used.");
            }
            if !trusted {
                bail!(
                    "The recovery key of '{project}' was not set by a member trusted with every environment. Nothing was used."
                );
            }
            seen.push(current);
            Ok(())
        })
    }

    fn forget(&self, project: &str) {
        self.opened.borrow_mut().remove(project);
    }

    /// Builds a commit on the latest state and sends it; on a conflict, reads again and
    /// rebuilds it once.
    fn write(
        &self,
        project: &str,
        build: impl Fn(&Opened) -> Result<Option<Commit>>,
    ) -> Result<()> {
        for attempt in 0..2 {
            let (session, commit) = {
                let opened = self.open(project)?;
                (opened.session.clone(), build(&opened)?)
            };
            let Some(commit) = commit else {
                return Ok(());
            };
            let seq = commit.head.seq;
            let result = session.call::<Done>(&Request::Commit(Box::new(commit)));
            self.forget(project);
            match result {
                Ok(_) => {
                    return self.pins.update(&session.url, |pins| {
                        pins.heads.insert(project.to_string(), seq);
                        Ok(())
                    });
                }
                Err(err) if attempt == 0 && is_status(&err, 409) => continue,
                Err(err) => return Err(err),
            }
        }
        bail!("The project kept changing on the server; try again.")
    }

    /// Whether the server has `project`. Any other refusal (a member still pending, no access
    /// to the project) is an error, so nothing switches to a server it can't use.
    pub fn project_exists(&self, project: &str) -> Result<bool> {
        let session = self.session_for(project)?;
        match session.call::<ProjectView>(&Request::ProjectGet {
            project: project.to_string(),
        }) {
            Ok(_) => Ok(true),
            Err(err) if is_status(&err, 404) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Creates `project` on the server with a new name key, wrapped for the caller and for
    /// the recovery key.
    pub fn create_project(&self, project: &str, recovery: &[u8; 32]) -> Result<()> {
        let session = self.session_for(project)?;
        let roster = self.pinned_members(&session)?;
        let recovery_public = PublicKey::from(&keys::recovery_secret(recovery));
        let me = session.identity.public();
        let creator_grant = grant(
            &session,
            project,
            (&session.identity.name, &me),
            ALL_ENVIRONMENTS,
            true,
        );
        let names = keys::random_key();
        let mut opened = Opened {
            session: session.clone(),
            project: project.to_string(),
            view: ProjectView {
                creator: creator_grant.clone(),
                recovery: SignedRecovery::default(),
                head: SignedHead::default(),
                index: Sealed {
                    nonce: String::new(),
                    ciphertext: String::new(),
                },
                access: Vec::new(),
                wraps: Vec::new(),
                records: Vec::new(),
            },
            members: roster.keys,
            removed: roster.removed,
            creator: session.identity.name.clone(),
            keys: BTreeMap::from([(names_slot(), names.clone())]),
            names: BTreeMap::new(),
        };
        opened.view.recovery = opened.signed_recovery(&recovery_public);
        let wraps = vec![
            opened.wrap(&names_slot(), &names, opened.me())?,
            opened.wrap(&names_slot(), &names, RECOVERY)?,
        ];
        session.call::<Done>(&Request::ProjectCreate(Box::new(NewProject {
            project: project.to_string(),
            recovery: opened.view.recovery.clone(),
            head: opened.head(Vec::new()),
            wraps,
            index: opened.sealed_index(&BTreeMap::new())?,
            grant: creator_grant,
        })))?;
        self.pins.update(&session.url, |pins| {
            pins.creators
                .insert(project.to_string(), session.identity.name.clone());
            pins.recoveries.insert(
                project.to_string(),
                vec![opened.view.recovery.public.clone()],
            );
            Ok(())
        })
    }

    pub fn members(&self, project: &str) -> Result<Vec<MemberView>> {
        let session = self.session_for(project)?;
        Ok(self.pinned_members(&session)?.views)
    }

    pub fn add_member(&self, project: &str, name: &str, admin: bool) -> Result<Invite> {
        self.session_for(project)?.call(&Request::MemberAdd {
            name: name.to_string(),
            admin,
        })
    }

    /// Activates a member whose fingerprint was checked, gives it access to `envs` of
    /// `project` and wraps the keys of those environments for it.
    pub fn approve(
        &self,
        project: &str,
        name: &str,
        fingerprint: &str,
        envs: &[String],
        write: bool,
    ) -> Result<()> {
        let session = self.session_for(project)?;
        session.call::<Done>(&Request::MemberApprove {
            name: name.to_string(),
            fingerprint: fingerprint.to_string(),
        })?;
        // The fingerprint is checked here too: the keys wrapped for and granted to must be
        // the ones the person confirmed, whatever the server says.
        let keys = *self
            .pinned_members(&session)?
            .keys
            .get(name)
            .ok_or_else(|| anyhow!("The server does not list '{name}'."))?;
        if keys.fingerprint() != fingerprint.trim() {
            bail!(
                "The fingerprint of '{name}' on the server is not the one given. Nothing was shared."
            );
        }
        for env in envs {
            let access = grant(&session, project, (name, &keys), env, write);
            session.call::<Done>(&Request::Grant {
                project: project.to_string(),
                access,
            })?;
        }
        self.forget(project);
        self.write(project, |opened| {
            let mut commit = opened.commit();
            for (slot, key) in &opened.keys {
                let granted = slot.0 == Purpose::Names
                    || envs.iter().any(|e| e == ALL_ENVIRONMENTS || *e == slot.1);
                if granted {
                    commit
                        .add_wraps
                        .push(opened.wrap_for(slot, key, name, &keys.x25519_key())?);
                }
            }
            Ok(Some(commit))
        })
    }

    /// Removes a member and replaces the keys of every environment it could read that this
    /// member can rekey. Returns the `(project, environment)` it could read.
    pub fn remove_member(&self, project: &str, name: &str) -> Result<Vec<(String, String)>> {
        let removed: Removed = self.session_for(project)?.call(&Request::MemberRemove {
            name: name.to_string(),
        })?;
        Ok(removed.lost_access)
    }

    pub fn audit(&self, project: &str, only_project: bool) -> Result<Vec<AuditEntry>> {
        self.session_for(project)?.call(&Request::Audit {
            project: only_project.then(|| project.to_string()),
        })
    }

    /// The environments of `project` that have a key.
    pub fn environments(&self, project: &str) -> Result<Vec<String>> {
        let opened = self.open(project)?;
        let mut envs: Vec<String> = opened
            .keys
            .keys()
            .filter(|slot| slot.0 == Purpose::Dek)
            .map(|slot| slot.1.clone())
            .collect();
        envs.dedup();
        Ok(envs)
    }

    /// A new DEK for `env`: every record of it is encrypted again and the key is wrapped for
    /// the members that can still read it. Returns the new key id.
    pub fn rekey(&self, project: &str, env: &str) -> Result<u32> {
        let new_id = RefCell::new(0);
        self.write(project, |opened| {
            let old: Vec<&SignedRecord> = opened
                .view
                .records
                .iter()
                .filter(|r| r.env == env)
                .collect();
            let key_id = opened.current_key_id(env).map_or(1, |id| id + 1);
            *new_id.borrow_mut() = key_id;
            let dek = keys::random_key();
            let slot = (Purpose::Dek, env.to_string(), key_id);
            let mut commit = opened.commit();
            for record in &old {
                let value = opened.decrypt(record)?;
                let id = RecordId {
                    key_id,
                    ..record_id(record)
                };
                commit.add_records.push(opened.encrypt(&id, &dek, &value)?);
                commit.remove_records.push(RecordRef {
                    env: record.env.clone(),
                    key: record.key.clone(),
                    version: record.version,
                });
            }
            commit.add_wraps = opened.wraps_for_env(&slot, &dek, env)?;
            commit.remove_wraps = old_wraps(opened, env, key_id);
            Ok(Some(commit))
        })?;
        Ok(new_id.into_inner())
    }

    /// Opens the recovery wraps with `recovery` and wraps every key again for the caller.
    pub fn recover(&self, project: &str, recovery: &[u8; 32]) -> Result<()> {
        self.write(project, |opened| {
            let secret = keys::recovery_secret(recovery);
            if PublicKey::from(&secret) != opened.recovery()? {
                bail!("This recovery key does not belong to this project.");
            }
            let keys = unwrap_for(project, &opened.view.wraps, RECOVERY, &secret)?;
            let mut commit = opened.commit();
            for (slot, key) in &keys {
                commit.add_wraps.push(opened.wrap(slot, key, opened.me())?);
            }
            Ok(Some(commit))
        })
    }

    /// Replaces the recovery key: every key is wrapped for the new one.
    pub fn replace_recovery(&self, project: &str, recovery: &[u8; 32]) -> Result<()> {
        let public = PublicKey::from(&keys::recovery_secret(recovery));
        self.write(project, |opened| {
            let mut commit = opened.commit();
            let with_new = Opened::clone_for_recovery(opened, &public);
            for (slot, key) in &opened.keys {
                commit.add_wraps.push(with_new.wrap(slot, key, RECOVERY)?);
            }
            commit.recovery = Some(with_new.view.recovery.clone());
            Ok(Some(commit))
        })
    }
}

impl Opened {
    /// A view of `opened` whose recovery key is `public`, to wrap keys for it.
    fn clone_for_recovery(opened: &Opened, public: &PublicKey) -> Opened {
        let mut view = opened.view.clone();
        view.recovery = opened.signed_recovery(public);
        Opened {
            session: opened.session.clone(),
            project: opened.project.clone(),
            view,
            members: opened.members.clone(),
            removed: opened.removed.clone(),
            creator: opened.creator.clone(),
            keys: BTreeMap::new(),
            names: BTreeMap::new(),
        }
    }
}

/// The wraps of the earlier DEKs of `env`, for every member and the recovery key.
fn old_wraps(opened: &Opened, env: &str, new_id: u32) -> Vec<WrapRef> {
    let mut members: Vec<String> = opened.members.keys().cloned().collect();
    members.push(RECOVERY.to_string());
    let mut refs = Vec::new();
    for key_id in 1..new_id {
        for member in &members {
            refs.push(WrapRef {
                purpose: Purpose::Dek,
                env: env.to_string(),
                key_id,
                member: member.clone(),
            });
        }
    }
    refs
}

impl SecretVault for RemoteVault<'_> {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>> {
        let opened = self.open(project)?;
        let tag = opened.tag(environment, key)?;
        let Some(version) = opened.active_version(environment, &tag) else {
            return Ok(None);
        };
        // The head lists every environment; records only come for the readable ones.
        let Some(record) = opened
            .versions(environment, &tag)
            .find(|r| r.version == version)
        else {
            bail!(
                "'{}' has no access to '{environment}' on the server.",
                opened.me()
            );
        };
        opened.decrypt(record).map(Some)
    }

    fn set(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        value: &Secret,
        change: Change,
    ) -> Result<()> {
        self.write(project, |opened| {
            let tag = opened.tag(environment, key)?;
            let mut commit = opened.commit();
            let key_id = match opened.current_key_id(environment) {
                Some(id) => id,
                None => {
                    let dek = keys::random_key();
                    let slot = (Purpose::Dek, environment.to_string(), 1);
                    commit.add_wraps = opened.wraps_for_env(&slot, &dek, environment)?;
                    return finish_set(
                        opened,
                        commit,
                        (environment, key, &tag),
                        (1, &dek),
                        value,
                        change,
                    );
                }
            };
            let dek = opened.keys[&(Purpose::Dek, environment.to_string(), key_id)].clone();
            finish_set(
                opened,
                commit,
                (environment, key, &tag),
                (key_id, &dek),
                value,
                change,
            )
        })
    }

    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool> {
        let had_value = RefCell::new(false);
        self.write(project, |opened| {
            let tag = opened.tag(environment, key)?;
            let versions: Vec<RecordRef> = opened
                .versions(environment, &tag)
                .map(|r| RecordRef {
                    env: r.env.clone(),
                    key: r.key.clone(),
                    version: r.version,
                })
                .collect();
            *had_value.borrow_mut() = opened.active_version(environment, &tag).is_some();
            if versions.is_empty() {
                return Ok(None);
            }
            let mut commit = opened.commit();
            let entries = opened
                .view
                .head
                .entries
                .iter()
                .filter(|e| !(e.env == environment && e.key == tag))
                .cloned()
                .collect();
            commit.head = opened.head(entries);
            commit.remove_records = versions;
            let mut names = opened.names.clone();
            names.remove(&tag);
            commit.index = Some(opened.sealed_index(&names)?);
            Ok(Some(commit))
        })?;
        Ok(had_value.into_inner())
    }

    fn history(&self, project: &str, environment: &str, key: &str) -> Result<Vec<Version>> {
        let opened = self.open(project)?;
        let tag = opened.tag(environment, key)?;
        let active = opened.active_version(environment, &tag);
        let mut versions: Vec<Version> = opened
            .versions(environment, &tag)
            .map(|r| Version {
                number: r.version,
                created_at: DateTime::from_timestamp(r.created_at, 0),
                active: Some(r.version) == active,
            })
            .collect();
        versions.sort_by_key(|v| std::cmp::Reverse(v.number));
        Ok(versions)
    }

    fn get_version(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        number: u32,
    ) -> Result<Option<Secret>> {
        let opened = self.open(project)?;
        let tag = opened.tag(environment, key)?;
        let record = opened
            .versions(environment, &tag)
            .find(|r| r.version == number);
        record.map(|r| opened.decrypt(r)).transpose()
    }
}

/// `(environment, variable, tag)` of a write.
type Target<'a> = (&'a str, &'a str, &'a str);

/// Adds the new version, makes it active, prunes old versions beyond `keep` and records
/// the name in the index.
fn finish_set(
    opened: &Opened,
    mut commit: Commit,
    (env, key, tag): Target,
    (key_id, dek): (u32, &Key32),
    value: &Secret,
    change: Change,
) -> Result<Option<Commit>> {
    let mut previous: Vec<u32> = opened.versions(env, tag).map(|r| r.version).collect();
    previous.sort_unstable_by(|a, b| b.cmp(a));
    let version = previous.first().map_or(1, |v| v + 1);
    let id = RecordId {
        env,
        key: tag,
        version,
        key_id,
        created_at: change.at.timestamp(),
    };
    commit.add_records.push(opened.encrypt(&id, dek, value)?);
    commit.remove_records = previous
        .into_iter()
        .skip(change.keep)
        .map(|version| RecordRef {
            env: env.to_string(),
            key: tag.to_string(),
            version,
        })
        .collect();
    let mut entries: Vec<HeadEntry> = opened
        .view
        .head
        .entries
        .iter()
        .filter(|e| !(e.env == env && e.key == tag))
        .cloned()
        .collect();
    entries.push(HeadEntry {
        env: env.to_string(),
        key: tag.to_string(),
        version,
    });
    commit.head = opened.head(entries);
    if opened.names.get(tag).map(String::as_str) != Some(key) {
        let mut names = opened.names.clone();
        names.insert(tag.to_string(), key.to_string());
        commit.index = Some(opened.sealed_index(&names)?);
    }
    Ok(Some(commit))
}

/// Logs in to `url` for the first time: as the first admin with a root token, or as a new
/// member with an invite. Returns the identity, which the caller stores or prints.
pub fn enrol(transport: &dyn Transport, credential: Enrolment, name: &str) -> Result<Identity> {
    let identity = Identity::generate(name);
    let keys = MemberKeys::of(&identity.public());
    let request = match credential {
        Enrolment::RootToken(root_token) => Request::Bootstrap {
            root_token,
            name: name.to_string(),
            keys,
        },
        Enrolment::Invite(invite) => Request::Join {
            invite,
            name: name.to_string(),
            keys,
        },
    };
    anonymous::<Done>(transport, &request)?;
    Ok(identity)
}

pub enum Enrolment {
    RootToken(String),
    Invite(String),
}

/// Whether `name` is waiting for approval, as seen by the server.
pub fn status_of(members: &[MemberView], name: &str) -> Option<MemberStatus> {
    members.iter().find(|m| m.name == name).map(|m| m.status)
}
