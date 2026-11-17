//! The encrypted file backend (ADR 0001): one JSON file per user and project in
//! `{data dir}/vaults/`, holding records encrypted with a DEK per environment, the DEKs and
//! the name key wrapped for the password (through the Argon2id KEK) and for the recovery key.
//!
//! The file is opened once per run: the password is asked once (or read from
//! `ENVY_VAULT_PASSWORD`), the keys stay in memory, and every write saves the whole file
//! atomically under an exclusive lock. A file changed by another process since it was read
//! is never overwritten.

use std::{
    cell::{RefCell, RefMut},
    collections::{BTreeMap, HashMap},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    Change, SecretVault, Version,
    format::{
        self, KeySlot, Purpose, RecordId, Sealed, b64, index_aad, names_slot, open_from, seal_to,
        unb64, wrap_aad,
    },
};
use crate::{
    keys::{self, KdfParams, Key32, encode},
    prompt::Prompter,
    schema::Secret,
};

const FORMAT: &str = "envy-file-vault";
const FORMAT_VERSION: u32 = 1;
const KEK_CHECK: &[u8] = b"envy-file-vault";
const PASSWORD: &str = "password";
const RECOVERY: &str = "recovery";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    format: String,
    v: u32,
    project: String,
    kdf: Kdf,
    kek_check: Sealed,
    recovery: RecoveryPublic,
    wraps: Vec<Wrap>,
    index: Sealed,
    records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Kdf {
    alg: String,
    m: u32,
    t: u32,
    p: u32,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryPublic {
    public: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Wrap {
    purpose: Purpose,
    env: String,
    key_id: u32,
    member: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epk: Option<String>,
    nonce: String,
    wrapped: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Active,
    Superseded,
    /// Reserved for value rotation; readers ignore it.
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    env: String,
    key: String,
    version: u32,
    status: Status,
    key_id: u32,
    created_at: i64,
    nonce: String,
    ciphertext: String,
}

/// A vault file opened with its keys.
struct Opened {
    file: VaultFile,
    /// SHA3 of the bytes read, to refuse overwriting a file changed by another process.
    read_digest: Option<String>,
    kek: Key32,
    keys: BTreeMap<KeySlot, Key32>,
    names: BTreeMap<String, String>,
}

fn digest(bytes: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    keys::hex(&Sha3_256::digest(bytes))
}

fn kek_check_aad(project: &str) -> Vec<u8> {
    encode(&[b"envy-kek-check-v1", project.as_bytes()])
}

fn record_aad(project: &str, record: &Record) -> Vec<u8> {
    format::record_aad(
        project,
        &RecordId {
            env: &record.env,
            key: &record.key,
            version: record.version,
            key_id: record.key_id,
            created_at: record.created_at,
        },
    )
}

fn recovery_public(file: &VaultFile) -> Result<PublicKey> {
    let bytes: [u8; 32] = unb64(&file.recovery.public)?
        .try_into()
        .map_err(|_| anyhow!("The file vault is corrupted (recovery key)."))?;
    Ok(PublicKey::from(bytes))
}

/// The two wraps every key has: one for the password, one for the recovery key.
fn wraps_for(
    project: &str,
    slot: &KeySlot,
    key: &Key32,
    kek: &Key32,
    recovery: &PublicKey,
) -> Result<[Wrap; 2]> {
    let (purpose, env, key_id) = slot.clone();
    let by_password = seal_to(kek, &wrap_aad(project, slot, PASSWORD), key.as_ref())?;
    let (epk, nonce, wrapped) =
        keys::x25519_wrap(recovery, &wrap_aad(project, slot, RECOVERY), key)?;
    Ok([
        Wrap {
            purpose,
            env: env.clone(),
            key_id,
            member: PASSWORD.into(),
            epk: None,
            nonce: by_password.nonce,
            wrapped: by_password.ciphertext,
        },
        Wrap {
            purpose,
            env,
            key_id,
            member: RECOVERY.into(),
            epk: Some(b64(&epk)),
            nonce: b64(&nonce),
            wrapped: b64(&wrapped),
        },
    ])
}

fn slot_of(wrap: &Wrap) -> KeySlot {
    (wrap.purpose, wrap.env.clone(), wrap.key_id)
}

/// Unwraps every key for `member`; `unwrap` opens one wrap.
fn unwrap_all(
    file: &VaultFile,
    member: &str,
    unwrap: impl Fn(&Wrap, &[u8]) -> Option<Key32>,
) -> Result<BTreeMap<KeySlot, Key32>> {
    let mut keys = BTreeMap::new();
    for wrap in file.wraps.iter().filter(|wrap| wrap.member == member) {
        let slot = slot_of(wrap);
        let aad = wrap_aad(&file.project, &slot, member);
        let key = unwrap(wrap, &aad)
            .ok_or_else(|| anyhow!("The file vault is corrupted (a key does not open)."))?;
        keys.insert(slot, key);
    }
    Ok(keys)
}

fn unwrap_with_kek(kek: &Key32) -> impl Fn(&Wrap, &[u8]) -> Option<Key32> + '_ {
    move |wrap, aad| {
        let sealed = Sealed {
            nonce: wrap.nonce.clone(),
            ciphertext: wrap.wrapped.clone(),
        };
        keys::to_key(&open_from(kek, aad, &sealed)?)
    }
}

fn unwrap_with_recovery(secret: &StaticSecret) -> impl Fn(&Wrap, &[u8]) -> Option<Key32> + '_ {
    move |wrap, aad| {
        let epk = unb64(wrap.epk.as_deref()?).ok()?;
        let nonce = unb64(&wrap.nonce).ok()?;
        let wrapped = unb64(&wrap.wrapped).ok()?;
        keys::x25519_unwrap(secret, &epk, aad, &nonce, &wrapped)
    }
}

pub struct EncryptedFileVault<'a> {
    /// `{data dir}/vaults`; `None` when no data folder could be found.
    dir: Option<PathBuf>,
    prompter: &'a dyn Prompter,
    /// `ENVY_VAULT_PASSWORD`, for non-interactive runs.
    preset: Option<&'a Secret>,
    kdf: KdfParams,
    password: RefCell<Option<Secret>>,
    opened: RefCell<HashMap<String, Opened>>,
}

impl<'a> EncryptedFileVault<'a> {
    pub fn new(
        data_dir: Option<PathBuf>,
        prompter: &'a dyn Prompter,
        preset: Option<&'a Secret>,
    ) -> Self {
        Self {
            dir: data_dir.map(|dir| dir.join("vaults")),
            prompter,
            preset,
            kdf: KdfParams::default(),
            password: RefCell::new(None),
            opened: RefCell::new(HashMap::new()),
        }
    }

    /// Cheaper key derivation for new vaults, for tests only: the parameters are stored in
    /// the file, so vaults created this way stay readable.
    pub fn with_kdf(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }

    fn path(&self, project: &str) -> Result<PathBuf> {
        let Some(dir) = &self.dir else {
            bail!(
                "The file backend needs a folder for its data, and Envy found none (set HOME, or LOCALAPPDATA on Windows)."
            );
        };
        Ok(dir.join(format!("{}.json", crate::audit::file_stem(project))))
    }

    /// Asks for the password (once per run) and opens the vault of `project`.
    pub fn unlock(&self, project: &str) -> Result<()> {
        self.opened(project).map(|_| ())
    }

    pub fn exists(&self, project: &str) -> bool {
        self.path(project).is_ok_and(|path| path.is_file())
    }

    /// Creates the vault of `project` for `password`, with `recovery` as its recovery key.
    pub fn create(&self, project: &str, password: &Secret, recovery: &[u8; 32]) -> Result<()> {
        if self.exists(project) {
            bail!("This project already has a file vault.");
        }
        let salt = keys::random_salt();
        let kek = keys::derive_kek(password, &salt, self.kdf)?;
        let recovery = PublicKey::from(&keys::recovery_secret(recovery));
        let names = keys::random_key();
        let file = VaultFile {
            format: FORMAT.into(),
            v: FORMAT_VERSION,
            project: project.into(),
            kdf: Kdf {
                alg: "argon2id".into(),
                m: self.kdf.m,
                t: self.kdf.t,
                p: self.kdf.p,
                salt: b64(&salt),
            },
            kek_check: seal_to(&kek, &kek_check_aad(project), KEK_CHECK)?,
            recovery: RecoveryPublic {
                public: b64(recovery.as_bytes()),
            },
            wraps: wraps_for(project, &names_slot(), &names, &kek, &recovery)?.to_vec(),
            index: seal_to(&names, &index_aad(project), b"{}")?,
            records: Vec::new(),
        };
        let mut opened = Opened {
            file,
            read_digest: None,
            kek,
            keys: BTreeMap::from([(names_slot(), names)]),
            names: BTreeMap::new(),
        };
        self.save(project, &mut opened)?;
        *self.password.borrow_mut() = Some(password.clone());
        Ok(())
    }

    fn password(&self) -> Result<Secret> {
        if let Some(password) = self.password.borrow().as_ref() {
            return Ok(password.clone());
        }
        let password = match self.preset {
            Some(preset) => preset.clone(),
            None => self.prompter.ask_secret("Password of the file vault")?,
        };
        *self.password.borrow_mut() = Some(password.clone());
        Ok(password)
    }

    fn read(&self, project: &str) -> Result<(VaultFile, String)> {
        let path = self.path(project)?;
        if !path.is_file() {
            bail!(
                "This project has no file vault on this machine yet. Run `envy migrate --to file`."
            );
        }
        let bytes =
            fs::read(&path).with_context(|| format!("Could not read {}", path.display()))?;
        let file: VaultFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a valid file vault", path.display()))?;
        if file.format != FORMAT || file.v != FORMAT_VERSION {
            bail!(
                "{} was written by a newer Envy (format {} v{}); update Envy.",
                path.display(),
                file.format,
                file.v
            );
        }
        if file.project != project {
            bail!("{} belongs to another project.", path.display());
        }
        Ok((file, digest(&bytes)))
    }

    fn kek_of(&self, file: &VaultFile, password: &Secret) -> Result<Key32> {
        let params = KdfParams {
            m: file.kdf.m,
            t: file.kdf.t,
            p: file.kdf.p,
        };
        let kek = keys::derive_kek(password, &unb64(&file.kdf.salt)?, params)?;
        match open_from(&kek, &kek_check_aad(&file.project), &file.kek_check) {
            Some(check) if check.as_slice() == KEK_CHECK => Ok(kek),
            _ => bail!("Wrong password for the file vault."),
        }
    }

    fn opened(&self, project: &str) -> Result<RefMut<'_, Opened>> {
        if !self.opened.borrow().contains_key(project) {
            let (file, read_digest) = self.read(project)?;
            let kek = self.kek_of(&file, &self.password()?)?;
            let keys = unwrap_all(&file, PASSWORD, unwrap_with_kek(&kek))?;
            let opened = Opened::new(file, Some(read_digest), kek, keys)?;
            self.opened.borrow_mut().insert(project.to_string(), opened);
        }
        Ok(RefMut::map(self.opened.borrow_mut(), |all| {
            all.get_mut(project).expect("inserted above")
        }))
    }

    /// Re-wraps every key for a new password. The records are not touched.
    pub fn change_password(&self, project: &str, new: &Secret) -> Result<()> {
        let mut opened = self.opened(project)?;
        opened.rewrap_password(&self.kdf, new)?;
        self.save(project, &mut opened)?;
        *self.password.borrow_mut() = Some(new.clone());
        Ok(())
    }

    /// A new DEK for `environment`; every record of it is encrypted again. Returns its id.
    pub fn rekey(&self, project: &str, environment: &str) -> Result<u32> {
        let mut opened = self.opened(project)?;
        let key_id = opened.rekey(environment)?;
        self.save(project, &mut opened)?;
        Ok(key_id)
    }

    /// Fails unless `recovery` is the recovery key of the project's vault.
    pub fn check_recovery(&self, project: &str, recovery: &[u8; 32]) -> Result<()> {
        let (file, _) = self.read(project)?;
        let public = PublicKey::from(&keys::recovery_secret(recovery));
        if public.as_bytes().as_slice() != unb64(&file.recovery.public)? {
            bail!("This recovery key does not belong to this project's file vault.");
        }
        Ok(())
    }

    /// Opens the vault with the recovery key and protects it with a new password.
    pub fn recover(&self, project: &str, recovery: &[u8; 32], new: &Secret) -> Result<()> {
        self.check_recovery(project, recovery)?;
        let (file, read_digest) = self.read(project)?;
        let secret = keys::recovery_secret(recovery);
        let keys = unwrap_all(&file, RECOVERY, unwrap_with_recovery(&secret))?;
        let mut opened = Opened::new(file, Some(read_digest), keys::random_key(), keys)?;
        opened.rewrap_password(&self.kdf, new)?;
        self.save(project, &mut opened)?;
        self.opened.borrow_mut().insert(project.to_string(), opened);
        *self.password.borrow_mut() = Some(new.clone());
        Ok(())
    }

    /// Replaces the recovery key: every key is wrapped again for the new one.
    pub fn replace_recovery(&self, project: &str, recovery: &[u8; 32]) -> Result<()> {
        let mut opened = self.opened(project)?;
        let public = PublicKey::from(&keys::recovery_secret(recovery));
        opened.file.recovery.public = b64(public.as_bytes());
        opened.rewrap_all()?;
        self.save(project, &mut opened)
    }

    fn save(&self, project: &str, opened: &mut Opened) -> Result<()> {
        let path = self.path(project)?;
        let bytes = opened.serialize()?;
        let _lock = Lock::take(&path)?;
        if let Some(expected) = &opened.read_digest {
            let current = fs::read(&path).map(|bytes| digest(&bytes)).ok();
            if current.as_ref() != Some(expected) {
                bail!(
                    "{} changed while this command ran (another Envy?). Nothing was written; run the command again.",
                    path.display()
                );
            }
        }
        write_atomically(&path, &bytes)?;
        opened.read_digest = Some(digest(&bytes));
        Ok(())
    }
}

impl Opened {
    fn new(
        file: VaultFile,
        read_digest: Option<String>,
        kek: Key32,
        keys: BTreeMap<KeySlot, Key32>,
    ) -> Result<Self> {
        let names_key = keys
            .get(&names_slot())
            .ok_or_else(|| anyhow!("The file vault is corrupted (no name key)."))?;
        let index = open_from(names_key, &index_aad(&file.project), &file.index)
            .ok_or_else(|| anyhow!("The file vault is corrupted (name index)."))?;
        let names = serde_json::from_slice(&index).context("The name index is corrupted")?;
        Ok(Self {
            file,
            read_digest,
            kek,
            keys,
            names,
        })
    }

    fn names_key(&self) -> &Key32 {
        self.keys.get(&names_slot()).expect("checked when opened")
    }

    fn tag(&self, environment: &str, variable: &str) -> String {
        keys::name_tag(self.names_key(), environment, variable)
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut file = self.file.clone();
        let index = serde_json::to_vec(&self.names)?;
        file.index = seal_to(self.names_key(), &index_aad(&file.project), &index)?;
        Ok(serde_json::to_vec_pretty(&file)?)
    }

    fn current_key_id(&self, environment: &str) -> Option<u32> {
        self.keys
            .keys()
            .filter(|(purpose, env, _)| *purpose == Purpose::Dek && env == environment)
            .map(|(_, _, key_id)| *key_id)
            .max()
    }

    fn add_key(&mut self, slot: KeySlot, key: Key32) -> Result<()> {
        let recovery = recovery_public(&self.file)?;
        let wraps = wraps_for(&self.file.project, &slot, &key, &self.kek, &recovery)?;
        self.file.wraps.extend(wraps);
        self.keys.insert(slot, key);
        Ok(())
    }

    /// The DEK new records of `environment` use, created on first use.
    fn dek_for(&mut self, environment: &str) -> Result<u32> {
        if let Some(key_id) = self.current_key_id(environment) {
            return Ok(key_id);
        }
        self.add_key(
            (Purpose::Dek, environment.to_string(), 1),
            keys::random_key(),
        )?;
        Ok(1)
    }

    fn dek(&self, environment: &str, key_id: u32) -> Result<&Key32> {
        self.keys
            .get(&(Purpose::Dek, environment.to_string(), key_id))
            .ok_or_else(|| {
                anyhow!("The file vault is corrupted (missing key {key_id} of '{environment}').")
            })
    }

    fn encrypt(&self, mut record: Record, value: &Secret) -> Result<Record> {
        let sealed = seal_to(
            self.dek(&record.env, record.key_id)?,
            &record_aad(&self.file.project, &record),
            &keys::pad(value),
        )?;
        record.nonce = sealed.nonce;
        record.ciphertext = sealed.ciphertext;
        Ok(record)
    }

    fn decrypt(&self, record: &Record) -> Result<Secret> {
        let sealed = Sealed {
            nonce: record.nonce.clone(),
            ciphertext: record.ciphertext.clone(),
        };
        let dek = self.dek(&record.env, record.key_id)?;
        open_from(dek, &record_aad(&self.file.project, record), &sealed)
            .and_then(|padded| keys::unpad(&padded))
            .ok_or_else(|| anyhow!("The file vault is corrupted (a value does not open)."))
    }

    fn versions<'r>(
        &'r self,
        environment: &'r str,
        tag: &'r str,
    ) -> impl Iterator<Item = &'r Record> {
        self.file.records.iter().filter(move |record| {
            record.env == environment && record.key == tag && record.status != Status::Pending
        })
    }

    fn rewrap_password(&mut self, kdf: &KdfParams, new: &Secret) -> Result<()> {
        let salt = keys::random_salt();
        self.kek = keys::derive_kek(new, &salt, *kdf)?;
        self.file.kdf = Kdf {
            alg: "argon2id".into(),
            m: kdf.m,
            t: kdf.t,
            p: kdf.p,
            salt: b64(&salt),
        };
        self.file.kek_check = seal_to(&self.kek, &kek_check_aad(&self.file.project), KEK_CHECK)?;
        self.rewrap_all()
    }

    fn rewrap_all(&mut self) -> Result<()> {
        let recovery = recovery_public(&self.file)?;
        let mut wraps = Vec::with_capacity(self.keys.len() * 2);
        for (slot, key) in &self.keys {
            wraps.extend(wraps_for(
                &self.file.project,
                slot,
                key,
                &self.kek,
                &recovery,
            )?);
        }
        self.file.wraps = wraps;
        Ok(())
    }

    fn rekey(&mut self, environment: &str) -> Result<u32> {
        let old = self.current_key_id(environment);
        let key_id = old.map_or(1, |id| id + 1);
        let records: Vec<(usize, Secret)> = self
            .file
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.env == environment)
            .map(|(i, record)| Ok((i, self.decrypt(record)?)))
            .collect::<Result<_>>()?;

        self.add_key(
            (Purpose::Dek, environment.to_string(), key_id),
            keys::random_key(),
        )?;
        for (i, value) in records {
            let record = Record {
                key_id,
                ..self.file.records[i].clone()
            };
            self.file.records[i] = self.encrypt(record, &value)?;
        }
        self.keys.retain(|(purpose, env, id), _| {
            !(*purpose == Purpose::Dek && env == environment && *id != key_id)
        });
        self.file.wraps.retain(|wrap| {
            !(wrap.purpose == Purpose::Dek && wrap.env == environment && wrap.key_id != key_id)
        });
        Ok(key_id)
    }
}

impl SecretVault for EncryptedFileVault<'_> {
    fn get(&self, project: &str, environment: &str, key: &str) -> Result<Option<Secret>> {
        let opened = self.opened(project)?;
        let tag = opened.tag(environment, key);
        let active = opened
            .versions(environment, &tag)
            .find(|record| record.status == Status::Active);
        active.map(|record| opened.decrypt(record)).transpose()
    }

    fn set(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        value: &Secret,
        change: Change,
    ) -> Result<()> {
        let mut opened = self.opened(project)?;
        let tag = opened.tag(environment, key);
        let key_id = opened.dek_for(environment)?;
        let version = opened
            .versions(environment, &tag)
            .map(|record| record.version)
            .max()
            .unwrap_or(0)
            + 1;

        for record in opened.file.records.iter_mut() {
            if record.env == environment && record.key == tag && record.status == Status::Active {
                record.status = Status::Superseded;
            }
        }
        let record = Record {
            env: environment.to_string(),
            key: tag.clone(),
            version,
            status: Status::Active,
            key_id,
            created_at: change.at.timestamp(),
            nonce: String::new(),
            ciphertext: String::new(),
        };
        let record = opened.encrypt(record, value)?;
        opened.file.records.push(record);
        prune(&mut opened.file.records, environment, &tag, change.keep);
        opened.names.insert(tag, key.to_string());
        self.save(project, &mut opened)
    }

    fn delete(&self, project: &str, environment: &str, key: &str) -> Result<bool> {
        let mut opened = self.opened(project)?;
        let tag = opened.tag(environment, key);
        let active = opened
            .versions(environment, &tag)
            .any(|record| record.status == Status::Active);
        let before = opened.file.records.len();
        opened
            .file
            .records
            .retain(|record| !(record.env == environment && record.key == tag));
        if opened.file.records.len() != before {
            opened.names.remove(&tag);
            self.save(project, &mut opened)?;
        }
        Ok(active)
    }

    fn history(&self, project: &str, environment: &str, key: &str) -> Result<Vec<Version>> {
        let opened = self.opened(project)?;
        let tag = opened.tag(environment, key);
        let mut versions: Vec<Version> = opened
            .versions(environment, &tag)
            .map(|record| Version {
                number: record.version,
                created_at: DateTime::from_timestamp(record.created_at, 0),
                active: record.status == Status::Active,
            })
            .collect();
        versions.sort_by_key(|version| std::cmp::Reverse(version.number));
        Ok(versions)
    }

    fn get_version(
        &self,
        project: &str,
        environment: &str,
        key: &str,
        number: u32,
    ) -> Result<Option<Secret>> {
        let opened = self.opened(project)?;
        let tag = opened.tag(environment, key);
        let found = opened
            .versions(environment, &tag)
            .find(|record| record.version == number);
        found.map(|record| opened.decrypt(record)).transpose()
    }
}

/// Keeps the active record and the newest `keep` superseded ones of a variable.
fn prune(records: &mut Vec<Record>, environment: &str, tag: &str, keep: usize) {
    let mut superseded: Vec<u32> = records
        .iter()
        .filter(|r| r.env == environment && r.key == tag && r.status == Status::Superseded)
        .map(|r| r.version)
        .collect();
    superseded.sort_unstable_by(|a, b| b.cmp(a));
    let dropped: Vec<u32> = superseded.into_iter().skip(keep).collect();
    records.retain(|r| !(r.env == environment && r.key == tag && dropped.contains(&r.version)));
}

/// An exclusive `{vault}.lock` held while the vault is written.
struct Lock(PathBuf);

impl Lock {
    fn take(vault: &Path) -> Result<Self> {
        let path = vault.with_extension("json.lock");
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => Ok(Self(path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => bail!(
                "Another Envy is writing the file vault. If none is running, remove {}.",
                path.display()
            ),
            Err(err) => Err(err).with_context(|| format!("Could not create {}", path.display())),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .with_context(|| format!("Could not create {}", dir.display()))
}

/// Writes next to the vault and renames over it, so a crash leaves the old file or the new
/// one, never half of one. On Unix only the user can read it.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("Could not create {}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("Could not write {}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path).with_context(|| format!("Could not replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::conformance;

    const FAST: KdfParams = KdfParams { m: 64, t: 1, p: 1 };
    const RECOVERY_KEY: [u8; 32] = [9; 32];

    struct NoPrompter;

    impl Prompter for NoPrompter {
        fn ask_secret(&self, label: &str) -> Result<Secret> {
            bail!("unexpected prompt: {label}")
        }
    }

    /// A vault in its own folder, with files for the projects the conformance cases use.
    struct Fixture {
        _dir: tempfile::TempDir,
        vault: EncryptedFileVault<'static>,
    }

    fn password() -> &'static Secret {
        Box::leak(Box::new(Secret::new("pw")))
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let vault = EncryptedFileVault::new(
            Some(dir.path().to_path_buf()),
            &NoPrompter,
            Some(password()),
        )
        .with_kdf(FAST);
        for project in ["p", "p1", "p2"] {
            vault.create(project, password(), &RECOVERY_KEY).unwrap();
        }
        Fixture { _dir: dir, vault }
    }

    impl SecretVault for Fixture {
        fn get(&self, p: &str, e: &str, k: &str) -> Result<Option<Secret>> {
            self.vault.get(p, e, k)
        }
        fn set(&self, p: &str, e: &str, k: &str, v: &Secret, c: Change) -> Result<()> {
            self.vault.set(p, e, k, v, c)
        }
        fn delete(&self, p: &str, e: &str, k: &str) -> Result<bool> {
            self.vault.delete(p, e, k)
        }
        fn history(&self, p: &str, e: &str, k: &str) -> Result<Vec<Version>> {
            self.vault.history(p, e, k)
        }
        fn get_version(&self, p: &str, e: &str, k: &str, n: u32) -> Result<Option<Secret>> {
            self.vault.get_version(p, e, k, n)
        }
    }

    fn change() -> Change {
        Change {
            at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            keep: 5,
        }
    }

    /// The same files read by a new process: nothing cached.
    fn reopen(fixture: &Fixture, password: &'static Secret) -> EncryptedFileVault<'static> {
        EncryptedFileVault::new(
            fixture
                .vault
                .dir
                .clone()
                .map(|d| d.parent().unwrap().to_path_buf()),
            &NoPrompter,
            Some(password),
        )
    }

    fn file_text(fixture: &Fixture) -> String {
        fs::read_to_string(fixture.vault.path("p").unwrap()).unwrap()
    }

    #[test]
    fn the_file_vault_passes_the_conformance_suite() {
        conformance::run(fixture);
    }

    #[test]
    fn values_and_names_never_reach_the_file_in_clear() {
        let fixture = fixture();
        fixture
            .vault
            .set(
                "p",
                "prod",
                "API_TOKEN",
                &Secret::new("s3cr3t-value"),
                change(),
            )
            .unwrap();
        let text = file_text(&fixture);
        assert!(!text.contains("s3cr3t"), "{text}");
        assert!(!text.contains("API_TOKEN"), "{text}");
        assert!(
            text.contains("\"env\": \"prod\""),
            "environments are visible"
        );
    }

    #[test]
    fn values_survive_a_new_process() {
        let fixture = fixture();
        fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v"), change())
            .unwrap();
        let again = reopen(&fixture, password());
        assert_eq!(
            again.get("p", "dev", "K").unwrap().unwrap().expose_secret(),
            "v"
        );
        assert_eq!(
            again.history("p", "dev", "K").unwrap()[0].created_at,
            Some(change().at)
        );
    }

    #[test]
    fn a_wrong_password_is_reported_before_anything_else() {
        let fixture = fixture();
        let wrong = Box::leak(Box::new(Secret::new("nope")));
        let err = reopen(&fixture, wrong).get("p", "dev", "K").unwrap_err();
        assert!(
            err.to_string()
                .contains("Wrong password for the file vault"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_vault_is_an_error_not_a_fallback() {
        let fixture = fixture();
        let err = fixture
            .vault
            .get("other", "dev", "K")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Run `envy migrate --to file`"), "{err}");
    }

    #[test]
    fn a_moved_or_edited_record_does_not_open() {
        let fixture = fixture();
        fixture
            .vault
            .set("p", "dev", "A", &Secret::new("a"), change())
            .unwrap();
        fixture
            .vault
            .set("p", "dev", "B", &Secret::new("b"), change())
            .unwrap();
        let path = fixture.vault.path("p").unwrap();
        let mut file: VaultFile =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // Give B's ciphertext to A: the AAD binds it to B.
        let b = file.records[1].clone();
        file.records[0].nonce = b.nonce;
        file.records[0].ciphertext = b.ciphertext;
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let err = reopen(&fixture, password())
            .get("p", "dev", "A")
            .unwrap_err();
        assert!(err.to_string().contains("corrupted"), "{err}");
    }

    #[test]
    fn a_file_changed_by_another_process_is_not_overwritten() {
        let fixture = fixture();
        fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v1"), change())
            .unwrap();
        let other = reopen(&fixture, password());
        other
            .set("p", "dev", "K", &Secret::new("v2"), change())
            .unwrap();

        let err = fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v3"), change())
            .unwrap_err();
        assert!(
            err.to_string().contains("changed while this command ran"),
            "{err}"
        );
        let fresh = reopen(&fixture, password());
        assert_eq!(
            fresh.get("p", "dev", "K").unwrap().unwrap().expose_secret(),
            "v2"
        );
    }

    #[test]
    fn a_new_password_keeps_the_values() {
        let fixture = fixture();
        fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v"), change())
            .unwrap();
        let new = Box::leak(Box::new(Secret::new("new-pw")));
        fixture.vault.change_password("p", new).unwrap();

        assert!(reopen(&fixture, password()).get("p", "dev", "K").is_err());
        assert_eq!(
            reopen(&fixture, new)
                .get("p", "dev", "K")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "v"
        );
    }

    #[test]
    fn rekeying_an_environment_encrypts_its_records_again() {
        let fixture = fixture();
        fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v1"), change())
            .unwrap();
        fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v2"), change())
            .unwrap();
        fixture
            .vault
            .set("p", "prod", "K", &Secret::new("p1"), change())
            .unwrap();
        let before = file_text(&fixture);

        assert_eq!(fixture.vault.rekey("p", "dev").unwrap(), 2);
        let file: VaultFile = serde_json::from_str(&file_text(&fixture)).unwrap();
        assert!(
            file.records
                .iter()
                .filter(|r| r.env == "dev")
                .all(|r| r.key_id == 2)
        );
        assert!(
            file.records
                .iter()
                .any(|r| r.env == "prod" && r.key_id == 1)
        );
        assert!(
            !file.wraps.iter().any(|w| w.env == "dev" && w.key_id == 1),
            "the old DEK is gone"
        );
        assert_ne!(before, file_text(&fixture));

        let again = reopen(&fixture, password());
        assert_eq!(
            again
                .get_version("p", "dev", "K", 1)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "v1"
        );
        assert_eq!(
            again
                .get("p", "prod", "K")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "p1"
        );
    }

    #[test]
    fn the_recovery_key_sets_a_new_password() {
        let fixture = fixture();
        fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v"), change())
            .unwrap();
        let fresh = reopen(&fixture, password());
        assert!(fresh.check_recovery("p", &[1; 32]).is_err());

        let new = Box::leak(Box::new(Secret::new("after-recovery")));
        fresh.recover("p", &RECOVERY_KEY, new).unwrap();
        assert!(reopen(&fixture, password()).get("p", "dev", "K").is_err());
        assert_eq!(
            reopen(&fixture, new)
                .get("p", "dev", "K")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "v"
        );
    }

    #[test]
    fn a_replaced_recovery_key_is_the_only_one_that_works() {
        let fixture = fixture();
        fixture
            .vault
            .set("p", "dev", "K", &Secret::new("v"), change())
            .unwrap();
        fixture.vault.replace_recovery("p", &[2; 32]).unwrap();

        let fresh = reopen(&fixture, password());
        assert!(fresh.check_recovery("p", &RECOVERY_KEY).is_err());
        let new = Box::leak(Box::new(Secret::new("x")));
        fresh.recover("p", &[2; 32], new).unwrap();
        assert_eq!(
            fresh.get("p", "dev", "K").unwrap().unwrap().expose_secret(),
            "v"
        );
    }

    #[test]
    #[cfg(unix)]
    fn only_the_user_can_read_the_vault() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture();
        let path = fixture.vault.path("p").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
}
