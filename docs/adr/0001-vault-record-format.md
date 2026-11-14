# ADR 0001: Record format of the encrypted vaults

- Status: Accepted (2026-11-13)
- Date: 2026-11-13
- Phase: 1 (`EncryptedFileVault`); the record and wrap formats are reused by `RemoteVault` (phase 2)

## Context

Envy 3 adds backends that store values outside the OS keyring: an encrypted file on the
user's machine (phase 1) and an Envy server that only ever sees ciphertext (phase 2). Both
store the same thing, a **record** per version of a value, and both must keep reading every
record they ever wrote. Records end up in backups and, later, on a server, so the format is
the most expensive part of the plan to change. It is fixed here, before any code.

Constraints taken from the plan and from `AGENTS.md`:

- Ready-made primitives only: Argon2id, XChaCha20-Poly1305, HKDF, X25519 (and Ed25519 later).
- Variable names are obfuscated in storage with a per-project name key.
- The vault keeps versions (`SecretVault::history`, `get_version`, `keep`).
- Nothing in the encoding may be ambiguous: names may contain any character (`/`, `#`, `|`).
- Windows and Linux in the same change; MSRV 1.89.
- The keyring stays the default; nothing changes for a user who does not opt in.

## Decision

### 1. Canonical encoding (used for every AAD, HMAC input and wrap context)

`encode(f1, f2, ...)` concatenates, for each field, its length as a 4-byte big-endian
unsigned integer followed by its bytes. Strings are UTF-8; integers are encoded as 8-byte
big-endian before being framed. The first field is always a domain label with a version
(`envy-record-v1`, `envy-wrap-v1`, ...), so a value valid in one context never verifies in
another.

### 2. Keys

| Key | Size | Made from | Protects | Where it lives |
| :-- | :-- | :-- | :-- | :-- |
| KEK | 32 B | Argon2id(password, salt) — m 19 MiB, t 2, p 1; the parameters and the 16 B salt are stored next to the vault | the wraps of the DEKs and of the name key | never stored |
| DEK | 32 B | random, one per `(project, environment)`, numbered `key_id` from 1 | the records of one environment | wrapped (section 4) |
| Name key | 32 B | random, one per project | the HMAC of the variable names and the name index | wrapped like a DEK, `purpose = names` |
| Recovery key | 24 BIP-39 words = 256 bits of entropy | random, shown once | an X25519 key pair: `sk = HKDF-SHA3-256(ikm = entropy, info = "envy-recovery-x25519-v1")` | only the public key is stored |

Changing the password re-derives the KEK and re-wraps the DEKs and the name key; no record is
re-encrypted. A new DEK for an environment (`key_id + 1`) re-encrypts every record of that
environment, including the old versions.

### 3. Record

```json
{
  "env": "prod",
  "key": "<hex HMAC-SHA3-256(name key, encode(\"envy-name-v1\", env, variable))>",
  "version": 3,
  "status": "active",
  "key_id": 1,
  "created_at": 1800000000,
  "nonce": "<base64, 24 bytes>",
  "ciphertext": "<base64>"
}
```

- `status` is `active`, `superseded` or `pending`. Phase 1 writes the first two; `pending` is
  reserved for value rotation (phase 4) and readers ignore it.
- Cipher: XChaCha20-Poly1305 with the DEK `key_id` and a random 24-byte nonce.
- AAD: `encode("envy-record-v1", project, env, key, version, key_id, created_at)`. Moving a
  ciphertext to another project, environment, variable, version or key fails, and so does
  changing its date (rotation reminders rely on it).
- Plaintext: the value's length (4-byte big-endian) followed by its UTF-8 bytes and zero
  padding up to a multiple of 256 bytes, so the stored size only reveals a size class.
- `status` is not authenticated, because activating a version must not re-encrypt it. A
  backend that can rewrite the file can therefore make an older version active again: the
  file backend accepts this (the file is the user's), the server answers it in phase 3 with a
  signed index.

### 4. Wraps

```json
{ "purpose": "dek", "env": "prod", "key_id": 1, "member": "password", "nonce": "...", "wrapped": "..." }
{ "purpose": "dek", "env": "prod", "key_id": 1, "member": "recovery", "epk": "...", "nonce": "...", "wrapped": "..." }
{ "purpose": "names", "env": "", "key_id": 1, "member": "password", "nonce": "...", "wrapped": "..." }
```

- AAD of every wrap: `encode("envy-wrap-v1", project, purpose, env, key_id, member)`.
- `password` member: XChaCha20-Poly1305 under the KEK.
- `recovery` member (and, in phase 2, every X25519 member): an ephemeral X25519 key `epk`;
  `wrap key = HKDF-SHA3-256(salt = epk || recipient public key, ikm = X25519(ephemeral, recipient),
  info = "envy-wrap-x25519-v1")`; then XChaCha20-Poly1305 under it.
- Every DEK and the name key always have a `recovery` wrap.

### 5. Name index

One XChaCha20-Poly1305 blob under the name key, AAD `encode("envy-index-v1", project)`,
holding the map `HMAC -> variable name`. It lets `envy migrate` and the server list what is
stored without the manifest. Nothing else needs it to read a value: the manifest gives the
name and the HMAC is recomputed.

### 6. The file backend

- One JSON file per user and project: `{data dir}/vaults/{project id}.json` (the same data
  folder as the audit log; the id is sanitised the same way). Header: `format`
  (`"envy-file-vault"`), `v` (`1`), `project`, `kdf` (parameters and salt), `kek_check` (a
  sealed constant, so a wrong password is reported before anything else), `recovery`
  (public key), `wraps`, `index`, `records`.
- Writes go to a temporary file in the same folder, are flushed and renamed over the vault.
  On Unix the file is `0600` and the folder `0700`; on Windows the per-user `LOCALAPPDATA`
  ACL applies. A `{file}.lock` created exclusively serialises concurrent writers; an
  existing lock is an error that names the file to remove.
- The password comes from `ENVY_VAULT_PASSWORD` or a prompt, once per run.
- `SecretVault` maps directly: `get` reads the `active` record, `set` marks it `superseded`
  and appends a new `active` one, `keep` prunes the oldest `superseded` records, `history`
  and `get_version` read by version.

### 7. Choosing the backend per project

The precedence of the plan's addendum: `--backend`, then `ENVY_BACKEND`, then the user's
`{data dir}/backends.json` (`{"projects": {"<id>": "file"}}`), then the keyring. The file is
written by `envy migrate`, never by anything committed, so cloning a repository never
changes where your values go. A routing vault picks the backend by project id, so a
workspace member and its root may use different backends without changing the resolver.
A project configured for the file backend whose file is missing is an error, never a silent
fall back to the keyring.

### 8. Commands

- `envy migrate --to file|keyring [--remove-source]`: copies every value and version of the
  project (dates kept; a version without a date gets the migration time), reads them back,
  records the choice in `backends.json`, and only with `--remove-source` deletes the source.
  The first migration to `file` asks for a new password (twice) and shows the recovery key
  once, asking for three of its words back.
- Backend-specific commands are grouped under `envy vault` and fail on a keyring project
  with "this project uses the keyring backend":
  `envy vault password` (new password, re-wraps), `envy vault rekey <env>` (new DEK),
  `envy vault recover` (recovery words → new password), `envy vault recovery-key` (new
  phrase, re-wraps to it). The plan called these `envy rotate --kek/--dek`; that name stays
  free for value rotation in phase 4, so one command does not mean two things.
- Every use of the recovery key and every rekey is recorded in the audit log.

### 9. New dependencies

`chacha20poly1305` 0.11, `hkdf` 0.13, `hmac` 0.13 and `x25519-dalek` 3.0 (all MSRV 1.85, same
RustCrypto generation as `aes-gcm` 0.11 and `sha3` 0.12), plus `sha2` for the BIP-39
checksum. The 2048-word English list is embedded and the encoding is checked against the
BIP-39 test vectors. The `bip39` crate builds on Rust 1.89 too, but brings five crates of the
bitcoin ecosystem for what is a word list and a checksum.

## Consequences

- Records and wraps are the phase 2 wire format: the server stores them as they are and never
  sees a KEK, a DEK in clear, a variable name or a value.
- The file reveals environment names, the number of variables and versions, size classes and
  dates. The variable names it hides are in clear in `envy.json` anyway: the obfuscation
  protects storage and backups, not the repository (SECURITY.md says so).
- Losing both the password and the recovery words loses the values for good.
- A future incompatible format is `v: 2` with new domain labels; `v: 1` keeps being read.

## Alternatives considered

- **AES-256-GCM like the bundles.** Its 96-bit random nonces are fine for a bundle, but a vault
  encrypts many values under one DEK over years; XChaCha20's 192-bit nonces remove the
  collision budget from the picture.
- **One DEK per project.** Simpler, but then giving a CI runner `prod` (phase 2/3) also gives it
  `dev`, and a rekey re-encrypts everything.
- **Names in clear.** Simpler `list`, but backups and the server would carry the full inventory.
- **A SQLite file.** Transactions for free, but a new native dependency on both platforms for a
  file that holds a few hundred records.
