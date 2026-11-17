# ADR 0002: The Envy server

- Status: Accepted (2026-11-17)
- Phase: 2 and 3 of the plan, released as 4.0
- Builds on: ADR 0001 (records, wraps and keys)

## Context

Teams want to share values without passing bundles around, give CI only what it needs, and
revoke a person in one place. The server must never be able to read a value, and a project
that does not opt in must behave exactly like 3.x.

The twelve decisions taken before this ADR:

1. One crate; the server sits behind the cargo feature `server` (Linux only).
2. axum + tokio for HTTP, confined to the server module.
3. TLS with rustls when a certificate is given; without one the server only listens on a
   loopback address unless `--behind-proxy` is passed. The client refuses `http://` outside
   localhost.
4. SQLite (`rusqlite`, bundled) for storage.
5. Opaque tokens with a TTL, stored hashed.
6. Records and heads signed with the Ed25519 key of their writer; each client remembers the
   last head it saw to detect a server serving old state.
7. Members join with a one-time invite and are approved by an admin who checks their key
   fingerprint out of band; the admin's client wraps the keys for them.
8. Access per project and environment, read or write.
9. Removing a member rekeys the environments they could read and asks for the values to be
   rotated.
10. Phases 2 and 3 together: members, restricted access, server audit, rate limiting.
11. A static, non-root, read-only Docker image published to GHCR by `release.yml`.
12. No offline mode: when the server is down, commands that need a value fail.

## Decision

### Layers

| Layer | Where | Compiled |
| :-- | :-- | :-- |
| Protocol (requests, responses, signed records, heads, wraps) | `remote/protocol.rs` | always |
| Client: `RemoteVault`, HTTP transport, pinned keys | `remote/` | always |
| Server core: authorisation, members, sessions, commits, audit, rate limiting | `server/mod.rs` | always (no I/O, no dependency) |
| In-memory store | `server/memory.rs` | always (tests, like `MemoryVault`) |
| SQLite store, HTTP and TLS, `envy serve` | `server/sqlite.rs`, `server/http.rs` | feature `server` on Linux |

The core and the protocol hold all the logic and run in every `cargo test`: the client talks to
an in-process core through a `Transport`. The feature only adds the network listener and SQLite,
so a plain `cargo install dot-envy` gets no listener, no SQLite and no async runtime. The OS
keyring becomes the default feature `keyring`, so the image builds without `libdbus`
(`--no-default-features --features server`).

### Identity

A member is a 32-byte seed. HKDF-SHA3-256 derives an X25519 key (`info = "envy-member-x25519-v1"`)
for wraps and an Ed25519 key (`"envy-member-ed25519-v1"`) for signatures. The fingerprint shown
to people is the first 16 bytes of SHA3-256(`encode("envy-fingerprint-v1", x25519 public,
ed25519 public)`), in groups of four hex digits. The seed lives in the OS keyring (service
`envy-identity`, user = server URL) or in `ENVY_IDENTITY` for CI. `envy login --print-identity`
prints a new seed once instead of storing it, for CI secrets.

### Protocol

`POST /v1/rpc` with a JSON request tagged by `op`; `GET /v1/health` for probes. Every response
is JSON; errors carry an HTTP status, a stable `code` and a message. Authenticated operations
send `Authorization: Bearer <token>`.

- **Sessions.** `challenge {name}` returns a random nonce (valid two minutes); `session {name,
  nonce, signature}` verifies the Ed25519 signature of `encode("envy-session-v1", server id,
  name, nonce)` and returns a random 256-bit token, stored as its SHA3-256, valid 12 hours by
  default (`--session-ttl`). No long-lived bearer secret exists; the seed never leaves the client.
- **Bootstrap.** `envy serve --init` works only on an empty store and prints a root token once
  (or writes it to `--init-output`, mode `0600`). `bootstrap {root_token, name, keys}` creates an
  admin and burns the token. `envy serve --new-root-token` issues another one on an existing
  store, so the host operator can add an admin after every admin lost their keys (that admin
  still needs the recovery key to read anything).
- **Members.** `member_add {name, admin}` (admin) returns a one-time invite valid 24 hours;
  `join {invite, name, keys}` makes the member `pending`; `member_approve {name, fingerprint}`
  (admin) makes it `active` only if the fingerprint matches; `member_remove {name}` revokes its
  sessions and access and returns the environments it could read; `members` lists names,
  status, admin flag and keys.
- **Access.** `grant {project, access}` (admin), where `access` names the member, the
  environment (or `*`), read or write, carries the member's keys and is signed by the admin over
  `encode("envy-grant-v1", project, member, env, write, keys, approver)`. The server checks the
  signature and that the keys are the ones the member registered. The creator of a project
  signs a grant of `*` with write to itself when it creates the project. Since the security
  fixes after 4.0 a grant also carries a `version`, signed as `encode("envy-grant-v2", ...,
  approver, version)`; a server that takes them says so in `info` (`versioned_grants`), and
  clients send unversioned grants to one that doesn't. Each client keeps the highest version
  it saw per member and environment and refuses older grants.
- **Projects.** `project_create {id, recovery_public, head, wraps, index}` (any active member);
  `project_get {id}` returns the head, the index, the access list, every wrap addressed to the
  caller or to `recovery`, and the records of the environments the caller can read;
  `commit {id, expected_seq, head, add_records, remove_records, add_wraps, remove_wraps, index,
  recovery_public}` applies a delta atomically if the stored head still has `expected_seq`
  (otherwise `409 conflict`, and the client reads again and retries once).
- **Audit.** `audit {project?}` (admin) returns the server's log: bootstraps, joins, sessions,
  member and access changes, reads and commits with the environments they touched.

### Integrity against the server

Records are the ADR 0001 records without `status`, plus `author` and an Ed25519 `signature` over
`encode("envy-record-sig-v1", project, env, key, version, key_id, created_at, nonce,
ciphertext)`. Wraps add `signer` and a signature over `encode("envy-wrap-sig-v1", project,
purpose, env, key_id, member, epk, nonce, wrapped)`. The **head** lists, for every
`(env, key)`, its active version; it carries `seq` and is signed by the writer over
`encode("envy-head-v1", project, seq, entries...)`. Which version is active comes from the
signed head, which closes the gap ADR 0001 left open for the file backend.

**Who receives keys.** A client never wraps a key for a member just because the server lists
it. The root is the project's creator: its self-signed grant is kept by the server with the project
for good (`creator` in `project_get`), and the client pins the creator the first time it sees the
project, or when it creates it. The client trusts every grant the creator signed, even after the
creator was removed (a removed member can't log in to sign anything new), then, repeatedly, grants
signed by a member that already holds a trusted grant with write access to the same environment. Only holders of trusted grants, with the
keys bound in the grant, receive the DEK of a new environment or of a rekey. A member the server
adds can sign nothing in that chain. A member this client once saw removed never receives a key
again, even if the server presents an old grant of it.

The project's recovery key receives every key too, so it is treated the same way: it is signed
by the member that set it (`encode("envy-recovery-v1", project, public key, signer)`), and a
client only wraps keys for it when that member is the creator or holds a trusted grant with write
access to every environment. Each client pins the recovery keys it accepted per project; a key replaced earlier is
refused if the server presents it again. Only a writer of every environment may replace it.

**Who may write.** A valid signature only names the writer, so clients also check the writer's
role against the same chain: a record must be signed by a trusted writer of its environment, a
wrap of an environment's key by a trusted writer of that environment (the name key: by any trusted
writer), and a head by a trusted writer. The creator, and the member reading (for what it signed
itself), always qualify. A member the server added can sign, but nothing it signs is used.

On the server side, a member may wrap keys for itself with read access (that is how `envy vault
recover` works), but giving a key to someone else, or replacing their wrap, takes write access to
the environment or being an admin.

The server checks every signature against the caller's key and the caller's access before it
stores anything. Clients check them again against keys they pinned: the first time a client
sees a member it records the member's keys under the server URL
(`{data dir}/remote/pins.json`); a key that later changes is an error. Clients also record the
highest `seq` seen per project and reject a lower one. A server that is malicious from the very
first contact can still present fake members; `envy user list` shows fingerprints so people can
compare them out of band, and approving a member requires its fingerprint.

### Keys of a remote project

As in ADR 0001: a name key and a DEK per environment, wrapped for each member with access and
for the project's recovery key (shown once by `envy migrate --to remote` on the first push). The
first writer of an environment creates its DEK and wraps it for every member that can read the
environment. `envy user approve` wraps the project's keys for the new member. Removing a member
or `envy vault rekey <env>` replaces the DEK of the environment, re-encrypts its records and
wraps the new DEK for the members that still have access. `envy vault recover` unwraps the
recovery wraps and wraps every key again for the caller.

### Client

`envy login [<url>] [--invite CODE | --root-token TOKEN] [--name NAME] [--print-identity]`
stores the URL for the project in the user's `backends.json` (`remotes`) and, when given an
invite or a root token, creates the identity and joins. A manifest may carry `"server"`, a hint
used only when `envy login` gets no URL. `envy migrate --to remote` creates the project on the
server (or, when it exists, only adds the values the server does not have) and switches the
project to the remote backend. `envy logout` forgets the choice; the server keeps the values.
`envy user add|approve|rm|list` manage members; `envy audit --server` reads the server's log.
A project that uses the remote backend fails when the server cannot be reached; nothing falls
back to another backend and nothing is cached on disk.

### Server operation

`envy serve [--data DIR] [--listen ADDR] [--tls-cert FILE --tls-key FILE] [--behind-proxy]
[--session-ttl HOURS] [--init [--init-output FILE]] [--new-root-token]`. Authentication
failures (`session`, `join`, `bootstrap`) are limited to 10 per client address per 10 minutes
(`429`); behind a proxy the address is the last one of `X-Forwarded-For`, the one the proxy added. Requests over 4 MiB are
refused. The image is `FROM scratch` with a static musl binary, user 65532, a read-only root
file system and one volume, `/data`.

## Consequences

- A stolen database, backup or token reveals no value and no variable name.
- The server still sees who reads and writes which environment and when, the number of values,
  versions, dates and size classes.
- Removing a member cannot take back what they already read: `envy user rm` says to rotate the
  values of the environments they had.
- The server core runs in every test, but the SQLite store and the HTTP layer only run with
  `--features server`; CI needs a step for them (see the pull request).
