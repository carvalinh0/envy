# Upgrading

`envy update` installs the latest release the same way Envy was installed: `cargo install` for a
Cargo install, the prebuilt binary otherwise (falling back to it when `cargo install` fails). Values,
manifests and `.envy-state` are never touched. `envy version` tells you when a newer release exists
(`ENVY_NO_UPDATE_CHECK=1` turns that lookup off); both read
`github.com/carvalinh0/envy/releases/latest` and trust your system's certificate store.

What each major release asks of you is below. See [compatibility](compatibility.md) for what older
releases do with data written by newer ones.

## After 4.0: security fixes

**Command line:**

- `envy migrate --to remote` on a project someone else created on the server stops and shows the
  creator's name and fingerprint. Check it with them and run it again with `--creator <fingerprint>`.
  This is needed once per machine and project.
- `envy login --root-token` needs the URL on the command line; it no longer uses the manifest's
  `server`.
- `envy run` no longer passes `ENVY_IDENTITY`, `ENVY_VAULT_PASSWORD` and `ENVY_PROTECT_PASSWORD` to the
  command. A script that calls `envy` again inside `envy run` must receive them another way.
- Invalid values are reported without the parser's detail (which could quote the value).
- `envy import <file>` without the key asks for it without echo.

**Server:** the image no longer adds `--behind-proxy` by default. A container started without
arguments now refuses to start; pass `--behind-proxy` (with a TLS proxy in front) or `--tls-cert` and
`--tls-key`. The rate limit behind a proxy uses the last `X-Forwarded-For` address. An admin needs
write access to an environment to remove its key wraps, and can't replace the recovery key's wraps.

Grants carry a version. Update the server first: a client only sends versioned grants to a server
that announces them, and grants given by 4.0 stay valid.

**Library (`dot-envy` crate):** `MigrateArgs` gained `creator`, `ImportArgs::key` is an
`Option<String>`, `RemoteVault` gained `unconfirmed_creator`, and `Access` and `ServerInfo` gained
`version` and `versioned_grants`.

## 4.0

**Command line:** nothing to do. Projects keep the backend they had; the server is only used after
`envy login` and `envy migrate --to remote`. `envy.json` may gain an optional `server` key, which
older releases drop when they rewrite the manifest (harmless: it is only a hint). If a project moves
to a server, update every machine that uses it to 4.0.

**Library (`dot-envy` crate):** `Backends` gained `remote` and `identities`, `Config` gained
`server_url` and `identity`, `Commands::Audit` takes `AuditArgs`, `MigrateArgs` gained `fresh`, and
the OS keyring is the default cargo feature `keyring` (`KeyringVault` needs it).

## 3.0

**Command line:** nothing to do. Every command, flag, manifest, keyring entry and bundle of 2.x keeps
working; the new manifest keys (`history`, `protected`, `rotate`) are optional and a manifest without
them keeps its checksum. Two things to know:

- Values stored by 2.x have no recorded date, so `envy history` shows "unknown" for them until they
  change, and `rotate.every` asks you to rotate them once.
- An Envy 2.x that rewrites a 3.0 manifest drops the new keys. Values of protected environments stay
  encrypted, but update every machine of the team to 3.0 before protecting an environment.

**Library (`dot-envy` crate):** the Rust API changed.

- `SecretVault::set` takes a `vault::Change` (`at`, `keep`) after the value, and the trait gained
  `history` and `get_version`. A custom vault can implement `vault::CredentialStore` instead (flat
  `namespace + user -> value` entries) and get the whole trait, history included.
- `Context` gained `backends`, `clock` and `audit`; `Config` gained `user`, `data_dir`,
  `protect_password` and `vault_password` (`Config::new` fills them with defaults).
- `Envy` gained `history` and `protected`, `Bundle` gained `expires_at` and `VarDetail` gained `rotate`
  (empty or `None` behave like 2.x).
