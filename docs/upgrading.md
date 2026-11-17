# Upgrading

`envy update` installs the latest release the same way Envy was installed: `cargo install` for a
Cargo install, the prebuilt binary otherwise (falling back to it when `cargo install` fails). Values,
manifests and `.envy-state` are never touched. `envy version` tells you when a newer release exists
(`ENVY_NO_UPDATE_CHECK=1` turns that lookup off); both read
`github.com/carvalinh0/envy/releases/latest` and trust your system's certificate store.

What each major release asks of you is below. See [compatibility](compatibility.md) for what older
releases do with data written by newer ones.

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
