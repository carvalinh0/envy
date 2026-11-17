# Compatibility

What runs where, since which version, and what one version does with data written by another.

## Operating systems

| System | Prebuilt binary | Tested in CI | Since | Notes |
| :-- | :-- | :-- | :-- | :-- |
| Linux x86_64 (glibc) | ✅ `x86_64-unknown-linux-gnu` | ✅ | 1.0 | The binary needs `libdbus-1` at runtime, even if you don't use the keyring. |
| Windows x86_64 | ✅ `x86_64-pc-windows-msvc` | ✅ | 2.0 | Values live in the Credential Manager. |
| Linux arm64, other Linux | ❌ | ❌ | — | `cargo install dot-envy` builds it; untested. |
| macOS | ❌ | ❌ | — | Compiles (Keychain backend included) with `cargo install dot-envy`; untested, so not supported yet. |
| Envy server (Docker) | `ghcr.io/carvalinh0/envy`, linux/amd64 | ✅ (tests run in the image build) | 4.0 | Static binary, no keyring, no `libdbus`. |
| Envy server (binary) | ❌ | ✅ | 4.0 | Linux only: `cargo install dot-envy --features server`. |

Building from source needs Rust 1.89 or newer; on Linux also `pkg-config` and `libdbus-1-dev` (unless
built with `--no-default-features`, which leaves out the keyring).

## Backends on each system

| Backend | Linux desktop | Linux without a desktop session, WSL | Windows | Containers |
| :-- | :-- | :-- | :-- | :-- |
| `keyring` | ✅ needs a running Secret Service (GNOME Keyring, KeePassXC, ...) | ❌ usually no Secret Service | ✅ Credential Manager, values up to 2560 bytes | ❌ |
| `file` (3.0+) | ✅ vault readable only by you | ✅ the recommended backend | ✅ protected by your user profile's permissions | ✅ when `HOME` or `XDG_DATA_HOME` is set |
| `remote` (4.0+) | ✅ | ✅ | ✅ | ✅ with `ENVY_SERVER` and `ENVY_IDENTITY` |

Protected environments store values encrypted, which takes about 4/3 of their size plus 60 bytes:
mind the 2560-byte limit of the Windows Credential Manager. See
[the headless guide](examples/wsl-and-headless.md) for machines without a keyring.

## Features by version

| Feature | Since |
| :-- | :-- |
| Keyring backend, typed schemas, `init`/`set`/`fill`/`check`/`run`/`ls`/`diff`, bundles, workspaces and `check -r` | 1.0 |
| Windows | 2.0 |
| `--backend`/`ENVY_BACKEND`, history and `rollback`, local audit, protected environments, `export --ttl`, `rotate.every` | 3.0 |
| Encrypted file backend, recovery keys, `envy migrate`, `envy vault` | 3.0 |
| Envy server: `serve`, `login`/`logout`, `user`, `migrate --to remote`, `audit --server`, `migrate --fresh` | 4.0 |

## Data written by one version, read by another

Newer releases always read what older ones wrote. Older releases mostly cope with newer data, with
the limits below.

| Data | Format since | An older release... |
| :-- | :-- | :-- |
| `envy.json` | 1.0 (`schemas/v1.json`) | ignores keys it does not know (`history`, `protected`, `rotate` from 3.0; `server` from 4.0) and **drops them** if it rewrites the manifest. A manifest without them keeps its checksum. |
| Keyring values | 1.0: service `envy`, `{project id}/{environment}/{variable}` | reads and writes the active values; it does not see the versions (service `envy-history`, 3.0) and does not record new ones. |
| Values of protected environments | 3.0; bound to their variable since the security fixes after 4.0 (`envy:sealed:v2:`) | reads the encrypted text as if it were the value, so it passes garbage to `envy run`. Update every machine before protecting an environment; values written by a newer release are not readable by 4.0, but the newer release reads the ones 4.0 wrote. |
| Bundles (`.envy`) | 1.0 (`envy-bundle-v1`) | imports them, ignoring `--ttl` (3.0). |
| `.envy-state` | 1.0 | reads it unchanged. |
| File vaults | 3.0 (format v1, [ADR 0001](adr/0001-vault-record-format.md)) | before 3.0, has no file backend. |
| `backends.json` | 3.0; `remotes` added in 4.0 | 3.x ignores the server URLs and drops them if it rewrites the file (after `envy migrate`); a project left on `remote` fails on 3.x instead of using another backend. |
| Server protocol | 4.0 (`/v1`) | clients and servers of the same major version work together. A 3.x client can't use a server. |

## Upgrading

Each major release says what it asks of you in [upgrading](upgrading.md).
For the command line, no major release so far removed or renamed a command, a flag or a manifest key.
