# Envy

Envy keeps your project's `.env` values out of your files: they live in a vault (your OS keyring, an
encrypted file, or a team server that never sees them), and only a **schema** of names, types and
non-secret defaults is committed. Nothing leaks because someone forgot `.gitignore`, pasted a file
into a chat, or shared their screen.

- **Typed values.** `envy check` and `envy run` refuse a missing or invalid value before your code
  starts, whatever language it is written in.
- **Environments.** `dev`, `staging`, `prod` and a shared `global`, in one project or a monorepo.
- **History and protection.** Every change is kept and can be rolled back; sensitive environments can
  require a password; a local audit log records who used what.
- **Sharing.** Encrypted bundles for a quick hand-over, or an end-to-end encrypted server for a team
  and its CI.

## Install

| System | Command |
| :-- | :-- |
| Linux | `curl -fsSL https://raw.githubusercontent.com/carvalinh0/envy/main/scripts/install.sh \| bash` |
| Windows | `powershell -c "irm https://raw.githubusercontent.com/carvalinh0/envy/main/scripts/install.ps1\|iex"` |
| Any system with Rust 1.89+ | `cargo install dot-envy` |
| Envy server (Docker) | `docker pull ghcr.io/carvalinh0/envy` |

The scripts use `cargo install` when Cargo is available and the prebuilt binary otherwise, copied to
`~/.local/bin` (Linux) or `%LOCALAPPDATA%\envy\bin` (Windows); `ENVY_INSTALL_DIR` changes the folder
and `ENVY_VERSION` pins a release. Prebuilt binaries exist for Linux and Windows on x86_64; the Linux
one needs `libdbus-1` (`sudo apt install libdbus-1-3`). macOS builds with Cargo but is not tested yet.
See [compatibility](docs/compatibility.md) for every system, backend and version.

## Quick start

```bash
cd my-project
envy init my-project      # turns .env.<environment> files into envy.json, stores their values, removes them
envy switch dev
envy check                # every variable set and valid?
envy run dev -- npm run dev
git add envy.json         # safe to commit: no values inside
```

A teammate who clones the project runs `envy fill dev` to type their own values, or imports a bundle
you sent them (`envy export dev`, then `envy import <file> <key>`). On a machine without a keyring
(WSL, servers, containers), see [the headless guide](docs/examples/wsl-and-headless.md).

## Documentation

**Using Envy**

- [Command reference](docs/commands.md): every command and option.
- [The manifest](docs/manifest.md): `envy.json`, variable types, where a value comes from.
- [Configuration](docs/configuration.md): environment variables and the files Envy writes.
- [Compatibility](docs/compatibility.md): systems, backends, versions and data across versions.
- [Upgrading](docs/upgrading.md): what each major release changes.

**Guides**

- [Monorepos](docs/guides/monorepos.md): a manifest per service, a shared workspace root.
- [History, protection, rotation and audit](docs/guides/history-and-protection.md).
- [Backends](docs/guides/backends.md): keyring, encrypted file, server; moving between them.
- [The Envy server](docs/guides/server.md): running it, inviting a team, CI identities.

**Examples**

- [GitHub Actions](docs/examples/github-actions.md) and [GitLab CI](docs/examples/gitlab-ci.md).
- [Docker](docs/examples/docker.md): the server, and Envy inside your application's image.
- [WSL, servers and dev containers](docs/examples/wsl-and-headless.md).

**Design**

- [ADR 0001](docs/adr/0001-vault-record-format.md): encrypted records and keys.
- [ADR 0002](docs/adr/0002-server.md): the server protocol.
- [SECURITY.md](SECURITY.md): what Envy protects, and what it does not.

## Development

You need Rust 1.89 or newer and, on Linux, `pkg-config` and `libdbus-1-dev`.

```bash
cargo test --all-targets
cargo test --all-targets --features server    # the server's SQLite store and HTTP listener (Linux)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The tests never touch your keyring, the network or your installed Envy. The architecture and the
rules for contributions are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting issues

Open a GitHub issue with your system, `envy --version`, the steps to reproduce and what you expected.

**Security problems** must not go to public issues: use a private GitHub Security Advisory or write
to contact@carvalinho.dev. See [SECURITY.md](SECURITY.md).
