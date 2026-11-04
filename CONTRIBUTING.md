# Contributing to Envy

Thanks for helping! This guide explains how the code is organised and what a good pull request looks like.

## Setup

You need Rust **1.89+**. On Linux also install `pkg-config` and `libdbus-1-dev` (the keyring uses D-Bus).

```bash
git clone https://github.com/carvalinh0/envy
cd envy
cargo test
```

Set `ENVY_NO_UPDATE_CHECK=1` when running `envy version` often, to skip the network lookup.

Run Envy from the source tree:

```bash
cargo run -- check dev
```

`FILE_NAME` and `SCHEMA_PATH` are embedded at build time by `build.rs` from this repository's `envy.json` (`production` for `--release`, `development` otherwise). Edit `envy.json` and run `envy up` to refresh its checksum and bump its version. An environment variable with the same name overrides the embedded value.

## Before opening a PR

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Every change needs tests: **unit tests** next to the code for logic, and **integration tests** in `tests/` for behaviour of commands. A bug fix starts with a failing test.

## Commit messages

The `main` branch is tagged automatically from the commit message (`.github/workflows/release.yml`):

| Message | Bump |
| :-- | :-- |
| `feat!: ...` | Major |
| `feat: ...` | Minor |
| `fix: ...` or anything else | Patch |

The tag action looks for `feat!:` and `feat:` **anywhere** in the messages of every commit pushed since the last tag, body included. Never write those strings in a commit body (not even quoted), or the push gets a bigger bump than intended.

## Architecture

Commands depend on abstractions, never on the operating system directly (SOLID):

| Module | Responsibility |
| :-- | :-- |
| `cli` | `clap` definitions of arguments and subcommands. |
| `app` | Routes a parsed command to its handler. |
| `commands/*` | One file per command. Each exposes `run` and receives a `Context`. |
| `context` | The dependencies a command needs, as trait objects. |
| `config` | `FILE_NAME`, `SCHEMA_PATH` (build-time defaults plus environment override), `-C` and paths. |
| `workspace` | Finding manifests: the project above the current folder, the workspace root of a member and every manifest of a tree. |
| `envy` | The manifest: model, checksum, structural validation and schema changes. |
| `schema` | Variable types, value parsing and the redacting `Secret` type. |
| `resolver` | Effective value of each variable (vault, `global`, workspace root, default). |
| `vault` | `SecretVault` trait, `KeyringVault` (production) and `MemoryVault` (tests). |
| `state` | `StateStore` trait and the `.envy-state` file. |
| `bundle` | `BundleCodec` trait and the AES-256-GCM implementation. |
| `dotenv`, `inference` | Reading `.env` files and guessing types (`TypeInferrer` trait). |
| `update` | Self-update: `ReleaseSource` (GitHub), version comparison, archive extraction and `SelfUpdater`. |
| `prompt`, `runner` | `Prompter` and `ProcessRunner` traits and their real implementations. |

To add a command: add its arguments to `cli.rs`, create `commands/<name>.rs`, register it in `commands/mod.rs` and `app.rs`, then add tests in `tests/`. Depend on the traits in `Context`; if you need something new from the OS, introduce a trait first.

### Testing

`tests/common/mod.rs` has a `Harness` that runs real arguments through `app::dispatch` with an in-memory vault, a scripted prompter and a recording process runner. Network access is behind `ReleaseSource`, and replacing the executable behind `SelfUpdater`, so the update tests never touch GitHub or the installed binary. `tests/cli_binary.rs` exercises the compiled binary and only uses commands that do not need a keyring.

## Reporting issues and security problems

Use the issue templates for bugs and features. For vulnerabilities follow [SECURITY.md](SECURITY.md); never open a public issue.
