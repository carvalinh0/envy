# Configuration

Envy needs no configuration. These variables change its behaviour when you need them.

## At runtime

| Variable | What it does |
| :-- | :-- |
| `ENVY_BACKEND` | Use this backend for every project: `keyring`, `file` or `remote`. Without it each project uses the backend chosen with `envy migrate` (the keyring by default). The `--backend` option wins over it. |
| `ENVY_VAULT_PASSWORD` | Password of the encrypted file vault, for runs that can't type it. |
| `ENVY_PROTECT_PASSWORD` | Password of [protected environments](guides/history-and-protection.md#protected-environments), for runs that can't type it. |
| `ENVY_SERVER` | URL of the Envy server for projects that have no `envy login` on this machine (CI, containers). |
| `ENVY_IDENTITY` | Member identity for the server, as printed by `envy login --print-identity`, instead of the keyring. |
| `ENVY_NO_UPDATE_CHECK` | Any value: `envy version` does not look for a newer release. |

Variables that hold secrets belong in your CI's secret store, never in a file of the repository.
`envy run` does not pass `ENVY_IDENTITY`, `ENVY_VAULT_PASSWORD` or `ENVY_PROTECT_PASSWORD` on to the
command it starts (unless the manifest declares a variable with that name): the command gets the values
of one environment, not the keys to all of them.

## Files Envy writes

| File | Where | Commit it? |
| :-- | :-- | :-- |
| `envy.json` | The project folder. | **Yes.** It holds no value. |
| `.envy-state` | Next to the manifest: the active environment. | No (add it to `.gitignore`). |
| `backends.json` | Data folder: the backend and server chosen for each project. | No (it is outside the repository). |
| `vaults/<id>.json` | Data folder: encrypted file vaults. | No. Back it up. |
| `audit/<id>.jsonl` | Data folder: the local audit log. | No. |
| `remote/pins.json` | Data folder: the server keys and states this machine trusts. | No. |

The data folder is `$XDG_DATA_HOME/envy` or `~/.local/share/envy` on Linux,
`%LOCALAPPDATA%\envy` on Windows and `~/Library/Application Support/envy` on macOS. Without a home
folder (some containers) there is none: auditing is off, and the file backend and `envy login` can't
be used (`ENVY_SERVER` and `ENVY_IDENTITY` still work).

## At build time

`FILE_NAME` (the manifest's name, `envy.json`) and `SCHEMA_PATH` (written to `$schema` by
`envy init`) are embedded when Envy is compiled, from the `envy.json` of this repository (its
`production` environment for release builds, `development` otherwise). A variable with the same name
overrides them at runtime, which is handy for development and tests:

```bash
FILE_NAME=custom.json SCHEMA_PATH=./schemas/v1.json envy init "My Project"
```
