# Backends: where the values live

| Backend | Where | Best for | Since |
| :-- | :-- | :-- | :-- |
| `keyring` (default) | The OS keyring: Secret Service on Linux, Credential Manager on Windows. | A developer machine with a desktop session. | 1.0 |
| `file` | An encrypted file per project in your data folder. | Machines without a keyring: WSL, servers, dev containers. | 3.0 |
| `remote` | An [Envy server](server.md), end-to-end encrypted. | Teams and CI. | 4.0 |

The backend is chosen **per project and per user**: `envy migrate` records the choice in
`backends.json` of your data folder, never in the repository, so a teammate who clones the project
keeps the keyring until they migrate too. `--backend` and `ENVY_BACKEND` force one backend for every
project of a run. A project configured for a backend that can't be reached fails; Envy never falls
back to another backend by itself.

## Moving between backends

```bash
envy migrate --to file                   # copy values and versions, check, switch
envy migrate --to file --remove-source   # ... and delete them from the old backend
envy migrate --to keyring                # back again
```

`envy migrate` copies every value with its versions and dates, reads them back and only then
switches the project. Without `--remove-source` the old backend keeps its copy.

On a machine without a keyring there is nothing to copy and the keyring can't even be read:
start the new backend empty with `--fresh`.

```bash
envy init my-app --new
envy migrate --to file --fresh
envy fill dev
```

## The encrypted file vault

The first migration to `file` asks for a new password (twice, or `ENVY_VAULT_PASSWORD`) and prints a
**recovery key**: 24 words shown once, three of which you type back. Keep them offline: they open the
vault if the password is lost, and nothing else can. Losing both loses the values.

| Command | What it does |
| :-- | :-- |
| `envy vault password` | Change the password. |
| `envy vault rekey <env>` | Encrypt an environment again with a new key. |
| `envy vault recover` | Type the 24 words and set a new password. |
| `envy vault recovery-key` | Replace the recovery key; the old words stop working. |

The vault is one file per project in your data folder, readable only by you on Linux. Values and
variable names are encrypted (XChaCha20-Poly1305 with one key per environment, the keys protected by
Argon2id of the password and by the recovery key). Environment names, the number of values and
versions, their dates and their size in 256-byte steps are visible. The format is
[ADR 0001](../adr/0001-vault-record-format.md). Back the folder up: a deleted vault can't be
recovered.
