# Command reference

Every command runs from any folder of a project: Envy uses the nearest `envy.json` above the current
folder, up to the root of the Git repository. `envy init` is the exception: it always works in the
current folder.

When a command takes an optional environment and you leave it out, Envy uses the one chosen with
`envy switch`.

**Global options**

| Option | What it does |
| :-- | :-- |
| `-C <dir>` | Run as if Envy was started in `<dir>` (`envy -C services/api check prod`). |
| `--backend <keyring\|file\|remote>` | Use this backend for every project in this run, whatever `envy migrate` chose. `ENVY_BACKEND` does the same. See [backends](guides/backends.md). |
| `-h`, `--help` / `-V`, `--version` | Help of any command / the version. |

**Exit codes:** `0` on success, `1` on any error. `envy check` exits `1` when a value is missing or
invalid, and `envy run` returns the exit code of the command it ran.

Contents: [projects](#projects) · [values](#values) · [history](#history) ·
[protected environments](#protected-environments) · [bundles](#bundles) · [backends](#backends) ·
[server](#server) · [records and maintenance](#records-and-maintenance)

---

## Projects

### `envy init <project-name>`

Creates `envy.json` in the current folder. Every `.env.<environment>` file found there becomes an
environment: its variables are declared with inferred types, its values are stored in the vault and
the file is removed. `.env.example` only provides names and types for `global`; a plain `.env` is
skipped (rename it to `.env.<environment>`). See [the manifest](manifest.md).

| Option | What it does |
| :-- | :-- |
| `--nondestructive` | Keep the `.env` files after storing their values. |
| `--new` | Don't scan for `.env` files; start with an empty manifest. |

### `envy schema [name]`

With a name, creates that environment (empty) and bumps the manifest version. Without one, prints
the environments and their variables.

### `envy switch <environment>`

Makes `<environment>` the default of the commands that take an optional one. It is stored in
`.envy-state` next to the manifest; keep that file out of Git.

### `envy up`

After editing `envy.json` by hand: checks it, recalculates the checksum and bumps the version.

| Option | What it does |
| :-- | :-- |
| `--new-id` | Give the project a new id (for a manifest copied from another project). The values stored for the old id are copied to the new one. |

### `envy diff [environment] [other]`

With no environment or one, lists the variables of that environment that have no value. With two,
compares their declarations (variables only in one of them, and different types).

---

## Values

### `envy set <environment> <variable> <value>`

Stores a value. The variable must be declared in the environment (or in `global`) and the value must
match its type. The value can end up in your shell history; prefer `envy fill`.

### `envy fill [environment]`

Asks, with hidden input, for every variable of the environment that has no value. An empty answer
skips it; three invalid answers in a row skip it too. Fails if something is still missing at the end.

### `envy ls [environment]`

Lists the variables of the environment, their types and their values, masked.

| Option | What it does |
| :-- | :-- |
| `--show` | Print the real values (recorded in the audit log). |

Also warns about values older than their `rotate.every`.

### `envy check [environment] [variable]`

Checks the manifest and that every variable of the environment (or of every environment, `global`
excepted) has a valid value; exits `1` otherwise. With a variable, checks only that one. It also warns
about values due for rotation, protected environments with values stored unencrypted on this machine,
and manifests that share an id with another one.

| Option | What it does |
| :-- | :-- |
| `-r`, `--recursive` | Check every project under the current folder (skips hidden folders, `node_modules`, `target`, `vendor`, `venv` and `__pycache__`). With an environment, projects without it are skipped. |

### `envy run <environment> -- <command> [args...]`

Runs a command with the values of the environment in its environment. Nothing is written to disk.
Fails without starting the command when a value is missing or invalid; otherwise returns the
command's exit code. Envy's own credentials (`ENVY_IDENTITY`, `ENVY_VAULT_PASSWORD`,
`ENVY_PROTECT_PASSWORD`) are removed from the command's environment.

```bash
envy run dev -- npm run dev
```

### `envy rm <variable>` (alias `envy remove`)

Removes the variable from the manifest and its value and versions from the vault.

| Option | What it does |
| :-- | :-- |
| `--from <environment>` | The environment to remove it from (default: the active one). |

### `envy rename <old> <new>`

Renames the variable in the manifest and moves its value. Its history stays with the old name and
is removed. In a protected environment the value is encrypted again for its new name, which asks for
the password.

| Option | What it does |
| :-- | :-- |
| `--in <environment>` | The environment of the variable (default: the active one). |

In a workspace member, `rm` and `rename` of a variable declared by the root must run in the root.

---

## History

### `envy history <variable>`

Lists the stored versions of a value, newest first, with their dates. Values are never printed.

| Option | What it does |
| :-- | :-- |
| `--in <environment>` | The environment of the variable (default: the active one). |

### `envy rollback <variable>`

Restores an earlier version. The restored value becomes a new version, so a rollback can be undone
with another one.

| Option | What it does |
| :-- | :-- |
| `--in <environment>` | The environment of the variable (default: the active one). |
| `--to <version>` | The version to restore (default: the one before the active value). |

How many versions are kept is set in the manifest (`"history": {"keep": N}`). See
[history and protection](guides/history-and-protection.md).

---

## Protected environments

### `envy protect <environment>`

Asks for a new password (twice), encrypts the values of the environment stored on this machine,
clears their history and adds the environment to `protected` in the manifest. Values written to it
from then on are encrypted with the password, and reading them asks for it once per run
(`ENVY_PROTECT_PASSWORD` for CI). A teammate whose manifest already lists the environment runs it to
encrypt their own values.

### `envy unprotect <environment>`

Asks for the password, decrypts the values stored on this machine and removes the environment from
`protected`.

---

## Bundles

### `envy export [environment]`

Writes the project's values (all environments, or one plus `global`) to an encrypted
`<project>.<scope>.envy` file and prints its key once. Send the key through a different channel than
the file.

| Option | What it does |
| :-- | :-- |
| `--ttl <duration>` | Refuse to import the bundle after this long: `12h`, `7d`, `2w`. |

### `envy import <file> [key]`

Stores the values of a bundle exported from the same project (same `id`). Values of undeclared
variables or of the wrong type are skipped. Without `key` it is asked for without echo, which keeps it
out of the shell history, where it would sit next to the file name.

---

## Backends

Where the values of a project live: the OS keyring (default), an encrypted file, or an Envy server.
See [backends](guides/backends.md) and [the server guide](guides/server.md).

### `envy migrate --to <keyring|file|remote>`

Copies every value and its versions to another backend, checks the copy and switches the project to
it on this machine. The first move to `file` creates the vault (new password and recovery key); the
first move to `remote` creates the project on the server (recovery key). When the server already has
the project, only the values it does not have are sent, and if someone else created it this machine
first needs their fingerprint: the creator receives every key of the project.

| Option | What it does |
| :-- | :-- |
| `--remove-source` | Delete the values from the old backend once they are copied and checked. |
| `--fresh` | Start the new backend empty, without reading the old one (for a machine without a keyring). |
| `--creator <fingerprint>` | With `--to remote`: the fingerprint of whoever created the project on the server, checked with them through another channel. Only needed the first time this machine joins a project it did not create. |

### `envy vault <action>`

Manages the keys of a project on the file vault or the server.

| Action | What it does |
| :-- | :-- |
| `password` | Change the password of the file vault (the server has none). |
| `rekey <environment>` | Encrypt the environment again with a new key, its history included. |
| `recover` | Ask for the 24-word recovery key and regain the keys (file vault: then set a new password). |
| `recovery-key` | Replace the recovery key; the old one stops working. |

---

## Server

### `envy login [url]`

Records the project's server for this user (without a URL, the `server` of the manifest). With an
invite or a root token it also creates your identity and joins the server, printing your
fingerprint.

| Option | What it does |
| :-- | :-- |
| `--invite <code>` | Join with an invite from `envy user add`. Needs `--name`. |
| `--root-token <token>` | Become the first admin with the token of `envy serve --init`. Needs `--name` and the URL on the command line (never the manifest's `server`). |
| `--name <name>` | Your member name: letters, digits, `.`, `_` and `-`. |
| `--print-identity` | Print the new identity once instead of storing it in the keyring (for CI secrets). |

Values move to the server with `envy migrate --to remote`.

### `envy logout`

Stops using the server for this project on this machine; it goes back to the keyring. The server
keeps the values.

### `envy user <action>`

Manages the members of the server (admins only, except `list`).

| Action | What it does |
| :-- | :-- |
| `add <name> [--admin]` | Invite a member; prints a one-time invite valid 24 hours. |
| `approve <name> --fingerprint <fp> --env <env>... [--write]` | Activate a member that joined, after comparing its fingerprint with the one it sent you. Repeat `--env` for each environment of this project (`*` for all); `--write` lets it change values. |
| `rm <name>` | Remove a member, revoke its sessions and replace the keys of what it could read. |
| `list` | List members, their status and fingerprints. |

### `envy serve`

Runs an Envy server. Only in Linux builds with the `server` feature and in the Docker image.

| Option | What it does |
| :-- | :-- |
| `--data <dir>` | Folder of the database (default `envy-data`). |
| `--listen <address>` | Address to listen on (default `127.0.0.1:8443`). |
| `--tls-cert <file>` `--tls-key <file>` | Serve https with this certificate and key (PEM). |
| `--behind-proxy` | Plain http on any address, for a TLS proxy in front; the client address is the last one in `X-Forwarded-For` (the one the proxy added). Keep the port reachable only by the proxy. |
| `--session-ttl <hours>` | How long a login lasts (default 12). |
| `--init` | Prepare an empty data folder and print the root token once. |
| `--init-output <file>` | With `--init`: write the root token to this new file instead. |
| `--new-root-token` | Print a root token for an existing server, to add an admin. |
| `--remove-project <id>` | Remove a project and its access from the server and exit, freeing its id. Its values are lost. Only on the host: no request does this. |

Without a certificate the server refuses to listen anywhere but a loopback address unless
`--behind-proxy` is given.

---

## Records and maintenance

### `envy audit`

Prints this project's local audit log (who stored, removed, ran, showed or exported which
variables, never the values) and fails if a line was modified.

| Option | What it does |
| :-- | :-- |
| `--server` | Print the server's log of this project instead (admins). |

### `envy version`

Prints the version and, when a newer release exists, says so (`ENVY_NO_UPDATE_CHECK=1` skips the
lookup).

### `envy update`

Updates Envy the way it was installed: `cargo install` for a Cargo install, the prebuilt binary of
the latest release otherwise. Values, manifests and `.envy-state` are not touched.
