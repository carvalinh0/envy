# Security Policy

Envy manages sensitive environment secrets, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Report them privately:

- Submit a private disclosure via GitHub Security Advisory, or
- Email the maintainer at contact@carvalinho.dev.

Include steps to reproduce or a proof of concept if you have one. We will acknowledge receipt within 48 hours and work on a patch promptly.

## Supported versions

Only the latest released version receives security fixes.

## How Envy protects your secrets

- **Storage:** values are stored in the operating system keyring, one entry per `project id / environment / variable`. Envy never writes raw values to disk, except to the `.env` files you already had before `envy init` (which are removed unless you pass `--nondestructive`).
- **File vault (`envy migrate --to file`):** one file per project in the user's data folder, `0600` on Unix. Every version of every value is encrypted with XChaCha20-Poly1305 under a random key per environment, padded to 256-byte steps; the associated data binds it to its project, environment, variable, version, key and date, so records can't be moved or redated. Variable names are replaced by an HMAC-SHA3-256 under a random per-project key. The environment keys and the name key are wrapped for the password (Argon2id, 19 MiB, 2 passes) and for the recovery key (X25519). The password and the recovery key are never stored. Writes are atomic, under a lock, and refuse to overwrite a file changed by another process. See `docs/adr/0001-vault-record-format.md`.
- **History:** the previous values of a variable (5 by default) are kept in the keyring too, under the service `envy-history`, with an index of their dates. `envy rm` removes them; `"history": {"keep": 0}` keeps none.
- **Protected environments:** values of an environment listed in `protected` are encrypted before they reach the keyring: AES-256-GCM with a key derived from the password by Argon2id (19 MiB, 2 passes), a random 128-bit salt and a random nonce per value. The password is never stored; a sealed constant in the environment's reserved entry checks it. `envy protect` clears the history of the environment, which could hold earlier values unencrypted.
- **Audit:** a local log per project and per user records which variables were stored, removed, renamed, rolled back, run, shown or exported, by whom and when. It never contains values. Each line carries the SHA3-256 of the previous one.
- **Bundle expiry:** `envy export --ttl` writes the expiry inside the encrypted payload, so it cannot be changed without the key.
- **Manifest:** `envy.json` holds only names, types and non-secret defaults. Variables of type `secret` cannot have a default.
- **Memory:** values are kept in types that are wiped on drop (`zeroize`) and print as `********` in `Display`/`Debug`. Error messages never include values.
- **Bundles:** `envy export` encrypts with AES-256-GCM using a random 256-bit key and a random nonce per bundle. The key is printed once and never stored. Any change to the file makes decryption fail.
- **Updates:** `envy update` downloads over HTTPS from the project's GitHub releases (or runs `cargo install`) and replaces the executable atomically, so a failed download or a corrupted archive leaves the current binary untouched.
- **Project binding:** a bundle only imports into a project with the same `id`.

## What Envy does not protect against

Knowing the limits helps you use it safely:

- **Same-user access.** Any process running as you can read your keyring while it is unlocked, and can read the environment of the processes started by `envy run`.
- **Shell history.** `envy set <env> <name> <value>` receives the value as an argument, so it can end up in your shell history and the process list. Prefer `envy fill`, which reads hidden input.
- **`envy ls --show`** prints real values to your terminal.
- **Sharing the key with the bundle.** Send the export key through a different channel than the `.envy` file.
- **`.envy-state`** only stores the active environment name, but should still stay out of Git.
- **Update integrity.** Releases do not publish checksums or signatures yet, so `envy update` trusts GitHub and TLS only.
- **Windows and macOS** keyring backends are compiled in but not tested yet.
- **Protection is per machine.** A teammate's values are only encrypted after they run `envy protect` themselves (`envy check` warns them). Values of `global` and of a workspace root are only protected if those environments are. A process running as you can still read the environment of `envy run`, and an attacker who learns the password can decrypt the values copied from your keyring offline.
- **Older releases.** An Envy older than 3.0 that rewrites the manifest drops `protected`, `history` and `rotate`. Encrypted values stay encrypted (it injects them as ciphertext), but values it writes are stored unencrypted and outside the history.
- **The audit log is yours.** Anyone who can write the file can rewrite the whole chain, and the newest line is only covered once a later event is written. It detects accidental or careless edits, not a determined attacker with your account.
- **What the file vault reveals.** Environment names, how many values and versions exist, their dates and their size class are visible to whoever reads the file. Variable names are hidden there, but they are in clear in `envy.json` anyway.
- **The file vault is yours too.** Whoever can write the file can delete it, or make an older version of a value active again (the active flag is not authenticated, so it can change without re-encryption). Keep backups of the folder if the values matter.
- **The recovery key opens everything.** Keep it offline. Without the password and without the recovery key the values are lost for good; nobody, including the Envy maintainers, can recover them.
- **Bundle expiry is a convenience.** Releases older than 3.0 ignore it, and whoever has the bundle and the key can decrypt it at any time.
