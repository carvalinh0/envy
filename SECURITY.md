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
