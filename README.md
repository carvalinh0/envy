# Envy

## What's Envy?

Envy is a tool that stores all your project `.env` files in a secure local vault and prevents them from being leaked or stolen — whether due to forgetting to add `.env` to `.gitignore`, or accidentally sharing sensitive files with LLMs and chat applications.

The values live in your operating system's keyring (Secret Service on Linux, Keychain on macOS, Credential Manager on Windows). Only the **schema** (names, types and non-secret defaults) is written to a file, so it is safe to commit.

### How Envy helps you

1. **Protects your secrets:** Prevents accidental exposure of raw environment variables.
2. **Facilitates secure sharing:** Allows you to export and share encrypted environment bundles during conversations or code reviews.
3. **Typechecks variables:** Validates your environment variables against a schema to prevent production code from receiving invalid values.
4. **Versions environment schemas:** Makes it safe and predictable to manage changes across different releases.
5. **Multi-environment support:** Easily manage distinct schemas for `dev`, `staging`, `prod`, etc.
6. **Safe interactive editing:** View and update secrets without opening `.env` files on screen during video calls or live streams.
7. **Safe use of env values in the code:** Instead of writing check scripts inside your code for each programming language to prevent errors, Envy does it for you.

## Support

| Environment | Supported | Version |
| :---------- | :-------: | :-----: |
| Linux | ✅ | All |
| Windows | ❌ | ^1.0.0 |
| MacOS | ❌ | None yet |
| Docker containers | ❌ | None yet |

> The keyring backends for macOS and Windows are compiled in, but only Linux is tested for now.
> On Linux you need a running Secret Service (GNOME Keyring, KeePassXC, ...) and `libdbus` to build from source.

## How to install

MacOS & Linux

```bash
curl -fsSL https://raw.githubusercontent.com/carvalinh0/envy/main/scripts/install.sh | bash
```

Windows

```shell
powershell -c "irm https://raw.githubusercontent.com/carvalinh0/envy/main/scripts/install.ps1|iex"
```

Docker

```bash
docker pull envy:latest
```

Cargo

```bash
cargo install dot-envy
```

The install scripts use `cargo install dot-envy` when Cargo is available and fall back to the prebuilt binary of the latest GitHub release when it is not (or when `cargo install` fails). The binary is copied to `~/.local/bin` (Linux/macOS) or `%LOCALAPPDATA%\envy\bin` (Windows); set `ENVY_INSTALL_DIR` to change it and `ENVY_VERSION` to pin a release (e.g. `v1.2.3`). Building with Cargo needs Rust **1.89 or newer**. The installed binary is called `envy`.

> Prebuilt binaries are currently published for Linux x86_64 only; they need `libdbus-1` at runtime (`sudo apt install libdbus-1-3`) and a running Secret Service.

## Configuration

You do not need to configure anything: the binary already knows the two values it needs. They are embedded **at build time** from the `envy.json` of this repository (`production` environment for release builds, `development` for any other profile), so changing them there is enough for the next release to ship with the new values.

| Variable | What it is | Current value (release) |
| :-- | :-- | :-- |
| `FILE_NAME` | Name of the manifest file in the current folder. | `envy.json` |
| `SCHEMA_PATH` | Value written to the `$schema` key of manifests created by `envy init`. It is a URL, so the schema is not needed on your machine. | `https://raw.githubusercontent.com/carvalinh0/envy/main/schemas/v1.json` |

Envy never reads the schema file at runtime: validation is built into the binary and `$schema` only helps your editor with completion.

An environment variable with the same name overrides the embedded value, which is useful for development and tests:

```bash
FILE_NAME=custom.json SCHEMA_PATH=./schemas/v1.json envy init "My Project"
```

The active environment (`envy switch`) is stored in a local `.envy-state` file. **Do not commit it** (add it to your `.gitignore`).

## Usage

Envy is simple and intuitive to use. Check the examples below:

```bash
# Shows a help message with all commands
envy help

# Shows the current version of envy. If a newer release exists it also tells you so
# (set ENVY_NO_UPDATE_CHECK=1 to skip that lookup).
envy version

# Update envy to the latest release
envy update

# Creates an envy.json file in your current folder and automatically detects any existing
# .env.<environment> file, storing its values securely in your local vault and removing the
# file. The generated manifest contains no raw secrets and is safe to commit to Git.
# Use --nondestructive to keep the .env files in your folder, or --new to skip the scan
# and leave your .env files untouched.
envy init <project-name>

# Import an encrypted [project_name.scope].envy bundle into your local vault.
# The bundle must have been exported from the same project (same id in envy.json).
envy import <path/to/file> <key>

# Switch the active environment context (e.g., dev, prod)
envy switch <env-name>

# Create a new schema (environment) in envy.json and automatically bump the version,
# or visualize your actual schema
envy schema <schema-name>
envy schema

# Check for any manual or external changes in the schema.
# If changes are detected, recalculates the checksum and bumps the version.
envy up

# Give the project a new id, for a manifest that was copied from another project.
# The values stored for the old id are copied to the new one.
envy up --new-id

# Set a variable inside your local vault for the current project.
# The variable must be declared in the schema and the value must match its type.
envy set <environment> <secret> <value>

# Remove a variable from your local vault and from the schema, bumping the schema version.
# Without --from the active environment is used. `envy remove` is an alias.
envy rm <secret> [--from <environment>]

# Rename a variable in your local vault and in the schema, bumping the schema version.
# Without --in the active environment is used.
envy rename my_secret my_secret_renamed [--in <environment>]

# Export your project secrets into an encrypted [project_name.scope].envy bundle
# to share securely with another developer. A random 256-bit key is generated and
# printed ONCE: send it through a different channel than the bundle.
envy export     # Exports all environments
envy export dev # Exports only dev (and global) secrets

# Run your project with environment variables injected directly into the child process.
# Fails without starting the command if any variable is missing or invalid.
envy run <dev> -- npm run dev

# Open an interactive prompt (hidden input) to fill in the variables that have no value yet
envy fill dev

# Check if all required environment variables are set and valid, and fail (exit code 1) if not
envy check          # Every environment
envy check prod
envy check prod DATABASE_URL
envy check -r       # Every project under the current folder (see "Monorepos")
envy check -r prod

# Show missing keys from the schema or compare two environment schemas
envy diff          # Show all missing keys for the active environment
envy diff dev      # Show missing keys for dev
envy diff dev prod # Compare differences between dev and prod schemas

# List all project environment keys securely (values masked by default)
envy ls [environment] [--show]
```

When an environment is optional and omitted, Envy uses the one selected with `envy switch`.

Every command works from any subfolder of a project: Envy looks for the manifest in the current folder,
then in its parents, up to the root of the Git repository (the first folder with a `.git`). `envy init`
is the exception and always creates the manifest in the current folder. `-C <dir>` runs Envy as if it
was started in `<dir>`:

```bash
envy -C services/api check prod
```

## Monorepos

Give each service its own manifest with `envy init` inside its folder. Each manifest has its own `id`,
so its secrets are kept apart from the other services, and its own `.envy-state`, so each service can
have a different active environment.

```
monorepo/
├── envy.json            # workspace root (optional)
├── services/api/        envy.json  .envy-state
├── services/worker/     envy.json  .envy-state
└── apps/web/            envy.json  .envy-state
```

Tools like Turborepo, Nx and pnpm run the scripts of a package inside its folder, so
`"dev": "envy run dev -- node server.js"` in each `package.json` just works.

### Sharing variables with a workspace root

A manifest with a `workspace` key is a workspace root: the projects listed in `members` inherit its
environments and variables. Members are paths relative to the root with `/` separators; `*` and `?`
match inside a folder name and `**` matches any number of folders.

```json
{
  "id": "...",
  "name": "Monorepo",
  "version": 1,
  "checksum": "...",
  "workspace": { "members": ["services/*", "apps/web"] },
  "schemas": {
    "prod": { "DATABASE_URL": { "type": "url" } },
    "global": { "REGION": { "type": "string", "default": "sa-east-1" } }
  }
}
```

Run `envy up` after adding the `workspace` key to refresh the checksum. Then:

- A member has its own environments **and** the root's ones: `services/api` gets `prod` even when its
  manifest does not declare it. The root's `global` reaches every environment of every member.
- When both declare a variable, the member's declaration (type and default) wins.
- Values stored for the member win over values stored for the root. `envy set` and `envy fill` always
  store values for the project you are in, so in a member they *override* the shared value only for
  that member. To change a shared value, run the command in the root (`envy -C ../.. set prod ...`).
- `envy rm` and `envy rename` of an inherited variable must be run in the root.
- `envy export` in a member only exports the member's own values; export the root separately.
- Inheritance has one level: a member's own `workspace` key only affects its own members.

### Checking every project

```bash
envy check -r          # every environment of every project under the current folder
envy check -r prod     # projects without a `prod` environment are skipped
```

It searches the folders below the current one (skipping hidden folders, `node_modules`, `target`,
`vendor`, `venv` and `__pycache__`), prints one line per project and fails (exit code 1) if any project
fails. It also fails when two manifests have the same `id`, which happens when a manifest is copied to
another service: both would read and write the same secrets. `envy up` and `envy check` warn about it as
well. Fix it by running `envy up --new-id` in the copied project.

## Updating

```bash
envy update
```

`envy update` keeps the way you installed Envy: a binary installed with Cargo (`~/.cargo/bin`) is updated with `cargo install dot-envy --version <latest>`, any other copy is replaced with the prebuilt binary of the latest release. If `cargo install` fails, the prebuilt binary is used instead. Your vault, `envy.json` and `.envy-state` are never touched.

`envy version` also checks, once per run, whether a newer release exists and prints a hint. The check is best effort (being offline is silently ignored), only happens in `envy version` and can be disabled with `ENVY_NO_UPDATE_CHECK=1`. Both commands read `github.com/carvalinh0/envy/releases/latest` and trust your operating system's certificate store.

> Prebuilt binaries are published for Linux x86_64 for now; on other platforms `envy update` only works for Cargo installs.

## Explaining the envy.json Manifest File

When you use `envy init` it automatically detects `.env.<environment>` files in your current folder and
stores their values in the local vault. A `.env.development` becomes an environment called `development`,
the same for `.env.production` or `.env.test`. The types are inferred from the values (for instance
`PORT=3000` becomes `port`, `true` becomes `boolean` and names containing `TOKEN`, `SECRET` or `PASSWORD`
become `secret`); edit the manifest if you want something different.

A `.env.example` file is understood as the `global` environment (see below): only its variable names and
types are used, its values are never stored and the file is never removed. A plain `.env` has no environment
name, so it is skipped and left untouched; rename it to `.env.<environment>` first.

This is an example of what `envy init` generates:

```json
{
  "$schema": "./schemas/v1.json",
  "id": "9f8a3b2c-...",
  "name": "My Project Name",
  "version": 1,
  "checksum": "a3f8b92c10d4e5f6...",
  "schemas": {
    "dev": {
      "PORT": { "type": "port", "default": "3000" },
      "DATABASE_URL": { "type": "url" },
      "API_TOKEN": { "type": "secret" }
    },
    "prod": {
      "DATABASE_URL": { "type": "url" }
    },
    "global": {
      "APP_NAME": { "type": "string", "default": "my-app" }
    }
  }
}
```

The file is validated by [`schemas/v1.json`](schemas/v1.json).

### Explaining each key

| Key Name | What it is | Is it safe to change? |
| :-: | - | - |
| $schema | Path or URL of the JSON Schema that describes this file (used by editors for completion). | Yes |
| id | Unique UUID generated by Envy to map your project to its corresponding secrets in the local vault. | No! Modifying this value disconnects the repository from your local vault secrets. |
| name | The name of the project (declared with the command `envy init "My Project Name"`). | Yes |
| version | Schema version counter used by Envy to ensure stored local values match the expected structure. | Auto-managed. Envy automatically bumps this version whenever schema structure changes. |
| checksum | SHA3-256 integrity hash of the file content (except the checksum itself) used to detect manual edits and git updates. | Auto-managed. If edited manually, run `envy up` to recalculate it and bump the version. |
| workspace | Optional. Makes the manifest a workspace root; `members` lists the projects that inherit it (see [Monorepos](#monorepos)). | Yes. Run `envy up` afterwards. |
| schemas | Container object holding variable type definitions and defaults for each environment. | Yes. You can edit variable types, add defaults, or modify schemas manually or via CLI commands. |
| schemas.global | Variables shared across all environments in the project. An environment can override them. | Yes. |
| schemas.&lt;env&gt; | Environment-specific definitions (e.g., dev, prod). Each variable is an object `{ "type": "...", "default": "..." }`. | Yes. |

### Variable types

`i8`, `i16`, `i32`, `i64`, `i128`, `u8`, `u16`, `u32`, `u64`, `u128`, `f32`, `f64`, `ip`, `url`, `port`, `uuid`, `base64`, `string`, `boolean`, `iso`, `cron`, `secret`.

- `default` is optional, must not be empty and must be a valid value for the type.
- A `secret` can **not** have a default, because the manifest is committed to Git.
- `iso` is an RFC 3339 date-time and `cron` is a cron expression with a seconds field (6 fields, or 7 with the year).

### Where does a variable's value come from?

For an environment, Envy looks (in this order) at:

1. the value stored in the vault for that environment (`envy set`, `envy fill`, `envy import`);
2. the value stored in the vault for `global`, when `global` declares the variable;
3. for a workspace member, the same two lookups in the vault of the workspace root;
4. the `default` written in the manifest.

If none exists the variable is *missing*: `envy check` and `envy run` fail and `envy fill` asks for it.

## Development

You need Rust **1.89 or newer**, `pkg-config` and `libdbus-1-dev` (Linux).

```bash
cargo test                                  # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The tests never touch your real keyring: commands receive their dependencies (vault, prompt, process runner, bundle codec) through traits, and the tests plug in fakes. See [CONTRIBUTING.md](CONTRIBUTING.md) for the architecture.

## Contributing

Contributions are always welcome! Whether you're fixing bugs, improving documentation, or proposing new features, feel free to contribute to Envy. The full guide is in [CONTRIBUTING.md](CONTRIBUTING.md).

1. Fork the repository and create your branch:

```bash
git checkout -b feature/my-amazing-feature
```

2. Make sure your code passes all tests and formatting checks:

```bash
cargo test
cargo clippy
cargo fmt --check
```

3. Commit your changes:

```bash
git commit -m "feat: add my amazing feature"
```

4. Push to your branch and open a Pull Request describing your changes.

## Reporting Issues

If you find a bug or have a suggestion, please open a GitHub Issue.

When submitting a bug report, please include:

- Your operating system and Envy version (`envy --version`).
- Clear, step-by-step instructions to reproduce the problem.
- Expected behavior versus actual behavior.

## Security Policy

Because Envy manages sensitive environment secrets, security is our top priority. The full policy and threat model are in [SECURITY.md](SECURITY.md).

If you discover a security vulnerability or exploit, please do not open a public GitHub issue.

Instead, report it privately:

- Submit a private disclosure via GitHub Security Advisory.
- Or email the maintainer directly at contact@carvalinho.dev.

Please include steps to reproduce or a proof of concept (PoC) if applicable. We will acknowledge receipt within 48 hours and work on a patch promptly.
