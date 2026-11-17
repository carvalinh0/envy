# The manifest: `envy.json`

The manifest is the only file Envy asks you to commit. It holds names, types and non-secret defaults,
never a value. It is validated by [`schemas/v1.json`](../schemas/v1.json), which editors use for
completion; Envy itself has the validation built in.

```json
{
  "$schema": "https://raw.githubusercontent.com/carvalinh0/envy/main/schemas/v1.json",
  "id": "9f8a3b2c-...",
  "name": "My Project",
  "version": 1,
  "checksum": "a3f8b92c10d4e5f6...",
  "schemas": {
    "dev": {
      "PORT": { "type": "port", "default": "3000" },
      "DATABASE_URL": { "type": "url" },
      "API_TOKEN": { "type": "secret", "rotate": { "every": "90d" } }
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

## How `envy init` builds it

`envy init` turns every `.env.<environment>` file of the folder into an environment
(`.env.production` becomes `production`), infers the types from the values (`PORT=3000` is a `port`,
`true` a `boolean`, names with `TOKEN`, `SECRET` or `PASSWORD` a `secret`), stores the values in the
vault and removes the files. `.env.example` provides the names and types of `global` and is never
removed; a plain `.env` has no environment name and is skipped. Edit the result as you like and run
`envy up`.

## Keys

| Key | What it is | Can I edit it? |
| :-- | :-- | :-- |
| `$schema` | URL or path of the JSON Schema, for editors. | Yes. |
| `id` | The project's UUID: the vault finds its values by it. | **No.** Changing it disconnects the values. A copied manifest gets its own id with `envy up --new-id`. |
| `name` | The project's name. | Yes. |
| `version` | Counter bumped on every change of structure. | Managed by Envy. |
| `checksum` | SHA3-256 of the rest of the file, to detect hand edits. | Managed: after editing the file, run `envy up`. |
| `workspace` | Optional. `{ "members": [...] }` makes this a [workspace root](guides/monorepos.md). | Yes, then `envy up`. |
| `history` | Optional. `{ "keep": N }`: older versions kept per value, 0 to 20 (default 5). | Yes, then `envy up`. |
| `protected` | Optional. Environments whose values are encrypted with a password. | Use `envy protect` / `envy unprotect`: added by hand it only applies to values written afterwards. |
| `server` | Optional. URL of the team's Envy server, used by `envy login` without a URL. It never decides where anyone's values are stored. | Yes, then `envy up`. |
| `schemas` | The environments and their variables. | Yes, or with the commands. |
| `schemas.global` | Variables every environment shares; an environment can redeclare them. | Yes. |
| `schemas.<env>.<VAR>` | `{ "type": ..., "default": ..., "rotate": ... }`. | Yes. Names may contain `/`, but not so that two variables share a keyring entry (`a/b` + `C` and `a` + `b/C` are both `a/b/C`): the manifest is refused until one is renamed. |

The optional keys are only hashed when they are present, so a manifest that does not use them keeps
the checksum it had with older releases. An older Envy that rewrites the manifest drops the keys it
does not know; see [compatibility](compatibility.md#data-written-by-one-version-read-by-another).

## Variables

- `type` (required): `i8`, `i16`, `i32`, `i64`, `i128`, `u8`, `u16`, `u32`, `u64`, `u128`, `f32`,
  `f64`, `ip`, `url`, `port`, `uuid`, `base64`, `string`, `boolean`, `iso` (RFC 3339 date-time),
  `cron` (with a seconds field: 6 fields, or 7 with the year) or `secret`.
- `default` (optional): not empty and valid for the type. A `secret` can't have one: the manifest is
  committed.
- `rotate` (optional): `{ "every": "90d" }` (`h`, `d` or `w`). `envy check` and `envy ls` warn when the
  stored value is older than that.

## Where a value comes from

For a variable of an environment, Envy uses the first of:

1. the value stored for that environment (`envy set`, `envy fill`, `envy import`);
2. the value stored for `global`, when `global` declares the variable;
3. in a workspace member, the same two lookups in the root's values;
4. the `default` of the manifest.

With none of them the variable is *missing*: `envy check` and `envy run` fail and `envy fill` asks
for it.
