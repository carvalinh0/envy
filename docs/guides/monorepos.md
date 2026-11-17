# Monorepos

Give each service its own manifest with `envy init` inside its folder. Each manifest has its own
`id`, so its values are kept apart from the other services, and its own `.envy-state`, so each
service can have a different active environment.

```
monorepo/
├── envy.json            # workspace root (optional)
├── services/api/        envy.json  .envy-state
├── services/worker/     envy.json  .envy-state
└── apps/web/            envy.json  .envy-state
```

Turborepo, Nx and pnpm run the scripts of a package inside its folder, so
`"dev": "envy run dev -- node server.js"` in each `package.json` just works.

## Sharing variables with a workspace root

A manifest with a `workspace` key is a workspace root: the projects listed in `members` inherit its
environments and variables. Members are paths relative to the root with `/` separators; `*` and `?`
match inside a folder name and `**` any number of folders.

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

Run `envy up` after adding the `workspace` key. Then:

- A member has its own environments **and** the root's: `services/api` gets `prod` even when its
  manifest does not declare it. The root's `global` reaches every environment of every member.
- When both declare a variable, the member's declaration (type and default) wins.
- Values stored for the member win over values stored for the root. `envy set` and `envy fill` store
  values for the project you are in, so in a member they override the shared value for that member
  only. To change a shared value, run the command in the root (`envy -C ../.. set prod ...`).
- `envy rm` and `envy rename` of an inherited variable must run in the root.
- `envy export` in a member only exports the member's own values; export the root separately.
- Inheritance has one level: a member's own `workspace` key only affects its own members.
- Each project can use its own [backend](backends.md): a member on the file vault still inherits
  from a root on the keyring.

## Checking every project

```bash
envy check -r          # every environment of every project under the current folder
envy check -r prod     # projects without a `prod` environment are skipped
```

It searches the folders below the current one (skipping hidden folders, `node_modules`, `target`,
`vendor`, `venv` and `__pycache__`), prints one line per project and fails if any project fails. It
also fails when two manifests have the same `id`, which happens when a manifest is copied to another
service: both would read and write the same values. Fix it with `envy up --new-id` in the copy.
