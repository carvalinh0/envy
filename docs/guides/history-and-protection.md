# History, protection, rotation and audit

All of this works on every backend, the plain keyring included.

## History and rollback

Every time a value changes, the old one is kept as a version. `envy history API_TOKEN` lists them
with their dates (never the values) and `envy rollback API_TOKEN` restores the previous one, or
`--to <version>` another. A rollback is itself a new version, so it can be undone.

Five versions are kept per variable; change it with `"history": {"keep": N}` in the manifest (0 to
20, 0 keeps none). `envy rm` removes the versions too, and `envy rename` starts the new name without
history. Values stored by an Envy older than 3.0 show an unknown date until they change.

## Protected environments

```bash
envy protect prod        # asks for a new password, twice
envy run prod -- ./deploy.sh   # asks for it once per run (or reads ENVY_PROTECT_PASSWORD)
```

`envy protect prod` encrypts the values of `prod` stored on your machine, clears their history (it
could hold them unencrypted) and adds `prod` to `protected` in the manifest. From then on every value
written to `prod` is encrypted with a key derived from the password (Argon2id, then AES-256-GCM).
`envy run`, `check`, `export` and `ls --show` ask for the password once per run; `envy ls` without
`--show` does not.

The password belongs to each machine. When a teammate pulls a manifest that protects `prod`,
`envy check` warns them about values stored unencrypted, and `envy protect prod` encrypts them with
their own password. Encrypted values stay encrypted even if an older Envy drops `protected` from the
manifest. Protect `global` too if it holds secrets that a protected environment uses.

## Rotation reminders

```json
"API_TOKEN": { "type": "secret", "rotate": { "every": "90d" } }
```

`envy check` and `envy ls` warn when the stored value is older than that (`h`, `d` or `w`). The exit
code does not change; Envy never changes a value by itself.

## Bundles that expire

`envy export dev --ttl 7d` writes the expiry inside the encrypted bundle, and `envy import` refuses it
after seven days. It prevents a late import by mistake; it is not a lock, since whoever has the bundle
and its key can decrypt it.

## Audit

Envy records who stored, removed, renamed, rolled back, ran, showed (`ls --show`) or exported which
variables, never their values, in a log per project and per user outside the repository (see
[configuration](../configuration.md#files-envy-writes)). `envy audit` prints it and fails if a line was
edited or removed. Without a home folder (some containers) nothing is recorded. A project on a server
also has the server's log: `envy audit --server`.
