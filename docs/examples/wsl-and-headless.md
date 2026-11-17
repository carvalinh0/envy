# WSL, servers and dev containers (no keyring)

On Linux the default backend needs a running Secret Service, which WSL, SSH sessions, servers and
dev containers usually lack. Use the encrypted [file backend](../guides/backends.md) there.

## A new project

```bash
envy init my-app --new           # an empty manifest: nothing is stored yet
envy schema dev
# declare variables in envy.json, then:
envy up
envy migrate --to file --fresh   # creates the vault: new password and recovery key
envy fill dev
envy run dev -- npm run dev
```

`--fresh` creates the vault without reading the keyring, which this machine can't do. Write the
24-word recovery key down: it is the only way back if the password is lost.

If you already have `.env.<environment>` files, keep them for now (`envy init` would try to store
their values in the keyring), create the project with `--new`, and fill the values with `envy fill`
or `envy set`.

## An existing project

A teammate committed `envy.json`; on this machine:

```bash
envy migrate --to file --fresh
envy fill dev                    # or `envy import <bundle> <key>` with a bundle they exported
```

## Typing the password less often

Envy asks for the vault password once per command. For scripts and long sessions, set
`ENVY_VAULT_PASSWORD` in the environment of that shell only:

```bash
read -rs ENVY_VAULT_PASSWORD && export ENVY_VAULT_PASSWORD
```

Never put it in a dotfile or in the repository.

## Dev containers

Mount a volume on the data folder so the vault survives rebuilds, for example in
`.devcontainer/devcontainer.json`:

```json
{
  "mounts": [
    "source=envy-data,target=/home/vscode/.local/share/envy,type=volume"
  ]
}
```

On a team with an [Envy server](../guides/server.md), `envy login` and `envy migrate --to remote`
(with `--creator` when someone else created the project) avoid the vault altogether: values stay on the server and each member has their own identity.
