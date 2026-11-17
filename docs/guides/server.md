# The Envy server

An Envy server keeps the values of a team's projects so nobody passes bundles around. It **never
sees a value or a variable name**: everything is encrypted on the members' machines with the keys of
[ADR 0001](../adr/0001-vault-record-format.md), and everything a member writes is signed with their
key. The protocol is [ADR 0002](../adr/0002-server.md).

## Running it

The image is `ghcr.io/carvalinh0/envy`: a static binary on an empty image, run as a non-root user,
with a read-only root file system and one volume, `/data`. Without Docker, build it on Linux with
`cargo install dot-envy --features server`. See [the Docker examples](../examples/docker.md) for a
complete setup behind Caddy.

```bash
# Once, on an empty data folder: prints (or writes) the root token.
envy serve --data /var/lib/envy --init

# Then, with your certificate:
envy serve --data /var/lib/envy --listen 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem
```

Without `--tls-cert`/`--tls-key` the server only listens on a loopback address, unless
`--behind-proxy` says a TLS proxy (Caddy, Traefik, nginx) is in front. Clients refuse `http://`
anywhere but localhost.

**Backups.** Everything is in `<data>/envy.db` (SQLite). Copy it while the server is stopped, or use
`sqlite3 envy.db ".backup backup.db"`. A backup holds only ciphertext.

**Lost every admin?** On the server host, `envy serve --data <data> --new-root-token` prints a token
that creates one more admin, who can invite and approve members again. An admin reads nothing by
being one: values are only reachable for members who hold keys. If nobody with access to a project
is left, approve a member for it and have them run `envy vault recover` with the project's recovery
key, which wraps every key for them again. Other members only trust what that member writes once an
admin whose access comes from the project's creator grants it write access.

## Team workflow

**First admin.**

```bash
envy login https://envy.example.com --root-token <token> --name felipe
envy migrate --to remote --remove-source   # creates the project, prints its recovery key
```

The root token stops working once used. The recovery key (24 words, shown once) can recover every
key of the project; keep it offline.

**A teammate joins.**

```bash
# admin
envy user add ana                          # prints a one-time invite (24 hours)

# Ana
envy login https://envy.example.com --invite <code> --name ana   # prints her fingerprint

# admin, after Ana sent the fingerprint through another channel
envy user approve ana --fingerprint <fingerprint> --env dev --env staging

# Ana
envy migrate --to remote                   # her local copies never overwrite the server's values
```

Approval fails if the fingerprint is not the key the server holds. Access is per project and
environment, read-only unless `--write`; `--env '*'` gives every environment. A member without access
to `prod` never receives its values.

**Someone leaves.** `envy user rm ana` revokes her sessions and access and replaces the key of every
environment she could read. Change those values: she may have copied them.

**Reading the server's log.** `envy audit --server` shows who logged in, read or changed which
environment.

## CI

Give each pipeline its own member, with access to what it needs only:

```bash
# admin
envy user add ci-prod
# in a checkout of the project: join without storing the identity; keep the printed one as a CI secret
envy login https://envy.example.com --invite <code> --name ci-prod --print-identity
# admin
envy user approve ci-prod --fingerprint <fingerprint> --env prod
```

The job then needs `ENVY_BACKEND=remote`, `ENVY_SERVER` and `ENVY_IDENTITY`. See the
[GitHub Actions](../examples/github-actions.md) and [GitLab CI](../examples/gitlab-ci.md) examples.

## What protects what

- Logins sign a challenge with the member's key and last 12 hours (`--session-ttl`); there is no
  long-lived password or token. Ten failed logins from an address within ten minutes block it for a
  while.
- Every value, key and project state from the server must be signed by a member this machine already
  knows (`envy user list` shows the fingerprints). A changed key, an unsigned value or a state older
  than one already seen is refused.
- Keys are only wrapped for members whose access was signed by an admin trusted from the project's
  creator, and for a recovery key set by such a member: the server can't add a recipient. Values,
  keys and project states are only used when written by such members, so the server can't add a
  writer either.
- If the server is down or misbehaves, commands that need a value fail. Nothing is cached on disk and
  nothing falls back to another backend.

The limits (what the server operator can still do) are in [SECURITY.md](../../SECURITY.md).
