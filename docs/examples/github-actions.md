# GitHub Actions

A pipeline reads its values from the [Envy server](../guides/server.md) with an identity of its own,
approved only for the environments it needs. Nothing is stored on the runner.

## One-time setup

```bash
# an admin, in the project
envy user add ci-prod

# anyone, in a checkout of the project: prints the identity once instead of storing it
envy login https://envy.example.com --invite <code> --name ci-prod --print-identity

# the admin, with the fingerprint printed above
envy user approve ci-prod --fingerprint <fingerprint> --env prod
```

Store the printed `envy-identity-v1:...` line as the repository secret `ENVY_IDENTITY`
(Settings → Secrets and variables → Actions).

## Deploy with the values of `prod`

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      ENVY_VERSION: v4.0.0
      ENVY_BACKEND: remote
      ENVY_SERVER: https://envy.example.com
      ENVY_IDENTITY: ${{ secrets.ENVY_IDENTITY }}
    steps:
      - uses: actions/checkout@v4

      # The prebuilt binary is faster than `cargo install`; the runner already has libdbus.
      - name: Install Envy
        run: |
          name="envy-${ENVY_VERSION}-x86_64-unknown-linux-gnu"
          curl -fsSL "https://github.com/carvalinh0/envy/releases/download/${ENVY_VERSION}/${name}.tar.gz" | tar -xz
          sudo install "${name}/envy" /usr/local/bin/envy
          envy --version

      - name: Check the values
        run: envy check prod

      - name: Deploy
        run: envy run prod -- ./scripts/deploy.sh
```

`envy run` puts the values in the environment of `deploy.sh` only; they never reach the job's
environment or its logs. If the server can't be reached, the step fails.

## Checking the manifest on every pull request

Projects without a server can still check that `envy.json` is valid in CI. `envy up` recomputes the
checksum, so a hand edit that was not committed with `envy up` shows as a diff:

```yaml
      - name: The manifest is up to date
        run: |
          envy up
          git diff --exit-code envy.json
```

## Monorepos

```yaml
      - name: Check every service
        run: envy check -r prod
```

A member of the workspace needs access to its own project and to the root's project on the server.
