# GitLab CI

The setup is the same as for [GitHub Actions](github-actions.md#one-time-setup): create a member
such as `ci-prod`, join with `--print-identity` and approve it for the environments the pipeline
needs. Store the identity as a **masked, protected** CI/CD variable named `ENVY_IDENTITY`
(Settings → CI/CD → Variables), so only protected branches can read it.

```yaml
deploy:
  image: debian:bookworm-slim
  stage: deploy
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  variables:
    ENVY_VERSION: v4.0.0
    ENVY_BACKEND: remote
    ENVY_SERVER: https://envy.example.com
    # ENVY_IDENTITY comes from the masked CI/CD variable.
  before_script:
    # The prebuilt binary needs libdbus-1 even without a keyring.
    - apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libdbus-1-3
    - name="envy-${ENVY_VERSION}-x86_64-unknown-linux-gnu"
    - curl -fsSL "https://github.com/carvalinh0/envy/releases/download/${ENVY_VERSION}/${name}.tar.gz" | tar -xz
    - install "${name}/envy" /usr/local/bin/envy
  script:
    - envy check prod
    - envy run prod -- ./scripts/deploy.sh
```

Containers of CI jobs usually have no home folder that survives the job: the server keys Envy pins
are kept for that run only, and the local audit log is off. The server's own log
(`envy audit --server`) still records what the pipeline read.
