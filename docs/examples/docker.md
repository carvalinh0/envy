# Docker

Two different things: running the **Envy server** in a container, and using **Envy inside your
application's container** to start it with its values.

## Running the server

The image `ghcr.io/carvalinh0/envy` runs `envy serve --data /data`; the arguments you pass are added
to that. Without arguments it listens on `0.0.0.0:8443` and refuses to start until you give it
`--tls-cert`/`--tls-key` or `--behind-proxy`. It runs as user 65532 and works with a read-only root
file system.

### Behind Caddy (recommended)

[`deploy/compose.yaml`](../../deploy/compose.yaml) puts the server behind Caddy, which gets and renews
the TLS certificate. Replace `envy.example.com` with your domain, then:

```bash
docker compose run --rm envy --init --init-output /data/root-token
docker compose up -d
```

The image has no shell or `cat`, so read the token from the volume with another container and
delete it afterwards:

```bash
docker run --rm -v envy_envy-data:/data alpine sh -c 'cat /data/root-token && rm /data/root-token'
```

(Compose names the volume `<folder>_envy-data`; `docker volume ls` shows it.) Give the token to the
first admin: `envy login https://envy.example.com --root-token <token> --name <name>`.

### With your own certificate

```bash
docker volume create envy-data
docker run --rm -v envy-data:/data ghcr.io/carvalinh0/envy --init        # prints the root token
docker run -d --name envy --restart unless-stopped --read-only --cap-drop ALL \
  -v envy-data:/data -v /etc/envy/tls:/tls:ro -p 443:8443 \
  ghcr.io/carvalinh0/envy \
  --listen 0.0.0.0:8443 --tls-cert /tls/cert.pem --tls-key /tls/key.pem
curl https://envy.example.com/v1/health                                  # ok
```

The certificate files must be readable by user 65532. Without `--tls-*` or `--behind-proxy` the
server refuses to listen on `0.0.0.0`.

**Backups:** stop the container and copy `envy.db` from the volume. It only holds ciphertext.

## Envy inside your application's container

The container starts your application through `envy run`, which fetches the values from the server
when the container starts. Nothing is baked into the image.

```dockerfile
FROM node:22-bookworm-slim

# Envy's prebuilt binary needs libdbus-1 (even without a keyring) and CA certificates.
ARG ENVY_VERSION=v4.0.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl libdbus-1-3 \
 && name="envy-${ENVY_VERSION}-x86_64-unknown-linux-gnu" \
 && curl -fsSL "https://github.com/carvalinh0/envy/releases/download/${ENVY_VERSION}/${name}.tar.gz" | tar -xz \
 && install "${name}/envy" /usr/local/bin/envy && rm -rf "${name}" \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN npm ci --omit=dev

ENV ENVY_BACKEND=remote
ENTRYPOINT ["envy", "run", "prod", "--"]
CMD ["node", "server.js"]
```

The image must contain `envy.json` (it is part of your sources). Pass the server and the identity
when the container starts, from your orchestrator's secrets, never as build arguments:

```bash
docker run -e ENVY_SERVER=https://envy.example.com -e ENVY_IDENTITY my-app
```

Create a dedicated member for each deployment (`envy user add app-prod`), approved read-only for the
one environment it runs with; see [the CI example](github-actions.md#one-time-setup) for the steps.
If the server is unreachable when the container starts, the container exits instead of starting
without its values.

## Local development in a container

A dev container has no keyring. Use the [file backend](wsl-and-headless.md): mount a volume on
`~/.local/share/envy` so the vault survives rebuilds of the container.
