# The Envy server: a static binary (musl) on an empty image, run as a non-root user.
# docker run -v envy-data:/data ghcr.io/carvalinh0/envy --init --init-output /data/root-token
# docker run -v envy-data:/data -p 8443:8443 --read-only ghcr.io/carvalinh0/envy \
#     --listen 0.0.0.0:8443 --tls-cert /tls/cert.pem --tls-key /tls/key.pem

FROM rust:1.89-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY . .
# The release workflow passes the tag, so `envy version` reports it (like the binaries).
ARG VERSION=""
RUN if [ -n "$VERSION" ]; then \
      sed -i "0,/^version = \".*\"/s//version = \"${VERSION#v}\"/" Cargo.toml; \
    fi
# No keyring (no libdbus): the image only serves. A failing test stops the build. The tests
# run in the default profile, like CI: `build.rs` embeds other values in release builds.
RUN cargo test --all-targets --no-default-features --features server \
 && cargo build --release --no-default-features --features server \
 && mkdir -p /out/data \
 && cp target/release/envy /out/envy

FROM scratch
# Links the image on ghcr.io to the repository (description, visibility and permissions).
LABEL org.opencontainers.image.source="https://github.com/carvalinh0/envy" \
      org.opencontainers.image.description="Envy server: shares encrypted environment values with a team" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/envy /envy
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/envy", "serve", "--data", "/data"]
CMD ["--listen", "0.0.0.0:8443", "--behind-proxy"]
