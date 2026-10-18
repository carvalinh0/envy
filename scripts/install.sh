#!/usr/bin/env bash
# Installs Envy (the `envy` binary).
#
# 1. If Cargo is available, it runs `cargo install dot-envy`.
# 2. Otherwise (or if that fails) it downloads the prebuilt binary of the latest GitHub release.
#
# Usage: curl -fsSL https://raw.githubusercontent.com/carvalinh0/envy/main/scripts/install.sh | bash
#
# Optional environment variables:
#   ENVY_INSTALL_DIR  where the prebuilt binary is copied to (default: ~/.local/bin)
#   ENVY_VERSION      release tag to download, e.g. v1.2.3 (default: the latest release)
#   ENVY_REPO         GitHub repository (default: carvalinh0/envy)
#   ENVY_GITHUB_URL   GitHub base URL (default: https://github.com)
set -euo pipefail

CRATE="dot-envy"
REPO="${ENVY_REPO:-carvalinh0/envy}"
GITHUB_URL="${ENVY_GITHUB_URL:-https://github.com}"
INSTALL_DIR="${ENVY_INSTALL_DIR:-$HOME/.local/bin}"
TMP_DIR=""

cleanup() { [ -z "$TMP_DIR" ] || rm -rf "$TMP_DIR"; }
trap cleanup EXIT

info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }
fail() { echo "error: $*" >&2; exit 1; }

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) fail "unsupported architecture '$arch'. Install Rust (https://rustup.rs) and run: cargo install $CRATE" ;;
  esac

  case "$os" in
    Linux)
      [ "$arch" = "x86_64" ] || fail "there is no prebuilt binary for Linux $arch. Install Rust (https://rustup.rs) and run: cargo install $CRATE"
      echo "x86_64-unknown-linux-gnu"
      ;;
    Darwin)
      warn "macOS is not tested yet."
      echo "${arch}-apple-darwin"
      ;;
    *) fail "unsupported system '$os'." ;;
  esac
}

install_with_cargo() {
  command -v cargo >/dev/null 2>&1 || return 1
  info "Cargo found, running: cargo install $CRATE"
  cargo install "$CRATE"
}

latest_tag() {
  if [ -n "${ENVY_VERSION:-}" ]; then
    echo "$ENVY_VERSION"
    return
  fi
  local url tag
  url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$GITHUB_URL/$REPO/releases/latest")" \
    || fail "could not find the latest release of $REPO (has the first release been published?)"
  tag="${url##*/}"
  case "$tag" in
    v[0-9]*) echo "$tag" ;;
    *) fail "no release was found for $REPO." ;;
  esac
}

install_with_binary() {
  command -v curl >/dev/null 2>&1 || fail "curl is required to download the prebuilt binary."
  command -v tar >/dev/null 2>&1 || fail "tar is required to extract the prebuilt binary."

  local target tag name url
  target="$(detect_target)"
  tag="$(latest_tag)"
  name="envy-${tag}-${target}"
  url="$GITHUB_URL/$REPO/releases/download/$tag/$name.tar.gz"

  TMP_DIR="$(mktemp -d)"

  info "Downloading $url"
  curl -fsSL "$url" -o "$TMP_DIR/envy.tar.gz" \
    || fail "could not download $url (does release $tag have a binary for $target?)"
  tar -xzf "$TMP_DIR/envy.tar.gz" -C "$TMP_DIR"

  mkdir -p "$INSTALL_DIR"
  install -m 755 "$TMP_DIR/$name/envy" "$INSTALL_DIR/envy"
  info "Installed to $INSTALL_DIR/envy"

  if ! "$INSTALL_DIR/envy" --version >/dev/null 2>&1; then
    warn "the binary was installed but could not start. On Linux it needs libdbus-1 (e.g. 'sudo apt install libdbus-1-3')."
  fi

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not in your PATH. Add it, e.g.: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
  esac
}

if install_with_cargo; then
  info "Done. Run 'envy --version' to check (make sure ~/.cargo/bin is in your PATH)."
  exit 0
fi

if command -v cargo >/dev/null 2>&1; then
  warn "cargo install failed, falling back to the prebuilt binary."
else
  info "Cargo not found, using the prebuilt binary."
fi

install_with_binary
info "Done. Run 'envy --version' to check."
