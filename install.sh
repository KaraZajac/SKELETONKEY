#!/usr/bin/env bash
# IAMROOT one-shot installer.
#
# Usage:
#   curl -sSL https://github.com/KaraZajac/IAMROOT/releases/latest/download/install.sh | sh
#
# Or with explicit version:
#   IAMROOT_VERSION=v0.1.0 curl ... | sh
#
# Or install to a different prefix:
#   IAMROOT_PREFIX=$HOME/.local/bin curl ... | sh
#
# Environment:
#   IAMROOT_VERSION   release tag (default: latest)
#   IAMROOT_PREFIX    install dir   (default: /usr/local/bin if writable, else error)
#   IAMROOT_REPO      override repo (default: KaraZajac/IAMROOT)
#
# Exit codes:
#   0 — installed successfully
#   1 — error (unsupported arch, download failure, permission denied)

set -euo pipefail

REPO="${IAMROOT_REPO:-KaraZajac/IAMROOT}"
VERSION="${IAMROOT_VERSION:-latest}"
PREFIX="${IAMROOT_PREFIX:-/usr/local/bin}"

log()   { printf '[\033[1;36m*\033[0m] %s\n' "$*" >&2; }
ok()    { printf '[\033[1;32m+\033[0m] %s\n' "$*" >&2; }
fail()  { printf '[\033[1;31m-\033[0m] %s\n' "$*" >&2; exit 1; }

# Detect architecture
arch=$(uname -m)
case "$arch" in
    x86_64|amd64)        target=x86_64 ;;
    aarch64|arm64)       target=arm64  ;;
    *) fail "Unsupported architecture: $arch (only x86_64 and arm64 currently)" ;;
esac
log "detected arch: $target"

# Resolve version → download URL
if [ "$VERSION" = "latest" ]; then
    url="https://github.com/${REPO}/releases/latest/download/iamroot-${target}"
    sha_url="https://github.com/${REPO}/releases/latest/download/iamroot-${target}.sha256"
else
    url="https://github.com/${REPO}/releases/download/${VERSION}/iamroot-${target}"
    sha_url="https://github.com/${REPO}/releases/download/${VERSION}/iamroot-${target}.sha256"
fi
log "downloading from: $url"

# Need curl. wget fallback would be nice but skipping for simplicity.
if ! command -v curl >/dev/null 2>&1; then
    fail "curl is required (apt install curl / dnf install curl)"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! curl -fsSLo "$tmp/iamroot" "$url"; then
    fail "download failed. Check the version exists at https://github.com/${REPO}/releases"
fi

# Verify checksum if available
if curl -fsSLo "$tmp/iamroot.sha256" "$sha_url" 2>/dev/null; then
    # The .sha256 file has the binary's original name; normalize for our local copy
    expected=$(awk '{print $1}' "$tmp/iamroot.sha256")
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$tmp/iamroot" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$tmp/iamroot" | awk '{print $1}')
    else
        actual=""
        log "no sha256sum/shasum available — skipping checksum verification"
    fi
    if [ -n "$actual" ]; then
        if [ "$actual" = "$expected" ]; then
            ok "checksum verified"
        else
            fail "checksum mismatch (expected $expected, got $actual)"
        fi
    fi
else
    log "no checksum file at $sha_url — skipping verification"
fi

chmod +x "$tmp/iamroot"

# Install. Try $PREFIX directly; if not writable, sudo.
target_path="$PREFIX/iamroot"
if [ -w "$PREFIX" ] || [ "$(id -u)" -eq 0 ]; then
    mv "$tmp/iamroot" "$target_path"
elif command -v sudo >/dev/null 2>&1; then
    log "$PREFIX needs sudo; you may be prompted for password"
    sudo mv "$tmp/iamroot" "$target_path"
else
    fail "$PREFIX not writable and sudo not available. Try IAMROOT_PREFIX=\$HOME/.local/bin"
fi

ok "installed: $target_path"
"$target_path" --version

cat >&2 <<EOF

[\033[1;33m!\033[0m] AUTHORIZED TESTING ONLY — see https://github.com/${REPO}/blob/main/docs/ETHICS.md

Quickstart:
    sudo iamroot --scan                                 # what's this box vulnerable to?
    sudo iamroot --audit                                # broader system hygiene
    sudo iamroot --detect-rules --format=auditd \\
       | sudo tee /etc/audit/rules.d/99-iamroot.rules   # deploy detection rules

See \`iamroot --help\` for all commands.
EOF
