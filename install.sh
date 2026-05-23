#!/usr/bin/env bash
# SKELETONKEY one-shot installer.
#
# Usage:
#   curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh
#
# Or with explicit version:
#   SKELETONKEY_VERSION=v0.1.0 curl ... | sh
#
# Or install to a different prefix:
#   SKELETONKEY_PREFIX=$HOME/.local/bin curl ... | sh
#
# Environment:
#   SKELETONKEY_VERSION   release tag (default: latest)
#   SKELETONKEY_PREFIX    install dir   (default: /usr/local/bin if writable, else error)
#   SKELETONKEY_REPO      override repo (default: KaraZajac/SKELETONKEY)
#
# Exit codes:
#   0 — installed successfully
#   1 — error (unsupported arch, download failure, permission denied)

# POSIX-friendly: -eu is universal, pipefail only on shells that
# support it (bash, ksh, dash >= 0.5.12). Without pipefail the
# installer still exits on the first hard error since every curl/
# tar/install step is checked explicitly.
set -eu
(set -o pipefail) 2>/dev/null && set -o pipefail || true

REPO="${SKELETONKEY_REPO:-KaraZajac/SKELETONKEY}"
VERSION="${SKELETONKEY_VERSION:-latest}"
PREFIX="${SKELETONKEY_PREFIX:-/usr/local/bin}"

log()   { printf '[\033[1;36m*\033[0m] %s\n' "$*" >&2; }
ok()    { printf '[\033[1;32m+\033[0m] %s\n' "$*" >&2; }
fail()  { printf '[\033[1;31m-\033[0m] %s\n' "$*" >&2; exit 1; }

# Detect architecture
arch=$(uname -m)
case "$arch" in
    # x86_64 default: the musl-static binary works on every libc
    # (glibc 2.x of any version, musl, uclibc) — costs ~800 KB extra
    # vs the dynamic build but eliminates the GLIBC_2.NN portability
    # ceiling that bit users on Debian-stable / older RHEL hosts.
    # Set SKELETONKEY_DYNAMIC=1 to fetch the smaller dynamic build
    # (needs glibc >= 2.38, i.e. Ubuntu 24.04 / Debian 13 / RHEL 10).
    x86_64|amd64)
        if [ "${SKELETONKEY_DYNAMIC:-0}" = "1" ]; then
            target=x86_64
        else
            target=x86_64-static
        fi
        ;;
    aarch64|arm64)       target=arm64  ;;
    *) fail "Unsupported architecture: $arch (only x86_64 and arm64 currently)" ;;
esac
log "detected arch: $target"

# Resolve version → download URL
if [ "$VERSION" = "latest" ]; then
    url="https://github.com/${REPO}/releases/latest/download/skeletonkey-${target}"
    sha_url="https://github.com/${REPO}/releases/latest/download/skeletonkey-${target}.sha256"
else
    url="https://github.com/${REPO}/releases/download/${VERSION}/skeletonkey-${target}"
    sha_url="https://github.com/${REPO}/releases/download/${VERSION}/skeletonkey-${target}.sha256"
fi
log "downloading from: $url"

# Need curl. wget fallback would be nice but skipping for simplicity.
if ! command -v curl >/dev/null 2>&1; then
    fail "curl is required (apt install curl / dnf install curl)"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! curl -fsSLo "$tmp/skeletonkey" "$url"; then
    fail "download failed. Check the version exists at https://github.com/${REPO}/releases"
fi

# Verify checksum if available
if curl -fsSLo "$tmp/skeletonkey.sha256" "$sha_url" 2>/dev/null; then
    # The .sha256 file has the binary's original name; normalize for our local copy
    expected=$(awk '{print $1}' "$tmp/skeletonkey.sha256")
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$tmp/skeletonkey" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$tmp/skeletonkey" | awk '{print $1}')
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

chmod +x "$tmp/skeletonkey"

# Install. Try $PREFIX directly; if not writable, sudo.
target_path="$PREFIX/skeletonkey"
if [ -w "$PREFIX" ] || [ "$(id -u)" -eq 0 ]; then
    mv "$tmp/skeletonkey" "$target_path"
elif command -v sudo >/dev/null 2>&1; then
    log "$PREFIX needs sudo; you may be prompted for password"
    sudo mv "$tmp/skeletonkey" "$target_path"
else
    fail "$PREFIX not writable and sudo not available. Try SKELETONKEY_PREFIX=\$HOME/.local/bin"
fi

ok "installed: $target_path"
"$target_path" --version

cat >&2 <<EOF

[\033[1;33m!\033[0m] AUTHORIZED TESTING ONLY — see https://github.com/${REPO}/blob/main/docs/ETHICS.md

Quickstart:
    sudo skeletonkey --scan                                 # what's this box vulnerable to?
    sudo skeletonkey --audit                                # broader system hygiene
    sudo skeletonkey --detect-rules --format=auditd \\
       | sudo tee /etc/audit/rules.d/99-skeletonkey.rules   # deploy detection rules

See \`skeletonkey --help\` for all commands.
EOF
