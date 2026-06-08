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
# PREFIX resolution is deferred until install time so we can pick a
# sudo-free default. SKELETONKEY is a privilege-escalation tool — by
# definition the operator does NOT have root yet, so the installer must
# NEVER need sudo. Empty here means "auto-pick a writable dir below".
PREFIX="${SKELETONKEY_PREFIX:-}"

log()   { printf '[\033[1;36m*\033[0m] %s\n' "$*" >&2; }
ok()    { printf '[\033[1;32m+\033[0m] %s\n' "$*" >&2; }
fail()  { printf '[\033[1;31m-\033[0m] %s\n' "$*" >&2; exit 1; }

# Detect architecture. Default to the musl-static binary on both
# x86_64 and arm64 — works on every libc (glibc 2.x of any version,
# musl, uclibc); costs ~800 KB extra vs dynamic but eliminates the
# GLIBC_2.NN portability ceiling that bites on Debian-stable, older
# RHEL hosts, and Alpine. Set SKELETONKEY_DYNAMIC=1 to fetch the
# smaller dynamic build (needs glibc >= 2.38 for x86_64 — Ubuntu
# 24.04 / Debian 13 / RHEL 10).
arch=$(uname -m)
case "$arch" in
    x86_64|amd64)
        if [ "${SKELETONKEY_DYNAMIC:-0}" = "1" ]; then
            target=x86_64
        else
            target=x86_64-static
        fi
        ;;
    aarch64|arm64)
        if [ "${SKELETONKEY_DYNAMIC:-0}" = "1" ]; then
            target=arm64
        else
            target=arm64-static
        fi
        ;;
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

# Choose install dir — NEVER escalate to sudo. If the user pinned
# SKELETONKEY_PREFIX we honor it exactly (creating it if needed) and
# error rather than escalate when it isn't writable. Otherwise prefer
# /usr/local/bin only when it happens to already be writable, and fall
# back to a guaranteed per-user dir ($HOME/.local/bin) that needs no
# privileges. This keeps `curl ... | sh` password-free for the exact
# users this tool is meant for: unprivileged accounts.
if [ -n "$PREFIX" ]; then
    [ -d "$PREFIX" ] || mkdir -p "$PREFIX" 2>/dev/null \
        || fail "cannot create SKELETONKEY_PREFIX=$PREFIX"
    [ -w "$PREFIX" ] || fail "SKELETONKEY_PREFIX=$PREFIX not writable (the installer never uses sudo — pick a writable dir)"
elif [ -w /usr/local/bin ]; then
    PREFIX=/usr/local/bin
else
    PREFIX="${XDG_BIN_HOME:-$HOME/.local/bin}"
    mkdir -p "$PREFIX" 2>/dev/null || fail "cannot create $PREFIX"
fi

target_path="$PREFIX/skeletonkey"
mv "$tmp/skeletonkey" "$target_path" || fail "failed to install to $target_path"
ok "installed: $target_path"

# ~/.local/bin is frequently absent from PATH on fresh accounts — tell
# the user how to invoke it rather than letting `skeletonkey` 404.
case ":$PATH:" in
    *":$PREFIX:"*) : ;;
    *) log "note: $PREFIX is not on \$PATH — run it as $target_path, or add the dir to PATH" ;;
esac

"$target_path" --version

cat >&2 <<EOF

[\033[1;33m!\033[0m] AUTHORIZED TESTING ONLY — see https://github.com/${REPO}/blob/main/docs/ETHICS.md

Quickstart (no root required — gaining it is the point):
    skeletonkey --scan                  # what's this box vulnerable to?
    skeletonkey --audit                 # broader system hygiene
    skeletonkey --auto --i-know         # run the safest available LPE

Deploy detection rules (defensive; only the write to /etc/audit needs root):
    skeletonkey --detect-rules --format=auditd \\
       | sudo tee /etc/audit/rules.d/99-skeletonkey.rules

See \`skeletonkey --help\` for all commands.
EOF
