#!/usr/bin/env bash
# tools/verify-vm/setup.sh — one-shot bootstrap for SKELETONKEY VM verification.
#
# What this does (idempotent — re-runs are safe):
#   1. Verifies Parallels Desktop is installed (you said you wanted to keep it).
#   2. Installs Vagrant via Homebrew if missing.
#   3. Installs the vagrant-parallels plugin if missing.
#   4. Pre-downloads a curated set of base boxes so first-use of `verify.sh`
#      doesn't hit a ~5 GB download.
#
# Cached boxes (~5-6 GB total on disk):
#   - generic/ubuntu1804  (4.15.0 stock; covers CVE-2016/2017/2019)
#   - generic/ubuntu2004  (5.4.0; covers CVE-2020/2021/2022 partial)
#   - generic/ubuntu2204  (5.15.0; covers CVE-2023/2024)
#   - generic/debian11    (5.10.0; covers CVE-2021/2022)
#   - generic/debian12    (6.1.0; covers CVE-2024-2026)
#
# Disk savings: skip the boxes you don't need by passing them on the cmdline,
# e.g. `setup.sh ubuntu2004 debian11` only fetches those two.

set -euo pipefail

PARALLELS_APP=/Applications/Parallels\ Desktop.app
DEFAULT_BOXES=(generic/ubuntu1804 generic/ubuntu2004 generic/ubuntu2204
               generic/debian11 generic/debian12)

# Allow per-box override on the cmdline.
if [[ $# -gt 0 ]]; then
    BOXES=()
    for arg in "$@"; do
        case "$arg" in
            ubuntu1804|ubuntu2004|ubuntu2204|debian11|debian12)
                BOXES+=("generic/$arg") ;;
            generic/*) BOXES+=("$arg") ;;
            *) echo "[-] unknown box: $arg (expected ubuntu1804|2004|2204|debian11|12)" >&2; exit 2 ;;
        esac
    done
else
    BOXES=("${DEFAULT_BOXES[@]}")
fi

echo "[*] SKELETONKEY VM verification — bootstrap"
echo

# 1. Parallels Desktop check
if [[ ! -d "$PARALLELS_APP" ]]; then
    echo "[-] Parallels Desktop not found at $PARALLELS_APP" >&2
    echo "    Install it first: https://www.parallels.com/products/desktop/" >&2
    exit 1
fi
echo "[+] Parallels Desktop: present"

# 2. Vagrant
if ! command -v vagrant >/dev/null 2>&1; then
    if ! command -v brew >/dev/null 2>&1; then
        echo "[-] Homebrew not found; install from https://brew.sh first" >&2
        exit 1
    fi
    echo "[*] installing vagrant via brew..."
    brew install --cask vagrant
fi
echo "[+] vagrant: $(vagrant --version)"

# 3. vagrant-parallels plugin
if ! vagrant plugin list 2>/dev/null | grep -q vagrant-parallels; then
    echo "[*] installing vagrant-parallels plugin..."
    vagrant plugin install vagrant-parallels
fi
echo "[+] vagrant-parallels: $(vagrant plugin list | grep vagrant-parallels)"

# 3.5. (verify.sh parses targets.yaml with awk — no Python deps required)

# 4. Pre-download boxes (each ~700 MB to ~1.5 GB)
echo
echo "[*] pre-downloading ${#BOXES[@]} base box(es)..."
for box in "${BOXES[@]}"; do
    if vagrant box list 2>/dev/null | grep -q "^$box "; then
        echo "[=] $box already cached (skip)"
    else
        echo "[+] fetching $box..."
        vagrant box add "$box" --provider=parallels --no-tty
    fi
done

echo
echo "[+] verification environment ready."
echo
echo "Next:"
echo "    ./tools/verify-vm/verify.sh <module>"
echo
echo "Try:"
echo "    ./tools/verify-vm/verify.sh nf_tables"
echo "    ./tools/verify-vm/verify.sh dirty_pipe --keep   # don't destroy VM after"
echo
echo "List the curated targets:"
echo "    cat ./tools/verify-vm/targets.yaml"
