#!/usr/bin/env bash
# tools/verify-vm/verify.sh — verify ONE module in the right pre-built VM.
#
# Usage:
#   verify.sh <module>           # provision, run --explain --active, suspend VM
#   verify.sh <module> --keep    # keep VM running after for inspection
#   verify.sh <module> --destroy # destroy VM after (full reset; slow next run)
#   verify.sh --list             # show every module + the box it's mapped to
#
# What it does:
#   1. Reads tools/verify-vm/targets.yaml: <module> -> (box, kernel_pkg, kver,
#      expect_detect).
#   2. Sets SKK_VM_* env vars + spins up the right Vagrant VM.
#   3. If a kernel pin is needed, installs it + reboots the VM.
#   4. Runs `skeletonkey --explain <module> --active` inside the VM via
#      `vagrant provision --provision-with build-and-verify`.
#   5. Captures stdout, parses the VERDICT line, compares against expect_detect.
#   6. Emits a JSON verification record on stdout (timestamped) suitable for
#      piping into the per-module verified-on table (separate follow-up).
#
# Requirements:
#   - tools/verify-vm/setup.sh has been run successfully (Vagrant +
#     vagrant-parallels + boxes cached).
#   - Module name matches a key in targets.yaml.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM_DIR="$REPO_ROOT/tools/verify-vm"
TARGETS="$VM_DIR/targets.yaml"
LOG_DIR="$VM_DIR/logs"
mkdir -p "$LOG_DIR"

# Minimal YAML field reader for targets.yaml's flat 2-level structure.
# Usage: yget <module> <field>
#   yget af_packet box           -> "ubuntu1804"
# Strips surrounding quotes and trailing whitespace; empty fields -> "".
yget() {
    local module="$1"
    local field="$2"
    awk -v m="${module}:" -v f="  ${field}:" '
        $0 ~ "^"m"[[:space:]]*$"   { inmod=1; next }
        inmod && /^[a-zA-Z]/        { inmod=0 }   # next top-level key
        inmod && $0 ~ "^"f          {
            sub("^[^:]+:[[:space:]]*", "")
            sub("[[:space:]]+#.*$",  "")          # trim trailing comment
            sub("^\"", ""); sub("\"$", "")
            print; exit
        }
    ' "$TARGETS"
}

# ── arg parsing ───────────────────────────────────────────────────────────
KEEP=0; DESTROY=0; LIST=0; MODULE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)     KEEP=1 ;;
        --destroy)  DESTROY=1 ;;
        --list)     LIST=1 ;;
        -h|--help)
            sed -n '1,30p' "$0"; exit 0 ;;
        --*)
            echo "[-] unknown flag: $1" >&2; exit 2 ;;
        *)
            MODULE="$1" ;;
    esac
    shift
done

# ── --list mode ───────────────────────────────────────────────────────────
if [[ $LIST -eq 1 ]]; then
    printf "%-22s %-14s %-18s %-14s %s\n" "MODULE" "BOX" "KERNEL" "EXPECT" "NOTES"
    printf "%-22s %-14s %-18s %-14s %s\n" "------" "---" "------" "------" "-----"
    # Iterate top-level keys (lines starting in column 0 with `something:`).
    awk '/^[a-z_][a-zA-Z0-9_]*:[[:space:]]*$/ { sub(":", ""); print }' "$TARGETS" | \
    while read -r mod; do
        box=$(yget "$mod" box)
        kv=$(yget "$mod" kernel_version)
        exp=$(yget "$mod" expect_detect)
        notes=$(yget "$mod" notes | head -c 60)
        [[ -z "$box" ]] && box="(manual)"
        [[ -z "$kv"  ]] && kv="stock"
        [[ -z "$exp" ]] && exp="?"
        printf "%-22s %-14s %-18s %-14s %s\n" "$mod" "$box" "$kv" "$exp" "$notes"
    done
    exit 0
fi

if [[ -z "$MODULE" ]]; then
    echo "[-] usage: verify.sh <module> [--keep|--destroy]"
    echo "    verify.sh --list   # show all targets"
    exit 2
fi

# ── load target ───────────────────────────────────────────────────────────
BOX=$(yget "$MODULE" box)
KERNEL_PKG=$(yget "$MODULE" kernel_pkg)
MAINLINE=$(yget "$MODULE" mainline_version)
KERNEL_VER=$(yget "$MODULE" kernel_version)
EXPECT=$(yget "$MODULE" expect_detect)
MANUAL=$(yget "$MODULE" manual)
NOTES=$(yget "$MODULE" notes)

if ! grep -q "^${MODULE}:" "$TARGETS"; then
    echo "[-] module not in targets.yaml: $MODULE" >&2
    exit 3
fi
if [[ "$MANUAL" == "true" || -z "$BOX" ]]; then
    echo "[-] $MODULE is marked manual: true (${NOTES:0:80})" >&2
    exit 4
fi
BOX="generic/$BOX"
VM_HOSTNAME="skk-${MODULE}"
SHORT_NOTES="${NOTES:0:80}"

# ── kick off provisioning ─────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════"
echo " SKELETONKEY VM verifier: $MODULE"
echo "════════════════════════════════════════════════════"
echo "  box:         $BOX"
echo "  kernel:      ${KERNEL_PKG:-(stock)}  → $KERNEL_VER"
echo "  expect:      $EXPECT"
echo "  notes:       $SHORT_NOTES"
echo

cd "$VM_DIR"
export SKK_VM_BOX="$BOX"
export SKK_VM_KERNEL_PKG="$KERNEL_PKG"
export SKK_VM_MAINLINE_VERSION="$MAINLINE"
export SKK_VM_KERNEL_VERSION="$KERNEL_VER"
export SKK_VM_HOSTNAME="$VM_HOSTNAME"
export SKK_MODULE="$MODULE"
export VAGRANT_VAGRANTFILE="$VM_DIR/Vagrantfile"

# Spin up if not running.
if ! vagrant status "$VM_HOSTNAME" 2>&1 | grep -q "running"; then
    echo "[*] vagrant up..."
    vagrant up "$VM_HOSTNAME" --provider=parallels
fi

# Reboot if any kernel pin was applied (uname -r != target).
if [[ -n "$KERNEL_PKG" || -n "$MAINLINE" ]]; then
    current_kver=$(vagrant ssh "$VM_HOSTNAME" -c "uname -r" 2>/dev/null | tr -d '\r')
    target_match="$KERNEL_VER"
    [[ -n "$MAINLINE" ]] && target_match="$MAINLINE"
    if [[ "$current_kver" != *"$target_match"* ]]; then
        echo "[*] current kernel $current_kver != target $target_match; rebooting..."
        vagrant reload "$VM_HOSTNAME"
        sleep 5
    fi
fi

# Run the explain probe.
LOG="$LOG_DIR/verify-${MODULE}-$(date +%Y%m%d-%H%M%S).log"

# Force rsync the source tree in. vagrant up runs rsync automatically on
# first up but NOT on a resume/already-running VM, so we always rsync here
# to guarantee /vagrant/ inside the guest matches the host's source tree.
echo "[*] syncing source into VM..."
vagrant rsync "$VM_HOSTNAME" 2>&1 | tail -5

echo "[*] running verifier..."
vagrant provision "$VM_HOSTNAME" --provision-with build-and-verify 2>&1 | tee "$LOG"

# Parse verdict. Vagrant prefixes provisioner output with the VM name
# (e.g. "    skk-pwnkit: VERDICT: VULNERABLE"), so anchor on the VERDICT
# keyword itself. `|| true` keeps pipefail+set-e from killing us on miss.
VERDICT=$(grep -E "VERDICT:" "$LOG" | tail -1 | awk '{print $NF}' || true)
[[ -z "$VERDICT" ]] && VERDICT="?"

# Compare.
if [[ "$VERDICT" == "$EXPECT" ]]; then
    STATUS=match
else
    STATUS=MISMATCH
fi

# Verification record (JSON).
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HOST_KVER=$(vagrant ssh "$VM_HOSTNAME" -c "uname -r" 2>/dev/null | tr -d '\r')
HOST_DISTRO=$(vagrant ssh "$VM_HOSTNAME" -c \
    "(. /etc/os-release && echo \"\$PRETTY_NAME\")" 2>/dev/null | tr -d '\r')

echo
echo "════════════════════════════════════════════════════"
echo " Verification record"
echo "════════════════════════════════════════════════════"
RECORD=$(cat <<JSON
{"module":"$MODULE","verified_at":"$NOW","host_kernel":"$HOST_KVER","host_distro":"$HOST_DISTRO","vm_box":"$BOX","expect_detect":"$EXPECT","actual_detect":"$VERDICT","status":"$STATUS"}
JSON
)
printf '%s\n' "$RECORD" | python3 -m json.tool 2>/dev/null || printf '%s\n' "$RECORD"

# Append to the permanent JSONL store (one record per line, dedup happens
# at refresh time in tools/refresh-verifications.py).
echo "$RECORD" >> "$REPO_ROOT/docs/VERIFICATIONS.jsonl"
echo
echo "[i] appended to docs/VERIFICATIONS.jsonl"
echo "[i] run 'tools/refresh-verifications.py' to regenerate core/verifications.c"
echo

# Lifecycle.
if [[ $DESTROY -eq 1 ]]; then
    echo "[*] --destroy: tearing down VM..."
    vagrant destroy -f "$VM_HOSTNAME"
elif [[ $KEEP -eq 1 ]]; then
    echo "[i] --keep: VM left running. Reconnect with:"
    echo "    cd tools/verify-vm && vagrant ssh $VM_HOSTNAME"
else
    echo "[*] suspending VM (resume next time)..."
    vagrant suspend "$VM_HOSTNAME"
fi

[[ "$STATUS" == "match" ]] && exit 0 || exit 5
