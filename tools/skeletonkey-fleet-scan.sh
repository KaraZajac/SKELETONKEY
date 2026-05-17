#!/usr/bin/env bash
# skeletonkey-fleet-scan — scan a host list with skeletonkey, aggregate results
#
# Usage:
#   skeletonkey-fleet-scan.sh [OPTIONS] hosts.txt
#   skeletonkey-fleet-scan.sh [OPTIONS] -                       # hosts on stdin
#   skeletonkey-fleet-scan.sh [OPTIONS] -                       # one host per line
#
# Each line in the host list is either:
#   - a hostname/IP (uses default ssh user from your config)
#   - user@host
#   - user@host:port
#
# Output: combined JSON to stdout, one object per host:
#   { "generated_at": "...", "summary": {...},
#     "hosts": [ { "host": "...", "ok": true,
#                  "scan": { /* skeletonkey --scan --json */ } }, ... ] }
#
# Options:
#   --binary <path>      path to skeletonkey binary (default: ./skeletonkey)
#   --ssh-key <path>     ssh key file (passed to scp and ssh)
#   --ssh-opts "..."     extra ssh options (e.g. "-o ConnectTimeout=5")
#   --remote-path <p>    where to scp the binary (default: /tmp/skeletonkey)
#   --no-sudo            don't prefix the remote command with sudo
#   --parallel <N>       run N hosts concurrently (default: 4)
#   --summary-only       skip per-host detail in stdout; print summary only
#   --no-cleanup         leave the binary behind on each host (default: rm)
#   -h | --help          this message
#
# Exit code: 0 if every host scanned (regardless of host-level vulns),
#            1 if any host failed to scan.

set -euo pipefail

BINARY="./skeletonkey"
SSH_KEY=""
SSH_OPTS=""
REMOTE_PATH="/tmp/skeletonkey"
USE_SUDO=1
PARALLEL=4
SUMMARY_ONLY=0
CLEANUP=1
HOSTFILE=""

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)        BINARY="$2"; shift 2;;
        --ssh-key)       SSH_KEY="$2"; shift 2;;
        --ssh-opts)      SSH_OPTS="$2"; shift 2;;
        --remote-path)   REMOTE_PATH="$2"; shift 2;;
        --no-sudo)       USE_SUDO=0; shift;;
        --parallel)      PARALLEL="$2"; shift 2;;
        --summary-only)  SUMMARY_ONLY=1; shift;;
        --no-cleanup)    CLEANUP=0; shift;;
        -h|--help)       usage 0;;
        -)               HOSTFILE="/dev/stdin"; shift;;
        *)               HOSTFILE="$1"; shift;;
    esac
done

if [[ -z "$HOSTFILE" ]]; then
    echo "error: no host file provided. Use -h for help." >&2
    exit 2
fi

if [[ ! -x "$BINARY" ]]; then
    echo "error: skeletonkey binary not found / not executable: $BINARY" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required for JSON aggregation" >&2
    exit 2
fi

# Build ssh/scp option arrays
SSH_BASE=(-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10)
[[ -n "$SSH_KEY" ]]  && SSH_BASE+=(-i "$SSH_KEY")
[[ -n "$SSH_OPTS" ]] && eval "SSH_BASE+=( $SSH_OPTS )"

scan_one_host() {
    local hostspec="$1"
    local host port user
    if [[ "$hostspec" == *:* ]]; then
        port="${hostspec##*:}"
        hostspec="${hostspec%:*}"
    else
        port="22"
    fi
    if [[ "$hostspec" == *@* ]]; then
        user="${hostspec%@*}"
        host="${hostspec#*@}"
    else
        user=""
        host="$hostspec"
    fi
    local target="${user:+${user}@}${host}"

    local sudo_prefix=""
    [[ "$USE_SUDO" -eq 1 ]] && sudo_prefix="sudo"

    # 1. scp the binary
    if ! scp "${SSH_BASE[@]}" -P "$port" -q "$BINARY" \
            "${target}:${REMOTE_PATH}" 2>/dev/null; then
        echo "{\"host\":\"${hostspec}\",\"ok\":false,\"error\":\"scp failed\"}"
        return 1
    fi

    # 2. run --scan --json
    # skeletonkey's exit codes are SEMANTIC (0=OK, 2=VULNERABLE, 4=PRECOND_FAIL, etc.)
    # — nonzero is NOT a failure here. Treat ANY stdout JSON as success;
    # only ssh-transport-level failures (key denied, network) are real
    # failures, and those manifest as empty stdout + nonzero exit.
    local scan_out
    scan_out=$(ssh "${SSH_BASE[@]}" -p "$port" "$target" \
            "$sudo_prefix $REMOTE_PATH --scan --json --no-color" 2>/dev/null || true)
    if [[ -z "$scan_out" ]]; then
        echo "{\"host\":\"${hostspec}\",\"ok\":false,\"error\":\"ssh run failed (empty output)\"}"
        # Still try to cleanup
        [[ "$CLEANUP" -eq 1 ]] && ssh "${SSH_BASE[@]}" -p "$port" "$target" \
            "rm -f $REMOTE_PATH" 2>/dev/null || true
        return 1
    fi

    # 3. cleanup
    if [[ "$CLEANUP" -eq 1 ]]; then
        ssh "${SSH_BASE[@]}" -p "$port" "$target" \
            "rm -f $REMOTE_PATH" 2>/dev/null || true
    fi

    # 4. emit one combined JSON object
    if ! echo "$scan_out" | jq --arg h "$hostspec" \
            '{host: $h, ok: true, scan: .}' 2>/dev/null; then
        echo "{\"host\":\"${hostspec}\",\"ok\":false,\"error\":\"invalid JSON from skeletonkey\"}"
        return 1
    fi
}

# Read host list (strip comments, blank lines)
mapfile -t HOSTS < <(grep -vE '^\s*(#|$)' "$HOSTFILE")
if [[ ${#HOSTS[@]} -eq 0 ]]; then
    echo "error: no hosts to scan" >&2
    exit 2
fi

# Optional progress to stderr
echo "[*] scanning ${#HOSTS[@]} host(s), parallel=$PARALLEL" >&2

# Run in parallel with xargs. Each invocation prints one JSON object.
export -f scan_one_host
export BINARY SSH_BASE SSH_KEY REMOTE_PATH USE_SUDO CLEANUP
# bash-export of an array doesn't survive, so re-serialize:
export SSH_BASE_STR="${SSH_BASE[*]}"

# Simpler: collect per-host results sequentially (good enough for small
# fleets); parallel mode uses GNU xargs -P if available.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

if [[ "$PARALLEL" -gt 1 ]] && command -v xargs >/dev/null 2>&1; then
    # -I{} implies -n1; specifying both warns on modern xargs.
    printf '%s\n' "${HOSTS[@]}" | xargs -P"$PARALLEL" -I{} \
        bash -c 'scan_one_host "$@"' _ {} >> "$TMP"
else
    for h in "${HOSTS[@]}"; do
        scan_one_host "$h" >> "$TMP" || true
    done
fi

# Aggregate. `jq -s` slurps the line-delimited JSON into an array.
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RESULT=$(jq -s --arg ts "$TIMESTAMP" '
    . as $hosts
    | {
        generated_at: $ts,
        n_hosts: ($hosts | length),
        summary: {
            ok: ($hosts | map(select(.ok)) | length),
            failed: ($hosts | map(select(.ok | not)) | length),
            vulnerable: (
                $hosts
                | map(select(.ok))
                | map(.scan.modules // [])
                | flatten
                | map(select(.result == "VULNERABLE"))
                | group_by(.cve)
                | map({cve: .[0].cve, name: .[0].name, count: length})
                | sort_by(-.count)
            )
        },
        hosts: $hosts
    }
' "$TMP")

if [[ "$SUMMARY_ONLY" -eq 1 ]]; then
    echo "$RESULT" | jq 'del(.hosts)'
else
    echo "$RESULT"
fi

# Exit nonzero if any host failed
FAILED=$(echo "$RESULT" | jq -r '.summary.failed')
[[ "$FAILED" -eq 0 ]] || exit 1
