# SKELETONKEY JSON output schema

`skeletonkey --scan --json` (and `--auto --json`, planned) emit a
single JSON object on **stdout**. All human-readable banner lines and
per-module log chatter go to **stderr** in JSON mode — pipes to SIEMs
and fleet aggregators get a clean machine-parseable document on
stdout while operators still see diagnostics on stderr.

This document is the contract for that JSON. SKELETONKEY treats it
as a stability commitment: new fields may appear in future releases,
but existing field names and value types do not change without a
major-version bump.

## Top-level object

```json
{
  "version": "0.5.0",
  "modules": [ /* ... per-module entries ... */ ]
}
```

| Field      | Type     | Stability  | Meaning |
|------------|----------|------------|---------|
| `version`  | string   | stable     | The SKELETONKEY release that produced this document. Semver-ish (`MAJOR.MINOR.PATCH`). Consumers may use it to correlate with the corpus inventory in [`CVES.md`](../CVES.md). |
| `modules`  | array    | stable     | One entry per registered module, emitted in the order the dispatcher's `--list` reports them. Length grows monotonically as new modules land. |

## Per-module entry

```json
{
  "name":   "dirty_pipe",
  "cve":    "CVE-2022-0847",
  "result": "OK"
}
```

| Field    | Type   | Stability | Meaning |
|----------|--------|-----------|---------|
| `name`   | string | stable    | The module's CLI identifier — what you pass to `--exploit <name>`. Lowercase, ASCII, `_`-delimited. Never changes for a given module across releases. |
| `cve`    | string | stable    | The CVE identifier (`CVE-YYYY-NNNNN`), or `"VARIANT"` for sibling variants without their own CVE (e.g. `copy_fail_gcm`), or `"-"` for primitives like `entrybleed` that have a CVE-less role. |
| `result` | string | stable    | One of the `result` enum values below. |

## `result` enum

| Value          | Exit code | Meaning |
|----------------|-----------|---------|
| `OK`           | 0         | Module's `detect()` ran successfully. Host is **patched** for this CVE, or the bug class is not applicable here (predates the introduction, wrong arch, etc.). Safe to ignore for this host. |
| `TEST_ERROR`   | 1         | `detect()` could not decide — the host fingerprint is missing data, the version parser failed, or an internal probe errored. Treat as "no information; check manually." |
| `VULNERABLE`   | 2         | Host is **vulnerable** to this CVE per the module's detect logic (version-based and/or empirical active probe). `--exploit <name> --i-know` will attempt to land root. |
| `EXPLOIT_FAIL` | 3         | Only ever returned by `--exploit`, never by `--scan`. Exploit was attempted but did not land root. Diagnostic context goes to stderr. |
| `PRECOND_FAIL` | 4         | A documented precondition is not met on this host — examples: unprivileged user namespaces disabled, AppArmor restriction on, sudo not installed, AF_RXRPC unavailable. The bug may exist on the kernel but the carrier path here is closed. |
| `EXPLOIT_OK`   | 5         | Only ever returned by `--exploit` / `--auto`. Root was achieved; for `--auto` mode this is the process exit code that drove the dispatcher into a root shell. |

## Process exit code semantics for `--scan`

The process exit code is the **worst (highest) result code** observed
across all modules. This lets a SIEM treat the binary's exit code as
a single-host alert level without re-parsing JSON:

| Exit code | Interpretation                                      |
|-----------|-----------------------------------------------------|
| 0         | All modules `OK`. Host is patched for the corpus.   |
| 1         | At least one module returned `TEST_ERROR`. Investigate. |
| 2         | At least one module returned `VULNERABLE`. Patch the host. |
| 4         | At least one module returned `PRECOND_FAIL` (and none worse). Host has reduced attack surface but is not necessarily safe. |

(Process exit codes 3 and 5 are exclusive to the `--exploit` /
`--auto` modes and never appear in `--scan` output.)

## Example: invoking + parsing

```bash
# capture pure JSON
skeletonkey --scan --json --no-color > host-$(hostname).json 2> /dev/null

# any vulnerable modules?
jq -e '.modules[] | select(.result == "VULNERABLE") | .name' host-*.json

# fleet roll-up — modules vulnerable across the fleet, by frequency
jq -s 'map(.modules[] | select(.result == "VULNERABLE") | .name)
       | flatten | group_by(.) | map({mod: .[0], count: length})
       | sort_by(-.count)' host-*.json
```

`jq -e` exits non-zero when its selector matches nothing, giving the
fleet runner a per-host "any-vulnerable" boolean without parsing the
document.

## Stability promises

**Stable across non-major releases:**

- Field names listed in the tables above (`version`, `modules`, `name`,
  `cve`, `result`).
- The `result` enum string set. New result strings cannot appear
  without a major version bump.
- The `modules` array containing exactly one entry per registered
  module.
- Exit-code semantics for `--scan`.

**May change without notice:**

- The `modules` array length, ordering, and contents (new modules are
  added regularly; ordering follows registration order which is
  stable per release but not a contract).
- Whitespace / formatting of the JSON itself (consumers MUST parse,
  not regex).
- Field values for `cve` (a stub variant could gain a real CVE later).

**May be added in future minor versions:**

- New per-module fields (e.g. `family`, `summary`, `safety_rank`,
  `kernel_range`). Consumers MUST ignore unknown fields.
- New top-level fields (e.g. `host_fingerprint`, `scan_started_at`,
  `schema_version`). Consumers MUST ignore unknown fields.
- A `--scan --active --json` output may grow per-probe verdict
  metadata under a new `probe` sub-object.

## Recommended consumer pattern

```python
import json, subprocess, sys

doc = json.loads(subprocess.check_output(
    ["skeletonkey", "--scan", "--json", "--no-color"],
    stderr=subprocess.DEVNULL,
))

assert doc["version"], "missing top-level version"
for mod in doc["modules"]:
    assert mod["name"] and mod["cve"] and mod["result"], \
        f"malformed module entry: {mod!r}"
    if mod["result"] == "VULNERABLE":
        print(f"{mod['name']} ({mod['cve']}): VULNERABLE", file=sys.stderr)
```

Ignore unknown fields. Match `result` against the enum, but treat
unknown strings as `TEST_ERROR`-equivalent (forward-compat).
