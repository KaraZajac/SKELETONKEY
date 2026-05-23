#!/usr/bin/env python3
"""
tools/refresh-kernel-ranges.py — Detect drift between each module's
kernel_patched_from table and Debian's security-tracker data.

The repo's no-fabrication rule (CVES.md) means every kernel_range
threshold has to come from a real, citeable source. Debian's
security tracker is the most reliable per-CVE backport list — it's
machine-readable and updated continuously by the Debian security
team. This script:

  1. Fetches https://security-tracker.debian.org/tracker/data/json
     (cached at /tmp/skeletonkey-debian-tracker.json, 12h TTL).
  2. Scans every modules/*/skeletonkey_modules.c for
     `kernel_patched_from <name>[] = { {M, m, p}, ... };` arrays and
     their corresponding `.cve = "CVE-..."` entry.
  3. For each module, compares the table against Debian's tracked
     fixed-versions for that CVE.
  4. Reports:
       missing branch       — Debian has a fix at X.Y.Z; our table
                              has no X.Y entry. The module's detect()
                              would say VULNERABLE on a Debian host
                              that's actually patched.
       too-tight threshold  — Our X.Y.Z is HIGHER than Debian's fix
                              version; our module would call a
                              fixed host vulnerable. False-positive.
       info (more conservative) — Our threshold is LOWER than
                              Debian's; we accept earlier kernels
                              as patched. Could be intentional or
                              could mean we have stale data.

Usage:
    tools/refresh-kernel-ranges.py            # human report
    tools/refresh-kernel-ranges.py --json     # machine-readable
    tools/refresh-kernel-ranges.py --patch    # propose C-source edits
    tools/refresh-kernel-ranges.py --refresh  # force re-fetch
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request

CACHE = "/tmp/skeletonkey-debian-tracker.json"
TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
CACHE_TTL_SEC = 12 * 3600


# ── tracker fetch ────────────────────────────────────────────────────

def fetch_tracker(force_refresh: bool = False) -> dict:
    """Return the parsed Debian tracker JSON. Cached at /tmp with 12h TTL."""
    if not force_refresh and os.path.exists(CACHE):
        age = time.time() - os.stat(CACHE).st_mtime
        if age < CACHE_TTL_SEC:
            print(f"[*] using cached tracker ({CACHE}, age {int(age)}s)",
                  file=sys.stderr)
            with open(CACHE) as f:
                return json.load(f)
    print(f"[*] fetching {TRACKER_URL} ...", file=sys.stderr)
    req = urllib.request.Request(
        TRACKER_URL,
        headers={"User-Agent": "skeletonkey/refresh-kernel-ranges"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(CACHE, "wb") as f:
        f.write(data)
    print(f"[*] tracker cached: {len(data) // 1024} KB", file=sys.stderr)
    return json.loads(data)


# ── module source parsing ────────────────────────────────────────────

# Some modules have multiple .cve entries (e.g. dirty_frag_esp +
# dirty_frag_esp6 share the same CVE). Pull the first one.
RE_CVE = re.compile(r'\.cve\s*=\s*"(CVE-\d{4}-\d{4,7})"')
RE_TABLE = re.compile(
    r'kernel_patched_from\s+(\w+)\s*\[\]\s*=\s*\{([^}]+(?:\}[^}]*)*?)\}\s*;',
    re.MULTILINE,
)
RE_ENTRY = re.compile(r'\{\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}')


def find_modules(repo_root: str):
    """Yield {name, src, cve, table, table_name, table_span} per module.

    `table_span` is (start, end) byte offsets of the array body for
    --patch mode that wants to edit the source. `table` is a list of
    (major, minor, patch) tuples in source order."""
    mods_dir = os.path.join(repo_root, "modules")
    for d in sorted(os.listdir(mods_dir)):
        src = os.path.join(mods_dir, d, "skeletonkey_modules.c")
        if not os.path.exists(src):
            continue
        with open(src) as f:
            text = f.read()
        cve_m = RE_CVE.search(text)
        if not cve_m:
            continue
        tab_m = RE_TABLE.search(text)
        if not tab_m:
            continue
        entries = [tuple(int(x) for x in e) for e in RE_ENTRY.findall(tab_m.group(2))]
        if not entries:
            continue
        yield {
            "name": d,
            "src": src,
            "cve": cve_m.group(1),
            "table": entries,
            "table_name": tab_m.group(1),
            "table_span": (tab_m.start(2), tab_m.end(2)),
        }


# ── Debian tracker lookup ────────────────────────────────────────────

# Debian release names we care about (in age order, oldest first).
# The tracker has more (e.g. ELTS) but those are usually too old to
# inform mainline-or-near-mainline backport thresholds.
DEBIAN_RELEASES = ["bullseye", "bookworm", "trixie", "forky", "sid"]


def parse_upstream_version(deb_ver: str) -> tuple[int, int, int] | None:
    """Map a Debian package version like '5.10.218-1' to upstream
    (5, 10, 218). Returns None on parse failure."""
    if not deb_ver:
        return None
    # Strip everything after first '-' (Debian revision) or '+' (backport).
    head = re.split(r'[-+~]', deb_ver, maxsplit=1)[0]
    parts = head.split(".")
    if len(parts) < 3:
        # Some Debian versions are X.Y (no patch). Treat patch as 0.
        if len(parts) == 2:
            parts.append("0")
        else:
            return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def debian_fixed_for(tracker: dict, cve: str) -> dict[str, tuple[int, int, int]]:
    """For a CVE, return {debian_release: upstream_version_tuple} of
    fixed versions per the tracker. Skips releases with no fix yet."""
    out: dict[str, tuple[int, int, int]] = {}
    for pkg in ("linux", "linux-grsec"):
        pkg_data = tracker.get(pkg, {})
        if cve not in pkg_data:
            continue
        cve_data = pkg_data[cve]
        for release, info in cve_data.get("releases", {}).items():
            if release not in DEBIAN_RELEASES:
                continue
            if info.get("status") != "resolved":
                continue
            fixed = info.get("fixed_version")
            up = parse_upstream_version(fixed)
            if up:
                out[release] = up
    return out


# ── compare + report ─────────────────────────────────────────────────

def branch_of(v: tuple[int, int, int]) -> tuple[int, int]:
    return (v[0], v[1])


def compare(table: list[tuple[int, int, int]],
            debian: dict[str, tuple[int, int, int]]) -> list[dict]:
    """Return a list of finding dicts ({severity, message, ...})."""
    findings: list[dict] = []
    our_by_branch = {branch_of(t): t for t in table}

    # Group Debian releases by branch (multiple releases may share a branch)
    debian_by_branch: dict[tuple[int, int], list[tuple[str, tuple[int, int, int]]]] = {}
    for rel, ver in debian.items():
        debian_by_branch.setdefault(branch_of(ver), []).append((rel, ver))

    for branch, rels in debian_by_branch.items():
        # Use the OLDEST fix Debian has on this branch (most permissive)
        rels.sort(key=lambda x: x[1])
        oldest_rel, oldest_ver = rels[0]
        rel_list = ", ".join(f"{r}: {v[0]}.{v[1]}.{v[2]}" for r, v in rels)

        if branch not in our_by_branch:
            findings.append({
                "severity": "MISSING",
                "message": (
                    f"Debian has fix on the {branch[0]}.{branch[1]} branch "
                    f"(earliest: {oldest_ver[0]}.{oldest_ver[1]}.{oldest_ver[2]}, "
                    f"all: {rel_list}), but our table has no {branch[0]}.{branch[1]} entry"
                ),
                "suggest_add": list(oldest_ver),
            })
        else:
            our = our_by_branch[branch]
            if our[2] > oldest_ver[2]:
                findings.append({
                    "severity": "TOO_TIGHT",
                    "message": (
                        f"Our {our[0]}.{our[1]}.{our[2]} threshold is later than "
                        f"Debian's earliest fix on the {branch[0]}.{branch[1]} branch "
                        f"({oldest_ver[0]}.{oldest_ver[1]}.{oldest_ver[2]}, from "
                        f"{oldest_rel}). Hosts at {branch[0]}.{branch[1]}.{oldest_ver[2]} "
                        "are patched per Debian but our detect() would report "
                        "VULNERABLE."
                    ),
                    "suggest_replace": list(oldest_ver),
                })
            elif our[2] < oldest_ver[2]:
                # Our threshold is earlier — we're more permissive about
                # what counts as patched. Usually fine (we have better
                # info than Debian's stable backport) but flag as info.
                findings.append({
                    "severity": "INFO",
                    "message": (
                        f"Our {our[0]}.{our[1]}.{our[2]} threshold is earlier "
                        f"than Debian's {oldest_ver[0]}.{oldest_ver[1]}.{oldest_ver[2]} "
                        f"({oldest_rel}). We're more permissive — verify this "
                        "is intentional (e.g. we tracked a different distro's "
                        "earlier backport)."
                    ),
                })

    return findings


# ── main ─────────────────────────────────────────────────────────────

def render_text(reports: list[dict]) -> None:
    """Human-readable report on stderr."""
    drifted = 0
    for r in reports:
        if not r["findings"]:
            print(f"[+] {r['name']:32s} ({r['cve']}) — table is current "
                  f"({len(r['table'])} entries)")
            continue
        drifted += 1
        print(f"[!] {r['name']} ({r['cve']})")
        print(f"    table: " + ", ".join(
            f"{M}.{m}.{p}" for (M, m, p) in r["table"]))
        if r["debian"]:
            print(f"    debian: " + ", ".join(
                f"{rel}={M}.{m}.{p}"
                for rel, (M, m, p) in sorted(r["debian"].items())))
        else:
            print("    debian: (no resolved entries for this CVE)")
        for f in r["findings"]:
            tag = {"MISSING": "+", "TOO_TIGHT": "✗", "INFO": "i"}[f["severity"]]
            print(f"      [{tag}] {f['message']}")
        print()
    total = len(reports)
    print(f"=== {drifted}/{total} module(s) drifted ===", file=sys.stderr)


def render_json(reports: list[dict]) -> None:
    print(json.dumps({"modules": reports}, indent=2, default=lambda o: list(o)))


def render_patch(reports: list[dict]) -> None:
    """Emit a brief proposed-edits diff for modules with MISSING or
    TOO_TIGHT findings. Not actually applied — operator reviews."""
    for r in reports:
        actionable = [f for f in r["findings"]
                      if f["severity"] in ("MISSING", "TOO_TIGHT")]
        if not actionable:
            continue
        print(f"--- {r['src']}")
        print(f"+++ {r['src']} (proposed)")
        print(f"@@ kernel_patched_from {r['table_name']}[] @@")
        # Reconstruct the table with the actionable changes applied.
        new_table = list(r["table"])
        new_branches = {branch_of(t): list(t) for t in new_table}
        for f in actionable:
            if "suggest_add" in f:
                v = tuple(f["suggest_add"])
                new_branches[branch_of(v)] = list(v)
            elif "suggest_replace" in f:
                v = tuple(f["suggest_replace"])
                new_branches[branch_of(v)] = list(v)
        new_sorted = sorted(new_branches.values())
        old_set = {tuple(t) for t in r["table"]}
        for entry in new_sorted:
            t = tuple(entry)
            if t in old_set:
                print(f"     {{{entry[0]:>2}, {entry[1]:>2}, {entry[2]:>3}}},")
            else:
                print(f" +   {{{entry[0]:>2}, {entry[1]:>2}, {entry[2]:>3}}},")
        for old in r["table"]:
            if branch_of(old) not in new_branches or \
               list(old) != new_branches[branch_of(old)]:
                print(f" -   {{{old[0]:>2}, {old[1]:>2}, {old[2]:>3}}},")
        print()


def main() -> int:
    json_mode = "--json" in sys.argv
    patch_mode = "--patch" in sys.argv
    force = "--refresh" in sys.argv

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tracker = fetch_tracker(force_refresh=force)

    if "linux" not in tracker:
        print("[-] tracker JSON has no 'linux' package — schema changed?",
              file=sys.stderr)
        return 1

    reports: list[dict] = []
    for mod in find_modules(repo_root):
        debian = debian_fixed_for(tracker, mod["cve"])
        findings = compare(mod["table"], debian)
        reports.append({
            "name": mod["name"],
            "src": mod["src"],
            "cve": mod["cve"],
            "table_name": mod["table_name"],
            "table": [list(t) for t in mod["table"]],
            "debian": {k: list(v) for k, v in debian.items()},
            "findings": findings,
        })

    if json_mode:
        render_json(reports)
    elif patch_mode:
        render_patch(reports)
    else:
        render_text(reports)

    # Exit code: 1 if any MISSING or TOO_TIGHT, 0 otherwise. INFO is fine.
    actionable = sum(1 for r in reports for f in r["findings"]
                     if f["severity"] in ("MISSING", "TOO_TIGHT"))
    return 1 if actionable else 0


if __name__ == "__main__":
    sys.exit(main())
