# IAMROOT for defenders

IAMROOT is dual-use: the same binary that runs exploits also ships the
detection rules to spot them. This document is for the blue team.

## TL;DR

```bash
# 1. Detect what you're vulnerable to (no system modification)
sudo iamroot --scan --json | jq .

# 2. Deploy detection rules covering every bundled CVE
sudo iamroot --detect-rules --format=auditd | sudo tee /etc/audit/rules.d/99-iamroot.rules
sudo systemctl restart auditd

# 3. (Optional) Apply pre-patch mitigations for vulnerable families
sudo iamroot --mitigate copy_fail   # or whatever module reports VULNERABLE

# 4. Watch
sudo ausearch -k iamroot-copy-fail -ts recent
sudo ausearch -k iamroot-dirty-pipe -ts recent
sudo ausearch -k iamroot-pwnkit -ts recent
```

## Why a single tool for offense and defense

Public LPE PoCs ship without detection rules. Public detection rules
ship without test corpora. The gap means defenders deploy rules they
never validate against a real exploit, and attackers iterate against
defenders who haven't tuned thresholds. IAMROOT closes that loop:

- Each module ships an exploit AND the detection rules that catch it.
- Every CVE in `CVES.md` has a row in the rule corpus.
- New CVEs we add ship both halves — there's no "rule lag" between an
  exploit landing in the bundle and the rule being available.
- Detection-rule tests live in CI alongside exploit tests (Phase 4
  followup).

## Operations cheat sheet

### Inventory what's bundled

```bash
iamroot --list
```

Prints every registered module with CVE, family, and one-line summary.

### Run all detectors

```bash
iamroot --scan                          # human-readable
iamroot --scan --json                   # one JSON object → SIEM ingest
iamroot --scan --json | jq '.modules[] | select(.result == "VULNERABLE")'
```

Result codes per module:

| Result | Meaning | Exit code |
|---|---|---|
| `OK` | Not vulnerable (patched, immune, or N/A) | 0 |
| `VULNERABLE` | Detect confirmed vulnerable | 2 |
| `PRECOND_FAIL` | Preconditions missing (module/feature not installed) | 4 |
| `TEST_ERROR` | Probe could not run (permissions, missing tools, etc.) | 1 |

`iamroot --scan` returns the WORST result code across all modules.
Use this in CI to fail builds that produce vulnerable images.

### Deploy detection rules

```bash
# auditd (most environments)
sudo iamroot --detect-rules --format=auditd \
  | sudo tee /etc/audit/rules.d/99-iamroot.rules
sudo augenrules --load     # or systemctl restart auditd

# Sigma (for SIEMs that ingest sigma)
iamroot --detect-rules --format=sigma > /etc/falco/iamroot.sigma.yml

# YARA / Falco — placeholders for future modules; currently empty
iamroot --detect-rules --format=yara
iamroot --detect-rules --format=falco
```

Rules are emitted in registry order, deduplicated by string-pointer:
family-shared rule sets emit once with a "see family rules above"
marker on siblings (no duplicate `-w /etc/passwd` lines hitting your
auditd config).

### Audit keys to watch

| Key | Modules | What it catches |
|---|---|---|
| `iamroot-copy-fail` | copy_fail, copy_fail_gcm, dirty_frag_esp{,6}, dirty_frag_rxrpc | Writes to passwd/shadow/sudoers/su |
| `iamroot-copy-fail-afalg` | copy_fail family | AF_ALG socket creation (kernel crypto API used by exploit) |
| `iamroot-copy-fail-xfrm` | copy_fail family | xfrm setsockopt (Dirty Frag ESP variants) |
| `iamroot-dirty-pipe` | dirty_pipe | Same target files; complements copy-fail watches |
| `iamroot-dirty-pipe-splice` | dirty_pipe | splice() syscalls (the bug's primitive) |
| `iamroot-pwnkit` | pwnkit | pkexec watch |
| `iamroot-pwnkit-execve` | pwnkit | execve of pkexec — combine with audit of argv to catch argc=0 |

Search:

```bash
sudo ausearch -k iamroot-copy-fail -ts today
sudo ausearch -k iamroot-pwnkit -ts today
```

### Mitigate (pre-patch)

For families with mitigations available, `--mitigate <name>` applies
distro-portable workarounds:

```bash
# Currently: copy_fail_family — blacklists algif_aead/esp4/esp6/rxrpc,
# sets kernel.apparmor_restrict_unprivileged_userns=1, drops caches.
sudo iamroot --mitigate copy_fail

# Revert mitigation (e.g., before applying the real kernel patch)
sudo iamroot --cleanup copy_fail
```

Modules without `--mitigate` (dirty_pipe, entrybleed, pwnkit) report
that the only real fix is upgrading the affected component. We don't
ship a half-baked mitigation when the real one is a package update.

## Fleet scanning

The `--scan --json` output is one-line-per-host friendly:

```bash
# scan a host list via ssh
for h in $(cat fleet.txt); do
  ssh $h sudo iamroot --scan --json | jq --arg h "$h" '. + {host: $h}'
done | jq -s . > fleet-scan-$(date +%F).json

# group by vulnerability
jq '.[] | {host, vulns: .modules | map(select(.result == "VULNERABLE")) | map(.cve)}' \
   fleet-scan-*.json
```

For very large fleets, deploy the binary as a one-shot under a remote
shell tool (Ansible/SaltStack/Fabric/etc.) and aggregate JSON output
into your SIEM. Each scan is a few seconds of CPU and no system
modification.

## Known false positives

| Rule | False-positive shape |
|---|---|
| `iamroot-copy-fail-afalg` | strongSwan and IPsec daemons use AF_ALG legitimately — scope with `-F auid=` to exclude service accounts |
| `iamroot-dirty-pipe-splice` | nginx, HAProxy, kTLS use splice() heavily — scope with `-F gid!=33 -F gid!=99` for those service accounts |
| `iamroot-pwnkit-execve` | gnome-software, polkit's own dispatcher legitimately exec pkexec — scope by parent process if you can correlate |

The shipped rules are starting points. Tune per environment.

## Submitting new detections

If you find a detection signature for a CVE we already bundle, file an
issue. We'll integrate the rule into the relevant module's
`detect_*` field and ship it on the next release. New CVEs accept
contributions per `docs/ARCHITECTURE.md`'s "adding a new CVE" flow —
each new module ships its own detection rules from day one.
