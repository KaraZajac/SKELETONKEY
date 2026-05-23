# SKELETONKEY detection playbook

Operational guide for blue teams using SKELETONKEY defensively. Pairs
with `docs/DEFENDERS.md` (the "what" reference) — this is the "how to
make it part of your daily ops" guide.

## The lifecycle

```
              ┌─────────────┐
              │  inventory  │  ← skeletonkey --list (what's bundled?)
              └──────┬──────┘
                     ▼
              ┌─────────────┐
              │    scan     │  ← skeletonkey --scan --json (what am I vulnerable to?)
              └──────┬──────┘
                     ▼
              ┌─────────────┐
              │  fleet scan │  ← skeletonkey-fleet-scan.sh hosts.txt
              └──────┬──────┘
                     ▼
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   ┌────────┐  ┌─────────┐  ┌──────────┐
   │ deploy │  │ mitigate│  │  upgrade │  ← three responses
   │  rules │  │ (pre-fix│  │ (kernel  │
   │(SIEM)  │  │ stopgap)│  │  patch)  │
   └────┬───┘  └─────┬───┘  └─────┬────┘
        └────────────┼────────────┘
                     ▼
              ┌─────────────┐
              │   monitor   │  ← ausearch -k skeletonkey-* / SIEM alerts
              └─────────────┘
```

## Recipes by team size

### Single host (workstation / single server)

```bash
# Daily/weekly hygiene check
sudo skeletonkey --scan

# Investigate a specific finding (one-page operator briefing)
sudo skeletonkey --explain nf_tables    # whichever module came back VULNERABLE
# Shows: CVE / CWE / MITRE ATT&CK / CISA KEV status, live detect() trace,
# OPSEC footprint (what an exploit would leave behind), detection-rule
# coverage, mitigation. Paste into the triage ticket.

# If anything's VULNERABLE, deploy detections + apply mitigation
sudo skeletonkey --detect-rules --format=auditd | sudo tee /etc/audit/rules.d/99-skeletonkey.rules
sudo augenrules --load
sudo skeletonkey --mitigate copy_fail   # or whichever module fired
```

The `--explain` output is also useful as a learning artifact: each
module's `--explain` block is a self-contained CVE briefing with the
reasoning chain the detect() function walked, so analysts can verify
SKELETONKEY's verdict against their own understanding of the bug.

### Small fleet (~10-100 hosts, SSH-reachable)

Use `tools/skeletonkey-fleet-scan.sh`:

```bash
# Hosts list — one per line; user@host:port supported
cat > hosts.txt <<EOF
prod-web-01
prod-web-02
deploy@bastion-01
ops@db-01:2222
EOF

# Scan; binary scp'd, run, cleaned up. Output is one JSON doc.
./skeletonkey-fleet-scan.sh \
    --binary ./skeletonkey \
    --ssh-key ~/.ssh/ops_key \
    --parallel 8 \
    hosts.txt > fleet-scan-$(date +%F).json

# Show me hosts with any VULNERABLE finding
jq '.hosts[] | select(.scan.modules | map(.result == "VULNERABLE") | any) | .host' \
   fleet-scan-*.json

# Show summary across the fleet
jq '.summary' fleet-scan-*.json
```

Output shape:

```json
{
  "generated_at": "2026-05-16T22:00:00Z",
  "n_hosts": 4,
  "summary": {
    "ok": 4,
    "failed": 0,
    "vulnerable": [
      { "cve": "CVE-2024-1086", "name": "nf_tables", "count": 2 },
      { "cve": "CVE-2023-0458", "name": "entrybleed", "count": 4 }
    ]
  },
  "hosts": [...]
}
```

### Larger fleet (>100 hosts)

`skeletonkey-fleet-scan.sh` is intentionally simple (parallel ssh). For
fleets too large for SSH-fan-out, wrap it in your config-management
tool of choice:

- **Ansible**: ship the binary via `copy:`, run via `command:`, parse
  JSON with `jq` in a follow-on task
- **SaltStack**: `cmd.run` returning JSON; `salt-call --return` to your
  SIEM
- **Fabric / Mitogen**: same shape, just Python-side

Sample Ansible task:

```yaml
- name: scan with skeletonkey
  copy:
    src: skeletonkey
    dest: /tmp/skeletonkey
    mode: '0755'
- name: run --scan --json
  command: /tmp/skeletonkey --scan --json --no-color
  register: scan
  changed_when: false
  failed_when: false        # skeletonkey exit codes are semantic, not errors
- name: collect
  set_fact:
    skeletonkey_scan: "{{ scan.stdout | from_json }}"
- name: cleanup
  file:
    path: /tmp/skeletonkey
    state: absent
```

## SIEM integration patterns

### Splunk

```
# splunk input config (inputs.conf)
[script:///opt/skeletonkey/skeletonkey-cron-scan.sh]
interval = 86400
source = skeletonkey
sourcetype = skeletonkey:scan
```

`skeletonkey-cron-scan.sh`:

```bash
#!/bin/bash
/usr/local/bin/skeletonkey --scan --json --no-color
```

Search the indexed events:

```spl
index=skeletonkey sourcetype="skeletonkey:scan" modules{}.result=VULNERABLE
| stats count by host modules{}.cve
```

### Elastic / OpenSearch

Filebeat module reading the per-host scan JSON files (one per day),
indexed into an `skeletonkey-*` index pattern. Standard Kibana
visualization on `modules.cve` over time tracks vulnerability lifecycle.

### Sigma → your platform

```bash
# Ship Sigma rules into your platform
skeletonkey --detect-rules --format=sigma > /etc/sigma/skeletonkey.yml
# Convert to your target (Sentinel, Elastic, etc.) via sigmac
sigmac -t elastic /etc/sigma/skeletonkey.yml
```

### YARA artifact scanning

YARA rules catch the **post-fire** state — page-cache shellcode
overwrites, malicious `.deb` drops, `/etc/passwd` UID flips. Run them
as a scheduled scan against sensitive paths:

```bash
# Ship YARA rules
sudo skeletonkey --detect-rules --format=yara | sudo tee /etc/yara/skeletonkey.yar

# Scheduled scan via cron — catches the page-cache and /tmp artifacts
# /etc/cron.d/skeletonkey-yara
*/15 * * * * root yara -r /etc/yara/skeletonkey.yar \
                       /etc/passwd /tmp /usr/bin/su /usr/bin/passwd \
                       2>>/var/log/skeletonkey-yara.log
```

What each rule catches:

| Rule | Triggers on |
|---|---|
| `etc_passwd_uid_flip` | Non-root user line in `/etc/passwd` with a zero-padded UID (`0000+`). Canonical Copy Fail / Dirty Frag / Dirty Pipe / DirtyDecrypt outcome. |
| `etc_passwd_root_no_password` | `root` line with empty password field — DirtyDecrypt's intermediate corruption step. |
| `pwnkit_gconv_modules_cache` | Small `gconv-modules` text file with a `module UTF-8// X// /tmp/…` redefinition. |
| `dirty_pipe_passwd_uid_flip` | Same UID-flip pattern (Dirty Pipe-specific tag). |
| `dirtydecrypt_payload_overlay` | First 28 bytes of `/usr/bin/su` (or similar) match the embedded 120-byte ET_DYN shellcode the V12 PoC overlays. |
| `fragnesia_payload_overlay` | Same shape for the 192-byte Fragnesia payload. |
| `pack2theroot_malicious_deb` | `.deb` ar-archive in `/tmp` with the SUID-bash postinst. |
| `pack2theroot_suid_bash_drop` | `/tmp/.suid_bash` exists and is a real bash ELF. |

The page-cache overlay rules (`dirtydecrypt_payload_overlay`,
`fragnesia_payload_overlay`) are particularly high-signal: no
legitimate ELF starts with those exact 28 bytes, so a hit means the
exploit landed.

### Falco runtime detection

Falco catches the exploit **as it fires** by hooking syscalls and
namespace events. Best deploy for K8s / container hosts but works on
any modern Linux:

```bash
sudo skeletonkey --detect-rules --format=falco \
    | sudo tee /etc/falco/rules.d/skeletonkey.yaml
sudo falco --validate /etc/falco/rules.d/skeletonkey.yaml
sudo systemctl reload falco   # or restart, depending on distro
```

What each rule catches:

| Rule | Triggers on |
|---|---|
| `Pwnkit-style pkexec invocation` | `pkexec` spawned with empty argv (the bug's hallmark). |
| `Pwnkit-style GCONV_PATH injection` | Non-root sets `GCONV_PATH=` / `CHARSET=` before spawning a setuid binary. |
| `AF_ALG authenc keyblob installed by non-root` | `socket(AF_ALG)` by non-root — Copy Fail / GCM variant primitive. |
| `XFRM NETLINK_XFRM bind from unprivileged userns` | XFRM SA setup from non-root userns — Dirty Frag / Fragnesia primitive. |
| `/etc/passwd modified by non-root` | Post-fire signal for the whole page-cache-write family. |
| `Dirty Pipe splice from setuid/sensitive file by non-root` | `splice()` of `/etc/passwd` or `/usr/bin/su` by non-root. |
| `AF_RXRPC socket created by non-root` | DirtyDecrypt primitive — `socket(AF_RXRPC)` is nearly unheard-of in production. |
| `rxrpc security key added` | `add_key("rxrpc", …)` by non-root — DirtyDecrypt handshake setup. |
| `TCP_ULP=espintcp set by non-root` | Fragnesia trigger — flipping a TCP socket to espintcp ULP. |
| `SUID bash dropped to /tmp` | Pack2TheRoot postinst landing `/tmp/.suid_bash`. |
| `dpkg invoked by PackageKit on behalf of non-root caller` | Pack2TheRoot chain — `packagekitd → dpkg` installing a /tmp `.pk-*.deb`. |

## Day-to-day operational shape

### What "good" looks like in the SIEM

- Daily `skeletonkey --scan --json` from every host indexed
- Trend dashboard: count of VULNERABLE results by CVE over time
- Goal: every VULNERABLE → OK transition within SLA (e.g., 14 days for
  patched-mainline bugs, 24h for actively-exploited)
- Alert on: any host with a result not seen yesterday (could indicate
  a config drift, a new install, or a disabled mitigation)

### Auditd events from the embedded rules

After deploying `skeletonkey --detect-rules --format=auditd`:

```bash
# By module key
sudo ausearch -k skeletonkey-copy-fail -ts today
sudo ausearch -k skeletonkey-dirty-pipe -ts today
sudo ausearch -k skeletonkey-pwnkit -ts today
sudo ausearch -k skeletonkey-nf-tables-userns -ts today
sudo ausearch -k skeletonkey-overlayfs -ts today

# Anything skeletonkey-tagged in the last hour
sudo ausearch -k 'skeletonkey-*' -ts recent

# Forward to syslog (rsyslog example)
# /etc/rsyslog.d/skeletonkey.conf:
:msg, contains, "skeletonkey-" @@your-siem.example.com:514
```

### When a VULNERABLE result fires

Decision tree:

```
A scan reports VULNERABLE for module X
│
├── Q: Can I patch the underlying kernel / package?
│   ├── YES → schedule patch window. In the meantime:
│   │        skeletonkey --mitigate X (if supported)
│   │        Verify auditd rule for X is loaded.
│   │        Monitor for the rule key.
│   └── NO (legacy LTS, embedded device, prod freeze) →
│            skeletonkey --mitigate X (essential)
│            Compensating control: tighten LSM (SELinux/AppArmor)
│            Document in risk register
│
└── Q: Was this VULNERABLE before? When?
    ├── First time → config drift; investigate why detection now
    │                 produces this result
    └── Persistent → mitigation isn't applied OR is being reverted
                      by config management; fix the config baseline
```

### Mitigation reverts

Mitigations can break legitimate functionality:

| Mitigation | Side effect |
|---|---|
| `copy_fail` blacklist algif_aead | strongSwan / IPsec breaks |
| `copy_fail` blacklist esp4/esp6 | IPsec breaks |
| `copy_fail` blacklist rxrpc | AFS / kAFS clients break |
| `copy_fail` AppArmor restrict userns=1 | bubblewrap, podman rootless break |

If you applied a mitigation and now need to revert (e.g., the kernel
patch has rolled out fleet-wide):

```bash
sudo skeletonkey --cleanup copy_fail
# OR manually:
sudo rm /etc/modprobe.d/dirtyfail-mitigations.conf
sudo rm /etc/sysctl.d/99-dirtyfail-mitigations.conf
# Reload affected modules / sysctls per your distro
```

## Per-module detection coverage

Across the 4 rule formats:

| Module | CVE | auditd | sigma | yara | falco |
|---|---|:-:|:-:|:-:|:-:|
| copy_fail | CVE-2026-31431 | ✓ | ✓ | ✓ | ✓ |
| copy_fail_gcm | (variant) | ✓ | ✓ | ✓ | ✓ |
| dirty_frag_esp | CVE-2026-43284 | ✓ | ✓ | ✓ | ✓ |
| dirty_frag_esp6 | CVE-2026-43284 | ✓ | ✓ | ✓ | ✓ |
| dirty_frag_rxrpc | CVE-2026-43500 | ✓ | ✓ | ✓ | ✓ |
| dirty_pipe | CVE-2022-0847 | ✓ | ✓ | ✓ | ✓ |
| dirtydecrypt | CVE-2026-31635 | ✓ | ✓ | ✓ | ✓ |
| fragnesia | CVE-2026-46300 | ✓ | ✓ | ✓ | ✓ |
| pwnkit | CVE-2021-4034 | ✓ | ✓ | ✓ | ✓ |
| pack2theroot | CVE-2026-41651 | ✓ | ✓ | ✓ | ✓ |
| Other 21 modules | various | ✓ | partial | — | — |

Full 4-format coverage on the 10 highest-value modules; auditd
covers everything. YARA / Falco expansion to the remaining 21 modules
is incremental contributor work (each module's `detect_yara` /
`detect_falco` field in the module struct just needs a string).

## Correlation across formats

Single-format detections are useful; the high-confidence signal is
the **correlation across formats** for the same module in a short
window. Each exploit leaves a recognisable multi-format trail:

| Exploit | falco fires | auditd fires | yara confirms |
|---|---|---|---|
| Pwnkit | `pkexec` empty argv | `execve /usr/bin/pkexec` + `GCONV_PATH=` env | gconv-modules cache in /tmp |
| Dirty Pipe | `splice()` from `/etc/passwd` | splice + write to `/etc/passwd` | UID flip in `/etc/passwd` |
| Copy Fail | `socket(AF_ALG)` | algif_aead + `ALG_SET_KEY` | UID flip in `/etc/passwd` |
| Dirty Frag (ESP) | NETLINK_XFRM sendto + TCP_ULP | XFRM_MSG_NEWSA | UID flip in `/etc/passwd` |
| DirtyDecrypt | `socket(AF_RXRPC)` + `add_key(rxrpc)` | AF_RXRPC + add_key | 120-byte ELF overwrites `/usr/bin/su` |
| Fragnesia | `TCP_ULP=espintcp` from non-root | XFRM + setsockopt(TCP_ULP) | 192-byte ELF overwrites `/usr/bin/su` |
| Pack2TheRoot | dpkg invoked by packagekitd with /tmp/.pk-*.deb | new `.deb` in `/tmp` + `chmod 4755` on `/tmp/.suid_bash` | malicious `.deb` + SUID bash both present |

If **three of the four signals** fire for the same module in the same
window, the exploit landed. **One signal alone** in a noisy
environment is more likely a tuning FP; **three signals** is incident
response.

## Worked example: catching DirtyDecrypt end-to-end

A SOC operator gets a Falco page:

```
CRITICAL  AF_RXRPC socket() by non-root  (user=alice proc=poc pid=44231)
```

1. **Confirm via auditd** — pull events keyed on the family:
   ```bash
   sudo ausearch -k skeletonkey-dirtydecrypt-rxrpc -ts recent
   ```
   Expect: `socket(...,33,...)` + subsequent `add_key("rxrpc",...)`.

2. **Confirm via yara** — scan setuid binaries for the page-cache
   overlay:
   ```bash
   yara /etc/yara/skeletonkey.yar /usr/bin/su /usr/bin/passwd
   ```
   If `dirtydecrypt_payload_overlay` matches `/usr/bin/su`, **the
   exploit landed** — the binary's page cache has been overwritten
   with the 120-byte shellcode.

3. **Recover** — the on-disk binary is intact; only the page cache is
   corrupted. Drop it:
   ```bash
   sudo skeletonkey --cleanup dirtydecrypt   # or: echo 3 > /proc/sys/vm/drop_caches
   ```

4. **Sigma hunt for lateral / repeat** — query your SIEM with the
   sigma rule ID `7c1e9a40-skeletonkey-dirtydecrypt` over the last 7
   days to find any other hosts.

5. **Patch.** DirtyDecrypt's mainline fix is commit `a2567217` in
   Linux 7.0 — see [`CVES.md`](../CVES.md) for distro backports.

6. **Harden.** `rxrpc` is rarely needed on non-AFS hosts:
   ```bash
   echo "blacklist rxrpc" | sudo tee /etc/modprobe.d/blacklist-rxrpc.conf
   sudo update-initramfs -u
   ```

The same shape applies to every module: pick the auditd key, the
yara rule for the artifact, the falco rule for the runtime signal,
and the sigma rule for the hunt.

## Common false positives + tuning

| Rule key | False positive | Fix |
|---|---|---|
| `skeletonkey-copy-fail-afalg` | strongSwan, libcrypto using kernel crypto | `-F auid=` exclude service account UIDs |
| `skeletonkey-dirty-pipe-splice` | nginx, HAProxy, kTLS | `-F gid!=33 -F gid!=99` exclude web service accounts |
| `skeletonkey-pwnkit-execve` | gnome-software, polkit's own re-exec | Correlate by parent process; pkexec via gnome dbus is benign |
| `skeletonkey-nf-tables-userns` | docker rootless, podman, snap confined apps | Whitelist known userns-using service GIDs |
| `skeletonkey-overlayfs` | docker / containerd mounting overlayfs as root | The rule is intended for unprivileged-userns overlayfs mounts; add `-F auid>=1000` |

## Pre-patch quarantine pattern

If a CVE is in active exploitation and you can't patch immediately:

```bash
# Stage 1: detect
sudo skeletonkey --scan --json | jq '.modules[] | select(.cve == "CVE-XXXX")'

# Stage 2: mitigate (where supported)
sudo skeletonkey --mitigate <module>

# Stage 3: monitor — auditd rules already deployed
sudo ausearch -k 'skeletonkey-*' -ts today | grep <module>

# Stage 4: contain — temporarily restrict the trigger surface
# e.g., for nf_tables CVE-2024-1086:
echo 0 | sudo tee /proc/sys/kernel/unprivileged_userns_clone
# OR
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1

# Stage 5: alert
# When auditd or sigma rule fires, page on-call
```

## Maintenance contract

When SKELETONKEY ships a new module:

1. CI test passes on at least one vulnerable + patched kernel pair
2. Detection rules ship alongside (auditd + sigma minimum)
3. CVES.md row added with patch status
4. NOTICE.md credits original researcher
5. ROADMAP.md updated

Treat these as the SLA for any blue-team-facing deliverable.

## When you find a new false positive

File an issue at https://github.com/KaraZajac/SKELETONKEY/issues with:
- The exact ausearch line that fired
- The legitimate process that produced it
- Distro / kernel version

Most false-positive fixes are a `-F` filter on the embedded rule —
small, mergeable.
