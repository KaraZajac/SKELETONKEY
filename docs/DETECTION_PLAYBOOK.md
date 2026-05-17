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

# If anything's VULNERABLE, deploy detections + apply mitigation
sudo skeletonkey --detect-rules --format=auditd | sudo tee /etc/audit/rules.d/99-skeletonkey.rules
sudo augenrules --load
sudo skeletonkey --mitigate copy_fail   # or whichever module fired
```

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
