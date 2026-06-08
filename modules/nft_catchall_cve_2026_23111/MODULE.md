# nft_catchall — CVE-2026-23111

An nf_tables use-after-free reachable from an unprivileged user: an
inverted condition in `nft_map_catchall_activate()` mishandles catch-all
map elements on transaction abort, freeing a chain that a catch-all GOTO
verdict still references.

## The bug

nftables *maps* can hold a **catch-all** element — a default that matches
when no other element does — and in a verdict map that element carries a
GOTO/JUMP to a chain. `nft_map_catchall_activate()` runs during the
**abort** phase of a netlink transaction to re-activate elements that a
rolled-back batch had touched. A single inverted `!` makes it operate on
*active* catch-all elements instead of skipping them, so the referenced
chain's use-count is driven to zero; a subsequent `DELCHAIN` frees the
chain while the catch-all verdict still points at it → **use-after-free**.

Chaining a kernel-address leak, arbitrary R/W, and a ROP over
`modprobe_path` / `selinux_state` turns the UAF into root — all reachable
by an unprivileged user who has `CONFIG_USER_NS` to gain `CAP_NET_ADMIN`
over a private network namespace.

## Affected range

| | |
|---|---|
| Vulnerable path introduced | ~5.13 (catch-all set elements) |
| Fixed upstream | commit `f41c5d1…` (remove the inverted `!`) |
| Debian backports | 6.1.164 (bookworm) · 6.12.73 (trixie) · 6.18.10 (forky·sid) |
| Table thresholds | 6.1.164 · 6.12.73 · 6.18.10 (≤ Debian → drift-clean) |
| NVD class | CWE-416 (Use After Free), CVSS 7.8 |
| CISA KEV | no |

The 5.10 (bullseye) branch is still unfixed at time of writing →
version-only VULNERABLE there.

## Trigger / detection

`detect()` returns `OK` below ~5.13 or for patched kernels, `PRECOND_FAIL`
when the kernel is vulnerable but unprivileged user-namespace clone is
denied (exploit unreachable), and `VULNERABLE` when the version is in
range and userns is allowed.

`exploit()` forks an isolated child that enters `unshare(USER|NET)`, opens
`NETLINK_NETFILTER`, builds a verdict map with a catch-all GOTO element,
and sends an aborting batch to drive the abort-path UAF; it observes
`nft_chain` / `kmalloc-cg-256` slabinfo and returns `EXPLOIT_FAIL`
(primitive-only). The full leak + R/W + ROP root-pop is **not** bundled,
and the trigger is reconstructed from public analysis, not VM-verified.

## Fix / mitigation

Upgrade the kernel. As a host hardening stopgap, deny unprivileged
user-namespace clone (`sysctl kernel.unprivileged_userns_clone=0`, or the
AppArmor `apparmor_restrict_unprivileged_userns` toggle) — that closes the
unprivileged path even on a kernel-vulnerable host.

## Credit

Upstream fix `f41c5d1…`; public reproduction by FuzzingLabs. See
`NOTICE.md`.
