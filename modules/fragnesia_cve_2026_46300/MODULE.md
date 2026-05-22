# fragnesia — CVE-2026-46300

> 🟡 **PRIMITIVE / ported.** Faithful port of the public V12 PoC into
> the `skeletonkey_module` interface. **Not yet validated end-to-end on
> a vulnerable-kernel VM** — see _Verification status_ below.

## Summary

Fragnesia ("Fragment Amnesia") is an XFRM ESP-in-TCP local privilege
escalation. `skb_try_coalesce()` fails to propagate the
`SKBFL_SHARED_FRAG` marker when moving paged fragments between socket
buffers — so the kernel forgets that a fragment is externally backed by
page-cache pages spliced in from a file. The ESP-in-TCP receive path
then decrypts in place, corrupting the page cache of a read-only file.

Fragnesia is a **latent bug exposed by the Dirty Frag fix**: the
candidate patch cites the Dirty Frag remediation (`f4c50a4034e6`) as a
commit it "fixes". It is the same page-cache-write bug class as Copy
Fail / Dirty Frag, reached through a different code path.

## Primitive

1. Build a 256-entry **AES-GCM keystream-byte table** via `AF_ALG`
   `ecb(aes)` — for any wanted output byte, this yields the ESP IV
   whose keystream byte XORs the current byte to the target.
2. Enter a mapped **user namespace** + **network namespace**, bring
   loopback up, and install an XFRM **ESP-in-TCP** state
   (`rfc4106(gcm(aes))`, `TCP_ENCAP_ESPINTCP`).
3. A **receiver** accepts a loopback TCP connection and flips it to the
   `espintcp` ULP; a **sender** `splice()`s page-cache pages of the
   target file into that TCP stream behind a crafted ESP prefix.
4. The coalesce bug makes the kernel decrypt the spliced page-cache
   pages in place — one chosen byte per trigger.

The exploit rewrites the first 192 bytes of a setuid-root binary
(`/usr/bin/su` and friends) with an ET_DYN ELF that drops privileges to
0 and `execve`s `/bin/sh`.

## Operations

| Op | Behaviour |
|---|---|
| `--scan` | Checks unprivileged-userns availability + a readable setuid carrier ≥ 4096 bytes. With `--active`, runs the full ESP-in-TCP primitive against a disposable `/tmp` file and reports VULNERABLE/OK empirically. |
| `--exploit … --i-know` | Forks a child that places the payload into the carrier's page cache and execs it for a root shell. `--no-shell` stops after the page-cache write. |
| `--cleanup` | Evicts the carrier from the page cache. The on-disk binary is never written. |
| `--detect-rules` | Emits embedded auditd + sigma rules. |

## Preconditions

- **Unprivileged user namespaces enabled.** On Ubuntu, AppArmor blocks
  this by default — `sysctl kernel.apparmor_restrict_unprivileged_userns=0`
  (or chain a separate bypass). This is the scoping question the old
  `_stubs/fragnesia_TBD` raised; the module ships and reports
  `PRECOND_FAIL` cleanly when the userns gate is closed.
- `CONFIG_INET_ESPINTCP` built into the kernel.
- A readable setuid-root binary ≥ 4096 bytes as the payload carrier.
- x86_64 (the embedded ELF payload is x86_64 shellcode).

## Port notes

The upstream PoC renders a full-screen ANSI "smash frame" TUI
(`draw_smash_frame` + terminal scroll-region escapes). That is **not**
ported — it cannot coexist with a shared multi-module dispatcher.
Progress is logged with `[*]`/`[+]`/`[-]` prefixes, gated on `--json`.
The exploit mechanism itself is reproduced faithfully.

## Verification status

This module is a **faithful port** of
<https://github.com/v12-security/pocs/tree/main/fragnesia>, compiled
into the SKELETONKEY module interface. It has **not** been validated
end-to-end against a known-vulnerable kernel inside the SKELETONKEY CI
matrix.

`detect()` deliberately does **not** return a kernel-version-based
patched/vulnerable verdict: the CVE-2026-46300 fix commit is not yet
pinned here. Instead:

- preconditions missing → `PRECOND_FAIL`
- preconditions present, no `--active` → `TEST_ERROR` so `--auto` does
  not fire it blind
- `--active` → empirical VULNERABLE / OK via the `/tmp` sentinel probe

**Before promoting to 🟢:** pin the fix commit + branch-backport
thresholds, add a `kernel_range`, and validate on a vulnerable VM.
