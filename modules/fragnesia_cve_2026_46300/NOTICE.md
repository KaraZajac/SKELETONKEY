# NOTICE — fragnesia

## Vulnerability

**CVE-2026-46300** — "Fragnesia" ("Fragment Amnesia"). XFRM ESP-in-TCP
local privilege escalation. `skb_try_coalesce()` fails to propagate the
`SKBFL_SHARED_FRAG` marker when moving paged fragments between socket
buffers, so the kernel loses track of the fact that a fragment is
externally backed by page-cache pages spliced in from a file. The
ESP-in-TCP receive path then decrypts in place, corrupting the page
cache of a read-only file.

Fragnesia is a **latent bug exposed by the Dirty Frag remediation**:
the candidate fix explicitly cites the Dirty Frag patch
(`f4c50a4034e6`) as a commit it "fixes" — the Dirty Frag remediation
made a previously latent flaw practically exploitable.

## Research credit

Discovered by **William Bowling** with the **V12 security** team.

> Reference PoC: <https://github.com/v12-security/pocs/tree/main/fragnesia>
> Patch thread: <https://lists.openwall.net/netdev/2026/05/13/79>

## SKELETONKEY role

`skeletonkey_modules.c` is a port of the V12 PoC
(`xfrm_espintcp_pagecache_replace`) into the `skeletonkey_module`
interface. The exploit primitive — the AES-GCM keystream-byte table
built via AF_ALG, the per-byte IV selection, the userns + netns + XFRM
ESP-in-TCP setup, the splice-driven sender/receiver trigger pair, the
192-byte ELF payload — is reproduced from that PoC.

**Port adaptation:** the PoC's ANSI "smash frame" TUI
(`draw_smash_frame` + terminal scroll-region escape sequences) is
**not** carried over — it is incompatible with running as one module
among many under a shared dispatcher. Progress is reported with
SKELETONKEY's `[*]`/`[+]`/`[-]` log prefixes instead. SKELETONKEY also
adds the detect/cleanup lifecycle, an `--active` probe, `--no-shell`
support, and the embedded detection rules. Research credit belongs to
the people above.

## Verification status

**Ported, not yet validated end-to-end on a vulnerable-kernel VM.**
Requires `CONFIG_INET_ESPINTCP` and unprivileged user-namespace
creation. The CVE-2026-46300 fix commit is not yet pinned in this
module — see `MODULE.md`.
