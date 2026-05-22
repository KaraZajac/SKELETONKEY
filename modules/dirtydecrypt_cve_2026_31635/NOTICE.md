# NOTICE — dirtydecrypt

## Vulnerability

**CVE-2026-31635** — "DirtyDecrypt" / "DirtyCBC". Missing copy-on-write
guard in `rxgk_decrypt_skb()` (`net/rxrpc/rxgk_common.h`). The function
calls `skb_to_sgvec()` then `crypto_krb5_decrypt()` with no
`skb_cow_data()`; the `krb5enc` AEAD template (`crypto/krb5enc.c`)
decrypts **in place** before verifying the HMAC. When the skb fragment
pages are page-cache pages (spliced in via `MSG_SPLICE_PAGES` over
loopback), the in-place decrypt corrupts the page cache of a read-only
file. The same pattern exists in rxkad (`rxkad_verify_packet_2`).

Sibling of Copy Fail (CVE-2026-31431) and Dirty Frag
(CVE-2026-43284 / CVE-2026-43500) — all are page-cache write
primitives that abuse a missing COW boundary.

## Research credit

Discovered and reported by the **Zellic** and **V12 security** team.
Public proof-of-concept by **Luna Tong** ("cts" / "gf_256"), Zellic
co-founder, on the V12 team.

> Reference PoC: <https://github.com/v12-security/pocs/tree/main/dirtydecrypt>

On disclosure (2026-05-09) the kernel maintainers indicated the issue
duplicated a flaw already patched in mainline; CVE-2026-31635 was
assigned subsequently.

## SKELETONKEY role

`skeletonkey_modules.c` is a port of the V12 PoC into the
`skeletonkey_module` interface. The exploit primitive — the
`fire()` / `pagecache_write()` sliding-window machinery, the rxgk XDR
token builder, the 120-byte ET_DYN ELF payload — is reproduced from
that PoC. SKELETONKEY adds the detect/cleanup lifecycle, an `--active`
sentinel probe, `--no-shell` support, and the embedded detection
rules. Research credit belongs to the people above.

## Verification status

**Ported, not yet validated end-to-end on a vulnerable-kernel VM.**
The CVE-2026-31635 fix commit is not yet pinned in this module, so
`detect()` does not perform a kernel-version patched/vulnerable
verdict — see `MODULE.md`.
