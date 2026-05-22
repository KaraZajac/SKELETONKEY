# dirtydecrypt — CVE-2026-31635

> 🟡 **PRIMITIVE / ported.** Faithful port of the public V12 PoC into
> the `skeletonkey_module` interface. **Not yet validated end-to-end on
> a vulnerable-kernel VM** — see _Verification status_ below.

## Summary

DirtyDecrypt (a.k.a. DirtyCBC) is a missing copy-on-write guard in
`rxgk_decrypt_skb()` (`net/rxrpc/rxgk_common.h`). The function decrypts
incoming rxgk socket buffers **in place** before the HMAC is verified.
When the skb fragment pages are page-cache pages — spliced in via
`MSG_SPLICE_PAGES` over loopback — the in-place AES decrypt corrupts the
page cache of a read-only file.

It is a sibling of Copy Fail (CVE-2026-31431) and Dirty Frag
(CVE-2026-43284 / 43500): same bug class, different kernel subsystem
(rxgk / AFS-style rxrpc encryption rather than algif_aead or xfrm-ESP).

## Primitive

Each `fire()`:

1. Adds an `rxrpc` security key holding a crafted rxgk XDR token.
2. Opens an `AF_RXRPC` client + a fake UDP server on loopback and
   completes the rxgk handshake.
3. Forges a DATA packet whose **wire header comes from userspace** and
   whose **payload pages come from the target file's page cache**
   (`splice` + `vmsplice`).
4. The kernel decrypts the spliced page-cache pages in place — the HMAC
   check then fails (expected), but the page cache is already mutated.

`pagecache_write()` drives a **sliding-window** technique: byte[0] of
each corrupted 16-byte AES block is uniformly random (≈1/256 chance of
the wanted value), and round _i+1_ at offset _S+i+1_ overwrites the
15-byte collateral of round _i_ without disturbing the byte round _i_
fixed. Net cost ≈ 256 fires per byte.

The exploit rewrites the first 120 bytes of a setuid-root binary
(`/usr/bin/su` and friends) with a tiny ET_DYN ELF that calls
`setuid(0)` + `execve("/bin/sh")`.

## Operations

| Op | Behaviour |
|---|---|
| `--scan` | Checks AF_RXRPC reachability + a readable setuid carrier. With `--active`, fires the primitive against a disposable `/tmp` file and reports VULNERABLE/OK empirically. |
| `--exploit … --i-know` | Forks a child that corrupts the carrier's page cache and execs it for a root shell. `--no-shell` stops after the page-cache write. |
| `--cleanup` | Evicts the carrier from the page cache (`POSIX_FADV_DONTNEED` + `drop_caches`). The on-disk binary is never written. |
| `--detect-rules` | Emits embedded auditd + sigma rules. |

## Preconditions

- `AF_RXRPC` reachable (the `rxrpc` module loadable / built in).
- A readable setuid-root binary to use as the payload carrier.
- x86_64 (the embedded ELF payload is x86_64 shellcode).

## Verification status

This module is a **faithful port** of
<https://github.com/v12-security/pocs/tree/main/dirtydecrypt>, compiled
into the SKELETONKEY module interface. It has **not** been validated
end-to-end against a known-vulnerable kernel inside the SKELETONKEY CI
matrix.

`detect()` deliberately does **not** return a kernel-version-based
patched/vulnerable verdict: the CVE-2026-31635 fix commit is not yet
pinned here, and fabricating a `kernel_patched_from` table would
violate the project's no-fabrication rule (`CVES.md`). Instead:

- preconditions missing → `PRECOND_FAIL`
- preconditions present, no `--active` → `TEST_ERROR` ("cannot
  determine passively") so `--auto` does not fire it blind
- `--active` → empirical VULNERABLE / OK via the `/tmp` sentinel probe

**Before promoting to 🟢:** pin the fix commit + branch-backport
thresholds, add a `kernel_range`, and validate on a vulnerable VM.
