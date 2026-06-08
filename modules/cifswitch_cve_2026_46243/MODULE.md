# cifswitch — CVE-2026-46243 ("CIFSwitch")

The kernel's `cifs.spnego` request-key type trusts userspace-forged
authority fields, letting the root `cifs.upcall` helper be coerced into
loading an attacker NSS module as root.

## The bug

`fs/smb/client/cifs_spnego.c` registers the `cifs.spnego` key type so the
kernel CIFS client can ask the root-privileged `cifs.upcall` helper to
perform a SPNEGO/Kerberos exchange. The key *description* carries
authority-bearing fields — `pid`, `uid`, `creduid`, `upcall_target` —
that `cifs.upcall` reads as trusted, kernel-originating inputs.

The flaw: the kernel never verified the request actually came from the
in-kernel CIFS client. Userspace can create keys of this type directly
through `add_key(2)` / `request_key(2)`, supplying all those fields. By
forging a description and manipulating user + mount namespaces, an
unprivileged user makes `cifs.upcall` trust attacker-controlled state and
load a malicious NSS shared library as root → root code execution.

## Affected range

| | |
|---|---|
| Flaw age | ~19 years (predates key-type origin checks) |
| Fixed upstream | commit `3da1fdf4efbc`, merged 7.1-rc5 |
| Debian backports | 5.10.257 · 6.1.174 · 6.12.90 · 7.0.10 |
| NVD class | CWE-20 (Improper Input Validation) |
| CISA KEV | no (as of disclosure) |

Branches Debian does not ship (5.15 / 6.6 / 6.8 / 6.11 …) are reported on
the version-only verdict; confirm empirically.

## Trigger / detection

`detect()` returns `OK` for patched kernels, `PRECOND_FAIL` for a
vulnerable kernel where `cifs.upcall` / the `cifs.spnego` request-key rule
isn't installed (cifs-utils absent → unreachable), and `VULNERABLE` when
both the version and the userspace path line up. The precondition probe
can be overridden with `SKELETONKEY_CIFS_ASSUME_PRESENT=1` (force present)
or `0` (force absent).

`exploit()` fires the non-destructive primitive: `add_key(2)` of a
forged-but-benign `cifs.spnego` key (no upcall, loads nothing), revoked
immediately. A clean accept is the witness that userspace can forge the
authority-bearing key type. The full root-pop (namespace switch +
malicious NSS load) is **not** bundled until VM-verified — honest
`EXPLOIT_FAIL` without a euid-0 witness.

## Fix / mitigation

Upgrade the kernel. As a runtime stopgap, blocklist the `cifs` module —
`--mitigate` writes `/etc/modprobe.d/skeletonkey-disable-cifs.conf`
(needs root) and `--cleanup` removes it. Already-loaded `cifs` persists
until unmount + `rmmod cifs` or reboot.

## Credit

Asim Manizada (2026-05-28). See `NOTICE.md`.
