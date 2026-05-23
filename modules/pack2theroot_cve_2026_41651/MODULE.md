# pack2theroot — CVE-2026-41651

> 🟡 **PRIMITIVE / ported.** Faithful port of the public Vozec PoC.
> **Not yet validated end-to-end on a vulnerable host** — see
> _Verification status_.

## Summary

Pack2TheRoot is a userspace LPE in the **PackageKit** daemon
(`packagekitd`), the cross-distro package-management D-Bus abstraction
layer shipped on virtually every desktop and most modern server Linux
distros (Ubuntu, Debian, Fedora, Rocky/RHEL via Cockpit, openSUSE…).

Three cooperating bugs in `src/pk-transaction.c` chain into a TOCTOU
window between polkit authorisation and dispatch. **The exploit needs
no GUI session, no special permissions, and no polkit prompt** —
GLib's D-Bus-vs-idle priority ordering makes it deterministic, not a
timing race.

```
1. InstallFiles(SIMULATE, dummy.deb)        ← polkit bypassed; idle queued
2. InstallFiles(NONE,    payload.deb)        ← cached_flags overwritten
3. GLib idle fires → pk_transaction_run()    ← reads payload.deb + NONE
   → dpkg runs postinst as root → SUID bash → root shell
```

The payload `.deb` is built entirely in C inside the module
(ar / ustar / gzip-stored, no external `dpkg-deb` dependency).

## Operations

| Op | Behaviour |
|---|---|
| `--scan` | Checks Debian/Ubuntu host, system D-Bus accessible, `org.freedesktop.PackageKit` registered, and reads `VersionMajor/Minor/Micro` from the daemon. Returns VULNERABLE only when the version falls in `1.0.2 ≤ V ≤ 1.3.4`. The fix release (1.3.5, commit `76cfb675`, 2026-04-22) is pinned. |
| `--exploit … --i-know` | Builds the two `.deb`s in `/tmp`, fires the two `InstallFiles` D-Bus calls back-to-back, polls up to 120s for `/tmp/.suid_bash` to appear, then `execv`s it for an interactive root shell. `--no-shell` stops after the SUID bash lands. |
| `--cleanup` | Removes the staged `.deb` files; best-effort `unlink(/tmp/.suid_bash)` (the file is root-owned — needs root to remove); best-effort `sudo -n dpkg -r` the installed staging packages. |
| `--detect-rules` | Emits embedded auditd + sigma rules covering the file-side footprint (the D-Bus call itself isn't auditable without bus monitoring). |

## Preconditions

- Linux + Debian/Ubuntu (the PoC's built-in `.deb` builder is
  Debian-family only; RHEL/Fedora ports would need an `.rpm` builder).
- PackageKit daemon registered on the system bus.
- PackageKit version in `[1.0.2, 1.3.4]`.
- Module built with `libglib2.0-dev` available (the top-level Makefile
  autodetects `gio-2.0` via `pkg-config`; the module compiles as a
  stub returning `PRECOND_FAIL` when GLib is absent).

## Side-effect notes

The exploit installs a malicious `.deb` (registered in dpkg's database
as `skeletonkey-p2tr-payload`) and drops `/tmp/.suid_bash`. Both are
intentionally visible — this is an authorised-testing tool, not a
covert toolkit. Run `--cleanup` (preferably as root) before leaving
the host.

## Verification status

This module is a **faithful port** of
<https://github.com/Vozec/CVE-2026-41651> into the SKELETONKEY module
interface. It has **not** been validated end-to-end against a known-
vulnerable PackageKit host inside the SKELETONKEY CI matrix.

Unlike the page-cache modules, `detect()` here is high-confidence:
the fix release is officially pinned and the version is read directly
from the daemon over D-Bus, so a `VULNERABLE` verdict is grounded in
upstream's own version metadata rather than a heuristic.

**Before promoting to 🟢:** validate the trigger end-to-end on a
Debian/Ubuntu host with PackageKit ≤ 1.3.4 (the Vozec repo ships a
Dockerfile that builds PackageKit 1.3.4 from source — that is the
recommended bench).
