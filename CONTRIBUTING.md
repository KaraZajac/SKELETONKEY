# Contributing to SKELETONKEY

SKELETONKEY is a curated corpus. PRs welcome for the things below.
For everything else, open an issue first to discuss scope.

## What we accept

### 1. Kernel offsets for the `--full-chain` table

The 11 🟡 PRIMITIVE modules use the shared finisher in
`core/finisher.c` to convert their primitive into a root pop via
`modprobe_path` overwrite. That needs `&modprobe_path` (and friends)
at runtime — resolved via env vars / `/proc/kallsyms` /
`/boot/System.map` / the embedded `kernel_table[]` in
`core/offsets.c`.

The embedded table is **empty by default** to honor the
no-fabricated-offsets rule. Every entry must come from a real kernel
you have root on.

**Workflow:**

```bash
sudo skeletonkey --dump-offsets   # on the target kernel build
# Paste the printed C struct entry into core/offsets.c kernel_table[]
# Open a PR titled "offsets: <distro> <kernel_release>"
```

Include in the PR body:
- Distro + kernel version (`uname -a`, `cat /etc/os-release`)
- How you verified the offsets (kallsyms / System.map / debuginfo)
- Whether `--full-chain` succeeds end-to-end against any 🟡 module
  on that kernel (if you can test on a vulnerable build)

### 2. New modules

A new CVE module is welcome if:

- The bug is **patched in upstream mainline** (no 0days here)
- It has a public CVE assignment or clear advisory
- The kernel range it affects has realistic deployment footprint
- You can include a working detect() with branch-backport ranges
- You ship matching detection rules (auditd at minimum)

Use any existing module as a template. Lightest-weight reference:
`modules/ptrace_traceme_cve_2019_13272/skeletonkey_modules.c`.

Mandatory:
- Detect short-circuits cleanly on patched kernels (we test this)
- `--i-know` gate on exploit
- Honest scope: `IAMROOT_EXPLOIT_OK` only after empirical root,
  otherwise `EXPLOIT_FAIL` with diagnostic
- `NOTICE.md` crediting the original CVE reporter + PoC author

After the module file exists, wire it into:
- `core/registry.h` (extern declaration)
- `skeletonkey.c` main() (register call)
- `Makefile` (new objects + ALL_OBJS)
- `CVES.md` (inventory entry)

### 3. Detection rules

If you're adding only detection coverage (no exploit) for an
existing or new CVE, that's fine. Drop a sigma rule into the module
or a new auditd rule file.

### 4. Bug reports + CVE-status corrections

Distro backports that patched a CVE without bumping the upstream
version → file an issue. Same for kernels we mis-classify as
vulnerable.

## What we don't accept

- Untested code paths claiming `IAMROOT_EXPLOIT_OK`
- Per-kernel offsets fabricated without verification
- Modules without detection rules
- 0day disclosures (responsible disclosure first; bundle here
  after upstream patch ships)
- Container escapes that don't chain to host root

## Code style

C99. Match the surrounding file. Run `make` and the existing
CI build (`.github/workflows/build.yml`) before opening the PR.

## License

By contributing you agree your work is MIT-licensed.
