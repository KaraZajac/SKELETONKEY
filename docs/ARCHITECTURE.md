# Architecture

## Module model

Each CVE (or tightly-related family of CVEs sharing a primitive) is
a **module** under `modules/`. A module is a self-contained
exploit + detection + metadata bundle that exports a standard
interface to the top-level dispatcher.

### Module layout

```
modules/<module_name>/
├── MODULE.md                  # Human-readable writeup of the bug
├── NOTICE.md                  # Credits to original researcher
├── kernel-range.json          # Machine-readable affected kernels
├── module.c                   # Implements skeletonkey_module interface
├── module.h
├── detect/
│   ├── auditd.rules           # blue team detection
│   ├── sigma.yml
│   └── yara.yara
├── src/                       # exploit internals
└── tests/                     # per-module tests (run in CI matrix)
```

### `skeletonkey_module` interface (planned, Phase 1)

```c
struct skeletonkey_module {
    const char *name;           /* "copy_fail" */
    const char *cve;            /* "CVE-2026-31431" */
    const char *summary;        /* one-line description */

    /* Return 1 if host appears vulnerable, 0 if patched/immune,
     * -1 if probe couldn't run. May call entrybleed_leak_kbase()
     * etc. from core/ if a leak primitive is needed. */
    int (*detect)(struct skeletonkey_host *host);

    /* Run the exploit. Caller has already passed the
     * authorization gate. Returns 0 on root acquired,
     * nonzero on failure. */
    int (*exploit)(struct skeletonkey_host *host, struct skeletonkey_opts *opts);

    /* Apply a runtime mitigation for this CVE (sysctl, module
     * blacklist, etc.). Returns 0 on success. NULL if no
     * mitigation is offered. */
    int (*mitigate)(struct skeletonkey_host *host);

    /* Undo --exploit-backdoor or --mitigate side effects. */
    int (*cleanup)(struct skeletonkey_host *host);

    /* Affected kernel version range, distros covered, etc. */
    const struct skeletonkey_kernel_range *ranges;
    size_t n_ranges;
};
```

Modules register themselves at link time via a constructor-attribute
table. The top-level `skeletonkey` binary iterates the registry on each
invocation.

## Shared `core/`

Code that more than one module needs lives in `core/`:

- `core/common.c` — fingerprinting (kernel version, distro, LSM,
  hardening flags), logging, error handling
- `core/apparmor_bypass.c` — Ubuntu's
  `apparmor_restrict_unprivileged_userns=1` defeat via
  `change_onexec("crun")` re-exec
- `core/exploit_su.c` — once we have page-cache-write or
  /etc/passwd-overwrite, this is the shared "drop to root shell"
  helper
- `core/fcrypt.c` — file-encryption helpers used by multiple modules
- `core/entrybleed.c` (planned, Phase 3) — kbase leak primitive that
  any module needing KASLR-defeat can call

## Top-level dispatcher

`skeletonkey.c` (planned, Phase 1) is the CLI entry point. Responsibilities:

1. Parse args (`--scan`, `--exploit <name>`, `--mitigate`,
   `--detect-rules`, `--cleanup`, etc.)
2. Fingerprint the host
3. For `--scan`: iterate module registry, call each module's
   `detect()`, emit table of results
4. For `--exploit <name>`: locate module, gate behind `--i-know`,
   call its `exploit()`
5. For `--detect-rules`: walk module registry, concatenate detection
   files in the requested format

## CI matrix

`.github/workflows/ci.yml` (planned, Phase 4) runs each module's
test against a matrix of distro × kernel VMs. Each test asserts:

- on a vulnerable VM: `detect()` returns 1, `exploit()` returns 0
  and produces uid=0
- on a patched VM: `detect()` returns 0, `exploit()` either refuses
  or fails gracefully

Failures on a previously-working matrix entry open an issue
automatically (likely cause: distro shipped a backport that broke
the module).

## Adding a new CVE

1. `git checkout -b add-cve-XXXX-NNNN`
2. `cp -r modules/_stubs/_template modules/<module_name>`
3. Fill in `MODULE.md`, `NOTICE.md`, `kernel-range.json`
4. Implement `module.c` exposing the `skeletonkey_module` interface
5. Ship at least one detection rule under `detect/`
6. Add tests under `tests/`
7. PR. CI runs the matrix. If it lands root on at least one
   vulnerable matched VM AND fails cleanly on a patched VM, it
   merges.

See `docs/module-template.md` (planned) for the per-module checklist.
