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
2. **Fingerprint the host** — `core/host.c` is called once at startup
   to populate `struct skeletonkey_host` (kernel version + arch +
   distro + capability gates + service presence). The result is
   handed to every module via `ctx->host`. See "Host fingerprint"
   below.
3. For `--scan`: iterate module registry, call each module's
   `detect()`, emit table of results
4. For `--exploit <name>`: locate module, gate behind `--i-know`,
   call its `exploit()`
5. For `--detect-rules`: walk module registry, concatenate detection
   files in the requested format

## Host fingerprint (`core/host.{h,c}`)

A single `struct skeletonkey_host` is populated once at startup and
exposed to every module via `ctx->host` (a stable pointer for the
process lifetime). It carries:

- **Identity:** `struct kernel_version kernel` + arch + nodename +
  distro id/version/pretty (parsed from `/etc/os-release`).
- **Process state:** euid, real_uid (defeats the userns illusion by
  reading `/proc/self/uid_map`), egid, username, is_root,
  is_ssh_session.
- **Platform family:** is_linux, is_debian_family, is_rpm_family,
  is_arch_family, is_suse_family.
- **Capability gates (Linux):** unprivileged_userns_allowed (live
  fork-probe), apparmor_restrict_userns, unprivileged_bpf_disabled,
  kpti_enabled, kernel_lockdown_active, selinux_enforcing,
  yama_ptrace_restricted.
- **System services:** has_systemd, has_dbus_system.

Modules that want to consult the fingerprint do:

```c
#include "../../core/host.h"
/* ... */
if (ctx->host && !ctx->host->unprivileged_userns_allowed)
    return SKELETONKEY_PRECOND_FAIL;
if (ctx->host->kernel.major < 7)
    return SKELETONKEY_OK;   /* predates the bug */
```

The migration is opt-in per module — modules that don't `#include`
host.h continue to do their own probes; modules that do save the
duplicate work and get a consistent view across the whole scan.

`--auto` and `--scan` (in verbose mode) print a two-line banner of
the fingerprint via `skeletonkey_host_print_banner()` so operators
can see at a glance which gates are open.

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
