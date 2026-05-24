/*
 * SKELETONKEY — core module interface
 *
 * Every CVE module exports one or more `struct skeletonkey_module` entries
 * via a registry function. The top-level dispatcher (skeletonkey.c) walks
 * the global registry to implement --scan, --exploit, --mitigate, etc.
 *
 * This is intentionally a small interface. Modules carry the
 * complexity; the dispatcher just routes.
 */

#ifndef SKELETONKEY_MODULE_H
#define SKELETONKEY_MODULE_H

#include <stddef.h>
#include <stdbool.h>

/* Standard result codes returned by detect()/exploit()/mitigate().
 *
 * These map to top-level exit codes when skeletonkey is invoked with a
 * single-module operation:
 *
 *   SKELETONKEY_OK            exit 0   detect: not vulnerable / clean
 *   SKELETONKEY_VULNERABLE    exit 2   detect: confirmed vulnerable
 *   SKELETONKEY_PRECOND_FAIL  exit 4   detect: preconditions missing
 *   SKELETONKEY_TEST_ERROR    exit 1   detect/exploit: error
 *   SKELETONKEY_EXPLOIT_OK    exit 5   exploit: succeeded (root achieved)
 *   SKELETONKEY_EXPLOIT_FAIL  exit 3   exploit: attempted but did not land
 *
 * Implementation note: copy_fail_family's df_result_t shares these
 * numeric values intentionally so the family code can return its
 * existing constants without translation.
 */
typedef enum {
    SKELETONKEY_OK              = 0,
    SKELETONKEY_TEST_ERROR      = 1,
    SKELETONKEY_VULNERABLE      = 2,
    SKELETONKEY_EXPLOIT_FAIL    = 3,
    SKELETONKEY_PRECOND_FAIL    = 4,
    SKELETONKEY_EXPLOIT_OK      = 5,
} skeletonkey_result_t;

/* Per-invocation context passed to module callbacks. The host
 * fingerprint (kernel / distro / capability gates / service presence)
 * is populated once at startup by core/host.c and handed to every
 * module callback here — see core/host.h. */
struct skeletonkey_host;   /* forward decl; full def in core/host.h */

struct skeletonkey_ctx {
    bool          no_color;     /* --no-color */
    bool          json;         /* --json (machine-readable output) */
    bool          active_probe; /* --active (do invasive probes in detect) */
    bool          no_shell;     /* --no-shell (exploit prep but don't pop) */
    bool          authorized;   /* user typed --i-know on exploit */
    bool          full_chain;   /* --full-chain (attempt root-pop after primitive) */
    bool          dry_run;      /* --dry-run (preview only; never call exploit/mitigate/cleanup) */

    /* Host fingerprint — see core/host.h. Stable pointer, populated
     * once by main() before any module callback runs. Modules that
     * want to consult it #include "../../core/host.h". May be NULL
     * only in degenerate test contexts; main() always sets it. */
    const struct skeletonkey_host *host;
};

struct skeletonkey_module {
    /* Short id used on the command line: `skeletonkey --exploit copy_fail`. */
    const char *name;

    /* CVE identifier (or "VARIANT" if no CVE assigned). */
    const char *cve;

    /* One-line human description. */
    const char *summary;

    /* Family this module belongs to (e.g. "copy_fail_family"). Modules
     * with shared infrastructure live in the same family. */
    const char *family;

    /* Affected kernel range, prose. Machine-readable range goes in
     * the module's kernel-range.json (consumed by CI). */
    const char *kernel_range;

    /* Probe the host. Should be side-effect-free unless ctx->active_probe
     * is true. Return SKELETONKEY_VULNERABLE if confirmed,
     * SKELETONKEY_PRECOND_FAIL if not applicable here, SKELETONKEY_OK if patched
     * or otherwise immune, SKELETONKEY_TEST_ERROR on probe error. */
    skeletonkey_result_t (*detect)(const struct skeletonkey_ctx *ctx);

    /* Run the exploit. Caller has already passed the --i-know gate. */
    skeletonkey_result_t (*exploit)(const struct skeletonkey_ctx *ctx);

    /* Apply a temporary mitigation. NULL if none offered. */
    skeletonkey_result_t (*mitigate)(const struct skeletonkey_ctx *ctx);

    /* Undo --exploit (e.g. evict from page cache) or --mitigate side
     * effects. NULL if no cleanup applies. */
    skeletonkey_result_t (*cleanup)(const struct skeletonkey_ctx *ctx);

    /* Detection rule corpus — embedded so the binary is self-
     * contained. Each may be NULL if this module ships no rules for
     * that format. Strings are NUL-terminated; concatenated in the
     * order modules register. */
    const char *detect_auditd;   /* auditd .rules content */
    const char *detect_sigma;    /* sigma YAML content */
    const char *detect_yara;     /* yara rules content */
    const char *detect_falco;    /* falco rules content */

    /* Operational-security notes — telemetry footprint THIS specific
     * exploit leaves behind. The inverse of detect_auditd/yara/falco
     * above (the rules catch what these notes describe). Free-form
     * prose, conventionally listing: dmesg lines triggered, auditd
     * events, file artifacts created/modified, persistence side-
     * effects, recommended cleanup. Per-module (not per-CVE) because
     * different exploits for the same bug can leave different
     * footprints. NULL if no analysis written yet.
     *
     * NB: ATT&CK / CWE / KEV metadata is properties of the CVE itself
     * (independent of exploit technique) and lives in
     * core/cve_metadata.{h,c} — looked up by CVE id, refreshed via
     * tools/refresh-cve-metadata.py. */
    const char *opsec_notes;

    /* Architecture support for the exploit() body. detect() works on
     * any Linux arch (it just consults ctx->host); the question this
     * field answers is: if this module says VULNERABLE, will the
     * --exploit path actually fire on aarch64 / arm64? Values:
     *
     *   "any"            — userspace bug or arch-agnostic kernel
     *                      primitive (pwnkit, sudo*, pack2theroot,
     *                      dirty_pipe, dirty_cow, most netfilter/fs
     *                      bugs that use msg_msg sprays + structural
     *                      escapes).
     *   "x86_64"         — strictly x86-only (entrybleed needs
     *                      prefetchnta + KPTI, which doesn't apply
     *                      to ARM's TTBR_EL0/EL1 model).
     *   "x86_64+unverified-arm64" — exploit body likely works on
     *                      arm64 but hasn't been verified on a real
     *                      arm64 host yet (e.g. copy_fail_family
     *                      assumes some x86_64 struct offsets;
     *                      --full-chain finisher uses x86_64-style
     *                      kernel ROP gadgets).
     *
     * NULL = unmapped (treat as "x86_64+unverified-arm64" by default;
     * a future arm64-on-Vagrant sweep will fill these in). Surfaced
     * in --list (ARCH column) and --module-info. */
    const char *arch_support;
};

#endif /* SKELETONKEY_MODULE_H */
