/*
 * IAMROOT — core module interface
 *
 * Every CVE module exports one or more `struct iamroot_module` entries
 * via a registry function. The top-level dispatcher (iamroot.c) walks
 * the global registry to implement --scan, --exploit, --mitigate, etc.
 *
 * This is intentionally a small interface. Modules carry the
 * complexity; the dispatcher just routes.
 */

#ifndef IAMROOT_MODULE_H
#define IAMROOT_MODULE_H

#include <stddef.h>
#include <stdbool.h>

/* Standard result codes returned by detect()/exploit()/mitigate().
 *
 * These map to top-level exit codes when iamroot is invoked with a
 * single-module operation:
 *
 *   IAMROOT_OK            exit 0   detect: not vulnerable / clean
 *   IAMROOT_VULNERABLE    exit 2   detect: confirmed vulnerable
 *   IAMROOT_PRECOND_FAIL  exit 4   detect: preconditions missing
 *   IAMROOT_TEST_ERROR    exit 1   detect/exploit: error
 *   IAMROOT_EXPLOIT_OK    exit 5   exploit: succeeded (root achieved)
 *   IAMROOT_EXPLOIT_FAIL  exit 3   exploit: attempted but did not land
 *
 * Implementation note: copy_fail_family's df_result_t shares these
 * numeric values intentionally so the family code can return its
 * existing constants without translation.
 */
typedef enum {
    IAMROOT_OK              = 0,
    IAMROOT_TEST_ERROR      = 1,
    IAMROOT_VULNERABLE      = 2,
    IAMROOT_EXPLOIT_FAIL    = 3,
    IAMROOT_PRECOND_FAIL    = 4,
    IAMROOT_EXPLOIT_OK      = 5,
} iamroot_result_t;

/* Per-invocation context passed to module callbacks. Lightweight for
 * now; will grow as modules need shared state (host fingerprint,
 * leaked kbase, etc.). */
struct iamroot_ctx {
    bool          no_color;     /* --no-color */
    bool          json;         /* --json (machine-readable output) */
    bool          active_probe; /* --active (do invasive probes in detect) */
    bool          no_shell;     /* --no-shell (exploit prep but don't pop) */
    bool          authorized;   /* user typed --i-know on exploit */
};

struct iamroot_module {
    /* Short id used on the command line: `iamroot --exploit copy_fail`. */
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
     * is true. Return IAMROOT_VULNERABLE if confirmed,
     * IAMROOT_PRECOND_FAIL if not applicable here, IAMROOT_OK if patched
     * or otherwise immune, IAMROOT_TEST_ERROR on probe error. */
    iamroot_result_t (*detect)(const struct iamroot_ctx *ctx);

    /* Run the exploit. Caller has already passed the --i-know gate. */
    iamroot_result_t (*exploit)(const struct iamroot_ctx *ctx);

    /* Apply a temporary mitigation. NULL if none offered. */
    iamroot_result_t (*mitigate)(const struct iamroot_ctx *ctx);

    /* Undo --exploit (e.g. evict from page cache) or --mitigate side
     * effects. NULL if no cleanup applies. */
    iamroot_result_t (*cleanup)(const struct iamroot_ctx *ctx);

    /* Detection rule corpus — embedded so the binary is self-
     * contained. Each may be NULL if this module ships no rules for
     * that format. Strings are NUL-terminated; concatenated in the
     * order modules register. */
    const char *detect_auditd;   /* auditd .rules content */
    const char *detect_sigma;    /* sigma YAML content */
    const char *detect_yara;     /* yara rules content */
    const char *detect_falco;    /* falco rules content */
};

#endif /* IAMROOT_MODULE_H */
