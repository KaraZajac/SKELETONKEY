/*
 * SKELETONKEY — per-module verification records
 *
 * "Verified-on" entries — concrete (distro, kernel, date) tuples where
 * tools/verify-vm/verify.sh has empirically confirmed a module's
 * detect() verdict against a known-vulnerable target. Each entry is one
 * row from docs/VERIFICATIONS.jsonl, auto-generated into the C table
 * by tools/refresh-verifications.py.
 *
 * Modules with >=1 record carry an empirical-trust badge ("✓ verified
 * on Ubuntu 20.04.6 / 5.4.0") in --list / --module-info / --explain
 * output. Modules with zero records are still tested at the unit level
 * (synthetic fingerprints), but have not yet been confirmed on a real
 * vulnerable kernel.
 *
 * Append-only by intent: each verify.sh run appends a fresh JSONL line
 * (timestamped); the refresh script dedupes to (module, vm_box,
 * kernel, expect_detect) when generating the C table so re-runs of the
 * same scenario update rather than accumulate.
 */

#ifndef SKELETONKEY_VERIFICATIONS_H
#define SKELETONKEY_VERIFICATIONS_H

#include <stdbool.h>
#include <stddef.h>

struct verification_record {
    const char *module;          /* module name (matches struct skeletonkey_module.name) */
    const char *verified_at;     /* "YYYY-MM-DD" (date-only; full timestamp truncated) */
    const char *host_kernel;     /* uname -r value, e.g. "5.4.0-169-generic" */
    const char *host_distro;     /* /etc/os-release PRETTY_NAME, e.g. "Ubuntu 20.04.6 LTS" */
    const char *vm_box;          /* vagrant box name, e.g. "generic/ubuntu2004" */
    const char *expect_detect;   /* "VULNERABLE" / "OK" / "PRECOND_FAIL" — what targets.yaml said */
    const char *actual_detect;   /* what skeletonkey --explain returned */
    const char *status;          /* "match" iff actual == expected; otherwise "MISMATCH" */
};

extern const struct verification_record verifications[];
extern const size_t                      verifications_count;

/* Returns the first record (count via *count_out) for the named module,
 * or NULL if the module has no recorded verifications. The records are
 * stored contiguously in the table, so once you have the pointer you
 * can iterate count_out entries forward. */
const struct verification_record *
verifications_for_module(const char *module, size_t *count_out);

/* True iff the module has at least one "match" record. */
bool verifications_module_has_match(const char *module);

#endif /* SKELETONKEY_VERIFICATIONS_H */
