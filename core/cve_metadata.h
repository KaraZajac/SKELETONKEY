/*
 * SKELETONKEY — CVE metadata lookup
 *
 * Per-CVE annotations sourced from authoritative federal databases:
 *   - CISA Known Exploited Vulnerabilities catalog (in_kev, date_added)
 *   - NVD CVE API (cwe)
 *   - Hand-curated MITRE ATT&CK technique mapping
 *
 * Kept separate from struct skeletonkey_module because these are
 * properties of the CVE (one CVE -> one set of values), not the
 * exploit module. Two modules covering the same CVE see the same
 * metadata. The OPSEC notes — which vary by exploit technique —
 * stay on the module struct.
 *
 * The table is auto-generated from docs/CVE_METADATA.json by
 * tools/refresh-cve-metadata.py. Do not hand-edit cve_metadata.c —
 * re-run the refresh tool.
 */

#ifndef SKELETONKEY_CVE_METADATA_H
#define SKELETONKEY_CVE_METADATA_H

#include <stdbool.h>
#include <stddef.h>

struct cve_metadata {
    const char *cve;                  /* "CVE-YYYY-NNNNN" */
    const char *cwe;                  /* "CWE-NNN" or NULL if NVD has no mapping */
    const char *attack_technique;     /* "T1068" etc. */
    const char *attack_subtechnique;  /* "T1068.001" or NULL */
    bool        in_kev;               /* true iff in CISA's KEV catalog */
    const char *kev_date_added;       /* "YYYY-MM-DD" or "" */
};

/* The full table. Length is `cve_metadata_table_len`. */
extern const struct cve_metadata cve_metadata_table[];
extern const size_t              cve_metadata_table_len;

/* Lookup by CVE id (e.g. "CVE-2024-1086"). Returns NULL if the CVE
 * isn't in the table. Cheap linear scan; we have <100 entries. */
const struct cve_metadata *cve_metadata_lookup(const char *cve);

#endif /* SKELETONKEY_CVE_METADATA_H */
