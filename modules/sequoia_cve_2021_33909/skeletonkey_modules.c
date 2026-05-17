/* sequoia_cve_2021_33909 — STUB pending agent implementation. */
#include "skeletonkey_modules.h"
#include "../../core/registry.h"

static skeletonkey_result_t sequoia_detect(const struct skeletonkey_ctx *ctx)
{ (void)ctx; return SKELETONKEY_PRECOND_FAIL; }

const struct skeletonkey_module sequoia_module = {
    .name = "sequoia",
    .cve = "CVE-2021-33909",
    .summary = "seq_file size_t overflow → kernel stack write (Qualys Sequoia) — stub pending implementation",
    .family = "filesystem",
    .kernel_range = "K < 5.13.4 / 5.10.52 / 5.4.134",
    .detect = sequoia_detect,
    .exploit = NULL, .mitigate = NULL, .cleanup = NULL,
    .detect_auditd = NULL, .detect_sigma = NULL,
    .detect_yara = NULL,   .detect_falco = NULL,
};

void skeletonkey_register_sequoia(void) { skeletonkey_register(&sequoia_module); }
