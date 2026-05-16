/*
 * copy_fail_family — IAMROOT module bridge layer
 *
 * Wraps the existing per-CVE detect/exploit functions (from the
 * absorbed DIRTYFAIL codebase) as standard iamroot_module entries.
 *
 * The bridge functions translate between the family's df_result_t
 * (defined in src/common.h) and iamroot_result_t (defined in
 * core/module.h). Numeric values are identical by design so the
 * translation is a direct cast.
 *
 * iamroot_ctx fields (no_color, json, active_probe, no_shell) are
 * forwarded to the family's existing global flags before each
 * callback. This preserves DIRTYFAIL's existing CLI semantics
 * unchanged.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"

#include "src/common.h"
#include "src/copyfail.h"
#include "src/copyfail_gcm.h"
#include "src/dirtyfrag_esp.h"
#include "src/dirtyfrag_esp6.h"
#include "src/dirtyfrag_rxrpc.h"

static void apply_ctx(const struct iamroot_ctx *ctx)
{
    dirtyfail_use_color     = !ctx->no_color;
    dirtyfail_active_probes = ctx->active_probe;
    dirtyfail_json          = ctx->json;
    /* dirtyfail_no_revert is intentionally not driven from ctx —
     * it's a debug knob; default stays off. */
}

/* ----- copy_fail (CVE-2026-31431) ----- */

static iamroot_result_t copy_fail_detect_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)copyfail_detect();
}

static iamroot_result_t copy_fail_exploit_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)copyfail_exploit(!ctx->no_shell);
}

/* Shared detection rules for the copy_fail family — every member of
 * this family exploits the same page-cache-write primitive and lands
 * in the same files (/etc/passwd or /usr/bin/su). One rule set covers
 * all five module entries. Per-module structs alias the same strings. */
static const char copy_fail_family_auditd[] =
    "# Copy Fail family (CVE-2026-31431 + Dirty Frag CVE-2026-43284 + RxRPC CVE-2026-43500)\n"
    "# Page-cache writes to passwd/shadow/su/sudoers from non-root.\n"
    "-w /etc/passwd     -p wa -k iamroot-copy-fail\n"
    "-w /etc/shadow     -p wa -k iamroot-copy-fail\n"
    "-w /etc/sudoers    -p wa -k iamroot-copy-fail\n"
    "-w /etc/sudoers.d  -p wa -k iamroot-copy-fail\n"
    "-w /usr/bin/su     -p wa -k iamroot-copy-fail\n"
    "# AF_ALG socket creation by non-root — heavily used by exploit\n"
    "-a always,exit -F arch=b64 -S socket -F a0=38 -k iamroot-copy-fail-afalg\n"
    "# xfrm SA setup (Dirty Frag ESP variants)\n"
    "-a always,exit -F arch=b64 -S setsockopt -k iamroot-copy-fail-xfrm\n";

static const char copy_fail_family_sigma[] =
    "title: Copy Fail / Dirty Frag family exploitation\n"
    "id: 4d8e6c2a-iamroot-copy-fail-family\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the file-modification footprint of Copy Fail (CVE-2026-31431) and\n"
    "  Dirty Frag siblings (CVE-2026-43284 v4/v6, CVE-2026-43500). Catches the\n"
    "  /etc/passwd UID-flip backdoor + the persistent backdoor account install.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  modification:\n"
    "    type: 'PATH'\n"
    "    name|startswith: ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/usr/bin/su']\n"
    "  not_root: {auid|expression: '!= 0'}\n"
    "  condition: modification and not_root\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.31431, cve.2026.43284, cve.2026.43500]\n";

const struct iamroot_module copy_fail_module = {
    .name           = "copy_fail",
    .cve            = "CVE-2026-31431",
    .summary        = "algif_aead authencesn page-cache write → /etc/passwd UID flip",
    .family         = "copy_fail_family",
    .kernel_range   = "≤ 6.12.84, fixed mainline 2026-04-22",
    .detect         = copy_fail_detect_wrap,
    .exploit        = copy_fail_exploit_wrap,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

/* ----- copy_fail_gcm (variant, no CVE) ----- */

static iamroot_result_t copy_fail_gcm_detect_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)copyfail_gcm_detect();
}

static iamroot_result_t copy_fail_gcm_exploit_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)copyfail_gcm_exploit(!ctx->no_shell);
}

const struct iamroot_module copy_fail_gcm_module = {
    .name         = "copy_fail_gcm",
    .cve          = "VARIANT",
    .summary      = "rfc4106(gcm(aes)) single-byte page-cache write (Copy Fail sibling)",
    .family       = "copy_fail_family",
    .kernel_range = "same as copy_fail; rfc4106(gcm(aes)) not in modprobe blacklist",
    .detect       = copy_fail_gcm_detect_wrap,
    .exploit      = copy_fail_gcm_exploit_wrap,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

/* ----- dirty_frag_esp (CVE-2026-43284 v4) ----- */

static iamroot_result_t dirty_frag_esp_detect_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)dirtyfrag_esp_detect();
}

static iamroot_result_t dirty_frag_esp_exploit_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)dirtyfrag_esp_exploit(!ctx->no_shell);
}

const struct iamroot_module dirty_frag_esp_module = {
    .name         = "dirty_frag_esp",
    .cve          = "CVE-2026-43284",
    .summary      = "IPv4 xfrm-ESP page-cache write (Dirty Frag v4)",
    .family       = "copy_fail_family",
    .kernel_range = "same family as copy_fail; xfrm-ESP path",
    .detect       = dirty_frag_esp_detect_wrap,
    .exploit      = dirty_frag_esp_exploit_wrap,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

/* ----- dirty_frag_esp6 (CVE-2026-43284 v6) ----- */

static iamroot_result_t dirty_frag_esp6_detect_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)dirtyfrag_esp6_detect();
}

static iamroot_result_t dirty_frag_esp6_exploit_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)dirtyfrag_esp6_exploit(!ctx->no_shell);
}

const struct iamroot_module dirty_frag_esp6_module = {
    .name         = "dirty_frag_esp6",
    .cve          = "CVE-2026-43284",
    .summary      = "IPv6 xfrm-ESP page-cache write (Dirty Frag v6)",
    .family       = "copy_fail_family",
    .kernel_range = "same family as copy_fail; xfrm-ESP6 path; V6 STORE shift auto-calibrated",
    .detect       = dirty_frag_esp6_detect_wrap,
    .exploit      = dirty_frag_esp6_exploit_wrap,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

/* ----- dirty_frag_rxrpc (CVE-2026-43500) ----- */

static iamroot_result_t dirty_frag_rxrpc_detect_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)dirtyfrag_rxrpc_detect();
}

static iamroot_result_t dirty_frag_rxrpc_exploit_wrap(const struct iamroot_ctx *ctx)
{
    apply_ctx(ctx);
    return (iamroot_result_t)dirtyfrag_rxrpc_exploit(!ctx->no_shell);
}

const struct iamroot_module dirty_frag_rxrpc_module = {
    .name         = "dirty_frag_rxrpc",
    .cve          = "CVE-2026-43500",
    .summary      = "AF_RXRPC handshake forgery + page-cache write (Dirty Frag RxRPC)",
    .family       = "copy_fail_family",
    .kernel_range = "kernels exposing AF_RXRPC + rxkad with fcrypt fallback",
    .detect       = dirty_frag_rxrpc_detect_wrap,
    .exploit      = dirty_frag_rxrpc_exploit_wrap,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

/* ----- Family registration ----- */

void iamroot_register_copy_fail_family(void)
{
    iamroot_register(&copy_fail_module);
    iamroot_register(&copy_fail_gcm_module);
    iamroot_register(&dirty_frag_esp_module);
    iamroot_register(&dirty_frag_esp6_module);
    iamroot_register(&dirty_frag_rxrpc_module);
}
