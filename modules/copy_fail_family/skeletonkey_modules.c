/*
 * copy_fail_family — SKELETONKEY module bridge layer
 *
 * Wraps the existing per-CVE detect/exploit functions (from the
 * absorbed DIRTYFAIL codebase) as standard skeletonkey_module entries.
 *
 * The bridge functions translate between the family's df_result_t
 * (defined in src/common.h) and skeletonkey_result_t (defined in
 * core/module.h). Numeric values are identical by design so the
 * translation is a direct cast.
 *
 * skeletonkey_ctx fields (no_color, json, active_probe, no_shell) are
 * forwarded to the family's existing global flags before each
 * callback. This preserves DIRTYFAIL's existing CLI semantics
 * unchanged.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/host.h"

#include "src/common.h"
#include "src/copyfail.h"
#include "src/copyfail_gcm.h"
#include "src/dirtyfrag_esp.h"
#include "src/dirtyfrag_esp6.h"
#include "src/dirtyfrag_rxrpc.h"
#include "src/mitigate.h"

#include <sys/stat.h>

static void apply_ctx(const struct skeletonkey_ctx *ctx)
{
    dirtyfail_use_color     = !ctx->no_color;
    dirtyfail_active_probes = ctx->active_probe;
    dirtyfail_json          = ctx->json;
    /* Forward the --i-know authorization gate. SKELETONKEY already
     * blocks --exploit/--auto unless --i-know is passed, so by the time
     * a DIRTYFAIL exploit callback runs, authorization is established.
     * This lets typed_confirm() skip its (now redundant) interactive
     * prompt, which otherwise deadlocks `skeletonkey --auto --i-know`. */
    dirtyfail_assume_yes    = ctx->authorized;
    /* dirtyfail_no_revert is intentionally not driven from ctx —
     * it's a debug knob; default stays off. */
}

/* Bridge-level userns precondition. The 4 dirty_frag siblings + the
 * GCM variant all reach the bug via XFRM-ESP / AF_RXRPC paths gated on
 * unprivileged user-namespace creation (the inner DIRTYFAIL detect
 * checks for it too, but doing it here gives the dispatcher one
 * testable point per module and short-circuits the heavier
 * inner-detect work when the gate is closed). copy_fail itself uses
 * AF_ALG which doesn't strictly need userns, so it bypasses this
 * gate — its inner detect still confirms the primitive empirically. */
static skeletonkey_result_t cff_check_userns(const char *modname,
                                             const struct skeletonkey_ctx *ctx)
{
    if (ctx->host && !ctx->host->unprivileged_userns_allowed) {
        if (!ctx->json)
            fprintf(stderr, "[i] %s: unprivileged user namespaces are "
                "disabled (host fingerprint) — XFRM/RxRPC variant "
                "unreachable here%s\n", modname,
                ctx->host->apparmor_restrict_userns
                    ? "; AppArmor restriction is on" : "");
        return SKELETONKEY_PRECOND_FAIL;
    }
    return SKELETONKEY_OK;
}

/* ----- Family-wide --mitigate / --cleanup -----
 *
 * The family-wide mitigation (blacklist algif_aead + esp4 + esp6 + rxrpc,
 * set apparmor_restrict_unprivileged_userns=1, drop_caches) is the same
 * for every member of this family. All 5 modules' .mitigate fields
 * therefore point at the same wrapper.
 *
 * For .cleanup we route based on visible state:
 *   - If the mitigation conf file is present, the user most recently
 *     ran --mitigate → revert that.
 *   - Otherwise the user ran --exploit → evict /etc/passwd from page
 *     cache.
 * This is a heuristic, not a state machine. Sufficient for the common
 * usage patterns. */

#define CFF_MITIGATE_CONF "/etc/modprobe.d/dirtyfail-mitigations.conf"

static skeletonkey_result_t copy_fail_family_mitigate(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    return (skeletonkey_result_t)mitigate_apply();
}

static skeletonkey_result_t copy_fail_family_cleanup(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    struct stat st;
    if (stat(CFF_MITIGATE_CONF, &st) == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[*] copy_fail_family: detected mitigation conf "
                            "(%s); reverting mitigation\n", CFF_MITIGATE_CONF);
        }
        return (skeletonkey_result_t)mitigate_revert();
    }
    if (!ctx->json) {
        fprintf(stderr, "[*] copy_fail_family: no mitigation conf; "
                        "evicting /etc/passwd from page cache\n");
    }
    return try_revert_passwd_page_cache() ? SKELETONKEY_OK : SKELETONKEY_TEST_ERROR;
}

/* ----- copy_fail (CVE-2026-31431) ----- */

static skeletonkey_result_t copy_fail_detect_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    return (skeletonkey_result_t)copyfail_detect();
}

static skeletonkey_result_t copy_fail_exploit_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    return (skeletonkey_result_t)copyfail_exploit(!ctx->no_shell);
}

/* Shared detection rules for the copy_fail family — every member of
 * this family exploits the same page-cache-write primitive and lands
 * in the same files (/etc/passwd or /usr/bin/su). One rule set covers
 * all five module entries. Per-module structs alias the same strings. */
static const char copy_fail_family_auditd[] =
    "# Copy Fail family (CVE-2026-31431 + Dirty Frag CVE-2026-43284 + RxRPC CVE-2026-43500)\n"
    "# Page-cache writes to passwd/shadow/su/sudoers from non-root.\n"
    "-w /etc/passwd     -p wa -k skeletonkey-copy-fail\n"
    "-w /etc/shadow     -p wa -k skeletonkey-copy-fail\n"
    "-w /etc/sudoers    -p wa -k skeletonkey-copy-fail\n"
    "-w /etc/sudoers.d  -p wa -k skeletonkey-copy-fail\n"
    "-w /usr/bin/su     -p wa -k skeletonkey-copy-fail\n"
    "# AF_ALG socket creation by non-root — heavily used by exploit\n"
    "-a always,exit -F arch=b64 -S socket -F a0=38 -k skeletonkey-copy-fail-afalg\n"
    "# xfrm SA setup (Dirty Frag ESP variants)\n"
    "-a always,exit -F arch=b64 -S setsockopt -k skeletonkey-copy-fail-xfrm\n";

static const char copy_fail_family_sigma[] =
    "title: Copy Fail / Dirty Frag family exploitation\n"
    "id: 4d8e6c2a-skeletonkey-copy-fail-family\n"
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

/* YARA + Falco rules shared across the 5 family modules. Scanned via
 * --detect-rules; the dispatcher dedups by pointer so the rule blob
 * emits once even though copy_fail / copy_fail_gcm / dirty_frag_*
 * all point at the same string. */
static const char copy_fail_family_yara[] =
    "rule etc_passwd_uid_flip : page_cache_write\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2026-31431 / CVE-2026-43284 / CVE-2026-43500\"\n"
    "        description = \"/etc/passwd page-cache UID flip: a non-root user line shows a zero-padded UID (the canonical Copy Fail / Dirty Frag / DirtyDecrypt / Dirty Pipe payload). Scan /etc/passwd; legitimate root uses plain '0:', never '0000:'.\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        // lowercase-start username, optional shadow ('x') password, then UID 0000 or longer\n"
    "        $uid_flip = /\\n[a-z_][a-z0-9_-]{0,30}:[^:]{0,8}:0{4,}:[0-9]+:/\n"
    "    condition:\n"
    "        $uid_flip\n"
    "}\n"
    "\n"
    "rule etc_passwd_root_no_password\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2026-31635 (DirtyDecrypt sliding-window write)\"\n"
    "        description = \"/etc/passwd root entry rewritten to have an empty password field — the DirtyDecrypt PoC's intermediate corruption (rewrite root's password to empty, then `su root` without password).\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $root_open  = /\\nroot::0:0:/   // empty password (canonical x or ! when shadowed)\n"
    "    condition:\n"
    "        $root_open\n"
    "}\n";

static const char copy_fail_family_falco[] =
    "- rule: AF_ALG authenc keyblob installed by non-root (Copy Fail primitive)\n"
    "  desc: |\n"
    "    A non-root process creates an AF_ALG socket and installs an\n"
    "    authencesn(hmac(sha256),cbc(aes)) keyblob via ALG_SET_KEY.\n"
    "    Core of the Copy Fail (CVE-2026-31431) primitive — also\n"
    "    triggered by the GCM variant. AF_ALG by non-root is rare on\n"
    "    most servers; tune by allow-listing your crypto-using daemons.\n"
    "  condition: >\n"
    "    evt.type = socket and evt.arg[0] = 38 and not user.uid = 0\n"
    "  output: >\n"
    "    AF_ALG socket() by non-root (user=%user.name pid=%proc.pid\n"
    "     ppid=%proc.ppid parent=%proc.pname cmdline=\"%proc.cmdline\")\n"
    "  priority: WARNING\n"
    "  tags: [process, cve.2026.31431, copy_fail]\n"
    "\n"
    "- rule: XFRM NETLINK_XFRM bind from unprivileged userns (Dirty Frag primitive)\n"
    "  desc: |\n"
    "    A NETLINK_XFRM socket is opened from inside an unprivileged\n"
    "    user namespace, with subsequent XFRM_MSG_NEWSA installing an\n"
    "    ESP(rfc4106(gcm(aes))) state. Core of the Dirty Frag esp/esp6\n"
    "    variants — also tripped by Fragnesia's setup phase. Legitimate\n"
    "    XFRM use is normally privileged (strongSwan, libreswan).\n"
    "  condition: >\n"
    "    evt.type = sendto and not user.uid = 0 and\n"
    "    proc.aname[1] != \"\"   // we want non-init userns; refine with k8s.namespace or container.id\n"
    "  output: >\n"
    "    NETLINK_XFRM sendto from non-root (user=%user.name pid=%proc.pid\n"
    "     proc=%proc.name)\n"
    "  priority: WARNING\n"
    "  tags: [process, cve.2026.43284, dirty_frag]\n"
    "\n"
    "- rule: /etc/passwd modified by non-root (Copy Fail / Dirty Frag / Dirty Pipe outcome)\n"
    "  desc: |\n"
    "    /etc/passwd is read-only for non-root, so a non-root caller\n"
    "    showing up on its open(W_OK) audit trail indicates a\n"
    "    page-cache write primitive succeeded. Catches the post-fire\n"
    "    state for the whole copy_fail family + dirty_pipe.\n"
    "  condition: >\n"
    "    open_write and fd.name = /etc/passwd and not user.uid = 0\n"
    "  output: >\n"
    "    Non-root write to /etc/passwd (user=%user.name pid=%proc.pid\n"
    "     proc=%proc.name)\n"
    "  priority: CRITICAL\n"
    "  tags: [filesystem, mitre_privilege_escalation, T1068, copy_fail, dirty_frag]\n";

const struct skeletonkey_module copy_fail_module = {
    .name           = "copy_fail",
    .cve            = "CVE-2026-31431",
    .summary        = "algif_aead authencesn page-cache write → /etc/passwd UID flip",
    .family         = "copy_fail_family",
    .kernel_range   = "≤ 6.12.84, fixed mainline 2026-04-22",
    .detect         = copy_fail_detect_wrap,
    .exploit        = copy_fail_exploit_wrap,
    .mitigate       = copy_fail_family_mitigate,
    .cleanup        = copy_fail_family_cleanup,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = copy_fail_family_yara,
    .detect_falco   = copy_fail_family_falco,
    .opsec_notes    = "Family-shared infrastructure (copy_fail, copy_fail_gcm, dirty_frag_esp/esp6, dirty_frag_rxrpc): all exploit a page-cache write primitive against /etc/passwd (UID flip to all-zeros) or install a persistent backdoor. Audit-visible via socket(AF_ALG) (a0=38), setsockopt(XFRM), AF_UNIX setup. Detection rules watch /etc/passwd, /etc/shadow, /etc/sudoers, /usr/bin/su for non-root writes. Family mitigation blacklists algif_aead/esp4/esp6/rxrpc and sets apparmor_restrict_unprivileged_userns=1. Cleanup evicts /etc/passwd from page cache and reverts mitigation conf.",
    .arch_support   = "x86_64+unverified-arm64",
};

/* ----- copy_fail_gcm (variant, no CVE) ----- */

static skeletonkey_result_t copy_fail_gcm_detect_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    skeletonkey_result_t pre = cff_check_userns("copy_fail_gcm", ctx);
    if (pre != SKELETONKEY_OK) return pre;
    return (skeletonkey_result_t)copyfail_gcm_detect();
}

static skeletonkey_result_t copy_fail_gcm_exploit_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    return (skeletonkey_result_t)copyfail_gcm_exploit(!ctx->no_shell);
}

const struct skeletonkey_module copy_fail_gcm_module = {
    .name         = "copy_fail_gcm",
    .cve          = "VARIANT",
    .summary      = "rfc4106(gcm(aes)) single-byte page-cache write (Copy Fail sibling)",
    .family       = "copy_fail_family",
    .kernel_range = "same as copy_fail; rfc4106(gcm(aes)) not in modprobe blacklist",
    .detect       = copy_fail_gcm_detect_wrap,
    .exploit      = copy_fail_gcm_exploit_wrap,
    .mitigate       = copy_fail_family_mitigate,
    .cleanup        = copy_fail_family_cleanup,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = copy_fail_family_yara,
    .detect_falco   = copy_fail_family_falco,
    .opsec_notes    = "Family-shared infrastructure (copy_fail, copy_fail_gcm, dirty_frag_esp/esp6, dirty_frag_rxrpc): all exploit a page-cache write primitive against /etc/passwd (UID flip to all-zeros) or install a persistent backdoor. Audit-visible via socket(AF_ALG) (a0=38), setsockopt(XFRM), AF_UNIX setup. Detection rules watch /etc/passwd, /etc/shadow, /etc/sudoers, /usr/bin/su for non-root writes. Family mitigation blacklists algif_aead/esp4/esp6/rxrpc and sets apparmor_restrict_unprivileged_userns=1. Cleanup evicts /etc/passwd from page cache and reverts mitigation conf.",
    .arch_support   = "x86_64+unverified-arm64",
};

/* ----- dirty_frag_esp (CVE-2026-43284 v4) ----- */

static skeletonkey_result_t dirty_frag_esp_detect_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    skeletonkey_result_t pre = cff_check_userns("dirty_frag_esp", ctx);
    if (pre != SKELETONKEY_OK) return pre;
    return (skeletonkey_result_t)dirtyfrag_esp_detect();
}

static skeletonkey_result_t dirty_frag_esp_exploit_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    return (skeletonkey_result_t)dirtyfrag_esp_exploit(!ctx->no_shell);
}

const struct skeletonkey_module dirty_frag_esp_module = {
    .name         = "dirty_frag_esp",
    .cve          = "CVE-2026-43284",
    .summary      = "IPv4 xfrm-ESP page-cache write (Dirty Frag v4)",
    .family       = "copy_fail_family",
    .kernel_range = "same family as copy_fail; xfrm-ESP path",
    .detect       = dirty_frag_esp_detect_wrap,
    .exploit      = dirty_frag_esp_exploit_wrap,
    .mitigate       = copy_fail_family_mitigate,
    .cleanup        = copy_fail_family_cleanup,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = copy_fail_family_yara,
    .detect_falco   = copy_fail_family_falco,
    .opsec_notes    = "Family-shared infrastructure (copy_fail, copy_fail_gcm, dirty_frag_esp/esp6, dirty_frag_rxrpc): all exploit a page-cache write primitive against /etc/passwd (UID flip to all-zeros) or install a persistent backdoor. Audit-visible via socket(AF_ALG) (a0=38), setsockopt(XFRM), AF_UNIX setup. Detection rules watch /etc/passwd, /etc/shadow, /etc/sudoers, /usr/bin/su for non-root writes. Family mitigation blacklists algif_aead/esp4/esp6/rxrpc and sets apparmor_restrict_unprivileged_userns=1. Cleanup evicts /etc/passwd from page cache and reverts mitigation conf.",
    .arch_support   = "x86_64+unverified-arm64",
};

/* ----- dirty_frag_esp6 (CVE-2026-43284 v6) ----- */

static skeletonkey_result_t dirty_frag_esp6_detect_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    skeletonkey_result_t pre = cff_check_userns("dirty_frag_esp6", ctx);
    if (pre != SKELETONKEY_OK) return pre;
    return (skeletonkey_result_t)dirtyfrag_esp6_detect();
}

static skeletonkey_result_t dirty_frag_esp6_exploit_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    return (skeletonkey_result_t)dirtyfrag_esp6_exploit(!ctx->no_shell);
}

const struct skeletonkey_module dirty_frag_esp6_module = {
    .name         = "dirty_frag_esp6",
    .cve          = "CVE-2026-43284",
    .summary      = "IPv6 xfrm-ESP page-cache write (Dirty Frag v6)",
    .family       = "copy_fail_family",
    .kernel_range = "same family as copy_fail; xfrm-ESP6 path; V6 STORE shift auto-calibrated",
    .detect       = dirty_frag_esp6_detect_wrap,
    .exploit      = dirty_frag_esp6_exploit_wrap,
    .mitigate       = copy_fail_family_mitigate,
    .cleanup        = copy_fail_family_cleanup,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = copy_fail_family_yara,
    .detect_falco   = copy_fail_family_falco,
    .opsec_notes    = "Family-shared infrastructure (copy_fail, copy_fail_gcm, dirty_frag_esp/esp6, dirty_frag_rxrpc): all exploit a page-cache write primitive against /etc/passwd (UID flip to all-zeros) or install a persistent backdoor. Audit-visible via socket(AF_ALG) (a0=38), setsockopt(XFRM), AF_UNIX setup. Detection rules watch /etc/passwd, /etc/shadow, /etc/sudoers, /usr/bin/su for non-root writes. Family mitigation blacklists algif_aead/esp4/esp6/rxrpc and sets apparmor_restrict_unprivileged_userns=1. Cleanup evicts /etc/passwd from page cache and reverts mitigation conf.",
    .arch_support   = "x86_64+unverified-arm64",
};

/* ----- dirty_frag_rxrpc (CVE-2026-43500) ----- */

static skeletonkey_result_t dirty_frag_rxrpc_detect_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    skeletonkey_result_t pre = cff_check_userns("dirty_frag_rxrpc", ctx);
    if (pre != SKELETONKEY_OK) return pre;
    return (skeletonkey_result_t)dirtyfrag_rxrpc_detect();
}

static skeletonkey_result_t dirty_frag_rxrpc_exploit_wrap(const struct skeletonkey_ctx *ctx)
{
    apply_ctx(ctx);
    return (skeletonkey_result_t)dirtyfrag_rxrpc_exploit(!ctx->no_shell);
}

const struct skeletonkey_module dirty_frag_rxrpc_module = {
    .name         = "dirty_frag_rxrpc",
    .cve          = "CVE-2026-43500",
    .summary      = "AF_RXRPC handshake forgery + page-cache write (Dirty Frag RxRPC)",
    .family       = "copy_fail_family",
    .kernel_range = "kernels exposing AF_RXRPC + rxkad with fcrypt fallback",
    .detect       = dirty_frag_rxrpc_detect_wrap,
    .exploit      = dirty_frag_rxrpc_exploit_wrap,
    .mitigate       = copy_fail_family_mitigate,
    .cleanup        = copy_fail_family_cleanup,
    .detect_auditd  = copy_fail_family_auditd,
    .detect_sigma   = copy_fail_family_sigma,
    .detect_yara    = copy_fail_family_yara,
    .detect_falco   = copy_fail_family_falco,
    .opsec_notes    = "Family-shared infrastructure (copy_fail, copy_fail_gcm, dirty_frag_esp/esp6, dirty_frag_rxrpc): all exploit a page-cache write primitive against /etc/passwd (UID flip to all-zeros) or install a persistent backdoor. Audit-visible via socket(AF_ALG) (a0=38), setsockopt(XFRM), AF_UNIX setup. Detection rules watch /etc/passwd, /etc/shadow, /etc/sudoers, /usr/bin/su for non-root writes. Family mitigation blacklists algif_aead/esp4/esp6/rxrpc and sets apparmor_restrict_unprivileged_userns=1. Cleanup evicts /etc/passwd from page cache and reverts mitigation conf.",
    .arch_support   = "x86_64+unverified-arm64",
};

/* ----- Family registration ----- */

void skeletonkey_register_copy_fail_family(void)
{
    skeletonkey_register(&copy_fail_module);
    skeletonkey_register(&copy_fail_gcm_module);
    skeletonkey_register(&dirty_frag_esp_module);
    skeletonkey_register(&dirty_frag_esp6_module);
    skeletonkey_register(&dirty_frag_rxrpc_module);
}
