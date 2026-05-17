/*
 * pwnkit_cve_2021_4034 — IAMROOT module
 *
 * STATUS: 🔵 DETECT-ONLY (2026-05-16). Full exploit follows.
 *
 * Detect: check pkexec presence + version. The fix landed in
 * polkit 0.121. Distros backport to various polkit versions, so a
 * naive "polkit < 0.121 == vulnerable" rule overcounts. We check
 * pkexec's reported version and the distro's polkit package version
 * if we can.
 *
 * Exploit: stubbed. The canonical Qualys PoC (~200 lines + an
 * embedded .so generator) is well-documented; landing it is a
 * follow-up commit.
 *
 * Pwnkit is the first USERSPACE LPE in IAMROOT — the rest of the
 * corpus is kernel bugs. The module shape is identical (same
 * iamroot_module interface), but the affected-version check is
 * package-version-based rather than kernel-version-based. core/
 * may eventually grow a `pkg_version` helper if a few more userspace
 * modules need it.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static const char *find_pkexec(void)
{
    static const char *candidates[] = {
        "/usr/bin/pkexec",
        "/usr/sbin/pkexec",
        "/bin/pkexec",
        "/sbin/pkexec",
        "/usr/local/bin/pkexec",
        NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0) {
            /* setuid bit is the marker for a vulnerable install */
            if (st.st_mode & S_ISUID) return candidates[i];
        }
    }
    return NULL;
}

/* Returns true if version_str represents a vulnerable polkit
 * (< 0.121 fix). Handles both formats:
 *   Older polkit: "0.105", "0.120" → vulnerable if minor < 121
 *   Modern polkit: bare integer "121", "122", "126" → vulnerable if < 121
 * Caveat: distro backports may have fixed lower-numbered versions;
 * we conservatively report VULNERABLE on parse failure rather than
 * silently passing. */
static bool pkexec_version_vulnerable(const char *version_str)
{
    int maj = 0, min = 0;
    int n = sscanf(version_str, "%d.%d", &maj, &min);
    if (n < 1) return true;          /* can't parse → assume worst */
    if (n == 1) {
        /* Bare integer (modern polkit): "121", "126", etc. */
        return maj < 121;
    }
    /* "X.Y" format (older polkit) */
    if (maj > 0) return false;       /* 1.x or higher = post-fix */
    return min < 121;                /* 0.121 is the fix */
}

static iamroot_result_t pwnkit_detect(const struct iamroot_ctx *ctx)
{
    const char *pkexec_path = find_pkexec();
    if (!pkexec_path) {
        if (!ctx->json) {
            fprintf(stderr, "[+] pwnkit: pkexec not installed; no attack surface\n");
        }
        return IAMROOT_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[i] pwnkit: found setuid pkexec at %s\n", pkexec_path);
    }

    /* Run `pkexec --version` and parse. We pipe stderr/stdout to a
     * temp file because popen() can have quoting quirks. */
    char cmd[512];
    snprintf(cmd, sizeof cmd, "%s --version 2>&1 | head -1", pkexec_path);
    FILE *p = popen(cmd, "r");
    if (!p) return IAMROOT_TEST_ERROR;

    char line[256] = {0};
    char *r = fgets(line, sizeof line, p);
    pclose(p);
    if (!r) {
        if (!ctx->json) {
            fprintf(stderr, "[?] pwnkit: could not parse pkexec --version output\n");
        }
        return IAMROOT_TEST_ERROR;
    }

    /* Output format: "pkexec version 0.105\n" or "pkexec version 0.120-..." */
    char *vp = strstr(line, "version");
    if (!vp) return IAMROOT_TEST_ERROR;
    vp += strlen("version");
    while (*vp == ' ' || *vp == '\t') vp++;

    if (!ctx->json) {
        char *nl = strchr(vp, '\n');
        if (nl) *nl = 0;
        fprintf(stderr, "[i] pwnkit: pkexec reports version '%s'\n", vp);
    }

    bool vuln = pkexec_version_vulnerable(vp);

    if (vuln) {
        if (!ctx->json) {
            fprintf(stderr, "[!] pwnkit: pkexec version is pre-0.121 fix → likely VULNERABLE\n");
            fprintf(stderr, "[i] pwnkit: distro backports may have fixed lower-numbered versions;\n"
                            "    check `apt-cache policy policykit-1` / `rpm -q polkit` for the patch level\n");
        }
        return IAMROOT_VULNERABLE;
    }
    if (!ctx->json) {
        fprintf(stderr, "[+] pwnkit: pkexec version is ≥ 0.121 (fixed)\n");
    }
    return IAMROOT_OK;
}

static iamroot_result_t pwnkit_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] pwnkit: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY (see CVES.md, ROADMAP.md Phase 7).\n"
        "    The canonical Qualys PoC (~200 lines + embedded .so generator)\n"
        "    is the reference; landing it in iamroot_module form is the\n"
        "    Phase 7 follow-up. For now, --scan correctly reports per-host\n"
        "    vulnerability; run Qualys' public PoC manually to verify.\n");
    return IAMROOT_PRECOND_FAIL;
}

/* ----- Embedded detection rules ----- */

static const char pwnkit_auditd[] =
    "# Pwnkit (CVE-2021-4034) — auditd detection rules\n"
    "# Flag pkexec execution from non-root + look for argc==0 indicators.\n"
    "-w /usr/bin/pkexec -p x -k iamroot-pwnkit\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec -k iamroot-pwnkit-execve\n"
    "-a always,exit -F arch=b32 -S execve -F path=/usr/bin/pkexec -k iamroot-pwnkit-execve\n";

static const char pwnkit_sigma[] =
    "title: Possible Pwnkit exploitation (CVE-2021-4034)\n"
    "id: 9e1d4f2c-iamroot-pwnkit\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects pkexec invocations with GCONV_PATH / CHARSET env tweaks (the\n"
    "  Qualys PoC pattern). Also flags any execve(pkexec) where argv0 is\n"
    "  empty or NULL (which is the bug's hallmark trigger).\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  pkexec_invocation:\n"
    "    type: 'EXECVE'\n"
    "    exe|endswith: '/pkexec'\n"
    "  suspicious_env:\n"
    "    - 'GCONV_PATH='\n"
    "    - 'CHARSET='\n"
    "    - 'PATH=GCONV_PATH=.'\n"
    "  condition: pkexec_invocation and suspicious_env\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2021.4034]\n";

const struct iamroot_module pwnkit_module = {
    .name           = "pwnkit",
    .cve            = "CVE-2021-4034",
    .summary        = "pkexec argv[0]=NULL → env-injection LPE (polkit ≤ 0.120)",
    .family         = "pwnkit",
    .kernel_range   = "userspace bug — affects polkit ≤ 0.120; pkexec setuid-root binary",
    .detect         = pwnkit_detect,
    .exploit        = pwnkit_exploit,
    .mitigate       = NULL,        /* mitigation = upgrade polkit / chmod -s pkexec */
    .cleanup        = NULL,        /* no per-exploit cleanup once full impl lands */
    .detect_auditd  = pwnkit_auditd,
    .detect_sigma   = pwnkit_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_pwnkit(void)
{
    iamroot_register(&pwnkit_module);
}
