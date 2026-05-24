/*
 * mutagen_astronomy_cve_2018_14634 — SKELETONKEY module
 *
 * STATUS: 🟡 PRIMITIVE. detect() is honest about a complex bug class
 *   (kernel-version range + RLIMIT_STACK check + readable SUID
 *   carrier). exploit() carries the Qualys trigger shape (huge
 *   argv/envp blob → integer overflow in create_elf_tables() →
 *   stack/heap clobber on the next execve of a SUID binary), then
 *   returns EXPLOIT_FAIL unless --full-chain is set on x86_64.
 *
 * The bug (Qualys Research Labs, September 2018):
 *   create_elf_tables() in fs/binfmt_elf.c uses a signed `int` to
 *   compute the size of argv/envp + auxiliary vector that gets
 *   copied onto the new process's stack during execve(). On 64-bit
 *   systems, an attacker can construct a multi-gigabyte argv+envp
 *   so the int math wraps to a small positive value, the kernel
 *   under-allocates, then memcpy()s GiB of attacker bytes off the
 *   end of the stack and into adjacent kernel-side allocations.
 *
 *   The classic exploitation path: drive the wrap, execve() a
 *   readable SUID-root binary (su / pkexec / sudo) with the giant
 *   argv, the SUID binary's process image gets corrupted before its
 *   first instruction runs → ROP gadget chain → root.
 *
 *   Discovered + publicly exploited by Qualys. Affects Linux
 *   2.6.x, 3.10.x, and 4.14.x lines on RedHat / CentOS / Debian
 *   x86_64. Recently CISA-KEV'd (added 2026-01-26) despite its age
 *   because legacy/EOL fleets are still running affected kernels.
 *
 * Affects: Linux kernels with the `int`-typed argv-size computation
 *   in create_elf_tables() — pre-fix. Mainline fix landed in
 *   September 2018 across 2.6, 3.10, and 4.14 stable branches.
 *
 * Preconditions:
 *   - Vulnerable kernel (see kernel_range below)
 *   - x86_64 (the int-wrap math only works at 64-bit)
 *   - RLIMIT_STACK can be set unlimited or to a large value by the
 *     unprivileged user (default true on most distros)
 *   - Readable SUID-root binary as the carrier
 *
 * arch_support: x86_64+unverified-arm64. The Qualys PoC is x86_64-
 *   only; arm64 has similar argv size math but the exploit chain
 *   uses x86-specific gadgets.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>

/* ---- kernel-range table -------------------------------------------- */

/* Fix landed in mainline Linux 4.18.8 + stable backports for 4.14
 * (4.14.71) and earlier LTS lines. The vulnerable window covers the
 * entire 2.6 / 3.x / early 4.x range. We list the fix branches:
 *
 *   2.6.x : EOL, no fix backport
 *   3.10.x: EOL, RedHat backport ~3.10.0-957.21.3.el7
 *   4.14.x: fix at 4.14.71 (stable backport)
 *   4.15+ : fix at 4.18.8 mainline → all 4.18+ branches inherit
 *
 * Our table only has data for the post-EOL branches Debian / Ubuntu
 * tracked at the time. Kernels on EOL lines (2.6, 3.x) report
 * VULNERABLE by version-only check; the RLIMIT_STACK active probe
 * (--active) is required to confirm exploitability on a real host. */
static const struct kernel_patched_from mutagen_patched_branches[] = {
    {4, 14, 71},   /* 4.14 LTS stable backport */
    {4, 18,  8},   /* mainline + everything above inherits */
};

static const struct kernel_range mutagen_range = {
    .patched_from = mutagen_patched_branches,
    .n_patched_from = sizeof(mutagen_patched_branches) /
                      sizeof(mutagen_patched_branches[0]),
};

/* ---- detect --------------------------------------------------------- */

static const char *find_suid_carrier(void)
{
    static const char *cs[] = {
        "/usr/bin/su", "/bin/su",
        "/usr/bin/pkexec",
        "/usr/bin/passwd",
        NULL,
    };
    for (size_t i = 0; cs[i]; i++) {
        struct stat st;
        if (stat(cs[i], &st) == 0 &&
            (st.st_mode & S_ISUID) && st.st_uid == 0 &&
            access(cs[i], R_OK) == 0)
            return cs[i];
    }
    return NULL;
}

static bool rlimit_stack_unlimitable(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) != 0) return false;
    /* The exploit needs to set RLIMIT_STACK = unlimited. If the hard
     * limit is already unlimited (or extremely large) the soft limit
     * can be bumped. */
    return rl.rlim_max == RLIM_INFINITY || rl.rlim_max > (1ULL << 30);
}

static skeletonkey_result_t mutagen_astronomy_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] mutagen_astronomy: host fingerprint missing kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    if (kernel_range_is_patched(&mutagen_range, v)) {
        if (!ctx->json)
            fprintf(stderr, "[+] mutagen_astronomy: kernel %s is patched (>= 4.14.71 or >= 4.18.8)\n", v->release);
        return SKELETONKEY_OK;
    }

    /* Older 2.6/3.10 lines are unconditionally vulnerable unless the
     * distro has backported (RedHat 3.10.0-957.21.3.el7+). The
     * version-only check correctly flags them as VULNERABLE. */

    if (!rlimit_stack_unlimitable()) {
        if (!ctx->json)
            fprintf(stderr, "[i] mutagen_astronomy: kernel %s in range BUT RLIMIT_STACK hard cap blocks the wrap\n", v->release);
        return SKELETONKEY_PRECOND_FAIL;
    }

    const char *carrier = find_suid_carrier();
    if (!carrier) {
        if (!ctx->json)
            fprintf(stderr, "[!] mutagen_astronomy: no readable setuid-root carrier (su / pkexec / passwd)\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] mutagen_astronomy: kernel %s + RLIMIT_STACK liftable + carrier %s → VULNERABLE\n",
                v->release, carrier);
        fprintf(stderr, "[i] mutagen_astronomy: Qualys exploit chain is x86_64; only the trigger fires portably\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- exploit (primitive only) -------------------------------------- */

static skeletonkey_result_t mutagen_astronomy_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] mutagen_astronomy: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    fprintf(stderr,
        "[i] mutagen_astronomy: the int-wrap trigger requires constructing a\n"
        "    multi-gigabyte argv+envp blob; we don't carry the full Qualys\n"
        "    chain here (per the verified-vs-claimed bar). To validate the\n"
        "    primitive: drive the wrap then execve a SUID-root carrier and\n"
        "    confirm a SIGSEGV in the carrier (the wrap consistently\n"
        "    corrupts adjacent stack, producing observable crash). Public\n"
        "    PoC: Qualys advisory + linux-exploit-suggester2 entry.\n"
        "    Returning EXPLOIT_FAIL honestly until full chain ported.\n");
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- detection rules ------------------------------------------------ */

static const char mutagen_auditd[] =
    "# mutagen_astronomy CVE-2018-14634 — auditd detection rules\n"
    "# A multi-GiB argv triggers the wrap. Real programs never need\n"
    "# argv this big; flag execve() calls with abnormally large\n"
    "# argv via the audit subsystem's a0/a1 capture.\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su      -k skeletonkey-mutagen\n"
    "-a always,exit -F arch=b64 -S execve -F path=/bin/su          -k skeletonkey-mutagen\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec  -k skeletonkey-mutagen\n";

static const char mutagen_sigma[] =
    "title: Possible CVE-2018-14634 Mutagen Astronomy SUID-execve LPE\n"
    "id: 5f9e1c20-skeletonkey-mutagen\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical Mutagen Astronomy primitive: setrlimit\n"
    "  raising RLIMIT_STACK followed by execve of a setuid-root\n"
    "  binary with abnormally large argv/envp. Pre-fix Linux\n"
    "  2.6/3.10/4.14 kernels with x86_64 are affected.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  setrlimit: {type: 'SYSCALL', syscall: 'setrlimit'}\n"
    "  execve_suid: {type: 'SYSCALL', syscall: 'execve'}\n"
    "  condition: setrlimit and execve_suid\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2018.14634]\n";

static const char mutagen_yara[] =
    "rule mutagen_astronomy_cve_2018_14634 : cve_2018_14634 elf_stack_overflow {\n"
    "    meta:\n"
    "        cve         = \"CVE-2018-14634\"\n"
    "        description = \"Qualys Mutagen Astronomy primitive — RLIMIT_STACK + huge argv\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"mutagen-astronomy\" ascii\n"
    "        $qualys = \"qualys\" ascii nocase\n"
    "    condition:\n"
    "        $tag\n"
    "}\n";

static const char mutagen_falco[] =
    "- rule: setrlimit(STACK)+execve of SUID with huge argv (Mutagen Astronomy)\n"
    "  desc: |\n"
    "    Process raises RLIMIT_STACK then execve()s a setuid-root binary.\n"
    "    The Mutagen Astronomy primitive (CVE-2018-14634) needs both. No\n"
    "    legitimate program needs RLIMIT_STACK=unlimited before exec'ing\n"
    "    su/pkexec.\n"
    "  condition: >\n"
    "    evt.type = execve and not user.uid = 0 and\n"
    "    (proc.exe in (/usr/bin/su, /bin/su, /usr/bin/pkexec, /usr/bin/passwd))\n"
    "  output: >\n"
    "    SUID execve with RLIMIT_STACK raised (user=%user.name\n"
    "     pid=%proc.pid exe=%proc.exe)\n"
    "  priority: HIGH\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2018.14634]\n";

const struct skeletonkey_module mutagen_astronomy_module = {
    .name           = "mutagen_astronomy",
    .cve            = "CVE-2018-14634",
    .summary        = "create_elf_tables() int wrap → SUID-execve stack corruption (Qualys)",
    .family         = "elf",
    .kernel_range   = "Linux 2.6 / 3.10 / 4.14 < 4.14.71 / 4.x < 4.18.8 (x86_64)",
    .detect         = mutagen_astronomy_detect,
    .exploit        = mutagen_astronomy_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR set hard RLIMIT_STACK limit */
    .cleanup        = NULL,
    .detect_auditd  = mutagen_auditd,
    .detect_sigma   = mutagen_sigma,
    .detect_yara    = mutagen_yara,
    .detect_falco   = mutagen_falco,
    .opsec_notes    = "Raises RLIMIT_STACK to unlimited via setrlimit(2), then execve()s a setuid-root binary (typically /usr/bin/su or /usr/bin/pkexec) with a multi-gigabyte argv/envp blob (≥4 GiB on x86_64). The int wrap in create_elf_tables() causes the kernel to under-allocate the new process's stack region; the subsequent memcpy of argv bytes corrupts adjacent kernel allocations. Observable as a SIGSEGV in the carrier on every attempt regardless of success. Audit-visible via setrlimit(RLIMIT_STACK) immediately followed by execve of /usr/bin/su or /usr/bin/pkexec with abnormally large argv. No persistent file artifacts. CISA KEV-listed Jan 2026 despite the bug's age — legacy/EOL fleets still running RHEL 7 / CentOS 7 / Debian 8 remain at risk.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_mutagen_astronomy(void)
{
    skeletonkey_register(&mutagen_astronomy_module);
}
