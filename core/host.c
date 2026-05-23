/*
 * SKELETONKEY — host fingerprint implementation
 *
 * Lives behind a one-shot lazy-init: skeletonkey_host_get() probes on
 * first call, stores into a file-static, and returns the same pointer
 * forever after. Single-threaded (skeletonkey is single-threaded), so
 * no synchronisation needed.
 */

#include "host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#ifdef __linux__
#include <sched.h>
#include <sys/wait.h>
#endif

static struct skeletonkey_host g_host;
static bool g_host_ready = false;

/* ── small parser helpers ─────────────────────────────────────────── */

/* Copy the value of a `KEY=VAL` line (stripping leading quotes and
 * trailing quote / newline) into `dst`. Caller passes the start of the
 * value (after `=`). Cap is the size of dst including NUL. */
static void parse_os_release_value(const char *s, char *dst, size_t cap)
{
	const char *p = s;
	if (*p == '"' || *p == '\'') p++;
	size_t L = strcspn(p, "\"'\n");
	if (L >= cap) L = cap - 1;
	memcpy(dst, p, L);
	dst[L] = '\0';
}

static bool path_exists(const char *p)
{
	struct stat st;
	return stat(p, &st) == 0;
}

#ifdef __linux__
/* Sysctl/sys-fs readers — Linux-only consumers (populate_caps). */
static bool read_int_file(const char *path, int *out)
{
	FILE *f = fopen(path, "r");
	if (!f) return false;
	int v;
	int n = fscanf(f, "%d", &v);
	fclose(f);
	if (n != 1) return false;
	*out = v;
	return true;
}

static bool read_first_line(const char *path, char *dst, size_t cap)
{
	FILE *f = fopen(path, "r");
	if (!f) return false;
	if (!fgets(dst, (int)cap, f)) { fclose(f); return false; }
	fclose(f);
	size_t n = strlen(dst);
	while (n > 0 && (dst[n-1] == '\n' || dst[n-1] == '\r')) dst[--n] = '\0';
	return true;
}
#endif

/* ── populators ───────────────────────────────────────────────────── */

static void populate_kernel(struct skeletonkey_host *h)
{
	struct utsname u;
	if (uname(&u) == 0) {
		/* utsname.machine/nodename can be up to 65 bytes on glibc; the
		 * %.*s precision spec tells gcc the snprintf is bounded so it
		 * does not warn about possible truncation (we WANT truncation;
		 * the snprintf already caps). */
		snprintf(h->arch,     sizeof h->arch,
			 "%.*s", (int)sizeof(h->arch) - 1, u.machine);
		snprintf(h->nodename, sizeof h->nodename,
			 "%.*s", (int)sizeof(h->nodename) - 1, u.nodename);
	}
	/* kernel_version_current owns the static release-string buffer
	 * and the parser — reuse it to keep one source of truth. */
	kernel_version_current(&h->kernel);
}

static void populate_distro(struct skeletonkey_host *h)
{
	snprintf(h->distro_id,         sizeof h->distro_id,         "?");
	snprintf(h->distro_version_id, sizeof h->distro_version_id, "?");
	snprintf(h->distro_pretty,     sizeof h->distro_pretty,     "?");

	FILE *f = fopen("/etc/os-release", "r");
	if (!f) return;
	char line[256];
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, "ID=", 3) == 0)
			parse_os_release_value(line + 3,
				h->distro_id, sizeof h->distro_id);
		else if (strncmp(line, "VERSION_ID=", 11) == 0)
			parse_os_release_value(line + 11,
				h->distro_version_id, sizeof h->distro_version_id);
		else if (strncmp(line, "PRETTY_NAME=", 12) == 0)
			parse_os_release_value(line + 12,
				h->distro_pretty, sizeof h->distro_pretty);
	}
	fclose(f);
}

static void populate_user(struct skeletonkey_host *h)
{
	h->euid = geteuid();
	h->egid = getegid();
	h->is_root = (h->euid == 0);
	h->is_ssh_session = (getenv("SSH_CONNECTION") != NULL);

	h->username[0] = '\0';
	struct passwd *pw = getpwuid(h->euid);
	if (pw && pw->pw_name)
		snprintf(h->username, sizeof h->username, "%s", pw->pw_name);

	/* Default: real_uid == euid (no userns). Try /proc/self/uid_map to
	 * discover the outer uid if we're inside a user namespace. Format
	 *
	 *   "0 0 4294967295"      → init ns, outer == 0
	 *   "0 1000 1"            → userns mapped, outer == 1000
	 *
	 * Only trust outer != 0 and != -1 as the bypass-userns case. */
	h->real_uid = h->euid;
	int fd = open("/proc/self/uid_map", O_RDONLY);
	if (fd >= 0) {
		char buf[256];
		ssize_t n = read(fd, buf, sizeof buf - 1);
		close(fd);
		if (n > 0) {
			buf[n] = '\0';
			int inner = -1, outer = -1, count = 0;
			if (sscanf(buf, "%d %d %d", &inner, &outer, &count) == 3 &&
			    inner == 0 && outer > 0)
				h->real_uid = (uid_t)outer;
		}
	}
}

static void populate_platform_family(struct skeletonkey_host *h)
{
#ifdef __linux__
	h->is_linux = true;
#else
	h->is_linux = false;
#endif
	h->is_debian_family = path_exists("/etc/debian_version");
	h->is_rpm_family    = path_exists("/etc/redhat-release") ||
	                      path_exists("/etc/fedora-release") ||
	                      path_exists("/etc/rocky-release") ||
	                      path_exists("/etc/almalinux-release");
	h->is_arch_family   = path_exists("/etc/arch-release");
	h->is_suse_family   = path_exists("/etc/SuSE-release") ||
	                      path_exists("/etc/SUSE-brand");
}

#ifdef __linux__
/* fork+unshare(CLONE_NEWUSER) probe. Forks once; ~1ms cost. */
static bool userns_probe(void)
{
	pid_t pid = fork();
	if (pid < 0) return false;
	if (pid == 0) {
		_exit(unshare(CLONE_NEWUSER) == 0 ? 0 : 1);
	}
	int st;
	if (waitpid(pid, &st, 0) < 0) return false;
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}
#endif

static void populate_caps(struct skeletonkey_host *h)
{
	h->unprivileged_userns_allowed = false;
	h->apparmor_restrict_userns    = false;
	h->unprivileged_bpf_disabled   = false;
	h->kpti_enabled                = false;
	h->kernel_lockdown_active      = false;
	h->selinux_enforcing           = false;
	h->yama_ptrace_restricted      = false;

#ifdef __linux__
	h->unprivileged_userns_allowed = userns_probe();

	int v = 0;
	if (read_int_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", &v))
		h->apparmor_restrict_userns = (v != 0);
	if (read_int_file("/proc/sys/kernel/unprivileged_bpf_disabled", &v))
		h->unprivileged_bpf_disabled = (v != 0);
	if (read_int_file("/sys/fs/selinux/enforce", &v))
		h->selinux_enforcing = (v != 0);
	if (read_int_file("/proc/sys/kernel/yama/ptrace_scope", &v))
		h->yama_ptrace_restricted = (v > 0);

	char buf[256];
	if (read_first_line("/sys/devices/system/cpu/vulnerabilities/meltdown", buf, sizeof buf))
		h->kpti_enabled = (strstr(buf, "Mitigation: PTI") != NULL);

	/* /sys/kernel/security/lockdown format: "[none] integrity confidentiality"
	 * — whichever level is bracketed is the active one. */
	if (read_first_line("/sys/kernel/security/lockdown", buf, sizeof buf))
		h->kernel_lockdown_active = (strstr(buf, "[none]") == NULL);
#endif
}

static void populate_services(struct skeletonkey_host *h)
{
	h->has_systemd     = path_exists("/run/systemd/system");
	h->has_dbus_system = path_exists("/run/dbus/system_bus_socket");
}

/* Best-effort: run `cmd`, capture first stdout line, strip newline,
 * copy up to (cap - 1) bytes into dst. Returns true iff popen
 * succeeded, the command exited 0, and we got at least one line.
 * Used for sudo/pkexec/packagekitd version parsing at startup. */
static bool capture_first_line(const char *cmd, char *dst, size_t cap)
{
	dst[0] = '\0';
	FILE *p = popen(cmd, "r");
	if (!p) return false;
	char buf[256];
	bool got = (fgets(buf, sizeof buf, p) != NULL);
	int rc = pclose(p);
	if (!got || rc != 0) return false;
	size_t L = strlen(buf);
	while (L > 0 && (buf[L-1] == '\n' || buf[L-1] == '\r'))
		buf[--L] = '\0';
	if (L >= cap) L = cap - 1;
	memcpy(dst, buf, L);
	dst[L] = '\0';
	return true;
}

/* Extract the version-string token from a line of the form
 * "<prefix>: <version> [rest]" or "<prefix> <version> [rest]". The
 * version token is everything from the first non-space after
 * `prefix` up to the next whitespace. Empty result when prefix not
 * found. */
static void extract_version_after_prefix(const char *line,
					 const char *prefix,
					 char *dst, size_t cap)
{
	dst[0] = '\0';
	const char *p = strstr(line, prefix);
	if (!p) return;
	p += strlen(prefix);
	while (*p == ' ' || *p == ':' || *p == '\t') p++;
	size_t i = 0;
	while (*p && *p != ' ' && *p != '\t' && i + 1 < cap)
		dst[i++] = *p++;
	dst[i] = '\0';
}

static void populate_userspace_versions(struct skeletonkey_host *h)
{
	h->sudo_version[0]   = '\0';
	h->polkit_version[0] = '\0';

	char line[256];
	if (capture_first_line("sudo -V 2>/dev/null", line, sizeof line))
		extract_version_after_prefix(line, "Sudo version",
			h->sudo_version, sizeof h->sudo_version);

	if (capture_first_line("pkexec --version 2>/dev/null", line, sizeof line))
		extract_version_after_prefix(line, "pkexec version",
			h->polkit_version, sizeof h->polkit_version);
}

/* ── public entrypoints ───────────────────────────────────────────── */

const struct skeletonkey_host *skeletonkey_host_get(void)
{
	if (g_host_ready) return &g_host;

	memset(&g_host, 0, sizeof g_host);
	populate_kernel(&g_host);
	populate_distro(&g_host);
	populate_user(&g_host);
	populate_platform_family(&g_host);
	populate_caps(&g_host);
	populate_services(&g_host);
	populate_userspace_versions(&g_host);
	g_host.probe_source = "skeletonkey core/host.c";
	g_host_ready = true;
	return &g_host;
}

bool skeletonkey_host_kernel_at_least(const struct skeletonkey_host *h,
				      int major, int minor, int patch)
{
	if (!h || h->kernel.major == 0)
		return false;
	if (h->kernel.major != major) return h->kernel.major > major;
	if (h->kernel.minor != minor) return h->kernel.minor > minor;
	return h->kernel.patch >= patch;
}

bool skeletonkey_host_kernel_in_range(const struct skeletonkey_host *h,
				      int lo_M, int lo_m, int lo_p,
				      int hi_M, int hi_m, int hi_p)
{
	return  skeletonkey_host_kernel_at_least(h, lo_M, lo_m, lo_p) &&
	       !skeletonkey_host_kernel_at_least(h, hi_M, hi_m, hi_p);
}

void skeletonkey_host_print_banner(const struct skeletonkey_host *h, bool json)
{
	if (json || h == NULL) return;
	fprintf(stderr, "[*] host: %s%s%s  kernel=%s  arch=%s  distro=%s/%s\n",
		h->nodename[0] ? h->nodename : "?",
		h->is_root ? "  (ROOT)" : "",
		h->is_ssh_session ? "  (SSH)" : "",
		h->kernel.release ? h->kernel.release : "?",
		h->arch[0] ? h->arch : "?",
		h->distro_id[0] ? h->distro_id : "?",
		h->distro_version_id[0] ? h->distro_version_id : "?");
	fprintf(stderr, "[*] gates: userns=%s  aa_restrict=%s  bpf_disabled=%s  "
			"kpti=%s  lockdown=%s  selinux=%s  yama_ptrace=%s\n",
		h->unprivileged_userns_allowed ? "yes" : "no",
		h->apparmor_restrict_userns    ? "on"  : "off",
		h->unprivileged_bpf_disabled   ? "yes" : "no",
		h->kpti_enabled                ? "on"  : "off",
		h->kernel_lockdown_active      ? "on"  : "off",
		h->selinux_enforcing           ? "on"  : "off",
		h->yama_ptrace_restricted      ? "yes" : "no");
	if (h->sudo_version[0] || h->polkit_version[0])
		fprintf(stderr, "[*] userspace: sudo=%s  polkit=%s\n",
			h->sudo_version[0]   ? h->sudo_version   : "-",
			h->polkit_version[0] ? h->polkit_version : "-");
}
