/*
 * SKELETONKEY — host fingerprint
 *
 * Populated once at startup, before any module's detect() runs. Every
 * module receives a stable pointer via skeletonkey_ctx.host and can
 * consult it without re-parsing /proc, /etc/os-release, uname(2), or
 * forking another userns probe.
 *
 * The struct is deliberately POD (no heap pointers, fixed-size
 * arrays) so lifetime reasoning is trivial. A single static instance
 * lives in core/host.c; skeletonkey_host_get() returns the same
 * pointer on every call. The first call probes; subsequent calls
 * are O(1) lookups.
 *
 * Fields that don't apply on a given platform (e.g. AppArmor sysctls
 * on a non-Linux dev build, KPTI on aarch64) stay at their false /
 * "?" defaults. Probing is best-effort: a missing sysctl never fails
 * the call, just leaves the corresponding bool false.
 */

#ifndef SKELETONKEY_HOST_H
#define SKELETONKEY_HOST_H

#include "kernel_range.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct skeletonkey_host {
	/* ── identity ─────────────────────────────────────────────── */

	struct kernel_version kernel;     /* uname.release parsed */
	char arch[32];                    /* uname.machine ("x86_64", "aarch64") */
	char nodename[64];                /* uname.nodename (for log lines) */

	char distro_id[64];               /* /etc/os-release ID ("ubuntu", "debian", "fedora", "?") */
	char distro_version_id[64];       /* /etc/os-release VERSION_ID ("24.04", "13", "?") */
	char distro_pretty[128];          /* /etc/os-release PRETTY_NAME for log lines */

	/* ── process state ─────────────────────────────────────────── */

	uid_t euid;                       /* geteuid() */
	uid_t real_uid;                   /* outer uid (defeats userns illusion via /proc/self/uid_map) */
	gid_t egid;                       /* getegid() */
	char username[64];                /* getpwuid(euid)->pw_name or "" */
	bool is_root;                     /* euid == 0 */
	bool is_ssh_session;              /* SSH_CONNECTION env var set */

	/* ── platform family ───────────────────────────────────────── */

	bool is_linux;                    /* compiled / running on Linux */
	bool is_debian_family;            /* /etc/debian_version exists */
	bool is_rpm_family;               /* redhat / fedora / rocky / almalinux release file */
	bool is_arch_family;              /* /etc/arch-release */
	bool is_suse_family;              /* /etc/SuSE-release or /etc/SUSE-brand */

	/* ── capability / gate flags (Linux) ──────────────────────── */

	bool unprivileged_userns_allowed; /* fork+unshare(CLONE_NEWUSER) succeeded */
	bool apparmor_restrict_userns;    /* sysctl: 1 = AA blocks unpriv userns */
	bool unprivileged_bpf_disabled;   /* /proc/sys/kernel/unprivileged_bpf_disabled = 1 */
	bool kpti_enabled;                /* /sys/.../meltdown contains "Mitigation: PTI" */
	bool kernel_lockdown_active;      /* /sys/kernel/security/lockdown != [none] */
	bool selinux_enforcing;           /* /sys/fs/selinux/enforce = 1 */
	bool yama_ptrace_restricted;      /* /proc/sys/kernel/yama/ptrace_scope > 0 */

	/* ── system services ──────────────────────────────────────── */

	bool has_systemd;                 /* /run/systemd/system exists */
	bool has_dbus_system;             /* /run/dbus/system_bus_socket exists */

	/* ── userspace component versions ─────────────────────────
	 * Parsed once at startup via popen() of the relevant binary's
	 * --version output. Empty string ("") means "tool not installed
	 * or version parse failed" — modules should treat that as
	 * PRECOND_FAIL (no exploit target). The exact format mirrors
	 * what the tool prints (`Sudo version 1.9.5p2`, `pkexec version
	 * 0.105`, …); modules do their own range parsing. */
	char sudo_version[64];            /* "1.9.13p1" or "" */
	char polkit_version[64];          /* "0.105" or "126" or "" */

	/* Informational: the SKELETONKEY component that populated this
	 * snapshot (for log/JSON output). */
	const char *probe_source;
};

/* Get the host fingerprint. Returns a stable, non-null pointer that
 * lives for the process lifetime. Probes happen lazily on the first
 * call (~50ms; dominated by the userns fork-probe), are cached, and
 * subsequent calls are free.
 *
 * Probing is best-effort: missing files / unsupported sysctls leave
 * the corresponding bool false. The function does not fail. */
const struct skeletonkey_host *skeletonkey_host_get(void);

/* Print a two-line "host fingerprint" banner to stderr suitable for
 * --auto / --scan verbose output. Silent on JSON mode. */
void skeletonkey_host_print_banner(const struct skeletonkey_host *h, bool json);

/* True iff h->kernel >= the (major, minor, patch) provided. Returns
 * false if h is NULL or its kernel version was never populated (major
 * == 0). Replaces the manual `v->major < X` / `(v->major == X &&
 * v->minor < Y)` patterns scattered across detect()s — cleaner reads
 * and one place to get the comparison right.
 *
 * Examples:
 *   if (!host_kernel_at_least(h, 7, 0, 0))    // kernel predates 7.0
 *       return SKELETONKEY_OK;
 *   if ( host_kernel_at_least(h, 6, 8, 0))    // kernel post-fix
 *       return SKELETONKEY_OK;
 */
bool skeletonkey_host_kernel_at_least(const struct skeletonkey_host *h,
                                      int major, int minor, int patch);

/* True iff h->kernel is in [lo, hi). Useful for "vulnerable range"
 * gates where the simple `kernel_range_is_patched` backport model
 * doesn't apply — e.g. a feature added in X.Y and removed/superseded
 * in W.Z, or a per-module "vulnerable only on these specific kernel
 * lines" check.
 *
 * Equivalent to:
 *   host_kernel_at_least(h, lo...) && !host_kernel_at_least(h, hi...)
 *
 * For "predates the bug" alone use host_kernel_at_least directly; the
 * `in_range` form is for the bounded interval case.
 *
 * Example:
 *   if (host_kernel_in_range(h, 5, 8, 0,  5, 17, 0))
 *       // kernel 5.8 ≤ K < 5.17 — vulnerable window per the mainline
 *       // introduction/fix dates (ignoring stable backports)
 */
bool skeletonkey_host_kernel_in_range(const struct skeletonkey_host *h,
                                      int lo_major, int lo_minor, int lo_patch,
                                      int hi_major, int hi_minor, int hi_patch);

#endif /* SKELETONKEY_HOST_H */
