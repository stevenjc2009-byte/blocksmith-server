/* bsgate_test — end-to-end test against a real bsgate process.
 *
 * This does not test bsgate's functions in isolation; it launches the actual
 * daemon, speaks the real protocol at it over loopback UDP as a 3DS would,
 * and stands in for the game logic on the Unix socket. Every security claim
 * in bsgate.c that can be tested from outside is tested here, and each
 * negative case is written so it goes red if the corresponding check is
 * removed.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <hydrogen.h>

#include "../proto/bs_proto.h"
#include "allowlist.h"
#include "proxyproto.h"
#include "ratelimit.h"
#include "replay.h"

enum { BS_GAME_JOIN = 1, BS_GAME_DATA = 2, BS_GAME_LEAVE = 3, BS_GAME_KICK = 4 };

static int   g_checks = 0;
static int   g_fails  = 0;
/* Sized so that g_dir plus the longest filename below still fits inside
 * sun_path (108). The same truncation trap the daemon guards against. */
static char  g_dir[64];
static pid_t g_daemon = -1;

static void check(bool cond, const char *what)
{
    g_checks++;
    if (!cond) {
        g_fails++;
        printf("  FAIL  %s\n", what);
    } else {
        printf("  ok    %s\n", what);
    }
}

static void die(const char *what)
{
    fprintf(stderr, "test: %s: %s\n", what, strerror(errno));
    if (g_daemon > 0) kill(g_daemon, SIGKILL);
    exit(1);
}

static void msleep(unsigned ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* --------------------------------------------------------------- plumbing */

static int  g_udp = -1;          /* our client socket                       */
static int  g_game = -1;         /* our stand-in for the game logic         */
static struct sockaddr_in g_srv; /* the daemon's UDP address                */
static char g_gate_sock[108];

static uint8_t g_server_pk[BS_KX_PUBLICKEYBYTES];
static uint8_t g_psk[hydro_kx_PSKBYTES];

/* Receives one UDP packet, or returns -1 if nothing arrives in `ms`. */
static ssize_t udp_recv(uint8_t *buf, size_t cap, unsigned ms)
{
    struct pollfd p = { .fd = g_udp, .events = POLLIN };
    if (poll(&p, 1, (int)ms) <= 0) return -1;
    return recv(g_udp, buf, cap, 0);
}

static ssize_t game_recv(uint8_t *buf, size_t cap, unsigned ms)
{
    struct pollfd p = { .fd = g_game, .events = POLLIN };
    if (poll(&p, 1, (int)ms) <= 0) return -1;
    return recv(g_game, buf, cap, 0);
}

/* ---- standing in for the playit relay ----------------------------------
 * When g_ppv2 is on, every outbound packet is wrapped in a PROXY protocol v2
 * header claiming to come from g_ppv2_ip:g_ppv2_port, exactly as the agent
 * would. The rest of the client code is unchanged, so the handshake is
 * genuinely being driven through the relay path rather than around it. */
static bool     g_ppv2      = false;
static uint32_t g_ppv2_ip   = 0;   /* network byte order */
static uint16_t g_ppv2_port = 0;   /* network byte order */

static const uint8_t PPV2_SIG[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

/* Builds a v2 header in `out`. `addr_len` is written into the length field so
 * the malformed cases can lie about it independently of what is really there. */
static size_t ppv2_header(uint8_t *out, uint8_t ver_cmd, uint8_t fam,
                          uint16_t addr_len, uint32_t ip, uint16_t port)
{
    memcpy(out, PPV2_SIG, sizeof PPV2_SIG);
    out[12] = ver_cmd;
    out[13] = fam;
    out[14] = (uint8_t)(addr_len >> 8);
    out[15] = (uint8_t)(addr_len & 0xff);
    memcpy(out + 16, &ip,   4);      /* src addr */
    memset(out + 20, 0, 4);          /* dst addr, unused by the gateway */
    memcpy(out + 24, &port, 2);      /* src port */
    memset(out + 26, 0, 2);          /* dst port */
    return 28;
}

static void udp_send_raw(const uint8_t *buf, size_t len)
{
    if (sendto(g_udp, buf, len, 0, (struct sockaddr *)&g_srv, sizeof g_srv) < 0) {
        die("sendto");
    }
}

/* Sends `buf` wrapped in a header claiming an arbitrary client address,
 * regardless of g_ppv2. Used by the cases that need to change address
 * mid-handshake. */
static void udp_send_as(uint32_t ip, uint16_t port, const uint8_t *buf, size_t len)
{
    uint8_t out[2048];
    size_t off = ppv2_header(out, 0x21, 0x12, 12, ip, port);
    memcpy(out + off, buf, len);
    udp_send_raw(out, off + len);
}

static void udp_send(const uint8_t *buf, size_t len)
{
    if (g_ppv2) { udp_send_as(g_ppv2_ip, g_ppv2_port, buf, len); return; }

    if (sendto(g_udp, buf, len, 0, (struct sockaddr *)&g_srv, sizeof g_srv) < 0) {
        die("sendto");
    }
}

static void game_send(const uint8_t *buf, size_t len)
{
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", g_gate_sock);
    if (sendto(g_game, buf, len, 0, (struct sockaddr *)&un, sizeof un) < 0) {
        die("game sendto");
    }
}

/* Drains anything left over so one case cannot see the previous case's
 * packets and pass for the wrong reason. */
static void drain(void)
{
    uint8_t b[2048];
    while (udp_recv(b, sizeof b, 30) > 0) { }
    while (game_recv(b, sizeof b, 30) > 0) { }
}

/* ------------------------------------------------------------- handshake */

struct client {
    hydro_kx_keypair kp;
    hydro_kx_session_keypair keys;
    uint32_t sid;
    uint64_t tx_msg_id;
    bool     established;
};

/* Runs the full client side. Returns true if the gateway completed the
 * handshake. `psk` and `server_pk` are parameters so the negative cases can
 * feed deliberately wrong ones. */
static bool client_connect(struct client *c, const uint8_t *psk, bool corrupt_cookie)
{
    hydro_kx_state st;
    uint8_t packet1[hydro_kx_XX_PACKET1BYTES];

    /* Step 1: the ephemeral must exist before HELLO, because HELLO's nonce is
     * packet1's first 32 bytes. See the ordering note in bs_proto.h. */
    if (hydro_kx_xx_1(&st, packet1, psk) != 0) return false;

    uint8_t hello[BS_HELLO_BYTES];
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    memcpy(hello + BS_HDR_BYTES, packet1, BS_NONCE_BYTES);
    udp_send(hello, sizeof hello);

    uint8_t rx[2048];
    ssize_t n = udp_recv(rx, sizeof rx, 1000);
    if (n != (ssize_t)BS_COOKIE_PKT_BYTES || rx[0] != BS_PKT_COOKIE) return false;

    uint8_t cookie[BS_COOKIE_BYTES];
    memcpy(cookie, rx + BS_HDR_BYTES, BS_COOKIE_BYTES);
    if (corrupt_cookie) cookie[0] ^= 0x01;

    uint8_t kx1[BS_KX1_BYTES];
    bs_put_hdr(kx1, BS_PKT_KX1);
    memcpy(kx1 + BS_HDR_BYTES, cookie, BS_COOKIE_BYTES);
    memcpy(kx1 + BS_HDR_BYTES + BS_COOKIE_BYTES, packet1, sizeof packet1);
    udp_send(kx1, sizeof kx1);

    n = udp_recv(rx, sizeof rx, 1000);
    if (n != (ssize_t)BS_KX2_BYTES || rx[0] != BS_PKT_KX2) return false;

    c->sid = bs_get_u32(rx + BS_HDR_BYTES);

    uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
    uint8_t peer_pk[hydro_kx_PUBLICKEYBYTES];
    if (hydro_kx_xx_3(&st, &c->keys, packet3, peer_pk,
                      rx + BS_HDR_BYTES + BS_SID_BYTES, psk, &c->kp) != 0) {
        return false;
    }

    /* The client authenticates the server too: XX is mutual. A relay that
     * tried to impersonate the gateway would fail right here. */
    if (!hydro_equal(peer_pk, g_server_pk, sizeof peer_pk)) return false;

    uint8_t kx3[BS_KX3_BYTES];
    bs_put_hdr(kx3, BS_PKT_KX3);
    bs_put_u32(kx3 + BS_HDR_BYTES, c->sid);
    memcpy(kx3 + BS_HDR_BYTES + BS_SID_BYTES, packet3, sizeof packet3);
    udp_send(kx3, sizeof kx3);

    c->tx_msg_id = 0;
    c->established = true;
    return true;
}

/* Builds a DATA packet; returned in `out`, length in `out_len`. Kept separate
 * from sending so the replay case can transmit the identical bytes twice. */
static void client_build_data(struct client *c, const char *text,
                              uint8_t *out, size_t *out_len)
{
    size_t len = strlen(text);
    bs_put_hdr(out, BS_PKT_DATA);
    bs_put_u32(out + BS_HDR_BYTES, c->sid);
    uint64_t msg_id = c->tx_msg_id++;
    bs_put_u64(out + BS_HDR_BYTES + BS_SID_BYTES, msg_id);
    hydro_secretbox_encrypt(out + BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES,
                            text, len, msg_id, BS_CTX_C2S, c->keys.tx);
    *out_len = BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES
             + hydro_secretbox_HEADERBYTES + len;
}

/* ------------------------------------------------------------ unit checks */

static void test_replay_window(void)
{
    puts("replay window");
    struct bs_replay r;
    bs_replay_init(&r);

    check(bs_replay_check(&r, 0),  "first packet accepted");
    check(!bs_replay_check(&r, 0), "immediate duplicate rejected");
    check(bs_replay_check(&r, 1),  "next in sequence accepted");
    check(bs_replay_check(&r, 5),  "forward jump accepted");
    check(bs_replay_check(&r, 3),  "out-of-order fill accepted once");
    check(!bs_replay_check(&r, 3), "same out-of-order id rejected");
    check(!bs_replay_check(&r, 5), "leading-edge duplicate rejected");

    /* Slide far past the window; ids left behind must not read as fresh, and
     * ids the window slid over must not read as already-seen. */
    check(bs_replay_check(&r, 100000), "far jump accepted");
    check(!bs_replay_check(&r, 3),     "id below window rejected");
    check(bs_replay_check(&r, 99999),  "id inside window after jump accepted");
    check(!bs_replay_check(&r, 99999), "...and only once");

    /* The wrap bug this guards: after sliding, a stale bit at the same
     * modular index must have been cleared. */
    struct bs_replay r2;
    bs_replay_init(&r2);
    check(bs_replay_check(&r2, 10), "seed at 10");
    check(bs_replay_check(&r2, 10 + BS_REPLAY_WINDOW), "advance exactly one window");
    check(bs_replay_check(&r2, 10 + BS_REPLAY_WINDOW - 1),
          "index that aliases the seed is not falsely seen");
}

static void test_ratelimit(void)
{
    puts("rate limiter");
    struct bs_ratelimit rl;
    bs_rl_init(&rl, 0);

    uint32_t a = htonl(0x0a000001), b = htonl(0x0a000002);

    unsigned allowed = 0;
    for (unsigned i = 0; i < BS_RL_BURST + 4; i++) {
        if (bs_rl_allow(&rl, a, 0)) allowed++;
    }
    check(allowed == BS_RL_BURST, "burst is capped at BS_RL_BURST");
    check(!bs_rl_allow(&rl, a, 0), "exhausted bucket denies");
    check(bs_rl_allow(&rl, b, 0),  "a different address is unaffected");
    check(bs_rl_allow(&rl, a, BS_RL_REFILL_MS + 1), "bucket refills over time");

    /* The global ceiling must hold even when every request is from a fresh
     * address, which is what a botnet looks like. */
    struct bs_ratelimit gl;
    bs_rl_init(&gl, 0);
    unsigned got = 0;
    for (unsigned i = 0; i < BS_RL_GLOBAL_BURST + 50; i++) {
        if (bs_rl_allow(&gl, htonl(0x0b000000u + i), 0)) got++;
    }
    check(got == BS_RL_GLOBAL_BURST, "global ceiling holds against many sources");
}

static void test_allowlist_parsing(void)
{
    puts("allowlist parsing");
    char path[192], err[256];
    snprintf(path, sizeof path, "%s/al_test", g_dir);

    uint8_t pk[BS_KX_PUBLICKEYBYTES];
    memset(pk, 0xAB, sizeof pk);
    char hex[2 * BS_KX_PUBLICKEYBYTES + 1];
    hydro_bin2hex(hex, sizeof hex, pk, sizeof pk);

    FILE *f = fopen(path, "w");
    fprintf(f, "# a comment\n\n  %s   steve\n", hex);
    fclose(f);

    struct bs_allowlist al;
    check(bs_allowlist_load(&al, path, err, sizeof err), "valid file loads");
    check(al.count == 1, "comments and blanks ignored");
    check(bs_allowlist_find(&al, pk) != NULL, "key found");
    check(al.count == 1 && !strcmp(al.entry[0].label, "steve"), "label parsed");

    uint8_t other[BS_KX_PUBLICKEYBYTES];
    memset(other, 0xCD, sizeof other);
    check(bs_allowlist_find(&al, other) == NULL, "unknown key not found");

    /* A duplicate must be refused outright: silently keeping one copy makes a
     * revocation look like it worked while the peer still gets in. */
    f = fopen(path, "w");
    fprintf(f, "%s alice\n%s bob\n", hex, hex);
    fclose(f);
    struct bs_allowlist dup = al;
    check(!bs_allowlist_load(&dup, path, err, sizeof err), "duplicate key refused");

    f = fopen(path, "w");
    fprintf(f, "%s alice\nnot-hex-at-all bob\n", hex);
    fclose(f);
    struct bs_allowlist bad = al;
    check(!bs_allowlist_load(&bad, path, err, sizeof err), "malformed line refused");
    check(bad.count == 1 && bs_allowlist_find(&bad, pk) != NULL,
          "refused load leaves the previous list untouched");
}

static void test_ppv2_parse(void)
{
    puts("proxy protocol v2 parser");

    const uint32_t ip   = htonl(0xC0A80105u);   /* 192.168.1.5 */
    const uint16_t port = htons(54321);

    uint8_t buf[128];
    struct sockaddr_in got;

    /* The shape the playit agent actually sends: v2, PROXY, AF_INET/DGRAM. */
    size_t n = ppv2_header(buf, 0x21, 0x12, 12, ip, port);
    memcpy(buf + n, "PAYLOAD", 7);
    int off = bs_ppv2_parse(buf, n + 7, &got);
    check(off == 28, "well-formed header returns the payload offset");
    check(got.sin_addr.s_addr == ip,  "source address recovered");
    check(got.sin_port == port,       "source port recovered");
    check(got.sin_family == AF_INET,  "family set to AF_INET");

    /* TLVs live inside the declared length; the payload starts after them. */
    n = ppv2_header(buf, 0x21, 0x12, 20, ip, port);
    memset(buf + n, 0, 8);                     /* 8 bytes of TLV padding */
    check(bs_ppv2_parse(buf, n + 8 + 4, &got) == 36, "TLVs are skipped");

    /* STREAM is accepted too — the gateway does not care which transport the
     * relay used to describe the flow, only who the client was. */
    n = ppv2_header(buf, 0x11 /* wrong slot on purpose below */, 0x11, 12, ip, port);
    buf[12] = 0x21;
    check(bs_ppv2_parse(buf, n, &got) == 28, "AF_INET/STREAM accepted");

    puts("proxy protocol v2 rejections");

    n = ppv2_header(buf, 0x21, 0x12, 12, ip, port);
    buf[3] ^= 0xFF;
    check(bs_ppv2_parse(buf, n, &got) < 0, "corrupt signature rejected");

    n = ppv2_header(buf, 0x11, 0x12, 12, ip, port);   /* version 1 */
    check(bs_ppv2_parse(buf, n, &got) < 0, "version 1 rejected");

    n = ppv2_header(buf, 0x20, 0x12, 12, ip, port);   /* LOCAL command */
    check(bs_ppv2_parse(buf, n, &got) < 0, "LOCAL command rejected");

    n = ppv2_header(buf, 0x21, 0x21, 12, ip, port);   /* AF_INET6 */
    check(bs_ppv2_parse(buf, n, &got) < 0, "IPv6 rejected");

    n = ppv2_header(buf, 0x21, 0x12, 11, ip, port);   /* too short to hold v4 */
    check(bs_ppv2_parse(buf, n, &got) < 0, "undersized address block rejected");

    n = ppv2_header(buf, 0x21, 0x12, 200, ip, port);  /* longer than the datagram */
    check(bs_ppv2_parse(buf, n, &got) < 0, "length past the end rejected");

    n = ppv2_header(buf, 0x21, 0x12, 12, ip, port);
    check(bs_ppv2_parse(buf, 15, &got) < 0, "truncated header rejected");
    check(bs_ppv2_parse(buf, 0, &got) < 0,  "empty input rejected");

    /* A packet that merely starts with something else must not be mistaken
     * for a header — this is what protects the feature-off path. */
    memset(buf, 0x06, sizeof buf);
    check(bs_ppv2_parse(buf, sizeof buf, &got) < 0, "ordinary payload rejected");
}

/* ------------------------------------------------------------ daemon setup */

static void write_allowlist(const uint8_t *pk, const char *label)
{
    char path[192];
    snprintf(path, sizeof path, "%s/allowlist", g_dir);

    FILE *f = fopen(path, "w");
    if (f == NULL) die("write allowlist");

    if (pk != NULL && label != NULL) {
        char hex[2 * BS_KX_PUBLICKEYBYTES + 1];
        hydro_bin2hex(hex, sizeof hex, pk, BS_KX_PUBLICKEYBYTES);
        fprintf(f, "%s %s\n", hex, label);
    } else {
        fprintf(f, "# intentionally empty\n");
    }
    fclose(f);
}

static void read_identity(void)
{
    char cmd[320];
    snprintf(cmd, sizeof cmd, "./bsgate --state-dir %s --print-identity", g_dir);
    FILE *p = popen(cmd, "r");
    if (p == NULL) die("popen print-identity");

    char line[256];
    bool got_pk = false, got_psk = false;
    while (fgets(line, sizeof line, p)) {
        char hex[256];
        if (sscanf(line, "server_public_key %255s", hex) == 1) {
            hydro_hex2bin(g_server_pk, sizeof g_server_pk, hex, strlen(hex), NULL, NULL);
            got_pk = true;
        } else if (sscanf(line, "network_psk %255s", hex) == 1) {
            hydro_hex2bin(g_psk, sizeof g_psk, hex, strlen(hex), NULL, NULL);
            got_psk = true;
        }
    }
    pclose(p);
    if (!got_pk || !got_psk) { fprintf(stderr, "test: --print-identity failed\n"); exit(1); }
}

/* `proxy_proto` and `trusted` mirror the daemon's own flags so the relay path
 * can be exercised against a real process rather than a mock. `trusted` may be
 * NULL to leave the default in place. */
static uint16_t start_daemon_ex(bool proxy_proto, const char *trusted)
{
    /* Ask the kernel for a free port, then release it. A fixed port makes the
     * test fail confusingly when something else on the box holds it. */
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(probe, (struct sockaddr *)&a, sizeof a) != 0) die("probe bind");
    socklen_t al = sizeof a;
    getsockname(probe, (struct sockaddr *)&a, &al);
    uint16_t port = ntohs(a.sin_port);
    close(probe);

    char listen_arg[64], game_arg[192];
    snprintf(listen_arg, sizeof listen_arg, "127.0.0.1:%u", port);
    snprintf(game_arg, sizeof game_arg, "%s/game.sock", g_dir);
    snprintf(g_gate_sock, sizeof g_gate_sock, "%s/gate.sock", g_dir);

    /* Built as an argv array rather than execl so the optional flags can be
     * appended without duplicating the call. Elements are plain char* and the
     * caller's string is copied, so nothing here casts away a qualifier. */
    char trusted_buf[64];
    char *argv[16];
    int n = 0;
    argv[n++] = "bsgate";
    argv[n++] = "--listen";      argv[n++] = listen_arg;
    argv[n++] = "--state-dir";   argv[n++] = g_dir;
    argv[n++] = "--game-socket"; argv[n++] = game_arg;
    if (proxy_proto) argv[n++] = "--proxy-protocol";
    if (trusted != NULL) {
        snprintf(trusted_buf, sizeof trusted_buf, "%s", trusted);
        argv[n++] = "--trusted-proxy";
        argv[n++] = trusted_buf;
    }
    argv[n] = NULL;

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        execv("./bsgate", argv);
        _exit(127);
    }
    g_daemon = pid;

    memset(&g_srv, 0, sizeof g_srv);
    g_srv.sin_family = AF_INET;
    g_srv.sin_port   = htons(port);
    g_srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    return port;
}

static uint16_t start_daemon(void)
{
    return start_daemon_ex(false, NULL);
}

/* Stops the running daemon and waits for it, so the next one can bind. */
static void stop_daemon(void)
{
    if (g_daemon <= 0) return;
    kill(g_daemon, SIGTERM);
    waitpid(g_daemon, NULL, 0);
    g_daemon = -1;
}

static void open_sockets(void)
{
    g_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp < 0) die("client socket");

    g_game = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (g_game < 0) die("game socket");

    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s/game.sock", g_dir);
    unlink(un.sun_path);
    if (bind(g_game, (struct sockaddr *)&un, sizeof un) != 0) die("bind game.sock");
}

/* Blocks until the daemon answers a HELLO, so no test races the daemon's
 * startup and fails for the wrong reason. */
static bool wait_ready(unsigned timeout_ms)
{
    for (unsigned waited = 0; waited < timeout_ms; waited += 50) {
        uint8_t hello[BS_HELLO_BYTES];
        memset(hello, 0, sizeof hello);
        bs_put_hdr(hello, BS_PKT_HELLO);
        hydro_random_buf(hello + BS_HDR_BYTES, BS_NONCE_BYTES);
        udp_send(hello, sizeof hello);

        uint8_t rx[256];
        if (udp_recv(rx, sizeof rx, 50) > 0) return true;
    }
    return false;
}

/* ---------------------------------------------------------- e2e scenarios */

static struct client g_alice;   /* on the allowlist */

static void test_happy_path(void)
{
    puts("end-to-end: allowlisted peer");
    drain();

    check(client_connect(&g_alice, g_psk, false), "handshake completes");

    uint8_t m[2048];
    ssize_t n = game_recv(m, sizeof m, 1000);
    check(n > 0 && m[0] == BS_GAME_JOIN, "game logic sees JOIN");
    check(n > 0 && bs_get_u32(m + 1) == g_alice.sid, "JOIN carries the session id");
    check(n > 0 && hydro_equal(m + 5, g_alice.kp.pk, BS_KX_PUBLICKEYBYTES),
          "JOIN carries the peer public key");
    check(n > 0 && !strcmp((char *)m + 5 + BS_KX_PUBLICKEYBYTES, "alice"),
          "JOIN carries the allowlist label");

    uint8_t pkt[BS_MAX_PACKET];
    size_t len;
    client_build_data(&g_alice, "dig 4 7 12", pkt, &len);
    udp_send(pkt, len);

    n = game_recv(m, sizeof m, 1000);
    check(n == 5 + 10 && m[0] == BS_GAME_DATA, "game logic receives DATA");
    check(n > 5 && !memcmp(m + 5, "dig 4 7 12", 10), "payload arrives intact");

    /* And back the other way. */
    uint8_t reply[5 + 32];
    reply[0] = BS_GAME_DATA;
    bs_put_u32(reply + 1, g_alice.sid);
    memcpy(reply + 5, "world ok", 8);
    game_send(reply, 5 + 8);

    uint8_t rx[2048];
    n = udp_recv(rx, sizeof rx, 1000);
    check(n > 0 && rx[0] == BS_PKT_DATA, "client receives a DATA packet");

    if (n > 0) {
        uint64_t mid = bs_get_u64(rx + BS_HDR_BYTES + BS_SID_BYTES);
        uint8_t plain[1024];
        size_t ctlen = (size_t)n - (BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES);
        int ok = hydro_secretbox_decrypt(plain,
                    rx + BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES,
                    ctlen, mid, BS_CTX_S2C, g_alice.keys.rx);
        check(ok == 0, "server->client packet authenticates");
        check(ok == 0 && !memcmp(plain, "world ok", 8), "server->client payload intact");
    } else {
        check(false, "server->client packet authenticates");
        check(false, "server->client payload intact");
    }
}

/* The client's only way to measure a round trip is to send an empty DATA and
 * time the answer, and it will not send the next keepalive until the previous
 * one comes back. Before the gate answered these, a lone player was silently
 * evicted after BS_SESSION_IDLE_MS with the ping still reading -1 — so this
 * checks both halves: something comes back, and it is empty rather than being
 * pushed at the game logic. */
static void test_keepalive_echo(void)
{
    puts("end-to-end: empty DATA is answered by the gate itself");
    drain();

    uint8_t pkt[BS_MAX_PACKET];
    size_t len;
    client_build_data(&g_alice, "", pkt, &len);
    udp_send(pkt, len);

    uint8_t rx[2048];
    ssize_t n = udp_recv(rx, sizeof rx, 1000);
    check(n > 0 && rx[0] == BS_PKT_DATA, "empty DATA gets a DATA back");

    if (n > 0) {
        uint64_t mid = bs_get_u64(rx + BS_HDR_BYTES + BS_SID_BYTES);
        size_t ctlen = (size_t)n - (BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES);
        uint8_t plain[1024];
        int ok = hydro_secretbox_decrypt(plain,
                    rx + BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES,
                    ctlen, mid, BS_CTX_S2C, g_alice.keys.rx);
        check(ok == 0, "the answer authenticates");
        check(ctlen == hydro_secretbox_HEADERBYTES, "the answer carries no payload");
    } else {
        check(false, "the answer authenticates");
        check(false, "the answer carries no payload");
    }

    /* An empty probe is gate business. Handing it to the game logic would make
     * every idle console look like traffic it has to parse. */
    uint8_t m[2048];
    check(game_recv(m, sizeof m, 200) < 0, "game logic is not bothered with it");
}

/* SIGUSR1 makes the daemon drop a snapshot for bsgate-status to read. The file
 * is removed first, so a stale snapshot left by an earlier run cannot make
 * this pass — the same trap that has bitten this project before. */
static void test_status_snapshot(void)
{
    puts("end-to-end: SIGUSR1 status snapshot");

    char path[192];
    snprintf(path, sizeof path, "%s/status.txt", g_dir);
    unlink(path);
    check(access(path, F_OK) != 0, "no stale snapshot before the signal");

    kill(g_daemon, SIGUSR1);

    FILE *f = NULL;
    for (int i = 0; i < 40 && f == NULL; i++) {   /* up to 2 s */
        f = fopen(path, "r");
        if (f == NULL) msleep(50);
    }
    check(f != NULL, "snapshot appears after SIGUSR1");
    if (f == NULL) return;

    struct stat st;
    check(stat(path, &st) == 0 && (st.st_mode & 07777) == 0640,
          "snapshot is mode 0640");

    char line[512];
    bool header = false, sessions_one = false, alice = false, joins = false;
    while (fgets(line, sizeof line, f)) {
        unsigned u;
        char label[64];
        if (!strncmp(line, "process bsgate", 14))            header = true;
        else if (sscanf(line, "sessions %u", &u) == 1)       sessions_one = (u == 1);
        else if (sscanf(line, "joins_total %u", &u) == 1)    joins = (u >= 1);
        else if (sscanf(line, "session %*x %63s", label) == 1) alice = !strcmp(label, "alice");
    }
    fclose(f);

    check(header,       "snapshot identifies the process");
    check(joins,        "snapshot counts the join");
    check(sessions_one, "snapshot reports one live session");
    check(alice,        "snapshot names the connected peer");
}

static void test_replay_rejected(void)
{
    puts("end-to-end: replay");
    drain();

    uint8_t pkt[BS_MAX_PACKET];
    size_t len;
    client_build_data(&g_alice, "place stone", pkt, &len);

    udp_send(pkt, len);
    uint8_t m[2048];
    check(game_recv(m, sizeof m, 1000) > 0, "original delivered");

    /* Byte-identical retransmission: valid AEAD tag, already-used message id. */
    udp_send(pkt, len);
    check(game_recv(m, sizeof m, 400) < 0, "byte-identical replay is dropped");
}

static void test_tampered_payload(void)
{
    puts("end-to-end: tampering");
    drain();

    uint8_t pkt[BS_MAX_PACKET];
    size_t len;
    client_build_data(&g_alice, "give diamond", pkt, &len);
    pkt[len - 1] ^= 0x40;            /* flip a bit in the ciphertext */
    udp_send(pkt, len);

    uint8_t m[2048];
    check(game_recv(m, sizeof m, 400) < 0, "tampered packet fails AEAD and is dropped");
}

static void test_unknown_key_rejected(void)
{
    puts("end-to-end: key not on the allowlist");
    drain();

    struct client mallory;
    memset(&mallory, 0, sizeof mallory);
    hydro_kx_keygen(&mallory.kp);

    /* The handshake itself succeeds cryptographically — Mallory has the build
     * and therefore the PSK. Authorisation is what stops them. */
    client_connect(&mallory, g_psk, false);

    uint8_t m[2048];
    check(game_recv(m, sizeof m, 600) < 0, "no JOIN for an unlisted key");

    uint8_t pkt[BS_MAX_PACKET];
    size_t len;
    mallory.keys = g_alice.keys;     /* even guessing a sid gains nothing */
    mallory.sid  = g_alice.sid;
    client_build_data(&mallory, "grief", pkt, &len);
    udp_send(pkt, len);
    check(game_recv(m, sizeof m, 400) < 0, "unlisted peer cannot inject data");
}

static void test_wrong_psk_rejected(void)
{
    puts("end-to-end: wrong network PSK");
    drain();

    struct client c;
    memset(&c, 0, sizeof c);
    hydro_kx_keygen(&c.kp);

    uint8_t bad_psk[hydro_kx_PSKBYTES];
    memcpy(bad_psk, g_psk, sizeof bad_psk);
    bad_psk[0] ^= 0xff;

    check(!client_connect(&c, bad_psk, false), "handshake fails without the PSK");

    uint8_t m[2048];
    check(game_recv(m, sizeof m, 400) < 0, "no JOIN reaches the game logic");
}

static void test_bad_cookie_rejected(void)
{
    puts("end-to-end: forged cookie");
    drain();

    struct client c;
    memset(&c, 0, sizeof c);
    hydro_kx_keygen(&c.kp);

    check(!client_connect(&c, g_psk, true), "KX1 with a corrupted cookie gets no KX2");
}

static void test_bad_version_silent(void)
{
    puts("end-to-end: protocol version and framing");
    drain();

    uint8_t hello[BS_HELLO_BYTES];
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    hello[1] = BS_PROTO_VERSION + 1;
    udp_send(hello, sizeof hello);

    uint8_t rx[256];
    check(udp_recv(rx, sizeof rx, 400) < 0, "wrong version gets no reply at all");

    /* Reserved bytes must be zero; a non-zero value is a probe or a bug. */
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    hello[2] = 0x01;
    udp_send(hello, sizeof hello);
    check(udp_recv(rx, sizeof rx, 400) < 0, "non-zero reserved byte gets no reply");

    /* A short HELLO must not produce a cookie either. */
    udp_send(hello, BS_HDR_BYTES + 4);
    check(udp_recv(rx, sizeof rx, 400) < 0, "truncated HELLO gets no reply");

    /* And a garbage type. */
    uint8_t junk[64];
    memset(junk, 0, sizeof junk);
    bs_put_hdr(junk, 0x7f);
    udp_send(junk, sizeof junk);
    check(udp_recv(rx, sizeof rx, 400) < 0, "unknown packet type gets no reply");
}

static void test_amplification(void)
{
    puts("amplification ratio");
    drain();

    uint8_t hello[BS_HELLO_BYTES];
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    hydro_random_buf(hello + BS_HDR_BYTES, BS_NONCE_BYTES);
    udp_send(hello, sizeof hello);

    uint8_t rx[256];
    ssize_t n = udp_recv(rx, sizeof rx, 1000);
    check(n > 0, "HELLO is answered");
    check(n > 0 && (size_t)n <= sizeof hello,
          "the only pre-auth reply is no larger than its request");
    printf("        request %zu B -> reply %zd B (ratio %.2f)\n",
           sizeof hello, n, n > 0 ? (double)n / (double)sizeof hello : 0.0);
}

static void test_revocation(void)
{
    puts("end-to-end: revocation on SIGHUP");
    drain();

    /* Alice is connected from the happy path. Remove her and reload. */
    write_allowlist(NULL, NULL);
    kill(g_daemon, SIGHUP);

    uint8_t m[2048];
    ssize_t n = game_recv(m, sizeof m, 1500);
    check(n >= 5 && m[0] == BS_GAME_LEAVE, "revoked peer generates LEAVE immediately");
    check(n >= 5 && bs_get_u32(m + 1) == g_alice.sid, "LEAVE names the right session");

    drain();
    uint8_t pkt[BS_MAX_PACKET];
    size_t len;
    client_build_data(&g_alice, "still here?", pkt, &len);
    udp_send(pkt, len);
    check(game_recv(m, sizeof m, 400) < 0, "revoked peer's data no longer reaches the game");

    /* A refused reload must keep the previous list rather than admitting
     * nobody or, worse, everybody. */
    char path[192];
    snprintf(path, sizeof path, "%s/allowlist", g_dir);
    FILE *f = fopen(path, "w");
    fprintf(f, "garbage line\n");
    fclose(f);
    kill(g_daemon, SIGHUP);
    msleep(300);
    check(kill(g_daemon, 0) == 0, "daemon survives a malformed allowlist reload");

    /* Restore Alice and confirm she can rejoin — proves revocation was the
     * allowlist doing its job, not the daemon having wedged. */
    write_allowlist(g_alice.kp.pk, "alice");
    kill(g_daemon, SIGHUP);
    msleep(300);
    drain();

    struct client again;
    memset(&again, 0, sizeof again);
    again.kp = g_alice.kp;
    check(client_connect(&again, g_psk, false), "re-added peer can reconnect");
    n = game_recv(m, sizeof m, 1000);
    check(n > 0 && m[0] == BS_GAME_JOIN, "reconnect produces a fresh JOIN");
}

static void test_key_file_permissions(void)
{
    puts("state file permissions");
    struct stat st;
    char path[192];

    snprintf(path, sizeof path, "%s/server.seed", g_dir);
    check(stat(path, &st) == 0, "server.seed exists");
    check((st.st_mode & (S_IRWXG | S_IRWXO)) == 0, "server.seed is owner-only");

    snprintf(path, sizeof path, "%s/network.psk", g_dir);
    check(stat(path, &st) == 0, "network.psk exists");
    check((st.st_mode & (S_IRWXG | S_IRWXO)) == 0, "network.psk is owner-only");

    /* Loosening the mode must make the daemon refuse to start, not warn. */
    chmod(path, 0644);
    char cmd[320];
    snprintf(cmd, sizeof cmd,
             "./bsgate --state-dir %s --print-identity >/dev/null 2>&1", g_dir);
    int rc = system(cmd);
    check(rc != 0, "world-readable PSK makes the daemon refuse to start");
    chmod(path, 0600);
}

/* ------------------------------------------------- behind the playit relay */

/* The whole point of the feature: a full handshake where every packet arrives
 * from the relay's socket and the client's identity comes from the header. */
static void test_ppv2_handshake(void)
{
    puts("relay: handshake through a PROXY header");
    drain();

    struct client bob;
    memset(&bob, 0, sizeof bob);
    bob.kp = g_alice.kp;   /* same allowlisted identity, new session */

    check(client_connect(&bob, g_psk, false), "handshake completes through the relay");

    uint8_t m[2048];
    ssize_t n = game_recv(m, sizeof m, 1000);
    check(n > 0 && m[0] == BS_GAME_JOIN, "JOIN reaches the game logic");

    uint8_t pkt[2048];
    size_t plen = 0;
    client_build_data(&bob, "relayed", pkt, &plen);
    udp_send(pkt, plen);

    n = game_recv(m, sizeof m, 1000);
    check(n == 5 + 7 && m[0] == BS_GAME_DATA && memcmp(m + 5, "relayed", 7) == 0,
          "data round-trips through the relay");
}

/* With the feature on, a bare packet carries no proof of who sent it. Silently
 * treating the relay's own address as the client's is the failure this guards. */
static void test_ppv2_missing_header_dropped(void)
{
    puts("relay: unwrapped packet is dropped");
    drain();

    uint8_t hello[BS_HELLO_BYTES];
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    hydro_random_buf(hello + BS_HDR_BYTES, BS_NONCE_BYTES);
    udp_send_raw(hello, sizeof hello);          /* deliberately unwrapped */

    uint8_t rx[256];
    check(udp_recv(rx, sizeof rx, 300) < 0, "no reply to a packet with no header");
}

static void test_ppv2_malformed_header_dropped(void)
{
    puts("relay: malformed header is dropped");
    drain();

    uint8_t hello[BS_HELLO_BYTES];
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    hydro_random_buf(hello + BS_HDR_BYTES, BS_NONCE_BYTES);

    uint8_t out[2048];
    size_t off = ppv2_header(out, 0x21, 0x12, 12, g_ppv2_ip, g_ppv2_port);
    out[5] ^= 0xFF;                              /* break the signature */
    memcpy(out + off, hello, sizeof hello);
    udp_send_raw(out, off + sizeof hello);

    uint8_t rx[256];
    check(udp_recv(rx, sizeof rx, 300) < 0, "no reply to a corrupt header");

    /* LOCAL carries no client address; accepting it would attribute traffic to
     * whatever happened to be in the uninitialised address slot. */
    off = ppv2_header(out, 0x20, 0x12, 12, g_ppv2_ip, g_ppv2_port);
    memcpy(out + off, hello, sizeof hello);
    udp_send_raw(out, off + sizeof hello);
    check(udp_recv(rx, sizeof rx, 300) < 0, "no reply to a LOCAL header");
}

/* Proves the cookie is bound to the address in the header and not to the
 * socket. If the gateway used the socket address, both HELLO and KX1 would
 * come from the same 127.0.0.1 and this would wrongly succeed. */
static void test_ppv2_cookie_bound_to_real_address(void)
{
    puts("relay: cookie is bound to the claimed client, not the relay");
    drain();

    const uint32_t ip_a = htonl(0x0A000001u);   /* 10.0.0.1 */
    const uint32_t ip_b = htonl(0x0A000002u);   /* 10.0.0.2 */
    const uint16_t port = htons(4000);

    hydro_kx_state st;
    uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
    if (hydro_kx_xx_1(&st, packet1, g_psk) != 0) { check(false, "kx1 setup"); return; }

    uint8_t hello[BS_HELLO_BYTES];
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    memcpy(hello + BS_HDR_BYTES, packet1, BS_NONCE_BYTES);
    udp_send_as(ip_a, port, hello, sizeof hello);

    uint8_t rx[2048];
    ssize_t n = udp_recv(rx, sizeof rx, 1000);
    check(n == (ssize_t)BS_COOKIE_PKT_BYTES, "cookie issued to 10.0.0.1");
    if (n != (ssize_t)BS_COOKIE_PKT_BYTES) return;

    uint8_t kx1[BS_KX1_BYTES];
    bs_put_hdr(kx1, BS_PKT_KX1);
    memcpy(kx1 + BS_HDR_BYTES, rx + BS_HDR_BYTES, BS_COOKIE_BYTES);
    memcpy(kx1 + BS_HDR_BYTES + BS_COOKIE_BYTES, packet1, sizeof packet1);

    /* Same cookie, different claimed client. */
    udp_send_as(ip_b, port, kx1, sizeof kx1);
    check(udp_recv(rx, sizeof rx, 300) < 0,
          "cookie replayed from a different client address is refused");

    /* The same cookie from the address it was issued to still works, so the
     * check above failed for the right reason. */
    udp_send_as(ip_a, port, kx1, sizeof kx1);
    n = udp_recv(rx, sizeof rx, 1000);
    check(n == (ssize_t)BS_KX2_BYTES && rx[0] == BS_PKT_KX2,
          "the same cookie still works from the original address");
}

/* The trust boundary itself. Started with a trusted range that excludes
 * loopback, every packet the test can send must be refused — otherwise the
 * header would be believed from anywhere. */
static void test_ppv2_untrusted_source(void)
{
    puts("relay: header from an untrusted source is refused");

    stop_daemon();
    start_daemon_ex(true, "10.99.0.0/16");
    msleep(600);
    drain();

    /* A daemon that failed to start would also send no reply, which would make
     * the check below pass for entirely the wrong reason. Confirm it is alive
     * first. */
    int st = 0;
    check(waitpid(g_daemon, &st, WNOHANG) == 0, "daemon is running");

    uint8_t hello[BS_HELLO_BYTES];
    memset(hello, 0, sizeof hello);
    bs_put_hdr(hello, BS_PKT_HELLO);
    hydro_random_buf(hello + BS_HDR_BYTES, BS_NONCE_BYTES);
    udp_send_as(htonl(0x0A630001u), htons(4000), hello, sizeof hello);

    uint8_t rx[256];
    check(udp_recv(rx, sizeof rx, 500) < 0,
          "loopback cannot assert a header when only 10.99/16 is trusted");
}

/* Believing any claimed address makes the cookie meaningless, so the daemon
 * must refuse to start rather than run in that state. */
static void test_ppv2_refuses_wildcard_trust(void)
{
    puts("relay: 0.0.0.0/0 trust is refused at startup");

    char listen_arg[64], game_arg[192];
    snprintf(listen_arg, sizeof listen_arg, "127.0.0.1:%u", 45999u);
    snprintf(game_arg, sizeof game_arg, "%s/game.sock", g_dir);

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 2); close(devnull); }
        execl("./bsgate", "bsgate",
              "--listen", listen_arg,
              "--state-dir", g_dir,
              "--game-socket", game_arg,
              "--proxy-protocol",
              "--trusted-proxy", "0.0.0.0/0",
              (char *)NULL);
        _exit(127);
    }

    /* Bounded wait. A plain waitpid() here turns "the daemon wrongly accepted
     * 0.0.0.0/0" into a 240s hang rather than a failed check, which is how
     * this read when the refusal was mutated out. A negative test that can
     * only deadlock is not a test. */
    int status = 0;
    bool exited = false;
    for (int i = 0; i < 300; i++) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) { exited = true; break; }
        if (r < 0) break;
        usleep(10000);
    }
    if (!exited) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    check(exited && WIFEXITED(status) && WEXITSTATUS(status) != 0,
          "daemon exits non-zero rather than trusting everyone");
}

/* ------------------------------------------------------------------- main */

/* If the test dies unexpectedly the daemon must die with it: an orphan holding
 * the inherited stdout pipe makes `make test` hang forever instead of failing,
 * which is exactly what happened the first time this was run. */
static void reap_daemon(void)
{
    if (g_daemon > 0) {
        kill(g_daemon, SIGKILL);
        waitpid(g_daemon, NULL, 0);
        g_daemon = -1;
    }
}

static void crash_handler(int sig)
{
    reap_daemon();
    _exit(128 + sig);
}

int main(void)
{
    /* Unbuffered, so a crash mid-suite still shows which check was last
     * reached. Block buffering hid the failure point on the first run. */
    setvbuf(stdout, NULL, _IONBF, 0);

    atexit(reap_daemon);
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGBUS,  crash_handler);

    if (hydro_init() != 0) { fprintf(stderr, "hydro_init failed\n"); return 1; }

    snprintf(g_dir, sizeof g_dir, "/tmp/bsgate_test_%d", (int)getpid());
    if (mkdir(g_dir, 0700) != 0) die("mkdir state dir");

    puts("== bsgate test ==");

    test_replay_window();
    test_ratelimit();
    test_allowlist_parsing();
    test_ppv2_parse();

    /* Creates server.seed and network.psk as a side effect. */
    read_identity();

    memset(&g_alice, 0, sizeof g_alice);
    hydro_kx_keygen(&g_alice.kp);
    write_allowlist(g_alice.kp.pk, "alice");

    open_sockets();
    start_daemon();

    if (!wait_ready(5000)) {
        fprintf(stderr, "test: daemon never became ready\n");
        kill(g_daemon, SIGKILL);
        return 1;
    }

    test_key_file_permissions();
    test_amplification();
    test_bad_version_silent();
    test_bad_cookie_rejected();
    test_happy_path();
    test_keepalive_echo();
    test_status_snapshot();
    test_replay_rejected();
    test_tampered_payload();
    test_wrong_psk_rejected();
    test_unknown_key_rejected();
    test_revocation();

    /* Everything from here runs against a daemon configured the way the
     * playit deployment actually runs it: loopback bind, every datagram
     * wrapped in a PROXY header. */
    stop_daemon();
    start_daemon_ex(true, NULL);

    g_ppv2      = true;
    g_ppv2_ip   = htonl(0xC0A8010Au);   /* 192.168.1.10 */
    g_ppv2_port = htons(50000);

    if (!wait_ready(5000)) {
        fprintf(stderr, "test: relay-mode daemon never became ready\n");
        reap_daemon();
        return 1;
    }

    test_ppv2_handshake();
    test_ppv2_missing_header_dropped();
    test_ppv2_malformed_header_dropped();
    test_ppv2_cookie_bound_to_real_address();
    test_ppv2_untrusted_source();
    test_ppv2_refuses_wildcard_trust();

    stop_daemon();

    /* Leaves the state dir behind on failure so it can be inspected. */
    if (g_fails == 0) {
        char rm[256];
        snprintf(rm, sizeof rm, "rm -rf %s", g_dir);
        if (system(rm) != 0) { /* best effort */ }
    } else {
        printf("state dir kept at %s\n", g_dir);
    }

    printf("\n%s %d checks, %d failed\n",
           g_fails == 0 ? "PASS" : "FAIL", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
