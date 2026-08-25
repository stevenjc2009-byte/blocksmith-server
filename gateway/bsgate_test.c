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

/* enum bs_game_msg — this suite stands in for bsgame on the game socket, so it
 * speaks the gate<->game framing and is bound by it. It used to declare its own
 * anonymous copy of the four values below this include block. */
#include "../proto/bs_gamelink.h"
#include "../proto/bs_proto.h"
#include "allowlist.h"
#include "invite.h"
#include "proxyproto.h"
#include "ratelimit.h"
#include "replay.h"

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

static void test_allowlist_append(void)
{
    puts("allowlist append");
    char path[192], err[256];
    snprintf(path, sizeof path, "%s/ap_test", g_dir);

    uint8_t a_pk[BS_KX_PUBLICKEYBYTES], b_pk[BS_KX_PUBLICKEYBYTES];
    memset(a_pk, 0x11, sizeof a_pk);
    memset(b_pk, 0x22, sizeof b_pk);
    char a_hex[2 * BS_KX_PUBLICKEYBYTES + 1];
    hydro_bin2hex(a_hex, sizeof a_hex, a_pk, sizeof a_pk);

    /* Deliberately written with NO trailing newline. The real allowlist is
     * mostly explanatory comments written by the provisioner, and a file whose
     * last line lacks one would otherwise absorb the appended key into it and
     * produce a list the daemon then refuses to reload — locking everyone out
     * as the delayed consequence of one enrolment. */
    FILE *f = fopen(path, "w");
    fprintf(f, "# keep me\n%s alice", a_hex);
    fclose(f);

    check(bs_allowlist_append(path, b_pk, "bob", err, sizeof err), "append succeeds");

    struct bs_allowlist al;
    check(bs_allowlist_load(&al, path, err, sizeof err), "appended file still parses");
    check(al.count == 2, "both entries present");
    check(bs_allowlist_find(&al, b_pk) != NULL, "the new key is findable");

    /* The comment is what proves this is an append and not a rewrite. */
    char buf[512] = {0};
    f = fopen(path, "r");
    size_t got = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    check(got > 0 && strstr(buf, "# keep me") != NULL, "existing comments survive");

    check(!bs_allowlist_append(path, b_pk, "bob2", err, sizeof err),
          "duplicate key refused");
    check(!bs_allowlist_append(path, a_pk, "alice", err, sizeof err),
          "duplicate label refused");
    check(!bs_allowlist_append(path, b_pk, "bad label!", err, sizeof err),
          "invalid label refused");

    /* A refusal must not have touched the file. */
    struct bs_allowlist after;
    check(bs_allowlist_load(&after, path, err, sizeof err) && after.count == 2,
          "refused appends leave the file unchanged");
}

static void test_invite_unit(void)
{
    puts("invite record");
    char path[192], err[256];
    snprintf(path, sizeof path, "%s/inv_test", g_dir);
    unlink(path);

    /* A missing file is the normal state — most of this server's life has no
     * invite armed — so it must read as success with armed=false, never as an
     * error the daemon refuses to start on. */
    struct bs_invite iv;
    memset(&iv, 0xFF, sizeof iv);
    check(bs_invite_load(&iv, path, err, sizeof err), "missing invite file is not an error");
    check(!iv.armed, "...and reads as disarmed");
    check(!bs_invite_valid(&iv, 1000), "a disarmed invite is never valid");

    char code[BS_INVITE_CODE_MAX + 1];
    bs_invite_generate(code, sizeof code);
    check(strlen(code) == BS_INVITE_CODE_LEN, "generated code is the right length");
    bool in_alphabet = true;
    for (size_t i = 0; code[i]; i++) {
        if (strchr(BS_INVITE_ALPHABET, code[i]) == NULL) in_alphabet = false;
    }
    check(in_alphabet, "every symbol comes from the confusable-free alphabet");

    /* Two in a row being equal would mean the generator is not random at all;
     * at 49 bits this cannot happen by chance. */
    char code2[BS_INVITE_CODE_MAX + 1];
    bs_invite_generate(code2, sizeof code2);
    check(strcmp(code, code2) != 0, "two generated codes differ");

    struct bs_invite armed;
    memset(&armed, 0, sizeof armed);
    armed.armed        = true;
    armed.expires_unix = 2000;
    armed.strikes_left = BS_INVITE_STRIKES;
    snprintf(armed.label, sizeof armed.label, "tom");
    bs_invite_hash_code(code, armed.code_hash);

    check(bs_invite_save(&armed, path, err, sizeof err), "invite saves");

    struct stat st;
    check(stat(path, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
          "invite file is owner-only");

    /* The stored record must not contain the code. This is the whole reason
     * the operator cannot be shown it twice. */
    char raw[512] = {0};
    FILE *f = fopen(path, "r");
    if (f) { if (fread(raw, 1, sizeof raw - 1, f) == 0) { /* empty */ } fclose(f); }
    check(strstr(raw, code) == NULL, "the plaintext code is not stored on disk");

    struct bs_invite back;
    check(bs_invite_load(&back, path, err, sizeof err), "invite loads back");
    check(back.armed && !strcmp(back.label, "tom"), "label round-trips");
    check(back.expires_unix == 2000, "expiry round-trips");
    check(back.strikes_left == BS_INVITE_STRIKES, "strike count round-trips");

    check(bs_invite_valid(&back, 1999),  "valid one second before expiry");
    check(!bs_invite_valid(&back, 2000), "not valid at the expiry instant");
    check(!bs_invite_valid(&back, 2001), "not valid after expiry");

    check(bs_invite_matches(&back, code, 1999), "the exact code matches");
    check(!bs_invite_matches(&back, code2, 1999), "a different code does not");
    check(!bs_invite_matches(&back, code, 2001), "the right code does not match once expired");

    /* Normalisation: the separator is presentation, and a 3DS software
     * keyboard makes people fight for a hyphen. Lower case, spaces and the
     * hyphen must all resolve to the same digest. */
    char pretty[64], lower[64], spaced[64];
    snprintf(pretty, sizeof pretty, "%.5s-%.5s", code, code + 5);
    snprintf(spaced, sizeof spaced, "%.5s %.5s", code, code + 5);
    snprintf(lower, sizeof lower, "%s", code);
    for (size_t i = 0; lower[i]; i++) {
        if (lower[i] >= 'A' && lower[i] <= 'Z') lower[i] = (char)(lower[i] - 'A' + 'a');
    }
    check(bs_invite_matches(&back, pretty, 1999), "XXXXX-XXXXX form matches");
    check(bs_invite_matches(&back, spaced, 1999), "space-separated form matches");
    check(bs_invite_matches(&back, lower,  1999), "lower case matches");
    check(!bs_invite_matches(&back, "", 1999),    "an empty code does not match");

    /* Zero strikes is a burnt invite: still on disk, but dead. */
    struct bs_invite burnt = back;
    burnt.strikes_left = 0;
    check(!bs_invite_valid(&burnt, 1999), "an invite with no strikes left is not valid");

    /* Disarming is expressed as the file's absence, so "consumed",
     * "cancelled" and "burnt out" converge on one state. */
    struct bs_invite off;
    memset(&off, 0, sizeof off);
    check(bs_invite_save(&off, path, err, sizeof err), "saving a disarmed invite succeeds");
    check(stat(path, &st) != 0, "...by removing the file");
    check(bs_invite_save(&off, path, err, sizeof err), "disarming twice is not an error");

    f = fopen(path, "w");
    fprintf(f, "label tom\ncode_hash not-hex\n");
    fclose(f);
    struct bs_invite keep = back;
    check(!bs_invite_load(&keep, path, err, sizeof err), "malformed invite refused");
    check(keep.armed && !strcmp(keep.label, "tom"),
          "refused load leaves the previous invite untouched");

    f = fopen(path, "w");
    fprintf(f, "label tom\n");
    fclose(f);
    check(!bs_invite_load(&keep, path, err, sizeof err), "incomplete invite refused");

    unlink(path);
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

/* ------------------------------------------------------------- enrolment */

/* Runs one of the daemon's one-shot invite modes and returns its stdout. The
 * real `bsgate-keys` drives it exactly this way, so the test is exercising the
 * shipped mechanism rather than a test-only shortcut into the file format. */
static void invite_cmd(const char *args, char *out, size_t cap)
{
    char cmd[384];
    snprintf(cmd, sizeof cmd, "./bsgate --state-dir %s %s 2>&1", g_dir, args);

    out[0] = '\0';
    FILE *p = popen(cmd, "r");
    if (p == NULL) die("popen invite");
    size_t n = fread(out, 1, cap - 1, p);
    out[n] = '\0';
    pclose(p);
}

/* Arms an invite and returns the code. SIGHUPs the daemon afterwards, because
 * that is the only channel `bsgate-keys` has to tell it. */
static void arm_invite(const char *label, char *code, size_t cap)
{
    char args[128], out[512];
    snprintf(args, sizeof args, "--arm-invite %s", label);
    invite_cmd(args, out, sizeof out);

    code[0] = '\0';
    char *line = strstr(out, "invite_code");
    if (line != NULL) {
        char buf[64];
        if (sscanf(line, "invite_code %63s", buf) == 1) snprintf(code, cap, "%s", buf);
    }

    kill(g_daemon, SIGHUP);
    msleep(300);
}

/* True if an invite is currently armed, according to the daemon's own reader. */
static bool invite_is_armed(void)
{
    char out[256];
    invite_cmd("--show-invite", out, sizeof out);
    return strstr(out, "invite_armed none") == NULL;
}

static unsigned invite_strikes_left(void)
{
    char out[256], label[64];
    long long secs = 0;
    unsigned strikes = 0;
    invite_cmd("--show-invite", out, sizeof out);
    if (sscanf(out, "invite_armed %63s %lld %u", label, &secs, &strikes) != 3) return 0;
    if (!strcmp(label, "none")) return 0;
    return strikes;
}

/* Sends `text` as an ENROL packet: framed exactly like DATA, differing only in
 * the type byte, so the client side needs no new crypto. */
static void client_send_enrol(struct client *c, const char *text)
{
    uint8_t out[BS_MAX_PACKET];
    size_t len = strlen(text);
    bs_put_hdr(out, BS_PKT_ENROL);
    bs_put_u32(out + BS_HDR_BYTES, c->sid);
    uint64_t msg_id = c->tx_msg_id++;
    bs_put_u64(out + BS_HDR_BYTES + BS_SID_BYTES, msg_id);
    hydro_secretbox_encrypt(out + BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES,
                            text, len, msg_id, BS_CTX_C2S, c->keys.tx);
    udp_send(out, BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES
                  + hydro_secretbox_HEADERBYTES + len);
}

/* Counts allowlist entries carrying `label`, read straight off disk — the
 * enrolment's whole job is to put one there. */
static int allowlist_count_label(const char *label)
{
    char path[192];
    snprintf(path, sizeof path, "%s/allowlist", g_dir);

    struct bs_allowlist al;
    char err[256];
    if (!bs_allowlist_load(&al, path, err, sizeof err)) return -1;

    int n = 0;
    for (size_t i = 0; i < al.count; i++) {
        if (!strcmp(al.entry[i].label, label)) n++;
    }
    return n;
}

/* Takes a fresh SIGUSR1 snapshot and returns its whole text. The status file
 * is the only outside view of the session table, and a probation session is
 * exactly the thing that must not be sitting in it unnoticed. */
static bool status_snapshot(char *out, size_t cap)
{
    char path[192];
    snprintf(path, sizeof path, "%s/status.txt", g_dir);
    unlink(path);
    kill(g_daemon, SIGUSR1);

    out[0] = '\0';
    for (int i = 0; i < 40; i++) {
        FILE *f = fopen(path, "r");
        if (f != NULL) {
            size_t n = fread(out, 1, cap - 1, f);
            out[n] = '\0';
            fclose(f);
            return n > 0;
        }
        msleep(50);
    }
    return false;
}

static struct client g_bob;      /* enrols during the run */

/* The control arm for everything below: with nothing armed, an unlisted key
 * must be dropped exactly as it was before this feature existed. If this ever
 * goes green for the wrong reason the rest of the section proves nothing. */
static void test_enrol_disabled_by_default(void)
{
    puts("enrolment: no invite armed behaves exactly as before");
    drain();

    check(!invite_is_armed(), "no invite is armed to begin with");

    struct client stranger;
    memset(&stranger, 0, sizeof stranger);
    hydro_kx_keygen(&stranger.kp);
    check(client_connect(&stranger, g_psk, false), "handshake still completes");

    uint8_t m[2048];
    check(game_recv(m, sizeof m, 600) < 0, "no JOIN for an unlisted key");

    /* "No JOIN" alone would still pass if the gate had quietly handed the
     * stranger a probation session and then turned them away when their code
     * failed — which is a session slot an unlisted peer could occupy at will.
     * The snapshot is what distinguishes "dropped" from "let in, then
     * rejected", and it has to be taken BEFORE any code is sent, because a
     * rejected code frees the slot again and hides the difference. */
    char st[4096];
    check(status_snapshot(st, sizeof st), "status snapshot taken");
    check(strstr(st, "enrolling") == NULL, "no probation session was created");
    check(strstr(st, "invite_armed none 0 0") != NULL, "status reports no armed invite");
    check(strstr(st, "enrolments_total 0") != NULL, "nothing has been enrolled");

    /* And sending a code — any code — must do nothing, because the session the
     * gate would have needed does not exist. */
    client_send_enrol(&stranger, "AAAAA-AAAAA");
    check(game_recv(m, sizeof m, 400) < 0, "an unsolicited code changes nothing");
    check(udp_recv(m, sizeof m, 400) < 0, "and gets no answer");
    check(allowlist_count_label("bob") == 0, "nothing was written to the allowlist");
}

static void test_enrol_happy_path(void)
{
    puts("enrolment: correct code joins the allowlist for good");
    drain();

    char code[64];
    arm_invite("bob", code, sizeof code);
    check(strlen(code) == BS_INVITE_CODE_LEN + 1, "arming prints an XXXXX-XXXXX code");
    check(invite_is_armed(), "the invite is armed");

    memset(&g_bob, 0, sizeof g_bob);
    hydro_kx_keygen(&g_bob.kp);
    check(client_connect(&g_bob, g_psk, false), "unlisted peer completes the handshake");

    uint8_t m[2048];
    check(game_recv(m, sizeof m, 400) < 0,
          "no JOIN before the code — probation is not membership");

    client_send_enrol(&g_bob, code);

    uint8_t rx[2048];
    ssize_t n = udp_recv(rx, sizeof rx, 1500);
    check(n > 0 && rx[0] == BS_PKT_ENROL_OK, "the console is told it is enrolled");

    n = game_recv(m, sizeof m, 1500);
    check(n > 0 && m[0] == BS_GAME_JOIN, "and only then does the game see a JOIN");
    check(n > 0 && !strcmp((char *)m + 5 + BS_KX_PUBLICKEYBYTES, "bob"),
          "JOIN carries the invite's label");

    check(allowlist_count_label("bob") == 1, "the key is on the allowlist exactly once");
    check(!invite_is_armed(), "the invite is consumed");
}

/* steve's requirement, stated in as many words: invited once, they connect
 * whenever they want, with nothing to accept. */
static void test_enrol_persists_across_reconnects(void)
{
    puts("enrolment: an enrolled console reconnects with no code");
    drain();

    check(!invite_is_armed(), "no invite armed for this reconnect");

    struct client again;
    memset(&again, 0, sizeof again);
    again.kp = g_bob.kp;
    check(client_connect(&again, g_psk, false), "bob reconnects");

    /* One key, one session: bob's previous session is still live, so the gate
     * replaces it and the game logic sees LEAVE before JOIN. Asserted in order
     * rather than skipped, because a JOIN with no matching LEAVE would leave
     * bsgame holding two players for one console. */
    uint8_t m[2048];
    ssize_t n = game_recv(m, sizeof m, 1500);
    check(n > 0 && m[0] == BS_GAME_LEAVE, "the stale session is closed first");

    n = game_recv(m, sizeof m, 1500);
    check(n > 0 && m[0] == BS_GAME_JOIN, "straight to JOIN, no enrolment");
    check(n > 0 && !strcmp((char *)m + 5 + BS_KX_PUBLICKEYBYTES, "bob"),
          "still known as bob");

    /* And a full daemon restart must not lose it: the allowlist is the record,
     * not the session table. */
    stop_daemon();
    start_daemon();
    if (!wait_ready(5000)) { check(false, "daemon restarted"); return; }
    check(true, "daemon restarted");
    drain();

    struct client after_restart;
    memset(&after_restart, 0, sizeof after_restart);
    after_restart.kp = g_bob.kp;
    check(client_connect(&after_restart, g_psk, false), "bob reconnects after a restart");
    n = game_recv(m, sizeof m, 1500);
    check(n > 0 && m[0] == BS_GAME_JOIN, "still admitted with no code");
    g_bob.sid  = after_restart.sid;
    g_bob.keys = after_restart.keys;
    g_bob.tx_msg_id = after_restart.tx_msg_id;
}

static void test_enrol_wrong_code_burns_strikes(void)
{
    puts("enrolment: wrong codes burn strikes and disarm the invite");
    drain();

    char code[64];
    arm_invite("carol", code, sizeof code);
    check(invite_strikes_left() == BS_INVITE_STRIKES, "starts with a full strike count");

    unsigned expected = BS_INVITE_STRIKES;
    for (unsigned attempt = 1; attempt <= BS_INVITE_STRIKES; attempt++) {
        struct client c;
        memset(&c, 0, sizeof c);
        hydro_kx_keygen(&c.kp);
        if (!client_connect(&c, g_psk, false)) { check(false, "probation handshake"); return; }

        client_send_enrol(&c, "ZZZZZ-ZZZZZ");
        msleep(300);

        uint8_t m[2048];
        char what[64];
        snprintf(what, sizeof what, "attempt %u gets no JOIN", attempt);
        check(game_recv(m, sizeof m, 300) < 0, what);

        expected--;
        snprintf(what, sizeof what, "attempt %u leaves %u strike(s)", attempt, expected);
        check(invite_strikes_left() == expected, what);
        drain();
    }

    check(!invite_is_armed(), "the invite is burnt after the last strike");
    check(allowlist_count_label("carol") == 0, "carol was never written to the allowlist");

    /* And the correct code is now worthless, which is the point of burning it. */
    struct client late;
    memset(&late, 0, sizeof late);
    hydro_kx_keygen(&late.kp);
    check(client_connect(&late, g_psk, false), "a later handshake still completes");
    client_send_enrol(&late, code);
    msleep(300);
    uint8_t m[2048];
    check(game_recv(m, sizeof m, 300) < 0, "the real code no longer enrols anyone");
    check(allowlist_count_label("carol") == 0, "...and still writes nothing");
}

static void test_enrol_replay_and_established(void)
{
    puts("enrolment: a captured code cannot be reused");
    drain();

    char code[64];
    arm_invite("dave", code, sizeof code);

    struct client dave;
    memset(&dave, 0, sizeof dave);
    hydro_kx_keygen(&dave.kp);
    check(client_connect(&dave, g_psk, false), "dave reaches probation");

    /* Capture the exact ENROL datagram, then reuse it. */
    uint8_t wire[BS_MAX_PACKET];
    size_t len = strlen(code);
    bs_put_hdr(wire, BS_PKT_ENROL);
    bs_put_u32(wire + BS_HDR_BYTES, dave.sid);
    uint64_t msg_id = dave.tx_msg_id++;
    bs_put_u64(wire + BS_HDR_BYTES + BS_SID_BYTES, msg_id);
    hydro_secretbox_encrypt(wire + BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES,
                            code, len, msg_id, BS_CTX_C2S, dave.keys.tx);
    size_t wire_len = BS_HDR_BYTES + BS_SID_BYTES + BS_MSGID_BYTES
                    + hydro_secretbox_HEADERBYTES + len;
    udp_send(wire, wire_len);

    uint8_t m[2048];
    ssize_t n = game_recv(m, sizeof m, 1500);
    check(n > 0 && m[0] == BS_GAME_JOIN, "dave enrols");
    check(allowlist_count_label("dave") == 1, "dave is on the allowlist once");
    drain();

    /* Byte-identical replay. The replay window alone should stop it, and the
     * established-session check behind that. Either way: no second entry. */
    udp_send(wire, wire_len);
    msleep(300);
    check(allowlist_count_label("dave") == 1, "replaying the code adds nothing");
    check(game_recv(m, sizeof m, 300) < 0, "and produces no second JOIN");

    /* A fresh, correctly-framed ENROL from a peer who is already in must also
     * go nowhere — the invite is consumed and they are not on probation. */
    client_send_enrol(&dave, code);
    msleep(300);
    check(allowlist_count_label("dave") == 1, "an established peer cannot re-enrol");
    check(!invite_is_armed(), "the invite stayed consumed");
}

static void test_enrol_one_at_a_time(void)
{
    puts("enrolment: only one probation session at a time");
    drain();

    char code[64];
    arm_invite("erin", code, sizeof code);

    struct client first, second;
    memset(&first, 0, sizeof first);
    memset(&second, 0, sizeof second);
    hydro_kx_keygen(&first.kp);
    hydro_kx_keygen(&second.kp);

    check(client_connect(&first, g_psk, false), "the first stranger reaches probation");

    /* The second is refused at KX3, before a session exists — so an armed
     * invite cannot be used to fill every slot with handshakes that never
     * enrol. client_connect() cannot see that: the gate sends nothing on a
     * successful KX3 either, so there is no reply to distinguish. The refusal
     * is proved by what the second stranger can then do, which is nothing:
     * they hold the correct code and it gets them exactly nowhere. */
    client_connect(&second, g_psk, false);
    client_send_enrol(&second, code);
    msleep(400);

    uint8_t m[2048];
    check(game_recv(m, sizeof m, 300) < 0, "the second stranger produces no JOIN");
    check(allowlist_count_label("erin") == 0, "...and is not written to the allowlist");
    check(invite_is_armed(), "...and did not consume the invite");
    drain();

    /* The slot still belongs to the first stranger, and their code works. */
    client_send_enrol(&first, code);
    ssize_t n = game_recv(m, sizeof m, 1500);
    check(n > 0 && m[0] == BS_GAME_JOIN, "the probation slot still belongs to the first");
    check(allowlist_count_label("erin") == 1, "erin is on the allowlist exactly once");
    drain();

    /* An abandoned probation session must free its slot rather than hold it
     * for the full idle timeout. BS_ENROL_WINDOW_MS is 10 s in the daemon;
     * waited out for real so the sweep in tick() is what is being tested. */
    char code2[64];
    arm_invite("frank", code2, sizeof code2);

    struct client silent, late;
    memset(&silent, 0, sizeof silent);
    memset(&late, 0, sizeof late);
    hydro_kx_keygen(&silent.kp);
    hydro_kx_keygen(&late.kp);

    check(client_connect(&silent, g_psk, false), "a stranger takes the slot and says nothing");
    msleep(11000);
    drain();

    client_connect(&late, g_psk, false);
    client_send_enrol(&late, code2);
    n = game_recv(m, sizeof m, 1500);
    check(n > 0 && m[0] == BS_GAME_JOIN, "the slot is released when the window expires");
    check(allowlist_count_label("frank") == 1, "frank is on the allowlist");

    /* Tidy up: leave nothing armed for the relay section that follows. */
    char out[256];
    arm_invite("gina", out, sizeof out);
    check(invite_is_armed(), "an invite can be armed again");
    invite_cmd("--cancel-invite", out, sizeof out);
    kill(g_daemon, SIGHUP);
    msleep(300);
    check(!invite_is_armed(), "cancelling disarms an invite");
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
    test_allowlist_append();
    test_invite_unit();
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

    /* Enrolment. The first case is the control: with nothing armed the gate
     * must behave exactly as it did before any of this existed. */
    test_enrol_disabled_by_default();
    test_enrol_happy_path();
    test_enrol_persists_across_reconnects();
    test_enrol_wrong_code_burns_strikes();
    test_enrol_replay_and_established();
    test_enrol_one_at_a_time();

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
