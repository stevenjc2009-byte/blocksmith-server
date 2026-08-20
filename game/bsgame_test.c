/* bsgame_test — end-to-end test against a real bsgame process.
 *
 * Same shape as server/gateway/bsgate_test.c: this launches the actual
 * daemon and speaks the real gate<->game protocol at it over a real Unix
 * datagram socket, standing in for bsgate on one end and for a second
 * player on the other. Every negative case is written so it goes red if the
 * corresponding check is removed — see the mutation notes in the report
 * this test was written for.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../proto/bs_proto.h"
#include "players.h"   /* BS_EDIT_BURST / BS_EDIT_REFILL_MS, for the rate-limit ceiling */
#include "validate.h"  /* BS_BLOCK_COUNT, for the highest-legal-block-id boundary test */

enum bs_game_msg { BS_GAME_JOIN = 1, BS_GAME_DATA = 2, BS_GAME_LEAVE = 3, BS_GAME_KICK = 4 };

/* Mirrors bsgame.c's BS_CHUNK_LEGACY_GRACE_MS — not shared via a header for
 * the same reason the bs_game_msg enum above isn't: an internal
 * implementation constant, not part of the wire protocol. A player who never
 * sends CHUNK_SUB only gets the legacy full-dump WORLD_SYNC once this much
 * time has passed since JOIN (see tick(), bsgame.c) — every test below that
 * exercises that legacy path has to wait at least this long, plus a tick,
 * before giving up on a WORLD_SYNC that just hasn't fired yet. */
#define BS_CHUNK_LEGACY_GRACE_MS 500u

static int  g_checks = 0;
static int  g_fails  = 0;
static char g_dir[64];
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

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* --------------------------------------------------------------- plumbing */

static int g_gate = -1;              /* our stand-in for bsgate            */
static char g_game_sock[108];        /* the daemon's socket, we send here  */
static char g_gate_sock[108];        /* our own socket, the daemon replies here */

static ssize_t gate_recv(uint8_t *buf, size_t cap, unsigned ms)
{
    struct pollfd p = { .fd = g_gate, .events = POLLIN };
    if (poll(&p, 1, (int)ms) <= 0) return -1;
    return recv(g_gate, buf, cap, 0);
}

static void gate_send(const uint8_t *buf, size_t len)
{
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", g_game_sock);
    if (sendto(g_gate, buf, len, 0, (struct sockaddr *)&un, sizeof un) < 0) die("gate sendto");
}

static void drain(void)
{
    uint8_t b[2048];
    while (gate_recv(b, sizeof b, 30) > 0) { }
}

/* ------------------------------------------------------- message builders */

static void send_join(uint32_t sid, const char *label)
{
    uint8_t buf[5 + 32 + 32];
    memset(buf, 0, sizeof buf);
    buf[0] = BS_GAME_JOIN;
    bs_put_u32(buf + 1, sid);
    /* pubkey left zeroed — bsgame does not look at it */
    snprintf((char *)buf + 5 + 32, 32, "%s", label);
    gate_send(buf, sizeof buf);
}

static void send_leave(uint32_t sid)
{
    uint8_t buf[5];
    buf[0] = BS_GAME_LEAVE;
    bs_put_u32(buf + 1, sid);
    gate_send(buf, sizeof buf);
}

static void send_app(uint32_t sid, const uint8_t *payload, size_t len)
{
    uint8_t buf[5 + BS_MAX_PAYLOAD];
    buf[0] = BS_GAME_DATA;
    bs_put_u32(buf + 1, sid);
    memcpy(buf + 5, payload, len);
    gate_send(buf, 5 + len);
}

static void send_block_edit(uint32_t sid, int32_t x, int32_t y, int32_t z, uint8_t block)
{
    uint8_t p[BS_BLOCK_EDIT_BYTES];
    p[0] = BS_APP_BLOCK_EDIT;
    bs_put_i32(p + 1, x);
    bs_put_i32(p + 5, y);
    bs_put_i32(p + 9, z);
    p[13] = block;
    send_app(sid, p, sizeof p);
}

static void send_pos_update(uint32_t sid, float x, float y, float z, float yaw, float pitch)
{
    uint8_t p[BS_POS_UPDATE_C_BYTES];
    p[0] = BS_APP_POS_UPDATE;
    bs_put_f32(p + 1,  x);
    bs_put_f32(p + 5,  y);
    bs_put_f32(p + 9,  z);
    bs_put_f32(p + 13, yaw);
    bs_put_f32(p + 17, pitch);
    send_app(sid, p, sizeof p);
}

static void send_chunk_sub(uint32_t sid, int32_t cx, int32_t cz)
{
    uint8_t p[BS_CHUNK_SUB_BYTES];
    p[0] = BS_APP_CHUNK_SUB;
    bs_put_i32(p + 1, cx);
    bs_put_i32(p + 5, cz);
    send_app(sid, p, sizeof p);
}

static void send_chunk_unsub(uint32_t sid, int32_t cx, int32_t cz)
{
    uint8_t p[BS_CHUNK_UNSUB_BYTES];
    p[0] = BS_APP_CHUNK_UNSUB;
    bs_put_i32(p + 1, cx);
    bs_put_i32(p + 5, cz);
    send_app(sid, p, sizeof p);
}

/* Reads BS_GAME_DATA envelopes off the shared gate socket until one is
 * addressed to `sid`, and unwraps it — or -1 once `ms` has elapsed with no
 * match. Skips, rather than fails on, a DATA envelope for a different sid:
 * once more than two players are connected (as V127-A's scoped-broadcast
 * tests below need, to prove a subscriber and a non-subscriber diverge) a
 * single broadcast can queue packets for several sids in an order this test
 * process does not control, and the first one off the wire is not
 * necessarily the one being waited for. A non-DATA envelope (e.g. a KICK)
 * still fails immediately rather than being skipped — that shape is never
 * expected to precede the packet a caller is polling for. */
static ssize_t recv_app_for(uint32_t sid, uint8_t *out, size_t cap, unsigned ms)
{
    uint64_t deadline = now_ms() + ms;

    for (;;) {
        uint64_t now = now_ms();
        if (now >= deadline) return -1;

        uint8_t buf[2048];
        ssize_t n = gate_recv(buf, sizeof buf, (unsigned)(deadline - now));
        if (n < 5 || buf[0] != BS_GAME_DATA) return -1;
        if (bs_get_u32(buf + 1) != sid) continue;

        size_t len = (size_t)n - 5;
        if (len > cap) return -1;
        memcpy(out, buf + 5, len);
        return (ssize_t)len;
    }
}

/* Like recv_app_for, but for the V127-A scoped-broadcast tests that check
 * TWO different recipients of the very same edit. recv_app_for's own
 * skip-and-keep-waiting design (see its header comment just above) is
 * exactly wrong for that: waiting for sid_a would permanently discard
 * sid_b's packet if it happens to arrive first, and vice versa, since a
 * skipped packet is gone. This reads in one pass instead, filing at most one
 * hit per sid into whichever out-param matches, and stops once both have
 * been seen or `ms` runs out — so neither recipient's packet is ever thrown
 * away waiting on the other's. A packet for neither sid (or a duplicate for
 * one already captured) is simply not needed here and is dropped, same as
 * recv_app_for drops a mismatched sid. */
static void recv_app_for_two(uint32_t sid_a, uint8_t *out_a, size_t cap_a, ssize_t *n_a,
                             uint32_t sid_b, uint8_t *out_b, size_t cap_b, ssize_t *n_b,
                             unsigned ms)
{
    *n_a = -1;
    *n_b = -1;
    uint64_t deadline = now_ms() + ms;

    while (*n_a < 0 || *n_b < 0) {
        uint64_t now = now_ms();
        if (now >= deadline) return;

        uint8_t buf[2048];
        ssize_t n = gate_recv(buf, sizeof buf, (unsigned)(deadline - now));
        if (n < 5 || buf[0] != BS_GAME_DATA) return;

        uint32_t sid = bs_get_u32(buf + 1);
        size_t len = (size_t)n - 5;

        if (sid == sid_a && *n_a < 0 && len <= cap_a) {
            memcpy(out_a, buf + 5, len);
            *n_a = (ssize_t)len;
        } else if (sid == sid_b && *n_b < 0 && len <= cap_b) {
            memcpy(out_b, buf + 5, len);
            *n_b = (ssize_t)len;
        }
    }
}

/* ------------------------------------------------------------ daemon setup */

/* Must run before open_sockets(): it binds g_gate to g_gate_sock, so that
 * path has to be populated first, not lazily inside start_daemon(). */
static void set_sock_paths(void)
{
    snprintf(g_game_sock, sizeof g_game_sock, "%s/game.sock", g_dir);
    snprintf(g_gate_sock, sizeof g_gate_sock, "%s/gate.sock", g_dir);
}

static void open_sockets(void)
{
    g_gate = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (g_gate < 0) die("gate socket");

    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", g_gate_sock);
    unlink(un.sun_path);
    if (bind(g_gate, (struct sockaddr *)&un, sizeof un) != 0) die("bind gate.sock");
}

static void start_daemon(void)
{
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        execl("./bsgame", "bsgame",
              "--game-socket", g_game_sock,
              "--gate-socket", g_gate_sock,
              "--state-dir",   g_dir,
              (char *)NULL);
        _exit(127);
    }
    g_daemon = pid;
}

static void stop_daemon(void)
{
    if (g_daemon <= 0) return;
    kill(g_daemon, SIGTERM);
    waitpid(g_daemon, NULL, 0);
    g_daemon = -1;
}

/* Blocks until the daemon's socket exists and answers a JOIN, so no test
 * races the daemon's startup and fails for the wrong reason. */
static bool wait_ready(unsigned timeout_ms)
{
    for (unsigned waited = 0; waited < timeout_ms; waited += 50) {
        struct stat st;
        if (stat(g_game_sock, &st) == 0) return true;
        msleep(50);
    }
    return false;
}

/* ---------------------------------------------------------- e2e scenarios */

/* The seed this run's daemon minted, as read off the wire by
 * test_join_sends_world_info_then_sync(). test_restart_persists_diffs()
 * re-reads it after a restart to prove world_seed.txt is what makes a world
 * the *same* world across restarts. 0 means "not seen yet". */
static uint32_t g_seen_seed = 0;

static void test_join_sends_world_info_then_sync(void)
{
    puts("end-to-end: join gets WORLD_INFO first, then a WORLD_SYNC");
    drain();

    send_join(0xA11CE001u, "alice");

    /* The wire protocol has no separate "you're in" message — the 3DS
     * client's CSTATE_AWAIT_WELCOME (source/net/bsnet_transport.c) leaves
     * "connecting" only on its first authenticated packet from the server.
     * That packet is now BS_APP_WORLD_INFO: the client cannot generate any
     * terrain until it knows which world it joined, so the seed has to
     * arrive before anything that refers to a block position.
     *
     * alice never sends CHUNK_SUB in this test, so she is on the V127-A
     * legacy path (see BS_CHUNK_LEGACY_GRACE_MS above): the WORLD_SYNC that
     * follows only fires from tick()'s grace-window fallback, not
     * immediately from JOIN, so this has to wait for it rather than expect
     * it back-to-back with WORLD_INFO. It is still what tells a legacy
     * client the sync is complete — that is the regression test for the bug
     * where `send_world_sync()` sent nothing at all when the diff store was
     * empty. */
    uint8_t out[16];
    ssize_t n = recv_app_for(0xA11CE001u, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "the first packet after JOIN is WORLD_INFO");
    if (n == (ssize_t)BS_WORLD_INFO_BYTES) {
        g_seen_seed = bs_get_u32(out + 1);
        check(g_seen_seed != 0, "WORLD_INFO carries a non-zero world seed");
    }

    n = recv_app_for(0xA11CE001u, out, sizeof out, BS_CHUNK_LEGACY_GRACE_MS + 400u);
    check(n == (ssize_t)BS_WORLD_SYNC_BYTES(0) && out[0] == BS_APP_WORLD_SYNC,
          "a fresh, zero-diff world still sends one legacy-path WORLD_SYNC packet");
    if (n == (ssize_t)BS_WORLD_SYNC_BYTES(0)) {
        check(bs_get_u16(out + 1) == 0, "the empty sync declares count 0");
    }

    check(kill(g_daemon, 0) == 0, "daemon survives join with an empty world");
}

static void test_edit_broadcast_to_other_player_only(void)
{
    puts("end-to-end: accepted edit is broadcast to the OTHER player, not the sender");
    drain();

    send_join(0xB0B00002u, "bob");

    /* bob never sends CHUNK_SUB, so he is on the V127-A legacy path and
     * tick() will fire him a one-shot full WORLD_SYNC once
     * BS_CHUNK_LEGACY_GRACE_MS has passed since his JOIN. Wait that out and
     * drain it here, up front, rather than let it land in the middle of a
     * later test's "nothing arrives on bob's socket" window and read as a
     * false positive. */
    msleep(BS_CHUNK_LEGACY_GRACE_MS + 200u);
    drain();

    send_block_edit(0xA11CE001u, 5, 10, -5, 2 /* BLOCK_DIRT */);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_BLOCK_EDIT_BYTES && out[0] == BS_APP_BLOCK_EDIT,
          "the other player receives the edit");
    if (n == (ssize_t)BS_BLOCK_EDIT_BYTES) {
        check(bs_get_i32(out + 1) == 5 && bs_get_i32(out + 5) == 10
              && bs_get_i32(out + 9) == -5 && out[13] == 2,
              "broadcast edit carries the exact coordinates and block id");
    }

    /* The sender (alice) must not see her own edit echoed back. */
    n = recv_app_for(0xA11CE001u, out, sizeof out, 300);
    check(n < 0, "the edit is not echoed back to the sender");
}

static void test_invalid_block_id_rejected(void)
{
    puts("end-to-end: invalid block id is rejected, not applied or broadcast");
    drain();

    send_block_edit(0xA11CE001u, 1, 1, 1, 200 /* far past BLOCK_COUNT */);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 400);
    check(n < 0, "no broadcast for an invalid block id");
}

/* The boundary, not a wild value. test_invalid_block_id_rejected() above uses 200,
 * which every version of BS_BLOCK_COUNT this server has ever had would refuse — so it
 * passed happily while the server was refusing BLOCK_PLANKS as well. The two ids that
 * actually distinguish a correct BS_BLOCK_COUNT from a stale one are the highest legal
 * block and the one just past it, so those are the two this checks. Goes red on
 * BS_BLOCK_COUNT 7 (planks silently dropped) and on 9 (a nonexistent block accepted). */
static void test_highest_block_id_is_accepted(void)
{
    puts("end-to-end: the highest legal block id is accepted and the next one is not");
    drain();

    /* Column (312, 312), which nothing else in this file touches. Both edits below
     * land in the authoritative diff store and stay there for the rest of the run, so
     * putting them anywhere near the origin makes the later CHUNK_SUB tests — which
     * assert an exact diff count for their column — fail for a reason that has nothing
     * to do with what they are testing. */
    send_block_edit(0xA11CE001u, 5000, 12, 5000, BS_BLOCK_COUNT - 1 /* BLOCK_PLANKS */);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_BLOCK_EDIT_BYTES && out[0] == BS_APP_BLOCK_EDIT
          && out[13] == (uint8_t)(BS_BLOCK_COUNT - 1),
          "an edit placing the highest legal block id is broadcast");

    drain();
    send_block_edit(0xA11CE001u, 5001, 12, 5001, BS_BLOCK_COUNT /* one past the end */);
    n = recv_app_for(0xB0B00002u, out, sizeof out, 400);
    check(n < 0, "an edit one past the highest legal block id is dropped");
}

static void test_out_of_range_coordinate_rejected(void)
{
    puts("end-to-end: absurd coordinate is rejected");
    drain();

    send_block_edit(0xA11CE001u, 2000000000, 5, 0, 1);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 400);
    check(n < 0, "no broadcast for a coordinate far outside the world");
}

static void test_out_of_range_y_rejected(void)
{
    puts("end-to-end: y outside the 128-block world is rejected");
    drain();

    send_block_edit(0xA11CE001u, 0, 500, 0, 1);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 400);
    check(n < 0, "no broadcast for y >= WORLD_HEIGHT");
}

static void test_edit_rate_limited(void)
{
    puts("end-to-end: an edit flood past the burst is rate-limited");
    drain();

    /* Send far more than the burst, as fast as this process can, and count how
     * many the other player actually sees broadcast. */
    const uint64_t t0 = now_ms();

    for (int i = 0; i < 200; i++) {
        send_block_edit(0xA11CE001u, 300 + i, 10, 300, 3);
    }

    unsigned seen = 0;
    uint8_t out[64];
    for (;;) {
        ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 150);
        if (n < 0) break;
        seen++;
    }

    /* The ceiling is not a bare BS_EDIT_BURST. The bucket refills one token
     * every BS_EDIT_REFILL_MS while the flood is still in flight, so a host
     * that needs longer than one refill interval to push and drain 200 packets
     * legitimately sees a few more than the burst. Hardcoding 40 encoded the
     * speed of one particular machine and failed the install on a slower one
     * that was behaving correctly (it saw 41).
     *
     * The 150 ms poll timeout that ends the drain loop above is subtracted:
     * nothing was being sent during it, so it must not buy the server extra
     * tokens. The +1 covers the partial interval at either end. An unlimited
     * server still broadcasts ~200 here, so this stays able to go red. */
    const uint64_t elapsed = now_ms() - t0;
    const uint64_t flood   = (elapsed > 150) ? elapsed - 150 : 0;
    const unsigned ceiling = BS_EDIT_BURST + (unsigned)(flood / BS_EDIT_REFILL_MS) + 1;

    check(seen > 0 && seen <= ceiling, "far fewer edits arrive than were sent, capped near the burst");
    printf("        sent 200, broadcast %u (ceiling %u for a %llu ms flood)\n",
           seen, ceiling, (unsigned long long)flood);
}

static void test_leave_frees_slot_and_stops_broadcasts(void)
{
    puts("end-to-end: LEAVE removes the player");
    drain();
    msleep(700);   /* let the edit-rate bucket refill from the flood test */
    drain();

    send_leave(0xB0B00002u);
    msleep(100);

    /* Bob is gone; alice's edit must reach nobody now. There is no third
     * socket to prove a negative against directly, so this is proven by
     * bob rejoining under a new sid afterward and getting a fresh
     * WORLD_SYNC — see test_world_sync_after_edits. Here we only confirm
     * the daemon is still healthy and alice can still edit. */
    send_block_edit(0xA11CE001u, 9, 9, 9, 1);
    check(kill(g_daemon, 0) == 0, "daemon survives a LEAVE for a departed player");
}

static void test_world_sync_after_edits(void)
{
    puts("end-to-end: a new joiner receives the accumulated diffs via WORLD_SYNC");
    drain();

    send_join(0xB0B00003u, "bob2");

    /* bob2 never sends CHUNK_SUB either, so this is still exercising the
     * legacy path — see BS_CHUNK_LEGACY_GRACE_MS above. Give tick()'s
     * grace-window fallback time to fire before starting to collect, so the
     * first recv_app_for's own timeout below isn't racing it. */
    msleep(BS_CHUNK_LEGACY_GRACE_MS + 200u);

    /* By now alice has made several accepted edits across the earlier
     * cases: (5,10,-5), (9,9,9), plus whatever survived the rate-limit
     * flood. Collect every WORLD_SYNC batch bob2 receives. */
    uint32_t total = 0;
    bool saw_first_edit = false;
    for (;;) {
        uint8_t out[2048];
        ssize_t n = recv_app_for(0xB0B00003u, out, sizeof out, 500);
        if (n < 0) break;
        if (n < 3 || out[0] != BS_APP_WORLD_SYNC) continue;

        uint16_t count = bs_get_u16(out + 1);
        for (uint16_t i = 0; i < count; i++) {
            const uint8_t *e = out + 3 + (size_t)i * BS_SYNC_ENTRY_BYTES;
            if (bs_get_i32(e) == 5 && bs_get_i32(e + 4) == 10 && bs_get_i32(e + 8) == -5) {
                saw_first_edit = true;
            }
        }
        total += count;
    }

    check(total > 0, "WORLD_SYNC delivers at least one diff to a new joiner");
    check(saw_first_edit, "WORLD_SYNC includes an edit made before this player joined");
}

static void test_pos_update_relay(void)
{
    puts("end-to-end: position updates relay to other players, tagged with the sender's sid");
    drain();

    send_pos_update(0xA11CE001u, 12.5f, 64.0f, -3.25f, 1.5f, -0.25f);

    uint8_t out[64];
    ssize_t n = -1;
    /* The tick loop is 100ms; give it a couple of ticks. */
    for (int i = 0; i < 5 && n < 0; i++) {
        n = recv_app_for(0xB0B00003u, out, sizeof out, 150);
    }
    check(n == (ssize_t)BS_POS_UPDATE_S_BYTES && out[0] == BS_APP_POS_UPDATE,
          "another player receives the relayed position");
    if (n == (ssize_t)BS_POS_UPDATE_S_BYTES) {
        check(bs_get_u32(out + 1) == 0xA11CE001u, "relayed position is tagged with alice's sid");
        float x = bs_get_f32(out + 5), y = bs_get_f32(out + 9), z = bs_get_f32(out + 13);
        check(x == 12.5f && y == 64.0f && z == -3.25f, "relayed position values are exact");
    }

    /* alice must not receive her own position back. */
    n = recv_app_for(0xA11CE001u, out, sizeof out, 300);
    check(n < 0, "position is not relayed back to its own sender");
}

static void test_malformed_payload_kicks(void)
{
    puts("end-to-end: a structurally malformed application message gets KICKed");
    drain();

    send_join(0xDEAD0004u, "mallory");
    msleep(100);
    drain();

    /* One byte, an unknown app-message type. */
    uint8_t junk[1] = { 0x7f };
    send_app(0xDEAD0004u, junk, sizeof junk);

    uint8_t buf[64];
    ssize_t n = gate_recv(buf, sizeof buf, 500);
    check(n == 5 && buf[0] == BS_GAME_KICK && bs_get_u32(buf + 1) == 0xDEAD0004u,
          "unknown application message type is KICKed");
}

static void test_malformed_block_edit_length_kicks(void)
{
    puts("end-to-end: a BLOCK_EDIT with the wrong length gets KICKed, not just dropped");
    drain();

    send_join(0xDEAD0005u, "trudy");
    msleep(100);
    drain();

    uint8_t junk[6] = { BS_APP_BLOCK_EDIT, 1, 2, 3, 4, 5 };   /* far too short */
    send_app(0xDEAD0005u, junk, sizeof junk);

    uint8_t buf[64];
    ssize_t n = gate_recv(buf, sizeof buf, 500);
    check(n == 5 && buf[0] == BS_GAME_KICK && bs_get_u32(buf + 1) == 0xDEAD0005u,
          "wrong-length BLOCK_EDIT is KICKed");
}

static void test_restart_persists_diffs(void)
{
    puts("end-to-end: diffs survive a restart");

    stop_daemon();
    start_daemon();
    if (!wait_ready(5000)) { fprintf(stderr, "test: restarted daemon never became ready\n"); exit(1); }
    drain();

    send_join(0xF00D0006u, "newcomer");

    /* "newcomer" never sends CHUNK_SUB, so — same as test_world_sync_after_edits
     * above — this is the legacy path, and the full-dump WORLD_SYNC only
     * fires once tick()'s grace window elapses. */
    msleep(BS_CHUNK_LEGACY_GRACE_MS + 200u);

    uint32_t total = 0;
    uint32_t seed_after_restart = 0;
    bool saw_edit = false;
    for (;;) {
        uint8_t out[2048];
        ssize_t n = recv_app_for(0xF00D0006u, out, sizeof out, 500);
        if (n < 0) break;
        if (n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO) {
            seed_after_restart = bs_get_u32(out + 1);
            continue;
        }
        if (n < 3 || out[0] != BS_APP_WORLD_SYNC) continue;
        uint16_t count = bs_get_u16(out + 1);
        for (uint16_t i = 0; i < count; i++) {
            const uint8_t *e = out + 3 + (size_t)i * BS_SYNC_ENTRY_BYTES;
            if (bs_get_i32(e) == 5 && bs_get_i32(e + 4) == 10 && bs_get_i32(e + 8) == -5) {
                saw_edit = true;
            }
        }
        total += count;
    }

    check(total > 0, "diffs made before the restart are present after it");
    check(saw_edit, "the specific (5,10,-5) edit survived the restart");

    /* The diffs are only meaningful against the terrain they were carved out
     * of, and that terrain is generated client-side from the seed. A restart
     * that kept the diffs but re-minted the seed would hand a rejoining
     * player somebody else's holes in the wrong hillside. */
    check(seed_after_restart != 0 && seed_after_restart == g_seen_seed,
          "the world seed is the same one after a restart");
}

/* Runs right after test_restart_persists_diffs, where the daemon has just
 * restarted and "newcomer" (0xF00D0006) is the only connected player — a
 * known, simple state to assert `players` and the player line against,
 * rather than tracking every earlier test's joins/leaves/kicks. */
static void test_status_snapshot(void)
{
    puts("SIGUSR1 status snapshot");

    char status_path[192];
    snprintf(status_path, sizeof status_path, "%s/status.txt", g_dir);
    unlink(status_path);   /* a stale file from a previous run must not pass this test */

    if (kill(g_daemon, SIGUSR1) != 0) die("kill SIGUSR1");

    /* write_status() only runs on the daemon's next poll() wakeup, which is
     * at most one tick away, but give it real headroom rather than exactly
     * the tick period. */
    bool appeared = false;
    struct stat st;
    for (unsigned waited = 0; waited < 2000; waited += 50) {
        if (stat(status_path, &st) == 0) { appeared = true; break; }
        msleep(50);
    }
    check(appeared, "status.txt appears after SIGUSR1");
    if (!appeared) return;

    check((st.st_mode & 0777) == 0640, "status.txt is mode 0640");

    FILE *f = fopen(status_path, "r");
    check(f != NULL, "status.txt opens");
    if (f == NULL) return;

    char line[256];
    check(fgets(line, sizeof line, f) != NULL && !strcmp(line, "process bsgame\n"),
          "first line identifies the process");

    bool saw_players_line = false, players_match = false, saw_newcomer_line = false;
    while (fgets(line, sizeof line, f) != NULL) {
        unsigned n;
        if (sscanf(line, "players %u", &n) == 1) {
            saw_players_line = true;
            players_match = (n == 1);
        }
        if (!strncmp(line, "player ", 7) && strstr(line, "newcomer") != NULL) {
            saw_newcomer_line = true;
        }
    }
    fclose(f);

    check(saw_players_line && players_match, "players count matches the one connected player");
    check(saw_newcomer_line, "a player line names the connected player's label");
}

static void test_disk_format(void)
{
    puts("on-disk format");
    char path[192];
    snprintf(path, sizeof path, "%s/block_diffs.bin", g_dir);

    FILE *f = fopen(path, "rb");
    check(f != NULL, "block_diffs.bin exists");
    if (f == NULL) return;

    char magic[8];
    check(fread(magic, 1, 8, f) == 8 && !memcmp(magic, "BSGDIFF1", 8), "file starts with the magic");

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    check(size >= 8 && (size - 8) % 16 == 0,
          "body is a whole number of 16-byte records (compacted, no stray bytes)");
    fclose(f);
}

/* -------------------------------------------------------- V127-A: CHUNK_SUB
 *
 * Placed after test_disk_format rather than interleaved with the earlier
 * tests: test_status_snapshot depends on "newcomer" being the *only*
 * connected player right after test_restart_persists_diffs (see its own
 * header comment), and every scenario below joins its own new player without
 * ever sending LEAVE, which would break that invariant if inserted earlier. */

/* Reads one BS_APP_CHUNK_DIFFS packet addressed to `sid` and unpacks its
 * header. `entries_out` must hold room for BS_CHUNK_DIFFS_MAX_ENTRIES; pass
 * NULL to skip copying entries out when a test only cares about the header. */
static bool recv_chunk_diffs_for(uint32_t sid, int32_t want_cx, int32_t want_cz,
                                 unsigned ms, uint8_t *flags_out, uint16_t *count_out,
                                 uint8_t entries_out[][BS_SYNC_ENTRY_BYTES])
{
    uint8_t out[BS_CHUNK_DIFFS_BYTES(BS_CHUNK_DIFFS_MAX_ENTRIES)];
    ssize_t n = recv_app_for(sid, out, sizeof out, ms);
    if (n < (ssize_t)BS_CHUNK_DIFFS_HDR_BYTES || out[0] != BS_APP_CHUNK_DIFFS) return false;

    int32_t cx = bs_get_i32(out + 1);
    int32_t cz = bs_get_i32(out + 5);
    if (cx != want_cx || cz != want_cz) return false;

    uint8_t  flags = out[9];
    uint16_t count = bs_get_u16(out + 10);
    if ((size_t)n != BS_CHUNK_DIFFS_BYTES(count)) return false;

    if (flags_out != NULL) *flags_out = flags;
    if (count_out != NULL) *count_out = count;
    if (entries_out != NULL) {
        for (uint16_t i = 0; i < count; i++) {
            memcpy(entries_out[i], out + BS_CHUNK_DIFFS_HDR_BYTES + (size_t)i * BS_SYNC_ENTRY_BYTES,
                   BS_SYNC_ENTRY_BYTES);
        }
    }
    return true;
}

/* Column (0, -1) — bs_col_of(5) = 0, bs_col_of(-5) = -1 — holds exactly one
 * diff at this point in the suite: (5,10,-5)=2, made by
 * test_edit_broadcast_to_other_player_only and never touched since. Chosen
 * deliberately, instead of a synthetic edit made just for this test, to also
 * prove CHUNK_SUB reaches into diffs that predate the subscription, not just
 * ones made after it — the same thing WORLD_SYNC has always had to prove for
 * the legacy path (see test_world_sync_after_edits). */
static void test_chunk_sub_delivers_scoped_diffs(void)
{
    puts("end-to-end: CHUNK_SUB returns only the subscribed column's diffs, chunked and LAST-flagged");
    drain();

    send_join(0xCA501001u, "carol");
    msleep(100);
    drain();

    send_chunk_sub(0xCA501001u, 0, -1);

    uint8_t  flags = 0xff;
    uint16_t count = 0;
    static uint8_t entries[BS_CHUNK_DIFFS_MAX_ENTRIES][BS_SYNC_ENTRY_BYTES];
    bool got = recv_chunk_diffs_for(0xCA501001u, 0, -1, 500, &flags, &count, entries);
    check(got, "CHUNK_SUB for a column with one diff gets a CHUNK_DIFFS reply for that column");
    if (got) {
        check((flags & BS_CHUNK_DIFFS_LAST) != 0, "single-batch reply is flagged LAST");
        check(count == 1, "the reply carries exactly the one diff in this column");
        if (count == 1) {
            check(bs_get_i32(entries[0]) == 5 && bs_get_i32(entries[0] + 4) == 10
                  && bs_get_i32(entries[0] + 8) == -5 && entries[0][12] == 2,
                  "the diff's coordinates and block id are exact");
        }
    }

    /* An empty column still gets exactly one packet, count 0, LAST set —
     * the same "empty is not the same as still coming" contract WORLD_SYNC
     * already has to honour for a fresh world (see
     * test_join_sends_world_info_then_sync). Column (777, 777) has never
     * been touched by any edit anywhere in this suite. */
    send_chunk_sub(0xCA501001u, 777, 777);
    got = recv_chunk_diffs_for(0xCA501001u, 777, 777, 500, &flags, &count, NULL);
    check(got, "CHUNK_SUB for an untouched column still gets a CHUNK_DIFFS reply");
    if (got) {
        check(count == 0, "an untouched column reports zero diffs");
        check((flags & BS_CHUNK_DIFFS_LAST) != 0, "the zero-diff reply is still flagged LAST");
    }
}

/* Regression test for the legacy-fallback interaction: a player who DOES
 * send CHUNK_SUB must never also receive the old full-dump WORLD_SYNC from
 * tick()'s grace-window fallback — that would defeat the entire purpose of
 * scoping (see BS_CHUNK_LEGACY_GRACE_MS's comment in bsgame.c). carol has
 * already subscribed above, well within the grace window; this proves the
 * fallback stays suppressed for her all the way past it. */
static void test_chunk_sub_suppresses_legacy_world_sync(void)
{
    puts("end-to-end: a CHUNK_SUB client never receives the legacy full WORLD_SYNC");
    drain();

    msleep(BS_CHUNK_LEGACY_GRACE_MS + 300u);

    uint8_t out[2048];
    ssize_t n = recv_app_for(0xCA501001u, out, sizeof out, 300);
    check(n < 0, "nothing arrives on carol's socket well past the legacy grace window");
}

/* dave subscribes to column (0, -1) only. An edit inside that column must
 * reach him; an edit in a different column must not. "newcomer"
 * (0xF00D0006u, joined back in test_restart_persists_diffs, still connected,
 * and never having sent CHUNK_SUB — both alice and bob2 were players in the
 * pre-restart daemon process and no longer exist after it) is checked
 * alongside dave on both edits as a control: she is on the legacy path and
 * must keep receiving every edit unscoped, proving the column check in
 * broadcast_block_edit() only applies to chunk-aware players.
 *
 * The edits themselves need their own sender, joined fresh here rather than
 * reusing alice — alice's session, like bob2's, was wiped by the restart. */
static void test_chunk_edit_broadcast_is_scoped_to_subscribers(void)
{
    puts("end-to-end: a live edit broadcasts only to players subscribed to its column");
    drain();

    send_join(0xA11CE002u, "alice2");
    msleep(100);
    drain();

    send_join(0xDA4E1002u, "dave");
    msleep(100);
    drain();

    send_chunk_sub(0xDA4E1002u, 0, -1);
    uint8_t flags = 0; uint16_t count = 0;
    check(recv_chunk_diffs_for(0xDA4E1002u, 0, -1, 500, &flags, &count, NULL),
          "dave's CHUNK_SUB for (0,-1) is acknowledged before the live-edit checks below");
    drain();

    /* (6, 11, -6) is also column (0, -1): bs_col_of(6) = 0, bs_col_of(-6) = -1.
     * Both recipients are checked from ONE recv_app_for_two call, not two
     * separate recv_app_for calls — see that helper's header comment for why
     * a plain recv_app_for(dave, ...) followed by recv_app_for(newcomer, ...)
     * is unsafe here: whichever of the two packets happens to arrive first
     * would be silently discarded while the first call keeps waiting for the
     * other sid. */
    send_block_edit(0xA11CE002u, 6, 11, -6, 4);

    uint8_t out_dave[64], out_newcomer[64];
    ssize_t n_dave, n_newcomer;
    recv_app_for_two(0xDA4E1002u, out_dave, sizeof out_dave, &n_dave,
                     0xF00D0006u, out_newcomer, sizeof out_newcomer, &n_newcomer, 500);
    check(n_dave == (ssize_t)BS_BLOCK_EDIT_BYTES && out_dave[0] == BS_APP_BLOCK_EDIT
          && bs_get_i32(out_dave + 1) == 6 && bs_get_i32(out_dave + 5) == 11
          && bs_get_i32(out_dave + 9) == -6,
          "dave receives an edit inside his subscribed column");
    check(n_newcomer == (ssize_t)BS_BLOCK_EDIT_BYTES && out_newcomer[0] == BS_APP_BLOCK_EDIT,
          "newcomer (legacy, unsubscribed) also receives it — legacy clients stay unscoped");

    /* (800, 11, 800) is column (50, 50) — nowhere near dave's subscription.
     * dave's half of this pair is expected to time out (n_dave < 0), so the
     * full 400ms has to elapse either way; newcomer's packet, if it arrives
     * first, must not be thrown away while that wait plays out. */
    send_block_edit(0xA11CE002u, 800, 11, 800, 5);

    recv_app_for_two(0xDA4E1002u, out_dave, sizeof out_dave, &n_dave,
                     0xF00D0006u, out_newcomer, sizeof out_newcomer, &n_newcomer, 400);
    check(n_dave < 0, "dave does NOT receive an edit outside his subscribed column");
    check(n_newcomer == (ssize_t)BS_BLOCK_EDIT_BYTES && out_newcomer[0] == BS_APP_BLOCK_EDIT,
          "newcomer still receives it regardless — confirms the miss above is scoping, not a lost packet");
}

/* Continues directly from the state test_chunk_edit_broadcast_is_scoped_to_subscribers
 * left behind: dave is still subscribed to column (0, -1), and alice2 is
 * still connected as the edit sender. */
static void test_chunk_unsub_stops_future_column_edits(void)
{
    puts("end-to-end: CHUNK_UNSUB stops future edits for that column from reaching the player");
    drain();

    send_chunk_unsub(0xDA4E1002u, 0, -1);
    msleep(100);
    drain();

    /* Same column as the earlier subscribed-edit case, so a failure here
     * against a successful reception there isolates UNSUB as the cause.
     * Paired the same way as above, and for the same reason: dave's half of
     * this pair is expected to time out, and newcomer's packet must not be
     * discarded while that wait runs. */
    send_block_edit(0xA11CE002u, 7, 12, -7, 6);

    uint8_t out_dave[64], out_newcomer[64];
    ssize_t n_dave, n_newcomer;
    recv_app_for_two(0xDA4E1002u, out_dave, sizeof out_dave, &n_dave,
                     0xF00D0006u, out_newcomer, sizeof out_newcomer, &n_newcomer, 500);
    check(n_dave < 0, "dave no longer receives edits for a column he unsubscribed from");
    check(n_newcomer == (ssize_t)BS_BLOCK_EDIT_BYTES && out_newcomer[0] == BS_APP_BLOCK_EDIT,
          "newcomer (legacy) still receives it — UNSUB affects only the unsubscribing player");
}

static void test_malformed_chunk_sub_and_unsub_kick(void)
{
    puts("end-to-end: wrong-length CHUNK_SUB / CHUNK_UNSUB gets KICKed, not just dropped");
    drain();

    send_join(0xBAD00007u, "eve");
    msleep(100);
    drain();

    uint8_t short_sub[3] = { BS_APP_CHUNK_SUB, 1, 2 };   /* far too short for BS_CHUNK_SUB_BYTES */
    send_app(0xBAD00007u, short_sub, sizeof short_sub);

    uint8_t buf[64];
    ssize_t n = gate_recv(buf, sizeof buf, 500);
    check(n == 5 && buf[0] == BS_GAME_KICK && bs_get_u32(buf + 1) == 0xBAD00007u,
          "wrong-length CHUNK_SUB is KICKed");

    send_join(0xBAD00008u, "mallory2");
    msleep(100);
    drain();

    uint8_t short_unsub[3] = { BS_APP_CHUNK_UNSUB, 1, 2 };
    send_app(0xBAD00008u, short_unsub, sizeof short_unsub);

    n = gate_recv(buf, sizeof buf, 500);
    check(n == 5 && buf[0] == BS_GAME_KICK && bs_get_u32(buf + 1) == 0xBAD00008u,
          "wrong-length CHUNK_UNSUB is KICKed");
}

/* ------------------------------------------------------------------- main */

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
    setvbuf(stdout, NULL, _IONBF, 0);

    atexit(reap_daemon);
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGBUS,  crash_handler);

    snprintf(g_dir, sizeof g_dir, "/tmp/bsgame_test_%d", (int)getpid());
    if (mkdir(g_dir, 0700) != 0) die("mkdir state dir");

    puts("== bsgame test ==");

    set_sock_paths();
    open_sockets();
    start_daemon();
    if (!wait_ready(5000)) {
        fprintf(stderr, "test: daemon never became ready\n");
        reap_daemon();
        return 1;
    }

    test_join_sends_world_info_then_sync();
    test_edit_broadcast_to_other_player_only();
    test_invalid_block_id_rejected();
    test_highest_block_id_is_accepted();
    test_out_of_range_coordinate_rejected();
    test_out_of_range_y_rejected();
    test_edit_rate_limited();
    test_leave_frees_slot_and_stops_broadcasts();
    test_world_sync_after_edits();
    test_pos_update_relay();
    test_malformed_payload_kicks();
    test_malformed_block_edit_length_kicks();
    test_restart_persists_diffs();
    test_status_snapshot();
    test_disk_format();

    test_chunk_sub_delivers_scoped_diffs();
    test_chunk_sub_suppresses_legacy_world_sync();
    test_chunk_edit_broadcast_is_scoped_to_subscribers();
    test_chunk_unsub_stops_future_column_edits();
    test_malformed_chunk_sub_and_unsub_kick();

    stop_daemon();

    if (g_fails == 0) {
        char rm[256];
        snprintf(rm, sizeof rm, "rm -rf %s", g_dir);
        if (system(rm) != 0) { /* best effort */ }
    } else {
        printf("state dir kept at %s\n", g_dir);
    }

    printf("\n%s %d checks, %d failed\n", g_fails == 0 ? "PASS" : "FAIL", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
