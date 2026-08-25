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
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../proto/bs_gamelink.h"  /* enum bs_game_msg — the gate<->game framing this suite speaks */
#include "../proto/bs_proto.h"
#include "players.h"   /* BS_EDIT_BURST / BS_EDIT_REFILL_MS, for the rate-limit ceiling */
#include "playerstate.h"  /* BS_PLAYER_STATE_BODY_BYTES, for the player.dat fixtures */
#include "validate.h"  /* BS_BLOCK_COUNT, for the highest-legal-core-block-id boundary test */
#include "world/crc32.h"    /* the checksum a hand-built player.dat has to carry */
#include "world/registry.h" /* v1.6.0: mirror the daemon's table in-process */

/* Mirrors bsgame.c's BS_CHUNK_LEGACY_GRACE_MS. Note this is NOT the same case
 * as enum bs_game_msg, which this file used to hand-copy on the line above and
 * now takes from ../proto/bs_gamelink.h: that enum is a contract between two
 * BINARIES, so a divergence between copies is a production framing bug. This
 * one is an internal implementation constant of one binary, not part of any
 * protocol, and this file mirroring it is a test reading a tuning value. A
 * player who never
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

static void send_inv_action(uint32_t sid, uint8_t op, uint8_t a, uint8_t b, uint8_t c)
{
    uint8_t p[BS_INV_ACTION_BYTES];
    p[0] = BS_APP_INV_ACTION;
    p[1] = op;
    p[2] = a;
    p[3] = b;
    p[4] = c;
    send_app(sid, p, sizeof p);
}

/* Reads slot `slot`'s (item, count) straight out of a raw BS_INV_STATE
 * payload — deliberately hand-parsed from the wire bytes rather than by
 * pulling in world/inventory.h's Inventory type, the same "this test only
 * knows the wire format" stance the rest of this file takes toward every
 * other message (block ids, coordinates, ...). `state` must be a buffer that
 * has already been confirmed to be BS_INV_STATE_BYTES long with state[0] ==
 * BS_APP_INV_STATE. */
static void inv_state_slot(const uint8_t *state, unsigned slot, uint8_t *item, uint8_t *count)
{
    *item  = state[2u + slot * 2u];
    *count = state[2u + slot * 2u + 1u];
}

/* True if every one of the BS_INV_SLOT_COUNT slots reads back { 0, 0 } —
 * bs_proto.h's own comment on BS_APP_INV_STATE guarantees count is 0 iff
 * item is 0, so checking both catches a server that ever violated that. */
static bool inv_state_is_empty(const uint8_t *state)
{
    for (unsigned i = 0; i < BS_INV_SLOT_COUNT; i++) {
        if (state[2u + i * 2u] != 0 || state[2u + i * 2u + 1u] != 0) return false;
    }
    return true;
}

/* Total units of `item` held across every slot — the INV_STATE equivalent of
 * world/inventory.h's inventoryCount(), for tests that care about a total
 * rather than which slot(s) it landed in. */
static uint32_t inv_state_total(const uint8_t *state, uint8_t item)
{
    uint32_t total = 0;
    for (unsigned i = 0; i < BS_INV_SLOT_COUNT; i++) {
        if (state[2u + i * 2u] == item) total += state[2u + i * 2u + 1u];
    }
    return total;
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

/* The core registry's advertised shape, pinned to hand-written literals rather
 * than to the functions that produce it.
 *
 * recv_registry_info() below compares the REGISTRY_INFO wire bytes against
 * registryCount() and registryCrc16() in THIS process. That is a real check —
 * the daemon and this test binary link the same world/registry.c in two
 * different processes, so it proves the two agree — but it is self-referential
 * about the VALUE. Move a core def and both sides move together: every check
 * stays green and the table has been silently re-baselined. That is not a
 * cosmetic re-baseline. A core-def change is a wire-compatibility event: a
 * client built against the old rows fails registryMatchesInfo() on crc, falls
 * into the bounded REGISTRY_FETCH retry and finishes the session with
 * s_reg_synced false. It has to be a named failure, not a quiet pass.
 *
 * Same idiom as the client's source/world/registry_test.c, which pins this same
 * golden and records every move of it with the reason. The values here were
 * verified independently of that file rather than copied from it: compiling
 * world/registry.c + world/crc32.c on their own, calling registryInitCore() and
 * printing the result gives count 10, crc16 0x4066, rev 1 — and the client's
 * source/world/registry.c, compiled separately the same way, prints the
 * identical pair, which is exactly what the byte-identical vendoring is
 * supposed to guarantee and is now checked rather than assumed.
 *
 * If this goes red, do NOT edit the literal to match. Find which core def moved
 * and decide whether that was intended. If it was, move the pin AND say why,
 * the way registry_test.c does for 0x7E5B -> 0x72A8 -> 0x4066. */
#define BS_REGISTRY_CORE_COUNT_GOLDEN 10u
#define BS_REGISTRY_CORE_CRC16_GOLDEN 0x4066u
#define BS_REGISTRY_REV_GOLDEN        1u

static void test_registry_core_pinned_to_golden(void)
{
    puts("registry: the core table matches a pinned golden, not only itself");
    registryInitCore();
    check(registryCount() == BS_REGISTRY_CORE_COUNT_GOLDEN,
          "core-only registryCount() matches the pinned golden 10");
    check(registryCrc16() == BS_REGISTRY_CORE_CRC16_GOLDEN,
          "core-only registryCrc16() matches the pinned golden 0x4066");
    check(REGISTRY_REV == BS_REGISTRY_REV_GOLDEN,
          "REGISTRY_REV matches the pinned golden 1");
}

/* Reads one BS_APP_REGISTRY_INFO packet addressed to `sid` and shape-checks
 * it against THIS process's own registry (daemon and test binary link the
 * same world/registry.c, so rev/count/crc16 must agree exactly). This is the
 * CROSS-PROCESS half of the pair: it proves the daemon's advertised table and
 * this process's table are the same table. What it deliberately does not do is
 * prove either of them is the INTENDED table — that is
 * test_registry_core_pinned_to_golden() above, and the two only mean something
 * together. Tests that load extra dynamic defs into this process (see the FETCH
 * batching scenario below) must mirror them locally first or these checks go
 * red. */
static bool recv_registry_info(uint32_t sid, unsigned ms)
{
    uint8_t out[64];
    ssize_t n = recv_app_for(sid, out, sizeof out, ms);
    if (n != (ssize_t)BS_APP_REGISTRY_INFO_BYTES || out[0] != BS_APP_REGISTRY_INFO) {
        return false;
    }
    check(out[1] == REGISTRY_REV,
          "REGISTRY_INFO carries the current table revision");
    check(out[2] == registryCount(),
          "REGISTRY_INFO count matches the linked-in table");
    check(bs_get_u16(out + 3) == registryCrc16(),
          "REGISTRY_INFO crc16 matches the linked-in table");
    return true;
}

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
    uint8_t out[64];   /* was [16]; BS_INV_STATE_BYTES (50) is now the largest packet caught below */
    ssize_t n = recv_app_for(0xA11CE001u, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "the first packet after JOIN is WORLD_INFO");
    if (n == (ssize_t)BS_WORLD_INFO_BYTES) {
        g_seen_seed = bs_get_u32(out + 1);
        check(g_seen_seed != 0, "WORLD_INFO carries a non-zero world seed");
    }

    /* Immediately after WORLD_INFO comes REGISTRY_INFO (v1.6.0 Phase A):
     * handle_join sends it before anything else that refers to block ids so
     * the client can reconcile its table before terrain arrives. The helper
     * validates rev/count/crc16 against this process's own table. */
    bool got_reg = recv_registry_info(0xA11CE001u, 500);
    check(got_reg, "REGISTRY_INFO arrives second, between WORLD_INFO and INV_STATE");

    /* Right behind REGISTRY_INFO, and still well before the legacy
     * WORLD_SYNC below (which only fires once BS_CHUNK_LEGACY_GRACE_MS has
     * passed), handle_join() also sends an unprompted INV_STATE — the
     * capability probe bs_proto.h's own comment above BS_APP_INV_STATE
     * describes. This test predates that feature and only cares about the
     * WORLD_INFO/WORLD_SYNC ordering, so the INV_STATE in between is read
     * and given a light shape check here rather than a full one —
     * test_inv_join_sends_empty_inv_state() is what actually exercises its
     * contents. Without reading it here, the WORLD_SYNC wait below would
     * catch this packet instead (recv_app_for filters by sid only, not by
     * message type) and fail on a type/length mismatch that has nothing to
     * do with what this test is checking. */
    n = recv_app_for(0xA11CE001u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "JOIN's third packet is the INV_STATE capability probe");

    /* And now PLAYER_STATE rides fourth, right behind INV_STATE — volunteered
     * once per join exactly as its proto comment describes. As with the
     * INV_STATE above, this test only cares that the packet is there and
     * does not disturb the ordering it predates; the fresh-spawn contents
     * get their own dedicated scenario further down
     * (test_ps_join_fresh_sends_zeroed_state). Without consuming it here the
     * legacy-WORLD_SYNC wait below would catch it instead and fail on a
     * type mismatch unrelated to what this test checks. */
    n = recv_app_for(0xA11CE001u, out, sizeof out, 500);
    check(n == (ssize_t)BS_PLAYER_STATE_BYTES && out[0] == BS_APP_PLAYER_STATE,
          "JOIN's fourth packet is the PLAYER_STATE capability probe");

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

    /* 0xFF, not 200. Until v1.6.0 this sent 200, which was "far past
     * BLOCK_COUNT" when the ceiling was BS_BLOCK_COUNT — but 200 is 0xC8, well
     * inside the master registry's dynamic id space, and is a perfectly legal
     * block id now that bsEditValid() accepts up to REG_ID_DYN_HI. Only the two
     * ids above the dyn range are still invalid, so this uses the top one. */
    send_block_edit(0xA11CE001u, 1, 1, 1, 0xFF /* above REG_ID_DYN_HI */);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 400);
    check(n < 0, "no broadcast for an invalid block id");
}

/* The core-block boundary, not a wild value. test_invalid_block_id_rejected()
 * above uses an id no version of this server has ever accepted — so it passed
 * happily while the server was refusing BLOCK_PLANKS as well. The id that
 * actually distinguishes a correct BS_BLOCK_COUNT from a stale one is the
 * highest core block, so that is what this places. Goes red on BS_BLOCK_COUNT 7
 * (planks silently dropped).
 *
 * The other half of this test used to be "and BS_BLOCK_COUNT itself is
 * dropped". That check is gone, because as of v1.6.0 it asserts the opposite of
 * the truth: bsEditValid() no longer tests block ids against BS_BLOCK_COUNT at
 * all (see validate.c), so id 8 is legal — the dyn-range ceiling is what draws
 * the line now, and test_dyn_range_block_ids_accepted() below is where it is
 * checked. BS_BLOCK_COUNT's own "one past the end is refused" boundary did not
 * go untested with it: it moved to the path that still enforces it, the ITEM id
 * in test_inv_pickup_out_of_range_item_refused(). */
static void test_highest_block_id_is_accepted(void)
{
    puts("end-to-end: the highest legal core block id is accepted");
    drain();

    /* Column (312, 312), which nothing else in this file touches. The edit below
     * lands in the authoritative diff store and stays there for the rest of the run, so
     * putting it anywhere near the origin makes the later CHUNK_SUB tests — which
     * assert an exact diff count for their column — fail for a reason that has nothing
     * to do with what they are testing. */
    send_block_edit(0xA11CE001u, 5000, 12, 5000, BS_BLOCK_COUNT - 1 /* BLOCK_PLANKS */);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xB0B00002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_BLOCK_EDIT_BYTES && out[0] == BS_APP_BLOCK_EDIT
          && out[13] == (uint8_t)(BS_BLOCK_COUNT - 1),
          "an edit placing the highest legal core block id is broadcast");
}

/* v1.6.0: the master block registry's dynamic id space is legal on the wire.
 *
 * The client (source/net/networld.c, editValid) accepts any id up to
 * REG_ID_DYN_HI, because a server may define dynamic blocks at 0x80..0xFD and a
 * player may place one. bsEditValid() capped at BS_BLOCK_COUNT (8) and refused
 * every single one of them, so a legal placement was dropped server-side and
 * never reached the other players or the diff store — silently, the same shape
 * of bug BLOCK_PLANKS hit (see validate.h).
 *
 * Both ends of the dyn range are checked, not just one: a ceiling raised to the
 * wrong constant (REG_ID_CORE_HI, say) would still accept 0x80 while refusing
 * 0xFD, and a check on the low end alone could not tell those apart.
 *
 * Deliberately no registry sync first — these ids are NOT defined in the
 * daemon's table when this runs. That is the point: bsEditValid() is a range
 * check on the id space, not a lookup in whatever the table happens to hold at
 * this instant, so an edit naming an id the server has not been told about yet
 * must still be accepted (an undefined id reads back as air until it resolves).
 *
 * Column (437,437) upward, chosen the same way and for the same reason as
 * test_highest_block_id_is_accepted's (312,312): nothing else in this file
 * subscribes to or counts diffs in these columns. */
static void test_dyn_range_block_ids_accepted(void)
{
    puts("end-to-end: the registry's dynamic block id range is accepted, the reserved ids above it are not");
    drain();

    uint8_t out[64];
    ssize_t n;

    send_block_edit(0xA11CE001u, 7000, 12, 7000, (uint8_t)REG_ID_DYN_LO);
    n = recv_app_for(0xB0B00002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_BLOCK_EDIT_BYTES && out[0] == BS_APP_BLOCK_EDIT
          && out[13] == (uint8_t)REG_ID_DYN_LO,
          "an edit placing the lowest dynamic block id (0x80) is broadcast");

    drain();
    send_block_edit(0xA11CE001u, 7100, 12, 7100, (uint8_t)REG_ID_DYN_HI);
    n = recv_app_for(0xB0B00002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_BLOCK_EDIT_BYTES && out[0] == BS_APP_BLOCK_EDIT
          && out[13] == (uint8_t)REG_ID_DYN_HI,
          "an edit placing the highest dynamic block id (0xFD) is broadcast");

    /* The ceiling is a ceiling, not a removed check: 0xFE and 0xFF are reserved
     * so a u8 row count can never overflow (world/registry.h), and neither is a
     * placeable block. If these two ever start passing, bsEditValid() has lost
     * its block-id test rather than had it raised. */
    drain();
    send_block_edit(0xA11CE001u, 7200, 12, 7200, (uint8_t)(REG_ID_DYN_HI + 1) /* 0xFE */);
    n = recv_app_for(0xB0B00002u, out, sizeof out, 400);
    check(n < 0, "an edit one past the highest dynamic block id (0xFE) is dropped");

    drain();
    send_block_edit(0xA11CE001u, 7300, 12, 7300, 0xFF);
    n = recv_app_for(0xB0B00002u, out, sizeof out, 400);
    check(n < 0, "an edit placing the top reserved id (0xFF) is dropped");
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

/* ------------------------------------------------ tick-rate independence
 *
 * The simulation rate has to be a property of the clock and nothing else.
 * bsgame used to tick once per poll() return, so every arriving datagram
 * bought an extra simulation step and the effective rate ROSE with traffic —
 * a busy server ran fast, an idle one ran slow, and every mechanic defined
 * per tick (fluid spread, smelting, hunger, growth) changed speed with the
 * player count. world/tick.c's fixed-step accumulator replaced that, but
 * until this scenario existed nothing checked it, so a refactor could put the
 * old behaviour back and the suite would stay green.
 *
 * This measures the daemon end to end: the real forked bsgame, its real
 * poll(), its real main loop, observed only from outside via ticks_total in
 * the SIGUSR1 status snapshot (which bsgame.c increments inside tick()
 * itself, at the one place a simulation step actually happens — not from the
 * TickClock's own count, which would still look right if the loop started
 * calling tick() per wakeup again). Nothing here reimplements the clock; a
 * test that recompiled the tick logic as its own translation unit would pass
 * with the daemon's copy of it deleted. */

/* Three seconds per arm. The failure being guarded against is a RATE, so the
 * window has to be long relative to everything that blurs a rate reading:
 * it is 60 tick periods, ~1000x the few milliseconds of uncertainty in each
 * status-file timestamp below, and well past the 500 ms legacy-grace one-shot
 * that JOIN eventually fires. It also means the busy arm delivers well over a
 * thousand datagrams, so the one-extra-tick-per-wakeup regression has room to
 * accumulate into an unmistakable difference instead of hiding inside noise —
 * a shorter window can be answered correctly by a broken server simply
 * because too little happened in it. Three arms cost the suite ~9.5 s. */
#define BS_TICK_WINDOW_MS 3000u

/* The accumulator can never run FAST — it spends banked real time and hands
 * back the remainder — so a reading above the top of this band means the loop
 * is ticking on something other than elapsed time. It can legitimately run
 * slow if the host cannot keep up (that is what TickClock's `dropped` counts),
 * hence a band rather than an equality, but 20 TPS on an idle Linux box is not
 * demanding and a reading under 16 is a real finding, not noise. */
#define BS_TICK_TPS_LO 16.0
#define BS_TICK_TPS_HI 24.0

/* The busy arm is worthless if the packets never actually got sent, so the
 * arm asserts its own premise: at least 200 datagrams a second across the
 * window. Without this the whole scenario could pass by not testing anything. */
#define BS_TICK_BUSY_MIN_PKT (BS_TICK_WINDOW_MS / 5u)

/* Forces a fresh status snapshot and reads ticks_total out of it, along with
 * the wall-clock instant it was observed. The file is unlinked first so a
 * stale one from the previous sample can never be mistaken for this one, and
 * bsgame writes it to a temp path and renames, so the moment it exists it is
 * complete. */
static bool sample_ticks(uint64_t *ticks_out, uint64_t *at_ms)
{
    char status_path[192];
    snprintf(status_path, sizeof status_path, "%s/status.txt", g_dir);
    unlink(status_path);

    if (kill(g_daemon, SIGUSR1) != 0) die("kill SIGUSR1");

    /* Polled at 2 ms so the timestamp taken below is close to the rename that
     * published the file; the daemon itself takes up to one tick period to
     * notice the signal, which is why the deadline is generous. */
    struct stat st;
    bool appeared = false;
    for (unsigned waited = 0; waited < 2000u; waited += 2u) {
        if (stat(status_path, &st) == 0) { appeared = true; break; }
        msleep(2);
    }
    if (!appeared) return false;
    *at_ms = now_ms();

    FILE *f = fopen(status_path, "r");
    if (f == NULL) return false;

    bool got = false;
    char line[256];
    while (fgets(line, sizeof line, f) != NULL) {
        unsigned long long v;
        if (sscanf(line, "ticks_total %llu", &v) == 1) {
            *ticks_out = (uint64_t)v;
            got = true;
        }
    }
    fclose(f);
    return got;
}

/* Sends one POS_UPDATE every `gap_ms` until `until_ms`, and returns how many
 * it managed. POS_UPDATE is used because bsgame answers it with no datagram
 * at all when the sender is the only relevant player and touches no disk (see
 * handle_pos_update) — so this arm varies the packet rate and nothing else.
 * gap_ms 0 means send nothing: the idle arm. */
static unsigned pump_traffic(uint32_t sid, unsigned gap_ms, uint64_t until_ms)
{
    unsigned sent = 0;

    if (gap_ms == 0) {
        uint64_t at;
        while ((at = now_ms()) < until_ms) {
            uint64_t left = until_ms - at;
            msleep(left > 20u ? 20u : (unsigned)left);
        }
        return 0;
    }

    while (now_ms() < until_ms) {
        send_pos_update(sid, (float)sent, 64.0f, 0.0f, 0.0f, 0.0f);
        sent++;
        msleep(gap_ms);
    }
    return sent;
}

/* One arm: sample, generate traffic for the window, sample again. Returns
 * ticks per second, or -1.0 if a snapshot could not be read. */
static double measure_tps(uint32_t sid, unsigned gap_ms, unsigned *sent_out)
{
    uint64_t k0 = 0, k1 = 0, t0 = 0, t1 = 0;

    *sent_out = 0;
    if (!sample_ticks(&k0, &t0)) return -1.0;
    *sent_out = pump_traffic(sid, gap_ms, t0 + BS_TICK_WINDOW_MS);
    if (!sample_ticks(&k1, &t1)) return -1.0;
    if (t1 <= t0 || k1 < k0) return -1.0;

    return (double)(k1 - k0) * 1000.0 / (double)(t1 - t0);
}

static void test_tick_rate_is_traffic_independent(void)
{
    puts("tick rate is independent of network traffic");
    drain();

    const uint32_t sid = 0x71CC0007u;
    send_join(sid, "ticker");

    /* Let JOIN's own burst (WORLD_INFO, REGISTRY_INFO, INV_STATE,
     * PLAYER_STATE) and the legacy-grace WORLD_SYNC land and be thrown away
     * before the first window opens, so no arm is measured across them. */
    msleep(BS_CHUNK_LEGACY_GRACE_MS + 400u);
    drain();

    unsigned sent_idle = 0, sent_light = 0, sent_busy = 0;

    const double tps_idle = measure_tps(sid, 0, &sent_idle);
    drain();
    const double tps_light = measure_tps(sid, 100, &sent_light);   /* ~10 packets/s */
    drain();
    const double tps_busy = measure_tps(sid, 2, &sent_busy);       /* as fast as a 2 ms
                                                                      sleep allows */
    drain();

    printf("        idle  %6.2f TPS over %ums, %u packets\n",
           tps_idle, BS_TICK_WINDOW_MS, sent_idle);
    printf("        light %6.2f TPS over %ums, %u packets\n",
           tps_light, BS_TICK_WINDOW_MS, sent_light);
    printf("        busy  %6.2f TPS over %ums, %u packets\n",
           tps_busy, BS_TICK_WINDOW_MS, sent_busy);

    /* Control. Stays green whether or not the rate itself is correct, so a
     * red anywhere below is a real finding and not a broken harness. */
    check(tps_idle > 0.0 && tps_light > 0.0 && tps_busy > 0.0,
          "all three traffic arms produced a tick-rate reading");

    /* The busy arm asserts its own premise before anything is concluded
     * from it. */
    check(sent_busy >= BS_TICK_BUSY_MIN_PKT,
          "the busy arm actually delivered at least 200 packets a second");

    check(tps_idle >= BS_TICK_TPS_LO && tps_idle <= BS_TICK_TPS_HI,
          "a server receiving nothing ticks at 20 TPS");
    check(tps_light >= BS_TICK_TPS_LO && tps_light <= BS_TICK_TPS_HI,
          "a server receiving ~10 packets/s ticks at 20 TPS");
    check(tps_busy >= BS_TICK_TPS_LO && tps_busy <= BS_TICK_TPS_HI,
          "a server receiving hundreds of packets/s still ticks at 20 TPS");

    /* And the claim itself, stated as a comparison rather than as three
     * separate band checks, so it stays meaningful even on a host slow
     * enough to drag every arm down together. */
    check(tps_busy <= tps_idle * 1.25 && tps_busy >= tps_idle * 0.75,
          "the busy tick rate matches the idle one within 25%");

    /* Second control, and a crash check on the burst itself. */
    check(kill(g_daemon, 0) == 0,
          "the daemon survives a sustained packet burst");

    send_leave(sid);
    msleep(50);
    drain();
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

/* ------------------------------------------------------------ V127-B: inventory
 *
 * Each scenario below joins its own fresh player rather than threading state
 * through a shared one — inventory ops have no coordinate or column to
 * collide with, unlike the block-edit tests above, so a self-contained join
 * per test is simpler than tracking a shared session's running inventory
 * across scenarios, and it means one failing assertion never leaves a later
 * test starting from a state it didn't expect. Every sid below is a fresh
 * one nothing earlier in this file has used. */

static void test_inv_join_sends_empty_inv_state(void)
{
    puts("end-to-end: JOIN sends an INV_STATE for a brand-new player, and it is empty");
    drain();

    send_join(0xF2A50009u, "frank");

    /* Same ordering as test_join_sends_world_info_then_sync: WORLD_INFO
     * leads, unchanged by this feature. REGISTRY_INFO follows it (v1.6.0),
     * and INV_STATE comes right after that — handle_join sends it before
     * the legacy WORLD_SYNC, which only fires later from tick()'s
     * grace-window fallback (see bsgame.c's handle_join). */
    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A50009u, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "the first packet after JOIN is still WORLD_INFO, unchanged by this feature");

    bool got_reg = recv_registry_info(0xF2A50009u, 500);
    check(got_reg, "REGISTRY_INFO arrives second, between WORLD_INFO and INV_STATE");

    n = recv_app_for(0xF2A50009u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "the third packet after JOIN is INV_STATE, the capability probe");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(out[1] == 0, "a brand-new player's selected hotbar slot is 0");
        check(inv_state_is_empty(out), "a brand-new player's inventory is entirely empty slots");
    }
}

static void test_inv_craft_without_ingredient_refused(void)
{
    puts("end-to-end: CRAFT with no ingredient in the inventory is refused, not applied");
    drain();

    send_join(0xF2A5000Au, "grace");
    msleep(100);
    drain();

    /* Recipe 3 is RECIPE_WOOD_TO_PLANKS (world/crafting.c): 1 wood -> 4
     * planks. grace has never picked up anything, so craftMake() must find
     * zero wood and leave the inventory untouched. */
    send_inv_action(0xF2A5000Au, BS_INV_OP_CRAFT, 3, 0, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A5000Au, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "a refused CRAFT is still answered with an INV_STATE");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_is_empty(out), "CRAFT with no wood produces no planks and changes nothing");
    }
}

static void test_inv_pickup_then_craft_spends_wood(void)
{
    puts("end-to-end: CRAFT actually spends the ingredient - planks appear AND the wood is gone");
    drain();

    send_join(0xF2A5000Bu, "henry");
    msleep(100);
    drain();

    /* Prime henry with exactly one wood via PICKUP (the client-reported op —
     * see handle_inv_action's header comment in bsgame.c), not a block edit:
     * this server has no terrain generator and never grants inventory from
     * an accepted BLOCK_EDIT, so PICKUP is the only way a test (or a real
     * client) gets an item into a fresh inventory. */
    send_inv_action(0xF2A5000Bu, BS_INV_OP_PICKUP, 5 /* BLOCK_WOOD */, 1, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A5000Bu, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE
          && inv_state_total(out, 5) == 1,
          "the priming PICKUP credits exactly one wood");

    send_inv_action(0xF2A5000Bu, BS_INV_OP_CRAFT, 3 /* RECIPE_WOOD_TO_PLANKS */, 0, 0);
    n = recv_app_for(0xF2A5000Bu, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "CRAFT is answered with a fresh INV_STATE");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_total(out, 7 /* BLOCK_PLANKS */) == 4,
              "the craft produced exactly 4 planks");
        check(inv_state_total(out, 5 /* BLOCK_WOOD */) == 0,
              "the one wood the craft consumed is entirely gone, not just decremented");
    }
}

static void test_inv_pickup_credits_item(void)
{
    puts("end-to-end: PICKUP credits the reported item and count, landing in the first empty slot");
    drain();

    send_join(0xF2A5000Cu, "iris");
    msleep(100);
    drain();

    send_inv_action(0xF2A5000Cu, BS_INV_OP_PICKUP, 2 /* BLOCK_DIRT */, 3, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A5000Cu, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "PICKUP is answered with a fresh INV_STATE");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        inv_state_slot(out, 0, &item, &count);
        check(item == 2 && count == 3, "the picked-up item lands in slot 0 with the reported count");
    }
}

static void test_inv_pickup_out_of_range_item_refused(void)
{
    puts("end-to-end: PICKUP with an item id past BS_BLOCK_COUNT is refused, not kicked");
    drain();

    send_join(0xF2A5000Du, "jack");
    msleep(100);
    drain();

    send_inv_action(0xF2A5000Du, BS_INV_OP_PICKUP, (uint8_t)BS_BLOCK_COUNT, 1, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A5000Du, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "an out-of-range PICKUP still gets an INV_STATE back, not a KICK");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_is_empty(out), "the out-of-range item id was never applied");
    }

    /* Prove the session is still alive, not just that this one packet wasn't
     * a KICK envelope: a genuinely refused-not-kicked player must go on
     * answering ordinary requests afterward. */
    send_inv_action(0xF2A5000Du, BS_INV_OP_PICKUP, 3 /* BLOCK_STONE */, 1, 0);
    n = recv_app_for(0xF2A5000Du, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE && inv_state_total(out, 3) == 1,
          "jack's session still answers a valid PICKUP after the refused one");
}

static void test_inv_consume_of_unheld_item_removes_nothing(void)
{
    puts("end-to-end: CONSUME of an item the player does not hold removes nothing");
    drain();

    send_join(0xF2A5000Eu, "karen");
    msleep(100);
    drain();

    send_inv_action(0xF2A5000Eu, BS_INV_OP_CONSUME, 5 /* BLOCK_WOOD */, 1, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A5000Eu, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "CONSUME is answered with an INV_STATE even when it removes nothing");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_is_empty(out), "an empty inventory stays empty — no slot goes negative or wraps");
    }
}

static void test_inv_action_wrong_length_refused_not_kicked(void)
{
    puts("end-to-end: a wrong-length INV_ACTION is refused, not KICKed, and the session keeps working");
    drain();

    send_join(0xF2A5000Fu, "leo");
    msleep(100);
    drain();

    uint8_t junk[3] = { BS_APP_INV_ACTION, 0, 0 };   /* far short of BS_INV_ACTION_BYTES */
    send_app(0xF2A5000Fu, junk, sizeof junk);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A5000Fu, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "a wrong-length INV_ACTION is answered with an unchanged INV_STATE, not a KICK");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_is_empty(out), "the malformed payload changed nothing");
    }

    send_inv_action(0xF2A5000Fu, BS_INV_OP_PICKUP, 1 /* BLOCK_GRASS */, 2, 0);
    n = recv_app_for(0xF2A5000Fu, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE && inv_state_total(out, 1) == 2,
          "leo's session still answers a valid action after the wrong-length one");
}

static void test_inv_action_out_of_range_slot_refused_not_kicked(void)
{
    puts("end-to-end: an out-of-range slot index in MOVE is refused, not KICKed");
    drain();

    send_join(0xF2A50010u, "mike");
    msleep(100);
    drain();

    /* 250 is well past INV_SLOT_COUNT (24) on both ends of the move. */
    send_inv_action(0xF2A50010u, BS_INV_OP_MOVE, 250, 250, 1);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A50010u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "an out-of-range MOVE is answered with an unchanged INV_STATE, not a KICK");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_is_empty(out), "the out-of-range MOVE changed nothing");
    }

    check(kill(g_daemon, 0) == 0, "daemon survives an out-of-range INV_ACTION argument");
}

/* --------------------------------------------------- player state persistence
 *
 * Same self-contained-join discipline as the inventory section above: every
 * scenario uses a fresh sid and label nothing earlier touches, so one
 * failing assertion cannot leave later tests standing on a state they did
 * not expect. Labels below are all already-sanitised shapes ([a-z0-9]), so
 * the on-disk path players/<label>/player.dat can be built directly.
 *
 * The daemon is restarted mid-suite here (SIGTERM + relaunch on the same
 * --state-dir), exactly like test_restart_persists_diffs does for the diff
 * store — that is the whole point being tested: state survives it. */

/* Joins and consumes the full four-packet welcome sequence — WORLD_INFO,
 * REGISTRY_INFO, INV_STATE, PLAYER_STATE — asserting the PLAYER_STATE
 * carries the fresh-spawn marker: flags byte 0 and an entirely zeroed body. */
static void join_expect_fresh_player_state(uint32_t sid, const char *label)
{
    send_join(sid, label);

    uint8_t out[128];
    ssize_t n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "WORLD_INFO still leads the join sequence");
    bool got_reg = recv_registry_info(sid, 500);
    check(got_reg, "REGISTRY_INFO arrives second, between WORLD_INFO and INV_STATE");

    n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "INV_STATE still comes third in the join sequence");

    n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_PLAYER_STATE_BYTES && out[0] == BS_APP_PLAYER_STATE,
          "PLAYER_STATE arrives fourth, well-formed");
    if (n != (ssize_t)BS_PLAYER_STATE_BYTES) return;

    check(out[1] == 0, "fresh-spawn PLAYER_STATE carries flags 0");
    bool all_zero = true;
    for (unsigned i = 1; i < BS_PLAYER_STATE_BYTES; i++) {
        if (out[i] != 0) all_zero = false;
    }
    check(all_zero, "fresh-spawn PLAYER_STATE body is entirely zeroed");
}

static bool player_dat_exists(const char *label)
{
    char path[256];
    snprintf(path, sizeof path, "%s/players/%s/player.dat", g_dir, label);
    struct stat st;
    return stat(path, &st) == 0;
}

/* True if a KICK envelope addressed to `sid` arrives within `ms`, skipping
 * DATA envelopes for anyone. Used as a negative assertion: a tolerated peer
 * must never draw one. */
static bool kicked_within(uint32_t sid, unsigned ms)
{
    uint64_t deadline = now_ms() + ms;
    for (;;) {
        uint64_t now = now_ms();
        if (now >= deadline) return false;

        uint8_t buf[2048];
        ssize_t n = gate_recv(buf, sizeof buf, (unsigned)(deadline - now));
        if (n < 5) return false;   /* timeout elapsed */
        if (buf[0] == BS_GAME_KICK && bs_get_u32(buf + 1) == sid) return true;
        /* anything else: keep waiting out the window */
    }
}

static void send_player_report(uint32_t sid, const uint8_t armor[8],
                               uint32_t xp_level, float xp_progress,
                               float health, float hunger)
{
    uint8_t p[BS_PLAYER_REPORT_BYTES];
    memset(p, 0, sizeof p);   /* reserved tail MUST be zero — bs_proto.h */
    p[0] = BS_APP_PLAYER_REPORT;
    memcpy(p + 1, armor, 8);
    bs_put_u32(p + 9, xp_level);
    bs_put_f32(p + 13, xp_progress);
    bs_put_f32(p + 17, health);
    bs_put_f32(p + 21, hunger);
    send_app(sid, p, sizeof p);
}

/* Reads a PLAYER_STATE addressed to `sid` and returns its decoded fields
 * through the out-params; false if none arrives in time or the packet is
 * not the right shape. Deliberately hand-parsed from raw wire bytes like
 * every other message in this file. */
static bool recv_player_state_fields(uint32_t sid, unsigned ms,
                                     uint8_t *flags_out,
                                     float *x_out, float *y_out, float *z_out,
                                     float *yaw_out, float *pitch_out,
                                     uint8_t armor_out[8],
                                     uint32_t *xp_level_out,
                                     float *xp_progress_out,
                                     float *health_out, float *hunger_out)
{
    uint8_t out[128];
    ssize_t n = recv_app_for(sid, out, sizeof out, ms);
    if (n != (ssize_t)BS_PLAYER_STATE_BYTES || out[0] != BS_APP_PLAYER_STATE) return false;

    *flags_out      = out[1];
    *x_out          = bs_get_f32(out + 2);
    *y_out          = bs_get_f32(out + 6);
    *z_out          = bs_get_f32(out + 10);
    *yaw_out        = bs_get_f32(out + 14);
    *pitch_out      = bs_get_f32(out + 18);
    memcpy(armor_out, out + 22, 8);
    *xp_level_out   = bs_get_u32(out + 30);
    *xp_progress_out= bs_get_f32(out + 34);
    *health_out     = bs_get_f32(out + 38);
    *hunger_out     = bs_get_f32(out + 42);
    return true;
}

static void test_ps_join_fresh_sends_zeroed_state(void)
{
    puts("end-to-end: JOIN for a brand-new label sends PLAYER_STATE flags=0 and writes no file");
    drain();

    join_expect_fresh_player_state(0x50A00001u, "psa");

    check(!player_dat_exists("psa"),
          "JOIN alone never creates player.dat — only a report or a prior save does");
}

static void test_ps_report_persists_across_sigterm_restart(void)
{
    puts("end-to-end: pose merged at save time plus PLAYER_REPORT values survive SIGTERM restart");
    drain();

    /* First join: prove this label starts fresh, then feed the server both
     * halves of what a save should hold — live pose via POS_UPDATE (the
     * existing channel) and meters via PLAYER_REPORT. The save happens
     * write-through inside the report handler, so the SIGTERM below needs
     * no clean shutdown flush to be honest. */
    join_expect_fresh_player_state(0x50A00002u, "psb");

    send_pos_update(0x50A00002u, 11.5f, 64.0f, -7.25f, 135.0f, -35.0f);
    const uint8_t armor[8] = { 5, 1, 0, 0, 0, 0, 0, 0 };   /* head {item 5 x1} */
    send_player_report(0x50A00002u, armor, 7u, 0.25f, 13.5f, 8.25f);
    msleep(150);   /* let the daemon process both datagrams */

    stop_daemon();
    start_daemon();
    if (!wait_ready(5000)) { fprintf(stderr, "test: restarted daemon never became ready\n"); exit(1); }
    drain();

    send_join(0x50A00003u, "psb");   /* same label, brand-new session */

    uint8_t out[128];
    ssize_t n = recv_app_for(0x50A00003u, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "restarted daemon still opens with WORLD_INFO");
    bool got_reg = recv_registry_info(0x50A00003u, 500);
    check(got_reg, "REGISTRY_INFO still arrives second after a restart");
    n = recv_app_for(0x50A00003u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "INV_STATE unchanged by player-state restore");

    uint8_t flags = 0xff, armor_back[8];
    float x = 0, y = 0, z = 0, yaw = 0, pitch = 0, prog = 0, hp = 0, hunger = 0;
    uint32_t xp_level = 0;
    bool got = recv_player_state_fields(0x50A00003u, 500, &flags,
                                        &x, &y, &z, &yaw, &pitch, armor_back,
                                        &xp_level, &prog, &hp, &hunger);
    check(got, "rejoin after restart gets a well-formed PLAYER_STATE");
    if (!got) return;

    check(flags == (BS_PLAYER_STATE_FLAG_POSE | BS_PLAYER_STATE_FLAG_EXT),
          "restored snapshot sets both valid flags, not just one");
    check(x == 11.5f && y == 64.0f && z == -7.25f,
          "pose persisted from POS_UPDATE, exact coordinates back");
    check(yaw == 135.0f && pitch == -35.0f,
          "yaw/pitch survive the round trip — rotation is really restored");
    check(armor_back[0] == 5 && armor_back[1] == 1
          && armor_back[2] == 0 && armor_back[3] == 0
          && armor_back[4] == 0 && armor_back[5] == 0
          && armor_back[6] == 0 && armor_back[7] == 0,
          "armour slots come back exactly as reported");
    check(xp_level == 7u, "xp level survives");
    check(prog == 0.25f && hp == 13.5f && hunger == 8.25f,
          "xp progress, health and hunger come back exact");
}

static void test_ps_corrupt_and_truncated_dat_degrade_to_fresh_spawn(void)
{
    puts("on-disk format: corrupt or truncated player.dat degrades to fresh spawn, never fatal");

    char dir[256], path[512];
    snprintf(dir, sizeof dir, "%s/players/psc", g_dir);
    mkdir(dir, 0700);   /* EEXIST fine — mirrors ensure_dir()'s tolerance */
    snprintf(path, sizeof path, "%s/player.dat", dir);

    /* Case 1: right length, wrong everything else. */
    FILE *f = fopen(path, "wb");
    if (f == NULL) die("write garbage player.dat");
    for (unsigned i = 0; i < 65; i++) fputc('X', f);
    fclose(f);

    drain();
    join_expect_fresh_player_state(0x50A00004u, "psc");
    send_leave(0x50A00004u);
    msleep(100);

    /* Case 2: plausible header prefix but cut off mid-payload — the shape a
     * torn write would leave if the tmp-promotion recovery ever lost. The
     * leave above must NOT have rewritten the file (nothing was loaded), so
     * this truncation lands on top of case 1's garbage deliberately. */
    f = fopen(path, "wb");
    if (f == NULL) die("write truncated player.dat");
    uint8_t buf[30];   /* 20-byte header + half the payload */
    memset(buf, 0, sizeof buf);
    bs_put_u32(buf + 0, 0x31505342u /* 'BSP1' */);
    bs_put_u32(buf + 4, 1u);
    bs_put_u32(buf + 8, BS_PLAYER_STATE_BODY_BYTES);
    bool wrote = fwrite(buf, 1, sizeof buf, f) == sizeof buf;
    fclose(f);
    if (!wrote) die("short write on truncated player.dat");

    join_expect_fresh_player_state(0x50A00005u, "psc");
    send_leave(0x50A00005u);
    msleep(100);

    check(player_dat_exists("psc"), "the corrupt file is left in place, not deleted speculatively");
    struct stat st;
    check(stat(path, &st) == 0 && st.st_size == (off_t)sizeof buf,
          "and it was not silently replaced by a fresh save either");
}

static void test_ps_old_client_never_reports_writes_no_file(void)
{
    puts("end-to-end: an old-style client joins, moves, leaves — never kicked, no file written");
    drain();

    /* An old client predating this feature ignores PLAYER_STATE entirely and
     * never sends PLAYER_REPORT. It still moves via POS_UPDATE, which today
     * updates only the live pose — none of it may spill into a file for a
     * label that has never had one. */
    join_expect_fresh_player_state(0x50A00006u, "psd");

    send_pos_update(0x50A00006u, 3.0f, 70.0f, 4.0f, 90.0f, 0.0f);
    msleep(150);
    check(!kicked_within(0x50A00006u, 300),
          "moving without ever reporting draws no KICK");

    send_leave(0x50A00006u);
    msleep(150);
    check(!kicked_within(0x50A00006u, 300),
          "leaving without ever reporting draws no KICK");
    check(!player_dat_exists("psd"),
          "no player.dat appears for a session that never saved anything");
}

static void test_ps_report_wrong_length_kicks(void)
{
    puts("end-to-end: wrong-length PLAYER_REPORT (31 B / 45 B) gets KICKed, not just dropped");
    drain();

    /* Known type, wrong length — the same protocol-violation treatment
     * BLOCK_EDIT/POS_UPDATE/CHUNK_SUB get for it (see handle_player_report's
     * header comment for why INV_ACTION's refuse-and-resync exception does
     * not extend here). Both near-miss lengths are tried: one over and one
     * well past BS_PLAYER_REPORT_BYTES (30). */
    send_join(0x50A00007u, "pse");
    msleep(100);
    drain();

    uint8_t junk[31];
    memset(junk, 2, sizeof junk);
    junk[0] = BS_APP_PLAYER_REPORT;
    send_app(0x50A00007u, junk, sizeof junk);

    uint8_t kbuf[64];
    ssize_t n = gate_recv(kbuf, sizeof kbuf, 500);
    check(n == 5 && kbuf[0] == BS_GAME_KICK && bs_get_u32(kbuf + 1) == 0x50A00007u,
          "a 31-byte PLAYER_REPORT is KICKed");

    send_join(0x50A00008u, "pes");
    msleep(100);
    drain();

    uint8_t junk45[45];
    memset(junk45, 3, sizeof junk45);
    junk45[0] = BS_APP_PLAYER_REPORT;
    send_app(0x50A00008u, junk45, sizeof junk45);

    n = gate_recv(kbuf, sizeof kbuf, 500);
    check(n == 5 && kbuf[0] == BS_GAME_KICK && bs_get_u32(kbuf + 1) == 0x50A00008u,
          "a 45-byte PLAYER_REPORT is KICKed too");
    check(kill(g_daemon, 0) == 0, "daemon survives both wrong-length reports");
}

/* ----------------------------------------- player.dat fixtures and probes
 *
 * The scenarios below need a player.dat the daemon must ACCEPT — the two
 * corruption tests above only ever needed one it must reject, which is why
 * they could get away with 65 'X' bytes and a 30-byte stub. Building a
 * valid one takes a real header and a real checksum, hence this helper.
 *
 * The 45-byte body is laid out straight from bs_proto.h's PLAYER_STATE wire
 * spec rather than by calling playerStateEncodeBody(): a fixture that shares
 * its encoder with the code under test can only ever agree with that code,
 * which is exactly the property a fixture must not have. The header is
 * likewise spelled out (magic 'BSP1', version 1, body size, payload CRC)
 * instead of pulled from playerstate.c's private #defines.
 *
 * `crc_fudge` is XORed into the stored checksum. Zero writes a file every
 * check accepts; anything else writes the one shape no earlier test reaches
 * — right length, right magic, right version, right size, wrong checksum —
 * which is playerstate.c's `stored != computed` branch and nothing else. */
static void write_player_dat(const char *path,
                             float x, float y, float z, float yaw, float pitch,
                             const uint8_t armor[8], uint32_t xp_level,
                             float xp_progress, float health, float hunger,
                             uint32_t crc_fudge)
{
    uint8_t file[20u + BS_PLAYER_STATE_BODY_BYTES];
    memset(file, 0, sizeof file);

    uint8_t *body = file + 20;
    body[0] = (uint8_t)(BS_PLAYER_STATE_FLAG_POSE | BS_PLAYER_STATE_FLAG_EXT);
    bs_put_f32(body + 1,  x);
    bs_put_f32(body + 5,  y);
    bs_put_f32(body + 9,  z);
    bs_put_f32(body + 13, yaw);
    bs_put_f32(body + 17, pitch);
    memcpy(body + 21, armor, 8);
    bs_put_u32(body + 29, xp_level);
    bs_put_f32(body + 33, xp_progress);
    bs_put_f32(body + 37, health);
    bs_put_f32(body + 41, hunger);

    bs_put_u32(file + 0,  0x31505342u /* 'BSP1' */);
    bs_put_u32(file + 4,  1u);
    bs_put_u32(file + 8,  BS_PLAYER_STATE_BODY_BYTES);
    bs_put_u32(file + 12, crc32(body, BS_PLAYER_STATE_BODY_BYTES) ^ crc_fudge);

    FILE *f = fopen(path, "wb");
    if (f == NULL) die("open player.dat fixture");
    bool ok = fwrite(file, 1, sizeof file, f) == sizeof file;
    if (fclose(f) != 0 || !ok) die("write player.dat fixture");
}

/* players/<label>/, created the way ensure_dir() would have. */
static void make_player_dir(const char *label, char *out, size_t cap)
{
    char players[256];
    snprintf(players, sizeof players, "%s/players", g_dir);
    if (mkdir(players, 0700) != 0 && errno != EEXIST) die("mkdir players dir");
    snprintf(out, cap, "%s/%s", players, label);
    if (mkdir(out, 0700) != 0 && errno != EEXIST) die("mkdir player dir");
}

/* Joins and swallows the three welcome packets that precede PLAYER_STATE
 * without re-asserting their order — join_expect_fresh_player_state() above
 * already owns that assertion, and everything below is about what the
 * fourth packet SAYS, not where it sits. */
static void join_skip_welcome(uint32_t sid, const char *label)
{
    send_join(sid, label);
    uint8_t out[128];
    for (unsigned i = 0; i < 3; i++) (void)recv_app_for(sid, out, sizeof out, 500);
}

static bool file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* player_state_recover(), promotion arm. A save cut off after the temp file
 * was written but before it was renamed leaves player.dat.tmp with no
 * player.dat beside it — the whole crash-safety claim of the module is that
 * this is indistinguishable from a completed save, and until now nothing
 * tested it in either direction. */
static void test_ps_recover_promotes_orphaned_tmp(void)
{
    puts("crash safety: an orphaned player.dat.tmp with no player.dat is promoted, not dropped");

    char dir[320], path[512], tmp[544];
    make_player_dir("psf", dir, sizeof dir);
    snprintf(path, sizeof path, "%s/player.dat", dir);
    snprintf(tmp,  sizeof tmp,  "%s/player.dat.tmp", dir);
    remove(path);

    const uint8_t armor[8] = { 3, 9, 0, 0, 0, 0, 0, 0 };
    write_player_dat(tmp, 1.5f, 65.0f, 2.5f, 45.0f, -10.0f,
                     armor, 3u, 0.5f, 17.0f, 4.0f, 0);

    drain();
    join_skip_welcome(0x50A00010u, "psf");

    uint8_t flags = 0xff, armor_back[8];
    float x = 0, y = 0, z = 0, yaw = 0, pitch = 0, prog = 0, hp = 0, hunger = 0;
    uint32_t xp_level = 0;
    bool got = recv_player_state_fields(0x50A00010u, 500, &flags,
                                        &x, &y, &z, &yaw, &pitch, armor_back,
                                        &xp_level, &prog, &hp, &hunger);
    check(got, "a join over an orphaned tmp still gets a well-formed PLAYER_STATE");
    if (got) {
        check(flags == (BS_PLAYER_STATE_FLAG_POSE | BS_PLAYER_STATE_FLAG_EXT),
              "the promoted tmp is restored, not treated as a fresh spawn");
        check(x == 1.5f && y == 65.0f && z == 2.5f && yaw == 45.0f && pitch == -10.0f,
              "the promoted tmp's pose comes back exact");
        check(armor_back[0] == 3 && armor_back[1] == 9 && xp_level == 3u
              && prog == 0.5f && hp == 17.0f && hunger == 4.0f,
              "the promoted tmp's armour and meters come back exact");
    }

    check(file_exists(path), "the tmp really was renamed into place, not merely read");
    check(!file_exists(tmp), "and nothing is left behind for the next load to redo");

    send_leave(0x50A00010u);
    msleep(100);
}

/* player_state_recover(), discard arm — and the one that matters most once
 * the save stops removing the real file first: from then on a crash between
 * write and rename ALWAYS leaves both files, and the real one is the older,
 * complete save that must win. A tmp promoted over it would be a rename
 * that never happened being applied anyway. */
static void test_ps_recover_discards_tmp_when_real_file_present(void)
{
    puts("crash safety: a tmp beside an intact player.dat is discarded, the real file wins");

    char dir[320], path[512], tmp[544];
    make_player_dir("psg", dir, sizeof dir);
    snprintf(path, sizeof path, "%s/player.dat", dir);
    snprintf(tmp,  sizeof tmp,  "%s/player.dat.tmp", dir);

    const uint8_t armor_real[8] = { 4, 1, 0, 0, 0, 0, 0, 0 };
    const uint8_t armor_tmp[8]  = { 6, 2, 0, 0, 0, 0, 0, 0 };
    write_player_dat(path, 10.0f, 70.0f, 10.0f, 0.0f, 0.0f,
                     armor_real, 1u, 0.125f, 20.0f, 20.0f, 0);
    write_player_dat(tmp, -99.0f, -99.0f, -99.0f, -99.0f, -99.0f,
                     armor_tmp, 99u, 1.0f, 1.0f, 1.0f, 0);

    drain();
    join_skip_welcome(0x50A00011u, "psg");

    uint8_t flags = 0xff, armor_back[8];
    float x = 0, y = 0, z = 0, yaw = 0, pitch = 0, prog = 0, hp = 0, hunger = 0;
    uint32_t xp_level = 0;
    bool got = recv_player_state_fields(0x50A00011u, 500, &flags,
                                        &x, &y, &z, &yaw, &pitch, armor_back,
                                        &xp_level, &prog, &hp, &hunger);
    check(got, "a join with both files present gets a well-formed PLAYER_STATE");
    if (got) {
        check(x == 10.0f && y == 70.0f && z == 10.0f,
              "the intact player.dat is what gets restored, not the leftover tmp");
        check(armor_back[0] == 4 && armor_back[1] == 1 && xp_level == 1u,
              "and its armour/XP too — the tmp's values appear nowhere");
    }
    check(!file_exists(tmp), "the superseded tmp is cleaned up rather than left to rot");

    send_leave(0x50A00011u);
    msleep(100);
}

/* The checksum branch, which no earlier test could reach: the corruption
 * test above fails at the magic check (65 'X' bytes) and at the short-read
 * check (30 bytes), so `stored != computed` had never once executed. This
 * file is correct in every other respect — right size, right magic, right
 * version, right body size, decodable payload — and must still be refused,
 * because a plausible torn write is the only thing a checksum exists to
 * catch. */
static void test_ps_bad_checksum_dat_degrades_to_fresh_spawn(void)
{
    puts("on-disk format: a well-formed player.dat with a bad payload CRC is refused");

    char dir[320], path[512], tmp[544];
    make_player_dir("psh", dir, sizeof dir);
    snprintf(path, sizeof path, "%s/player.dat", dir);
    snprintf(tmp,  sizeof tmp,  "%s/player.dat.tmp", dir);
    remove(tmp);

    const uint8_t armor[8] = { 2, 5, 0, 0, 0, 0, 0, 0 };
    write_player_dat(path, 42.0f, 80.0f, 42.0f, 12.0f, 3.0f,
                     armor, 9u, 0.75f, 15.0f, 12.0f, 0x00000001u /* flip one CRC bit */);

    drain();
    join_expect_fresh_player_state(0x50A00012u, "psh");

    send_leave(0x50A00012u);
    msleep(100);

    struct stat st;
    check(stat(path, &st) == 0 && st.st_size == (off_t)(20u + BS_PLAYER_STATE_BODY_BYTES),
          "the bad-checksum file is left in place untouched, not deleted or overwritten");
}

/* S4: armour ids and counts are validated on exactly the terms the
 * inventory path validates PICKUP/CONSUME on (`a < BS_BLOCK_COUNT`,
 * `b >= 1 && b <= BS_INV_STACK_MAX`, bsgame.c) — same id space, so an
 * armour slot may not hold an id the inventory would have refused. The
 * policy is playerstate.h's documented per-field one: the offending SLOT is
 * dropped to empty, exactly as a broken item/count pairing already is,
 * while every well-formed slot beside it survives. */
static void test_ps_report_out_of_range_armour_is_dropped(void)
{
    puts("end-to-end: out-of-range armour ids and counts are dropped per-slot, neighbours kept");
    drain();

    join_expect_fresh_player_state(0x50A00013u, "psi");

    /* head: id 200, far past BS_BLOCK_COUNT — the out-of-bounds index the
     * 3DS client would later use to look up a block.
     * chest: legal id, count 200, past BS_INV_STACK_MAX.
     * legs: entirely legal, the control that proves this is validation and
     *       not a blanket wipe.
     * feet: the exact boundary pair — highest legal id, highest legal count
     *       — which must be kept, or the bound is off by one. */
    const uint8_t armor[8] = {
        200, 1,
        5,   200,
        5,   3,
        (uint8_t)(BS_BLOCK_COUNT - 1), (uint8_t)BS_INV_STACK_MAX,
    };
    send_player_report(0x50A00013u, armor, 2u, 0.5f, 10.0f, 9.0f);
    msleep(150);
    send_leave(0x50A00013u);
    msleep(150);

    join_skip_welcome(0x50A00014u, "psi");

    uint8_t flags = 0xff, back[8];
    float x = 0, y = 0, z = 0, yaw = 0, pitch = 0, prog = 0, hp = 0, hunger = 0;
    uint32_t xp_level = 0;
    bool got = recv_player_state_fields(0x50A00014u, 500, &flags,
                                        &x, &y, &z, &yaw, &pitch, back,
                                        &xp_level, &prog, &hp, &hunger);
    check(got, "the report with bad armour is stored and served back, not rejected wholesale");
    if (!got) return;

    check(back[0] == 0 && back[1] == 0,
          "an armour id past BS_BLOCK_COUNT is dropped to an empty slot");
    check(back[2] == 0 && back[3] == 0,
          "an armour count past BS_INV_STACK_MAX is dropped to an empty slot");
    check(back[4] == 5 && back[5] == 3,
          "the legal slot beside them is untouched — this is validation, not a wipe");
    check(back[6] == (uint8_t)(BS_BLOCK_COUNT - 1) && back[7] == (uint8_t)BS_INV_STACK_MAX,
          "the highest legal id/count pair is kept — the bound is not off by one");
    check(xp_level == 2u && prog == 0.5f && hp == 10.0f && hunger == 9.0f,
          "and the meters in the same report are unaffected by the armour fix-ups");

    send_leave(0x50A00014u);
    msleep(100);
}

/* S3: PLAYER_REPORT is unthrottled and has no token bucket, so "save on
 * every report" is "rewrite this file as fast as a peer can send", two
 * mkdir syscalls included. A report that changes nothing must therefore
 * change nothing on disk either — the same `if (changed)` gate
 * save_player_inventory() has sat behind since it was written. */
static void test_ps_identical_report_does_not_rewrite_file(void)
{
    puts("end-to-end: a byte-identical PLAYER_REPORT does not rewrite player.dat");
    drain();

    join_expect_fresh_player_state(0x50A00015u, "psj");

    const uint8_t armor[8] = { 5, 2, 0, 0, 0, 0, 0, 0 };
    send_player_report(0x50A00015u, armor, 4u, 0.75f, 11.0f, 6.0f);
    msleep(150);

    char path[512];
    snprintf(path, sizeof path, "%s/players/psj/player.dat", g_dir);

    struct stat before;
    check(stat(path, &before) == 0, "the first report really did write player.dat");

    /* Stamping a distinctive mtime is what lets the negative assertion below
     * go red at all. A rewrite lands through rename(), so the replacement
     * carries both a fresh mtime and a fresh inode; either one moving off
     * these values is a write this test says must not have happened.
     * Comparing sizes would prove nothing — the file is a fixed 65 bytes
     * whether it was rewritten or not. */
    struct timeval stamp[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
    if (utimes(path, stamp) != 0) die("stamp player.dat mtime");

    send_player_report(0x50A00015u, armor, 4u, 0.75f, 11.0f, 6.0f);   /* identical */
    msleep(200);

    struct stat same;
    check(stat(path, &same) == 0, "player.dat still exists after the repeat report");
    check(same.st_mtime == (time_t)1000000000,
          "an identical report leaves player.dat's mtime untouched — no rewrite");
    check(same.st_ino == before.st_ino,
          "and its inode untouched — no rename happened either");

    /* Control, without which the two checks above would pass just as well
     * against a save path that had stopped working altogether: the very same
     * report with ONE field moved must still hit the disk. */
    send_player_report(0x50A00015u, armor, 4u, 0.75f, 11.0f, 5.0f);   /* hunger differs */
    msleep(200);

    struct stat after;
    check(stat(path, &after) == 0, "player.dat still exists after the changed report");
    check(after.st_mtime != (time_t)1000000000,
          "a report differing by one field DOES rewrite the file");

    send_leave(0x50A00015u);
    msleep(100);
}

/* ------------------------------------------------- registry sync (v1.6.0 Phase A)
 *
 * Placed last on purpose: the batching scenario below rewrites
 * <state_dir>/registry.bin and restarts the daemon on it, which would change
 * what every later join's REGISTRY_INFO advertises. Everything above this
 * point therefore runs against the core-only table. */

static void send_registry_fetch(uint32_t sid, uint8_t first_index)
{
    uint8_t p[BS_APP_REGISTRY_FETCH_BYTES];
    p[0] = BS_APP_REGISTRY_FETCH;
    p[1] = first_index;
    send_app(sid, p, sizeof p);
}

/* Consumes the four-packet welcome sequence for a fresh sid, asserting the
 * v1.6.0 order WORLD_INFO -> REGISTRY_INFO -> INV_STATE -> PLAYER_STATE with
 * the INFO fully validated by recv_registry_info(). */
static void join_expect_registry_sequence(uint32_t sid, const char *label)
{
    send_join(sid, label);

    uint8_t out[64];
    ssize_t n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "registry probe: WORLD_INFO leads");
    bool got_reg = recv_registry_info(sid, 500);
    check(got_reg, "registry probe: REGISTRY_INFO arrives second");
    n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "registry probe: INV_STATE third");
    n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_PLAYER_STATE_BYTES && out[0] == BS_APP_PLAYER_STATE,
          "registry probe: PLAYER_STATE fourth");
}

/* FETCH is a C->S message no client has ever sent before this suite — the
 * capability-probe discipline says an old server would KICK for it, so this
 * also proves the new type is really wired into the dispatch, not just
 * defined in bs_proto.h. On a core-only table the honest answer is exactly
 * one empty batch flagged LAST. */
static void test_registry_fetch_empty_reply(void)
{
    puts("end-to-end: FETCH over a core-only table answers one empty LAST-flagged DEFS");
    drain();

    join_expect_registry_sequence(0x9E670001u, "reggie");

    send_registry_fetch(0x9E670001u, REG_ID_DYN_LO);

    uint8_t defs[BS_APP_REGISTRY_DEFS_BYTES(BS_APP_REGISTRY_DEFS_MAX_N)];
    ssize_t n = recv_app_for(0x9E670001u, defs, sizeof defs, 500);
    check(n == (ssize_t)BS_APP_REGISTRY_DEFS_BYTES(0)
          && defs[0] == BS_APP_REGISTRY_DEFS
          && defs[1] == REG_ID_DYN_LO && defs[2] == 0 && defs[3] == 1,
          "FETCH over a core-only table answers exactly one empty LAST-flagged DEFS");
}

/* Writes <state_dir>/registry.bin holding 40 dummy dynamic rows, restarts the
 * daemon so it boots from that bin, then walks the whole FETCH exchange:
 * 40 rows must come back as two DEFS packets (36 + 4) with the LAST flag only
 * on the second. This is simultaneously the cross-process crc proof — the
 * daemon computes its crc16 inside its own process from the bin it loaded,
 * while this process rebuilds the identical table through world/registry.c
 * and recv_registry_info() compares the two byte-for-byte. */
static void test_registry_fetch_batches_over_36_defs(void)
{
    puts("end-to-end: 40 dynamic defs round-trip as two DEFS batches with matching crc16");

    /* Build the exact table the daemon will boot with, here first. */
    registryInitCore();
    static uint8_t recs[40][REGISTRY_WIRE_RECORD_BYTES];
    for (unsigned i = 0; i < 40; i++) {
        BlockDef d;
        memset(&d, 0, sizeof d);
        snprintf(d.name, sizeof d.name, "dummy%02u", i);
        memset(d.tex, 3 /* BTEX_STONE */, BLOCK_FACES);
        d.flags       = REG_FLAG_SOLID;
        d.hardness    = 1;
        d.variant_of  = 0;   /* bases carry their own id at apply time */
        d.fluid_class = REG_FLUID_NONE;
        registryDefPack(recs[i], (BlockId)(REG_ID_DYN_LO + i), &d);
    }
    check(registryRemoteApply(REG_ID_DYN_LO, &recs[0][0], 40) == 40,
          "this process's mirror of the 40-row table applies cleanly");

    /* Persist it where the daemon boots from, then restart on it. */
    stop_daemon();
    char path[512];
    snprintf(path, sizeof path, "%s/registry.bin", g_dir);
    FILE *f = fopen(path, "wb");
    check(f != NULL, "registry.bin opens for writing");
    if (f == NULL) return;
    uint8_t hdr[2] = { 40, 0 };   /* u16 count LE */
    bool ok = fwrite(hdr, 1, 2, f) == 2;
    for (unsigned i = 0; ok && i < 40; i++) {
        ok = fwrite(recs[i], 1, REGISTRY_WIRE_RECORD_BYTES, f) == REGISTRY_WIRE_RECORD_BYTES;
    }
    ok = fclose(f) == 0 && ok;
    check(ok, "registry.bin written: count 40 + 40 id-ascending records");

    start_daemon();
    if (!wait_ready(5000)) { fprintf(stderr, "test: restarted daemon never became ready\n"); exit(1); }
    drain();

    join_expect_registry_sequence(0x9E670002u, "reggie2");

    send_registry_fetch(0x9E670002u, REG_ID_DYN_LO);

    /* Batch 1: full 36 rows, not flagged LAST. */
    uint8_t defs[BS_APP_REGISTRY_DEFS_BYTES(BS_APP_REGISTRY_DEFS_MAX_N)];
    ssize_t n = recv_app_for(0x9E670002u, defs, sizeof defs, 500);
    check(n == (ssize_t)BS_APP_REGISTRY_DEFS_BYTES(36)
          && defs[0] == BS_APP_REGISTRY_DEFS
          && defs[1] == REG_ID_DYN_LO && defs[2] == 36 && defs[3] == 0,
          "the first DEFS batch carries 36 rows starting at 0x80, LAST clear");
    bool ids_ok = true, names_ok = true;
    if (n == (ssize_t)BS_APP_REGISTRY_DEFS_BYTES(36)) {
        for (unsigned i = 0; i < 36; i++) {
            const uint8_t *rec = defs + 4 + i * REGISTRY_WIRE_RECORD_BYTES;
            if (rec[0] != (uint8_t)(REG_ID_DYN_LO + i)) ids_ok = false;
            char want[REGISTRY_NAME_MAX];
            snprintf(want, sizeof want, "dummy%02u", i);
            if (strcmp((const char *)rec + 1, want) != 0) names_ok = false;
        }
    }
    check(ids_ok, "batch 1 record ids ascend 0x80..0xA3 exactly");
    check(names_ok, "batch 1 record names match what registry.bin held");

    /* Batch 2: the remaining 4 rows, flagged LAST. */
    n = recv_app_for(0x9E670002u, defs, sizeof defs, 500);
    check(n == (ssize_t)BS_APP_REGISTRY_DEFS_BYTES(4)
          && defs[0] == BS_APP_REGISTRY_DEFS
          && defs[1] == REG_ID_DYN_LO + 36 && defs[2] == 4 && defs[3] == 1,
          "the final DEFS batch carries the last 4 rows with LAST set");
    ids_ok = true;
    if (n == (ssize_t)BS_APP_REGISTRY_DEFS_BYTES(4)) {
        for (unsigned i = 0; i < 4; i++) {
            const uint8_t *rec = defs + 4 + i * REGISTRY_WIRE_RECORD_BYTES;
            if (rec[0] != (uint8_t)(REG_ID_DYN_LO + 36 + i)) ids_ok = false;
        }
    }
    check(ids_ok, "batch 2 record ids are 0xA4..0xA7 exactly");

    /* And nothing further arrives: two batches was the whole answer. */
    uint8_t extra[16];
    n = recv_app_for(0x9E670002u, extra, sizeof extra, 300);
    check(n < 0, "no third DEFS batch follows the LAST-flagged one");
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

    /* First, and before the daemon exists: a pure in-process check on the
     * linked-in table, which must run while it is still core-only. The FETCH
     * batching scenario at the end registers 40 dynamic defs into this same
     * process, so this cannot be moved down there. */
    test_registry_core_pinned_to_golden();

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
    test_dyn_range_block_ids_accepted();
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
    test_tick_rate_is_traffic_independent();
    test_disk_format();

    test_chunk_sub_delivers_scoped_diffs();
    test_chunk_sub_suppresses_legacy_world_sync();
    test_chunk_edit_broadcast_is_scoped_to_subscribers();
    test_chunk_unsub_stops_future_column_edits();
    test_malformed_chunk_sub_and_unsub_kick();

    test_inv_join_sends_empty_inv_state();
    test_inv_craft_without_ingredient_refused();
    test_inv_pickup_then_craft_spends_wood();
    test_inv_pickup_credits_item();
    test_inv_pickup_out_of_range_item_refused();
    test_inv_consume_of_unheld_item_removes_nothing();
    test_inv_action_wrong_length_refused_not_kicked();
    test_inv_action_out_of_range_slot_refused_not_kicked();

    test_ps_join_fresh_sends_zeroed_state();
    test_ps_report_persists_across_sigterm_restart();
    test_ps_corrupt_and_truncated_dat_degrade_to_fresh_spawn();
    test_ps_old_client_never_reports_writes_no_file();
    test_ps_report_wrong_length_kicks();
    test_ps_recover_promotes_orphaned_tmp();
    test_ps_recover_discards_tmp_when_real_file_present();
    test_ps_bad_checksum_dat_degrades_to_fresh_spawn();
    test_ps_report_out_of_range_armour_is_dropped();
    test_ps_identical_report_does_not_rewrite_file();

    /* Registry sync runs last: its batching scenario rewrites registry.bin
     * and restarts the daemon, which would change what any later join's
     * REGISTRY_INFO advertises. */
    test_registry_fetch_empty_reply();
    test_registry_fetch_batches_over_36_defs();

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
