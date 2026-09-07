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
#include "cheststore.h"   /* v1.9.10: the transfer rules and chests.bin, exercised in-process */
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
 * recv_app_for drops a mismatched sid.
 *
 * v1.9.8: a packet whose payload type is BS_APP_WORLD_GEN or BS_APP_TIME_SYNC
 * is dropped too, for either sid, even on a first match. Both are ambient
 * background traffic unrelated to whatever this call is actually pairing up
 * (see recv_app_skip_gen's comment for the fuller rationale) -- and unlike
 * recv_app_skip_gen's retry loop, this function can't just keep reading past
 * one: capturing an ambient packet into *n_a or *n_b would falsely satisfy
 * that half of the wait, either stopping the read before the real packet
 * this caller wants ever arrives, or reading as a spurious non-negative
 * result on a check that asserts silence. */
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
        if (n >= 6 && (buf[5] == BS_APP_WORLD_GEN || buf[5] == BS_APP_TIME_SYNC)) continue;

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

/* v1.8.3 Phase 4. NULL for every start in this suite except the three inside
 * test_world_gen_persists_across_restart(), which is the only scenario that
 * needs the daemon brought up on a declaration it did not mint. A file-scope
 * knob rather than a parameter so the ~10 existing start_daemon() call sites
 * stay untouched — this is a test-harness detail, not a behaviour they have an
 * opinion about. */
static const char *g_forced_gen = NULL;

/* Which spelling g_forced_gen is passed with. "--world-gen" is guarded and
 * refuses to contradict a stored value on a --state-dir that has edits;
 * "--world-gen-force" overrides that. This suite needs both, because it forces
 * over its own scratch dir AFTER the scenarios that place blocks. */
static const char *g_forced_gen_flag = "--world-gen";

static void start_daemon(void)
{
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        if (g_forced_gen != NULL) {
            execl("./bsgame", "bsgame",
                  "--game-socket",     g_game_sock,
                  "--gate-socket",     g_gate_sock,
                  "--state-dir",       g_dir,
                  g_forced_gen_flag,   g_forced_gen,
                  (char *)NULL);
        } else {
            execl("./bsgame", "bsgame",
                  "--game-socket", g_game_sock,
                  "--gate-socket", g_gate_sock,
                  "--state-dir",   g_dir,
                  (char *)NULL);
        }
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
 * the way registry_test.c does for 0x7E5B -> 0x72A8 -> 0x4066.
 *
 * MOVED 2026-08-31, 10 -> 15 and 0x4066 -> 0x189B, and it WAS intended: client
 * v1.8.3 Phase 3 (6d4847e) appends five core rows -- snow, ice, cactus, dead
 * bush and fern -- and world/registry.c is one of the eleven files vendored
 * byte-identical from the client by tools/sync-world-sources.sh. So this pin
 * did exactly its job: it caught a deliberate content change arriving through
 * the mirror rather than through an edit to this repo.
 *
 * The instruction above was followed rather than short-cut. Neither number was
 * copied out of the failing printout. A probe that links ONLY registry.c and
 * crc32.c -- no test file, so no pinned literal is reachable from it -- was
 * compiled twice, once against this repo's game/world/ and once against the
 * client's source/world/, and both printed
 *
 *     count=15 crc16=0x189B rev=1
 *
 * which is the same independent-verification method the paragraph above
 * describes for the previous value, and which re-confirms the byte-identical
 * vendoring at the same time. All eleven mirrored files were separately checked
 * identical with cmp.
 *
 * REGISTRY_REV deliberately stays 1. It is the wire revision of the registry
 * protocol, not a hash of the rows; nothing about how the table is transmitted
 * changed, and the crc16 above is what detects content drift. Bumping it would
 * have told every already-deployed client the format had moved when it had not.
 *
 * Rows 0..9 are unchanged by that commit -- proved mechanically rather than by
 * reading, by a probe linking this tree's registry.c and the pre-Phase-3 one
 * and diffing only the old rows' output -- so a client built before v1.8.3 and
 * one built after still agree about every block either of them knows. What they
 * disagree about is the crc, which is exactly what registryMatchesInfo() is for
 * and why the server ships ahead of the client.
 *
 * MOVED AGAIN 2026-09-02, 0x189B -> 0xBDC5, by the client's v1.8.8, and this move is a
 * different shape from the one above: the COUNT does not move. It stays 15. No record was
 * added; exactly one byte inside one existing record changed value -- world/registry.c's
 * cactus row (id 12), .hardness 8 -> 9 -- which makes this task 50's shape, not Phase 3's.
 * So registryMatchesInfo() disagrees on the crc half only, and BS_PROTO_VERSION stays 1
 * because nothing about transport packet types changed.
 *
 * Why the byte moved at all: v1.8.8 is the first release in which a cactus can be broken.
 * The client's inventoryCanHold() used to reject any id >= BLOCK_COUNT (8), so a cactus
 * drop could never enter the bag and the block was effectively unbreakable; its .hardness
 * was a number nothing read. With the ceiling widened, that byte is now the block's break
 * time, and it was set to 9 so it is distinct from snow's 8 and ice's 10.
 *
 * Measured by ABLATION on the client tree, not by subtracting totals: rebuilding the real
 * registry.c with ONLY the cactus hardness put back to 8 reproduces 0x189B exactly, which
 * proves the ceiling widening itself is crc-neutral (it is a predicate; predicates store no
 * bytes) and that this entire move belongs to the durability retune.
 *
 * The lockstep rule above still holds and still points the same way: the SERVER SHIPS
 * FIRST.
 *
 * MOVED A THIRD TIME 2026-09-02, 0xBDC5 -> 0xD236, and this time the COUNT moves with it,
 * 15 -> 27. This is the rest of the client's v1.8.8: twelve new core rows, ids 15..26 --
 * birch_log/birch_planks/birch_leaves, spruce_log/spruce_planks/spruce_leaves,
 * tall_grass_top, poppy/daisy/bluebell/orchid, apple. So this move has Phase 3's shape
 * (records ADDED, count moves), not the cactus retune's (one byte inside an existing row).
 *
 * BS_PROTO_VERSION and REGISTRY_REV both stay 1, for the same reason as both moves above:
 * twelve more records travel over a wire whose format did not change. What moved is the
 * CONTENT of the table, which is exactly what registryMatchesInfo()'s crc half is for.
 *
 * Rows 0..14 are untouched by this change -- nothing was renumbered and no existing row's
 * hardness was retuned -- so the only thing a v1.8.7 client and a v1.8.8 one disagree about
 * is the twelve rows the older one has never heard of.
 *
 * That asymmetry is why the ordering matters more here than it did for the cactus byte. A
 * NEW client joining an OLD server is a refused join: loud, immediate, recoverable. The
 * reverse -- an OLD client on a NEW server -- is the dangerous direction, because every
 * birch log, spruce leaf and flower the server places is an id that client cannot name, and
 * it would render them as holes rather than as an error. The crc refusing the join is the
 * only thing standing between those two cases, so a server carrying 0xD236 has to be
 * DEPLOYED BEFORE the client that generates these blocks is released.
 *
 * Measured, not copied out of a failing printout: the probe method this comment describes
 * for 0x189B was re-run for this move -- registry.c and crc32.c only, no test file linked,
 * so no pinned literal is reachable from the binary and it cannot echo back the number it
 * is meant to be checking. Compiled once against this repo's game/world/ and once against
 * the client's source/world/. Both printed
 *
 *     count=27 crc16=0xD236 rev=1
 *
 * and all eleven mirrored files were separately confirmed byte-identical with cmp after
 * tools/sync-world-sources.sh ran (it reported block.h and registry.c synced, the other
 * nine unchanged).
 *
 * MOVED A FOURTH TIME 2026-09-02, 0xD236 -> 0x165E, by the client's v1.8.10 "Light", which
 * appends ONE core row -- torch, id 27 -- the first light source. registryCount() moves
 * 27 -> 28 with it, Phase-3's shape again: a record APPENDED, not a byte retuned inside an
 * existing one. torch is BLOCK_SHAPE_CROSS, non-solid (REG_FLAG_TRANSPARENT), luminance 14
 * (REG_FLAG_LUMINOUS set alongside it, matching the pairing convention every other lit test
 * row already uses even though light.c reads only the .luminance byte), and .hardness 1 --
 * the smallest nonzero value the byte allows, since 0 is reserved for "no break time at
 * all" (air, water) and every other targetable core row is nonzero for the same reason: a
 * torch must be breakable with its own durability, never instant and never unbreakable.
 *
 * Measured the same way as the 0xD236 move above -- probe linking registry.c alone (no
 * test file, so the golden is not reachable from the binary being measured), compiled once
 * against the client's source/world/registry.c and once against this repo's own
 * game/world/registry.c after tools/sync-world-sources.sh ran (it reported block.h and
 * registry.c synced, the other nine unchanged, and diff -q confirmed both copies
 * byte-identical). Both printed
 *
 *     count=28 crc16=0x165E rev=1
 *     id27: name=torch hardness=1 luminance=14 flags=0x2A tex0=31
 *
 * The lockstep rule is unchanged and points the same way: this row is a defined, breakable,
 * light-emitting block a v1.8.9 client has never heard of, so the SERVER SHIPS FIRST -- a
 * v1.8.9 client joining a v1.8.10 server fails registryMatchesInfo() on both halves and
 * refuses the join (loud, recoverable); the reverse would render every torch as an
 * unnamed hole. BS_PROTO_VERSION stays 1: nothing about transport packet types changed.
 *
 * MOVED A FIFTH TIME 2026-09-02/03, 0x165E -> 0xE15E, by the client's v1.8.12 "Ores", which
 * appends SIX core rows -- coal_ore/iron_ore/gold_ore/redstone_ore/lapis_ore/diamond_ore,
 * ids 28..33. registryCount() moves 28 -> 34, Phase-3's shape again: six records APPENDED,
 * nothing renumbered. All six are FULL_CUBE, SOLID (not TRANSPARENT: the art is fully
 * opaque), and each carries its OWN hardness rather than a flat value -- a six-step ladder,
 * coal 60 < iron 70 < lapis 80 < gold 85 < redstone 90 < diamond 100, every step above
 * stone's 45. No tool-tier gate in this client version: every ore is breakable by hand.
 *
 * Measured the same way as every move above -- a probe linking registry.c alone (no test
 * file, so the golden is not reachable from the binary being measured), compiled once
 * against the client's source/world/registry.c and once against this repo's own
 * game/world/registry.c (block.h and registry.c copied byte-for-byte from the client tree;
 * `cmp` on all eleven mirrored files confirmed the other nine untouched and these two
 * identical).
 *
 * Corrected 2026-09-03: this parenthesis used to claim "there is no
 * tools/sync-world-sources.sh in this repo despite this comment block's earlier entries
 * assuming one." That was wrong, and it was wrong in the one place it is most misleading --
 * THIS repo is the repo the script lives in. It sits at tools/sync-world-sources.sh relative
 * to the root of the repository containing this file, which is exactly what every earlier
 * entry meant. Run from that root it reported all eleven mirrored files `unchanged`,
 * "game/world/ was already in sync", exit 0. game/Makefile's `check-world-drift` target names
 * it as the fix when the two trees diverge, so a reader who believes it does not exist
 * hand-copies the mirror instead -- which is precisely how eleven files that must stay
 * byte-identical drift apart.
 *
 * Both printed
 *
 *     count=34 crc=0xE15E
 *     id=28 name=coal_ore     hardness= 60 flags=0x01 tex0=32
 *     id=29 name=iron_ore     hardness= 70 flags=0x01 tex0=33
 *     id=30 name=gold_ore     hardness= 85 flags=0x01 tex0=34
 *     id=31 name=redstone_ore hardness= 90 flags=0x01 tex0=35
 *     id=32 name=lapis_ore    hardness= 80 flags=0x01 tex0=36
 *     id=33 name=diamond_ore  hardness=100 flags=0x01 tex0=37
 *     zero-hardness-count=0
 *
 * The lockstep rule is unchanged and points the same way: these six rows are defined,
 * breakable blocks a v1.8.11 client has never heard of, so the SERVER SHIPS FIRST -- a
 * v1.8.11 client joining a v1.8.12 server fails registryMatchesInfo() on both halves and
 * refuses the join (loud, recoverable); the reverse would render every ore as an unnamed
 * hole. BS_PROTO_VERSION stays 1: nothing about transport packet types changed. REGISTRY_REV
 * stays 1: appending rows is not a change in the MEANING of existing fields.
 *
 * NOT MOVED WITH THIS RELEASE, and flagged rather than fixed here: test_registry_core...
 * pins only count/crc/rev. A SEPARATE test in this same file,
 * test_inv_pickup_undefined_core_id_refused(), relies on core id 28 being UNDEFINED (its own
 * comment: "Goes red the day the registry grows to 29 core rows without this test moving --
 * which is the point"). Id 28 is now BLOCK_COAL_ORE, a defined row, so that test's premise no
 * longer holds and it needs its literal moved from 28 to 34 (one past this new golden) by
 * whoever lands this alongside a full server-suite run. That edit is test LOGIC, not a
 * golden, and is out of this lane's scope.
 *
 * MOVED A SIXTH TIME 2026-09-03, 0xE15E -> 0x9610, by the client's v1.8.14 "Animals", which
 * appends FOUR core rows -- raw_porkchop/raw_beef/raw_chicken/raw_mutton, ids 34..37.
 * registryCount() moves 34 -> 38, the same shape as every move above: four records APPENDED,
 * nothing renumbered.
 *
 * ⚠ 34..37 AND NOT 27..30. The client's docs/plan-1.8.14-animals.md names 27..30 for these
 * rows and it is STALE -- it was written before v1.8.10's torch took 27 and before v1.8.12's
 * six ores took 28..33. The first free core id was read off BLOCK_DIAMOND_ORE == 33 in the
 * live tree, not off the plan. Recording it here because a reader who trusts that document
 * over this table renumbers four ids that are already on players' SD cards.
 *
 * All four are FULL_CUBE and SOLID, not TRANSPARENT -- the art is fully opaque, and the same
 * argument the ore rows make applies: claiming TRANSPARENT would push four cube rows into the
 * client mesher's deferred pass and cost every internal face they have for nothing. They
 * follow the BLOCK_APPLE mould rather than the plant mould deliberately: the client's
 * blockDropsNothing() answers from the SHAPE and hands the bag BLOCK_AIR for every CROSS
 * block, so a CROSS meat row would be an animal you kill and get nothing from.
 *
 * Each carries its OWN hardness rather than a flat value -- a four-step ladder ordered by the
 * size of the animal, chicken 3 < porkchop 4 < mutton 5 < beef 6, every step above the
 * 1-tick floor the plants sit at and every step far under stone's 45 (this is soft material).
 * A flat value across all four is the exact failure mode the client's coreHardnessIsDeclared()
 * exists to catch.
 *
 * Measured the same way as every move above -- a probe (animb_meat_crc_probe.c) linking
 * registry.c alone, no test file, so the golden below is not reachable from the binary being
 * measured. Compiled once against the client's source/world/registry.c and once against this
 * repo's own game/world/registry.c after tools/sync-world-sources.sh ran (it reported block.h
 * and registry.c `synced` and the other nine `unchanged`; `cmp` on all eleven then reported
 * every one identical). Both printed
 *
 *     count=38 crc=0x9610 rev=1
 *     id=34 name=raw_porkchop  hardness=  4 flags=0x01 tex0=38 solid=1 liquid=0
 *     id=35 name=raw_beef      hardness=  6 flags=0x01 tex0=39 solid=1 liquid=0
 *     id=36 name=raw_chicken   hardness=  3 flags=0x01 tex0=40 solid=1 liquid=0
 *     id=37 name=raw_mutton    hardness=  5 flags=0x01 tex0=41 solid=1 liquid=0
 *     targetable-rows=36 zero-hardness-count=0
 *
 * The lockstep rule is unchanged and points the same way: these four rows are defined,
 * breakable, carryable blocks a v1.8.13 client has never heard of, so the SERVER SHIPS FIRST
 * -- a v1.8.13 client joining a v1.8.14 server fails registryMatchesInfo() on both halves and
 * refuses the join (loud, recoverable); the reverse would hand a player meat the client cannot
 * name. BS_PROTO_VERSION stays 1: nothing about transport packet types changed. REGISTRY_REV
 * stays 1: appending rows is not a change in the MEANING of existing fields.
 *
 * MOVED WITH THIS RELEASE, unlike last time: test_inv_pickup_undefined_core_id_refused()'s
 * literal goes 34 -> 38, because id 34 is now BLOCK_RAW_PORKCHOP and that test's whole premise
 * is an id that is NOT defined. The previous entry left that edit for a following lane and
 * said so; this one does it in the same commit, because a golden that moves without it leaves
 * the suite red for a reason unrelated to the golden.
 *
 * MOVED A SEVENTH TIME 2026-09-03, 0x9610 -> 0xE486, by the client's v1.8.15 "Furnace", which
 * appends FIVE core rows -- cooked_porkchop/cooked_beef/cooked_chicken/cooked_mutton at ids
 * 38..41, and the furnace itself at 42. registryCount() moves 38 -> 43, the same shape as every
 * move above: five records APPENDED, nothing renumbered.
 *
 * The four cooked meats mirror the raw cuts they are smelted from, row for row -- FULL_CUBE and
 * SOLID like them (a CROSS cooked chop would hit the client's blockDropsNothing() and yield
 * nothing, which defeats the point of cooking it), and carrying the SAME hardness ladder
 * ordered by animal size, chicken 3 < porkchop 4 < mutton 5 < beef 6. The furnace is built out
 * of stone and prices like it at hardness 45, and reuses BTEX_STONE on five of its six faces,
 * so its row's tex0 is 3 -- an EXISTING tile -- rather than a new one; only the front face
 * needs new art, twice over, once per lit state.
 *
 * Measured the same way as every move above -- a probe (srve_furnace_crc_probe.c) linking
 * registry.c alone, no test file, so the golden below is not reachable from the binary being
 * measured and cannot launder a wrong pin into a matching answer. Compiled once against this
 * repo's own game/world/registry.c after tools/sync-world-sources.sh ran (it reported block.h
 * and registry.c `synced` and the other nine `unchanged`) and once against the client's
 * source/world/registry.c. Both printed
 *
 *     count=43 crc=0xE486 rev=1
 *     id=38 name=cooked_porkchop  hardness=  4 flags=0x01 tex0=42
 *     id=39 name=cooked_beef      hardness=  6 flags=0x01 tex0=43
 *     id=40 name=cooked_chicken   hardness=  3 flags=0x01 tex0=44
 *     id=41 name=cooked_mutton    hardness=  5 flags=0x01 tex0=45
 *     id=42 name=furnace          hardness= 45 flags=0x01 tex0= 3
 *     first-undefined-core-id=43
 *
 * A THIRD arm ran that same probe against this repo's PRE-sync game/world/registry.c,
 * reconstructed out of `git show HEAD:game/world/...`, and printed count=38 crc=0x9610 rev=1
 * with first-undefined-core-id=38. That arm is what makes the two numbers below evidence
 * rather than assertion: the probe demonstrably reports whatever registry it is linked
 * against, so a golden that agrees with it is not a golden edited until the suite went quiet.
 *
 * The lockstep rule is unchanged and points the same way, and this release is the sharpest case
 * of it so far: these five rows are defined blocks a v1.8.14 client has never heard of, so the
 * SERVER SHIPS FIRST -- a v1.8.14 client joining a v1.8.15 server fails registryMatchesInfo()
 * on both halves and refuses the join (loud, recoverable). The reverse is NOT loud here: the
 * client's source/net/networld.c:260-328 degrades an id the server does not define down to
 * air, so a v1.8.15 player against a v1.9.4 server would watch furnaces quietly disappear and
 * be told nothing at all. BS_PROTO_VERSION stays 1: nothing about transport packet types
 * changed. REGISTRY_REV stays 1: appending rows is not a change in the MEANING of existing
 * fields.
 *
 * MOVED WITH THIS RELEASE, as v1.9.4 did: test_inv_pickup_undefined_core_id_refused()'s literal
 * goes 38 -> 43, because id 38 is now BLOCK_COOKED_PORKCHOP and that test's whole premise is an
 * id that is NOT defined. 43 is what the probe's first-undefined-core-id line above reports --
 * read off the table, not inferred from the count.
 *
 * MOVED AN EIGHTH TIME 2026-09-05, 0xE486 -> 0x2A61, by the client's v1.9.0 "Storage", which
 * appends ONE core row -- the chest at id 43. registryCount() moves 43 -> 44, the same shape as
 * every move above: one record APPENDED, nothing renumbered. The client's block.h carries a
 * _Static_assert(BLOCK_CHEST == 43) saying so in as many words.
 *
 * FULL_CUBE and SOLID like the furnace before it, hardness 40 -- matching BLOCK_PLANKS exactly,
 * because it is crafted from planks, the same argument the furnace's row makes for stone. Its
 * tex0 is 9 (BTEX_PLANKS): five of six faces reuse plank art and only FACE_TOP carries the one
 * new tile, atlas slot 57.
 *
 * Measured the same way as every move above -- a probe (chest_crc_probe.c) linking registry.c
 * alone, no test file, so the golden below is not reachable from the binary being measured.
 * Compiled and run TWICE, once against the client's source/world/registry.c and once against
 * this repo's own game/world/registry.c after tools/sync-world-sources.sh ran (it reported
 * block.h and registry.c `synced` and the other nine `unchanged`; `cmp` on the two registry.c
 * files then reported them identical). Both arms printed
 *
 *     count=44 crc=0x2A61 rev=1
 *     id=40 name=cooked_chicken  hardness=  3 flags=0x01 tex0=44
 *     id=41 name=cooked_mutton   hardness=  5 flags=0x01 tex0=45
 *     id=42 name=furnace         hardness= 45 flags=0x01 tex0= 3
 *     id=43 name=chest           hardness= 40 flags=0x01 tex0= 9
 *
 * The lockstep rule points the same way as v1.8.15 and for the same reason: the chest is a
 * defined block a v1.8.20 client has never heard of, so the SERVER SHIPS FIRST. A v1.8.20
 * client joining this server fails registryMatchesInfo() on both halves and refuses the join,
 * which is loud and recoverable; the reverse is silent, because the client degrades an id the
 * server does not define down to air, so the player would watch chests disappear and be told
 * nothing. BS_PROTO_VERSION stays 1 -- no transport packet type changed. REGISTRY_REV stays 1
 * -- appending a row is not a change in the MEANING of existing fields.
 *
 * ⚠ THE CHEST'S CONTENTS ARE NOT COVERED BY ANY OF THIS. This row makes the server agree with
 * the client about what block id 43 IS, which is all a registry row ever does. The server has
 * no BlockStateTable and no chest store, so a chest placed on a server is a shared block with
 * per-client contents until the opcodes in the client's docs/design-1.9.0-chest-multiplayer.md
 * are built here. Shipping the row without them is deliberate and is the lockstep rule working
 * as intended -- it is what lets the client's capability gate see an old server -- but it must
 * not be mistaken for chest support.
 *
 * MOVED WITH THIS RELEASE, as v1.9.4 and v1.9.5 did:
 * test_inv_pickup_undefined_core_id_refused()'s literal goes 43 -> 44, because id 43 is now
 * BLOCK_CHEST and that test's whole premise is an id that is NOT defined. This one did NOT rot
 * silently the way that function's own comment warns it can: id 43 is holdable, so the pickup
 * was applied and `the undefined id was never applied` went red. It went red as one of exactly
 * three failures in the run ("FAIL 337 checks, 3 failed"), the other two being the two goldens
 * above -- which is the control that says the suite noticed the row rather than absorbing it. */
#define BS_REGISTRY_CORE_COUNT_GOLDEN 44u
#define BS_REGISTRY_CORE_CRC16_GOLDEN 0x2A61u
#define BS_REGISTRY_REV_GOLDEN        1u

static void test_registry_core_pinned_to_golden(void)
{
    puts("registry: the core table matches a pinned golden, not only itself");
    registryInitCore();
    check(registryCount() == BS_REGISTRY_CORE_COUNT_GOLDEN,
          "core-only registryCount() matches the pinned golden 44");
    check(registryCrc16() == BS_REGISTRY_CORE_CRC16_GOLDEN,
          "core-only registryCrc16() matches the pinned golden 0x2A61");
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

/* v1.8.3 Phase 4. What every join in this run must be told the generator is.
 * Spelled out rather than read back off the wire and compared to itself: a test
 * that only checks the second packet agrees with the first would stay green if
 * the daemon declared 7 to everyone.
 *
 * 5 as of the mint-by-evidence change: this is the client's GEN_VERSION_ORES,
 * the newest terrain it ships, and it is what bsgame.c's BSGAME_WORLD_GEN_FRESH
 * mints an EMPTY --state-dir at. This suite always runs against a scratch
 * directory it just created, so the mint sees no block_diffs.bin and takes the
 * fresh branch rather than the legacy one. It was 1 before that change, when the
 * mint was an unconditional constant. */
#define BSGAME_TEST_WORLD_GEN 5u

/* Reads the BS_APP_WORLD_GEN that rides immediately behind WORLD_INFO, and
 * checks its POSITION IN THE BURST as well as its bytes.
 *
 * The position matters as much as the value and is easy to lose: recv_app_for()
 * filters by session id only, never by message type, so if send_world_gen()
 * were moved below send_registry_info() this helper would read the REGISTRY_INFO
 * instead — and every later read in the caller would be off by one packet. That
 * is exactly what makes the ordering assertion here real rather than decorative.
 *
 * The byte-level little-endian check is separate from the value check on
 * purpose. bs_get_u16() is this repo's own decoder, so a value check alone
 * passes against a big-endian encoder as long as both sides are wrong the same
 * way — the whole failure mode interop_test.c exists for. Checking out[1]/out[2]
 * against the literal bytes is the half that does not go through bs_get_u16.
 *
 * Returns false when the packet was not a WORLD_GEN at all, so a caller can
 * bail rather than read the rest of the burst at the wrong offset. */
static bool recv_world_gen(uint32_t sid, unsigned ms)
{
    uint8_t out[64];
    memset(out, 0, sizeof out);
    ssize_t n = recv_app_for(sid, out, sizeof out, ms);

    const bool shaped = (n == (ssize_t)BS_WORLD_GEN_BYTES && out[0] == BS_APP_WORLD_GEN);
    check(shaped, "WORLD_GEN rides second in the join burst, behind WORLD_INFO and ahead of"
                  " REGISTRY_INFO, exactly BS_WORLD_GEN_BYTES long");
    if (!shaped) return false;

    check(bs_get_u16(out + 1) == BSGAME_TEST_WORLD_GEN,
          "WORLD_GEN declares generator 5 (ores) — what an empty --state-dir mints, which is"
          " the newest terrain the client ships");
    check(out[1] == 0x05 && out[2] == 0x00,
          "WORLD_GEN's version field is little-endian on the wire: the three bytes are"
          " {0x0F, 0x05, 0x00}, checked without going through bs_get_u16");
    return true;
}

/* v1.9.0. recv_app_for, but discarding BS_APP_WORLD_GEN.
 *
 * bsgame.c now resends WORLD_GEN twice after the join burst, one tick apart, so
 * for the first ~100 ms of a session that message can turn up between any two
 * other packets. recv_app_for filters by session id and never by type, so a test
 * reading a SEQUENCE would either mis-type the packet it wanted or, worse, find
 * something where it asserted nothing arrives. Three checks failed exactly that
 * way the first time the resend went in — the failure was in the suite's
 * assumptions, not in the daemon, and this is the repair.
 *
 * v1.9.8: also discards BS_APP_TIME_SYNC, for the identical reason one size up.
 * send_time_sync() (bsgame.c) puts one on the wire at the end of every join
 * burst AND once a second forever after (tickDue(t, TICK_HZ, 0)), so any test
 * whose wait window runs past a one-second boundary — several of the
 * broadcast/silence scenarios below do — can have a TIME_SYNC land in the
 * middle of a sequence it did not ask for. It is exactly the same shape of bug
 * WORLD_GEN's resends caused, so it gets exactly the same fix: skipped here,
 * still counted, still visible only to a caller that asks.
 *
 * Deliberately NOT used by recv_world_gen() above, and that separation is the
 * whole point. recv_world_gen asserts WHERE in the burst WORLD_GEN sits; a
 * helper that skipped the message would turn that assertion into a tautology.
 * The same logic is why join_expect_registry_sequence() (this file) reads its
 * trailing TIME_SYNC with recv_app_for directly rather than through here —
 * that packet's position is the thing under test. Every other reader wants
 * the next packet that is neither kind of ambient background noise.
 *
 * The skip is counted and returned so a caller can still see them if it cares;
 * nothing does yet, and a test that asserted silence would be lying if it could
 * not tell "nothing came" from "only ambient packets came". */
static ssize_t recv_app_skip_gen(uint32_t sid, uint8_t *out, size_t cap, unsigned ms,
                                 unsigned *skipped)
{
    if (skipped) *skipped = 0;
    const uint64_t until = now_ms() + ms;

    for (;;) {
        const uint64_t now = now_ms();
        if (now >= until) return -1;

        const ssize_t n = recv_app_for(sid, out, cap, (unsigned)(until - now));
        if (n < 1) return n;
        if (out[0] != BS_APP_WORLD_GEN && out[0] != BS_APP_TIME_SYNC) return n;
        if (skipped) (*skipped)++;
    }
}

/* v1.9.10. Reads the BS_APP_SERVER_CAPS that now closes every join burst.
 *
 * This helper is a REPAIR as much as it is coverage. send_server_caps()
 * (bsgame.c) was added to the tail of handle_join(), one packet behind
 * TIME_SYNC, and the burst readers in this file were not told: the skip above
 * discards WORLD_GEN and TIME_SYNC and nothing else, and
 * join_expect_registry_sequence() stopped counting at TIME_SYNC. Four checks
 * went red as a result — the legacy WORLD_SYNC wait in
 * test_join_sends_world_info_then_sync() caught SERVER_CAPS instead, and both
 * registry FETCH scenarios read it where they expected a DEFS batch. The
 * daemon is right and the suite was stale; consuming the packet HERE, with
 * assertions on it, is the fix that does not make the extra packet invisible.
 *
 * Read through recv_app_skip_gen rather than recv_app_for because the two
 * callers arrive here differently: join_expect_registry_sequence() has just
 * consumed the burst's TIME_SYNC explicitly, and
 * test_join_sends_world_info_then_sync() reads the whole burst with the skip
 * and so has not. That costs no strictness — SERVER_CAPS's position behind
 * TIME_SYNC is pinned in the caller that cares about it, by the TIME_SYNC
 * check standing immediately in front of this call. */
static bool recv_server_caps(uint32_t sid, unsigned ms)
{
    uint8_t out[64];
    memset(out, 0, sizeof out);
    unsigned skipped = 0;
    const ssize_t n = recv_app_skip_gen(sid, out, sizeof out, ms, &skipped);

    const bool shaped = (n == (ssize_t)BS_SERVER_CAPS_BYTES && out[0] == BS_APP_SERVER_CAPS);
    check(shaped, "v1.9.10: SERVER_CAPS closes the join burst, behind the state packets, exactly"
                  " BS_SERVER_CAPS_BYTES long");
    if (!shaped) return false;

    check((bs_get_u32(out + 1) & BS_CAP_CHESTS) != 0,
          "and it advertises BS_CAP_CHESTS — this build keeps chest contents server-side, so a"
          " client may open one");
    check(out[1] == 0x01 && out[2] == 0x00 && out[3] == 0x00 && out[4] == 0x00,
          "the caps word is little-endian on the wire: the four bytes are {0x01, 0x00, 0x00,"
          " 0x00}, checked without going through bs_get_u32");
    return true;
}

/* v1.9.0. How many BS_APP_WORLD_GEN datagrams one join must put on the wire:
 * the join burst's own, plus bsgame.c's BS_WORLD_GEN_RESENDS.
 *
 * A LITERAL ON PURPOSE, for the reason BSGAME_TEST_WORLD_GEN above is one.
 * bsgame.c's constants are not visible here anyway — this suite is a separate
 * process talking over the gateway socket — but even if they were, a test that
 * counted `1 + BS_WORLD_GEN_RESENDS` would agree with the daemon no matter what
 * that number became, including zero. Three is the claim being made: enough that
 * a silent downgrade to the legacy generator needs three losses in 100 ms rather
 * than one, and few enough to fit inside the client's 250 ms
 * NETWORLD_GEN_GRACE_MS with 150 ms to spare. */
#define BSGAME_TEST_WORLD_GEN_COPIES 3u

/* v1.9.0. The resend schedule, end to end against the real daemon.
 *
 * What this is defending: the transport is plain UDP with no retransmission, and
 * WORLD_GEN is the only packet in the join burst whose loss is silent AND wrong.
 * A client that never hears it waits out its own 250 ms grace, decides the server
 * is too old to have an opinion, and generates the LEGACY terrain — a different
 * world from everyone else's, with both sides believing they agree. There is no
 * C->S message to ask again with and adding one is banned in that direction, so
 * the only place the repair can live is here.
 *
 * Counts rather than reading positions, deliberately. recv_world_gen() above
 * pins the burst ORDER and is the right tool for that; this one has to survive
 * two more copies arriving in among REGISTRY_INFO, INV_STATE and PLAYER_STATE,
 * whose interleaving with a 50 ms timer is not something a test should pin. */
static void test_world_gen_is_resent_after_join(void)
{
    puts("end-to-end: WORLD_GEN is resent, so one lost datagram cannot silently"
         " downgrade a client to the legacy generator");
    drain();

    const uint32_t sid = 0x9E43110Fu;
    send_join(sid, "genresend");

    /* 300 ms: past the last scheduled resend at 100 ms with room for a late
     * tick, and short of BS_CHUNK_LEGACY_GRACE_MS (500) so the full WORLD_SYNC
     * that fires there cannot land inside the window. A window that spanned two
     * different timers would make a failure ambiguous about which one broke. */
    const uint64_t until = now_ms() + 300u;

    unsigned seen = 0;
    unsigned malformed = 0;
    unsigned spins = 0;
    for (;;) {
        const uint64_t now = now_ms();
        if (now >= until) break;
        /* recv_app_for returns -1 both on timeout and on a packet it cannot
         * file, so the deadline alone is not a guaranteed exit. */
        if (++spins > 512u) break;

        uint8_t out[2048];
        const ssize_t n = recv_app_for(sid, out, sizeof out, (unsigned)(until - now));
        if (n < 1) continue;
        if (out[0] != BS_APP_WORLD_GEN) continue;

        seen++;
        if (n != (ssize_t)BS_WORLD_GEN_BYTES) { malformed++; continue; }
        if (bs_get_u16(out + 1) != BSGAME_TEST_WORLD_GEN) malformed++;
    }

    /* Each of the first two was made to go red on its own, against production code,
     * before this test was believed:
     *
     *   seen      — bsgame.c's resend site reduced to `(void)0`, so the block still
     *               runs on schedule and still counts but puts nothing on the wire,
     *               which is exactly the behaviour before this change. Result:
     *               "FAIL 292 checks, 1 failed", this check and only this check,
     *               total unchanged, so the arm failed a check rather than deleting
     *               any. (Arming it at BS_WORLD_GEN_RESENDS 2u -> 0u does not
     *               compile: a uint8_t < 0u is -Werror=type-limits.)
     *   malformed — send_world_gen() shortened by one byte. Result: this check red
     *               while `seen` stayed green, so the two are not the same claim.
     *               That arm is over-broad and is NOT a clean one — a short
     *               WORLD_GEN breaks every positional join-burst read in the suite
     *               and the total fell from 292 to 184. It shows this check can
     *               fail; it shows nothing else.
     *
     * The third is deliberately not a claim about the daemon. It is this test's own
     * runaway guard, green in both arms and in the fixed build, and it is here so a
     * `seen` failure can never be blamed on the loop having exited early. */
    check(seen == BSGAME_TEST_WORLD_GEN_COPIES,
          "one join puts three WORLD_GEN datagrams on the wire: the burst's own plus two"
          " resends one tick apart");
    check(malformed == 0,
          "every resent copy is a whole BS_WORLD_GEN_BYTES declaring the same generator —"
          " a resend that disagreed with the first would be worse than no resend at all");
    check(spins <= 512u, "the collection loop terminated on its deadline, not on its"
                         " runaway guard");
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
    unsigned gen_skipped = 0;
    ssize_t n = recv_app_skip_gen(0xA11CE001u, out, sizeof out, 500, &gen_skipped);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "the first packet after JOIN is WORLD_INFO");
    if (n == (ssize_t)BS_WORLD_INFO_BYTES) {
        g_seen_seed = bs_get_u32(out + 1);
        check(g_seen_seed != 0, "WORLD_INFO carries a non-zero world seed");
    }

    /* v1.8.3 Phase 4: WORLD_GEN took the slot immediately behind WORLD_INFO,
     * so it has to be consumed before REGISTRY_INFO is looked for — see
     * recv_world_gen() for why reading it in the right place is itself the
     * ordering assertion. */
    (void)recv_world_gen(0xA11CE001u, 500);

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
    n = recv_app_skip_gen(0xA11CE001u, out, sizeof out, 500, &gen_skipped);
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
    n = recv_app_skip_gen(0xA11CE001u, out, sizeof out, 500, &gen_skipped);
    check(n == (ssize_t)BS_PLAYER_STATE_BYTES && out[0] == BS_APP_PLAYER_STATE,
          "JOIN's fourth packet is the PLAYER_STATE capability probe");

    /* v1.9.10: and SERVER_CAPS closes the burst behind it. Consumed here for
     * the same reason PLAYER_STATE is consumed above — recv_app_skip_gen()
     * does not skip it, so the legacy-WORLD_SYNC wait below would otherwise
     * catch it and fail on a type mismatch that has nothing to do with what
     * this scenario is about. (It did, until this line went in.) */
    (void)recv_server_caps(0xA11CE001u, 500);

    n = recv_app_skip_gen(0xA11CE001u, out, sizeof out,
                          BS_CHUNK_LEGACY_GRACE_MS + 400u, &gen_skipped);
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

    /* The sender (alice) must not see her own edit echoed back. v1.9.8:
     * recv_app_skip_gen so a TIME_SYNC broadcast landing in this window is
     * not mistaken for an echo -- see recv_app_skip_gen's comment. */
    n = recv_app_skip_gen(0xA11CE001u, out, sizeof out, 300, NULL);
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

    /* v1.9.8: recv_app_skip_gen -- see recv_app_skip_gen's comment for why a
     * TIME_SYNC broadcast in this window must not be mistaken for the
     * rejected-edit broadcast this test asserts never happens. */
    uint8_t out[64];
    ssize_t n = recv_app_skip_gen(0xB0B00002u, out, sizeof out, 400, NULL);
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
 * side. v1.9.1: that boundary itself moved again, off BS_BLOCK_COUNT and onto
 * the registry's own core count, when the item-id guard became
 * inventoryCanHold() — see test_inv_pickup_undefined_core_id_refused() for
 * the current "one past the end is refused" item-id check;
 * test_inv_pickup_out_of_range_item_refused() still exists but now checks a
 * different thing (a defined id refused for being a liquid, not for being
 * out of range) — see that test's own comment. */
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
    /* v1.9.8: recv_app_skip_gen on both of these -- the once-a-second
     * TIME_SYNC broadcast (send_time_sync(), bsgame.c) can land in either
     * 400ms window regardless of anything this test does, and recv_app_for
     * would mistake that ambient packet for the rejected-edit broadcast this
     * test is asserting never happens. See recv_app_skip_gen's comment. */
    drain();
    send_block_edit(0xA11CE001u, 7200, 12, 7200, (uint8_t)(REG_ID_DYN_HI + 1) /* 0xFE */);
    n = recv_app_skip_gen(0xB0B00002u, out, sizeof out, 400, NULL);
    check(n < 0, "an edit one past the highest dynamic block id (0xFE) is dropped");

    drain();
    send_block_edit(0xA11CE001u, 7300, 12, 7300, 0xFF);
    n = recv_app_skip_gen(0xB0B00002u, out, sizeof out, 400, NULL);
    check(n < 0, "an edit placing the top reserved id (0xFF) is dropped");
}

static void test_out_of_range_coordinate_rejected(void)
{
    puts("end-to-end: absurd coordinate is rejected");
    drain();

    send_block_edit(0xA11CE001u, 2000000000, 5, 0, 1);

    /* v1.9.8: recv_app_skip_gen, not recv_app_for — the once-a-second
     * TIME_SYNC broadcast (send_time_sync(), bsgame.c) can land inside this
     * window regardless of anything this test does, and an "n < 0" check
     * that used recv_app_for would mistake that ambient packet for the
     * broadcast this test is actually asserting never happens. */
    uint8_t out[64];
    ssize_t n = recv_app_skip_gen(0xB0B00002u, out, sizeof out, 400, NULL);
    check(n < 0, "no broadcast for a coordinate far outside the world");
}

static void test_out_of_range_y_rejected(void)
{
    puts("end-to-end: y outside the 128-block world is rejected");
    drain();

    send_block_edit(0xA11CE001u, 0, 500, 0, 1);

    /* v1.9.8: recv_app_skip_gen -- see recv_app_skip_gen's comment for why a
     * TIME_SYNC broadcast in this window must not be mistaken for the
     * rejected-edit broadcast this test asserts never happens. */
    uint8_t out[64];
    ssize_t n = recv_app_skip_gen(0xB0B00002u, out, sizeof out, 400, NULL);
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

    /* alice must not receive her own position back. v1.9.8: recv_app_skip_gen
     * so a TIME_SYNC broadcast landing in this 300ms window (send_time_sync(),
     * bsgame.c, once a second) is not mistaken for her own echoed position —
     * see recv_app_skip_gen's own comment. */
    n = recv_app_skip_gen(0xA11CE001u, out, sizeof out, 300, NULL);
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

    /* v1.9.8: recv_app_skip_gen — this wait alone is long enough to cross a
     * TIME_SYNC broadcast boundary (send_time_sync(), bsgame.c, once a
     * second), and that ambient packet is not the legacy WORLD_SYNC this
     * test is proving stays suppressed. See recv_app_skip_gen's comment. */
    uint8_t out[2048];
    ssize_t n = recv_app_skip_gen(0xCA501001u, out, sizeof out, 300, NULL);
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

    (void)recv_world_gen(0xF2A50009u, 500);   /* v1.8.3 Phase 4, second in the burst */

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

/* v1.9.1: this used to be "past BS_BLOCK_COUNT", full stop. The guard is
 * inventoryCanHold(a) now (see bsgame.c's comment on the change), and water
 * (id 8) is still refused under it, but for a DIFFERENT reason than before —
 * it is a defined core row, so it is not the id-space check this test used to
 * exercise. It is refused because REG_FLAG_LIQUID excludes it: there is no
 * bucket, world/inventory.h says so in as many words. Picked deliberately, not
 * left over: an id that is refused for the OLD reason (past the id space)
 * would stop testing anything the moment the registry grew past 8, and 8 is
 * exactly that id. test_inv_pickup_undefined_core_id_refused() below is where
 * the id-space boundary itself is checked. */
static void test_inv_pickup_out_of_range_item_refused(void)
{
    puts("end-to-end: PICKUP of a liquid (water, id 8) is refused, not kicked");
    drain();

    send_join(0xF2A5000Du, "jack");
    msleep(100);
    drain();

    send_inv_action(0xF2A5000Du, BS_INV_OP_PICKUP, 8 /* BLOCK_WATER */, 1, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A5000Du, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "a refused PICKUP still gets an INV_STATE back, not a KICK");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_is_empty(out), "the liquid was never applied");
    }

    /* Prove the session is still alive, not just that this one packet wasn't
     * a KICK envelope: a genuinely refused-not-kicked player must go on
     * answering ordinary requests afterward. */
    send_inv_action(0xF2A5000Du, BS_INV_OP_PICKUP, 3 /* BLOCK_STONE */, 1, 0);
    n = recv_app_for(0xF2A5000Du, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE && inv_state_total(out, 3) == 1,
          "jack's session still answers a valid PICKUP after the refused one");
}

/* The id-space half of the ceiling, kept separate from the liquid exclusion
 * above for the reason stated there. 43 is one past BS_REGISTRY_CORE_COUNT_GOLDEN
 * (test_registry_core_pinned_to_golden()'s golden, this same file) and the daemon
 * has registered no dynamic ids at the point this runs — the FETCH/DEFS batching
 * scenario that registers 40 of them runs last in main(), deliberately after this
 * — so registryIsDefined(43) is false here and inventoryCanHold(43) refuses it on
 * that ground, not on a liquid flag. Goes red the day the registry grows to 44
 * core rows without this test moving — which is the point: it is meant to be
 * touched the next time a block is added, not to run forever unexamined.
 *
 * MOVED 2026-09-02 from 27 to 28 by v1.8.10's torch (BLOCK_TORCH = 27): the id this
 * test relied on being undefined is now a defined, breakable, non-liquid core row,
 * so the literal has to follow BS_REGISTRY_CORE_COUNT_GOLDEN's move from 27 to 28
 * exactly as this comment always said it would.
 *
 * MOVED AGAIN 2026-09-02/03 from 28 to 34 by v1.8.12 "Ores"'s six ore rows (ids
 * 28..33: coal/iron/gold/redstone/lapis/diamond, ORE-BLOCKS lane). Id 28 is now
 * BLOCK_COAL_ORE, a defined, breakable, non-liquid core row, so this test's premise
 * again no longer held — following BS_REGISTRY_CORE_COUNT_GOLDEN's move from 28 to
 * 34 (this same file, just above) exactly as this comment says it must. Fixed by
 * the ORE-PINS lane, which ORE-BLOCKS explicitly left this literal for: it landed
 * the registry rows and the golden but declined to touch this test's LOGIC, out of
 * its ownership.
 *
 * MOVED A THIRD TIME 2026-09-03 from 34 to 38 by v1.8.14 "Animals"'s four raw meat rows (ids
 * 34..37: raw_porkchop/raw_beef/raw_chicken/raw_mutton). Id 34 is now BLOCK_RAW_PORKCHOP, a
 * defined, breakable, non-liquid core row, so this test's premise once more no longer held —
 * following BS_REGISTRY_CORE_COUNT_GOLDEN's move from 34 to 38 (this same file, above)
 * exactly as this comment says it must. Unlike the previous move this one lands in the SAME
 * commit as the golden, rather than being handed to a following lane: the golden and this
 * literal go red together, so splitting them leaves a red suite whose failure has nothing to
 * do with the change that caused it.
 *
 * MOVED A FOURTH TIME 2026-09-03 from 38 to 43 by v1.8.15 "Furnace"'s five new core rows (ids
 * 38..41: the four cooked meats, and 42: the furnace). Id 38 is now BLOCK_COOKED_PORKCHOP, a
 * defined, breakable, non-liquid core row, so this test's premise once again no longer held --
 * following BS_REGISTRY_CORE_COUNT_GOLDEN's move from 38 to 43 (this same file, above), in the
 * same commit as the golden for the reason the previous entry gives.
 *
 * This one did not have to be predicted: it was OBSERVED. The suite was built and run against
 * the freshly synced game/world/ BEFORE any pin here moved, and reported
 *
 *     FAIL  core-only registryCount() matches the pinned golden 38
 *     FAIL  core-only registryCrc16() matches the pinned golden 0x9610
 *     FAIL  the undefined id was never applied
 *     FAIL 298 checks, 3 failed
 *
 * -- three failures, of which this test is the third and the only one that is not a golden.
 * That red run is what identified this literal as stale; it was not found by reading. Note the
 * shape of the failure, because it is why this test is worth keeping: 38 is now a perfectly
 * valid pickup, so the daemon CREDITED it and inv_state_is_empty() went false. A stale literal
 * here does not fail loudly on its own terms -- it quietly stops testing refusal at all and
 * starts testing a successful pickup instead. 43 was then read off the probe's
 * first-undefined-core-id line rather than inferred, so the premise is measured, not assumed. */
static void test_inv_pickup_undefined_core_id_refused(void)
{
    puts("end-to-end: PICKUP of an undefined core id (44, one past the golden count) is refused, not kicked");
    drain();

    send_join(0xF2A50011u, "nadia");
    msleep(100);
    drain();

    send_inv_action(0xF2A50011u, BS_INV_OP_PICKUP, 44, 1, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A50011u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "a PICKUP of an undefined id still gets an INV_STATE back, not a KICK");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_is_empty(out), "the undefined id was never applied");
    }
}

/* The success criterion this release exists for, stated as a check rather than
 * as a constant: an item id past the OLD ceiling (BS_BLOCK_COUNT, 8) really
 * does survive the real PICKUP -> inventoryAdd() -> INV_STATE path now, not
 * merely "the guard reads a bigger number". Two ids, not one:
 *
 *   12 (BLOCK_CACTUS)      steve's literal report -- a cactus, picked up on a
 *                          server, used to vanish on the next INV_STATE
 *                          because the server refused the PICKUP silently.
 *   26 (BLOCK_APPLE)       the highest id v1.8.8 added, proving this is the
 *                          whole widened registry and not a one-off carve-out
 *                          for cactus alone.
 *
 * Both are FULL_CUBE, non-liquid, defined core rows -- exactly the shape
 * inventoryCanHold() was written to admit. */
static void test_inv_pickup_past_old_wire_ceiling_now_credited(void)
{
    puts("end-to-end: PICKUP of an item id past the old BS_BLOCK_COUNT ceiling is credited, not dropped");
    drain();

    send_join(0xF2A50012u, "opal");
    msleep(100);
    drain();

    /* Picked up TWO, not one: a CONSUME of 1 afterward has to land on a
     * distinguishing count (2 -> 1). Consuming the only one held (1 -> 0)
     * would read identically whether CONSUME actually ran or was silently
     * refused, because a never-credited item is also stuck at 0 -- that
     * shape was tried first and caught by the sabotage arm below: PICKUP
     * failing under the reverted guard left both branches at zero and the
     * CONSUME check passed for the wrong reason. */
    send_inv_action(0xF2A50012u, BS_INV_OP_PICKUP, 12 /* BLOCK_CACTUS */, 2, 0);

    uint8_t out[64];
    ssize_t n = recv_app_for(0xF2A50012u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "PICKUP of the cactus id is answered with an INV_STATE");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_total(out, 12) == 2,
              "the cactus really is in the bag afterward -- this is the rejoin bug, fixed server-side");
    }

    send_inv_action(0xF2A50012u, BS_INV_OP_PICKUP, 26 /* BLOCK_APPLE */, 4, 0);
    n = recv_app_for(0xF2A50012u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE && inv_state_total(out, 26) == 4,
          "the highest id v1.8.8 added (apple, 26) is credited too, not just cactus");

    /* CONSUME exercises the same guard on the other of the two operations it
     * gates; PICKUP alone would leave handle_inv_action()'s CONSUME arm
     * unexercised by anything past the old ceiling. Checked against 1, not 0
     * -- see the comment above the PICKUP that primed this slot with 2. */
    send_inv_action(0xF2A50012u, BS_INV_OP_CONSUME, 12 /* BLOCK_CACTUS */, 1, 0);
    n = recv_app_for(0xF2A50012u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE && inv_state_total(out, 12) == 1,
          "CONSUME of the same past-ceiling id is honoured too, not just PICKUP");
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
    (void)recv_world_gen(sid, 500);   /* v1.8.3 Phase 4, second in the burst */
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
    (void)recv_world_gen(0x50A00003u, 500);   /* v1.8.3 Phase 4, second in the burst */
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

/* Joins and swallows the welcome packets that precede PLAYER_STATE without
 * re-asserting their order — join_expect_fresh_player_state() above already
 * owns that assertion, and everything below is about what the LAST packet
 * SAYS, not where it sits.
 *
 * The count is a named constant rather than a bare 3 because a bare number here
 * is a silent trap, and it sprang: v1.8.3 Phase 4 put WORLD_GEN second in the
 * burst and this loop, still swallowing three, handed its callers the INV_STATE
 * to read as a PLAYER_STATE. recv_app_for() filters on session id and never on
 * message type, so that surfaced three scenarios away from the change as
 * "a join over an orphaned tmp still gets a well-formed PLAYER_STATE" going
 * red — a sentence about crash recovery with nothing in it about ordering. Any
 * future packet added to handle_join() ahead of PLAYER_STATE has to be counted
 * in here too. */
#define JOIN_WELCOME_PACKETS_BEFORE_PLAYER_STATE 4u   /* WORLD_INFO, WORLD_GEN, REGISTRY_INFO, INV_STATE */

static void join_skip_welcome(uint32_t sid, const char *label)
{
    send_join(sid, label);
    uint8_t out[128];
    for (unsigned i = 0; i < JOIN_WELCOME_PACKETS_BEFORE_PLAYER_STATE; i++)
        (void)recv_app_for(sid, out, sizeof out, 500);
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
 * inventory path validates PICKUP/CONSUME on (`inventoryCanHold(a)`,
 * `b >= 1 && b <= BS_INV_STACK_MAX`, bsgame.c) — same id space, same
 * predicate, so an armour slot may not hold an id the inventory would have
 * refused. v1.9.1: that predicate moved from `a < BS_BLOCK_COUNT` to
 * inventoryCanHold() (registry-driven — see validate.h and bsgame.c's
 * comment on the same move); 200 is still refused because it is undefined,
 * not because of where BS_BLOCK_COUNT sits. The policy is playerstate.h's
 * documented per-field one: the offending SLOT is dropped to empty, exactly
 * as a broken item/count pairing already is, while every well-formed slot
 * beside it survives. */
static void test_ps_report_out_of_range_armour_is_dropped(void)
{
    puts("end-to-end: out-of-range armour ids and counts are dropped per-slot, neighbours kept");
    drain();

    join_expect_fresh_player_state(0x50A00013u, "psi");

    /* head: id 200, undefined in the registry — the out-of-bounds index the
     * 3DS client would later use to look up a block.
     * chest: legal id, count 200, past BS_INV_STACK_MAX.
     * legs: entirely legal, the control that proves this is validation and
     *       not a blanket wipe.
     * feet: the exact old-ceiling boundary pair — highest id BS_BLOCK_COUNT
     *       ever gated, highest legal count — kept for the same reason
     *       test_inv_pickup_past_old_wire_ceiling_now_credited() exists: the
     *       old boundary is still legal under the new predicate, not just
     *       the new ids past it. */
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
          "an undefined armour id is dropped to an empty slot");
    check(back[2] == 0 && back[3] == 0,
          "an armour count past BS_INV_STACK_MAX is dropped to an empty slot");
    check(back[4] == 5 && back[5] == 3,
          "the legal slot beside them is untouched — this is validation, not a wipe");
    check(back[6] == (uint8_t)(BS_BLOCK_COUNT - 1) && back[7] == (uint8_t)BS_INV_STACK_MAX,
          "the old ceiling's highest id/count pair is still kept — the old boundary did not become illegal");
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

/* ------------------------------------------- v1.8.3 Phase 4: world_gen.txt */

/* Brings the daemon back up with (or without) a generator argument and waits
 * for it, so the scenario below reads as three restarts rather than thirty
 * lines of fork bookkeeping.
 *
 * `force` picks --world-gen-force over --world-gen. Every restart in the
 * scenario below needs it, and that is not a convenience: this suite runs all
 * three restarts against ONE shared scratch --state-dir, and by the time the
 * scenario is reached (main() calls it after test_edit_broadcast_to_other_player_only,
 * test_world_sync_after_edits, test_restart_persists_diffs and test_disk_format,
 * all of which place blocks) that dir has a non-empty block_diffs.bin. Plain
 * --world-gen is REFUSED there by design. Passing NULL forces nothing and the
 * flag is irrelevant. */
static void restart_with_gen(const char *gen, bool force)
{
    stop_daemon();
    g_forced_gen      = gen;
    g_forced_gen_flag = force ? "--world-gen-force" : "--world-gen";
    start_daemon();
    if (!wait_ready(5000)) {
        fprintf(stderr, "test: daemon never became ready after a %s restart\n",
                g_forced_gen_flag);
        exit(1);
    }
    g_forced_gen      = NULL;
    g_forced_gen_flag = "--world-gen";
    drain();
}

/* Joins, throws away WORLD_INFO, and returns the raw two version bytes of the
 * WORLD_GEN behind it. Separate from recv_world_gen() because that helper pins
 * the value to 1, which is the right assertion everywhere else in this suite
 * and the wrong one here — the whole point of this scenario is a declaration
 * that is deliberately NOT the default. */
static bool join_read_gen_bytes(uint32_t sid, const char *label, uint8_t v[2])
{
    send_join(sid, label);

    uint8_t out[64];
    memset(out, 0, sizeof out);
    ssize_t n = recv_app_for(sid, out, sizeof out, 500);
    if (n != (ssize_t)BS_WORLD_INFO_BYTES || out[0] != BS_APP_WORLD_INFO) return false;

    memset(out, 0, sizeof out);
    n = recv_app_for(sid, out, sizeof out, 500);
    if (n != (ssize_t)BS_WORLD_GEN_BYTES || out[0] != BS_APP_WORLD_GEN) return false;

    v[0] = out[1];
    v[1] = out[2];
    return true;
}

/* The declaration is READ from --state-dir/world_gen.txt, not decided afresh
 * every boot.
 *
 * Restarting and checking the two joins agree would not prove that, and the
 * trap is worth naming because it is the obvious test to write: the mint would
 * answer 1 here (this shared state-dir has edits in it by now, so it takes the
 * legacy branch), so an implementation that ignored the file entirely and
 * minted on every boot would hand both joins a 1 and pass. So this forces a
 * value the mint can never choose (3), restarts WITHOUT the flag, and requires
 * 3 to come back. Only reading the file can produce that.
 *
 * 3 is not a generator any client can make. That is deliberate and it is safe
 * here: the server never generates anything, this state-dir is a scratch
 * directory this run created, and the declaration is restored to
 * BSGAME_TEST_WORLD_GEN at the end — which the registry scenarios that follow
 * re-verify for free, because their own recv_world_gen() pins it. It also
 * happens to be the value a client's refusal path would fire on, which is what
 * interop_test.c uses it for.
 *
 * Every restart here forces with --world-gen-force. See restart_with_gen(): by
 * the time main() reaches this scenario the shared scratch state-dir has edits
 * in it, and plain --world-gen refuses to contradict a stored value there. That
 * refusal is the subject of test_world_gen_refuses_to_strand_edits() below; this
 * scenario is about persistence, so it takes the override and stays about the
 * thing it was written to test. */
static void test_world_gen_persists_across_restart(void)
{
    puts("v1.8.3 Phase 4: the declared generator comes out of world_gen.txt, not out of a fresh mint every boot");

    char path[256];
    snprintf(path, sizeof path, "%s/world_gen.txt", g_dir);

    unsigned long long stored = 0;
    FILE *f = fopen(path, "r");
    check(f != NULL, "world_gen.txt was written into --state-dir on the daemon's first run");
    if (f != NULL) {
        check(fscanf(f, "%llu", &stored) == 1, "world_gen.txt holds a plain decimal number an operator can cat");
        fclose(f);
    }
    check(stored == BSGAME_TEST_WORLD_GEN,
          "an empty --state-dir mints the declaration at 5 (ores), the newest terrain the"
          " client ships — this dir was empty when the daemon first came up");

    /* Forced to a value the mint would never choose, and written through. */
    restart_with_gen("3", true);
    uint8_t v[2] = { 0xFF, 0xFF };
    check(join_read_gen_bytes(0x6E0F0001u, "genforce", v),
          "--world-gen-force 3 comes up and still sends WORLD_INFO then WORLD_GEN in that order");
    check(v[0] == 0x03 && v[1] == 0x00,
          "--world-gen-force 3 is declared on the wire as the little-endian bytes {0x03, 0x00}");

    /* And now the actual claim: no flag, and 3 has to survive. */
    restart_with_gen(NULL, false);
    v[0] = 0xFF; v[1] = 0xFF;
    check(join_read_gen_bytes(0x6E0F0002u, "genread", v),
          "the daemon restarted with NO --world-gen still sends WORLD_GEN");
    check(v[0] == 0x03 && v[1] == 0x00,
          "the forced 3 came back after a restart with no argument — the declaration is read"
          " from world_gen.txt, not minted (a mint-every-boot build answers 1 here)");

    stored = 0;
    f = fopen(path, "r");
    check(f != NULL, "world_gen.txt still exists after the restart");
    if (f != NULL) {
        if (fscanf(f, "%llu", &stored) != 1) stored = 0;
        fclose(f);
    }
    check(stored == 3u, "world_gen.txt on disk holds the forced 3, matching what the wire said");

    /* Restore, so every join after this one is told BSGAME_TEST_WORLD_GEN
     * again. The registry scenarios below re-prove it landed, through
     * recv_world_gen(). */
    restart_with_gen("5", true);
    v[0] = 0xFF; v[1] = 0xFF;
    check(join_read_gen_bytes(0x6E0F0003u, "genrestore", v),
          "the state dir is put back and the daemon comes up clean");
    check(v[0] == 0x05 && v[1] == 0x00,
          "the declaration is 5 again for the rest of this run");
}

/* The guard: --world-gen may NOT quietly contradict a stored declaration on a
 * --state-dir that already has edits in it.
 *
 * This is the half of the flag that did not exist before. The stored value used
 * to be read only when nothing was forced, so a forced run never opened
 * world_gen.txt at all — there was no comparison to refuse on, and a typo in a
 * unit file rewrote the declaration silently at startup, stranding every record
 * in block_diffs.bin against terrain of a different shape.
 *
 * Runs immediately after test_world_gen_persists_across_restart(), which leaves
 * the dir storing 5 and (by then) full of edits, so both halves of the guard's
 * precondition hold without this scenario having to build them.
 *
 * The daemon is expected to EXIT rather than come up, so this cannot go through
 * restart_with_gen() — that helper exit(1)s when the daemon never becomes ready,
 * which here is the pass condition. It forks and waits on the status directly.
 *
 * Two assertions, and the second is the one that matters: a build that printed
 * the refusal and then wrote the file anyway would pass the first alone. */
static void test_world_gen_refuses_to_strand_edits(void)
{
    puts("the world generator cannot be changed out from under a world that has edits");

    char path[256];
    snprintf(path, sizeof path, "%s/world_gen.txt", g_dir);

    char diffs[256];
    snprintf(diffs, sizeof diffs, "%s/block_diffs.bin", g_dir);
    struct stat dst;
    check(stat(diffs, &dst) == 0 && dst.st_size > 8,
          "the shared state-dir really does have edits by now, so the guard's precondition"
          " holds and this scenario is not passing vacuously");

    unsigned long long before = 0;
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        if (fscanf(f, "%llu", &before) != 1) before = 0;
        fclose(f);
    }
    check(before == BSGAME_TEST_WORLD_GEN,
          "world_gen.txt holds 5 going in, left there by the persistence scenario above");

    stop_daemon();

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        execl("./bsgame", "bsgame",
              "--game-socket", g_game_sock,
              "--gate-socket", g_gate_sock,
              "--state-dir",   g_dir,
              "--world-gen",   "3",
              (char *)NULL);
        _exit(127);
    }

    /* Bounded, and that is not defensive padding — it is the difference between
     * a check that goes red and one that hangs. A plain waitpid() here blocks
     * forever the moment the guard is missing, because then the daemon comes up
     * and runs, which is exactly the arm this scenario exists to catch. Measured:
     * the first version of this test was written with an unbounded waitpid and
     * the sabotage run had to be killed at 600s having reported nothing. */
    int  status = 0;
    bool exited = false;
    for (unsigned waited = 0; waited < 5000; waited += 50) {
        if (waitpid(pid, &status, WNOHANG) == pid) { exited = true; break; }
        msleep(50);
    }
    if (!exited) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }
    check(exited && WIFEXITED(status) && WEXITSTATUS(status) == 1,
          "--world-gen 3 over a stored 5 on a world with edits exits 1 instead of starting");

    unsigned long long after = 0;
    f = fopen(path, "r");
    check(f != NULL, "world_gen.txt still exists after the refusal");
    if (f != NULL) {
        if (fscanf(f, "%llu", &after) != 1) after = 0;
        fclose(f);
    }
    check(after == BSGAME_TEST_WORLD_GEN,
          "and still holds 5 — the refusal happened BEFORE the write, so the declaration"
          " on disk is untouched");

    /* And the override still works, which is what makes the refusal a guard
     * rather than a wall. Put the daemon back for whatever runs after this. */
    restart_with_gen("5", true);
    uint8_t v[2] = { 0xFF, 0xFF };
    check(join_read_gen_bytes(0x6E0F0004u, "genguard", v),
          "--world-gen-force brings the daemon back up over the same dir");
    check(v[0] == 0x05 && v[1] == 0x00,
          "and the declaration is still 5 for the rest of this run");
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
    (void)recv_world_gen(sid, 500);   /* v1.8.3 Phase 4, second in the burst */
    bool got_reg = recv_registry_info(sid, 500);
    check(got_reg, "registry probe: REGISTRY_INFO arrives second");
    n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "registry probe: INV_STATE third");
    n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_PLAYER_STATE_BYTES && out[0] == BS_APP_PLAYER_STATE,
          "registry probe: PLAYER_STATE fourth");

    /* v1.9.8. TIME_SYNC now rides last in every join burst (handle_join(),
     * bsgame.c's send_time_sync() call) — see that call's own comment for
     * why it carries none of the ordering weight WORLD_INFO..PLAYER_STATE
     * do. Consumed here so the FETCH exchanges that call this helper are not
     * handed a leftover TIME_SYNC datagram instead of their real
     * REGISTRY_DEFS reply. */
    n = recv_app_for(sid, out, sizeof out, 500);
    check(n == (ssize_t)BS_TIME_SYNC_BYTES && out[0] == BS_APP_TIME_SYNC,
          "registry probe: TIME_SYNC rides behind PLAYER_STATE");

    /* v1.9.10. SERVER_CAPS is now the last packet of the burst, behind
     * TIME_SYNC, and it has to be consumed here for the same reason TIME_SYNC
     * is: the FETCH exchanges that call this helper read their REGISTRY_DEFS
     * reply with recv_app_for(), which filters by session and not by type, so
     * a leftover packet is handed to them in its place. Three checks in the
     * two FETCH scenarios below failed exactly that way before this line. */
    (void)recv_server_caps(sid, 500);
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
    unsigned defs_gen_skipped = 0;
    n = recv_app_skip_gen(0x9E670002u, extra, sizeof extra, 300, &defs_gen_skipped);
    check(n < 0, "no third DEFS batch follows the LAST-flagged one");
}

/* ------------------------------------------------------------ v1.9.8: day/night */

/* BS_APP_TIME_SYNC (proto/bs_proto.h) is the server-authoritative day/night
 * counter described in the client's own source/world/daynight.h:338-365:
 * send_time_sync() (bsgame.c) puts one on the wire at the end of every join
 * burst, and tick() broadcasts another once a second forever after
 * (tickDue(t, TICK_HZ, 0)), persisting it to day_time.txt in --state-dir on
 * the same beat. join_expect_registry_sequence() above already proves WHERE
 * in the join burst the packet rides; this proves what it actually SAYS and
 * that it keeps moving. */
static void test_time_sync_on_join_and_periodic(void)
{
    puts("v1.9.8: TIME_SYNC arrives on join and again, larger, about a second later");
    drain();

    send_join(0x71A50001u, "chronos");

    uint8_t out[64];
    ssize_t n = recv_app_for(0x71A50001u, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "day/night probe: WORLD_INFO leads");
    (void)recv_world_gen(0x71A50001u, 500);
    (void)recv_registry_info(0x71A50001u, 500);
    n = recv_app_for(0x71A50001u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "day/night probe: INV_STATE next");
    n = recv_app_for(0x71A50001u, out, sizeof out, 500);
    check(n == (ssize_t)BS_PLAYER_STATE_BYTES && out[0] == BS_APP_PLAYER_STATE,
          "day/night probe: PLAYER_STATE next");

    n = recv_app_for(0x71A50001u, out, sizeof out, 500);
    const bool shaped = (n == (ssize_t)BS_TIME_SYNC_BYTES && out[0] == BS_APP_TIME_SYNC);
    check(shaped, "TIME_SYNC rides last in the join burst, exactly BS_TIME_SYNC_BYTES long");
    if (!shaped) return;

    uint64_t join_ticks = bs_get_u64(out + 1);

    /* 1000 is BSGAME_DAY_START_TICKS (bsgame.c) and DAY_START_TICKS
     * (daynight.h) both — a literal on purpose here, the same way
     * BSGAME_TEST_WORLD_GEN is one above: bsgame.c's own #define is not
     * visible to this translation unit, and this suite is a separate
     * process speaking only the wire protocol. By the time this test runs
     * the shared daemon has been up through the whole suite, so the real
     * value is certain to be well past this floor; this only guards against
     * a build that forgot to load the persisted clock at all and answers 0. */
    check(join_ticks >= 1000u,
          "the join-time counter is at least the calendar's start tick (1000)");

    /* Decoded independently of bs_get_u64 -- that function is exactly what
     * this message's own wire bytes are supposed to satisfy, so using it
     * to check itself would prove nothing about whether the bytes are
     * REALLY little-endian on the wire. */
    uint64_t manual = 0;
    for (int i = 7; i >= 0; i--) manual = (manual << 8) | out[1 + (unsigned)i];
    check(manual == join_ticks,
          "the counter's wire bytes are little-endian, verified without going through bs_get_u64");

    /* tickDue(t, TICK_HZ, 0) fires once a second of SIMULATED ticks, not
     * once a second of wall clock -- test_tick_rate_is_traffic_independent
     * above already established this suite's own accepted floor for that
     * (BS_TICK_TPS_LO = 16.0), so 20 ticks can legitimately take up to
     * 20/16 = 1.25s of real time under load, before any scheduling or gate
     * round-trip overhead on top. 1600ms measured too tight and this check
     * went red on ordinary WSL scheduling jitter, not a real regression;
     * 2500ms keeps that same margin.
     *
     * This loop skips, rather than fails on, any packet that is not the
     * TIME_SYNC we are waiting for. Diagnosed by inlining a raw envelope dump
     * here: chronos never sends a single CHUNK_SUB (this test has no reason
     * to), so BS_CHUNK_LEGACY_GRACE_MS after its own join (500 ms -- see that
     * constant in bsgame.c) tick()'s legacy fallback correctly fires it one
     * unrequested full BS_APP_WORLD_SYNC dump. That is pre-existing, intended
     * behaviour for any client that never subscribes to chunks (see
     * BS_CHUNK_LEGACY_GRACE_MS's own comment in bsgame.c) -- unrelated to the
     * day/night feature and not something this test should treat as a
     * failure. recv_app_skip_gen() is not reused here because it already
     * skips BS_APP_TIME_SYNC itself (the exact packet this wait is for), so a
     * type-check that keeps everything except TIME_SYNC is written out
     * directly instead of adding a third hardcoded type to that shared
     * helper for what only this one test needs.
     *
     * `wide`, not `out`, is the receive buffer here: recv_app_for() returns
     * -1 -- indistinguishable from a real timeout -- when a packet arrives
     * that is too big for the caller's buffer, and it has already consumed
     * that datagram off the socket by the time it tells you so. The legacy
     * WORLD_SYNC above is exactly such an oversized, unwanted packet; with
     * `out`'s 64 bytes as the receive buffer it would silently end this wait
     * right there instead of being skipped. BS_MAX_PAYLOAD is the largest any
     * single application payload can legally be. */
    uint64_t deadline = now_ms() + 2500;
    uint8_t wide[BS_MAX_PAYLOAD];
    ssize_t n2 = -1;
    for (;;) {
        uint64_t now = now_ms();
        if (now >= deadline) { n2 = -1; break; }
        n2 = recv_app_for(0x71A50001u, wide, sizeof wide, (unsigned)(deadline - now));
        if (n2 < 0 || wide[0] == BS_APP_TIME_SYNC) break;
    }
    check(n2 == (ssize_t)BS_TIME_SYNC_BYTES && wide[0] == BS_APP_TIME_SYNC,
          "a second TIME_SYNC arrives roughly a second later, unprompted");
    if (n2 == (ssize_t)BS_TIME_SYNC_BYTES) {
        uint64_t periodic_ticks = bs_get_u64(wide + 1);
        check(periodic_ticks > join_ticks,
              "and its counter is strictly larger — the clock is really advancing, not"
              " repeating a stale value");
    }
}

/* Proves day_time.txt actually survives a restart -- the task's persistence
 * requirement. Placed at the very end of main()'s sequence, after every
 * other scenario that restarts the shared --state-dir or cares what a fresh
 * join's REGISTRY_INFO/world_gen advertises, so this restart cannot disturb
 * anything that runs after it (nothing does). */
static void test_day_time_persists_across_restart(void)
{
    puts("v1.9.8: day_time.txt survives a restart and the clock resumes, not restarts");
    drain();

    char path[256];
    snprintf(path, sizeof path, "%s/day_time.txt", g_dir);

    unsigned long long before = 0;
    FILE *f = fopen(path, "r");
    check(f != NULL, "day_time.txt exists before the restart (written at daemon startup)");
    if (f != NULL) {
        check(fscanf(f, "%llu", &before) == 1,
              "day_time.txt holds a plain decimal number an operator can cat");
        fclose(f);
    }

    /* day_time_save() (bsgame.c) writes this file once a second, on the same
     * tickDue(t, TICK_HZ, 0) boundary as the broadcast — give the clock a
     * full beat so the on-disk value has demonstrably moved since the read
     * above, proving the periodic save is real and not a one-time mint. */
    msleep(1100);

    stop_daemon();

    unsigned long long at_shutdown = 0;
    f = fopen(path, "r");
    check(f != NULL, "day_time.txt still exists right after shutdown");
    if (f != NULL) {
        check(fscanf(f, "%llu", &at_shutdown) == 1, "and still holds a number");
        fclose(f);
    }
    check(at_shutdown > before,
          "the on-disk counter advanced during the run — day_time_save() is not a one-time mint");

    start_daemon();
    if (!wait_ready(5000)) { fprintf(stderr, "test: restarted daemon never became ready\n"); exit(1); }
    drain();

    uint8_t out[64];
    send_join(0xDA790002u, "resumed");
    ssize_t n = recv_app_for(0xDA790002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_WORLD_INFO_BYTES && out[0] == BS_APP_WORLD_INFO,
          "day/night restart probe: WORLD_INFO leads");
    (void)recv_world_gen(0xDA790002u, 500);
    (void)recv_registry_info(0xDA790002u, 500);
    n = recv_app_for(0xDA790002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_INV_STATE_BYTES && out[0] == BS_APP_INV_STATE,
          "day/night restart probe: INV_STATE next");
    n = recv_app_for(0xDA790002u, out, sizeof out, 500);
    check(n == (ssize_t)BS_PLAYER_STATE_BYTES && out[0] == BS_APP_PLAYER_STATE,
          "day/night restart probe: PLAYER_STATE next");

    n = recv_app_for(0xDA790002u, out, sizeof out, 500);
    const bool shaped = (n == (ssize_t)BS_TIME_SYNC_BYTES && out[0] == BS_APP_TIME_SYNC);
    check(shaped, "TIME_SYNC rides last in the post-restart join burst too");
    if (!shaped) return;

    uint64_t resumed_ticks = bs_get_u64(out + 1);
    check(resumed_ticks >= at_shutdown,
          "the clock resumes at or after where it was saved — a restart never rewinds the"
          " calendar (day_time_load() never returns less than what was on disk)");
}

/* ------------------------------------------------------------ v1.9.10: chests
 *
 * Two halves, deliberately.
 *
 * The first half is IN-PROCESS against game/cheststore.c, which this binary
 * already links (game/Makefile's bsgame_test rule). cheststore.h says in as
 * many words that the module is "plain C with no network or logging
 * dependency, so the transfer rules and the file format can be exercised by
 * host tests rather than trusted" — this is that. Every rule the header
 * states about room, merge, refusal, withdrawal, capacity and the on-disk
 * mirror is checked here, where a wrong answer is one function call away from
 * its cause instead of six packets away.
 *
 * The second half is END-TO-END through the real daemon, and it exists
 * because the interesting v1.9.10 behaviour is NOT in cheststore.c. It is in
 * bsgame.c's chest_action_apply(): that a chest action is gated on the diff
 * store actually holding BLOCK_CHEST at the position, that a refusal is
 * SILENT and never a kick even though handle_app_payload() kicks unknown
 * types, that an accepted transfer broadcasts one CHEST_STATE to everyone,
 * and that a BLOCK_EDIT which replaces a chest takes its contents with it.
 * None of those can be seen from inside cheststore.c.
 *
 * Placed last in main(), after the day/night restart, for the reason that
 * scenario's own comment gives: nothing after this point cares what a fresh
 * join's REGISTRY_INFO or world_gen advertises, and these scenarios place
 * blocks and would otherwise be one more thing every later test is standing
 * on. Positions are all in an x band of 5000+ that nothing earlier touches.
 */

/* The chest block's id in the vendored registry (game/world/block.h asserts
 * BLOCK_CHEST == 43). A literal with the name in a comment, the way every
 * other block id in this file is written: this suite speaks the wire, and on
 * the wire a block id is a byte. */
#define BSGAME_TEST_BLOCK_CHEST 43u

/* game/cheststore.c's own BS_CHEST_REC_BYTES, which is private to that
 * translation unit. Restated as a literal on purpose — computing it from
 * BS_CHEST_STATE_BYTES here would agree with the implementation no matter
 * what either became, which is the failure BSGAME_TEST_WORLD_GEN's comment
 * above describes. 12 bytes of position plus 8 x (item, count). */
#define BSGAME_TEST_CHEST_REC_BYTES 28u

static void send_chest_action(uint32_t sid, uint8_t op, int32_t x, int32_t y, int32_t z,
                              uint8_t a, uint8_t b, uint8_t count)
{
    uint8_t p[BS_CHEST_ACTION_BYTES];
    p[0] = BS_APP_CHEST_ACTION;
    p[1] = op;
    bs_put_i32(p + 2,  x);
    bs_put_i32(p + 6,  y);
    bs_put_i32(p + 10, z);
    p[14] = a;
    p[15] = b;
    p[16] = count;
    send_app(sid, p, sizeof p);
}

/* Reads until a BS_APP_CHEST_STATE addressed to `sid` turns up, or `ms`
 * elapses. Not recv_app_skip_gen(): the players these scenarios join never
 * send CHUNK_SUB, so BS_CHUNK_LEGACY_GRACE_MS after each join tick() fires
 * them one unrequested full BS_APP_WORLD_SYNC dump — a packet that is
 * neither WORLD_GEN nor TIME_SYNC and is far larger than 64 bytes. Both
 * facts matter: skipping by type is what keeps it out of the way, and the
 * BS_MAX_PAYLOAD receive buffer is what stops recv_app_for() from returning
 * -1 (indistinguishable from a timeout) after it has already eaten the
 * datagram. test_time_sync_on_join_and_periodic() above learned both the
 * hard way; this is the same repair. */
static ssize_t recv_chest_state(uint32_t sid, uint8_t *out, size_t cap, unsigned ms)
{
    const uint64_t until = now_ms() + ms;

    for (;;) {
        const uint64_t now = now_ms();
        if (now >= until) return -1;

        uint8_t wide[BS_MAX_PAYLOAD];
        const ssize_t n = recv_app_for(sid, wide, sizeof wide, (unsigned)(until - now));
        if (n < 1) return -1;
        if (wide[0] != BS_APP_CHEST_STATE) continue;
        if ((size_t)n > cap) return -1;
        memcpy(out, wide, (size_t)n);
        return n;
    }
}

/* Slot `slot`'s (item, count) out of a raw BS_APP_CHEST_STATE payload, hand
 * parsed from the wire bytes exactly as inv_state_slot() does for INV_STATE:
 * type byte, then x/y/z, then the pairs. */
static void chest_state_slot(const uint8_t *st, unsigned slot, uint8_t *item, uint8_t *count)
{
    *item  = st[BS_APP_HDR_BYTES + 12u + slot * 2u];
    *count = st[BS_APP_HDR_BYTES + 12u + slot * 2u + 1u];
}

static bool chest_state_is_empty(const uint8_t *st)
{
    for (unsigned i = 0; i < BS_CHEST_SLOTS; i++) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, i, &item, &count);
        if (item != 0 || count != 0) return false;
    }
    return true;
}

/* Does the snapshot describe the chest at (x, y, z)? Decoded without
 * bs_get_i32 for the reason recv_world_gen() gives: this suite's own decoder
 * agreeing with this suite's own encoder proves nothing about what is
 * actually on the wire. */
static bool chest_state_at(const uint8_t *st, int32_t x, int32_t y, int32_t z)
{
    const int32_t v[3] = { x, y, z };
    for (unsigned axis = 0; axis < 3; axis++) {
        const uint32_t u = (uint32_t)v[axis];
        for (unsigned b = 0; b < 4; b++) {
            const uint8_t want = (uint8_t)((u >> (8u * b)) & 0xFFu);
            if (st[BS_APP_HDR_BYTES + axis * 4u + b] != want) return false;
        }
    }
    return true;
}

/* The silence probe every refusal scenario below rests on, and the reason it
 * reads RAW envelopes rather than going through recv_app_for(): that helper
 * folds a KICK into the same -1 a timeout gives, and "refused silently" versus
 * "disconnected" is the exact distinction bs_proto.h's CHEST_ACTION contract
 * makes ("refuses, silently and without a kick, anything that does not
 * validate"). A test that could not tell those apart would stay green if
 * handle_chest_action() started kicking. */
static void chest_watch(uint32_t sid, unsigned ms, bool *saw_state, bool *saw_kick)
{
    *saw_state = false;
    *saw_kick  = false;
    const uint64_t until = now_ms() + ms;

    for (;;) {
        const uint64_t now = now_ms();
        if (now >= until) return;

        uint8_t buf[5 + BS_MAX_PAYLOAD];
        const ssize_t n = gate_recv(buf, sizeof buf, (unsigned)(until - now));
        if (n < 5) continue;                       /* poll timed out; the deadline decides */
        if (bs_get_u32(buf + 1) != sid) continue;
        if (buf[0] == BS_GAME_KICK) *saw_kick = true;
        if (buf[0] == BS_GAME_DATA && n >= 6 && buf[5] == BS_APP_CHEST_STATE) *saw_state = true;
    }
}

/* One BLOCK_EDIT, given time to land. 80 ms is comfortably inside the edit
 * token bucket (BS_EDIT_BURST 40, one back per BS_EDIT_REFILL_MS 50) for the
 * handful of placements each scenario makes. */
static void chest_place_block(uint32_t sid, int32_t x, int32_t y, int32_t z, uint8_t block)
{
    send_block_edit(sid, x, y, z, block);
    msleep(80);
}

/* Joins a player and swallows the whole welcome burst, so a scenario's first
 * read is its own CHEST_STATE and not a leftover PLAYER_STATE. */
static void chest_join(uint32_t sid, const char *label)
{
    send_join(sid, label);
    msleep(150);
    drain();
}

/* Total units of `item` across all eight slots of a CHEST_STATE snapshot —
 * the chest-side twin of inv_state_total(), for the scenarios below that care
 * about a sum rather than about which slot a unit landed in. */
static uint32_t chest_state_total(const uint8_t *st, uint8_t item)
{
    uint32_t total = 0;
    for (unsigned i = 0; i < BS_CHEST_SLOTS; i++) {
        uint8_t it = 0, ct = 0;
        chest_state_slot(st, i, &it, &ct);
        if (it == item) total += ct;
    }
    return total;
}

/* recv_chest_state()'s twin for the OTHER half of a chest transfer. Same
 * skip-by-type loop and the same reason for it: these players sit on the
 * legacy path, so an unrequested WORLD_SYNC dump and a once-a-second
 * TIME_SYNC are both in flight around every read. */
static ssize_t recv_inv_state(uint32_t sid, uint8_t *out, size_t cap, unsigned ms)
{
    const uint64_t until = now_ms() + ms;

    for (;;) {
        const uint64_t now = now_ms();
        if (now >= until) return -1;

        uint8_t wide[BS_MAX_PAYLOAD];
        const ssize_t n = recv_app_for(sid, wide, sizeof wide, (unsigned)(until - now));
        if (n < 1) return -1;
        if (wide[0] != BS_APP_INV_STATE) continue;
        if ((size_t)n > cap) return -1;
        memcpy(out, wide, (size_t)n);
        return n;
    }
}

/* v1.9.10 fix. Puts `count` units of `item` in the player's bag through the
 * PICKUP path a real client uses for a mined block, and waits for the
 * INV_STATE that answers it so the units are provably seated before the
 * caller's first chest action.
 *
 * Every DEPOSIT scenario below needs this now, and that is the whole point of
 * the fix: a deposit is a MOVE out of a bag the server owns, so a deposit of
 * units the actor does not hold is refused. Before the fix these scenarios
 * deposited out of thin air and the chest filled up anyway. */
static void chest_give(uint32_t sid, uint8_t item, uint8_t count)
{
    send_inv_action(sid, BS_INV_OP_PICKUP, item, count, 0);
    uint8_t inv[BS_INV_STATE_BYTES];
    (void)recv_inv_state(sid, inv, sizeof inv, 700);
}

/* Reads the player's whole bag back off the wire WITHOUT going through a
 * chest action: a BS_INV_OP_SELECT is answered with a fresh INV_STATE
 * unconditionally (handle_inv_action's last line), and selecting a hotbar
 * slot moves no units.
 *
 * Deliberately not "read the INV_STATE the chest action replied with". The
 * conservation scenario has to be able to weigh the bag even on a build that
 * sends no INV_STATE after a chest action at all — otherwise the invariant
 * check would fail as a timeout rather than as a wrong SUM, and a timeout
 * proves nothing about conservation. */
static bool chest_bag_read(uint32_t sid, uint8_t *out)
{
    send_inv_action(sid, BS_INV_OP_SELECT, 0, 0, 0);
    return recv_inv_state(sid, out, BS_INV_STATE_BYTES, 700) == (ssize_t)BS_INV_STATE_BYTES;
}

/* v1.9.10 fix (2026-09-07). chest_give()'s opposite, over the CONSUME path a
 * real client uses for a placed block, and waits for the INV_STATE that
 * answers it. The break-refused scenario below needs it to EMPTY a bag it
 * deliberately filled: "the player can empty their bag and break it again" is
 * half of what a refusal has to be worth, and a scenario that could only fill
 * a bag could not measure that half. */
static void chest_take(uint32_t sid, uint8_t item, uint8_t count)
{
    send_inv_action(sid, BS_INV_OP_CONSUME, item, count, 0);
    uint8_t inv[BS_INV_STATE_BYTES];
    (void)recv_inv_state(sid, inv, sizeof inv, 700);
}

/* v1.9.10 fix (2026-09-07). Fills a bag to its very last slot: INV_SLOT_COUNT
 * stacks of BS_INV_STACK_MAX, all of one item, so inventoryAdd() has neither a
 * partial stack to merge into nor an empty slot to spill into and REFUSES
 * everything. Returns the number of units it put in, which is what the caller
 * then weighs the bag against. */
static uint32_t chest_fill_bag(uint32_t sid, uint8_t item)
{
    for (unsigned i = 0; i < BS_INV_SLOT_COUNT; i++) {
        chest_give(sid, item, (uint8_t)BS_INV_STACK_MAX);
    }
    return (uint32_t)BS_INV_SLOT_COUNT * (uint32_t)BS_INV_STACK_MAX;
}

static void chest_empty_bag(uint32_t sid, uint8_t item)
{
    for (unsigned i = 0; i < BS_INV_SLOT_COUNT; i++) {
        chest_take(sid, item, (uint8_t)BS_INV_STACK_MAX);
    }
}

/* v1.9.10 fix (2026-09-07). Did a BLOCK_EDIT for THIS cell reach `sid` inside
 * `ms`? The refusal probe: broadcast_block_edit() is the last thing
 * handle_block_edit() does on an accepted edit, so a watcher on a second,
 * legacy player (one that has never sent CHUNK_SUB, and therefore receives
 * every broadcast unscoped) distinguishes "the break was refused and the world
 * did not change" from "the break went through and the payout was silent".
 *
 * Raw envelopes for chest_watch()'s reason: recv_app_for() folds a KICK into
 * the same -1 a timeout gives, and a refused break must not be a kick either.
 * Matched on the POSITION too — the scenario places blocks of its own, and a
 * probe that answered "some block edit happened" would go green on the wrong
 * one. */
static bool chest_saw_block_edit(uint32_t sid, int32_t x, int32_t y, int32_t z, unsigned ms)
{
    const uint64_t until = now_ms() + ms;
    bool seen = false;

    for (;;) {
        const uint64_t now = now_ms();
        if (now >= until) return seen;

        uint8_t buf[5 + BS_MAX_PAYLOAD];
        const ssize_t n = gate_recv(buf, sizeof buf, (unsigned)(until - now));
        if (n < 5) continue;                       /* poll timed out; the deadline decides */
        if (bs_get_u32(buf + 1) != sid) continue;
        if (buf[0] != BS_GAME_DATA) continue;
        if (n < (ssize_t)(5 + BS_BLOCK_EDIT_BYTES) || buf[5] != BS_APP_BLOCK_EDIT) continue;
        if (bs_get_i32(buf + 6) == x && bs_get_i32(buf + 10) == y && bs_get_i32(buf + 14) == z) {
            seen = true;
        }
    }
}

/* ---- in-process: the wire codec ---------------------------------------- */

static void test_chest_action_decode(void)
{
    puts("v1.9.10: chestActionDecode accepts exactly one frame shape and reads it little-endian");

    /* Hand-written literal bytes, NOT a frame built with bs_put_i32.
     * chestActionDecode() reads the position with bs_get_i32, so a frame
     * built by that function's inverse would agree with it even if both were
     * big-endian — the same failure mode recv_world_gen()'s byte-level check
     * above exists for. Every field's intended value is stated beside it. */
    const uint8_t frame[BS_CHEST_ACTION_BYTES] = {
        BS_APP_CHEST_ACTION,
        BS_CHEST_OP_DEPOSIT,
        0x04, 0x03, 0x02, 0x01,   /* x = 0x01020304 = 16909060 */
        0x0B, 0x0A, 0x00, 0x00,   /* y = 0x00000A0B =     2571 */
        0xFF, 0xFF, 0xFF, 0xFF,   /* z = 0xFFFFFFFF =       -1 */
        0x07,                     /* a     */
        0x03,                     /* b     */
        0x05                      /* count */
    };

    BsChestAction act;
    memset(&act, 0xEE, sizeof act);
    const bool ok = chestActionDecode(frame, sizeof frame, &act);
    check(ok, "a well-formed BS_CHEST_ACTION_BYTES frame decodes");
    if (ok) {
        check(act.op == BS_CHEST_OP_DEPOSIT, "the op byte is field 1, straight after the type byte");
        check(act.x == 16909060, "x is the four bytes after the op, least significant first");
        check(act.y == 2571,     "y is the next four, least significant first");
        check(act.z == -1,       "z is the next four, least significant first");
        check(act.a == 0x07 && act.b == 0x03 && act.count == 0x05,
              "a, b and count are the last three bytes, in that order");
    }

    /* Negative coordinates on all three axes, in two's complement. The
     * client sends absolute world positions and half the world is negative,
     * so a decoder that sign-extended the wrong byte would work perfectly
     * for every chest east of the origin and fail for every chest west. */
    const uint8_t neg[BS_CHEST_ACTION_BYTES] = {
        BS_APP_CHEST_ACTION,
        BS_CHEST_OP_WITHDRAW,
        0x79, 0xFE, 0xFF, 0xFF,   /* x = 0xFFFFFE79 = -391 */
        0x00, 0xFF, 0xFF, 0xFF,   /* y = 0xFFFFFF00 = -256 */
        0xFE, 0xFF, 0xFF, 0xFF,   /* z = 0xFFFFFFFE =   -2 */
        0x00, 0x00, 0x01
    };
    memset(&act, 0xEE, sizeof act);
    const bool neg_ok = chestActionDecode(neg, sizeof neg, &act);
    check(neg_ok, "a frame carrying negative coordinates decodes");
    if (neg_ok) {
        check(act.x == -391 && act.y == -256 && act.z == -2,
              "negative coordinates round-trip sign-correct on all three axes");
        check(act.op == BS_CHEST_OP_WITHDRAW, "and the withdraw op decodes as itself");
    }

    /* Every wrong length, not a sampled one. cheststore.h's contract is
     * "false unless it is exactly that long", and BS_CHEST_ACTION_BYTES is
     * 17, so 0..24 covers short frames, the exact frame, and long ones. */
    unsigned wrong_len_accepted = 0;
    uint8_t pad[32];
    memcpy(pad, frame, sizeof frame);
    memset(pad + sizeof frame, 0, sizeof pad - sizeof frame);
    for (size_t len = 0; len <= 24u; len++) {
        if (len == BS_CHEST_ACTION_BYTES) continue;
        BsChestAction junk;
        if (chestActionDecode(pad, len, &junk)) wrong_len_accepted++;
    }
    check(wrong_len_accepted == 0,
          "every length from 0 to 24 except BS_CHEST_ACTION_BYTES (17) is refused — a"
          " short frame and a long one are both malformed, not a prefix to read");

    check(BS_CHEST_ACTION_BYTES == 17u,
          "BS_CHEST_ACTION_BYTES is 17 — the number the length check above is really about");

    /* Right length, wrong type byte. The payload arrives at this decoder
     * only because handle_app_payload() dispatched on body[0], so this can
     * only fire on a hand-built frame — but it is the one field a caller
     * could plausibly stop checking, and dropping it would leave a
     * CHEST_STATE (an S->C message) decodable as an action. */
    unsigned wrong_type_accepted = 0;
    const uint8_t wrong_types[] = { 0x00, BS_APP_BLOCK_EDIT, BS_APP_CHEST_STATE, 0x14, 0xFF };
    for (unsigned i = 0; i < sizeof wrong_types / sizeof wrong_types[0]; i++) {
        uint8_t bad[BS_CHEST_ACTION_BYTES];
        memcpy(bad, frame, sizeof bad);
        bad[0] = wrong_types[i];
        BsChestAction junk;
        if (chestActionDecode(bad, sizeof bad, &junk)) wrong_type_accepted++;
    }
    check(wrong_type_accepted == 0,
          "a right-length frame carrying any type byte other than BS_APP_CHEST_ACTION is refused,"
          " CHEST_STATE's own 0x12 included");
}

static void test_chest_state_encode(void)
{
    puts("v1.9.10: chestStateEncode writes exactly 29 bytes, and a chest with no record is empty");

    check(BS_CHEST_STATE_BYTES == 29u,
          "BS_CHEST_STATE_BYTES is 29: one type byte, twelve of position, eight (item, count) pairs");
    check(BS_CHEST_SLOTS == 8u, "a chest has eight slots on the wire");

    BsChest c;
    memset(&c, 0, sizeof c);
    c.x = -391; c.y = 70; c.z = 16909060;
    for (unsigned i = 0; i < BS_CHEST_SLOTS; i++) {
        c.slot[i][0] = (uint8_t)(2u + i);       /* dirt upward: distinct per slot */
        c.slot[i][1] = (uint8_t)(1u + i * 3u);
    }

    /* Written into a longer buffer with a sentinel tail, so "writes exactly
     * BS_CHEST_STATE_BYTES" is a claim this test can actually fail on rather
     * than one the array size quietly guarantees. */
    uint8_t buf[BS_CHEST_STATE_BYTES + 4u];
    memset(buf, 0xA5, sizeof buf);
    chestStateEncode(buf, c.x, c.y, c.z, &c);

    check(buf[0] == BS_APP_CHEST_STATE, "the snapshot's type byte is BS_APP_CHEST_STATE (0x12)");
    check(buf[BS_CHEST_STATE_BYTES] == 0xA5 && buf[BS_CHEST_STATE_BYTES + 1u] == 0xA5
          && buf[BS_CHEST_STATE_BYTES + 2u] == 0xA5 && buf[BS_CHEST_STATE_BYTES + 3u] == 0xA5,
          "and it writes 29 bytes and not one more — the four sentinel bytes past the end survive");
    check(chest_state_at(buf, -391, 70, 16909060),
          "x, y, z are little-endian in that order, negative values included (checked byte by byte,"
          " not through bs_get_i32)");

    bool slots_ok = true;
    for (unsigned i = 0; i < BS_CHEST_SLOTS; i++) {
        uint8_t item = 0, count = 0;
        chest_state_slot(buf, i, &item, &count);
        if (item != (uint8_t)(2u + i) || count != (uint8_t)(1u + i * 3u)) slots_ok = false;
    }
    check(slots_ok, "all eight (item, count) pairs follow the position in slot order");

    /* The NULL case is not a convenience: bsgame.c's broadcast_chest_state()
     * passes cheststoreFind()'s result straight through, and that is NULL
     * for every chest nobody has deposited into yet — which is every chest
     * the moment it is placed. */
    memset(buf, 0xA5, sizeof buf);
    chestStateEncode(buf, 5, 6, 7, NULL);
    check(buf[0] == BS_APP_CHEST_STATE && chest_state_at(buf, 5, 6, 7),
          "a chest with no record still encodes its own position");
    check(chest_state_is_empty(buf),
          "and all sixteen slot bytes are zero — a chest that has never been used reads as empty,"
          " never as uninitialised");
}

/* ---- in-process: the transfer rules ------------------------------------ */

/* BsChestStore is BS_CHEST_MAX (4096) x 28 bytes plus change — 115 KiB, far
 * past what belongs on a test's stack, so every scenario below works on a
 * heap copy. */
static BsChestStore *chest_store_new(void)
{
    BsChestStore *cs = malloc(sizeof *cs);
    if (cs == NULL) die("malloc BsChestStore");
    memset(cs, 0, sizeof *cs);
    return cs;
}

static void test_cheststore_deposit_rules(void)
{
    puts("v1.9.10: cheststoreRoom/Deposit — empty slot, merge, cap, wrong item, bad index");

    BsChestStore *cs = chest_store_new();
    const int32_t x = 10, y = 40, z = -20;

    check(cheststoreCount(cs) == 0, "a zeroed store holds no chests");
    check(cheststoreFind(cs, x, y, z) == NULL,
          "and a chest nobody has deposited into has no record — NULL, not an empty one");
    check(cheststoreRoom(cs, x, y, z, 0, 2 /* BLOCK_DIRT */) == (uint8_t)BS_INV_STACK_MAX,
          "an untouched chest's slot 0 has room for a whole stack");

    check(cheststoreDeposit(cs, x, y, z, 0, 2, 5),
          "a deposit into an empty slot lands");
    check(cheststoreCount(cs) == 1, "and it is the deposit that creates the record, nothing earlier");
    const BsChest *c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[0][0] == 2 && c->slot[0][1] == 5,
          "the slot holds the item and the count that were deposited");

    check(cheststoreRoom(cs, x, y, z, 0, 2) == (uint8_t)(BS_INV_STACK_MAX - 5u),
          "room in a slot holding the same item is the cap minus what is already there");
    check(cheststoreDeposit(cs, x, y, z, 0, 2, 3),
          "a deposit of the same item merges into the stack");
    c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[0][0] == 2 && c->slot[0][1] == 8,
          "and the counts add rather than replacing");
    check(cheststoreCount(cs) == 1, "a second deposit into the same chest makes no second record");

    /* The cap. 95 + 10 does not fit, and the store is all-or-nothing: it
     * refuses rather than moving the 4 that would. bsgame.c is where the
     * partial move lives — it asks cheststoreRoom() first and deposits the
     * smaller of the two. That split is the whole reason both halves of this
     * section exist. */
    check(cheststoreDeposit(cs, x, y, z, 1, 2, 95), "a 95-unit deposit into an empty slot lands");
    check(cheststoreRoom(cs, x, y, z, 1, 2) == 4u,
          "a slot holding 95 of an item has room for exactly 4 more");
    check(!cheststoreDeposit(cs, x, y, z, 1, 2, 10),
          "and asking it to take 10 is refused outright — cheststoreDeposit is all-or-nothing,"
          " the partial move is bsgame.c's job");
    c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[1][1] == 95, "the refused deposit changed nothing");
    check(cheststoreDeposit(cs, x, y, z, 1, 2, 4), "the 4 that do fit are accepted");
    c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[1][1] == (uint8_t)BS_INV_STACK_MAX,
          "leaving the slot at the stack cap, 99");
    check(cheststoreRoom(cs, x, y, z, 1, 2) == 0u, "a slot at the cap has no room left");
    check(!cheststoreDeposit(cs, x, y, z, 1, 2, 1), "and refuses even one more unit");

    /* A different item in the destination. This is the rule that keeps a
     * chest slot a stack rather than a pile. */
    check(cheststoreRoom(cs, x, y, z, 0, 3 /* BLOCK_STONE */) == 0u,
          "a slot holding a different item reports no room, whatever is left of the cap");
    check(!cheststoreDeposit(cs, x, y, z, 0, 3, 1),
          "and a deposit of a different item into it is refused");
    c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[0][0] == 2 && c->slot[0][1] == 8,
          "the slot still holds what it held — no overwrite, no silent swap");

    check(cheststoreRoom(cs, x, y, z, (uint8_t)BS_CHEST_SLOTS, 2) == 0u,
          "slot index 8 is one past the last slot and reports no room");
    check(!cheststoreDeposit(cs, x, y, z, (uint8_t)BS_CHEST_SLOTS, 2, 1),
          "a deposit into slot 8 is refused");
    check(!cheststoreDeposit(cs, x, y, z, 255, 2, 1), "so is one into slot 255");

    check(cheststoreRoom(cs, x, y, z, 2, 0) == 0u, "item id 0 (air) has no room anywhere");
    check(!cheststoreDeposit(cs, x, y, z, 2, 0, 1), "and depositing item 0 is refused");
    check(!cheststoreDeposit(cs, x, y, z, 2, 2, 0),
          "so is a deposit of zero units — a count is never a way of saying nothing");
    check(!cheststoreDeposit(cs, x, y, z, 2, 2, (uint8_t)(BS_INV_STACK_MAX + 1u)),
          "so is one of 100 units, past BS_INV_STACK_MAX");

    /* A refused deposit into a chest with no record must not leave an empty
     * record behind — cheststore.c answers room before it creates anything,
     * and this is what says so. */
    check(!cheststoreDeposit(cs, 999, 40, 999, 0, 0, 1),
          "a refused deposit into a chest that has no record is still refused");
    check(cheststoreFind(cs, 999, 40, 999) == NULL && cheststoreCount(cs) == 1,
          "and leaves no empty record behind — the table still holds exactly one chest");

    free(cs);
}

static void test_cheststore_withdraw_rules(void)
{
    puts("v1.9.10: cheststoreWithdraw — takes what is there, empties to item 0, refuses the rest");

    BsChestStore *cs = chest_store_new();
    const int32_t x = -5, y = 12, z = 30;

    check(cheststoreWithdraw(cs, x, y, z, 0, 1, NULL) == 0,
          "a withdraw from a chest with no record takes nothing");

    check(cheststoreDeposit(cs, x, y, z, 2, 5 /* BLOCK_WOOD */, 10), "priming deposit of 10 wood");

    uint8_t item = 0xEE;
    check(cheststoreWithdraw(cs, x, y, z, 2, 4, &item) == 4, "a withdraw of 4 returns 4");
    check(item == 5, "and reports which item it took through item_out");
    const BsChest *c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[2][0] == 5 && c->slot[2][1] == 6,
          "leaving 6 of the same item in the slot");

    /* NOT a clamp. cheststore.h: "0 and nothing changed when the slot ...
     * holds fewer than `units` — the caller asked for units that do not
     * exist, and the verified model refuses rather than rounds down". This
     * is the half of the duplication defence that matters when two clients
     * race: the loser is told no, not given a smaller share. */
    check(cheststoreWithdraw(cs, x, y, z, 2, 20, NULL) == 0,
          "a withdraw of more than the slot holds takes NOTHING — it is refused, not rounded down");
    c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[2][1] == 6, "and the slot is untouched by the refusal");

    check(cheststoreWithdraw(cs, x, y, z, 2, 6, NULL) == 6, "a withdraw of exactly what is there succeeds");
    c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[2][0] == 0 && c->slot[2][1] == 0,
          "and empties the slot to {0, 0} — the item id is cleared too, never left stale beside a zero count");

    check(cheststoreWithdraw(cs, x, y, z, 2, 1, NULL) == 0, "a withdraw from the now-empty slot takes nothing");
    check(cheststoreWithdraw(cs, x, y, z, 0, 1, NULL) == 0, "so does one from a slot never used");
    check(cheststoreWithdraw(cs, x, y, z, (uint8_t)BS_CHEST_SLOTS, 1, NULL) == 0,
          "so does one from slot 8, past the last slot");
    check(cheststoreWithdraw(cs, x, y, z, 255, 1, NULL) == 0, "and one from slot 255");

    /* units == 0 means "the whole stack" to this function. Unreachable from
     * the wire — bsgame.c refuses count 0 before it gets here, and
     * test_chest_action_count_validation() below proves that — but it is
     * what the header documents, so it is what is checked. */
    check(cheststoreDeposit(cs, x, y, z, 3, 5, 7), "priming deposit of 7 wood into slot 3");
    check(cheststoreWithdraw(cs, x, y, z, 3, 0, NULL) == 7,
          "units == 0 takes the whole stack at the module's own interface (bsgame.c never asks that)");
    c = cheststoreFind(cs, x, y, z);
    check(c != NULL && c->slot[3][0] == 0 && c->slot[3][1] == 0, "and empties that slot too");

    free(cs);
}

static void test_cheststore_remove_and_capacity(void)
{
    puts("v1.9.10: cheststoreRemove drops a record whole, and the table stops at BS_CHEST_MAX");

    BsChestStore *cs = chest_store_new();

    check(cheststoreDeposit(cs, 1, 40, 1, 0, 2, 3), "a chest to remove");
    check(cheststoreDeposit(cs, 2, 40, 2, 0, 2, 3), "and one beside it");
    check(cheststoreRemove(cs, 1, 40, 1), "cheststoreRemove reports it removed one");
    check(cheststoreFind(cs, 1, 40, 1) == NULL, "the record is gone, contents and all");
    check(cheststoreFind(cs, 2, 40, 2) != NULL,
          "and its neighbour survived — the swap-with-last compaction did not take the wrong one");
    check(cheststoreCount(cs) == 1, "the count fell by exactly one");
    check(!cheststoreRemove(cs, 1, 40, 1), "removing it again reports there was nothing to remove");

    /* Fill to BS_CHEST_MAX. cheststore.h: the bound exists for the reason
     * BS_DIFF_MAX does — a hostile client must not be able to grow this
     * without limit — so what happens AT the bound is a documented behaviour
     * and not an implementation accident. */
    memset(cs, 0, sizeof *cs);
    unsigned filled = 0;
    for (uint32_t i = 0; i < BS_CHEST_MAX; i++) {
        if (cheststoreDeposit(cs, (int32_t)i, 40, 7000, 0, 2, 1)) filled++;
    }
    check(filled == BS_CHEST_MAX, "BS_CHEST_MAX (4096) distinct chests all take their first deposit");
    check(cheststoreCount(cs) == BS_CHEST_MAX, "and the table reports exactly that many");

    check(cheststoreRoom(cs, 999999, 40, 7000, 0, 2) == 0u,
          "with the table full, a chest that has no record reports no room — the caller is told"
          " BEFORE it takes the units out of a bag");
    check(!cheststoreDeposit(cs, 999999, 40, 7000, 0, 2, 1),
          "and the deposit that would have created record 4097 is refused");
    check(cheststoreCount(cs) == BS_CHEST_MAX, "the refusal did not grow the table");

    check(cheststoreRoom(cs, 0, 40, 7000, 5, 2) == (uint8_t)BS_INV_STACK_MAX,
          "a chest that already HAS a record is unaffected by a full table");
    check(cheststoreDeposit(cs, 0, 40, 7000, 5, 2, 1), "and can still take a deposit");

    check(cheststoreRemove(cs, 0, 40, 7000), "removing one frees a row");
    check(cheststoreCount(cs) == BS_CHEST_MAX - 1u, "the table is one short of full");
    check(cheststoreDeposit(cs, 999999, 40, 7000, 0, 2, 1),
          "and the deposit that was refused a moment ago now lands in the freed row");

    free(cs);
}

/* ---- in-process: the on-disk mirror ------------------------------------ */

static void chest_bin_path(char *out, size_t cap, const char *dir)
{
    snprintf(out, cap, "%s/chests.bin", dir);
}

/* Writes a chests.bin by hand: magic, then `n` 28-byte records straight out
 * of `recs`. Used for the sanitising cases, which have to put bytes on disk
 * that cheststoreFlush() would never write. */
static bool chest_bin_write(const char *dir, const uint8_t *recs, unsigned n, const char *magic)
{
    char path[256];
    chest_bin_path(path, sizeof path, dir);
    FILE *f = fopen(path, "wb");
    if (f == NULL) return false;
    bool ok = fwrite(magic, 1, 8, f) == 8;
    if (ok && n > 0) {
        ok = fwrite(recs, 1, (size_t)n * BSGAME_TEST_CHEST_REC_BYTES, f)
             == (size_t)n * BSGAME_TEST_CHEST_REC_BYTES;
    }
    return fclose(f) == 0 && ok;
}

static void chest_rec_put(uint8_t *rec, int32_t x, int32_t y, int32_t z,
                          uint8_t item0, uint8_t count0)
{
    memset(rec, 0, BSGAME_TEST_CHEST_REC_BYTES);
    bs_put_i32(rec,     x);
    bs_put_i32(rec + 4, y);
    bs_put_i32(rec + 8, z);
    rec[12] = item0;
    rec[13] = count0;
}

static void test_cheststore_disk_round_trip(void)
{
    puts("v1.9.10: chests.bin round-trips, debounces, and sanitises every record it reads back");

    char dir[192];
    snprintf(dir, sizeof dir, "%s/chest_rt", g_dir);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) die("mkdir chest_rt");

    char err[256];
    unsigned dropped = 0xFFFFFFFFu;
    BsChestStore *cs = chest_store_new();

    check(cheststoreOpen(cs, dir, err, sizeof err, &dropped),
          "opening a state dir with no chests.bin succeeds — a fresh world, not an error");
    check(cheststoreCount(cs) == 0 && dropped == 0, "and yields an empty store with nothing dropped");

    check(cheststoreFlush(cs, 100000u, true) == 0,
          "flushing a store nothing has changed writes nothing, even forced");

    check(cheststoreDeposit(cs, 100, 40, -200, 0, 2 /* BLOCK_DIRT */, 9), "a deposit to persist");
    check(cheststoreDeposit(cs, 100, 40, -200, 7, 5 /* BLOCK_WOOD */, 1), "and a second slot in the same chest");
    check(cheststoreDeposit(cs, -300, 12, 400, 3, 3 /* BLOCK_STONE */, 64), "and a second chest");

    /* The debounce, with synthetic clocks so the assertion is about
     * BS_CHEST_FLUSH_MS and not about how fast this machine runs. */
    check(cheststoreFlush(cs, 100000u, true) == 1, "a forced flush of a dirty store writes the file");
    check(cheststoreFlush(cs, 100000u, true) == 0, "and the store is clean afterwards, so a second forced flush is a no-op");
    check(cheststoreDeposit(cs, -300, 12, 400, 4, 3, 1), "dirty it again");
    check(cheststoreFlush(cs, 100500u, false) == 0,
          "an unforced flush 500 ms after the last one is not yet due — BS_CHEST_FLUSH_MS is 1000");
    check(cheststoreFlush(cs, 101000u, false) == 1, "one a full second after it is");

    char path[256];
    chest_bin_path(path, sizeof path, dir);
    FILE *f = fopen(path, "rb");
    check(f != NULL, "chests.bin exists on disk");
    if (f != NULL) {
        char magic[8];
        check(fread(magic, 1, 8, f) == 8 && memcmp(magic, "BSCHEST1", 8) == 0,
              "and starts with the BSCHEST1 magic");
        fseek(f, 0, SEEK_END);
        const long size = ftell(f);
        fclose(f);
        check(size == 8L + 2L * (long)BSGAME_TEST_CHEST_REC_BYTES,
              "its body is a whole number of 28-byte records, one per chest — 8 + 2*28 = 64 bytes");
    }

    BsChestStore *re = chest_store_new();
    dropped = 0xFFFFFFFFu;
    check(cheststoreOpen(re, dir, err, sizeof err, &dropped),
          "a second store opens the file the first one wrote");
    check(cheststoreCount(re) == 2 && dropped == 0, "and reads back both chests, dropping none");
    const BsChest *a = cheststoreFind(re, 100, 40, -200);
    const BsChest *b = cheststoreFind(re, -300, 12, 400);
    check(a != NULL && a->slot[0][0] == 2 && a->slot[0][1] == 9
          && a->slot[7][0] == 5 && a->slot[7][1] == 1,
          "the first chest's slots survive the round trip, including a negative z");
    check(b != NULL && b->slot[3][0] == 3 && b->slot[3][1] == 64 && b->slot[4][1] == 1,
          "and so do the second's, including a negative x");
    free(re);
    free(cs);

    /* Refusals. cheststore.h's stance is diffstoreOpen's: a file that is
     * present but is not this format is a reason to refuse to start, because
     * running with half the players' chests silently emptied is worse. */
    BsChestStore *bad = chest_store_new();
    check(chest_bin_write(dir, NULL, 0, "NOTCHEST"), "a file with the wrong magic is written");
    err[0] = '\0';
    check(!cheststoreOpen(bad, dir, err, sizeof err, &dropped),
          "and cheststoreOpen refuses it rather than treating it as an empty world");
    check(err[0] != '\0', "with a reason in err the caller can print");

    uint8_t torn[8 + BSGAME_TEST_CHEST_REC_BYTES];
    memcpy(torn, "BSCHEST1", 8);
    chest_rec_put(torn + 8, 1, 2, 3, 2, 1);
    f = fopen(path, "wb");
    check(f != NULL, "a truncated file opens for writing");
    if (f != NULL) {
        /* One record short of whole: 8 + 20 of a 28-byte record. */
        check(fwrite(torn, 1, 8u + 20u, f) == 8u + 20u, "and 20 of a record's 28 bytes are written");
        fclose(f);
    }
    err[0] = '\0';
    check(!cheststoreOpen(bad, dir, err, sizeof err, &dropped),
          "a torn trailing record is refused too — the length is not a whole number of records");
    check(err[0] != '\0', "and that refusal also carries a reason");

    /* Sanitising. Every field of every record that IS read is checked rather
     * than trusted, because chests.bin is a file an operator (or anything
     * with write access to the state dir) can edit. */
    uint8_t recs[4][BSGAME_TEST_CHEST_REC_BYTES];
    chest_rec_put(recs[0], 70000, 40, 0, 2, 5);        /* x past BS_WORLD_XZ_LIMIT   */
    chest_rec_put(recs[1], 10, 40, 10, 8 /* water */, 5);  /* inventoryCanHold refuses  */
    chest_rec_put(recs[2], 20, 40, 20, 2, 200);        /* count past BS_INV_STACK_MAX */
    chest_rec_put(recs[3], 20, 40, 20, 2, 1);          /* duplicate position          */
    check(chest_bin_write(dir, &recs[0][0], 4, "BSCHEST1"), "a hand-built chests.bin with four dubious records");

    dropped = 0xFFFFFFFFu;
    check(cheststoreOpen(bad, dir, err, sizeof err, &dropped),
          "cheststoreOpen accepts a well-formed file whose CONTENTS are dubious — it sanitises"
          " rather than refusing to start");
    check(cheststoreCount(bad) == 2 && dropped == 2,
          "two of the four records are kept and two dropped: the out-of-range position and the"
          " duplicate of a position already loaded");
    check(cheststoreFind(bad, 70000, 40, 0) == NULL,
          "the record bsEditValid() refuses is gone entirely, position and all");
    const BsChest *liq = cheststoreFind(bad, 10, 40, 10);
    check(liq != NULL && liq->slot[0][0] == 0 && liq->slot[0][1] == 0,
          "a slot holding an id inventoryCanHold() refuses is CLEARED, not dropped with its chest");
    const BsChest *over = cheststoreFind(bad, 20, 40, 20);
    check(over != NULL && over->slot[0][0] == 2 && over->slot[0][1] == (uint8_t)BS_INV_STACK_MAX,
          "and a count past BS_INV_STACK_MAX is clamped to 99, keeping the item");

    free(bad);
    remove(path);
}

/* ---- end-to-end: the daemon -------------------------------------------- */

static void test_chest_deposit_broadcasts_a_snapshot(void)
{
    puts("v1.9.10 end-to-end: a DEPOSIT into a placed chest answers with a whole-chest snapshot");
    drain();

    const uint32_t sid = 0xC4E51001u;
    const int32_t x = 5001, y = 40, z = 5000;
    chest_join(sid, "chesta");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* v1.9.10 fix: a DEPOSIT is a MOVE out of the bag now, so every scenario
     * below has to put the units in the bag first. Before the fix these
     * deposits came out of nothing. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 8);
    chest_give(sid, 3 /* BLOCK_STONE */, 2);
    drain();

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0 /* chest slot */, 5);

    uint8_t st[BS_CHEST_STATE_BYTES];
    ssize_t n = recv_chest_state(sid, st, sizeof st, 700);
    const bool shaped = (n == (ssize_t)BS_CHEST_STATE_BYTES);
    check(shaped, "an accepted DEPOSIT puts exactly one BS_CHEST_STATE_BYTES snapshot on the wire");
    if (!shaped) return;

    check(chest_state_at(st, x, y, z), "the snapshot names the chest that was deposited into");
    uint8_t item = 0, count = 0;
    chest_state_slot(st, 0, &item, &count);
    check(item == 2 && count == 5, "chest slot 0 holds the 5 dirt that were deposited");

    /* The other seven slots come back in the same packet: CHEST_STATE is a
     * whole-chest snapshot and never a delta (bs_proto.h's own words), which
     * is what makes it impossible to desync. */
    bool rest_empty = true;
    for (unsigned i = 1; i < BS_CHEST_SLOTS; i++) {
        uint8_t it = 0, ct = 0;
        chest_state_slot(st, i, &it, &ct);
        if (it != 0 || ct != 0) rest_empty = false;
    }
    check(rest_empty, "and the other seven slots ride along empty — a snapshot, never a delta");

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 0, 3);
    n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "a second DEPOSIT is answered too");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        chest_state_slot(st, 0, &item, &count);
        check(item == 2 && count == 8, "and it merged into the same stack: 5 + 3 = 8");
    }

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 3 /* BLOCK_STONE */, 7, 2);
    n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "a deposit into the last slot is answered");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t i0 = 0, c0 = 0, i7 = 0, c7 = 0;
        chest_state_slot(st, 0, &i0, &c0);
        chest_state_slot(st, 7, &i7, &c7);
        check(i0 == 2 && c0 == 8 && i7 == 3 && c7 == 2,
              "and the snapshot carries both slots at once — slot 0 untouched, slot 7 new");
    }
}

static void test_chest_deposit_partial_merge_at_the_cap(void)
{
    puts("v1.9.10 end-to-end: a deposit that does not fit whole moves what fits, and says so");
    drain();

    const uint32_t sid = 0xC4E51002u;
    const int32_t x = 5002, y = 40, z = 5000;
    chest_join(sid, "chestb");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* 106 dirt: 95 for the priming deposit, 10 for the one that only
     * partly fits, and 1 left over so the final attempt is refused for
     * having no ROOM rather than for an empty bag. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 95);
    chest_give(sid, 2, 11);
    drain();

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0, 95);
    uint8_t st[BS_CHEST_STATE_BYTES];
    ssize_t n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "the priming 95-unit deposit is accepted");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(item == 2 && count == 95, "leaving slot 0 at 95");
    }

    /* The case bsgame.c's chest_action_apply() header states outright: "a
     * slot at 95 asked for 10 goes to 99 and the snapshot says so". Only 4
     * move; the client reconciles its own bag from the snapshot, which is
     * why no INV_STATE follows. */
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 0, 10);
    n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "asking a slot at 95 to take 10 more is ACCEPTED, not refused");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(item == 2 && count == (uint8_t)BS_INV_STACK_MAX,
              "and exactly the 4 that fit moved — the snapshot shows 99, not 105 and not 95");
    }

    /* Now there is no room at all, and that is a refusal rather than a
     * zero-unit transfer. */
    bool saw_state = false, saw_kick = false;
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 0, 1);
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_state, "a deposit into a slot already at the cap produces no snapshot at all");
    check(!saw_kick, "and no kick");
}

static void test_chest_deposit_refusals_are_silent(void)
{
    puts("v1.9.10 end-to-end: every invalid DEPOSIT is refused silently — no snapshot, no kick");
    drain();

    const uint32_t sid = 0xC4E51003u;
    const int32_t x = 5003, y = 40, z = 5000;
    chest_join(sid, "chestc");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* The stone matters: without it the "different item into an occupied
     * slot" case below would be refused for an EMPTY BAG instead, and the
     * refusal this scenario names would stop being the one being tested. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 7);
    chest_give(sid, 3 /* BLOCK_STONE */, 1);
    drain();

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0, 1);
    uint8_t st[BS_CHEST_STATE_BYTES];
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "the priming deposit lands, so slot 0 holds dirt for the refusals below");

    /* Each of these is a separate documented refusal. They are run as one
     * batch and watched together because the assertion is identical for all
     * of them — nothing comes back and the session survives — and because
     * one 400 ms silence window per case would add three seconds to the
     * suite for no extra evidence. */
    struct { const char *what; uint8_t item; uint8_t slot; uint8_t count; } bad[] = {
        { "a different item into an occupied slot", 3 /* BLOCK_STONE */, 0,   1 },
        { "chest slot 8, one past the last",        2,                   8,   1 },
        { "chest slot 255",                         2,                   255, 1 },
        { "water (id 8), which inventoryCanHold refuses", 8,             1,   1 },
        { "item id 0",                              0,                   1,   1 },
    };
    bool any_state = false, any_kick = false;
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        bool saw_state = false, saw_kick = false;
        send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, bad[i].item, bad[i].slot, bad[i].count);
        chest_watch(sid, 250, &saw_state, &saw_kick);
        if (saw_state) { any_state = true; printf("  ..    a snapshot came back for: %s\n", bad[i].what); }
        if (saw_kick)  { any_kick  = true; printf("  ..    a KICK came back for: %s\n", bad[i].what); }
    }
    check(!any_state,
          "none of the five invalid DEPOSITs produces a CHEST_STATE: wrong item into an occupied"
          " slot, slot 8, slot 255, a liquid, item 0");
    check(!any_kick,
          "and none of them disconnects the player — a malformed or invalid CHEST_ACTION is a"
          " refusal, never a protocol violation, unlike an unknown message type");

    /* The refusals changed nothing, and the session still works. Without
     * this the two silence checks above would stay green against a daemon
     * that had stopped listening altogether. */
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 0, 4);
    const ssize_t n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES,
          "and a valid DEPOSIT sent straight afterwards is still answered — the session survived"
          " all five");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(item == 2 && count == 5, "slot 0 holds 1 + 4 = 5 dirt: not one refusal moved a unit");
        uint8_t i1 = 0, c1 = 0;
        chest_state_slot(st, 1, &i1, &c1);
        check(i1 == 0 && c1 == 0, "and slot 1, the target of the liquid and item-0 attempts, is still empty");
    }
    check(kill(g_daemon, 0) == 0, "the daemon is still up after five invalid chest actions");
}

static void test_chest_withdraw(void)
{
    puts("v1.9.10 end-to-end: WITHDRAW takes what was asked, empties the slot, then refuses");
    drain();

    const uint32_t sid = 0xC4E51004u;
    const int32_t x = 5004, y = 40, z = 5000;
    chest_join(sid, "chestd");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* v1.9.10 fix: a DEPOSIT is a MOVE out of the bag now, so every scenario
     * below has to put the units in the bag first. Before the fix these
     * deposits came out of nothing. */
    chest_give(sid, 5 /* BLOCK_WOOD */, 13);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 5 /* BLOCK_WOOD */, 2, 10);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "priming deposit of 10 wood into chest slot 2");

    /* WITHDRAW's field contract is the mirror of DEPOSIT's and easy to get
     * backwards: a = the CHEST slot, b = the inventory slot (which this
     * server ignores entirely — the client is authoritative for its own
     * bag). Passing 6 as `b` here is deliberate: if the two were ever
     * swapped, this would try to take from chest slot 6, which is empty. */
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 2 /* chest slot */, 6 /* inv slot */, 4);
    ssize_t n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "a WITHDRAW of 4 is answered with a snapshot");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 2, &item, &count);
        check(item == 5 && count == 6, "and the chest slot is down to 6 — a = the chest slot, b is ignored");
    }

    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 2, 0, 6);
    n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "taking the remaining 6 is answered");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 2, &item, &count);
        check(item == 0 && count == 0,
              "and the emptied slot reads back as {0, 0} — the item id goes with the last unit");
    }

    /* Three refusals, silent like every other. The over-ask is the one worth
     * naming: cheststore.h refuses rather than rounding down, so asking a
     * slot holding nothing (or holding fewer than asked) for units yields no
     * snapshot at all. */
    struct { const char *what; uint8_t slot; uint8_t count; } bad[] = {
        { "the slot that was just emptied",          2,   1 },
        { "a slot that was never used",              0,   1 },
        { "chest slot 8, one past the last",         8,   1 },
        { "chest slot 255",                          255, 1 },
    };
    bool any_state = false, any_kick = false;
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        bool saw_state = false, saw_kick = false;
        send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, bad[i].slot, 0, bad[i].count);
        chest_watch(sid, 250, &saw_state, &saw_kick);
        if (saw_state) { any_state = true; printf("  ..    a snapshot came back for: %s\n", bad[i].what); }
        if (saw_kick)  { any_kick  = true; printf("  ..    a KICK came back for: %s\n", bad[i].what); }
    }
    check(!any_state, "a WITHDRAW from an empty slot, an unused slot, slot 8 or slot 255 produces no snapshot");
    check(!any_kick,  "and none of them kicks the player");

    /* The over-ask, on a slot that really does hold something. */
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 5, 4, 3);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "priming deposit of 3 wood into chest slot 4");
    bool saw_state = false, saw_kick = false;
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 4, 0, 20);
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_state,
          "asking a slot holding 3 for 20 units is REFUSED outright — cheststore.h rounds nothing"
          " down, so no snapshot goes out");
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 4, 0, 3);
    n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "and the 3 that are there can still be taken afterwards");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 4, &item, &count);
        check(item == 0 && count == 0, "leaving that slot empty too");
    }
}

static void test_chest_action_count_validation(void)
{
    puts("v1.9.10 end-to-end: count is a count — 0 is refused, and so is anything past 99");
    drain();

    const uint32_t sid = 0xC4E51005u;
    const int32_t x = 5005, y = 40, z = 5000;
    chest_join(sid, "cheste");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* Only the priming deposit needs backing: every refusal below is
     * gated on `count` or on the op byte, both of which are read before
     * the bag is consulted at all. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 6);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0, 6);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "priming deposit of 6 dirt");

    /* count 0 is the one that matters. cheststoreWithdraw() reads 0 as "the
     * whole stack" at its own interface, so a bsgame.c that forwarded it
     * would empty the slot on a packet that asked for nothing — the exact
     * shape bs_proto.h forbids: "a COUNT, never a pad: 0 is refused, not
     * read as everything". */
    bool saw_state = false, saw_kick = false;
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 0, 0, 0);
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_state, "a WITHDRAW with count 0 is refused, NOT read as \"take everything\"");
    check(!saw_kick, "and does not kick");

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 1, 0);
    chest_watch(sid, 250, &saw_state, &saw_kick);
    check(!saw_state, "a DEPOSIT with count 0 is refused too");

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 1, 100);
    chest_watch(sid, 250, &saw_state, &saw_kick);
    check(!saw_state, "and so is a count of 100, one past BS_INV_STACK_MAX");

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 1, 255);
    chest_watch(sid, 250, &saw_state, &saw_kick);
    check(!saw_state, "and 255");

    /* An op byte that is neither DEPOSIT nor WITHDRAW. */
    send_chest_action(sid, 0x02, x, y, z, 2, 1, 1);
    chest_watch(sid, 250, &saw_state, &saw_kick);
    check(!saw_state, "an unknown op byte (0x02) is refused");
    send_chest_action(sid, 0xFF, x, y, z, 2, 1, 1);
    chest_watch(sid, 250, &saw_state, &saw_kick);
    check(!saw_state, "and so is 0xFF");
    check(!saw_kick, "no unknown-op refusal kicks either — the dispatch table's default case is"
                     " for unknown MESSAGE TYPES, not unknown ops inside a known one");

    /* Nothing above moved a unit, and the session is alive. */
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 0, 0, 6);
    const ssize_t n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "a valid action after seven refusals is still answered");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(item == 0 && count == 0,
              "and the 6 dirt were all still there to take — not one refusal removed a unit");
    }
}

static void test_chest_action_malformed_is_not_a_kick(void)
{
    puts("v1.9.10 end-to-end: a wrong-length CHEST_ACTION is dropped, NOT KICKed");
    drain();

    const uint32_t sid = 0xC4E51006u;
    const int32_t x = 5006, y = 40, z = 5000;
    chest_join(sid, "chestf");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* v1.9.10 fix: a DEPOSIT is a MOVE out of the bag now, so every scenario
     * below has to put the units in the bag first. Before the fix these
     * deposits came out of nothing. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 2);
    drain();

    /* This is the important one. handle_app_payload() KICKs an unknown
     * message type, and BLOCK_EDIT, POS_UPDATE, CHUNK_SUB, CHUNK_UNSUB and
     * PLAYER_REPORT all kick on "right type, wrong length" too — five of the
     * seven neighbours of this case behave the opposite way. bs_proto.h
     * makes CHEST_ACTION an explicit exception ("refuses, silently and
     * without a kick, anything that does not validate"), so the pull toward
     * the majority rule is exactly what this test is holding the line
     * against. */
    const uint8_t stub[3] = { BS_APP_CHEST_ACTION, BS_CHEST_OP_DEPOSIT, 0 };
    send_app(sid, stub, sizeof stub);
    bool saw_state = false, saw_kick = false;
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_kick, "a 3-byte CHEST_ACTION does NOT disconnect the player");
    check(!saw_state, "and produces no snapshot either");

    uint8_t over[BS_CHEST_ACTION_BYTES + 4u];
    memset(over, 0, sizeof over);
    over[0] = BS_APP_CHEST_ACTION;
    send_app(sid, over, sizeof over);
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_kick, "neither does a 21-byte one — too long is malformed, not a frame with padding");
    check(!saw_state, "and it produces no snapshot");

    /* The proof the session is really still there rather than merely quiet:
     * a valid action on it is answered. Without this, both checks above
     * would pass against a daemon that had silently dropped the player. */
    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0, 2);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "and the same session answers a well-formed CHEST_ACTION straight afterwards — it was"
          " never disconnected, only ignored");
}

static void test_chest_position_gating(void)
{
    puts("v1.9.10 end-to-end: a chest action is refused unless a chest really stands there");
    drain();

    const uint32_t sid = 0xC4E51007u;
    const int32_t y = 40, z = 5000;
    chest_join(sid, "chestg");
    /* Enough dirt that every refusal below is a POSITION refusal. The
     * position gates run before the bag is consulted, so this only really
     * backs the valid deposit at the end -- but a scenario whose refusals
     * could be explained by an empty bag would prove nothing about the
     * gate it is named after. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 10);
    drain();

    /* A cell with no diff at all. The diff store is what knows which cells
     * are chests (cheststore.h is explicit that it does not), so this is the
     * check that stops a client naming an arbitrary coordinate and getting a
     * chest for free. */
    bool saw_state = false, saw_kick = false;
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, 5100, y, z, 2, 0, 1);
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_state, "a DEPOSIT at a cell the world has never been edited at is refused");
    check(!saw_kick, "and is not a kick");

    /* A cell holding a real block that is not a chest. */
    chest_place_block(sid, 5101, y, z, 3 /* BLOCK_STONE */);
    drain();
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, 5101, y, z, 2, 0, 1);
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_state, "a DEPOSIT at a cell holding stone is refused — the block has to be a chest");
    check(!saw_kick, "and is not a kick");

    /* Out of the world entirely — and note carefully what these two checks do
     * NOT prove.
     *
     * chest_action_apply() calls bsEditValid() before it looks the cell up,
     * so a position past BS_WORLD_XZ_LIMIT (60000) or BS_WORLD_HEIGHT (128)
     * is refused there first. But it would be refused by the chest-presence
     * gate a line later anyway: handle_block_edit() runs the same
     * bsEditValid(), so no out-of-range cell can ever be in the diff store to
     * be found. MEASURED, not assumed — with that bsEditValid() call replaced
     * by `if (false)` in a scratch copy, this whole suite still printed PASS
     * 531 checks, 0 failed. The range gate is defence in depth that nothing
     * reachable from the wire can distinguish, and no end-to-end check can
     * honestly claim to cover it.
     *
     * So these two assert the OBSERVABLE behaviour — an absurd position is
     * refused, and quietly — and nothing about which guard did it. The one
     * place bsEditValid() is both load-bearing and testable is
     * cheststore.c's decode_record(), where it drops out-of-range records
     * read back off disk; test_cheststore_disk_round_trip() above covers
     * that, and a red arm on that call confirms the coverage is real. */
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, 70000, y, z, 2, 0, 1);
    chest_watch(sid, 300, &saw_state, &saw_kick);
    check(!saw_state, "a DEPOSIT at x = 70000, past BS_WORLD_XZ_LIMIT, is refused");
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, 5102, 5000, z, 2, 0, 1);
    chest_watch(sid, 300, &saw_state, &saw_kick);
    check(!saw_state, "and so is one at y = 5000, past BS_WORLD_HEIGHT");
    check(!saw_kick, "neither out-of-range position kicks the player");

    /* And the same player, at a cell that IS a chest, still works. */
    chest_place_block(sid, 5103, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    drain();
    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, 5103, y, z, 2, 0, 1);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "and a DEPOSIT at a cell that really does hold a chest is answered");
}

static void test_chest_orphan_record_dropped_on_block_edit(void)
{
    puts("v1.9.10 end-to-end: breaking a chest drops its contents; replacing chest with chest keeps them");
    drain();

    const uint32_t sid = 0xC4E51008u;
    const int32_t x = 5008, y = 40, z = 5000;
    chest_join(sid, "chesth");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* v1.9.10 fix: a DEPOSIT is a MOVE out of the bag now, so every scenario
     * below has to put the units in the bag first. Before the fix these
     * deposits came out of nothing. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 8);
    chest_give(sid, 5 /* BLOCK_WOOD */, 1);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0, 7);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "seven dirt go into the chest");

    /* Chest onto chest: the block did not change, so the record must not be
     * touched. bsgame.c gates the drop on `block != BLOCK_CHEST` for exactly
     * this, and without the gate every re-place would empty the chest. */
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    drain();
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 0, 1);
    ssize_t n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "a deposit after a chest-onto-chest edit is answered");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(item == 2 && count == 8,
              "and the chest still holds what it held: 7 + 1 = 8 — a chest-onto-chest edit keeps"
              " the contents");
    }

    /* Now replace it with something else, then put a chest back. A record
     * that outlived its block would resurrect, full, inside the next chest
     * placed on the same cell — free items for anyone who breaks and
     * re-places a chest. */
    chest_place_block(sid, x, y, z, 3 /* BLOCK_STONE */);
    drain();
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    drain();

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 5 /* BLOCK_WOOD */, 3, 1);
    n = recv_chest_state(sid, st, sizeof st, 700);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES, "a deposit into the newly placed chest is answered");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t i0 = 0, c0 = 0, i3 = 0, c3 = 0;
        chest_state_slot(st, 0, &i0, &c0);
        chest_state_slot(st, 3, &i3, &c3);
        check(i0 == 0 && c0 == 0,
              "and slot 0 is EMPTY — the eight dirt went with the block that was broken, they did"
              " not resurrect inside the new chest");
        check(i3 == 5 && c3 == 1, "while the new deposit is where it was put");
    }
}

static void test_chest_two_players_cannot_take_the_same_stack(void)
{
    puts("v1.9.10 end-to-end: the second player to pull on a stack is refused, not given a copy");
    drain();

    const uint32_t sid_a = 0xC4E51009u, sid_b = 0xC4E5100Au;
    const int32_t x = 5009, y = 40, z = 5000;
    chest_join(sid_a, "chesti");
    chest_join(sid_b, "chestj");
    chest_place_block(sid_a, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    /* v1.9.10 fix: a DEPOSIT is a MOVE out of the bag now, so every scenario
     * below has to put the units in the bag first. Before the fix these
     * deposits came out of nothing. */
    chest_give(sid_a, 2 /* BLOCK_DIRT */, 9);
    chest_give(sid_b, 5 /* BLOCK_WOOD */, 2);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid_a, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0, 9);
    check(recv_chest_state(sid_a, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "nine dirt go into a chest both players can reach");

    /* The same snapshot reaches the OTHER player: broadcast_chest_state()
     * sends to every connected player, not to the actor and not scoped by
     * column, so a player who cannot see the chest still stores what they
     * will find in it. */
    const ssize_t nb = recv_chest_state(sid_b, st, sizeof st, 700);
    check(nb == (ssize_t)BS_CHEST_STATE_BYTES,
          "and the snapshot reaches the second player too — CHEST_STATE goes to everyone");
    if (nb == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(chest_state_at(st, x, y, z) && item == 2 && count == 9,
              "carrying the same position and the same nine dirt the depositor saw");
    }

    /* A takes the lot. */
    send_chest_action(sid_a, BS_CHEST_OP_WITHDRAW, x, y, z, 0, 0, 9);
    const ssize_t na = recv_chest_state(sid_a, st, sizeof st, 700);
    check(na == (ssize_t)BS_CHEST_STATE_BYTES, "the first player's withdraw of all nine is answered");
    if (na == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(item == 0 && count == 0, "and the slot is empty afterwards");
    }
    drain();

    /* B asks for the same nine. The whole point of keeping chest contents
     * server-side: B is told no rather than handed a second copy. */
    bool saw_state = false, saw_kick = false;
    send_chest_action(sid_b, BS_CHEST_OP_WITHDRAW, x, y, z, 0, 0, 9);
    chest_watch(sid_b, 500, &saw_state, &saw_kick);
    check(!saw_state,
          "the second player asking for the same nine gets NO snapshot — the units are gone and"
          " the store refuses rather than duplicating them");
    check(!saw_kick, "and is not kicked for asking");

    send_chest_action(sid_b, BS_CHEST_OP_DEPOSIT, x, y, z, 5 /* BLOCK_WOOD */, 0, 2);
    check(recv_chest_state(sid_b, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "and the refused player's session still works — a valid action of theirs is answered");

    send_leave(sid_a);
    send_leave(sid_b);
    msleep(50);
    drain();
}

/* v1.9.10 fix (2026-09-07). THE invariant, and the reason this group needed a
 * scenario that asserts a SUM rather than a sequence.
 *
 * Every other scenario in this group checks the chest half of a transfer and
 * nothing else, because before this fix the chest half was the only half the
 * server had: bsgame.c's own comment said "a DEPOSIT does not debit p->inv and
 * a WITHDRAW does not credit it". A suite made entirely of chest-side
 * assertions is green on a server that duplicates every deposited stack and
 * destroys every withdrawn one, because neither of those is visible from the
 * chest side. This scenario is what closes that: it weighs BOTH halves, before
 * and after, and asserts the total did not move.
 *
 * Deliberately asserts nothing about which individual actions were accepted.
 * The mixed run below contains refusals on purpose — an over-ask, a deposit
 * with no room, a deposit of units the bag no longer holds — and pinning which
 * ones are refused would make this scenario go red for reasons that are not
 * conservation, which is the one thing it exists to measure. The accept/refuse
 * rules are pinned by the scenarios above and below it.
 *
 * Driven entirely through the real handle_chest_action() over the real gate
 * socket, never through cheststore.c directly: the bug was in bsgame.c, which
 * a store-level test cannot reach. */
static void test_chest_conservation_invariant(void)
{
    puts("v1.9.10 fix: bag + chest conserves every unit across a mixed run of transfers");
    drain();

    const uint32_t sid = 0xC4E5100Bu;
    const int32_t x = 5011, y = 40, z = 5000;
    chest_join(sid, "chestk");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    drain();

    /* 180 dirt (two full stacks and change) and 40 wood, seated through
     * PICKUP. Two 90s rather than one 180: PICKUP's count is one byte and
     * bs_proto.h caps it at BS_INV_STACK_MAX. */
    chest_give(sid, 2 /* BLOCK_DIRT */, 90);
    chest_give(sid, 2, 90);
    chest_give(sid, 5 /* BLOCK_WOOD */, 40);
    drain();

    uint8_t inv[BS_INV_STATE_BYTES];
    const bool got_start = chest_bag_read(sid, inv);
    check(got_start, "the primed bag reads back as a full INV_STATE");
    if (!got_start) return;

    const uint32_t dirt_start = inv_state_total(inv, 2);
    const uint32_t wood_start = inv_state_total(inv, 5);
    check(dirt_start == 180u && wood_start == 40u,
          "and it holds the 180 dirt and 40 wood that were put in it — the chest is empty, so"
          " those two numbers ARE the world totals this scenario has to conserve");

    /* A mixed run: full stacks, partial merges at the cap, over-asks, a
     * deposit of units the bag has already spent, and withdraws in both the
     * exact and the too-large shape. Ordered so that a server which debits
     * nothing ends up visibly heavier and one which credits nothing ends up
     * visibly lighter. */
    struct { uint8_t op; uint8_t a; uint8_t b; uint8_t count; } run[] = {
        { BS_CHEST_OP_DEPOSIT,  2, 0, 99 },   /* fills chest slot 0            */
        { BS_CHEST_OP_DEPOSIT,  2, 0, 10 },   /* no room: refused              */
        { BS_CHEST_OP_DEPOSIT,  2, 1, 81 },   /* the rest of the dirt          */
        { BS_CHEST_OP_DEPOSIT,  2, 2,  1 },   /* bag has no dirt left          */
        { BS_CHEST_OP_WITHDRAW, 0, 0, 50 },   /* takes half of slot 0          */
        { BS_CHEST_OP_WITHDRAW, 0, 0, 60 },   /* slot 0 holds 49: over-ask     */
        { BS_CHEST_OP_WITHDRAW, 0, 0, 49 },   /* exactly what is there         */
        { BS_CHEST_OP_DEPOSIT,  5, 3, 40 },   /* all the wood                  */
        { BS_CHEST_OP_WITHDRAW, 3, 0, 41 },   /* one more than the slot holds  */
        { BS_CHEST_OP_WITHDRAW, 3, 0, 25 },   /* and then part of it           */
        /* Slot 1 holds 81, so there is room for 18 of these 40. This is the
         * one shape a run of whole-stack transfers never produces, and the
         * one an over-debiting server needs in order to be visible from
         * HERE: debit the bag by what was asked while the chest takes only
         * what fits, and the 22-unit difference is destroyed. Added
         * 2026-09-07 because the over-accept red arm went red only in the
         * scenario below and left this invariant — the primary criterion —
         * green. */
        { BS_CHEST_OP_DEPOSIT,  2, 1, 40 },   /* partial clamp: 18 of 40 fit   */
    };
    for (unsigned i = 0; i < sizeof run / sizeof run[0]; i++) {
        send_chest_action(sid, run[i].op, x, y, z, run[i].a, run[i].b, run[i].count);
        msleep(120);
        drain();
    }

    /* One last accepted transfer, purely to force a fresh CHEST_STATE out of
     * the server: a refused action produces no snapshot, so without this the
     * scenario would have to weigh the chest from a stale one. */
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 4, 20);
    uint8_t st[BS_CHEST_STATE_BYTES];
    const ssize_t ns = recv_chest_state(sid, st, sizeof st, 900);
    check(ns == (ssize_t)BS_CHEST_STATE_BYTES,
          "a final DEPOSIT is answered, so the chest can be weighed from a current snapshot");
    if (ns != (ssize_t)BS_CHEST_STATE_BYTES) return;

    const bool got_end = chest_bag_read(sid, inv);
    check(got_end, "and the bag reads back one last time");
    if (!got_end) return;

    const uint32_t dirt_end = inv_state_total(inv, 2) + chest_state_total(st, 2);
    const uint32_t wood_end = inv_state_total(inv, 5) + chest_state_total(st, 5);

    printf("  ..    dirt: %u before, %u after (bag %u + chest %u)\n",
           dirt_start, dirt_end, inv_state_total(inv, 2), chest_state_total(st, 2));
    printf("  ..    wood: %u before, %u after (bag %u + chest %u)\n",
           wood_start, wood_end, inv_state_total(inv, 5), chest_state_total(st, 5));

    check(dirt_end == dirt_start,
          "CONSERVATION, dirt: bag + chest after the whole run equals bag + chest before it —"
          " a deposit that is not debited duplicates, a withdraw that is not credited destroys,"
          " and this is the only check in the group that can see either");
    check(wood_end == wood_start,
          "CONSERVATION, wood: the same total across an item that went in whole and came back"
          " out in PART — the run leaves 15 wood behind on purpose, because an item that went in"
          " and came all the way back out again nets to zero on the chest side and would balance"
          " even on a server that debited nothing");
}

/* v1.9.10 fix (2026-09-07). The four behaviours the conservation invariant
 * above is the SUM of, asserted one at a time so a failure says which half
 * broke. Conservation catches a server that duplicates or destroys; it cannot
 * distinguish "the debit never happened" from "the credit happened twice",
 * and it cannot see the INV_STATE at all — a server that moved the units
 * correctly and simply never told the actor would balance perfectly and leave
 * every client's bag stale until its next unrelated INV_ACTION. */
static void test_chest_transfer_moves_units_not_copies_them(void)
{
    puts("v1.9.10 fix: a transfer DEBITS the bag, CREDITS it, answers with INV_STATE, and never"
         " moves more than the chest took");
    drain();

    const uint32_t sid = 0xC4E5100Cu;
    const int32_t x = 5012, y = 40, z = 5000;
    chest_join(sid, "chestl");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    chest_give(sid, 2 /* BLOCK_DIRT */, 99);
    chest_give(sid, 2, 30);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    uint8_t inv[BS_INV_STATE_BYTES];
    uint8_t item = 0, count = 0;

    /* ---- DEPOSIT: the chest gains, the bag loses, and the actor is told. */
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 0, 10);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "a DEPOSIT of 10 dirt out of a bag holding 129 is answered with a snapshot");
    chest_state_slot(st, 0, &item, &count);
    check(item == 2 && count == 10, "and the chest slot holds the 10");

    ssize_t ni = recv_inv_state(sid, inv, sizeof inv, 700);
    check(ni == (ssize_t)BS_INV_STATE_BYTES,
          "the SAME action also sends the actor an INV_STATE — without it the client's bag stays"
          " stale and the 10 dirt exist in both places on screen");
    if (ni == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_total(inv, 2) == 119u,
              "and the bag is down to 119 — the deposit DEBITED it, it did not copy the units");
    }

    /* ---- WITHDRAW: the bag gains exactly what the chest lost. */
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 0, 0, 4);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "a WITHDRAW of 4 is answered with a snapshot");
    chest_state_slot(st, 0, &item, &count);
    check(item == 2 && count == 6, "leaving 6 in the chest slot");
    ni = recv_inv_state(sid, inv, sizeof inv, 700);
    check(ni == (ssize_t)BS_INV_STATE_BYTES, "and with an INV_STATE too");
    if (ni == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_total(inv, 2) == 123u,
              "with the bag back up to 123 — the withdraw CREDITED it, the units were not"
              " destroyed on the way out");
    }

    /* ---- The over-accept case. bsgame.c clamps a deposit to the slot's
     * remaining room, so a client that debited the full `count` would lose
     * the difference. The bag must end up holding exactly what the chest
     * refused. */
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 1, 95);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "priming chest slot 1 to 95");
    (void)recv_inv_state(sid, inv, sizeof inv, 700);

    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 1, 10);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "asking that slot for 10 more is accepted");
    chest_state_slot(st, 1, &item, &count);
    check(item == 2 && count == (uint8_t)BS_INV_STACK_MAX, "and it goes to 99, taking only 4");
    ni = recv_inv_state(sid, inv, sizeof inv, 700);
    check(ni == (ssize_t)BS_INV_STATE_BYTES, "with the matching INV_STATE");
    if (ni == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_total(inv, 2) == 24u,
              "and the bag went 28 -> 24, debited by the 4 that MOVED and not by the 10 that were"
              " asked for — the actor holds exactly what the server did not accept");
    }

    /* ---- The source shortfall: more than the bag holds is refused whole. */
    bool saw_state = false, saw_kick = false;
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 2, 25);
    chest_watch(sid, 400, &saw_state, &saw_kick);
    check(!saw_state,
          "a DEPOSIT of 25 out of a bag holding 24 produces no snapshot — bs_proto.h refuses"
          " \"more units than the source holds\", and the bag is a source like any other");
    check(!saw_kick, "and does not kick");
    if (chest_bag_read(sid, inv)) {
        check(inv_state_total(inv, 2) == 24u, "and the refusal moved nothing: still 24 in the bag");
    } else {
        check(false, "the bag could be read back after the refusal");
    }
}

/* v1.9.10 fix (2026-09-07). The second, coupled fault: before this change
 * broadcast_chest_state() had exactly one caller, so a chest's contents only
 * ever reached a client that happened to be connected when somebody moved a
 * stack. A player who joined later opened a full chest, saw eight empty slots,
 * could take nothing out of it — and could BREAK it, paying themselves from
 * their own empty local record while the server deleted the real contents.
 *
 * The check that matters is the last one: the joiner can actually WITHDRAW
 * what the snapshot showed. A snapshot the client stores but cannot act on
 * would satisfy a weaker test and still lose the chest. */
static void test_chest_contents_reach_a_player_who_joins_later(void)
{
    puts("v1.9.10 fix: a player who joins after a chest is filled gets its contents on CHUNK_SUB");
    drain();

    const uint32_t sid_a = 0xC4E5100Du, sid_b = 0xC4E5100Eu;
    /* A column of its own, well clear of every other chest scenario's:
     * 5120 >> BS_CHUNK_DIM_SHIFT is column 320, and the rest of this group
     * lives around columns 312-313. */
    const int32_t x = 5120, y = 40, z = 5120;
    const int32_t cx = 320, cz = 320;

    chest_join(sid_a, "chestm");
    chest_place_block(sid_a, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    chest_give(sid_a, 2 /* BLOCK_DIRT */, 40);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid_a, BS_CHEST_OP_DEPOSIT, x, y, z, 2, 5, 40);
    check(recv_chest_state(sid_a, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "the first player fills chest slot 5 with 40 dirt");
    drain();

    /* B was not connected for that broadcast, and the server does not resend
     * a snapshot until the next mutation. */
    chest_join(sid_b, "chestn");
    drain();

    /* A column with nothing in it first, so the delivery is provably SCOPED
     * and not a full dump that happens to include the right chest. */
    bool saw_state = false, saw_kick = false;
    send_chunk_sub(sid_b, 400, 400);
    chest_watch(sid_b, 400, &saw_state, &saw_kick);
    check(!saw_state,
          "subscribing to an empty column sends no chest snapshots at all — the contents ride the"
          " column, they are not dumped at whoever asks for anything");
    check(!saw_kick, "and a CHUNK_SUB for an empty column is not a kick");

    /* Now the column the chest is actually in. */
    send_chunk_sub(sid_b, cx, cz);
    const ssize_t n = recv_chest_state(sid_b, st, sizeof st, 900);
    check(n == (ssize_t)BS_CHEST_STATE_BYTES,
          "subscribing to the chest's column DOES deliver a snapshot — a joiner used to see eight"
          " empty slots and break the chest believing it empty");
    if (n == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t it = 0, ct = 0;
        chest_state_slot(st, 5, &it, &ct);
        check(chest_state_at(st, x, y, z),
              "the snapshot names the chest's own position, not the column's");
        check(it == 2 && ct == 40,
              "and carries the 40 dirt the other player put there before this one existed");
    }

    /* The payoff, and the check that a merely-stored snapshot cannot pass:
     * the joiner can take the units out. */
    send_chest_action(sid_b, BS_CHEST_OP_WITHDRAW, x, y, z, 5, 0, 40);
    const ssize_t nw = recv_chest_state(sid_b, st, sizeof st, 900);
    check(nw == (ssize_t)BS_CHEST_STATE_BYTES,
          "and the joiner can withdraw from a chest they never saw being filled");
    uint8_t inv[BS_INV_STATE_BYTES];
    if (recv_inv_state(sid_b, inv, sizeof inv, 900) == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_total(inv, 2) == 40u,
              "with all 40 dirt landing in a bag that started empty");
    } else {
        check(false, "the joiner's withdraw is answered with an INV_STATE");
    }

    send_leave(sid_a);
    send_leave(sid_b);
    msleep(50);
    drain();
}

/* v1.9.10 fix (2026-09-07). THE HEADLINE BUG, from the ledger side.
 *
 * Breaking a chest used to run cheststoreRemove() and put a BLOCK_EDIT on the
 * wire and nothing else. Measured with an adversary receiver bound to the real
 * bsgame.c: 0 CHEST_STATE, 0 INV_STATE, 1 BLOCK_EDIT — 94 units left the
 * authoritative store with nothing on the wire to account for them. The client
 * appeared to pay itself out of its own local record, and the very next
 * INV_ACTION (handle_inv_action answers every one of them with an
 * unconditional INV_STATE built from p->inv) overwrote the bag with a server
 * inventory that had never been credited, so the items vanished on the next
 * hotbar tap.
 *
 * What this asserts is a SUM, for test_chest_conservation_invariant()'s reason:
 * bag + chest weighed before the break and after it, per item id. A scenario
 * that only checked "an INV_STATE arrived" would stay green on a server that
 * credited the wrong number, and one that only checked the chest side cannot
 * see this bug at all — the chest side is correct either way, the record is
 * gone in both.
 *
 * Two item ids in two different chest slots on purpose: the payout walks all
 * BS_CHEST_SLOTS, and a loop that credited only the first non-empty slot would
 * balance for a one-item chest. */
static void test_chest_break_pays_the_breaker(void)
{
    puts("v1.9.10 fix: breaking a chest CREDITS the breaker's bag — bag + chest conserves");
    drain();

    const uint32_t sid = 0xC4E5100Fu;
    const int32_t x = 5013, y = 40, z = 5000;
    chest_join(sid, "chesto");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    chest_give(sid, 2 /* BLOCK_DIRT */, 40);
    chest_give(sid, 5 /* BLOCK_WOOD */, 12);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 2 /* BLOCK_DIRT */, 0, 30);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "thirty dirt go into chest slot 0");
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 5 /* BLOCK_WOOD */, 3, 12);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "and twelve wood into chest slot 3 — two item ids in two slots, so a payout that walks"
          " only the first non-empty slot cannot balance");
    drain();

    /* The weigh-in. Both halves, before anything is broken. */
    uint8_t bag[BS_INV_STATE_BYTES];
    uint32_t bag_dirt = 0, bag_wood = 0;
    if (chest_bag_read(sid, bag)) {
        bag_dirt = inv_state_total(bag, 2);
        bag_wood = inv_state_total(bag, 5);
        check(bag_dirt == 10 && bag_wood == 0,
              "the bag holds the ten dirt the deposit left behind and no wood at all");
    } else {
        check(false, "the bag can be weighed before the break");
    }
    const uint32_t chest_dirt = 30, chest_wood = 12;
    drain();

    /* The break. Stone over the chest: the block changes, so the record goes. */
    send_block_edit(sid, x, y, z, 3 /* BLOCK_STONE */);

    const ssize_t n = recv_inv_state(sid, bag, sizeof bag, 900);
    check(n == (ssize_t)BS_INV_STATE_BYTES,
          "the breaker is sent an INV_STATE — before this fix the break put ONE BLOCK_EDIT on the"
          " wire and nothing else, and the contents left the store unaccounted for");
    if (n == (ssize_t)BS_INV_STATE_BYTES) {
        check(inv_state_total(bag, 2) == bag_dirt + chest_dirt,
              "and it carries the credited dirt: bag + chest before == bag after");
        check(inv_state_total(bag, 5) == bag_wood + chest_wood,
              "and the credited wood too — the second slot was paid out, not just the first");
    }

    /* Read the bag back independently of the reply, so the conservation claim
     * does not rest on the same packet the credit claim does: a server that
     * sent a correct-looking INV_STATE without committing p->inv would be
     * green above and red here, which is exactly the shape of the original bug
     * seen from the client (the next INV_ACTION overwrote the bag). */
    if (chest_bag_read(sid, bag)) {
        check(inv_state_total(bag, 2) == bag_dirt + chest_dirt
              && inv_state_total(bag, 5) == bag_wood + chest_wood,
              "and a FRESH read of the bag — a separate INV_ACTION, the very thing that used to"
              " make the items vanish — still shows the credit, so p->inv really was committed");
    } else {
        check(false, "the bag can be weighed after the break");
    }

    /* The record went with the block: put a chest back and it comes up empty.
     * Without this the payout would be a duplication bug instead of a
     * destruction one. */
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    drain();
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 0, 0, 1);
    bool saw_state = false, saw_kick = false;
    chest_watch(sid, 500, &saw_state, &saw_kick);
    check(!saw_state,
          "a chest re-placed on the same cell is EMPTY — the units were paid out once, they did"
          " not also stay in a record that outlived the block");
    check(!saw_kick, "and asking is not a kick");

    send_leave(sid);
    msleep(50);
    drain();
}

/* v1.9.10 fix (2026-09-07). The other half of the payout, and the one that
 * decides what "conserves" means when the bag has no room.
 *
 * There are exactly three things a server can do with a chest full of units
 * the breaker cannot carry: destroy the remainder (the bug, in a new costume),
 * drop it into the world (impossible — this process has no entity system, see
 * bsgame.c's header comment), or refuse the break. It refuses, and refusing is
 * only worth anything if it is COMPLETE: the block must not change, the record
 * must survive with its contents, and the player must be able to empty their
 * bag and try again. This scenario measures all three, in that order.
 *
 * The ordering trap lives here. diffstoreApply() commits the edit before the
 * old orphan-drop line ran, so a refusal decided after the commit would leave
 * a world that had changed and a chest record that had not. `observer` is what
 * catches that: a second, legacy player (never sends CHUNK_SUB, so
 * broadcast_block_edit() reaches it unscoped) watching the cell for a
 * BLOCK_EDIT that must never arrive. */
static void test_chest_break_into_a_full_bag_is_refused(void)
{
    puts("v1.9.10 fix: a break that cannot be paid for is REFUSED whole — block, record and bag"
         " all unchanged");
    drain();

    const uint32_t sid = 0xC4E51010u, observer = 0xC4E51011u;
    const int32_t x = 5014, y = 40, z = 5000;
    chest_join(sid, "chestp");
    chest_join(observer, "chestq");
    chest_place_block(sid, x, y, z, (uint8_t)BSGAME_TEST_BLOCK_CHEST);
    chest_give(sid, 5 /* BLOCK_WOOD */, 20);
    drain();

    uint8_t st[BS_CHEST_STATE_BYTES];
    send_chest_action(sid, BS_CHEST_OP_DEPOSIT, x, y, z, 5 /* BLOCK_WOOD */, 0, 20);
    check(recv_chest_state(sid, st, sizeof st, 700) == (ssize_t)BS_CHEST_STATE_BYTES,
          "twenty wood go into the chest, leaving the depositor's bag empty");
    drain();

    /* Every slot, at the cap, all one item: inventoryAdd() has nothing to
     * merge into and nothing to spill into, so it refuses outright. */
    const uint32_t filled = chest_fill_bag(sid, 2 /* BLOCK_DIRT */);
    uint8_t bag[BS_INV_STATE_BYTES];
    if (chest_bag_read(sid, bag)) {
        check(inv_state_total(bag, 2) == filled,
              "and the breaker's bag is then filled to its very last slot — every slot at the"
              " stack cap, so nothing more can fit in it at all");
    } else {
        check(false, "the filled bag can be weighed");
    }
    drain();

    /* The break that cannot be paid for. */
    send_block_edit(sid, x, y, z, 3 /* BLOCK_STONE */);
    check(!chest_saw_block_edit(observer, x, y, z, 500),
          "NO BLOCK_EDIT reaches the other player — the world did not change, so the refusal was"
          " decided BEFORE the diff store was committed, not after it");
    check(recv_inv_state(sid, bag, sizeof bag, 300) != (ssize_t)BS_INV_STATE_BYTES,
          "and the breaker is credited nothing — a refused break sends no INV_STATE");
    drain();

    if (chest_bag_read(sid, bag)) {
        check(inv_state_total(bag, 2) == filled && inv_state_total(bag, 5) == 0,
              "the bag is byte-for-byte what it was: still full of dirt, still holding no wood —"
              " no partial payout was smuggled in");
    } else {
        check(false, "the bag can be weighed after the refusal");
    }

    /* "Empty your bag and try again" is the whole promise of a refusal, so it
     * is asserted rather than assumed. */
    chest_empty_bag(sid, 2 /* BLOCK_DIRT */);
    if (chest_bag_read(sid, bag)) {
        check(inv_state_total(bag, 2) == 0, "the player empties the bag");
    } else {
        check(false, "the emptied bag can be weighed");
    }
    drain();

    /* THE RECORD SURVIVED, AND THE BLOCK IS STILL A CHEST. One packet proves
     * both: chest_action_apply() refuses a CHEST_ACTION unless the diff store
     * says BLOCK_CHEST stands at the cell, and a WITHDRAW can only answer with
     * a snapshot if the record is still there holding the units. */
    send_chest_action(sid, BS_CHEST_OP_WITHDRAW, x, y, z, 0, 0, 1);
    const ssize_t nw = recv_chest_state(sid, st, sizeof st, 900);
    check(nw == (ssize_t)BS_CHEST_STATE_BYTES,
          "a WITHDRAW at the cell is still answered — the block is STILL A CHEST and the record"
          " survived the refused break");
    if (nw == (ssize_t)BS_CHEST_STATE_BYTES) {
        uint8_t item = 0, count = 0;
        chest_state_slot(st, 0, &item, &count);
        check(item == 5 && count == 19,
              "with all twenty wood still in it before that withdraw — the contents were intact,"
              " not silently trimmed to what would have fitted");
    }
    drain();

    /* And now the break goes through, paying out the nineteen that are left. */
    send_block_edit(sid, x, y, z, 3 /* BLOCK_STONE */);
    check(chest_saw_block_edit(observer, x, y, z, 700),
          "breaking it again with room in the bag DOES change the world this time");
    if (chest_bag_read(sid, bag)) {
        check(inv_state_total(bag, 5) == 20u,
              "and the player ends up holding all twenty wood: 1 withdrawn + 19 paid out by the"
              " break — nothing was destroyed by the refusal that came before it");
    } else {
        check(false, "the bag can be weighed after the retried break");
    }

    send_leave(sid);
    send_leave(observer);
    msleep(50);
    drain();
}

/* v1.9.10 (2026-09-07), the crash-durability fix, SOURCE-TEXT half.
 *
 * handle_block_edit() force-flushes chests.bin in the same step as the chest
 * break (bsgame.c, inside `if (has_record)`). MEASURED window it closes: prime
 * a chest, SIGKILL inside BS_CHEST_FLUSH_MS, and inventory.dat already holds
 * the credited units while chests.bin still holds the removed record's old
 * ones — the two stores disagreeing on disk.
 *
 * Why this is a source-text check and not a behavioural one. A behavioural
 * check was written first — read chests.bin off disk right after the break —
 * and thrown out, because it could not go red. This suite runs ONE shared
 * daemon (main(), g_daemon) through every chest scenario above; by the time a
 * break happens, tick()'s own debounced cheststoreFlush(force=false) (every
 * TICK_HZ=20 tick, 50ms) already has a stale last_flush_ms from that traffic
 * and flushes on the very next tick regardless of the fix. Proving the forced
 * flush behaviourally needs a real kill and restart, which a shared-process
 * suite cannot do without ending the run; scratchpad/m1910/srvmeasure.c is
 * that instrument and stays the only one that can catch the actual window.
 * What is left to guard in-repo is that the CALL is still there, so this pins
 * the source text — the technique ../../source/net/networld_test.c already
 * uses on source/main.c's edit hooks.
 *
 * Scoped, not grepped. bsgame.c calls cheststoreFlush() in three places —
 * here, in tick(), and at shutdown — so a file-wide search for the name passes
 * with the fix deleted, i.e. proves nothing. Everything below runs against the
 * `if (has_record)` block's body alone, and the extraction has its own checks:
 * a locator that finds nothing FAILS rather than quietly searching an empty
 * string and reporting no violation. */
static char *read_whole_source_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    const long n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = (char *)malloc((size_t)n + 1);
    if (buf == NULL) { fclose(f); return NULL; }
    const size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    return buf;
}

/* The `}` matching the `{` at `open`, or NULL if the text runs out first. Plain
 * brace counting, which is sound on the one region it is used on below: the
 * `if (has_record)` block's body is ten lines of comment-free code whose only
 * braces are real ones (its format strings carry "(%d,%d,%d)", no braces). A
 * miscount surfaces as NULL — a FAILING check — never as a silently over-wide
 * body that would make the scoping vacuous. */
static const char *matching_brace(const char *open)
{
    int depth = 0;
    for (const char *c = open; *c != '\0'; c++) {
        if (*c == '{') {
            depth++;
        } else if (*c == '}') {
            depth--;
            if (depth == 0) return c;
        }
    }
    return NULL;
}

static void test_chest_break_forces_a_chest_store_flush(void)
{
    puts("handle_block_edit() force-flushes chests.bin in the same step as the chest break");

    /* `make test` (game/Makefile) runs ./bsgame_test with game/ as the working
     * directory, and this suite never chdir()s — VERIFIED by running it, not
     * assumed. The path is named in the check text so a failure says which one
     * was tried rather than only that a file was missing. */
    static const char *const SRC_PATH = "bsgame.c";
    char what[192];

    char *src = read_whole_source_file(SRC_PATH);
    snprintf(what, sizeof what,
             "the daemon's source could be read (tried \"%s\", relative to the suite's working"
             " directory)", SRC_PATH);
    check(src != NULL, what);
    if (src == NULL) return;

    /* Control for the whole technique: the OTHER cheststoreFlush() calls are
     * still in this file. That is precisely why the search below is scoped —
     * with these present, a file-wide search for the name stays green even with
     * the forced flush deleted. If this ever fails, the scoping has stopped
     * being the thing that makes the assertions meaningful. */
    check(strstr(src, "cheststoreFlush(&g->chests, now, false)") != NULL,
          "control: tick()'s DEBOUNCED cheststoreFlush() is still elsewhere in this file, so a"
          " file-wide search for the name would pass even with the forced flush deleted");

    const char *fn = strstr(src, "static void handle_block_edit(");
    check(fn != NULL, "handle_block_edit() was located in the daemon's source");
    if (fn == NULL) {
        free(src);
        return;
    }

    /* Function bounds first, so the block search cannot wander into a later
     * function if handle_block_edit() ever loses its own. Line-initial closing
     * brace, the idiom networld_test.c uses: every top-level function here ends
     * at column 0 and nothing inside this one starts a line with `}`. */
    const char *fn_end = strstr(fn, "\n}");
    check(fn_end != NULL, "handle_block_edit()'s body is delimited");
    if (fn_end == NULL) {
        free(src);
        return;
    }

    const char *blk = strstr(fn, "if (has_record) {");
    check(blk != NULL && blk < fn_end,
          "the `if (has_record)` chest-break block was located inside handle_block_edit()");
    if (blk == NULL || blk >= fn_end) {
        free(src);
        return;
    }

    const char *open  = strchr(blk, '{');
    const char *close = (open != NULL) ? matching_brace(open) : NULL;
    check(close != NULL, "the `if (has_record)` block's body is delimited by a matching brace");
    if (close == NULL) {
        free(src);
        return;
    }

    const size_t body_len = (size_t)(close - blk) + 1u;
    char *body = (char *)malloc(body_len + 1u);
    check(body != NULL, "the block's body could be copied out for searching");
    if (body == NULL) {
        free(src);
        return;
    }
    memcpy(body, blk, body_len);
    body[body_len] = '\0';

    /* ---- the extraction is real, and it is NARROW -------------------------
     *
     * These four are what stop the assertions below from being a file-wide
     * grep wearing a scope's clothes. They go red if the delimiter ever
     * over-runs, which is the failure mode that would make everything after
     * them pass for the wrong reason. */
    check(body_len > 0u && body_len < 1024u,
          "the extracted body is block-sized, not file-sized — the scope really is a scope");
    check(strstr(body, "cheststoreRemove(&g->chests, x, y, z)") != NULL,
          "control: the removal this block exists to perform is inside the extracted body, so the"
          " search shape does find hits in it");
    check(strstr(body, "broadcast_block_edit") == NULL,
          "and the body stops at the block: broadcast_block_edit(), the next statement AFTER it,"
          " is outside what was extracted");
    check(strstr(body, "cheststoreFlush(&g->chests, now, false)") == NULL,
          "and it did not swallow tick()'s debounced flush either");

    /* ---- the assertion ---------------------------------------------------- */
    const char *remove_at = strstr(body, "cheststoreRemove(");
    const char *flush_at  = strstr(body, "cheststoreFlush(");

    check(flush_at != NULL,
          "a cheststoreFlush() call stands INSIDE the `if (has_record)` block — the chest break"
          " writes chests.bin in the same step it removes the record");
    check(strstr(body, "cheststoreFlush(&g->chests, now, true)") != NULL,
          "and it is the FORCED form (force=true) — a debounced call here would leave the"
          " measured crash window open");
    check(remove_at != NULL && flush_at != NULL && flush_at > remove_at,
          "and the flush comes AFTER the removal, so what reaches the disk is the store with the"
          " record already gone");

    free(body);
    free(src);
}

/* v1.9.10 (2026-09-06). The chest group's own check count, pinned as a
 * LITERAL the way the client tree's *_EXPECTED_CHECKS constants are (see
 * tests/food_placeable_invariant_test.c, which writes the idiom out: "a
 * literal, never computed from a production constant"). Without it, deleting
 * a check inside this group shrinks the run silently and every remaining
 * check still passes.
 *
 * Scoped to this group's DELTA rather than to g_checks as a whole, and that
 * is deliberate: this suite has never carried a whole-file pin, and adding
 * one would go red every time anyone added a check anywhere else in the file
 * — a pin that cries wolf gets raised instead of read.
 *
 * MEASURED, not summed: this is the number the run below actually printed
 * for `g_checks - chest_checks_before`, read off a green run on 2026-09-06,
 * not a total arrived at by counting check() calls in the source.
 *
 * 2026-09-07, the conservation fix: 184 -> 214. Three scenarios were added
 * (test_chest_conservation_invariant, the transfer-debits-and-credits one and
 * the joiner-gets-the-contents one) and no check was removed. Read off this
 * run's own "chest group ran N checks" line, again, never summed.
 *
 * 2026-09-07, the break-payout fix: 214 -> 233. Two scenarios were added
 * (test_chest_break_pays_the_breaker and
 * test_chest_break_into_a_full_bag_is_refused) and no check was removed. Read
 * off the "chest group ran 233 checks (pin is 214)" line that run printed
 * while the pin was still at the old number — not summed from the source.
 *
 * 2026-09-07, the crash-durability fix (forced cheststoreFlush() at the
 * chest-break site in handle_block_edit()): no check added here. A disk-read
 * check was tried (chest_bin_has_record() right after the break) and thrown
 * out — red-armed by reverting the forced flush, it stayed GREEN, because
 * this suite runs one shared daemon (main(), g_daemon) through many earlier
 * chest scenarios first, each marking the store dirty; by the time this
 * scenario runs, tick()'s own debounced cheststoreFlush(force=false) (called
 * every TICK_HZ=20 tick, 50ms) already has a stale last_flush_ms from that
 * earlier traffic, so the very next tick flushes anyway regardless of the
 * fix. A check that cannot go red proves nothing, so it was removed rather
 * than kept for show. The real regression coverage for this fix is
 * scratchpad/m1910/srvmeasure.c, which SIGKILLs the daemon inside the
 * debounce window and reads chests.bin/inventory.dat back after a restart —
 * that needs a real kill and restart this shared-process suite cannot do
 * without ending the whole run, so it stays the only instrument that can
 * catch the actual crash window.
 *
 * 2026-09-07, the crash-durability fix, source-text half: 233 -> 247. The
 * paragraph above still describes the DISK-READ attempt correctly and it is
 * still gone. What replaced it is a source-text scenario,
 * test_chest_break_forces_a_chest_store_flush(), which pins the forced
 * cheststoreFlush() call inside handle_block_edit()'s `if (has_record)` block
 * — see its own header for why the scoping is what makes it non-tautological.
 * Unlike the disk-read attempt it DOES go red: verified twice, once with the
 * flush statement deleted outright and once with it merely moved out of the
 * block to just before broadcast_block_edit(). Read off the "chest group ran
 * 247 checks (pin is 233)" line that run printed while the pin was still at
 * the old number — not summed from the source. */
#define BSGAME_TEST_CHEST_CHECKS 247

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
    test_world_gen_is_resent_after_join();
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
    test_inv_pickup_undefined_core_id_refused();
    test_inv_pickup_past_old_wire_ceiling_now_credited();
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

    /* v1.8.3 Phase 4. Placed here, above the registry scenarios, because it
     * restarts the daemon three times and leaves the declaration back at
     * BSGAME_TEST_WORLD_GEN — and the registry joins below then re-prove that
     * restore for free through recv_world_gen(). Running it after them would
     * leave nothing to check the restore with. */
    test_world_gen_persists_across_restart();

    /* Immediately behind it, and the order is load-bearing in both directions:
     * it needs the stored 5 and the edits that scenario runs on top of, and it
     * leaves the same 5 behind for the registry joins to re-prove. */
    test_world_gen_refuses_to_strand_edits();

    /* Registry sync runs last: its batching scenario rewrites registry.bin
     * and restarts the daemon, which would change what any later join's
     * REGISTRY_INFO advertises. */
    test_registry_fetch_empty_reply();
    test_registry_fetch_batches_over_36_defs();

    /* v1.9.8, day/night clock: last of all. test_day_time_persists_across_restart
     * restarts the shared --state-dir one more time, which would upset any
     * later scenario that cares what a fresh join's REGISTRY_INFO or
     * world_gen declares — nothing after this point does. */
    test_time_sync_on_join_and_periodic();
    test_day_time_persists_across_restart();

    /* v1.9.10, chests: after the day/night restart, for the same reason that
     * scenario gives — these place blocks and join players, and nothing above
     * should have to work around a world they have edited. The in-process
     * half needs no daemon at all but is run here so the whole group's check
     * count is one contiguous span. */
    const int chest_checks_before = g_checks;
    test_chest_action_decode();
    test_chest_state_encode();
    test_cheststore_deposit_rules();
    test_cheststore_withdraw_rules();
    test_cheststore_remove_and_capacity();
    test_cheststore_disk_round_trip();
    test_chest_deposit_broadcasts_a_snapshot();
    test_chest_deposit_partial_merge_at_the_cap();
    test_chest_deposit_refusals_are_silent();
    test_chest_withdraw();
    test_chest_action_count_validation();
    test_chest_action_malformed_is_not_a_kick();
    test_chest_position_gating();
    test_chest_orphan_record_dropped_on_block_edit();
    test_chest_two_players_cannot_take_the_same_stack();
    test_chest_conservation_invariant();
    test_chest_transfer_moves_units_not_copies_them();
    test_chest_contents_reach_a_player_who_joins_later();
    test_chest_break_pays_the_breaker();
    test_chest_break_into_a_full_bag_is_refused();
    test_chest_break_forces_a_chest_store_flush();
    const int chest_checks = g_checks - chest_checks_before;
    printf("  ..    chest group ran %d checks (pin is %d)\n", chest_checks, BSGAME_TEST_CHEST_CHECKS);
    check(chest_checks == BSGAME_TEST_CHEST_CHECKS,
          "the chest group ran the number of checks it is pinned at — a deleted check shrinks the"
          " run silently otherwise, and every survivor still passes");

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
