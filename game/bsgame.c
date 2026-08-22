/* bsgame — Blocksmith authoritative game-logic process.
 *
 * Everything that knows what a block, a player or an edit *means* lives
 * here. bsgate (server/gateway/bsgate.c) terminates the encrypted link from
 * a 3DS, authenticates the session, and forwards already-plaintext
 * application bytes to this process over a local Unix datagram socket —
 * see the BS_GAME_* framing below, which mirrors bsgate.c:293-298 and
 * server/README.md's "Game-logic interface" table exactly.
 *
 * This process touches no network socket other than that one Unix socket,
 * and contains no crypto: bsgate already decided who is allowed to be here.
 * What it must not do is trust *what* an authenticated session sends — a
 * compromised or buggy client is explicitly in scope, so every byte from
 * the gate is validated the same way an internet-facing process would.
 *
 * World model: terrain is deterministic (BS_WORLD_SEED, source/main.c), so
 * every client generates identical ground locally and this process only
 * ever ships the *diffs* players have made — see diffstore.h.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>   /* umask, around the socket bind below */
#include <sys/un.h>

#include "../proto/bs_proto.h"
#include "diffstore.h"
#include "playerstate.h"
#include "players.h"
#include "validate.h"
#include "world/registry.h"

/* Vendored, byte-identical copies of the client's own <3ds.h>-free
 * inventory/crafting logic — see game/world/'s vendoring note in
 * game/Makefile and players.h. Unlike world/block.h and world/world.h (which
 * validate.c reaches conditionally, via -I$(WORLD), only when the client tree
 * sits beside this repo — see validate.c), these are always present in this
 * repo and included unconditionally: bsgame runs inventoryMoveUnits,
 * craftMake and friends as part of its own authoritative game state, not as
 * a build-time drift check, so they cannot be optional the way a
 * compile-time assert is. */
#include "world/crafting.h"
#include "world/inventory.h"

/* Gate<->game framing. Not shared via a header because it is not part of
 * the wire protocol proper (see bs_proto.h's own header comment) — it is a
 * local IPC convention between two processes on the same box. Duplicated
 * here exactly as server/gateway/bsgate_test.c already duplicates it rather
 * than including gateway-private code from server/game. Canonical values:
 * server/gateway/bsgate.c:293-298. */
enum bs_game_msg {
    BS_GAME_JOIN  = 1,   /* gate -> game: sid(4) + pubkey(32) + label(32) */
    BS_GAME_DATA  = 2,   /* both ways:    sid(4) + payload                */
    BS_GAME_LEAVE = 3,   /* gate -> game: sid(4)                          */
    BS_GAME_KICK  = 4    /* game -> gate: sid(4)                         */
};

#define BS_GAME_ENVELOPE_BYTES 5u   /* 1 kind + 4 sid, both directions */
#define BS_JOIN_BODY_BYTES     64u  /* 32 pubkey + 32 label, per bsgate.c */

/* Largest datagram either direction ever sends or receives on the game
 * socket: the envelope plus the largest application payload. */
#define BS_GAME_MAX_DGRAM (BS_GAME_ENVELOPE_BYTES + BS_MAX_PAYLOAD)

/* Tick rate: 10 Hz (100 ms). This is a block-placement game for 2-6 people
 * on 3DS Wi-Fi, not a shooter — nothing here needs sub-100ms precision, and
 * every extra tick is bandwidth spent on stale-tolerant position data
 * across up to BS_GAME_MAX_PLAYERS clients. 10 Hz is the same order as the
 * position-update rate most block-building games use and comfortably below
 * anything that would stress an Old 3DS's Wi-Fi stack or this process's
 * single poll() loop; the poll timeout below is what actually paces it, so
 * a quiet server spends the time between ticks blocked, not spinning. */
#define BS_GAME_TICK_MS 100u

/* V127-A: how long bsgame waits, after JOIN, for a player's first CHUNK_SUB
 * before deciding they are running a pre-V127-A client and falling back to
 * the old full-dump WORLD_SYNC (see tick() and send_world_sync()). A modern
 * client already knows where it is the instant it applies WORLD_INFO's seed
 * and generates terrain locally, so its first CHUNK_SUB is one local
 * computation plus a single network hop away — a few hundred ms is
 * generous, not tight, even over 3DS Wi-Fi. A client too old to have any
 * CHUNK_SUB code at all will obviously never send one, so this window only
 * ever costs such a client that same short, one-time delay before it
 * receives exactly what it always did. There is no capability bit in JOIN
 * to tell old and new clients apart up front (the wire format is fixed —
 * see bs_proto.h's header comment — and JOIN's body is just pubkey+label),
 * so this grace window is a heuristic, not a protocol-level guarantee: a
 * pathological modern client that delays its first CHUNK_SUB past this
 * window would receive one redundant full WORLD_SYNC before scoping takes
 * over. That is wasted bandwidth, never a correctness problem — every
 * later edit is still scoped correctly once chunk_sub_seen is set (see
 * broadcast_block_edit()). */
#define BS_CHUNK_LEGACY_GRACE_MS 500u

static volatile sig_atomic_t g_quit = 0;
static void on_sigterm(int s) { (void)s; g_quit = 1; }

/* Set by SIGUSR1, consumed by the main loop, which calls write_status() —
 * see that function's header comment for why a signal-triggered snapshot
 * file is used instead of a query socket. Mirrors gateway/bsgate.c's own
 * g_status/on_sigusr1. */
static volatile sig_atomic_t g_status = 0;
static void on_sigusr1(int s) { (void)s; g_status = 1; }

struct bs_game {
    int  unix_fd;
    char game_sock_path[108];
    char gate_sock_path[108];

    /* Where write_status() drops its snapshot, written only on SIGUSR1 — see
     * write_status(). Not a unix socket path, so unlike the two above it is
     * not bound by sun_path's 108-byte cap. */
    char     status_path[512];
    uint64_t started_ms;

    /* The --state-dir argument itself, kept verbatim (world_seed_load and
     * diffstoreOpen below are handed it directly as a local and never store
     * it). player_inv_dir() needs it at arbitrary points after startup — on
     * every JOIN and after every inventory-changing message — not just once
     * during setup, so unlike status_path it is kept as the raw directory
     * rather than a single derived file path. */
    char state_dir[456];

    /* Lifetime counters, for the status snapshot only — reading them here
     * changes no behaviour. Incremented at the existing accept/reject sites
     * in handle_block_edit() and handle_join(). */
    uint64_t joins_total;
    uint64_t edits_accepted;
    uint64_t edits_rejected_range;
    uint64_t edits_rejected_rate;
    uint64_t edits_rejected_full;

    /* The terrain seed this server's world generates from, sent to every
     * client at JOIN as BS_APP_WORLD_INFO. Persisted in --state-dir next to
     * block_diffs.bin, because the diffs are coordinates into the terrain this
     * seed produces: change the seed and every stored edit lands somewhere
     * meaningless. Loaded or minted once at startup, never changed while
     * running. */
    uint32_t world_seed;

    BsPlayers   players;
    BsDiffStore diffs;
};

/* ------------------------------------------------------------------- util */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

__attribute__((format(printf, 1, 2)))
static void logf_(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

/* Same truncation-is-an-error stance as bsgate.c's path_set(): a state
 * directory or socket path that got silently cut off would bind or send to
 * the wrong place, which looks like a network problem, not a config one. */
__attribute__((format(printf, 3, 4)))
static bool path_set(char *dst, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return n >= 0 && (size_t)n < cap;
}

/* ---------------------------------------------------------- world seed */

/* Loads --state-dir/world_seed.txt, or mints and writes one on first run.
 * `forced` is a --world-seed argument (NULL when not given), which overwrites
 * whatever is stored: changing a live world's seed strands every diff already
 * in block_diffs.bin, so it is deliberately an explicit operator act and never
 * something that happens by itself.
 *
 * Plain decimal text rather than four raw bytes so an operator can read it with
 * cat and set it with echo — this is the one number that decides what the whole
 * world looks like, and needing a hex editor to see it would be hostile.
 *
 * Returns false only on an I/O error the operator needs to know about; a
 * missing file is the ordinary first-run path, not a failure. */
static bool world_seed_load(const char *state_dir, const char *forced,
                            uint32_t *out, char *err, size_t errcap)
{
    char path[512];
    if (!path_set(path, sizeof path, "%s/world_seed.txt", state_dir)) {
        snprintf(err, errcap, "--state-dir is too long for the world seed path");
        return false;
    }

    if (forced == NULL) {
        FILE *f = fopen(path, "r");
        if (f != NULL) {
            unsigned long long v = 0;
            int got = fscanf(f, "%llu", &v);
            fclose(f);
            if (got == 1) {
                *out = (uint32_t)v;
                logf_("game: world seed %u (from %s)", *out, path);
                return true;
            }
            /* These messages name the file, not the full path: the caller's
             * error buffer is 256 bytes and `path` alone can be 512, which the
             * compiler is right to refuse to let us truncate silently. The
             * directory is the operator's own --state-dir argument, so naming
             * the file inside it is enough to find. */
            snprintf(err, errcap, "world_seed.txt in --state-dir holds no number");
            return false;
        }
        if (errno != ENOENT) {
            snprintf(err, errcap, "cannot read world_seed.txt in --state-dir: %s",
                     strerror(errno));
            return false;
        }
    }

    if (forced != NULL) {
        *out = (uint32_t)strtoul(forced, NULL, 10);
    } else {
        /* First run. clock_gettime's nanoseconds mixed with the pid, rather
         * than time(NULL): two servers first started in the same second on the
         * same box must not come up with the same world. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        *out = (uint32_t)(ts.tv_nsec * 2654435761u) ^ (uint32_t)getpid();
    }

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        snprintf(err, errcap, "cannot write world_seed.txt in --state-dir: %s",
                 strerror(errno));
        return false;
    }
    fprintf(f, "%u\n", *out);
    if (fclose(f) != 0) {
        snprintf(err, errcap, "short write on world_seed.txt in --state-dir: %s",
                 strerror(errno));
        return false;
    }

    logf_("game: world seed %u (%s, written to %s)", *out,
          forced ? "forced by --world-seed" : "newly minted", path);
    return true;
}

/* ------------------------------------------------------------- gate I/O */

static void gate_send(struct bs_game *g, const uint8_t *buf, size_t len)
{
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", g->gate_sock_path);

    ssize_t n = sendto(g->unix_fd, buf, len, MSG_DONTWAIT,
                       (struct sockaddr *)&un, sizeof un);
    if (n < 0 && errno != EAGAIN && errno != ENOENT && errno != ECONNREFUSED) {
        logf_("game: gate socket send failed: %s", strerror(errno));
    }
}

static void send_data(struct bs_game *g, uint32_t sid, const uint8_t *payload, size_t len)
{
    if (len > BS_MAX_PAYLOAD) return;   /* caller bug, not remote input; never true here */

    uint8_t buf[BS_GAME_ENVELOPE_BYTES + BS_MAX_PAYLOAD];
    buf[0] = BS_GAME_DATA;
    bs_put_u32(buf + 1, sid);
    memcpy(buf + BS_GAME_ENVELOPE_BYTES, payload, len);
    gate_send(g, buf, BS_GAME_ENVELOPE_BYTES + len);
}

static void send_kick(struct bs_game *g, uint32_t sid, const char *why)
{
    logf_("game: kicking sid %08x: %s", sid, why);
    uint8_t buf[BS_GAME_ENVELOPE_BYTES];
    buf[0] = BS_GAME_KICK;
    bs_put_u32(buf + 1, sid);
    gate_send(g, buf, sizeof buf);
}

/* Sends to every connected player except `exclude_sid` (0 to exclude none —
 * sid 0 is never issued, see bsgate.c's fresh_sid()). */
static void broadcast_except(struct bs_game *g, uint32_t exclude_sid,
                             const uint8_t *payload, size_t len)
{
    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        BsPlayer *p = &g->players.p[i];
        if (!p->used || p->sid == exclude_sid) continue;
        send_data(g, p->sid, payload, len);
    }
}

/* ----------------------------------------------------------- application */

/* V127-A: a live edit is broadcast only to players who can actually place it
 * — those subscribed to its column, plus (unscoped, as always) any player
 * still on the pre-V127-A legacy path, who by definition has no subscription
 * set at all and must keep seeing every edit exactly as before (see
 * chunk_sub_seen's header comment in players.h and tick()'s grace-window
 * fallback). The diff store itself is unaffected either way: it already
 * holds every accepted edit regardless of who was subscribed to what at the
 * time — diffstoreApply() runs in handle_block_edit() before this is ever
 * called — so a player who subscribes to a column later still gets its full
 * history via send_chunk_diffs(), not just edits made after they asked. */
static void broadcast_block_edit(struct bs_game *g, uint32_t from_sid,
                                 int32_t x, int32_t y, int32_t z, uint8_t block)
{
    int32_t cx = bs_col_of(x);
    int32_t cz = bs_col_of(z);

    uint8_t out[BS_BLOCK_EDIT_BYTES];
    out[0] = BS_APP_BLOCK_EDIT;
    bs_put_i32(out + 1, x);
    bs_put_i32(out + 5, y);
    bs_put_i32(out + 9, z);
    out[13] = block;

    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        BsPlayer *p = &g->players.p[i];
        if (!p->used || p->sid == from_sid) continue;
        if (p->chunk_sub_seen && !playerSubHas(p, cx, cz)) continue;

        send_data(g, p->sid, out, sizeof out);
    }
}

/* Ships the whole current diff set to one player, in batches of
 * BS_SYNC_MAX_ENTRIES so each packet stays inside BS_MAX_PAYLOAD (see
 * bs_proto.h). Ordering does not matter: every entry is an independent
 * (x, y, z, block) triple, not a delta against a previous one.
 *
 * V127-A: no longer called unconditionally from handle_join(). It is now the
 * legacy fallback for a player who has not sent a single CHUNK_SUB within
 * BS_CHUNK_LEGACY_GRACE_MS of joining — see tick() — because a modern client
 * gets its diffs scoped per column instead (send_chunk_diffs()), which is the
 * whole point of CHUNK_SUB existing (see bs_proto.h's comment on
 * BS_APP_CHUNK_SUB). This function's own behaviour is otherwise unchanged, so
 * every scenario described below still applies to whoever it is now called
 * for.
 *
 * This must always send at least one packet, even when `total == 0`. The
 * wire protocol has no separate "you're in" message — the 3DS client
 * (source/net/bsnet_transport.c, state CSTATE_AWAIT_WELCOME) only leaves its
 * connecting state on receipt of its first authenticated packet from the
 * server, and this WORLD_SYNC (here, an empty one: BS_APP_WORLD_SYNC with
 * count 0) is that packet. A fresh, unedited world has zero diffs, so a
 * plain `while (sent < total)` sends nothing at all and the client times out
 * waiting for admission that already happened — proven end to end: an
 * allowlisted client was accepted by both bsgate and bsgame and still never
 * left "Handshake completed, but the server never admitted the session".
 * Do NOT turn this back into a bare `while` loop — that reintroduces the
 * exact bug this comment describes. (This particular guarantee is now
 * carried by WORLD_INFO instead — see send_world_info() and handle_join()
 * below — but the empty-batch behaviour stays exactly as load-bearing for
 * the legacy path: it is still how such a client learns a fresh world has
 * zero diffs rather than waiting forever for a sync that will never arrive.) */
static void send_world_sync(struct bs_game *g, uint32_t sid)
{
    uint32_t total = diffstoreCount(&g->diffs);
    uint32_t sent  = 0;

    do {
        uint32_t batch = total - sent;
        if (batch > BS_SYNC_MAX_ENTRIES) batch = BS_SYNC_MAX_ENTRIES;

        uint8_t payload[BS_WORLD_SYNC_BYTES(BS_SYNC_MAX_ENTRIES)];
        payload[0] = BS_APP_WORLD_SYNC;
        bs_put_u16(payload + 1, (uint16_t)batch);

        uint8_t *w = payload + 3;
        for (uint32_t i = 0; i < batch; i++) {
            const BsDiff *d = diffstoreAt(&g->diffs, sent + i);
            bs_put_i32(w,     d->x);
            bs_put_i32(w + 4, d->y);
            bs_put_i32(w + 8, d->z);
            w[12] = d->block;
            w += BS_SYNC_ENTRY_BYTES;
        }

        send_data(g, sid, payload, BS_WORLD_SYNC_BYTES(batch));
        sent += batch;
    } while (sent < total);
}

/* V127-A: ships one column's diffs to one player, in batches of
 * BS_CHUNK_DIFFS_MAX_ENTRIES so each packet stays inside BS_MAX_PAYLOAD, the
 * same shape send_world_sync() uses for the whole store. The final batch —
 * BS_CHUNK_DIFFS_LAST set — always goes out, even when it is empty, so the
 * client can tell "this column has no edits" from "still coming" (see
 * bs_proto.h's comment on BS_CHUNK_DIFFS_LAST); this mirrors why
 * send_world_sync() must never become a bare `while` loop.
 *
 * Enumeration is a linear scan of the whole diff store, not a per-column
 * index kept in step with diffstoreApply(): CHUNK_SUB fires when a player's
 * loaded columns change, which is bounded by player movement, not by
 * BS_GAME_TICK_MS, so this never runs at anything like tick frequency. Even
 * scaled up past today's BS_DIFF_MAX (65536) to the ~100,000-diff mark this
 * feature is reasoned against, one call is on the order of 100k int
 * comparisons — a fraction of a millisecond, and cheaper than a second data
 * structure that has to stay correct across every diffstoreApply() call and
 * any future compaction or eviction of the store. If the store's cap ever
 * grows by orders of magnitude this trade flips and a real column index
 * becomes worth its upkeep — not the case at today's BS_DIFF_MAX. */
static void send_chunk_diffs(struct bs_game *g, uint32_t sid, int32_t cx, int32_t cz)
{
    uint32_t total = diffstoreCount(&g->diffs);

    uint8_t payload[BS_CHUNK_DIFFS_BYTES(BS_CHUNK_DIFFS_MAX_ENTRIES)];
    uint32_t batch = 0;

    for (uint32_t i = 0; i < total; i++) {
        const BsDiff *d = diffstoreAt(&g->diffs, i);
        if (bs_col_of(d->x) != cx || bs_col_of(d->z) != cz) continue;

        uint8_t *w = payload + BS_CHUNK_DIFFS_HDR_BYTES + (size_t)batch * BS_SYNC_ENTRY_BYTES;
        bs_put_i32(w,     d->x);
        bs_put_i32(w + 4, d->y);
        bs_put_i32(w + 8, d->z);
        w[12] = d->block;
        batch++;

        if (batch == BS_CHUNK_DIFFS_MAX_ENTRIES) {
            payload[0] = BS_APP_CHUNK_DIFFS;
            bs_put_i32(payload + 1, cx);
            bs_put_i32(payload + 5, cz);
            payload[9] = 0;   /* more batches for this column still to come */
            bs_put_u16(payload + 10, (uint16_t)batch);
            send_data(g, sid, payload, BS_CHUNK_DIFFS_BYTES(batch));
            batch = 0;
        }
    }

    payload[0] = BS_APP_CHUNK_DIFFS;
    bs_put_i32(payload + 1, cx);
    bs_put_i32(payload + 5, cz);
    payload[9] = BS_CHUNK_DIFFS_LAST;
    bs_put_u16(payload + 10, (uint16_t)batch);
    send_data(g, sid, payload, BS_CHUNK_DIFFS_BYTES(batch));
}

/* Tells one player which world they are standing in. Sent before the diffs,
 * not after: BS_APP_WORLD_SYNC entries are coordinates into the terrain this
 * seed generates, so a client that applied them first would be writing edits
 * into whatever world it had already made up. See bs_proto.h. */
static void send_world_info(struct bs_game *g, uint32_t sid)
{
    uint8_t payload[BS_WORLD_INFO_BYTES];
    payload[0] = BS_APP_WORLD_INFO;
    bs_put_u32(payload + 1, g->world_seed);
    send_data(g, sid, payload, sizeof payload);
}

/* Tells one player the fingerprint of this server's block registry: layout
 * revision, defined-row count and the CRC-16 over the canonical table stream.
 * Sent immediately after WORLD_INFO at join (handle_join below) — a client
 * whose compiled-in table hashes identically is done on the spot, and one
 * that does not match answers with REGISTRY_FETCH, which only ever arrives
 * because this packet was seen (bs_proto.h's capability-probe note). */
static void send_registry_info(struct bs_game *g, uint32_t sid)
{
    uint8_t payload[BS_APP_REGISTRY_INFO_BYTES];
    payload[0] = BS_APP_REGISTRY_INFO;
    payload[1] = REGISTRY_REV;
    payload[2] = registryCount();
    bs_put_u16(payload + 3, registryCrc16());
    send_data(g, sid, payload, sizeof payload);
}

/* Answers one REGISTRY_FETCH with every dynamic def from `first` up, in
 * consecutive DEFS batches that each fit one BS_MAX_PAYLOAD packet
 * (BS_APP_REGISTRY_DEFS_MAX_N records), last=1 on the final batch. An empty
 * final batch is still sent when there is nothing to say — it is what tells
 * the client the fetch terminated rather than stalled.
 *
 * Both ends derive dynamic ids the same way (lowest free first), so the
 * client validates each batch against its own next-free slot; this side just
 * streams its table id-ascending and lets that check catch any disagreement. */
static void handle_registry_fetch(struct bs_game *g, BsPlayer *p,
                                  const uint8_t *msg, size_t len)
{
    if (len != BS_APP_REGISTRY_FETCH_BYTES) {
        send_kick(g, p->sid, "malformed REGISTRY_FETCH");
        playerFree(p);
        return;
    }

    const uint8_t first = msg[1];
    if (first < REG_ID_DYN_LO || first > REG_ID_DYN_HI) {
        send_kick(g, p->sid, "REGISTRY_FETCH out of range");
        playerFree(p);
        return;
    }

    uint8_t pkt[BS_APP_HDR_BYTES + 3u +
                BS_APP_REGISTRY_DEFS_MAX_N * REGISTRY_WIRE_RECORD_BYTES];
    size_t      n = 0;
    uint8_t     batch_first = first;

    for (int id = first; id <= REG_ID_DYN_HI; id++) {
        if (!registryIsDefined((BlockId)id)) continue;
        if (n == 0) batch_first = (uint8_t)id;
        registryDefPack(pkt + BS_APP_HDR_BYTES + 3u +
                            (size_t)n * REGISTRY_WIRE_RECORD_BYTES,
                        (BlockId)id, registryGet((BlockId)id));
        n++;
        if (n < BS_APP_REGISTRY_DEFS_MAX_N) continue;
        pkt[0] = BS_APP_REGISTRY_DEFS;
        pkt[1] = batch_first;
        pkt[2] = (uint8_t)n;
        pkt[3] = 0;   /* more batches follow */
        send_data(g, p->sid, pkt, BS_APP_REGISTRY_DEFS_BYTES(n));
        n = 0;
    }

    /* The terminating batch, empty or not. */
    pkt[0] = BS_APP_REGISTRY_DEFS;
    pkt[1] = batch_first;
    pkt[2] = (uint8_t)n;
    pkt[3] = 1;       /* last */
    send_data(g, p->sid, pkt, BS_APP_REGISTRY_DEFS_BYTES(n));
}

/* --------------------------------------------------------------- inventory
 *
 * Per-player inventories persist at <state-dir>/players/<sanitised label>/
 * inventory.dat, using inventorySave()/inventoryLoad() exactly as they are
 * (see world/inventory.h's own "Save / load" section) — a directory per
 * player, the way block_diffs.bin is a file per world, both under the same
 * operator-controlled --state-dir root.
 */

/* mkdir() that treats "already exists" as success, not failure — every
 * caller below calls this on a path that may legitimately already be there
 * (a returning player, a server that already made players/ for someone
 * else), and only a *different* kind of failure (no permission, not a
 * directory, disk full) is worth logging. */
static bool ensure_dir(const char *path)
{
    if (mkdir(path, 0700) == 0) return true;
    return errno == EEXIST;
}

/* Resolves to <state-dir>/players/<sanitised label>/, creating both path
 * components if missing, and writes it into `out`. False only on a path or
 * mkdir failure, in which case `out` is not meaningfully defined and the
 * caller must not use it.
 *
 * `label` reaches here from bsgate's allowlist via JOIN (handle_join below) —
 * authenticated (bsgate already checked the session's key against the
 * allowlist) but not TRUSTED, the same distinction bsgame.c's own header
 * comment draws for every other byte a session sends. An operator can name an
 * allowlist entry almost anything up to BS_GAME_LABEL_MAX bytes, and that
 * string is about to become a directory component on disk. Every byte
 * outside [A-Za-z0-9_-] is replaced with '_' rather than the join being
 * refused outright: an ordinary label ("alice", "bob-2") is untouched by this
 * loop and needs no special case, while a label containing "/", ".." or a
 * leading "." can now never walk out of players/ or collide with a dotfile,
 * because none of those bytes can survive into `safe` unescaped. Escaping
 * instead of rejecting also means a stray or unusual character in an
 * operator's chosen label degrades to "a slightly different folder name"
 * rather than "this player can never join". */
static bool player_inv_dir(const struct bs_game *g, const char *label, char *out, size_t outcap)
{
    char safe[BS_GAME_LABEL_MAX];
    size_t j = 0;
    for (size_t i = 0; label[i] != '\0' && j + 1 < sizeof safe; i++) {
        unsigned char c = (unsigned char)label[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '_' || c == '-';
        safe[j++] = ok ? (char)c : '_';
    }
    safe[j] = '\0';
    if (j == 0) snprintf(safe, sizeof safe, "_");   /* never an empty path component */

    char players_dir[492];
    if (!path_set(players_dir, sizeof players_dir, "%s/players", g->state_dir)) return false;
    if (!ensure_dir(players_dir)) {
        logf_("game: cannot create %s: %s", players_dir, strerror(errno));
        return false;
    }

    if (!path_set(out, outcap, "%s/%s", players_dir, safe)) return false;
    if (!ensure_dir(out)) {
        logf_("game: cannot create %s: %s", out, strerror(errno));
        return false;
    }
    return true;
}

/* Loads `p`'s inventory from disk, or leaves it as the empty inventory
 * playerAlloc()'s inventoryInit() call already left it as — a first-time
 * join and an unresolvable directory degrade to exactly the same thing
 * inventoryLoad() itself would do for a missing/corrupt file (see
 * world/inventory.h), so there is no separate error path to invent here. */
static void load_player_inventory(struct bs_game *g, BsPlayer *p)
{
    char dir[512];
    if (!player_inv_dir(g, p->label, dir, sizeof dir)) {
        logf_("game: %s: cannot resolve inventory directory, starting empty", p->label);
        return;
    }
    inventoryLoad(&p->inv, dir);   /* always leaves *inv valid; see world/inventory.h */
}

/* Saves `p`'s current inventory to disk. Failure is logged, not propagated —
 * the same stance diffstoreApply() takes on a persist failure: the in-memory
 * state (and everything already sent to the client about it) stays correct
 * for the running session regardless of whether the write landed, and a
 * player is never kicked or refused an action over a disk problem that is
 * not theirs. */
static void save_player_inventory(struct bs_game *g, const BsPlayer *p)
{
    char dir[512];
    if (!player_inv_dir(g, p->label, dir, sizeof dir)) {
        logf_("game: %s: cannot resolve inventory directory, change not persisted", p->label);
        return;
    }
    if (!inventorySave(&p->inv, dir)) {
        logf_("game: %s: failed to save inventory to %s", p->label, dir);
    }
}

/* The whole of `inv`, wire-encoded — see bs_proto.h's BS_APP_INV_STATE
 * comment for why this is always the full 50 bytes and never a delta. Sent
 * unprompted once at JOIN (handle_join) and again after every
 * BS_APP_INV_ACTION this player sends, whether it was applied or refused
 * (handle_inv_action) — the refused case is what lets a rejected action
 * resync the client instead of leaving it holding a guess. */
static void send_inv_state(struct bs_game *g, uint32_t sid, const Inventory *inv)
{
    uint8_t payload[BS_INV_STATE_BYTES];
    payload[0] = BS_APP_INV_STATE;
    payload[1] = inv->selected_hotbar;

    for (int i = 0; i < INV_SLOT_COUNT; i++) {
        payload[2 + i * 2]     = inv->slots[i].item;
        payload[2 + i * 2 + 1] = inv->slots[i].count;
    }

    send_data(g, sid, payload, sizeof payload);
}

/* ----------------------------------------------------------- player state
 *
 * Per-player state beyond the inventory — pose, armour, XP and meters —
 * persists at <state-dir>/players/<sanitised label>/player.dat, a sibling
 * of inventory.dat in the very same per-player directory (player_inv_dir()
 * below is reused verbatim, label sanitisation included). Persistence is
 * write-through on every state-changing event, the same policy the two
 * stores beside it already use: block_diffs.bin appends+fsyncs inside
 * diffstoreApply() the moment an edit is accepted, and inventory.dat is
 * rewritten by save_player_inventory() after every changed INV_ACTION.
 * There is no periodic flusher for either, so there is none here either:
 * a PLAYER_REPORT saves immediately, and LEAVE performs one final save
 * merging the live pose in. Pose-only movement never writes by itself —
 * POS_UPDATE arrives at wire frequency and would turn into disk churn —
 * so a hard crash can lose pose deltas since the last persist point,
 * exactly the class of bounded loss diffstore already tolerates with its
 * torn-tail discard. */

/* Loads `p`'s saved state from player.dat. `p->state` ends up valid either
 * way; what distinguishes "restored" from "fresh spawn" is both the return
 * value and `state_dirty`, which doubles as that record: a valid load sets
 * it so the leave-save below rewrites the file (merging whatever fresher
 * pose this session produced) instead of leaving it frozen mid-session. */
static bool load_player_state(struct bs_game *g, BsPlayer *p)
{
    char dir[512];
    if (!player_inv_dir(g, p->label, dir, sizeof dir)) {
        logf_("game: %s: cannot resolve player directory, starting fresh", p->label);
        return false;
    }
    bool found = playerStateLoad(&p->state, dir);
    if (found) {
        logf_("game: %s: restored player state from %s", p->label, dir);
    }
    p->state_dirty = found;
    return found;
}

/* Saves `p`'s current state to disk, merging the live pose in at write time
 * rather than keeping a second pose channel in sync: x/y/z/yaw/pitch keep
 * arriving via POS_UPDATE exactly as they always did, and only a real
 * persist event copies them across. Failure is logged, not propagated —
 * the same stance save_player_inventory() takes, for the same reason: a
 * disk problem that is not the player's doing must not cost them their
 * session. */
static void save_player_state(struct bs_game *g, const BsPlayer *p)
{
    BsPlayerState snapshot = p->state;
    if (p->has_pos) {
        snapshot.x     = p->x;
        snapshot.y     = p->y;
        snapshot.z     = p->z;
        snapshot.yaw   = p->yaw;
        snapshot.pitch = p->pitch;
        snapshot.has_pose = true;
    }

    char dir[512];
    if (!player_inv_dir(g, p->label, dir, sizeof dir)) {
        logf_("game: %s: cannot resolve player directory, change not persisted", p->label);
        return;
    }
    if (!playerStateSave(&snapshot, dir)) {
        logf_("game: %s: failed to save player state to %s", p->label, dir);
    }
}

/* The whole of the player's state, wire-encoded — see bs_proto.h's
 * BS_APP_PLAYER_STATE comment for why this is volunteered once at JOIN even
 * when nothing is saved: the all-zero flags=0 packet is how the client
 * tells "fresh spawn" apart from packet loss. `ext_valid` is true exactly
 * when a usable player.dat was loaded for this join; the pose flag follows
 * the loaded state itself. */
static void send_player_state(struct bs_game *g, uint32_t sid,
                              const BsPlayer *p, bool ext_valid)
{
    unsigned flags = 0;
    if (p->state.has_pose) flags |= BS_PLAYER_STATE_FLAG_POSE;
    if (ext_valid)         flags |= BS_PLAYER_STATE_FLAG_EXT;

    uint8_t payload[BS_PLAYER_STATE_BYTES];
    payload[0] = BS_APP_PLAYER_STATE;
    playerStateEncodeBody(payload + 1, &p->state, flags);

    send_data(g, sid, payload, sizeof payload);
}

static void handle_join(struct bs_game *g, uint32_t sid, const uint8_t *body, size_t len,
                        uint64_t now)
{
    if (len != BS_JOIN_BODY_BYTES) {
        logf_("game: malformed JOIN for sid %08x (%zu bytes), ignoring", sid, len);
        return;
    }

    /* body is [32-byte pubkey][32-byte label] (game_notify_join, bsgate.c).
     * The pubkey is not needed here: bsgate already checked it against the
     * allowlist before this JOIN was ever sent, and bsgame has no identity
     * decision left to make. */
    const uint8_t *label_bytes = body + 32;
    size_t label_len = strnlen((const char *)label_bytes, 32);
    if (label_len >= BS_GAME_LABEL_MAX) label_len = BS_GAME_LABEL_MAX - 1;

    char label[BS_GAME_LABEL_MAX];
    memcpy(label, label_bytes, label_len);
    label[label_len] = '\0';

    /* One sid, one player. A duplicate JOIN should not happen — bsgate
     * frees any stale session for the same key before issuing a fresh sid
     * — but replacing rather than leaking a slot costs nothing and matches
     * how bsgate itself treats a reconnect. */
    BsPlayer *existing = playerBySid(&g->players, sid);
    if (existing != NULL) playerFree(existing);

    BsPlayer *p = playerAlloc(&g->players, sid, label, now);
    if (p == NULL) {
        logf_("game: player table full, cannot seat sid %08x (%s)", sid, label);
        send_kick(g, sid, "server full");
        return;
    }

    logf_("game: %s joined (sid %08x), world seed %u", p->label, sid, g->world_seed);
    g->joins_total++;
    /* Order matters and is load-bearing — see send_world_info(). This is also
     * the packet that admits the client (the 3DS transport leaves
     * CSTATE_AWAIT_WELCOME on the first authenticated packet of any type,
     * source/net/bsnet_transport.c), a role send_world_sync() used to hold
     * before V127-A.
     *
     * send_world_sync() is deliberately NOT called here anymore. Sending the
     * whole diff store to every joiner is exactly the problem V127-A exists
     * to fix (see bs_proto.h's comment above BS_APP_CHUNK_SUB): it overflows
     * a 3DS client's pending store and wastes bandwidth on columns it will
     * never render. A modern client instead subscribes to the columns it has
     * loaded (CHUNK_SUB) and gets only those diffs back (send_chunk_diffs()).
     * tick() below still falls back to the old full-dump WORLD_SYNC, but only
     * for a player who never sends a CHUNK_SUB within BS_CHUNK_LEGACY_GRACE_MS
     * of this JOIN — see BS_CHUNK_LEGACY_GRACE_MS's own comment for why that
     * is a safe way to tell a pre-V127-A client apart from a modern one
     * without a capability bit the fixed wire format has no room for. */
    send_world_info(g, sid);

    /* REGISTRY_INFO rides right behind WORLD_INFO and before anything that
     * could put a block id on the wire — the join order world_info ->
     * registry_info -> inv_state -> player_state is load-bearing (v1.6.0
     * Phase A): a client must be able to apply registry definitions before
     * it generates or meshes a single server column, and this is the same
     * ordering slot WORLD_INFO already owns. Volunteered, never requested:
     * an old client ignores it harmlessly, and only a client that has seen
     * it may answer with REGISTRY_FETCH. */
    send_registry_info(g, sid);

    /* AFTER send_world_info, not before — WORLD_INFO's own comment above
     * covers why it must lead. INV_STATE has no such ordering requirement
     * against WORLD_INFO (an inventory slot is not a coordinate into
     * anything), but it is still the capability probe bs_proto.h's comment
     * on BS_APP_INV_STATE describes: an old client that has never heard of
     * this message type ignores it (net/networld.c's `default: break;`) and
     * keeps its inventory exactly as local as it always was, while a new
     * client learns from receiving it that INV_ACTION is safe to send. */
    load_player_inventory(g, p);
    send_inv_state(g, sid, &p->inv);

    /* PLAYER_STATE rides right behind INV_STATE and works the same way:
     * volunteered once per join (bs_proto.h's BS_APP_PLAYER_STATE comment),
     * ignored harmlessly by any client that predates it, and the gate that
     * tells a new client PLAYER_REPORT is safe to send. It always goes out
     * even when nothing is saved — a zeroed flags=0 packet is the fresh-
     * spawn marker, deliberately distinguishable from a packet that was
     * simply lost. */
    bool state_restored = load_player_state(g, p);
    send_player_state(g, sid, p, state_restored);
}

static void handle_leave(struct bs_game *g, uint32_t sid)
{
    BsPlayer *p = playerBySid(&g->players, sid);
    if (p == NULL) return;
    logf_("game: %s left (sid %08x)", p->label, sid);

    /* Final persist before the slot is wiped — this is what carries a
     * session's pose home for a player whose last PLAYER_REPORT predates
     * their latest movement. Only ever reached for a clean LEAVE; a crash
     * or a hard kill skips it, which is precisely why the write-through on
     * every report exists beside it (see the player-state section above). */
    if (p->state_dirty) save_player_state(g, p);

    playerFree(p);
}

/* `msg` is the whole application payload, type byte included, so its length
 * compares directly against the BS_*_BYTES constants in bs_proto.h (which
 * themselves include BS_APP_HDR_BYTES) instead of a second, easy-to-drift
 * set of body-only sizes. */
static void handle_block_edit(struct bs_game *g, BsPlayer *p, const uint8_t *msg, size_t len,
                              uint64_t now)
{
    if (len != BS_BLOCK_EDIT_BYTES) {
        send_kick(g, p->sid, "malformed BLOCK_EDIT");
        playerFree(p);
        return;
    }

    int32_t x = bs_get_i32(msg + 1);
    int32_t y = bs_get_i32(msg + 5);
    int32_t z = bs_get_i32(msg + 9);
    uint8_t block = msg[13];

    if (!bsEditValid(x, y, z, block)) {
        g->edits_rejected_range++;
        logf_("game: %s: rejected edit (%d,%d,%d)=%u, out of range", p->label, x, y, z, block);
        return;
    }
    if (!playerEditAllow(p, now)) {
        g->edits_rejected_rate++;
        logf_("game: %s: rejected edit, rate limit", p->label);
        return;
    }
    if (!diffstoreApply(&g->diffs, x, y, z, block)) {
        g->edits_rejected_full++;
        logf_("game: %s: rejected edit, diff table is full", p->label);
        return;
    }
    g->edits_accepted++;

    broadcast_block_edit(g, p->sid, x, y, z, block);
}

static void handle_pos_update(struct bs_game *g, BsPlayer *p, const uint8_t *msg, size_t len)
{
    if (len != BS_POS_UPDATE_C_BYTES) {
        send_kick(g, p->sid, "malformed POS_UPDATE");
        playerFree(p);
        return;
    }

    p->x     = bs_get_f32(msg + 1);
    p->y     = bs_get_f32(msg + 5);
    p->z     = bs_get_f32(msg + 9);
    p->yaw   = bs_get_f32(msg + 13);
    p->pitch = bs_get_f32(msg + 17);
    p->has_pos   = true;
    p->pos_dirty = true;
}

/* V127-A: the client has loaded column (cx, cz) and wants its diffs.
 * `chunk_sub_seen` is set unconditionally, even if the subscription table
 * turns out to be full below — this is what tells tick() the player is a
 * modern client and must never fall back to a legacy full WORLD_SYNC, which
 * would defeat the entire point of scoping (see BS_CHUNK_LEGACY_GRACE_MS). */
static void handle_chunk_sub(struct bs_game *g, BsPlayer *p, const uint8_t *msg, size_t len)
{
    if (len != BS_CHUNK_SUB_BYTES) {
        send_kick(g, p->sid, "malformed CHUNK_SUB");
        playerFree(p);
        return;
    }

    int32_t cx = bs_get_i32(msg + 1);
    int32_t cz = bs_get_i32(msg + 5);

    p->chunk_sub_seen = true;

    if (!playerSubAdd(p, cx, cz)) {
        /* Table full: not a protocol violation — a client asking to track
         * more columns than any legitimate render distance needs is
         * misbehaving, not lying about its message shape — so this is
         * dropped rather than kicked, the same stance handle_block_edit()
         * takes on a well-formed-but-refused edit. */
        logf_("game: %s: CHUNK_SUB (%d,%d) dropped, subscription table full",
              p->label, cx, cz);
        return;
    }

    send_chunk_diffs(g, p->sid, cx, cz);
}

/* V127-A: the client has dropped column (cx, cz) and no longer wants its
 * edits broadcast. Unlike CHUNK_SUB this does not set chunk_sub_seen — an
 * UNSUB with no prior SUB (e.g. reordered on lossy Wi-Fi) must not be able
 * to flip a legacy client onto the scoped path with an empty subscription
 * set, which would silently stop every future edit from ever reaching it. */
static void handle_chunk_unsub(struct bs_game *g, BsPlayer *p, const uint8_t *msg, size_t len)
{
    if (len != BS_CHUNK_UNSUB_BYTES) {
        send_kick(g, p->sid, "malformed CHUNK_UNSUB");
        playerFree(p);
        return;
    }

    int32_t cx = bs_get_i32(msg + 1);
    int32_t cz = bs_get_i32(msg + 5);
    playerSubRemove(p, cx, cz);
}

/* One requested inventory or crafting operation from an already-joined
 * player. See proto/bs_proto.h's own comment above enum bs_inv_op for the
 * trust split this function enforces: MOVE/SWAP/SPLIT/SELECT/CRAFT are
 * checked against p->inv, the inventory this server actually owns, so none
 * of them can manufacture units the player did not already have — CRAFT in
 * particular can only succeed by spending a real, present ingredient count,
 * because craftMake() attempts the whole recipe on its own scratch copy and
 * only commits it back if that succeeds (world/crafting.h). PICKUP and
 * CONSUME are not verified at all: they are the client's own report of what
 * a block break or a placement just did to its held items, applied here
 * exactly as told. That is a deliberate, permanent gap, not an oversight —
 * bsgame has no terrain generator (see this file's header comment: terrain
 * is deterministic, and this process only ever ships the diffs players have
 * made) and never will, so it has no way to know what block actually stood
 * at the coordinate a break or place just touched, and therefore no way to
 * check a PICKUP/CONSUME report against anything but itself. This grants a
 * modified client nothing handle_block_edit() did not already grant it —
 * that function is untouched by this feature and exactly as
 * client-authoritative as it always was — just in inventory-count form
 * instead of world-block form. So an INV_STATE this server sends back is an
 * honest record of what its own inventory logic did with what it was told,
 * never a claim that what it was told was itself true; nobody downstream
 * should read it as more than that.
 *
 * A malformed payload (wrong length) or a bad argument (unknown op, an
 * out-of-range slot/hotbar/recipe/item index, a count outside
 * 1..BS_INV_STACK_MAX, or a "must be zero" parameter that is not) is
 * refused, not kicked: unlike handle_app_payload's own dispatch (which kicks
 * on a message *type* it does not recognise, because that is a client not
 * speaking the protocol it claims to), a bad argument inside a message type
 * the server does understand is an ordinary wrong answer — bs_proto.h's own
 * comment above enum bs_inv_op states this stance for an unrecognised op
 * specifically; it is extended here to every other way this payload can be
 * malformed, so a single momentary desync (a dropped ACK, a stale UI still
 * showing an old op table) costs the player a resync, never a session. */
static void handle_inv_action(struct bs_game *g, BsPlayer *p, const uint8_t *msg, size_t len)
{
    if (len != BS_INV_ACTION_BYTES) {
        send_inv_state(g, p->sid, &p->inv);
        return;
    }

    uint8_t op = msg[1];
    uint8_t a  = msg[2];
    uint8_t b  = msg[3];
    uint8_t c  = msg[4];
    bool changed = false;

    switch (op) {
    case BS_INV_OP_MOVE:
        if (a < INV_SLOT_COUNT && b < INV_SLOT_COUNT) {
            changed = inventoryMoveUnits(&p->inv, a, b, c) > 0;
        }
        break;

    case BS_INV_OP_SWAP:
        if (a < INV_SLOT_COUNT && b < INV_SLOT_COUNT) {
            inventorySwapSlots(&p->inv, a, b);
            changed = true;
        }
        break;

    case BS_INV_OP_SPLIT:
        if (a < INV_SLOT_COUNT && b < INV_SLOT_COUNT) {
            changed = inventorySplitStack(&p->inv, a, b);
        }
        break;

    case BS_INV_OP_SELECT:
        if (a < INV_HOTBAR_SLOTS) {
            inventorySelectHotbar(&p->inv, a);
            changed = true;
        }
        break;

    case BS_INV_OP_CRAFT:
        if (a < RECIPE_COUNT) {
            changed = craftMake(&p->inv, a);
        }
        break;

    /* Taken on trust — see this function's header comment. */
    case BS_INV_OP_PICKUP:
        if (a < BS_BLOCK_COUNT && b >= 1 && b <= BS_INV_STACK_MAX && c == 0) {
            changed = inventoryAdd(&p->inv, a, b, NULL) != INV_ADD_REFUSED;
        }
        break;

    case BS_INV_OP_CONSUME:
        if (a < BS_BLOCK_COUNT && b >= 1 && b <= BS_INV_STACK_MAX && c == 0) {
            changed = inventoryRemove(&p->inv, a, b) > 0;
        }
        break;

    default:
        /* Unknown op: refused, answered with an unchanged INV_STATE, not
         * kicked — see bs_proto.h's comment above enum bs_inv_op. */
        break;
    }

    if (changed) {
        save_player_inventory(g, p);
    }
    send_inv_state(g, p->sid, &p->inv);
}

/* The client's report of its own armour, XP and meters (BS_APP_PLAYER_REPORT,
 * proto/bs_proto.h). Taken on trust for the same reason and in the same
 * terms as INV_ACTION's PICKUP/CONSUME ops above: this server has no
 * simulation of hunger, damage or experience to check a report against — it
 * is the store, not the referee, and the values only ever flow back to the
 * same client at its next join. playerStateApplyMeters() still sanitises
 * every field into its documented range, so a hostile or buggy reporter can
 * corrupt nothing but its own record.
 *
 * A wrong-length payload is KICKed, matching what every other known-type
 * wrong length gets here except INV_ACTION: BLOCK_EDIT, POS_UPDATE,
 * CHUNK_SUB and CHUNK_UNSUB all treat "right type, wrong length" as a
 * protocol violation from a client not speaking the format it claims to.
 * INV_ACTION alone refuses-and-resyncs because an INV_STATE reply is its
 * built-in correction; PLAYER_REPORT has no reply message, so there is
 * nothing to resync with and the majority rule applies. */
static void handle_player_report(struct bs_game *g, BsPlayer *p, const uint8_t *msg, size_t len)
{
    if (len != BS_PLAYER_REPORT_BYTES) {
        send_kick(g, p->sid, "malformed PLAYER_REPORT");
        playerFree(p);
        return;
    }

    playerStateApplyMeters(&p->state, msg + 1);
    p->state_dirty = true;
    save_player_state(g, p);   /* write-through now — see the section comment */
}

/* One accepted application payload from an already-joined player. Anything
 * structurally wrong here — a type this build does not know, or a length
 * that does not match its type — is treated as a protocol violation from a
 * client that is not speaking the format it claims to, which bsgate cannot
 * catch (it never looks inside these bytes) and only bsgame can: it is
 * kicked rather than merely dropped. An edit that is well-formed but simply
 * refused (bad coordinate, bad rate) is a normal outcome, not a protocol
 * violation, so it is only ever dropped. */
static void handle_app_payload(struct bs_game *g, uint32_t sid, const uint8_t *body, size_t len,
                               uint64_t now)
{
    BsPlayer *p = playerBySid(&g->players, sid);
    if (p == NULL) return;   /* JOIN raced with a stray DATA after a LEAVE; ignore */
    p->last_seen_ms = now;

    if (len < BS_APP_HDR_BYTES) {
        send_kick(g, sid, "empty application payload");
        playerFree(p);
        return;
    }

    switch (body[0]) {
    case BS_APP_BLOCK_EDIT:
        handle_block_edit(g, p, body, len, now);
        break;
    case BS_APP_POS_UPDATE:
        handle_pos_update(g, p, body, len);
        break;
    case BS_APP_CHUNK_SUB:
        handle_chunk_sub(g, p, body, len);
        break;
    case BS_APP_CHUNK_UNSUB:
        handle_chunk_unsub(g, p, body, len);
        break;
    case BS_APP_INV_ACTION:
        handle_inv_action(g, p, body, len);
        break;
    case BS_APP_PLAYER_REPORT:
        handle_player_report(g, p, body, len);
        break;
    case BS_APP_REGISTRY_FETCH:
        handle_registry_fetch(g, p, body, len);
        break;
    default:
        send_kick(g, sid, "unknown application message type");
        playerFree(p);
        break;
    }
}

/* ------------------------------------------------------------- gate recv */

static void handle_gate_msg(struct bs_game *g)
{
    uint8_t buf[BS_GAME_MAX_DGRAM];
    ssize_t n = recv(g->unix_fd, buf, sizeof buf, MSG_DONTWAIT);
    if (n < (ssize_t)BS_GAME_ENVELOPE_BYTES) return;   /* short read or nothing pending */

    uint32_t sid = bs_get_u32(buf + 1);
    size_t   body_len = (size_t)n - BS_GAME_ENVELOPE_BYTES;
    uint64_t now = now_ms();

    switch (buf[0]) {
    case BS_GAME_JOIN:  handle_join(g, sid, buf + BS_GAME_ENVELOPE_BYTES, body_len, now); break;
    case BS_GAME_LEAVE: handle_leave(g, sid);                                             break;
    case BS_GAME_DATA:  handle_app_payload(g, sid, buf + BS_GAME_ENVELOPE_BYTES, body_len, now);
                        break;
    default:
        /* BS_GAME_KICK is game -> gate only; anything else is not a kind
         * this process was ever meant to receive. */
        break;
    }
}

/* ------------------------------------------------------------------- tick */

static void tick(struct bs_game *g)
{
    uint64_t now = now_ms();

    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        BsPlayer *p = &g->players.p[i];
        if (!p->used) continue;

        /* V127-A legacy fallback: a player who still has not sent a single
         * CHUNK_SUB by BS_CHUNK_LEGACY_GRACE_MS after JOIN is assumed to be
         * a pre-V127-A client and gets the old full-dump WORLD_SYNC exactly
         * once — see BS_CHUNK_LEGACY_GRACE_MS and send_world_sync()'s own
         * comments for why this is safe. legacy_sync_sent makes this a
         * one-shot: it is set here whether or not chunk_sub_seen ended up
         * true, so a player who starts subscribing mere moments after the
         * window closes is not also handed a redundant full dump. */
        uint64_t since_join = (now > p->joined_ms) ? now - p->joined_ms : 0;
        if (!p->chunk_sub_seen && !p->legacy_sync_sent
            && since_join >= BS_CHUNK_LEGACY_GRACE_MS) {
            send_world_sync(g, p->sid);
            p->legacy_sync_sent = true;
        }

        if (!p->has_pos || !p->pos_dirty) continue;

        uint8_t out[BS_POS_UPDATE_S_BYTES];
        out[0] = BS_APP_POS_UPDATE;
        bs_put_u32(out + 1, p->sid);
        bs_put_f32(out + 5,  p->x);
        bs_put_f32(out + 9,  p->y);
        bs_put_f32(out + 13, p->z);
        bs_put_f32(out + 17, p->yaw);
        bs_put_f32(out + 21, p->pitch);

        broadcast_except(g, p->sid, out, sizeof out);
        p->pos_dirty = false;
    }
}

/* --------------------------------------------------------------- status */

/* Writes a plain-text snapshot of what this process currently knows, for
 * tools/bsgate-status to read back. Triggered by SIGUSR1 only — see
 * gateway/bsgate.c's write_status() for the full reasoning: a socket here
 * would be a second thing listening with a second parser on a box whose
 * entire design is zero inbound ports, while a signal costs no attack
 * surface (only root and this process's own uid may ever send one) and the
 * reader can never talk back through a plain file.
 *
 * Written to a temp path and renamed onto status_path, so a reader never
 * observes a half-written file, and mode 0640 so the group can read it but
 * the world cannot. */
static void write_status(struct bs_game *g, uint64_t t)
{
    char tmp[520];
    if (!path_set(tmp, sizeof tmp, "%s.tmp", g->status_path)) return;

    FILE *f = fopen(tmp, "w");
    if (f == NULL) {
        logf_("game: status: %s: %s", tmp, strerror(errno));
        return;
    }
    fchmod(fileno(f), 0640);

    unsigned players = 0;
    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        if (g->players.p[i].used) players++;
    }

    fprintf(f, "process bsgame\n");
    fprintf(f, "uptime_s %llu\n", (unsigned long long)((t - g->started_ms) / 1000u));
    fprintf(f, "players %u\n", players);
    fprintf(f, "players_max %u\n", BS_GAME_MAX_PLAYERS);
    fprintf(f, "tick_ms %u\n", BS_GAME_TICK_MS);
    fprintf(f, "block_diffs %u\n", diffstoreCount(&g->diffs));
    fprintf(f, "block_diffs_max %u\n", BS_DIFF_MAX);
    fprintf(f, "joins_total %llu\n", (unsigned long long)g->joins_total);
    fprintf(f, "edits_accepted %llu\n", (unsigned long long)g->edits_accepted);
    fprintf(f, "edits_rejected_range %llu\n", (unsigned long long)g->edits_rejected_range);
    fprintf(f, "edits_rejected_rate %llu\n", (unsigned long long)g->edits_rejected_rate);
    fprintf(f, "edits_rejected_full %llu\n", (unsigned long long)g->edits_rejected_full);

    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        const BsPlayer *p = &g->players.p[i];
        if (!p->used) continue;

        /* label is BS_GAME_LABEL_MAX-sized and arrives verbatim from
         * bsgate's allowlist (see handle_join()), which never lets a space
         * into it — safe to place unquoted in this space-separated line. */
        double x = 0.0, y = 0.0, z = 0.0, yaw = 0.0, pitch = 0.0;
        if (p->has_pos) {
            x = (double)p->x; y = (double)p->y; z = (double)p->z;
            yaw = (double)p->yaw; pitch = (double)p->pitch;
        }

        /* idle_ms is time since the last message WE heard FROM this player
         * — it is NOT a round-trip time. This process never solicits a
         * reply, so it has no RTT to report; tools/bsgate-status must label
         * this column honestly and must not present it as latency. */
        fprintf(f, "player %08x %s %.1f %.1f %.1f %.1f %.1f %d %llu\n",
                p->sid, p->label, x, y, z, yaw, pitch,
                p->has_pos ? 1 : 0,
                (unsigned long long)(t - p->last_seen_ms));
    }

    fclose(f);
    if (rename(tmp, g->status_path) != 0) {
        logf_("game: status: rename: %s", strerror(errno));
        unlink(tmp);
    }
}

/* ------------------------------------------------------------------ setup */

static bool unix_bind(struct bs_game *g, const char *path)
{
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;

    if (!path_set(un.sun_path, sizeof un.sun_path, "%s", path)) {
        logf_("game: socket path too long (max %zu): %s", sizeof un.sun_path - 1, path);
        return false;
    }

    g->unix_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (g->unix_fd < 0) { logf_("game: unix socket: %s", strerror(errno)); return false; }

    unlink(path);

    /* 0770 with the shared group, matching gateway/bsgate.c's unix_bind: the
     * gate process has to connect() to this socket, which needs write on the
     * socket file, and it only ever reaches it through group membership.
     * Without this the unit's UMask=0077 would leave game.sock 0700
     * bsgame:bsgame and the gate would be locked out of its own game link. */
    mode_t old = umask(0007);
    bool ok = bind(g->unix_fd, (struct sockaddr *)&un, sizeof un) == 0;
    umask(old);

    if (!ok) {
        logf_("game: bind %s: %s", path, strerror(errno));
        return false;
    }
    return true;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: bsgame --game-socket PATH --gate-socket PATH --state-dir DIR\n"
        "  --game-socket PATH   unix socket this process binds (gate sends JOIN/DATA/LEAVE here)\n"
        "  --gate-socket PATH   unix socket bsgate binds (this process sends DATA/KICK there)\n"
        "  --state-dir DIR      holds block_diffs.bin, world_seed.txt and, on SIGUSR1, status.txt\n"
        "  --world-seed N       force this world's terrain seed, overwriting world_seed.txt.\n"
        "                       Omit it: the stored seed is reused, or minted on first run.\n"
        "                       Changing it strands every edit already in block_diffs.bin.\n");
}

int main(int argc, char **argv)
{
    const char *game_sock = NULL, *gate_sock = NULL, *state_dir = NULL, *world_seed = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--game-socket") && i + 1 < argc)      game_sock = argv[++i];
        else if (!strcmp(argv[i], "--gate-socket") && i + 1 < argc) gate_sock = argv[++i];
        else if (!strcmp(argv[i], "--state-dir") && i + 1 < argc)   state_dir = argv[++i];
        else if (!strcmp(argv[i], "--world-seed") && i + 1 < argc)  world_seed = argv[++i];
        else { usage(); return 2; }
    }
    if (game_sock == NULL || gate_sock == NULL || state_dir == NULL) {
        usage();
        return 2;
    }

    static struct bs_game g;
    memset(&g, 0, sizeof g);
    g.unix_fd = -1;
    g.started_ms = now_ms();

    if (!path_set(g.game_sock_path, sizeof g.game_sock_path, "%s", game_sock)
        || !path_set(g.gate_sock_path, sizeof g.gate_sock_path, "%s", gate_sock)) {
        logf_("game: a --*-socket path is too long (unix sockets cap at %zu bytes)",
              sizeof g.game_sock_path - 1);
        return 1;
    }
    if (!path_set(g.status_path, sizeof g.status_path, "%s/status.txt", state_dir)) {
        logf_("game: --state-dir is too long for the status file path (max %zu)",
              sizeof g.status_path - 1);
        return 1;
    }
    if (!path_set(g.state_dir, sizeof g.state_dir, "%s", state_dir)) {
        logf_("game: --state-dir is too long (max %zu)", sizeof g.state_dir - 1);
        return 1;
    }

    playersInit(&g.players);

    char err[256];
    /* Before the diff store, so a bad seed file stops the server while the
     * world is still untouched rather than after diffs are already open. */
    if (!world_seed_load(state_dir, world_seed, &g.world_seed, err, sizeof err)) {
        logf_("game: %s", err);
        return 1;
    }
    if (!diffstoreOpen(&g.diffs, state_dir, err, sizeof err)) {
        logf_("game: %s", err);
        return 1;
    }
    logf_("game: %u block diff(s) loaded from %s", diffstoreCount(&g.diffs), state_dir);

    /* v1.6.0 Phase A: the block registry is canonical server state — core
     * rows compiled in, dynamic rows restored from <state-dir>/registry.bin
     * — and it must be settled BEFORE any join can be accepted, because the
     * INFO a joining client compares against goes out within milliseconds of
     * its first packet. A false load means "no file yet" (a fresh state dir)
     * or an unreadable one; either way the table stays core-only, which is
     * exactly what an empty file would have said. Frozen immediately after:
     * nothing registers at runtime in this phase, and post-freeze reads need
     * no locks. */
    registryInitCore();
    char reg_path[512];
    if (path_set(reg_path, sizeof reg_path, "%s/registry.bin", state_dir)) {
        if (registrySidecarLoad(reg_path)) {
            /* registryCount() counts every defined row (air + core + dyn);
             * the dynamic share is whatever sits in the dyn id range. */
            unsigned total = registryCount();
            unsigned dyn   = 0;
            for (unsigned id = (unsigned)REG_ID_DYN_LO;
                 id <= (unsigned)REG_ID_DYN_HI; id++) {
                if (registryIsDefined((BlockId)id)) dyn++;
            }
            logf_("game: %u block def(s) loaded (%u dynamic) from %s",
                  total, dyn, reg_path);
        } else
            logf_("game: no registry.bin loaded from %s (core table only)", state_dir);
    }
    registryFreeze();

    if (!unix_bind(&g, g.game_sock_path)) {
        diffstoreClose(&g.diffs);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sa.sa_handler = on_sigusr1;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    logf_("game: ready (game-socket %s, gate-socket %s)", g.game_sock_path, g.gate_sock_path);

    while (!g_quit) {
        struct pollfd fd = { .fd = g.unix_fd, .events = POLLIN };
        int r = poll(&fd, 1, (int)BS_GAME_TICK_MS);
        if (r < 0 && errno != EINTR) {
            logf_("game: poll: %s", strerror(errno));
            break;
        }

        if (r > 0 && (fd.revents & POLLIN)) {
            /* Drain everything queued before ticking, so a burst of
             * datagrams delivered between two poll() wakeups is not spread
             * across several ticks' worth of broadcast latency. */
            for (;;) {
                struct pollfd probe = { .fd = g.unix_fd, .events = POLLIN };
                if (poll(&probe, 1, 0) <= 0) break;
                handle_gate_msg(&g);
            }
        }

        if (g_status) {
            g_status = 0;
            write_status(&g, now_ms());
        }

        tick(&g);
    }

    logf_("game: shutting down");
    close(g.unix_fd);
    diffstoreClose(&g.diffs);
    return 0;
}
