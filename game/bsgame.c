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
#include "players.h"
#include "validate.h"

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

static volatile sig_atomic_t g_quit = 0;
static void on_sigterm(int s) { (void)s; g_quit = 1; }

struct bs_game {
    int  unix_fd;
    char game_sock_path[108];
    char gate_sock_path[108];

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

static void broadcast_block_edit(struct bs_game *g, uint32_t from_sid,
                                 int32_t x, int32_t y, int32_t z, uint8_t block)
{
    uint8_t out[BS_BLOCK_EDIT_BYTES];
    out[0] = BS_APP_BLOCK_EDIT;
    bs_put_i32(out + 1, x);
    bs_put_i32(out + 5, y);
    bs_put_i32(out + 9, z);
    out[13] = block;
    broadcast_except(g, from_sid, out, sizeof out);
}

/* Ships the whole current diff set to one player, right after JOIN, in
 * batches of BS_SYNC_MAX_ENTRIES so each packet stays inside BS_MAX_PAYLOAD
 * (see bs_proto.h). Ordering does not matter: every entry is an independent
 * (x, y, z, block) triple, not a delta against a previous one. */
static void send_world_sync(struct bs_game *g, uint32_t sid)
{
    uint32_t total = diffstoreCount(&g->diffs);
    uint32_t sent  = 0;

    while (sent < total) {
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
    }
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

    logf_("game: %s joined (sid %08x)", p->label, sid);
    send_world_sync(g, sid);
}

static void handle_leave(struct bs_game *g, uint32_t sid)
{
    BsPlayer *p = playerBySid(&g->players, sid);
    if (p == NULL) return;
    logf_("game: %s left (sid %08x)", p->label, sid);
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
        logf_("game: %s: rejected edit (%d,%d,%d)=%u, out of range", p->label, x, y, z, block);
        return;
    }
    if (!playerEditAllow(p, now)) {
        logf_("game: %s: rejected edit, rate limit", p->label);
        return;
    }
    if (!diffstoreApply(&g->diffs, x, y, z, block)) {
        logf_("game: %s: rejected edit, diff table is full", p->label);
        return;
    }

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
    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        BsPlayer *p = &g->players.p[i];
        if (!p->used || !p->has_pos || !p->pos_dirty) continue;

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
        "  --state-dir DIR      holds block_diffs.bin\n");
}

int main(int argc, char **argv)
{
    const char *game_sock = NULL, *gate_sock = NULL, *state_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--game-socket") && i + 1 < argc)      game_sock = argv[++i];
        else if (!strcmp(argv[i], "--gate-socket") && i + 1 < argc) gate_sock = argv[++i];
        else if (!strcmp(argv[i], "--state-dir") && i + 1 < argc)   state_dir = argv[++i];
        else { usage(); return 2; }
    }
    if (game_sock == NULL || gate_sock == NULL || state_dir == NULL) {
        usage();
        return 2;
    }

    static struct bs_game g;
    memset(&g, 0, sizeof g);
    g.unix_fd = -1;

    if (!path_set(g.game_sock_path, sizeof g.game_sock_path, "%s", game_sock)
        || !path_set(g.gate_sock_path, sizeof g.gate_sock_path, "%s", gate_sock)) {
        logf_("game: a --*-socket path is too long (unix sockets cap at %zu bytes)",
              sizeof g.game_sock_path - 1);
        return 1;
    }

    playersInit(&g.players);

    char err[256];
    if (!diffstoreOpen(&g.diffs, state_dir, err, sizeof err)) {
        logf_("game: %s", err);
        return 1;
    }
    logf_("game: %u block diff(s) loaded from %s", diffstoreCount(&g.diffs), state_dir);

    if (!unix_bind(&g, g.game_sock_path)) {
        diffstoreClose(&g.diffs);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
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

        tick(&g);
    }

    logf_("game: shutting down");
    close(g.unix_fd);
    diffstoreClose(&g.diffs);
    return 0;
}
