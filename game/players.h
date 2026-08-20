/* players.h — the connected-player table.
 *
 * A flat array, not a hash map: BS_GAME_MAX_PLAYERS is small enough that a
 * linear scan is both simpler and faster than anything with an index to
 * maintain, the same call World's own WORLD_MAP_SLOTS sizing note (in
 * source/world/world.h) makes for a different structure at a different
 * scale.
 */

#ifndef BS_GAME_PLAYERS_H
#define BS_GAME_PLAYERS_H

#include <stdbool.h>
#include <stdint.h>

/* Mirrors bsgate's BS_MAX_SESSIONS (server/gateway/bsgate.c). Duplicated
 * rather than shared because it isn't part of the wire protocol — it is
 * just the largest number of concurrent sids the gate can ever hand us, and
 * bsgame needs room for exactly that many, not more. */
#define BS_GAME_MAX_PLAYERS 16u

/* Matches BS_ALLOW_LABEL_MAX (server/gateway/allowlist.h) — the label
 * arrives from the gate's JOIN message already sized to this. */
#define BS_GAME_LABEL_MAX 32u

/* Per-player token bucket for edits. This is a second, independent rate
 * limit from bsgate's packet-level one (server/gateway/ratelimit.h): that
 * one guards raw UDP/handshake volume before authentication ever happens;
 * this one guards application-level abuse from a session that is
 * authenticated but running a modified or buggy client. Same scaled-integer
 * technique as server/gateway/ratelimit.c, so a refill shorter than one
 * whole token still makes progress. */
#define BS_EDIT_SCALE     64u
#define BS_EDIT_BURST     40u   /* edits a player may spend in one burst        */
#define BS_EDIT_REFILL_MS 50u   /* one token back per this many ms (20/s sustained) */

/* Per-player column subscription set (V127-A). A render-distance-4 client
 * needs roughly 81 columns (a 9x9 footprint), so this leaves close to 3x
 * headroom for the window while a client is subscribing to a wider ring
 * before it has unsubscribed the old one — without a client ever needing to
 * be trusted to stay under any particular render distance. Fixed-size and
 * linearly scanned, like BS_GAME_MAX_PLAYERS itself: at this size an array is
 * both simpler and cheaper than a hash set with a table to maintain, and the
 * cost is trivial either way — 256 * 8 bytes = 2 KiB per player, 32 KiB for
 * the whole BS_GAME_MAX_PLAYERS table. */
#define BS_PLAYER_SUB_MAX 256u

typedef struct {
    int32_t cx, cz;
} BsColumn;

typedef struct {
    bool     used;
    uint32_t sid;
    char     label[BS_GAME_LABEL_MAX];

    float x, y, z;
    float yaw, pitch;
    bool  has_pos;    /* at least one POS_UPDATE has arrived from them   */
    bool  pos_dirty;  /* pose changed since the last broadcast tick      */

    uint64_t last_seen_ms;  /* last time any message from them was accepted */

    uint16_t edit_tokens;   /* scaled by BS_EDIT_SCALE */
    uint64_t edit_last_ms;

    /* V127-A per-column diff subscriptions. `joined_ms` is set once, at
     * JOIN, and never touched again — unlike last_seen_ms it must NOT move
     * on every message, because bsgame.c's legacy-WORLD_SYNC grace window
     * (BS_CHUNK_LEGACY_GRACE_MS) is measured from the moment this player
     * connected, not from their last activity. */
    BsColumn subs[BS_PLAYER_SUB_MAX];
    uint16_t sub_count;
    bool     chunk_sub_seen;    /* this player has sent at least one CHUNK_SUB */
    bool     legacy_sync_sent;  /* the grace-window full WORLD_SYNC already went out */
    uint64_t joined_ms;
} BsPlayer;

typedef struct {
    BsPlayer p[BS_GAME_MAX_PLAYERS];
} BsPlayers;

void playersInit(BsPlayers *pl);

/* NULL if no player holds this sid. */
BsPlayer *playerBySid(BsPlayers *pl, uint32_t sid);

/* NULL if the table is full. `label` is copied and truncated to fit. */
BsPlayer *playerAlloc(BsPlayers *pl, uint32_t sid, const char *label, uint64_t now_ms);

void playerFree(BsPlayer *p);

/* Consumes one edit token if the bucket has one. False — and nothing
 * changed — if it is empty, meaning the caller must drop the edit. */
bool playerEditAllow(BsPlayer *p, uint64_t now_ms);

/* Adds (cx, cz) to `p`'s subscription set. Idempotent — subscribing to a
 * column already held is a harmless no-op, since the client is free to
 * re-assert a column it thinks it might have lost (e.g. after a dropped
 * UNSUB/SUB pair on lossy Wi-Fi). False only when the set is already at
 * BS_PLAYER_SUB_MAX and `cx, cz` is not already in it — a modified or
 * confused client asking for more columns than any real render distance
 * needs, refused the same way diffstoreApply() refuses a full table rather
 * than growing it. */
bool playerSubAdd(BsPlayer *p, int32_t cx, int32_t cz);

/* Removes (cx, cz) if present; a no-op if it was never subscribed (the
 * client may UNSUB a column it never successfully SUBed, e.g. after a
 * dropped packet — that is not an error). */
void playerSubRemove(BsPlayer *p, int32_t cx, int32_t cz);

/* True if `p` currently holds a live subscription to (cx, cz). */
bool playerSubHas(const BsPlayer *p, int32_t cx, int32_t cz);

#endif /* BS_GAME_PLAYERS_H */
