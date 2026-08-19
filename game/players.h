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

#endif /* BS_GAME_PLAYERS_H */
