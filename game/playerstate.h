/* playerstate.h — persistent per-player state beyond the inventory.
 *
 * Pose, armour and the XP/health/hunger meters, held in memory inside each
 * BsPlayer (players.h) and mirrored to <state-dir>/players/<label>/player.dat
 * so they survive a restart — the same directory inventory.dat lives in, and
 * the same crash-safety mechanism (see the Save / load section below).
 *
 * This module owns two serialisations of one truth:
 *
 *   - the wire body shared with bs_proto.h's BS_APP_PLAYER_STATE (the 45
 *     bytes after the type byte), which is ALSO the file payload — the file
 *     is literally the state snapshot, header'd and checksummed;
 *   - the armour+meters block shared with BS_APP_PLAYER_REPORT (the 24 bytes
 *     after its type byte), identical layout in both messages, so one
 *     decoder serves the restore path and the capture path.
 *
 * Like world/inventory.c, this is plain C with no network or crypto
 * dependency, so the encode/sanitise logic can be exercised by host tests
 * rather than trusted.
 */

#ifndef BS_GAME_PLAYERSTATE_H
#define BS_GAME_PLAYERSTATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../proto/bs_proto.h"

/* The STATE packet minus its type byte — what the file stores and what
 * playerStateEncodeBody()/playerStateDecodeBody() speak. Kept derived from
 * BS_PLAYER_STATE_BYTES so the wire constant stays the single source of
 * truth. */
#define BS_PLAYER_STATE_BODY_BYTES (BS_PLAYER_STATE_BYTES - BS_APP_HDR_BYTES)

typedef struct {
    bool  has_pose;             /* x/y/z/yaw/pitch below are meaningful      */
    float x, y, z;
    float yaw, pitch;

    uint8_t armor[BS_ARMOR_SLOTS][2];   /* head/chest/legs/feet {item,count} */

    uint32_t xp_level;
    float    xp_progress;       /* 0..1 through the current level            */
    float    health;            /* 0..20                                     */
    float    hunger;            /* 0..20                                     */
} BsPlayerState;

/* Zeroes everything, including has_pose — exactly what a brand-new player
 * keeps until their first POS_UPDATE or PLAYER_REPORT, and what a missing,
 * corrupt or unreadable save degrades to. */
void playerStateInit(BsPlayerState *st);

/* Encodes the 45-byte STATE body: flags byte first, then pose (all five
 * floats written as zero when BS_PLAYER_STATE_FLAG_POSE is not set — the
 * caller's flags word is authoritative, never re-derived here), then the
 * armour+meters block. `flags` carries BS_PLAYER_STATE_FLAG_* values. */
void playerStateEncodeBody(uint8_t out[BS_PLAYER_STATE_BODY_BYTES],
                           const BsPlayerState *st, unsigned flags);

/* Decodes a 45-byte STATE body into `st`, which is initialised first — a
 * body that fails validation leaves the same all-zero result a missing file
 * would have produced, never a half-applied one. Field-level sanitisation
 * mirrors inventoryLoad()'s per-slot defence-in-depth: a non-finite or
 * out-of-range value is clamped or dropped individually rather than
 * poisoning the rest of the snapshot (the CRC has already vouched that the
 * bytes are the ones some server wrote, so this guards hand-edited files
 * and nothing else). False only when the flags byte itself carries bits
 * this build does not know — a file or packet from somewhere else entirely,
 * refused whole. */
bool playerStateDecodeBody(BsPlayerState *st,
                           const uint8_t body[BS_PLAYER_STATE_BODY_BYTES]);

/* Applies the shared armour+meters block (BS_PLAYER_METERS_BYTES bytes:
 * armour[4][2], u32 xp_level, f32 xp_progress, f32 health, f32 hunger —
 * the exact layout both PLAYER_STATE's body and PLAYER_REPORT carry after
 * their type byte). Values are sanitised with the same rules
 * playerStateDecodeBody() uses: an untrusted client's report gets no more
 * benefit of the doubt than a hand-edited file.
 *
 * Returns true when the SANITISED result differs from what `st` already
 * held — i.e. whether this block was worth persisting. It is deliberately
 * the post-sanitisation comparison: two reports that differ only in bytes
 * this function throws away are the same state, and re-writing player.dat
 * for them would be pure disk churn. The knowledge of which fields this
 * block owns stays here rather than being re-derived by the caller, where
 * it would silently rot the next time a field is added. */
bool playerStateApplyMeters(BsPlayerState *st,
                            const uint8_t blk[BS_PLAYER_METERS_BYTES]);

/* Which check a playerStateLoad() call stopped at. Exists so the operator
 * can be told WHY a player came back as a fresh spawn: every failure below
 * degrades to the same silent, identical-looking outcome for the player, so
 * without this a corrupt save and a first-ever join are indistinguishable in
 * the log — and the corrupt one is the one somebody needs to know about. The
 * enum is returned rather than a message string because this module has no
 * logging dependency and is not about to grow one; naming the failure is
 * bsgame.c's job, detecting it is this module's. */
typedef enum {
    BS_PSTATE_LOAD_OK = 0,      /* a valid save was found and applied       */
    BS_PSTATE_LOAD_NO_FILE,     /* no player.dat: first join, not an error  */
    BS_PSTATE_LOAD_BAD_PATH,    /* dir too long to hold player.dat          */
    BS_PSTATE_LOAD_SHORT_FILE,  /* truncated — fewer bytes than the format  */
    BS_PSTATE_LOAD_BAD_MAGIC,
    BS_PSTATE_LOAD_BAD_VERSION,
    BS_PSTATE_LOAD_BAD_SIZE,    /* header's body size is not this build's   */
    BS_PSTATE_LOAD_BAD_CRC,     /* payload checksum mismatch: torn write    */
    BS_PSTATE_LOAD_BAD_BODY,    /* flags byte carries bits we never wrote   */
} BsPlayerStateLoadResult;

/* Loads dir/player.dat into `st`. True only when a valid save was found
 * and applied — unlike inventoryLoad(), whose caller needs no distinction,
 * this one does: JOIN's PLAYER_STATE flags byte must tell the client
 * "restored" (flags valid) apart from "fresh spawn" (flags zero), and a
 * corrupt file must be reported as the latter. Always leaves `st` fully
 * valid either way, so "false" simply means "keep what init gave you".
 * A leftover player.dat.tmp from an interrupted save is promoted or
 * discarded before reading, exactly as inventoryLoad() does.
 *
 * `why`, when not NULL, receives the check that stopped the load — see
 * BsPlayerStateLoadResult. It is always written, including on success. */
bool playerStateLoad(BsPlayerState *st, const char *dir,
                     BsPlayerStateLoadResult *why);

/* A short, stable, human-readable name for `r`, for logging. Never NULL. */
const char *playerStateLoadResultName(BsPlayerStateLoadResult r);

/* Saves `st` to dir/player.dat. False on any IO failure, in which case the
 * previous save (if any) is untouched — nothing touches the real path until
 * the replacement is known-good and closed. The extended-state flag is
 * always set on disk (a file exists, therefore there is something to
 * restore); the pose flag follows `st->has_pose`.
 *
 * True means durable, not merely written: the payload is fsync'd before the
 * rename and the directory entry after it, so a host power cut immediately
 * on return cannot resurrect the previous save or an all-zero file. */
bool playerStateSave(const BsPlayerState *st, const char *dir);

#endif /* BS_GAME_PLAYERSTATE_H */
