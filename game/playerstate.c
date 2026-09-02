/* For open()/fsync() below — the same declaration diffstore.c needs for the
 * same write-fsync-rename, and set for the same reason: -std=c11 alone hides
 * every POSIX prototype. */
#define _GNU_SOURCE

#include "playerstate.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../proto/bs_proto.h"
#include "validate.h"      /* BS_INV_STACK_MAX — armour counts share the inventory cap */
#include "world/crc32.h"
#include "world/inventory.h"  /* inventoryCanHold() — armour ids share the block id space */

/* On-disk format: a 20-byte header, then exactly the BS_APP_PLAYER_STATE
 * wire body (the packet minus its type byte) as the payload —
 *
 *   u32 magic      'BSP1' read little-endian (0x31505342)
 *   u32 version    1
 *   u32 size       BS_PLAYER_STATE_BODY_BYTES (45) — guards a layout change
 *   u32 crc32      over the payload
 *   u8  payload    flags, pose, armour+meters (see bs_proto.h)
 *
 * The same three-part shape inventory.dat uses (magic / version+size /
 * checksummed payload), so every save file under players/<label>/ fails
 * safe the same way: wrong magic, wrong version, wrong size or a failed
 * checksum means "treated as absent", never fatal and never half-applied.
 *
 * Crash safety follows diffstore.c's write-fsync-rename, NOT inventory.c's
 * remove-then-rename: the new bytes are written whole to "<path>.tmp",
 * fsync'd, and then renamed straight over the real path, whose directory
 * entry is fsync'd in turn. See playerStateSave() for why this file may do
 * what inventory.c may not, and player_state_recover() for the leftover
 * ".tmp" that a crash before the rename can still leave behind. */

#define PSTATE_FILE_NAME "player.dat"

/* 'BSP1' — Blocksmith Player state, format 1 — read as bytes little-endian,
 * named in the same shape as inventory.c's INVENTORY_MAGIC ('BSI1') so no
 * two files under a player's directory can ever be mistaken for another
 * even if a path got crossed. */
#define PSTATE_MAGIC     0x31505342u
#define PSTATE_VERSION   1u

#define PSTATE_HDR_BYTES  20u
#define PSTATE_FILE_BYTES (PSTATE_HDR_BYTES + BS_PLAYER_STATE_BODY_BYTES)

/* Meters are clamped into the ranges bs_proto.h documents for their wire
 * fields. A value outside them cannot come from this server's own encoder,
 * so it arrives either hand-edited or from something that is not us — the
 * CRC already vouches for the bytes, these bounds vouch for what they mean.
 */
#define PSTATE_METER_MAX     20.0f
#define PSTATE_PROGRESS_MAX   1.0f

static bool pstate_path(char *out, size_t cap, const char *dir)
{
    int n = snprintf(out, cap, "%s/%s", dir, PSTATE_FILE_NAME);
    return n >= 0 && (size_t)n < cap;
}

static bool pstate_tmp_path(const char *path, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s.tmp", path);
    return n >= 0 && (size_t)n < cap;
}

/* True unless the float is an IEEE NaN or infinity — a bit test rather than
 * math.h's isfinite() so this module stays free of any libm dependency, the
 * same dependency-free stance bs_proto.h's own float helpers take. */
static bool f32_finite(float v)
{
    uint32_t u;
    memcpy(&u, &v, sizeof u);
    return (u & 0x7F800000u) != 0x7F800000u;
}

static float clampf(float v, float lo, float hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

void playerStateInit(BsPlayerState *st)
{
    memset(st, 0, sizeof *st);
}

/* The armour+meters block, encoded — identical bytes whether they end up
 * inside a PLAYER_STATE body or a PLAYER_REPORT payload, which is the whole
 * point of the two messages sharing one layout after their type byte. */
static void encode_meters(uint8_t out[BS_PLAYER_METERS_BYTES],
                          const BsPlayerState *st)
{
    uint8_t *w = out;
    for (unsigned i = 0; i < BS_ARMOR_SLOTS; i++) {
        w[0] = st->armor[i][0];
        w[1] = st->armor[i][1];
        w += 2;
    }
    bs_put_u32(w,      st->xp_level);
    bs_put_f32(w + 4,  st->xp_progress);
    bs_put_f32(w + 8,  st->health);
    bs_put_f32(w + 12, st->hunger);
}

void playerStateEncodeBody(uint8_t out[BS_PLAYER_STATE_BODY_BYTES],
                           const BsPlayerState *st, unsigned flags)
{
    out[0] = (uint8_t)(flags & 0xFFu);

    /* Pose fields are written as explicit zeros whenever the caller did not
     * flag them valid, so a fresh-spawn snapshot is all-zero by construction
     * rather than by the caller remembering to zero the struct first. */
    const BsPlayerState zeroed = { .has_pose = false };
    const BsPlayerState *pose  = (flags & BS_PLAYER_STATE_FLAG_POSE) ? st : &zeroed;

    bs_put_f32(out + 1,  pose->x);
    bs_put_f32(out + 5,  pose->y);
    bs_put_f32(out + 9,  pose->z);
    bs_put_f32(out + 13, pose->yaw);
    bs_put_f32(out + 17, pose->pitch);

    encode_meters(out + 21, st);
}

/* Sanitises one raw {item, count} armour pair to what this build is willing
 * to store, per playerstate.h's documented per-field policy: the offending
 * SLOT is dropped to empty, its neighbours untouched, rather than the whole
 * blob being refused (that stance is reserved for the flags byte, which is
 * a statement about the format itself rather than about one value in it).
 *
 * Two independent rules, in order:
 *
 *   - the pairing rule INV_STATE's wire comment states for inventory slots,
 *     which holds here too: count 0 if and only if item 0. Anything else is
 *     a half-written pair.
 *   - the range rule handle_inv_action() already enforces on PICKUP and
 *     CONSUME (`inventoryCanHold(a) && b >= 1 && b <= BS_INV_STACK_MAX`,
 *     bsgame.c). Armour ids are the SAME id space as inventory item ids, so
 *     a slot may not hold an id the inventory path would have refused. This
 *     is the check that stops a modified client persisting an id this build
 *     does not carry, which comes back at the next join and would otherwise
 *     be trusted at face value.
 *
 *     v1.9.1: that range rule moved from `*item >= BS_BLOCK_COUNT` to
 *     `!inventoryCanHold(*item)`, in step with handle_inv_action()'s PICKUP
 *     and CONSUME guards — see bsgame.c's comment on that move for the full
 *     reasoning. inventoryCanHold(0) is false (0 is ITEM_NONE), so this still
 *     needs the pairing rule below to run first for a legitimate empty slot;
 *     it already does.
 *
 * The pairing rule runs first so that a legitimate empty slot (0, 0) reaches
 * the range rule already normalised and passes it, rather than the range
 * rule having to special-case zero. */
static void sanitise_armor_pair(uint8_t *item, uint8_t *count)
{
    if ((*item == 0) != (*count == 0)
        || !inventoryCanHold(*item)
        || (unsigned)*count > BS_INV_STACK_MAX) {
        *item  = 0;
        *count = 0;
    }
}

bool playerStateApplyMeters(BsPlayerState *st,
                            const uint8_t blk[BS_PLAYER_METERS_BYTES])
{
    bool changed = false;

    for (unsigned i = 0; i < BS_ARMOR_SLOTS; i++) {
        uint8_t item  = blk[i * 2];
        uint8_t count = blk[i * 2 + 1];
        sanitise_armor_pair(&item, &count);

        if (st->armor[i][0] != item || st->armor[i][1] != count) changed = true;
        st->armor[i][0] = item;
        st->armor[i][1] = count;
    }

    /* Every field below is sanitised into a local FIRST and only then
     * compared, so `changed` reports a difference in stored state rather
     * than in the bytes that arrived — two reports whose only difference is
     * one this function is about to clamp away are the same state, and must
     * not cost a rewrite of player.dat (see the header). */
    const uint32_t xp_level = bs_get_u32(blk + 8);
    if (st->xp_level != xp_level) changed = true;
    st->xp_level = xp_level;

    float xp_progress = bs_get_f32(blk + 12);
    xp_progress = f32_finite(xp_progress)
                ? clampf(xp_progress, 0.0f, PSTATE_PROGRESS_MAX) : 0.0f;
    if (st->xp_progress != xp_progress) changed = true;
    st->xp_progress = xp_progress;

    float health = bs_get_f32(blk + 16);
    health = f32_finite(health) ? clampf(health, 0.0f, PSTATE_METER_MAX) : 0.0f;
    if (st->health != health) changed = true;
    st->health = health;

    float hunger = bs_get_f32(blk + 20);
    hunger = f32_finite(hunger) ? clampf(hunger, 0.0f, PSTATE_METER_MAX) : 0.0f;
    if (st->hunger != hunger) changed = true;
    st->hunger = hunger;

    return changed;
}

bool playerStateDecodeBody(BsPlayerState *st,
                           const uint8_t body[BS_PLAYER_STATE_BODY_BYTES])
{
    unsigned flags = body[0];
    if ((flags & ~(unsigned)(BS_PLAYER_STATE_FLAG_POSE | BS_PLAYER_STATE_FLAG_EXT)) != 0) {
        return false;   /* bits this build never wrote — refuse the blob whole */
    }

    playerStateInit(st);

    if (flags & BS_PLAYER_STATE_FLAG_POSE) {
        st->x     = bs_get_f32(body + 1);
        st->y     = bs_get_f32(body + 5);
        st->z     = bs_get_f32(body + 9);
        st->yaw   = bs_get_f32(body + 13);
        st->pitch = bs_get_f32(body + 17);

        /* One non-finite coordinate poisons the whole pose: restoring half
         * a position would teleport less wrong but no more truthfully. */
        if (f32_finite(st->x) && f32_finite(st->y) && f32_finite(st->z)
            && f32_finite(st->yaw) && f32_finite(st->pitch)) {
            st->has_pose = true;
        } else {
            st->has_pose = false;
            st->x = 0.0f; st->y = 0.0f; st->z = 0.0f;
            st->yaw = 0.0f; st->pitch = 0.0f;
        }
    }

    if (flags & BS_PLAYER_STATE_FLAG_EXT) {
        /* "Changed" is meaningless here — playerStateInit() zeroed `st` two
         * lines up, so this is a fill, not an update. Only the live-report
         * path (bsgame.c) has a previous value to have changed from. */
        (void)playerStateApplyMeters(st, body + 21);
    }

    return true;
}

bool playerStateSave(const BsPlayerState *st, const char *dir)
{
    if (st == NULL || dir == NULL) return false;

    char path[512], tmp[512];
    if (!pstate_path(path, sizeof path, dir)) return false;
    if (!pstate_tmp_path(path, tmp, sizeof tmp)) return false;

    uint8_t buf[PSTATE_FILE_BYTES];

    /* A file exists, therefore there is extended state to restore — the EXT
     * bit is always part of what lands on disk; only the pose bit follows
     * the struct. */
    unsigned flags = BS_PLAYER_STATE_FLAG_EXT;
    if (st->has_pose) flags |= BS_PLAYER_STATE_FLAG_POSE;

    playerStateEncodeBody(buf + PSTATE_HDR_BYTES, st, flags);

    const uint32_t crc = crc32(buf + PSTATE_HDR_BYTES, BS_PLAYER_STATE_BODY_BYTES);
    bs_put_u32(buf + 0,  PSTATE_MAGIC);
    bs_put_u32(buf + 4,  PSTATE_VERSION);
    bs_put_u32(buf + 8,  BS_PLAYER_STATE_BODY_BYTES);
    bs_put_u32(buf + 12, crc);

    FILE *f = fopen(tmp, "wb");
    if (f == NULL) return false;

    const bool wrote_ok = fwrite(buf, 1, sizeof buf, f) == sizeof buf;

    /* Two flushes, because there are two buffers. fflush moves the bytes out
     * of stdio into the kernel — which is all fclose would have done, and all
     * this function used to do. fsync moves them out of the page cache onto
     * the device. Only the second one makes the rename below meaningful
     * across a power cut: without it the directory entry can reach the disk
     * before the data it names, which is the classic "the file is there and
     * it is 65 bytes of zeroes" outcome. This is the same write-fsync-rename
     * diffstore.c's compact() performs (diffstore.c:198), reached through
     * fileno() rather than a raw fd only because this module already had a
     * FILE* and the buffer above it to flush; diffstore.c opens raw because
     * it has neither. */
    const bool synced = wrote_ok && fflush(f) == 0 && fsync(fileno(f)) == 0;

    if (fclose(f) != 0 || !synced) {
        remove(tmp);
        return false;
    }

    /* NO remove(path) before this rename, and this is the one place this
     * module deliberately diverges from world/inventory.c, whose identical
     * comment says the opposite. inventory.c is compiled verbatim for the
     * 3DS and for Windows, where rename() genuinely refuses to replace an
     * existing destination and the remove is unavoidable. playerstate.c is
     * server-only and Linux-only, where rename(2) IS the atomic replace —
     * so the remove would not close a window, it would manufacture the exact
     * one it claims to close: an interval with no player.dat at all, ending
     * in a destroyed save if the rename then failed. Removed. */
    if (rename(tmp, path) != 0) return false;

    /* The rename is a directory modification, and it is no more durable than
     * the payload was: fsync the directory so the new entry survives too.
     * Losing it is survivable (the tmp is still there and the next load's
     * player_state_recover() promotes it) but only by accident — this is
     * what makes "playerStateSave returned true" mean the save is on the
     * device rather than merely scheduled. A directory that cannot be
     * opened or synced is not failed over: the payload is already durable
     * and the rename is already visible to everything on this kernel, so
     * reporting a failed save here would be a lie in the costlier
     * direction. */
    const int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }

    return true;
}

/* Promotes a leftover player.dat.tmp into place if the last save was cut
 * between removing the old file and renaming the new one over it — byte
 * for byte the recovery step inventory.c's inventoryRecover performs, for
 * the same reason: "never saved" and "saved, then interrupted right after"
 * should not be two different outcomes for the player. */
static void player_state_recover(const char *path)
{
    char tmp[512];
    if (!pstate_tmp_path(path, tmp, sizeof tmp)) return;

    FILE *t = fopen(tmp, "rb");
    if (t == NULL) return;             /* no interrupted save to recover */
    fclose(t);

    FILE *real = fopen(path, "rb");
    if (real != NULL) {                /* real file is fine; drop the tmp  */
        fclose(real);
        remove(tmp);
        return;
    }

    rename(tmp, path);
}

const char *playerStateLoadResultName(BsPlayerStateLoadResult r)
{
    switch (r) {
    case BS_PSTATE_LOAD_OK:          return "ok";
    case BS_PSTATE_LOAD_NO_FILE:     return "no player.dat";
    case BS_PSTATE_LOAD_BAD_PATH:    return "path too long";
    case BS_PSTATE_LOAD_SHORT_FILE:  return "truncated file";
    case BS_PSTATE_LOAD_BAD_MAGIC:   return "bad magic";
    case BS_PSTATE_LOAD_BAD_VERSION: return "unsupported version";
    case BS_PSTATE_LOAD_BAD_SIZE:    return "unexpected body size";
    case BS_PSTATE_LOAD_BAD_CRC:     return "checksum mismatch";
    case BS_PSTATE_LOAD_BAD_BODY:    return "unknown flag bits";
    }
    return "unknown";   /* an enum value from a future build; never NULL */
}

bool playerStateLoad(BsPlayerState *st, const char *dir,
                     BsPlayerStateLoadResult *why)
{
    /* Set before every early return rather than once at the end, because
     * which check stopped the load IS the information the caller wants and a
     * single exit would have to reconstruct it. `sink` removes the NULL test
     * from each of those returns; a caller that does not care pays one
     * stack slot for it. */
    BsPlayerStateLoadResult sink;
    if (why == NULL) why = &sink;
    *why = BS_PSTATE_LOAD_BAD_PATH;

    if (st == NULL || dir == NULL) return false;   /* caller bug, not I/O  */

    /* Every early return below leaves this in place, so "missing",
     * "truncated", "wrong magic/version/size", "bad checksum" and
     * "unknown flags" all degrade to exactly what playerStateInit()
     * produces — the caller learns "nothing usable" from the false
     * return alone, never a partially-filled struct. */
    playerStateInit(st);

    char path[512];
    if (!pstate_path(path, sizeof path, dir)) return false;

    player_state_recover(path);

    *why = BS_PSTATE_LOAD_NO_FILE;
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;       /* missing file: fresh spawn, not error */

    uint8_t buf[PSTATE_FILE_BYTES];
    const size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    *why = BS_PSTATE_LOAD_SHORT_FILE;
    if (n != sizeof buf) return false; /* short/truncated file: defaults   */

    *why = BS_PSTATE_LOAD_BAD_MAGIC;
    if (bs_get_u32(buf + 0) != PSTATE_MAGIC)              return false;
    *why = BS_PSTATE_LOAD_BAD_VERSION;
    if (bs_get_u32(buf + 4) != PSTATE_VERSION)            return false;
    *why = BS_PSTATE_LOAD_BAD_SIZE;
    if (bs_get_u32(buf + 8) != BS_PLAYER_STATE_BODY_BYTES) return false;

    const uint32_t stored   = bs_get_u32(buf + 12);
    const uint32_t computed = crc32(buf + PSTATE_HDR_BYTES, BS_PLAYER_STATE_BODY_BYTES);
    *why = BS_PSTATE_LOAD_BAD_CRC;
    if (stored != computed) return false;                 /* corrupt payload */

    *why = BS_PSTATE_LOAD_BAD_BODY;
    if (!playerStateDecodeBody(st, buf + PSTATE_HDR_BYTES)) return false;

    *why = BS_PSTATE_LOAD_OK;
    return true;
}
