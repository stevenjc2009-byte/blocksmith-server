#include "playerstate.h"

#include <stdio.h>
#include <string.h>

#include "../proto/bs_proto.h"
#include "world/crc32.h"

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
 * Crash safety copies inventory.c's proven mechanism rather than inventing
 * one: the new bytes are written whole to "<path>.tmp", flushed via fclose,
 * the real path is removed, and only then is the tmp renamed over it. A
 * power cut between the remove and the rename is recovered on the next
 * load by promoting the leftover ".tmp" back into place — see
 * player_state_recover() below. */

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

void playerStateApplyMeters(BsPlayerState *st,
                            const uint8_t blk[BS_PLAYER_METERS_BYTES])
{
    for (unsigned i = 0; i < BS_ARMOR_SLOTS; i++) {
        uint8_t item  = blk[i * 2];
        uint8_t count = blk[i * 2 + 1];

        /* The pairing rule INV_STATE's wire comment states for inventory
         * slots holds here too: count 0 if and only if item 0. Anything
         * else is a half-written pair — dropped to empty, not passed on. */
        if ((item == 0) != (count == 0)) {
            item  = 0;
            count = 0;
        }
        st->armor[i][0] = item;
        st->armor[i][1] = count;
    }

    st->xp_level = bs_get_u32(blk + 8);

    st->xp_progress = bs_get_f32(blk + 12);
    if (!f32_finite(st->xp_progress)) st->xp_progress = 0.0f;
    else st->xp_progress = clampf(st->xp_progress, 0.0f, PSTATE_PROGRESS_MAX);

    st->health = bs_get_f32(blk + 16);
    if (!f32_finite(st->health)) st->health = 0.0f;
    else st->health = clampf(st->health, 0.0f, PSTATE_METER_MAX);

    st->hunger = bs_get_f32(blk + 20);
    if (!f32_finite(st->hunger)) st->hunger = 0.0f;
    else st->hunger = clampf(st->hunger, 0.0f, PSTATE_METER_MAX);
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
        playerStateApplyMeters(st, body + 21);
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

    /* fclose is the flush — the same reasoning inventory.c records next to
     * its own: without it the rename below can promote a buffer, not data. */
    if (fclose(f) != 0 || !wrote_ok) {
        remove(tmp);
        return false;
    }

    /* remove-before-rename because a plain rename() refuses to replace an
     * existing destination; failing only because the real file does not
     * exist yet (first-ever save) is expected and fine. */
    remove(path);

    if (rename(tmp, path) != 0) return false;

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

bool playerStateLoad(BsPlayerState *st, const char *dir)
{
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

    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;       /* missing file: fresh spawn, not error */

    uint8_t buf[PSTATE_FILE_BYTES];
    const size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n != sizeof buf) return false; /* short/truncated file: defaults   */

    if (bs_get_u32(buf + 0) != PSTATE_MAGIC)              return false;
    if (bs_get_u32(buf + 4) != PSTATE_VERSION)            return false;
    if (bs_get_u32(buf + 8) != BS_PLAYER_STATE_BODY_BYTES) return false;

    const uint32_t stored   = bs_get_u32(buf + 12);
    const uint32_t computed = crc32(buf + PSTATE_HDR_BYTES, BS_PLAYER_STATE_BODY_BYTES);
    if (stored != computed) return false;                 /* corrupt payload */

    return playerStateDecodeBody(st, buf + PSTATE_HDR_BYTES);
}
