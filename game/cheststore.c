/* For open()/fsync() below — the same declaration diffstore.c and
 * playerstate.c need, for the same reason: -std=c11 alone hides them. */
#define _GNU_SOURCE

#include "cheststore.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "validate.h"
#include "world/block.h"       /* BLOCK_CHEST, for bsEditValid() at load   */
#include "world/inventory.h"   /* inventoryCanHold(), INV_STACK_MAX        */

/* On-disk format: an 8-byte magic, then fixed 28-byte little-endian records
 * — x, y, z (int32) + BS_CHEST_SLOTS x (item u8, count u8). Fixed width and
 * delimiter-free like block_diffs.bin, and the record body after the
 * position is byte-for-byte the CHEST_STATE wire body, so there is exactly
 * one layout to keep right. Unlike block_diffs.bin this is NOT an append
 * log: a chest's contents are mutable state, so the whole file is rewritten
 * (cheststoreFlush) — see BS_CHEST_FLUSH_MS in the header. */
#define BS_CHEST_MAGIC     "BSCHEST1"
#define BS_CHEST_MAGIC_LEN 8u
#define BS_CHEST_REC_BYTES (4u * 3u + BS_CHEST_SLOTS * 2u)   /* 28 */

_Static_assert(BS_CHEST_REC_BYTES == BS_CHEST_STATE_BYTES - BS_APP_HDR_BYTES,
               "a chests.bin record must be exactly a CHEST_STATE body");
_Static_assert(INV_STACK_MAX == BS_INV_STACK_MAX,
               "chest stack cap must be the client's INV_STACK_MAX");

static BsChest *find_mut(BsChestStore *cs, int32_t x, int32_t y, int32_t z)
{
    for (uint32_t i = 0; i < cs->count; i++) {
        BsChest *c = &cs->entry[i];
        if (c->x == x && c->y == y && c->z == z) return c;
    }
    return NULL;
}

const BsChest *cheststoreFind(const BsChestStore *cs, int32_t x, int32_t y, int32_t z)
{
    for (uint32_t i = 0; i < cs->count; i++) {
        const BsChest *c = &cs->entry[i];
        if (c->x == x && c->y == y && c->z == z) return c;
    }
    return NULL;
}

const BsChest *cheststoreAt(const BsChestStore *cs, uint32_t i)
{
    return i < cs->count ? &cs->entry[i] : NULL;
}

/* NULL only when the table is full. */
static BsChest *find_or_create(BsChestStore *cs, int32_t x, int32_t y, int32_t z)
{
    BsChest *c = find_mut(cs, x, y, z);
    if (c != NULL) return c;
    if (cs->count >= BS_CHEST_MAX) return NULL;

    c = &cs->entry[cs->count++];
    memset(c, 0, sizeof *c);
    c->x = x;
    c->y = y;
    c->z = z;
    return c;
}

bool cheststoreRemove(BsChestStore *cs, int32_t x, int32_t y, int32_t z)
{
    BsChest *c = find_mut(cs, x, y, z);
    if (c == NULL) return false;

    /* Swap the last entry into the hole: order carries no meaning here. */
    const uint32_t last = cs->count - 1u;
    *c = cs->entry[last];
    memset(&cs->entry[last], 0, sizeof cs->entry[last]);
    cs->count = last;
    cs->dirty = true;
    return true;
}

uint8_t cheststoreRoom(const BsChestStore *cs, int32_t x, int32_t y, int32_t z,
                       uint8_t slot, uint8_t item)
{
    if (slot >= BS_CHEST_SLOTS || item == 0) return 0;

    const BsChest *c = cheststoreFind(cs, x, y, z);
    if (c == NULL) return (uint8_t)(cs->count >= BS_CHEST_MAX ? 0u : BS_INV_STACK_MAX);

    const uint8_t held_item  = c->slot[slot][0];
    const uint8_t held_count = c->slot[slot][1];
    if (held_count == 0) return (uint8_t)BS_INV_STACK_MAX;
    if (held_item != item) return 0;
    return (uint8_t)(BS_INV_STACK_MAX - held_count);
}

bool cheststoreDeposit(BsChestStore *cs, int32_t x, int32_t y, int32_t z,
                       uint8_t slot, uint8_t item, uint8_t units)
{
    if (slot >= BS_CHEST_SLOTS) return false;
    if (item == 0) return false;
    if (units < 1u || units > (uint8_t)BS_INV_STACK_MAX) return false;

    /* Room is answered before anything is created, so a refused deposit
     * into a chest with no record leaves no empty record behind. */
    if (units > cheststoreRoom(cs, x, y, z, slot, item)) return false;

    BsChest *c = find_or_create(cs, x, y, z);
    if (c == NULL) return false;   /* full table — cheststoreRoom already said 0 */

    c->slot[slot][0] = item;
    c->slot[slot][1] = (uint8_t)(c->slot[slot][1] + units);
    cs->dirty = true;
    return true;
}

uint8_t cheststoreWithdraw(BsChestStore *cs, int32_t x, int32_t y, int32_t z,
                           uint8_t slot, uint8_t units, uint8_t *item_out)
{
    if (slot >= BS_CHEST_SLOTS) return 0;

    BsChest *c = find_mut(cs, x, y, z);
    if (c == NULL) return 0;

    const uint8_t held = c->slot[slot][1];
    if (held == 0) return 0;
    if (units == 0) units = held;
    if (units > held) return 0;

    if (item_out != NULL) *item_out = c->slot[slot][0];

    const uint8_t left = (uint8_t)(held - units);
    c->slot[slot][1] = left;
    if (left == 0) c->slot[slot][0] = 0;
    cs->dirty = true;
    return units;
}

/* ------------------------------------------------------------ wire codec */

bool chestActionDecode(const uint8_t *msg, size_t len, BsChestAction *out)
{
    if (len != BS_CHEST_ACTION_BYTES) return false;
    if (msg[0] != BS_APP_CHEST_ACTION) return false;

    out->op    = msg[1];
    out->x     = bs_get_i32(msg + 2);
    out->y     = bs_get_i32(msg + 6);
    out->z     = bs_get_i32(msg + 10);
    out->a     = msg[14];
    out->b     = msg[15];
    out->count = msg[16];
    return true;
}

static void encode_body(uint8_t out[BS_CHEST_REC_BYTES], int32_t x, int32_t y, int32_t z,
                        const BsChest *c)
{
    bs_put_i32(out,     x);
    bs_put_i32(out + 4, y);
    bs_put_i32(out + 8, z);
    for (unsigned i = 0; i < BS_CHEST_SLOTS; i++) {
        out[12u + i * 2u]      = c != NULL ? c->slot[i][0] : 0;
        out[12u + i * 2u + 1u] = c != NULL ? c->slot[i][1] : 0;
    }
}

void chestStateEncode(uint8_t out[BS_CHEST_STATE_BYTES], int32_t x, int32_t y, int32_t z,
                      const BsChest *c)
{
    out[0] = BS_APP_CHEST_STATE;
    encode_body(out + BS_APP_HDR_BYTES, x, y, z, c);
}

/* ------------------------------------------------------------- disk */

static bool chest_tmp_path(const char *path, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s.tmp", path);
    return n > 0 && (size_t)n < cap;
}

/* Reads one record into `c`, sanitising every field (see cheststoreOpen's
 * contract in the header). False when the record as a whole is unusable. */
static bool decode_record(const uint8_t rec[BS_CHEST_REC_BYTES], BsChest *c)
{
    memset(c, 0, sizeof *c);
    c->x = bs_get_i32(rec);
    c->y = bs_get_i32(rec + 4);
    c->z = bs_get_i32(rec + 8);
    if (!bsEditValid(c->x, c->y, c->z, BLOCK_CHEST)) return false;

    for (unsigned i = 0; i < BS_CHEST_SLOTS; i++) {
        uint8_t item  = rec[12u + i * 2u];
        uint8_t count = rec[12u + i * 2u + 1u];
        if (item == 0 || count == 0 || !inventoryCanHold(item)) {
            item  = 0;
            count = 0;
        } else if (count > (uint8_t)BS_INV_STACK_MAX) {
            count = (uint8_t)BS_INV_STACK_MAX;
        }
        c->slot[i][0] = item;
        c->slot[i][1] = count;
    }
    return true;
}

bool cheststoreOpen(BsChestStore *cs, const char *dir, char *err, size_t errlen,
                    unsigned *dropped)
{
    memset(cs, 0, sizeof *cs);
    if (dropped != NULL) *dropped = 0;

    if ((size_t)snprintf(cs->path, sizeof cs->path, "%s/chests.bin", dir) >= sizeof cs->path) {
        snprintf(err, errlen, "state dir path too long: %s", dir);
        return false;
    }

    FILE *f = fopen(cs->path, "rb");
    if (f == NULL) {
        if (errno == ENOENT) return true;   /* fresh world: nothing to load */
        snprintf(err, errlen, "open %s: %s", cs->path, strerror(errno));
        return false;
    }

    uint8_t magic[BS_CHEST_MAGIC_LEN];
    if (fread(magic, 1, sizeof magic, f) != sizeof magic
        || memcmp(magic, BS_CHEST_MAGIC, BS_CHEST_MAGIC_LEN) != 0) {
        snprintf(err, errlen, "%s: not a chests.bin (bad magic)", cs->path);
        fclose(f);
        return false;
    }

    for (;;) {
        uint8_t rec[BS_CHEST_REC_BYTES];
        const size_t got = fread(rec, 1, sizeof rec, f);
        if (got == 0) break;
        if (got != sizeof rec) {
            snprintf(err, errlen, "%s: torn trailing record (%zu of %u bytes)",
                     cs->path, got, (unsigned)BS_CHEST_REC_BYTES);
            fclose(f);
            return false;
        }

        BsChest c;
        if (!decode_record(rec, &c) || cheststoreFind(cs, c.x, c.y, c.z) != NULL
            || cs->count >= BS_CHEST_MAX) {
            if (dropped != NULL) (*dropped)++;
            continue;
        }
        cs->entry[cs->count++] = c;
    }

    if (ferror(f)) {
        snprintf(err, errlen, "read %s: %s", cs->path, strerror(errno));
        fclose(f);
        return false;
    }
    fclose(f);
    return true;
}

static bool write_all(int fd, const uint8_t *p, size_t len)
{
    while (len > 0) {
        const ssize_t n = write(fd, p, len);
        if (n <= 0) return false;
        p   += n;
        len -= (size_t)n;
    }
    return true;
}

static bool write_file(const BsChestStore *cs)
{
    char tmp[sizeof cs->path + 8];
    if (!chest_tmp_path(cs->path, tmp, sizeof tmp)) {
        errno = ENAMETOOLONG;
        return false;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;

    bool ok = write_all(fd, (const uint8_t *)BS_CHEST_MAGIC, BS_CHEST_MAGIC_LEN);
    for (uint32_t i = 0; ok && i < cs->count; i++) {
        uint8_t rec[BS_CHEST_REC_BYTES];
        const BsChest *c = &cs->entry[i];
        encode_body(rec, c->x, c->y, c->z, c);
        ok = write_all(fd, rec, sizeof rec);
    }
    if (ok) ok = fsync(fd) == 0;

    if (!ok) {
        const int saved = errno;
        close(fd);
        remove(tmp);
        errno = saved;
        return false;
    }
    close(fd);

    if (rename(tmp, cs->path) != 0) {
        const int saved = errno;
        remove(tmp);
        errno = saved;
        return false;
    }

    /* The directory entry too, so a power cut right after the rename
     * cannot bring the previous file back — playerStateSave()'s reasoning.
     * Losing this one is survivable (best effort, like there). */
    char dirpath[sizeof cs->path];
    snprintf(dirpath, sizeof dirpath, "%s", cs->path);
    char *slash = strrchr(dirpath, '/');
    if (slash != NULL) {
        *slash = '\0';
        int dfd = open(dirpath, O_RDONLY);
        if (dfd >= 0) {
            (void)fsync(dfd);
            close(dfd);
        }
    }
    return true;
}

int cheststoreFlush(BsChestStore *cs, uint64_t now_ms, bool force)
{
    if (!cs->dirty) return 0;
    if (!force && now_ms - cs->last_flush_ms < BS_CHEST_FLUSH_MS) return 0;

    /* Stamped before the attempt, success or not, so a persistently failing
     * disk is retried (and reported by the caller) once a second, not once
     * a tick. */
    cs->last_flush_ms = now_ms;
    if (!write_file(cs)) return -1;
    cs->dirty = false;
    return 1;
}
