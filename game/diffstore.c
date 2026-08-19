#define _GNU_SOURCE

#include "diffstore.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../proto/bs_proto.h"
#include "validate.h"

/* On-disk format: an 8-byte magic, then fixed 16-byte little-endian records
 * — x, y, z (int32) + block id (uint8) + 3 reserved zero bytes. Fixed width
 * and delimiter-free was chosen over anything richer (a text format, a
 * length-prefixed one) because:
 *
 *   - appending one new edit is a single write() at the current end of
 *     file, no seeking and no rewriting anything already there, which is
 *     what "runs every time a player breaks or places a block" wants;
 *   - a crash mid-write leaves at most one torn trailing record, and it is
 *     trivially detected — (file size - 8) % 16 != 0 — and discarded
 *     without touching anything before it;
 *   - replay is "last record for a coordinate wins", so there is no delete
 *     opcode: undoing an edit is just writing a new one, which matches the
 *     diffs-against-deterministic-terrain model this whole server exists
 *     to serve (see the header comment on diffstore.h).
 *
 * The file is compacted to exactly the live set on every clean open (see
 * diffstoreOpen), so it only grows across edits made *during* one running
 * session rather than over the game's entire lifetime. */
#define BS_DIFF_MAGIC     "BSGDIFF1"
#define BS_DIFF_MAGIC_LEN 8u
#define BS_DIFF_REC_BYTES 16u

static void encode_record(uint8_t out[BS_DIFF_REC_BYTES], const BsDiff *d)
{
    bs_put_i32(out,     d->x);
    bs_put_i32(out + 4, d->y);
    bs_put_i32(out + 8, d->z);
    out[12] = d->block;
    out[13] = 0; out[14] = 0; out[15] = 0;
}

static void decode_record(const uint8_t in[BS_DIFF_REC_BYTES], BsDiff *d)
{
    d->x = bs_get_i32(in);
    d->y = bs_get_i32(in + 4);
    d->z = bs_get_i32(in + 8);
    d->block = in[12];
}

/* Cache index, not a security boundary — a collision just costs another
 * probe step. Same multiplicative-mixing style as
 * server/gateway/ratelimit.c's slot_index(). */
static uint32_t diff_hash(int32_t x, int32_t y, int32_t z)
{
    uint32_t h = (uint32_t)x * 2654435761u;
    h ^= (uint32_t)y * 2246822519u;
    h ^= (uint32_t)z * 3266489917u;
    h ^= h >> 15;
    return h;
}

/* Finds the slot for (x, y, z): an existing entry, or the first empty slot
 * on its probe sequence. NULL only if the whole table was scanned without
 * either — cannot happen while count stays below BS_DIFF_MAX at a 0.5 load
 * factor, but a fixed-size open-addressing scan gets a bound checked anyway
 * rather than trusted to terminate on its own. */
static int32_t *diff_slot(BsDiffStore *ds, int32_t x, int32_t y, int32_t z, bool *found)
{
    uint32_t i = diff_hash(x, y, z) & (BS_DIFF_SLOTS - 1u);

    for (uint32_t probes = 0; probes < BS_DIFF_SLOTS; probes++) {
        int32_t *slot = &ds->table[i];
        if (*slot == -1) { *found = false; return slot; }

        const BsDiff *e = &ds->entry[(uint32_t)*slot];
        if (e->x == x && e->y == y && e->z == z) { *found = true; return slot; }

        i = (i + 1u) & (BS_DIFF_SLOTS - 1u);
    }
    *found = false;
    return NULL;
}

static bool diff_upsert_memory(BsDiffStore *ds, int32_t x, int32_t y, int32_t z, uint8_t block)
{
    bool found = false;
    int32_t *slot = diff_slot(ds, x, y, z, &found);
    if (slot == NULL) return false;

    if (found) {
        ds->entry[(uint32_t)*slot].block = block;
        return true;
    }

    if (ds->count >= BS_DIFF_MAX) return false;

    uint32_t idx = ds->count++;
    ds->entry[idx].x     = x;
    ds->entry[idx].y     = y;
    ds->entry[idx].z     = z;
    ds->entry[idx].block = block;
    *slot = (int32_t)idx;
    return true;
}

const BsDiff *diffstoreFind(const BsDiffStore *ds, int32_t x, int32_t y, int32_t z)
{
    uint32_t i = diff_hash(x, y, z) & (BS_DIFF_SLOTS - 1u);

    for (uint32_t probes = 0; probes < BS_DIFF_SLOTS; probes++) {
        int32_t slot = ds->table[i];
        if (slot == -1) return NULL;

        const BsDiff *e = &ds->entry[(uint32_t)slot];
        if (e->x == x && e->y == y && e->z == z) return e;

        i = (i + 1u) & (BS_DIFF_SLOTS - 1u);
    }
    return NULL;
}

const BsDiff *diffstoreAt(const BsDiffStore *ds, uint32_t index)
{
    if (index >= ds->count) return NULL;
    return &ds->entry[index];
}

/* Reads every whole record after the magic and replays it into memory.
 * A torn trailing record (a crash mid-append) is discarded with a warning
 * rather than failing the load. A record whose values fail bsEditValid() —
 * disk is not more trusted than the network — is dropped the same way: the
 * file may have been hand-edited or come from an older, looser build. */
static bool load_records(BsDiffStore *ds, int fd, uint64_t file_size, char *err, size_t errlen)
{
    uint64_t body          = file_size - BS_DIFF_MAGIC_LEN;
    uint64_t whole_records = body / BS_DIFF_REC_BYTES;
    uint64_t torn          = body % BS_DIFF_REC_BYTES;

    if (torn != 0) {
        fprintf(stderr, "bsgame: %s has a %llu-byte torn trailing record, discarding it\n",
                ds->path, (unsigned long long)torn);
    }

    for (uint64_t i = 0; i < whole_records; i++) {
        uint8_t rec[BS_DIFF_REC_BYTES];
        ssize_t r = read(fd, rec, sizeof rec);
        if (r != (ssize_t)sizeof rec) {
            snprintf(err, errlen, "short read replaying %s (record %llu of %llu)",
                     ds->path, (unsigned long long)i, (unsigned long long)whole_records);
            return false;
        }

        BsDiff d;
        decode_record(rec, &d);

        if (!bsEditValid(d.x, d.y, d.z, d.block)) {
            fprintf(stderr, "bsgame: %s: record %llu is out of range, dropping (%d,%d,%d)=%u\n",
                    ds->path, (unsigned long long)i, d.x, d.y, d.z, d.block);
            continue;
        }
        if (!diff_upsert_memory(ds, d.x, d.y, d.z, d.block)) {
            fprintf(stderr, "bsgame: %s: record %llu dropped, diff table is full\n",
                    ds->path, (unsigned long long)i);
        }
    }
    return true;
}

/* Rewrites the file to hold exactly the current live set: magic, then one
 * record per entry, fsync'd, then renamed over the original — the same
 * write-fsync-rename shape bsgate.c uses for its own state files, so a
 * crash mid-compaction leaves the previous file untouched rather than a
 * half-written one. */
static bool compact(BsDiffStore *ds, char *err, size_t errlen)
{
    char tmp_path[sizeof ds->path + 8];
    if ((size_t)snprintf(tmp_path, sizeof tmp_path, "%s.compact", ds->path) >= sizeof tmp_path) {
        snprintf(err, errlen, "compacted path too long for %s", ds->path);
        return false;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        snprintf(err, errlen, "open %s: %s", tmp_path, strerror(errno));
        return false;
    }

    bool ok = write(fd, BS_DIFF_MAGIC, BS_DIFF_MAGIC_LEN) == (ssize_t)BS_DIFF_MAGIC_LEN;
    for (uint32_t i = 0; ok && i < ds->count; i++) {
        uint8_t rec[BS_DIFF_REC_BYTES];
        encode_record(rec, &ds->entry[i]);
        ok = write(fd, rec, sizeof rec) == (ssize_t)sizeof rec;
    }
    if (ok) ok = fsync(fd) == 0;

    if (!ok) {
        snprintf(err, errlen, "writing %s: %s", tmp_path, strerror(errno));
        close(fd);
        return false;
    }
    close(fd);

    if (rename(tmp_path, ds->path) != 0) {
        snprintf(err, errlen, "rename %s -> %s: %s", tmp_path, ds->path, strerror(errno));
        return false;
    }
    return true;
}

bool diffstoreOpen(BsDiffStore *ds, const char *dir, char *err, size_t errlen)
{
    memset(ds, 0, sizeof *ds);
    for (uint32_t i = 0; i < BS_DIFF_SLOTS; i++) ds->table[i] = -1;
    ds->fd = -1;

    int n = snprintf(ds->path, sizeof ds->path, "%s/block_diffs.bin", dir);
    if (n < 0 || (size_t)n >= sizeof ds->path) {
        snprintf(err, errlen, "--state-dir path too long for block_diffs.bin");
        return false;
    }

    int fd = open(ds->path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        snprintf(err, errlen, "open %s: %s", ds->path, strerror(errno));
        return false;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        snprintf(err, errlen, "lseek %s: %s", ds->path, strerror(errno));
        close(fd);
        return false;
    }

    if (size == 0) {
        if (write(fd, BS_DIFF_MAGIC, BS_DIFF_MAGIC_LEN) != (ssize_t)BS_DIFF_MAGIC_LEN
            || fsync(fd) != 0) {
            snprintf(err, errlen, "initialising %s: %s", ds->path, strerror(errno));
            close(fd);
            return false;
        }
    } else {
        if (lseek(fd, 0, SEEK_SET) < 0) {
            snprintf(err, errlen, "lseek %s: %s", ds->path, strerror(errno));
            close(fd);
            return false;
        }

        uint8_t magic[BS_DIFF_MAGIC_LEN];
        if ((uint64_t)size < BS_DIFF_MAGIC_LEN
            || read(fd, magic, BS_DIFF_MAGIC_LEN) != (ssize_t)BS_DIFF_MAGIC_LEN
            || memcmp(magic, BS_DIFF_MAGIC, BS_DIFF_MAGIC_LEN) != 0) {
            snprintf(err, errlen,
                     "%s does not start with the expected header — refusing to guess", ds->path);
            close(fd);
            return false;
        }

        if (!load_records(ds, fd, (uint64_t)size, err, errlen)) {
            close(fd);
            return false;
        }
    }
    close(fd);

    if (!compact(ds, err, errlen)) return false;

    ds->fd = open(ds->path, O_WRONLY | O_APPEND, 0600);
    if (ds->fd < 0) {
        snprintf(err, errlen, "reopen %s: %s", ds->path, strerror(errno));
        return false;
    }
    return true;
}

void diffstoreClose(BsDiffStore *ds)
{
    if (ds->fd >= 0) close(ds->fd);
    ds->fd = -1;
}

bool diffstoreApply(BsDiffStore *ds, int32_t x, int32_t y, int32_t z, uint8_t block)
{
    if (!diff_upsert_memory(ds, x, y, z, block)) return false;

    BsDiff d = { x, y, z, block };
    uint8_t rec[BS_DIFF_REC_BYTES];
    encode_record(rec, &d);

    if (write(ds->fd, rec, sizeof rec) != (ssize_t)sizeof rec || fsync(ds->fd) != 0) {
        /* The in-memory table already has it, so the edit is live for this
         * session regardless. A disk problem here means it might not
         * survive the next restart — worth shouting about, not worth
         * taking a running game down over. */
        fprintf(stderr, "bsgame: warning: failed to persist edit at (%d,%d,%d): %s\n",
                x, y, z, strerror(errno));
    }
    return true;
}
