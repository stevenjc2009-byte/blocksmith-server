/* diffstore.h — the authoritative set of player-made block edits.
 *
 * Terrain itself is never stored: BS_WORLD_SEED (source/main.c) is fixed and
 * every client generates identical terrain locally, so the server only ever
 * needs to remember what players changed. This is that set, held in memory
 * for fast lookup and mirrored to disk so it survives a restart.
 */

#ifndef BS_GAME_DIFFSTORE_H
#define BS_GAME_DIFFSTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded so a hostile or buggy client cannot grow this without limit —
 * validate.h's bsEditValid() is what keeps individual coordinates sane, this
 * is the ceiling on how many distinct ones can exist at all. 65536 distinct
 * edited locations is far past what casual building by 2-8 players reaches;
 * at 16 bytes per entry the live table costs 1 MiB, plus 512 KiB for the
 * open-addressing index below — a fixed, known cost rather than something
 * that grows with how long the world has been played. */
#define BS_DIFF_MAX    65536u
#define BS_DIFF_SLOTS 131072u   /* power of two, ~0.5 load factor for short probes */

typedef struct {
    int32_t x, y, z;
    uint8_t block;
} BsDiff;

typedef struct {
    BsDiff   entry[BS_DIFF_MAX];
    int32_t  table[BS_DIFF_SLOTS];  /* index into entry[], or -1 = empty slot */
    uint32_t count;

    int  fd;              /* open, O_APPEND, for durable writes of new edits */
    char path[512];
} BsDiffStore;

/* Opens (creating if absent) `dir`/block_diffs.bin, replays every edit in it
 * into memory, compacts the file down to exactly the resulting live set, and
 * leaves `fd` open in append mode for future edits. False on any I/O or
 * format error, with a reason in `err` — refuses to start rather than run
 * with a half-loaded world, the same philosophy bsgate.c uses for its own
 * state files. */
bool diffstoreOpen(BsDiffStore *ds, const char *dir, char *err, size_t errlen);
void diffstoreClose(BsDiffStore *ds);

/* NULL if this block has never been touched by a player edit — i.e. it is
 * still whatever the seed generates. */
const BsDiff *diffstoreFind(const BsDiffStore *ds, int32_t x, int32_t y, int32_t z);

/* Applies one already-validated edit: updates the in-memory table and
 * appends+fsyncs a record to the on-disk log. False only when this is a
 * brand new coordinate and the table is already at BS_DIFF_MAX — the one
 * case bounded memory has to refuse outright rather than grow. A disk
 * failure while persisting is logged, not treated as refusal: the edit
 * stays live for the running session either way. */
bool diffstoreApply(BsDiffStore *ds, int32_t x, int32_t y, int32_t z, uint8_t block);

static inline uint32_t diffstoreCount(const BsDiffStore *ds) { return ds->count; }

/* `index` in [0, diffstoreCount()) — for batching a WORLD_SYNC on join.
 * NULL if out of range. */
const BsDiff *diffstoreAt(const BsDiffStore *ds, uint32_t index);

#endif /* BS_GAME_DIFFSTORE_H */
