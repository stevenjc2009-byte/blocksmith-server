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
 * is the ceiling on how many distinct ones can exist at all. A fixed, known
 * cost rather than something that grows with how long the world has been
 * played: at 16 bytes per entry the live table costs 2 MiB, plus 1 MiB for
 * the open-addressing index below.
 *
 * This was 65536, and what actually bound it was not memory but the client:
 * the server replayed its ENTIRE store to every joining client in one burst,
 * and the client's pending store refused everything past its own cap — losing
 * the NEWEST edits, because the replay goes oldest-first. Raising this before
 * that was fixed would only have made a joining player lose more of what had
 * just been built.
 *
 * Per-column subscription (BS_APP_CHUNK_SUB, proto/bs_proto.h) is what removed
 * that coupling: a client now receives one column's diffs at a time, bounded by
 * its render distance rather than by how much has ever been built. So this can
 * be sized for the world instead of for the wire, and 131072 puts it past
 * 100000 with room to spare.
 *
 * Old clients that never send CHUNK_SUB still get the full dump and still lose
 * whatever exceeds their own cap. That is not a regression — it was already
 * true at 65536 — but it is a reason to update them. */
#define BS_DIFF_MAX   131072u
#define BS_DIFF_SLOTS 262144u   /* power of two, ~0.5 load factor for short probes */

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
