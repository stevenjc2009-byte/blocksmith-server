/* cheststore.h — the authoritative contents of every player-placed chest.
 *
 * v1.9.10 (client v1.9.0, docs/design-1.9.0-chest-multiplayer.md in the
 * client tree). One 8-slot record per chest, keyed by absolute (x, y, z) the
 * way BsDiffStore is, mirrored to <state-dir>/chests.bin so it survives a
 * restart. A chest EXISTS when the diff store says BLOCK_CHEST stands at that
 * position (bsgame.c checks that, not this module); a chest with no record
 * here is simply empty, and a record is only ever created by the first
 * deposit into it.
 *
 * The slot layout {item u8, count u8} x BS_CHEST_SLOTS is the wire layout of
 * BS_APP_CHEST_STATE verbatim, so encoding a snapshot is a copy, and it is
 * also the client's own chest.h pack layout — the same bytes the client would
 * have written for the same contents in single player.
 *
 * Like playerstate.h this is plain C with no network or logging dependency,
 * so the transfer rules and the file format can be exercised by host tests
 * rather than trusted. The only world knowledge it has is inventoryCanHold()
 * (world/inventory.h) for "is this item id one a container may hold" and
 * bsEditValid() (validate.h) for "is this position one the world has". */

#ifndef BS_GAME_CHESTSTORE_H
#define BS_GAME_CHESTSTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../proto/bs_proto.h"

/* Bounded for the reason BS_DIFF_MAX is (diffstore.h): a hostile client must
 * not be able to grow this without limit. Chests are one block kind out of a
 * 131072-entry diff table and every one costs a block edit plus a crafted
 * chest; 4096 is 28 bytes each, 112 KiB, and far past anything 16 players
 * build. A flat array with a linear scan rather than a hash index: at this
 * size the scan is a few microseconds, it runs only on chest actions and on
 * block edits (players.h's BS_GAME_MAX_PLAYERS makes the same call), and it
 * needs no tombstones to remove from — a chest is broken far more often than
 * a diff is undone. */
#define BS_CHEST_MAX 4096u

/* How long the on-disk mirror may lag memory. Chest contents are mutable
 * state (day_time.txt's precedent, not block_diffs.bin's append log), so the
 * whole file is rewritten tmp+fsync+rename each time — a player emptying a
 * chest slot by slot would otherwise rewrite it eight times in a second.
 * One second matches tick()'s own once-a-second save/broadcast beat. */
#define BS_CHEST_FLUSH_MS 1000u

typedef struct {
    int32_t x, y, z;
    uint8_t slot[BS_CHEST_SLOTS][2];   /* [i][0] = item id, [i][1] = count; {0,0} = empty */
} BsChest;

typedef struct {
    BsChest  entry[BS_CHEST_MAX];
    uint32_t count;

    bool     dirty;          /* memory is ahead of chests.bin                */
    uint64_t last_flush_ms;  /* when the file was last (attempted to be) written */
    char     path[512];
} BsChestStore;

/* One decoded BS_APP_CHEST_ACTION — see chestActionDecode(). */
typedef struct {
    uint8_t op;
    int32_t x, y, z;
    uint8_t a, b;
    uint8_t count;
} BsChestAction;

/* Zeroes the store, points it at `dir`/chests.bin and loads whatever that
 * file holds. A missing file is an empty store (a fresh world), not an
 * error. A file that is present but not this format — wrong magic, or a
 * length that is not a whole number of records — is refused with a reason in
 * `err`, and the caller should refuse to start: the same posture
 * diffstoreOpen() takes, because running with half of the players' chests
 * silently emptied is worse than not running.
 *
 * Every record that IS read is sanitised rather than trusted: a position
 * bsEditValid() refuses, or a position already loaded, drops the whole
 * record; a slot whose item inventoryCanHold() refuses, or whose (item,
 * count) pairing is inconsistent, is cleared; a count past BS_INV_STACK_MAX
 * is clamped to it. `dropped` (may be NULL) receives how many records were
 * dropped. Requires the block registry to be initialised, for
 * inventoryCanHold(). */
bool cheststoreOpen(BsChestStore *cs, const char *dir, char *err, size_t errlen,
                    unsigned *dropped);

/* NULL if no deposit has ever created a record here. */
const BsChest *cheststoreFind(const BsChestStore *cs, int32_t x, int32_t y, int32_t z);

/* The `i`th record, for a caller that has to ENUMERATE the store rather than
 * look one position up in it — bsgame.c's CHUNK_SUB reply walks every record
 * to find the ones standing in the column a player just loaded, exactly as
 * send_chunk_diffs() walks the diff store with diffstoreAt(). NULL once `i`
 * reaches cheststoreCount(). Order carries no meaning and is not stable
 * across a cheststoreRemove() (which swaps the last entry into the hole), so
 * an index is only ever valid for the duration of one walk. */
const BsChest *cheststoreAt(const BsChestStore *cs, uint32_t i);

/* Drops the record at (x, y, z), contents and all. True if there was one.
 * bsgame.c calls this when a BLOCK_EDIT replaces the chest block at a
 * position with anything else: a record that outlived its block would
 * resurrect, full, inside the next chest placed on the same cell. */
bool cheststoreRemove(BsChestStore *cs, int32_t x, int32_t y, int32_t z);

/* How many units of `item` chest slot `slot` at (x, y, z) can take right now:
 * BS_INV_STACK_MAX for an empty slot, BS_INV_STACK_MAX minus what is held for
 * a slot holding the same item, 0 for a slot holding a different item, for a
 * slot index out of range, and for a chest with no record yet when the table
 * is already full (the one case cheststoreDeposit() could otherwise fail
 * after the caller has already taken the units from a bag). */
uint8_t cheststoreRoom(const BsChestStore *cs, int32_t x, int32_t y, int32_t z,
                       uint8_t slot, uint8_t item);

/* Puts `units` of `item` into chest slot `slot` at (x, y, z), creating the
 * chest's record if this is its first deposit. All-or-nothing: true only when
 * every unit landed — an empty slot takes them as a new stack, a slot holding
 * the same item merges as long as the total stays within BS_INV_STACK_MAX —
 * and false, with nothing changed, otherwise: a different item in the slot, a
 * merge that would overflow, a slot out of range, units outside
 * 1..BS_INV_STACK_MAX, an item id of 0, or a full table. Marks the store
 * dirty on success. */
bool cheststoreDeposit(BsChestStore *cs, int32_t x, int32_t y, int32_t z,
                       uint8_t slot, uint8_t item, uint8_t units);

/* Takes `units` out of chest slot `slot` at (x, y, z). `units` of 0 means the
 * whole stack. Returns how many were taken and, through `item_out` (may be
 * NULL), what they were; 0 and nothing changed when the slot is empty, out of
 * range, has no record, or holds fewer than `units` — the caller asked for
 * units that do not exist, and the verified model refuses rather than rounds
 * down. The slot reverts to {0, 0} when it reaches 0. Marks the store dirty
 * on success. */
uint8_t cheststoreWithdraw(BsChestStore *cs, int32_t x, int32_t y, int32_t z,
                           uint8_t slot, uint8_t units, uint8_t *item_out);

/* Writes chests.bin if memory is ahead of it. Debounced: with `force` false
 * nothing is written until BS_CHEST_FLUSH_MS have passed since the last
 * attempt, so a burst of transfers costs one rewrite; `force` true writes now
 * (clean shutdown). Returns 1 when the file was written, 0 when there was
 * nothing to do or it is not yet due, -1 on an I/O failure (errno set) — in
 * which case the store stays dirty and the next due flush tries again.
 *
 * Whole-file write-fsync-rename, playerstate.c's shape: the new bytes go to
 * "<path>.tmp", are fsync'd, renamed over the real path, and the directory
 * is fsync'd; a crash at any point leaves either the previous file or the
 * new one, never a torn one. */
int cheststoreFlush(BsChestStore *cs, uint64_t now_ms, bool force);

static inline uint32_t cheststoreCount(const BsChestStore *cs) { return cs->count; }

/* Decodes a BS_APP_CHEST_ACTION payload (type byte included, so `len`
 * compares against BS_CHEST_ACTION_BYTES directly). False unless it is
 * exactly that long and carries that type — nothing about the fields is
 * validated here; that is the caller's job, with the world in hand. */
bool chestActionDecode(const uint8_t *msg, size_t len, BsChestAction *out);

/* Encodes one BS_APP_CHEST_STATE snapshot for the chest at (x, y, z). `c`
 * may be NULL, meaning a chest that has no record yet — eight empty slots —
 * so a caller never has to special-case a chest nobody has used. */
void chestStateEncode(uint8_t out[BS_CHEST_STATE_BYTES], int32_t x, int32_t y, int32_t z,
                      const BsChest *c);

#endif /* BS_GAME_CHESTSTORE_H */
