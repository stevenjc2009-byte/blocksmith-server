// Step 8.2 (data half). Hotbar + main inventory as one flat slot array, plus what it
// takes to add, remove, split and rearrange stacks, and to survive a quit.
//
// Nothing in here includes <3ds.h>. Same reasoning as world/region.c and app/options.c:
// this is pure C so the merge/split/refuse logic — the part that is actually easy to get
// subtly wrong — can be checked with host gcc in under a second, not by relaunching an
// emulator and squinting at a touchscreen.
//
// This header is the contract for whoever builds the touchscreen UI on top of it (a
// separate step) and for whoever wires interact.c's block-break to it (also a separate
// step, see the comment on inventoryAdd). Neither of those exists yet, so nothing here
// depends on scene/ or gfx/.
//
// ── Item space ─────────────────────────────────────────────────────────────────────────
//
// There is no item registry distinct from the block registry. An ItemId *is* a BlockId:
// every item this game has today is a block you mined, and it draws with that block's own
// tile (blockInfo(item)->tex / blockFaceTex, see gfx/atlas.h) and re-places as that exact
// block. Inventing a parallel item table — id, display name, icon tile, stack rules, all
// duplicated from the block table — would be machinery for a distinction (item vs. block)
// that does not exist in this game yet. The day a non-block item shows up (a tool, say),
// that is the point to split the two; adding the split now, for content that is not there,
// is exactly the kind of speculative generality this project's style avoids.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "world/block.h"

// ── Item id space ──────────────────────────────────────────────────────────────────────

typedef BlockId ItemId;

// A slot with no item in it always reads back as { ITEM_NONE, 0 } — never a stale item id
// paired with a zero count, so "is this slot empty" is one field compare, not two.
#define ITEM_NONE BLOCK_AIR

// Whether the inventory is able to carry this id at all — the one home for the item-id
// ceiling, so the rule is stated once instead of being restated at every call site.
//
// The ceiling is BLOCK_COUNT and NOT the registry's full 256-id space, on purpose — but the
// reason is a WIRE AGREEMENT, not memory safety. Nothing in this client is sized
// [BLOCK_COUNT]; grep the tree and the only two hits are comments recording bounds that were
// already widened away (world/mesher.c's rect table and net/networld_test.c's note on it).
// Every slot-drawing path is registry-backed and bounds-checked: scene/ui.c's iconUv() goes
// through atlasTile(blockFaceTex(id, FACE_TOP)), blockFaceTex() -> blockInfo() ->
// registryView() covers the whole 256-id space, and world/atlas_uv.h's atlasRect() clamps an
// out-of-range tile to ATLAS_TILE_MISSING rather than wrapping. The slot's label is
// blockInfo(item)->name by that same path. The crafting tables are [RECIPE_COUNT] and are
// indexed by recipe index, not by item id at all. So a dyn id sitting in a slot would draw
// the missing-texture marker; it would not read out of bounds.
//
// What the ceiling actually buys is agreement across the wire:
// deps/blocksmith-server/game/bsgame.c mirrors it exactly for BS_INV_OP_PICKUP and
// BS_INV_OP_CONSUME, and playerstate.c for the armour slots — so a dynamic
// (server-registered, 0x80..0xFD) id is not carryable on either side yet, and widening here
// alone would only make this client offer the player a pickup the server then refuses.
//
// ⚠ deps/blocksmith-server/game/validate.h still states the OLD memory-safety rationale for
// BS_BLOCK_COUNT ("index client-side tables sized BLOCK_COUNT and would read out of bounds on
// the 3DS"). The ceiling it guards is still correct, so nothing is broken today, but that
// stated reason no longer holds — do not lean on it when deciding whether the ceiling may
// move. The wire agreement above is the reason that is still load-bearing.
//
// ⚠ This predicate is also what scene/interact.c refuses a *break* on: a block the bag
// cannot hold must not be minable, or breaking it deletes it from the world with nothing to
// show for it. When inventory becomes registry-aware, widening this one function is what
// lifts both rules at once — and interact.c's guard goes with it.
static inline bool inventoryCanHold(ItemId item)
{
	return item != ITEM_NONE && (uint32_t)item < BLOCK_COUNT;
}

// ── Slot layout ────────────────────────────────────────────────────────────────────────
//
// Both the hotbar and the main grid are the *same* array — the hotbar is simply slots
// [0, INV_HOTBAR_SLOTS). That is what lets every function below (add, remove, swap, move,
// split, the save format) work in terms of a single slot index regardless of which part of
// the screen it came from: the touchscreen UI does not need a second index space or a
// "which grid" tag, and a drag from the hotbar to the main grid (or back) is exactly the
// same call as a drag within one grid.
//
// INV_HOTBAR_SLOTS = 8, sized off the bottom screen the UI has to draw it on rather than
// off any other game's number: the 3DS bottom screen is 320x240. A touch target has to
// survive a stylus tap that is off by a few pixels, so eight equal slots across the full
// 320px width give each one 40px — about 7.6mm at the console's real screen size, which is
// inside the usual 7-10mm minimum touch-target guidance and leaves a couple of pixels of
// gutter between slots without shrinking below that floor. Going to 9 or 10 slots (36 or
// 32px) was considered and rejected: both are below the comfortable end of that range for
// a resistive-feeling stylus tap, and there is no content reason to want more — see below.
//
// INV_MAIN_COLS/ROWS = 8x2 (16 slots), for the same 320px width and because the bottom
// screen also has to hold the crafting list and an output slot below the grid; two rows at
// 40px plus the hotbar row is 120px of a 240px screen, leaving about half the screen for
// the crafting panel and a border, without the UI agent having to fight the inventory grid
// for space. Three rows (24 main slots) was considered — it still fits, but leaves a
// crafting panel with less than 100px, which is tight for a small icon list plus an output
// slot on a 3DS. Total INV_SLOT_COUNT is 24, which comfortably outnumbers the 6 items this
// game currently has (see block.h): most of a build's worth of any one material fits in a
// single stack (see INV_STACK_MAX below), so 24 slots is headroom for holding several
// different materials at once, not a requirement to hold many stacks of one.
#define INV_HOTBAR_SLOTS  8
#define INV_MAIN_COLS     8
#define INV_MAIN_ROWS     2
#define INV_MAIN_SLOTS    (INV_MAIN_COLS * INV_MAIN_ROWS)
#define INV_SLOT_COUNT    (INV_HOTBAR_SLOTS + INV_MAIN_SLOTS)

// Largest count a single slot can hold. 99 rather than a round power of two or a number
// borrowed from any other game: the touchscreen count badge drawn in the corner of a slot
// icon has room for two digits at a legible size on a 320px-wide screen, and a three-digit
// badge (100+) would either overflow the icon or force a smaller font than the rest of the
// UI uses. The cap is a uint8_t field (0..255) so nothing overflows even if this constant
// is revisited later; 99 is a game rule enforced by inventoryAdd, not a storage limit.
#define INV_STACK_MAX 99

typedef struct {
	ItemId  item;    // ITEM_NONE if empty
	uint8_t count;   // 0 iff item == ITEM_NONE; 1..INV_STACK_MAX otherwise
} InvSlot;

typedef struct {
	InvSlot slots[INV_SLOT_COUNT];
	uint8_t selected_hotbar;   // which hotbar slot (0..INV_HOTBAR_SLOTS-1) is "in hand"
} Inventory;

// True for a slot index inside the hotbar range. The UI needs this to decide which strip
// to redraw a slot in; nothing in this file branches on it, because add/remove/move treat
// every slot the same regardless of which half of the screen it is drawn in.
static inline bool invSlotIsHotbar(int slot) { return slot >= 0 && slot < INV_HOTBAR_SLOTS; }

// Zeroes every slot and resets the hotbar selection to 0. This is also what a missing or
// corrupt save falls back to — see inventoryLoad.
void inventoryInit(Inventory* inv);

// ── Adding and removing ───────────────────────────────────────────────────────────────
//
// The one rule every function in this section is built around: an item that does not fit
// is *reported*, never silently dropped. A survival game that eats a block the player just
// picked up is a bug the player has no way to see — there is no error toast for "and then
// nothing happened" — so the return value always tells the caller exactly how much of the
// request actually landed.

typedef enum {
	INV_ADD_OK = 0,    // every unit fit
	INV_ADD_PARTIAL,   // some fit, the rest did not; *out_leftover holds what did not
	INV_ADD_REFUSED,   // nothing fit at all; the inventory is provably unchanged (see below)
} InvAddResult;

// Adds up to `count` of `item`, merging into existing partial stacks of the same item
// first (scanning slot 0 upward, i.e. hotbar before main grid), then filling empty slots
// with new stacks, spilling into a second (and third, ...) empty slot if one stack's worth
// is not enough to hold everything requested.
//
// `out_leftover` (may be NULL) receives how many units did *not* fit — 0 on INV_ADD_OK.
// The result and `out_leftover` together are the whole story: a caller that only checks
// the enum still learns whether anything was refused, and a caller that wants to show
// "3 dirt dropped, inventory full" has the exact number without recomputing it.
//
// INV_ADD_REFUSED can only happen when the loop below performs zero writes — no existing
// stack had room and no slot was empty — which means the inventory is byte-for-byte
// unchanged on that path by construction, not by a rollback: there is nothing to roll back
// from, because nothing was ever set until it was known to fit.
//
// This is the call interact.c's future block-break wiring uses, and it is meant to be one
// line: inventoryAdd(&inv, broken_block_id, 1, NULL) turns a mined block straight into a
// held item, with `count` almost always 1 (one block breaks into one item) and NULL for
// `out_leftover` when the caller does not care to report the refusal itself.
InvAddResult inventoryAdd(Inventory* inv, ItemId item, uint8_t count, uint8_t* out_leftover);

// Removes up to `count` of `item`, taking from whichever slots hold it (slot 0 upward)
// until either `count` is reached or the item runs out. Returns how many were actually
// removed, which may be less than `count` if the inventory held fewer — asking to remove
// more than is present is not an error, it just can't remove what is not there, and it
// never touches any slot holding a different item. A slot that reaches 0 reverts to
// { ITEM_NONE, 0 }, same as inventoryInit leaves it.
uint8_t inventoryRemove(Inventory* inv, ItemId item, uint8_t count);

// Total held across every slot. Used by crafting.c to check a recipe's ingredients without
// caring which slot(s) they are spread across.
uint32_t inventoryCount(const Inventory* inv, ItemId item);

// ── Rearranging slots ──────────────────────────────────────────────────────────────────
//
// Three primitives, in increasing generality; the touchscreen UI is expected to build
// "drag stack A onto slot B" out of whichever one matches what the player did, not to
// reimplement the merge/refuse rules itself.

// Exchanges the entire contents of two slots — item, count, empty or not. This is what a
// plain drag-and-drop (no merge) looks like: pick up slot A, drop on slot B, whatever was
// in B is now where A's stack came from.
void inventorySwapSlots(Inventory* inv, int a, int b);

// Moves up to `units` from `src` into `dst`. If `dst` is empty, the units go there
// directly, creating a new stack. If `dst` holds the *same* item, moves as many as fit
// under INV_STACK_MAX and leaves any remainder in `src` — this is what a drag onto a
// nearly-full stack of the same item does: it tops the target up and the leftover stays
// exactly where it was, rather than the whole move being refused. If `dst` holds a
// *different* item, the move is refused outright (returns 0, nothing changes) rather than
// overwriting whatever the player already had sitting in that slot.
//
// Returns the number of units actually moved, 0..units. This is the primitive
// inventorySplitStack is built on; a future "move N with a quantity picker" touchscreen
// gesture is this same call with a `units` the UI already has from the picker, not a new
// function.
uint8_t inventoryMoveUnits(Inventory* inv, int src, int dst, uint8_t units);

// Splits `slot`'s stack into two: `dst` (which must currently be empty) gets floor(count/2),
// `slot` keeps the rest (the ceiling half). A long-press-to-split gesture has no natural way
// for the player to pick an exact fraction, so an even split is the one answer that needs no
// extra UI; a stack of 1 cannot be split (there is nothing to divide) and returns false with
// no change, same as a `dst` that is not empty.
bool inventorySplitStack(Inventory* inv, int slot, int dst);

// ── Hotbar selection ──────────────────────────────────────────────────────────────────

// Sets which hotbar slot is "in hand". Out-of-range clamps to the last hotbar slot rather
// than being ignored, so a caller passing a raw D-pad/touch index never leaves the
// selection pointing outside the hotbar.
void inventorySelectHotbar(Inventory* inv, uint8_t hotbar_slot);

// What the player is currently holding — ITEM_NONE if the selected hotbar slot is empty.
// This is what feeds scene/interact.h's Interact.holding every frame.
ItemId  inventoryHeldItem(const Inventory* inv);
uint8_t inventoryHeldCount(const Inventory* inv);

// ── Save / load ────────────────────────────────────────────────────────────────────────
//
// One inventory per world, saved next to that world's region files rather than in
// app/options.c's own file: `world_dir` is the same directory world/region.h's
// regionWriteColumn takes (a directory under REGION_ROOT), and this writes
// "<world_dir>/inventory.dat" inside it. Crash safety follows options.c's proven shape
// exactly rather than inventing a new one: the new bytes are written whole to
// "<path>.tmp", flushed via fclose, the real path is removed, and only then is the tmp
// renamed over it. A power cut between the remove and the rename is recovered on the next
// load by promoting a leftover ".tmp" back into place, the same way options.c's
// optionsRecover and region.c's regionRecover do — see inventory.c for the mechanism.
//
// Both functions treat "nothing usable on disk" (missing file, wrong magic/version, a
// slot count that does not match this build, a failed checksum, a short read) the same
// way options.c treats a garbage ini: fall back to inventoryInit()'s empty inventory
// rather than propagate an error. There is no player-visible difference between "never
// saved" and "saved, but unreadable" that this module could usefully report — either way
// the safe thing is an empty inventory, never a crash and never a value the rest of the
// game has not validated.

// Loads `world_dir`/inventory.dat into `inv`. Always leaves `inv` fully valid (see
// inventoryInit) and always returns true, except when `inv` is NULL or `world_dir` is NULL
// or empty, which is a caller bug rather than a file-format problem — see inventory.c's
// dirUsable(). A file longer than the on-disk record is refused the same as a short one.
bool inventoryLoad(Inventory* inv, const char* world_dir);

// Saves `inv` to `world_dir`/inventory.dat. False on any IO failure (could not open the
// tmp file, a short write, the final rename failing) or on a NULL/empty `world_dir` (see
// inventory.c's dirUsable()), in which case the previous save (if any) is left exactly as
// it was — nothing here touches the real path until the replacement is known-good and
// closed. The caller counts a failure rather than retries, same as a failed region write;
// a lost inventory save is not worth stalling a frame over.
bool inventorySave(const Inventory* inv, const char* world_dir);
