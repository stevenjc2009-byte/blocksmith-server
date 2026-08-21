#include "world/inventory.h"

#include <stdio.h>
#include <string.h>

#include "world/crc32.h"

// Nothing in here includes <3ds.h>. Same reasoning as world/region.c and app/options.c:
// libctru mounts the SD card as a devoptab under "sdmc:/", so fopen("sdmc:/.../inventory.dat")
// on console and fopen("build-host/.../inventory.dat") on the host go through the exact same
// code below — that is the only reason the crash-recovery path can be exercised by a host
// test at all.

void inventoryInit(Inventory* inv)
{
	if (!inv) return;
	// Zero gives every slot { ITEM_NONE (== BLOCK_AIR == 0), count 0 } and selects hotbar 0,
	// which is exactly the state a fresh inventory (and a missing/corrupt save) should have.
	memset(inv, 0, sizeof(*inv));
}

// ── Adding and removing ───────────────────────────────────────────────────────────────

InvAddResult inventoryAdd(Inventory* inv, ItemId item, uint8_t count, uint8_t* out_leftover)
{
	if (out_leftover) *out_leftover = count;

	if (!inv || item == ITEM_NONE || item >= BLOCK_COUNT)
		return INV_ADD_REFUSED;

	if (count == 0) {
		// Nothing was asked for, so nothing is owed — this is success, not refusal.
		if (out_leftover) *out_leftover = 0;
		return INV_ADD_OK;
	}

	uint8_t remaining = count;

	// Pass 1: top up existing stacks of the same item. Scanning from slot 0 means the
	// hotbar (slots [0, INV_HOTBAR_SLOTS)) is preferred over the main grid, since it is
	// the same array and the hotbar is simply its front — no separate "prefer hotbar"
	// branch is needed.
	for (int i = 0; i < INV_SLOT_COUNT && remaining > 0; i++) {
		InvSlot* s = &inv->slots[i];
		if (s->item != item) continue;

		const uint8_t space = (uint8_t)(INV_STACK_MAX - s->count);
		const uint8_t take  = (remaining < space) ? remaining : space;
		if (take == 0) continue;

		s->count = (uint8_t)(s->count + take);
		remaining = (uint8_t)(remaining - take);
	}

	// Pass 2: whatever is left over spills into empty slots, one new stack per slot,
	// looping until either everything fits or there are no more empty slots.
	for (int i = 0; i < INV_SLOT_COUNT && remaining > 0; i++) {
		InvSlot* s = &inv->slots[i];
		if (s->item != ITEM_NONE) continue;

		const uint8_t take = (remaining < INV_STACK_MAX) ? remaining : INV_STACK_MAX;
		s->item  = item;
		s->count = take;
		remaining = (uint8_t)(remaining - take);
	}

	if (out_leftover) *out_leftover = remaining;

	if (remaining == 0)     return INV_ADD_OK;
	if (remaining == count) return INV_ADD_REFUSED;  // the loops above wrote nothing at all
	return INV_ADD_PARTIAL;
}

uint8_t inventoryRemove(Inventory* inv, ItemId item, uint8_t count)
{
	if (!inv || item == ITEM_NONE || item >= BLOCK_COUNT || count == 0) return 0;

	uint8_t remaining = count;
	for (int i = 0; i < INV_SLOT_COUNT && remaining > 0; i++) {
		InvSlot* s = &inv->slots[i];
		if (s->item != item) continue;

		const uint8_t take = (s->count < remaining) ? s->count : remaining;
		s->count = (uint8_t)(s->count - take);
		remaining = (uint8_t)(remaining - take);

		if (s->count == 0) s->item = ITEM_NONE;   // revert to a clean empty slot
	}

	return (uint8_t)(count - remaining);
}

uint32_t inventoryCount(const Inventory* inv, ItemId item)
{
	if (!inv || item == ITEM_NONE) return 0;

	uint32_t total = 0;
	for (int i = 0; i < INV_SLOT_COUNT; i++)
		if (inv->slots[i].item == item) total += inv->slots[i].count;
	return total;
}

// ── Rearranging slots ──────────────────────────────────────────────────────────────────

void inventorySwapSlots(Inventory* inv, int a, int b)
{
	if (!inv) return;
	if (a < 0 || a >= INV_SLOT_COUNT || b < 0 || b >= INV_SLOT_COUNT || a == b) return;

	const InvSlot tmp = inv->slots[a];
	inv->slots[a] = inv->slots[b];
	inv->slots[b] = tmp;
}

uint8_t inventoryMoveUnits(Inventory* inv, int src, int dst, uint8_t units)
{
	if (!inv) return 0;
	if (src < 0 || src >= INV_SLOT_COUNT || dst < 0 || dst >= INV_SLOT_COUNT || src == dst)
		return 0;

	InvSlot* s = &inv->slots[src];
	InvSlot* d = &inv->slots[dst];

	if (s->item == ITEM_NONE || units == 0) return 0;
	if (units > s->count) units = s->count;

	// A destination holding a different item refuses outright rather than merging,
	// overwriting, or bumping the mismatched stack aside — any of those would either lose
	// items or move something the player did not ask to move.
	if (d->item != ITEM_NONE && d->item != s->item) return 0;

	const uint8_t space = (d->item == ITEM_NONE) ? INV_STACK_MAX : (uint8_t)(INV_STACK_MAX - d->count);
	const uint8_t move  = (units < space) ? units : space;
	if (move == 0) return 0;

	if (d->item == ITEM_NONE) d->item = s->item;
	d->count = (uint8_t)(d->count + move);

	s->count = (uint8_t)(s->count - move);
	if (s->count == 0) s->item = ITEM_NONE;

	return move;
}

bool inventorySplitStack(Inventory* inv, int slot, int dst)
{
	if (!inv) return false;
	if (slot < 0 || slot >= INV_SLOT_COUNT || dst < 0 || dst >= INV_SLOT_COUNT || slot == dst)
		return false;

	const InvSlot* s = &inv->slots[slot];
	if (s->item == ITEM_NONE || s->count < 2) return false;      // nothing to divide
	if (inv->slots[dst].item != ITEM_NONE)    return false;      // destination must be empty

	// Origin keeps the ceiling half, destination gets the floor half — a deterministic
	// even split needs no quantity picker, which a long-press touchscreen gesture has no
	// natural way to drive anyway (see inventory.h).
	const uint8_t move = (uint8_t)(s->count / 2);
	const uint8_t moved = inventoryMoveUnits(inv, slot, dst, move);
	return moved == move && moved > 0;
}

// ── Hotbar selection ──────────────────────────────────────────────────────────────────

void inventorySelectHotbar(Inventory* inv, uint8_t hotbar_slot)
{
	if (!inv) return;
	if (hotbar_slot >= INV_HOTBAR_SLOTS) hotbar_slot = INV_HOTBAR_SLOTS - 1;
	inv->selected_hotbar = hotbar_slot;
}

ItemId inventoryHeldItem(const Inventory* inv)
{
	if (!inv) return ITEM_NONE;
	return inv->slots[inv->selected_hotbar].item;
}

uint8_t inventoryHeldCount(const Inventory* inv)
{
	if (!inv) return 0;
	return inv->slots[inv->selected_hotbar].count;
}

// ── Save / load ────────────────────────────────────────────────────────────────────────
//
// On-disk layout, 20 + INV_SLOT_COUNT*2 bytes total (68 today), all fixed-size:
//
//   0x00  u32  magic     INVENTORY_MAGIC
//   0x04  u32  version   INVENTORY_VERSION
//   0x08  u32  slot_count  INV_SLOT_COUNT at save time
//   0x0C  u32  crc        crc32 over everything from 0x10 to EOF
//   0x10  u8   selected_hotbar
//   0x11  u8[3] reserved, written zero
//   0x14  (u8 item, u8 count) x slot_count
//
// The crc field sits *before* the range it covers so computing it never has to exclude
// itself. slot_count is checked separately (not folded into the crc) because "this file
// was written by a build with a different INV_SLOT_COUNT" is a distinct failure from
// "these bytes were corrupted" and both are handled the same way regardless (fall back to
// empty), but keeping them separate makes each check read as what it actually is.

#define INVENTORY_FILE_NAME "inventory.dat"

// "BSI1" (Blocksmith Inventory, format 1) read as bytes little-endian, same naming shape
// as world/region.c's DIR_MAGIC "BSR1" — a different letter so the two files can never be
// mistaken for one another even if a path ever got crossed.
#define INVENTORY_MAGIC   0x31495342u
#define INVENTORY_VERSION 1u

#define INV_FILE_HDR_BYTES 20
#define INV_FILE_BYTES     (INV_FILE_HDR_BYTES + INV_SLOT_COUNT * 2)

// Little-endian on both the ARM11 and the host, but written and read a byte at a time
// anyway — copied from world/region.c's put32/get32 rather than re-derived, since this is
// solving the exact same "a save file must load on whichever machine reads it" problem.
static void put32(uint8_t* p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static uint32_t get32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool inventoryPath(char* out, size_t cap, const char* world_dir)
{
	return snprintf(out, cap, "%s/%s", world_dir, INVENTORY_FILE_NAME) < (int)cap;
}

static bool tmpPath(const char* path, char* out, size_t cap)
{
	return snprintf(out, cap, "%s.tmp", path) < (int)cap;
}

bool inventorySave(const Inventory* inv, const char* world_dir)
{
	if (!inv || !world_dir) return false;

	char path[512], tmp[512];
	if (!inventoryPath(path, sizeof(path), world_dir)) return false;
	if (!tmpPath(path, tmp, sizeof(tmp))) return false;

	uint8_t buf[INV_FILE_BYTES];
	buf[16] = inv->selected_hotbar;
	buf[17] = buf[18] = buf[19] = 0;
	for (int i = 0; i < INV_SLOT_COUNT; i++) {
		buf[20 + i * 2 + 0] = inv->slots[i].item;
		buf[20 + i * 2 + 1] = inv->slots[i].count;
	}

	const uint32_t crc = crc32(buf + 16, sizeof(buf) - 16);
	put32(buf + 0,  INVENTORY_MAGIC);
	put32(buf + 4,  INVENTORY_VERSION);
	put32(buf + 8,  (uint32_t)INV_SLOT_COUNT);
	put32(buf + 12, crc);

	FILE* f = fopen(tmp, "wb");
	if (!f) return false;

	const bool wrote_ok = fwrite(buf, 1, sizeof(buf), f) == sizeof(buf);

	// fclose is the flush: this is what makes the bytes actually reach the card rather
	// than sitting in stdio's buffer when the rename below runs — same reasoning as
	// options.c's optionsSave.
	if (fclose(f) != 0 || !wrote_ok) { remove(tmp); return false; }

	// Windows' rename() refuses to replace an existing destination, so the old file has
	// to go first — same reason options.c's optionsSave and region.c's regionCompact both
	// remove before they rename. remove() failing because `path` does not exist yet (the
	// very first save) is expected and not a failure of this function.
	remove(path);

	if (rename(tmp, path) != 0) return false;

	// The window this leaves — a power cut between the remove and the rename — is closed
	// by inventoryRecover below the next time anything tries to load this path, same as
	// options.c's optionsRecover closes it for options.ini.
	return true;
}

// Mirrors options.c's optionsRecover / region.c's regionRecover: if the last save was cut
// between removing the old file and renaming the new one into place, `path` is gone and
// `path.tmp` is a complete, unopened replacement. Promoting it here means inventoryLoad
// never has to tell "never saved" apart from "saved, then interrupted right after".
static void inventoryRecover(const char* path)
{
	char tmp[512];
	if (!tmpPath(path, tmp, sizeof(tmp))) return;

	FILE* t = fopen(tmp, "rb");
	if (!t) return;             // no interrupted save to recover
	fclose(t);

	FILE* real = fopen(path, "rb");
	if (real) { fclose(real); remove(tmp); return; }   // real file is fine; drop the leftover tmp

	rename(tmp, path);
}

bool inventoryLoad(Inventory* inv, const char* world_dir)
{
	if (!inv || !world_dir) return false;

	// Always start from a fully valid, empty inventory. Every early return below leaves
	// this in place, so "file missing", "file corrupt" and "file from an incompatible
	// build" all degrade to the same safe result instead of three different failure modes
	// the rest of the game would have to know about.
	inventoryInit(inv);

	char path[512];
	if (!inventoryPath(path, sizeof(path), world_dir)) return true;   // path too long: defaults

	inventoryRecover(path);

	FILE* f = fopen(path, "rb");
	if (!f) return true;   // missing file is not an error — see inventory.h

	uint8_t buf[INV_FILE_BYTES];
	const size_t n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (n != sizeof(buf)) return true;   // short/truncated file: defaults

	if (get32(buf + 0) != INVENTORY_MAGIC)               return true;
	if (get32(buf + 4) != INVENTORY_VERSION)             return true;
	if (get32(buf + 8) != (uint32_t)INV_SLOT_COUNT)      return true;   // layout changed since save

	const uint32_t stored   = get32(buf + 12);
	const uint32_t computed = crc32(buf + 16, sizeof(buf) - 16);
	if (stored != computed) return true;   // corrupted payload: defaults

	uint8_t sel = buf[16];
	if (sel >= INV_HOTBAR_SLOTS) sel = 0;
	inv->selected_hotbar = sel;

	for (int i = 0; i < INV_SLOT_COUNT; i++) {
		const ItemId  item  = buf[20 + i * 2 + 0];
		const uint8_t count = buf[20 + i * 2 + 1];

		// Defence in depth even though the crc already vouches for these exact bytes: an
		// id outside the block registry, or a count paired with ITEM_NONE, is treated the
		// same way a malformed options.ini field is treated — fall back to "empty" rather
		// than hand the rest of the game a slot state nothing else has ever validated.
		if (item == ITEM_NONE || item >= BLOCK_COUNT || count == 0) continue;   // slot already zeroed by inventoryInit

		inv->slots[i].item  = item;
		inv->slots[i].count = (count > INV_STACK_MAX) ? INV_STACK_MAX : count;
	}

	return true;
}
