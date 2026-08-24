// The block registry.
//
// One table, one row per block. Adding a block should be a single row here, not
// six edits spread across the mesher, the collision code and the inventory.
//
// Nothing in source/world includes <3ds.h>. That is deliberate: the world data
// structures are pure C so they can be compiled and unit-tested on the PC with
// gcc, where a failing assertion takes a second to see instead of a rebuild, an
// emulator launch and a screenshot.
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef uint8_t BlockId;

enum {
	BLOCK_AIR = 0,
	BLOCK_GRASS,
	BLOCK_DIRT,
	BLOCK_STONE,
	BLOCK_SAND,
	BLOCK_WOOD,
	BLOCK_LEAVES,
	// Appended, never inserted. A block id is written into every saved chunk and into
	// every block-edit packet on the wire, so inserting one would silently reinterpret
	// every existing world and desync every client that had not been updated.
	BLOCK_PLANKS,
	BLOCK_COUNT
};

// Core blocks that are NOT items — roadmap tasks 17 and 19.
//
// These are ordinary compiled-in core registry rows (the core id space is
// REG_ID_CORE_LO..REG_ID_CORE_HI, 0x01..0x7F — see world/registry.h), appended after
// BLOCK_PLANKS exactly as every id before them was, and frozen for the same reason: an
// id is written into every saved chunk and every block-edit packet. What is different
// is that they sit OUTSIDE the enum above, and BLOCK_COUNT does not move.
//
// That is deliberate, and it is not a way of dodging a static assert. BLOCK_COUNT has
// exactly one live use left in this client — inventoryCanHold() in world/inventory.h,
// the ceiling on what a slot may carry — and one on the server, BS_BLOCK_COUNT in
// deps/blocksmith-server/game/validate.h, which bounds the ITEM ids in
// BS_INV_OP_PICKUP/CONSUME and in the armour slots precisely because those index client
// tables sized BLOCK_COUNT. Every table indexed by a WORLD block id is already sized
// REGISTRY_MAX or 256 — world/mesher.c's s_rect, world/visgraph.c's openTable,
// world/light.c's emission table — because dynamic ids 0x80..0xFD have been arriving
// over the wire since v1.6.0 Phase A. So BLOCK_COUNT is the item-id ceiling and nothing
// else, and these two ids are strictly less exotic than a dyn id the client already
// handles.
//
// Neither of these is an item. Water must not be minable or placeable until the
// survival rung says otherwise, and tall grass has no drop yet. Widening BLOCK_COUNT to
// 10 would make both legal item ids on THIS client while the server still refused them
// at 8 — a client/server disagreement invented for no gain — and would need
// deps/blocksmith-server's BS_BLOCK_COUNT to move in step, in a tree this client does
// not own. Leaving BLOCK_COUNT alone gets the wanted behaviour for free:
// inventoryCanHold() answers false, so scene/interact.c refuses the break rather than
// deleting the block, and neither id can reach the hotbar.
//
// When the survival rung gives water a bucket and tall grass a seed drop, the move is
// to widen inventoryCanHold() past BLOCK_COUNT on both sides — the change
// scene/interact.c's own ⚠ comment already flags — not to slide these two into the enum
// above, which would renumber nothing but would quietly re-point the server's item
// ceiling at them.
enum {
	BLOCK_WATER      = BLOCK_COUNT,      // 8
	BLOCK_TALL_GRASS = BLOCK_COUNT + 1,  // 9
};

// Mirrors the TILE_* enum in gfx/atlas.h. Duplicated rather than included, because
// that header pulls in <3ds.h> and would break the host build.
// source/world/block_tiles_check.c static-asserts that the two agree, so the
// duplication cannot drift silently.
enum {
	BTEX_GRASS_TOP = 0,
	BTEX_GRASS_SIDE,
	BTEX_DIRT,
	BTEX_STONE,
	BTEX_SAND,
	BTEX_SENTINEL,
	BTEX_WOOD_SIDE,
	BTEX_WOOD_TOP,
	BTEX_LEAVES,
	BTEX_PLANKS,
	BTEX_WATER,
	BTEX_TALL_GRASS,
};

// Face order. This is a contract, not a convenience: the registry's tex[] below is
// indexed by it, world/mesher.c's kFaces[] table is written in it, scene/chunk_render.c's
// kFaceShade[] is initialised by name from it, and world.v.pica's faceShade uniform array
// is read with the same index straight out of the vertex. Reordering these silently
// re-textures and re-lights every face in the game.
enum {
	FACE_EAST = 0,   // +X
	FACE_WEST,       // -X
	FACE_TOP,        // +Y
	FACE_BOTTOM,     // -Y
	FACE_SOUTH,      // +Z
	FACE_NORTH,      // -Z
	BLOCK_FACES,
};

// Block shape (v1.6.0 task 13). What geometry a block turns into, as opposed to how
// it behaves — the two are deliberately separate axes:
//
//   shape  says what the mesher draws and what the raycast is aiming at.
//   solid  says whether it fills its cell for collision, AO and occlusion.
//
// A water block is FULL_CUBE and not solid; a plant is CROSS and not solid; every
// block that exists today is FULL_CUBE and solid, which is why nothing about the
// current world changes.
//
// Values are frozen: they are packed into BlockDef.flags (see registry.h) and so
// travel on the wire and into registry.bin. Append, never insert. Three bits are
// reserved there, so slabs and stairs have room without another format change.
enum {
	BLOCK_SHAPE_FULL_CUBE = 0,  // the six axis-aligned faces of a unit cube
	BLOCK_SHAPE_CROSS     = 1,  // two quads on the cell's diagonals, double-sided
	BLOCK_SHAPE_COUNT,
};

typedef struct {
	const char* name;
	uint8_t     tex[BLOCK_FACES];
	bool        solid;         // fills its cell: hides the touching neighbour face
	bool        transparent;   // drawn, but does not hide what is behind it
	bool        liquid;
	uint8_t     shape;         // BLOCK_SHAPE_*
} BlockInfo;

// Never returns NULL — an unknown id reads back as air, because a bad id should
// leave a hole rather than crash a mesher mid-chunk.
const BlockInfo* blockInfo(BlockId id);

static inline bool blockIsSolid(BlockId id) { return blockInfo(id)->solid; }
static inline bool blockIsAir(BlockId id)   { return id == BLOCK_AIR; }

// Whether this block occupies its whole cell geometrically. This is the question the
// mesher's occlusion and AO tables want, and it is NOT `solid`: a non-cube shape can
// never hide the face behind it however solid it is, and a cell it only crosses
// diagonally is not a crevice for AO purposes.
static inline bool blockIsFullCube(BlockId id)
{
	return blockInfo(id)->shape == BLOCK_SHAPE_FULL_CUBE;
}

// Whether the mesher emits geometry for this block at all.
//
// Until v1.6.0 task 13 this question did not exist: `solid` answered it, because every
// block that was not air was solid. It has to be its own question now because the two
// shapes this task exists for break that coincidence in opposite directions — a plant
// draws without colliding, and so does water. Air never draws; neither does an id with
// no registry row, which is what keeps a corrupt or not-yet-defined id a hole rather
// than a cell textured with air's tile.
bool blockIsDrawn(BlockId id);

// Whether a raycast stops here — i.e. whether the player can aim at it, break it, or
// place against it. Anything drawn and not a liquid: a plant must be breakable even
// though you walk straight through it, and you must not be able to mine a lake.
bool blockIsTargetable(BlockId id);

// Whether breaking this block yields nothing to carry (v1.7.1 task 47).
//
// This exists because scene/interact.c used to ask ONE question — "can the bag hold what I am
// about to break?" — and treat a no as "then it cannot be broken". That is right for a block
// whose id the bag refuses because of the BLOCK_COUNT ceiling, and wrong for a plant, which is
// meant to break and simply has nothing to give you. The two had been the same question only by
// coincidence, and the coincidence broke the moment task 19 shipped tall grass: the comment on
// blockIsTargetable above says a plant must be breakable, and it was not. steve reported it as
// "the grass is not breakable, I do not know why that is" on 2026-08-24.
//
// Answered from the SHAPE, not from an id: every cross-quad plant behaves this way, so the next
// one added — and v1.8.2 adds several, per biome — is correct without touching this file. When
// the survival rung gives plants a real drop (seeds, saplings), this becomes the lookup that
// returns it instead of a bool, and interact.c's call site does not move.
static inline bool blockDropsNothing(BlockId id)
{
	return blockInfo(id)->shape == BLOCK_SHAPE_CROSS;
}

// Atlas tile for one face. Out-of-range faces return the block's first tile.
uint8_t blockFaceTex(BlockId id, int face);
