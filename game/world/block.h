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

typedef struct {
	const char* name;
	uint8_t     tex[BLOCK_FACES];
	bool        solid;         // fills its cell: hides the touching neighbour face
	bool        transparent;   // drawn, but does not hide what is behind it
	bool        liquid;
} BlockInfo;

// Never returns NULL — an unknown id reads back as air, because a bad id should
// leave a hole rather than crash a mesher mid-chunk.
const BlockInfo* blockInfo(BlockId id);

static inline bool blockIsSolid(BlockId id) { return blockInfo(id)->solid; }
static inline bool blockIsAir(BlockId id)   { return id == BLOCK_AIR; }

// Atlas tile for one face. Out-of-range faces return the block's first tile.
uint8_t blockFaceTex(BlockId id, int face);
