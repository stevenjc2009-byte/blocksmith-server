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

// Core blocks appended after the closed first span — roadmap tasks 17 and 19, and v1.8.3
// Phase 3.
//
// These are ordinary compiled-in core registry rows (the core id space is
// REG_ID_CORE_LO..REG_ID_CORE_HI, 0x01..0x7F — see world/registry.h), appended after
// BLOCK_PLANKS exactly as every id before them was, and frozen for the same reason: an
// id is written into every saved chunk and every block-edit packet. What is different
// is that they sit OUTSIDE the enum above, and BLOCK_COUNT does not move.
//
// ── What BLOCK_COUNT means, as of v1.8.8 ───────────────────────────────────────────────
//
// It is the WIRE item span, and nothing else. It is no longer the bag's ceiling.
//
// Until v1.8.8 it was both, because world/inventory.h's inventoryCanHold() was literally
// `item < BLOCK_COUNT`. That is what made every row from water (8) upward uncarryable, and
// — since scene/interact.c refuses a break whose drop the bag cannot bank — what made the
// three FULL_CUBE rows among them, snow, ice and CACTUS, unbreakable. steve reported the
// cactus. It was never an id-space problem: BlockId is a uint8_t and the core span had 112
// free rows under it at the time.
//
// v1.8.8 took the route this comment had been prescribing all along — widen the PREDICATE,
// never the constant. inventoryCanHold() now asks the REGISTRY — defined, not air, not a
// liquid — instead of comparing against 8. So:
//
//   BLOCK_COUNT (8)        the frozen span of ids the WIRE agrees are items. The server's
//                          BS_BLOCK_COUNT in deps/blocksmith-server/game/validate.h is the
//                          same number, and its game/bsgame.c bounds BS_INV_OP_PICKUP and
//                          BS_INV_OP_CONSUME by it, as game/playerstate.c does the armour
//                          slots. world/inventory.h's inventoryItemOnWire() is this client's
//                          name for that span, and net/inv_bridge.c is its only caller.
//                          ⚠ It cannot move on one side alone. See inventoryItemOnWire().
//   inventoryCanHold()     what the BAG may hold, locally. Registry-driven, so it already
//                          covers every row v1.8.8 and later append without another edit.
//                          It lives in world/inventory.h and not here — see the ⚠ beside
//                          blockIsTargetable() below for the link reason that keeps it there.
//
// Every table indexed by a WORLD block id was already sized REGISTRY_MAX or 256 —
// world/mesher.c's s_rect, world/visgraph.c's openTable, world/light.c's emission table —
// because dynamic ids 0x80..0xFD have been arriving over the wire since v1.6.0 Phase A. So
// nothing was ever sized [BLOCK_COUNT] and widening the bag reads nothing out of bounds.
//
// Water is still not carryable, and still for the reason below rather than by accident of a
// constant: it sets REG_FLAG_LIQUID, and inventoryCanHold() excludes liquids because there
// is no bucket. That exclusion is now a stated game rule in one place instead of a side
// effect of where the ceiling happened to fall.
//
// ── What v1.8.8 changed for the Phase 3 five ───────────────────────────────────────────
//
// snow, ice, cactus, dead bush and fern (ids 10..14) were appended by v1.8.3 Phase 3 with
// BLOCK_COUNT held at 8, which was right for that rung: the ceiling and the blocks were two
// INDEPENDENT changes and only the blocks were needed for terrain. The consequence, recorded
// there and measured against the real guard at scene/interact.c —
// `!blockDropsNothing(here) && !inventoryCanHold(here)` — was:
//
//   snow, ice, cactus   FULL_CUBE and past the ceiling, so the break was REFUSED. Unminable
//                       scenery. **v1.8.8 ends this**: all three are carryable, so the guard
//                       does not fire, and all three break and drop themselves.
//   dead_bush, fern     CROSS, so blockDropsNothing() is true, the break is allowed, and it
//                       yields nothing — identical to tall grass, and UNCHANGED by v1.8.8.
//                       They are carryable now, but breakComplete() hands the bag BLOCK_AIR
//                       for any CROSS block, so no plant id reaches a slot until the survival
//                       rung gives plants a real drop.
//
// What is still open, and is a wire question rather than a client one: an id at or above
// BLOCK_COUNT that the bag now holds is NOT reported to a server, because inventoryItemOnWire()
// still stops at 8. In single player that is invisible. On a server the block breaks, the
// BS_APP_BLOCK_EDIT goes out and is honoured, and the pickup is not — so the server's
// authoritative inventory does not know about it and the next BS_APP_INV_STATE snapshot takes
// it back. Nothing crashes, nothing is kicked, and the world is consistent; the bag is not.
// Closing it needs BS_BLOCK_COUNT and the two guards in the server tree to move first.
//
// ⚠ These are LITERALS, and they must stay literals. Do not "tidy" them back into
// BLOCK_COUNT / BLOCK_COUNT + 1, however much more self-documenting that looks.
//
// They were spelled that way until v1.8.2 and it was a trap. BLOCK_COUNT terminates the
// enum above, whose own comment invites appending — so appending one id, the single most
// natural thing a person adding a block does, would move BLOCK_COUNT from 8 to 9 and drag
// BLOCK_WATER to 9 and BLOCK_TALL_GRASS to 10 with it. The build stays clean. The saved
// chunks do not move: registry.c's core table uses designated initialisers [8] and [9], so
// the ROWS stay put while the SYMBOLS slide off them, and every saved world still holds
// byte 8 for water and still renders it as water because the mesher reads the raw id.
// What breaks is everything that says BLOCK_WATER by name — worldgen, world/water.c, the
// liquid checks, the mesher's deferred pass — all of it now talking about tall grass,
// while BLOCK_TALL_GRASS names an undefined row and becomes a hole. And BLOCK_COUNT is the
// WIRE item span (see above), so moving it to 9 also silently offers id 8 to
// BS_INV_OP_PICKUP while the server still refuses it at 8.
//
// So the corruption is not in the file; it is in the meaning of the symbol, and it
// presents as bad worldgen and strange water rather than as any kind of error. This
// codebase has been bitten by that exact shape before — see world/atlas_uv.h's note that a
// wrong texture constant still renders A texture, so the bug looks like bad art.
//
// The asserts below are what make that impossible: they fail the build the moment the
// literals stop agreeing with what the enum implies. v1.8.8 widened the PREDICATE exactly as
// this paragraph used to prescribe, and BLOCK_COUNT did not move — which is the shape every
// future widening should copy. When the survival rung really does give water a bucket, that
// is one more row's worth of behaviour inside inventoryCanHold(), still not an append here.
enum {
	BLOCK_WATER      = 8,
	BLOCK_TALL_GRASS = 9,
	// v1.8.3 Phase 3. Literals for the same reason as the two above, and the ⚠ note
	// applies to every one of them: do not tidy these into BLOCK_COUNT + n.
	BLOCK_SNOW       = 10,
	BLOCK_ICE        = 11,
	BLOCK_CACTUS     = 12,
	BLOCK_DEAD_BUSH  = 13,
	BLOCK_FERN       = 14,
	// ── v1.8.8: per-biome timber and flora, ids 15..26 ─────────────────────────────────
	//
	// Literals, for the same reason as every id above them; the ⚠ note applies unchanged.
	//
	// Twelve rows and not more. Biome COLOUR is a tint applied by the mesher, not an id —
	// there is deliberately no "taiga grass" or "jungle dirt" here, because a block only
	// earns an id when it BEHAVES or DRAWS differently, and a recoloured grass block does
	// neither. What is below is materials: two more species of tree whose bark, boards and
	// canopies are drawn differently rather than tinted differently, the upper half of a
	// two-block grass clump, four flowers that grow in different biomes, and a fruit.
	BLOCK_BIRCH_LOG     = 15,
	BLOCK_BIRCH_PLANKS  = 16,
	BLOCK_BIRCH_LEAVES  = 17,
	BLOCK_SPRUCE_LOG    = 18,
	BLOCK_SPRUCE_PLANKS = 19,
	BLOCK_SPRUCE_LEAVES = 20,
	BLOCK_TALL_GRASS_TOP = 21,
	BLOCK_POPPY         = 22,
	BLOCK_DAISY         = 23,
	BLOCK_BLUEBELL      = 24,
	BLOCK_ORCHID        = 25,
	BLOCK_APPLE         = 26,
	// ── v1.8.10 "Light": the first light source ────────────────────────────────────────
	//
	// A literal, for the same reason as every id above it; the ⚠ note applies unchanged.
	// docs/plan-1.8.10-light.md §2.3 is the design: BLOCK_SHAPE_CROSS (the shape tall
	// grass and the four flowers already use), non-solid, luminance set to 14 — the top
	// of Minecraft's torch range and one below this registry's 4-bit ceiling of 15, kept
	// off the ceiling only because 14 is the number the ask actually named. §2.3 also
	// says plainly that nothing in world/mesher.c has to change: emitCross() already
	// draws any BLOCK_SHAPE_CROSS block, so this is content riding existing geometry.
	BLOCK_TORCH         = 27,
};
_Static_assert(BLOCK_COUNT == 8,
               "BLOCK_COUNT is the closed first item span and is written into every shipped "
               "save and packet; it must never move");
_Static_assert(BLOCK_WATER == 8 && BLOCK_TALL_GRASS == 9,
               "water and tall grass ids are on players' SD cards; they must never move");
_Static_assert(BLOCK_SNOW == 10 && BLOCK_ICE == 11 && BLOCK_CACTUS == 12 &&
                   BLOCK_DEAD_BUSH == 13 && BLOCK_FERN == 14,
               "v1.8.3 Phase 3's ids are written into saved chunks and block-edit packets "
               "the moment a server ships them; they must never move");
_Static_assert(BLOCK_BIRCH_LOG == 15 && BLOCK_BIRCH_PLANKS == 16 &&
                   BLOCK_BIRCH_LEAVES == 17 && BLOCK_SPRUCE_LOG == 18 &&
                   BLOCK_SPRUCE_PLANKS == 19 && BLOCK_SPRUCE_LEAVES == 20 &&
                   BLOCK_TALL_GRASS_TOP == 21 && BLOCK_POPPY == 22 && BLOCK_DAISY == 23 &&
                   BLOCK_BLUEBELL == 24 && BLOCK_ORCHID == 25 && BLOCK_APPLE == 26,
               "v1.8.8's per-biome ids are written into saved chunks and block-edit packets "
               "the moment a server ships them; they must never move");
_Static_assert(BLOCK_TORCH == 27,
               "v1.8.10's torch id is written into saved chunks and block-edit packets the "
               "moment a server ships it; it must never move");

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
	// v1.8.3 Phase 3, slots 12..16. Same order as gfx/atlas_tiles.h and as
	// tools/make_atlas.py's TILES list, which is what makes each name land on its own art;
	// world/block_tiles_check.c fails the build if the two enums ever disagree.
	BTEX_SNOW,
	BTEX_ICE,
	BTEX_CACTUS,
	BTEX_DEAD_BUSH,
	BTEX_FERN,
	// v1.8.8, slots 17..30. Same order as gfx/atlas_tiles.h and as tools/make_atlas.py's
	// TILES list; world/block_tiles_check.c fails the build if the two enums disagree.
	BTEX_BIRCH_LOG_SIDE,
	BTEX_BIRCH_LOG_TOP,
	BTEX_BIRCH_PLANKS,
	BTEX_BIRCH_LEAVES,
	BTEX_SPRUCE_LOG_SIDE,
	BTEX_SPRUCE_LOG_TOP,
	BTEX_SPRUCE_PLANKS,
	BTEX_SPRUCE_LEAVES,
	BTEX_TALL_GRASS_TOP,
	BTEX_POPPY,
	BTEX_DAISY,
	BTEX_BLUEBELL,
	BTEX_ORCHID,
	BTEX_APPLE,
	// v1.8.10 "Light", slot 31. Same order as gfx/atlas_tiles.h and as
	// tools/make_atlas.py's TILES list; world/block_tiles_check.c fails the build if the
	// two enums disagree.
	BTEX_TORCH,
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
	// How long a bare hand takes to break this block, in 20 TPS ticks (v1.9.x task 50).
	// Copied straight out of BlockDef.hardness, which has carried this byte on the wire and
	// in registry.bin since v1.6.0 Phase A — the read-side view simply never exposed it, so
	// every caller that wanted it had to reach past blockInfo() into the registry. 0 means
	// "no break time", which is air and water: neither is targetable, so neither is ever
	// asked. world/mining.h turns this into the number of ticks a break actually takes.
	uint8_t     hardness;
} BlockInfo;

// Never returns NULL — an unknown id reads back as air, because a bad id should
// leave a hole rather than crash a mesher mid-chunk.
const BlockInfo* blockInfo(BlockId id);

static inline bool blockIsSolid(BlockId id) { return blockInfo(id)->solid; }
static inline bool blockIsAir(BlockId id)   { return id == BLOCK_AIR; }

// Bare-hand break time in 20 TPS ticks. Zero for anything with no break time of its own —
// air, and the ids no raycast will ever hand you. See world/mining.h for the arithmetic
// that turns this into a break duration; this is only the lookup.
//
// ⚠ ADDING A BLOCK: its break time is the `.hardness` byte on its row in
// world/registry.c's kCoreDefs[], and there is no default worth having. A row written
// without one gets 0 from the designated-initialiser zero-fill, breakTicksRequired()
// returns 0, and the block shatters the instant the button goes down — a plausible-looking
// block with no durability at all, and nothing in any build reports it. That is why
// world/registry_test.c's coreHardnessIsDeclared() fails the host suite for any DEFINED,
// TARGETABLE core row whose hardness is 0. If a row genuinely must be 0, it has to be
// untargetable (a liquid, like water) and the test exempts it for that reason and no other.
static inline uint8_t blockHardnessTicks(BlockId id) { return blockInfo(id)->hardness; }

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

// ⚠ The item-id ceiling — "may the bag hold this id" — is NOT in this header. It is
// world/inventory.h's inventoryCanHold(), and since v1.8.8 it is answered from the registry
// (defined, not air, not a liquid) rather than by comparing against BLOCK_COUNT.
//
// It is over there and not here for a link reason worth knowing before moving it back: this
// header is mirrored into deps/blocksmith-server, but block.c is NOT — that server's own
// game/Makefile says so in as many words ("block.h has no block.c ... there is no
// world/block.o"). The server does compile world/inventory.c and world/registry.c, so a
// predicate written over registry.h links on both sides and one written over blockInfo() does
// not. It would compile here and fail to link there.

// Whether breaking this block yields nothing to carry (v1.7.1 task 47).
//
// This exists because scene/interact.c used to ask ONE question — "can the bag hold what I am
// about to break?" — and treat a no as "then it cannot be broken". That is right for a block
// whose id the bag genuinely refuses (since v1.8.8: a liquid, or an id with no registry row at
// all — see world/inventory.h's inventoryCanHold(), and the ⚠ beside blockIsTargetable), and
// wrong for a plant, which is meant to break and simply has nothing to give you. The two had
// been the same question only by coincidence, and the coincidence broke the moment task 19
// shipped tall grass: the comment on
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
