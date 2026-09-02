// The master block registry — implementation. See registry.h for the contract.
#include "world/registry.h"

#include <stdio.h>
#include <string.h>

// The compiled-in core rows, ids 0x00..0x1A. These are the old kBlocks[] table
// recast as BlockDefs; the ids and textures are frozen forever because every
// saved region file and every replay encodes them by number.
//
// 0x00..0x07 are the WIRE item span (world/block.h's BLOCK_COUNT and the server's
// BS_BLOCK_COUNT). Since v1.8.8 that is all BLOCK_COUNT means: what the BAG may hold is
// world/inventory.h's inventoryCanHold(), which reads THIS table through registryIsDefined()
// and registryView() — defined, not air, not a liquid — so every row here except air and
// water is carryable, and a row added below is carryable the moment it exists.
// world/inventory.h holds the whole account of the split and of what the wire still costs.
//
// ── ⚠ ADDING A BLOCK — the five places, and the one that bites ────────────────────────
//
// Do all five. Four of them fail loudly if you miss them; the fifth does not, which is why
// it is listed first.
//
//   1. THIS TABLE — the row, INCLUDING `.hardness`.
//      A row written without .hardness gets 0 from the designated-initialiser zero-fill.
//      Nothing warns. blockHardnessTicks() returns 0, breakTicksRequired() returns 0, and
//      the block shatters on the first frame of the press — a block that looks finished and
//      has no durability at all. This is the failure mode this note exists for.
//      world/registry_test.c's coreHardnessIsDeclared() is the backstop: it fails the host
//      suite for any DEFINED and TARGETABLE core row whose hardness is 0. Only an
//      untargetable row (a liquid — see water at [8]) may legitimately be 0, and it is
//      exempted for exactly that reason.
//   2. world/block.h — the BLOCK_* id, as a LITERAL outside the BLOCK_COUNT enum. That
//      header's own ⚠ note explains at length why it must be a literal; do not append to
//      the enum.
//   3. world/block.h — the BTEX_* tile constant, in the same order as gfx/atlas_tiles.h.
//      world/block_tiles_check.c static-asserts the two enums agree, so a mismatch fails
//      the build.
//   4. tools/make_atlas.py — the tile's entry in TILES and the function that draws it.
//      Art is generated, never borrowed. A missing tile renders ATLAS_TILE_MISSING.
//   5. world/block.h's _Static_assert list — pin the new id's number, so a later append
//      cannot slide it.
//   6. THE MIRRORED TEST PINS — a fifth place beyond the four above, and it bites exactly
//      like #1 does: nothing here fails to COMPILE, the host suite fails to PASS.
//      world/registry_test.c's REGISTRY_FULL_COUNT_PIN, the "27 core blocks" literal in
//      testRegistryRoundTrip(), the pinned CRC in testRegistryCrcStability(), the row count
//      in coreHardnessIsDeclared(), and REGISTRY_TEST_EXPECTED_CHECKS all move together —
//      count and check-count by exactly one, the CRC to a new value you must COMPUTE (a
//      scratchpad probe linking the real registry.c/block.c and printing registryCrc16(),
//      never hand-fit to whatever makes the test pass). world/mining_test.c's matching row
//      count and its own named CHECK for the new block's break time move with it. And
//      deps/blocksmith-server/game/bsgame_test.c's BS_REGISTRY_CORE_COUNT_GOLDEN /
//      BS_REGISTRY_CORE_CRC16_GOLDEN, in the repo tools/sync-world-sources.sh vendors this
//      table into, move too — computed the same way, not guessed, and shipped server-first.
//      tools/run_host_tests.sh runs under `set -e`, so a stale pin here does not just fail
//      loudly, it aborts the whole host suite at this file and skips every test after it.
//
// Nothing in step 1 needs an inventory or interact.c edit any more. That was the point of
// v1.8.8: the bag reads the registry, so a correct row IS a carryable, breakable block.
//
// ── .hardness (roadmap task 50) ────────────────────────────────────────────────────────
//
// The unit is TICKS at 20 TPS — world/tick.h's clock — and not deciseconds, not seconds,
// not frames. Ticks because the ARM11 has no hardware divide instruction and this project
// avoids a runtime division wherever a stored value will do: a break timer counting ticks
// compares against this byte directly, where deciseconds would need a divide (or a second
// constant) at every comparison. Frames were never a candidate; world/tick.h's own header
// says why, and world/mining.h repeats it at the call site.
//
// These numbers are TUNED FOR A TOOLLESS GAME and are deliberately not Minecraft's. There
// are no tools in this codebase yet (world/inventory.h says so outright: an ItemId IS a
// BlockId), so every break is a bare-hand break, and Minecraft's bare-hand stone at 7.5 s
// would be nothing but a wait. Roadmap task 32 (v1.10.0) introduces tools and retunes
// these; until then:
//
//   grass / dirt   12 ticks = 0.60 s     sand         10 ticks = 0.50 s
//   stone          45 ticks = 2.25 s     wood/planks  40 ticks = 2.00 s
//   leaves          4 ticks = 0.20 s     tall grass    1 tick  = 0.05 s
//
// Air and water are 0, set explicitly rather than left to the zero-fill. Neither is
// targetable (blockIsTargetable() is `drawn && !liquid`, and air is not drawn), so neither
// value is ever read — writing them down says that is a decision and not an omission.
static const BlockDef kCoreDefs[REG_ID_DYN_LO] = {
	[REG_ID_AIR] = {
		.name  = "air",
		.tex   = { 0, 0, 0, 0, 0, 0 },
		.flags = REG_FLAG_TRANSPARENT,
		.hardness = 0,
	},
	[1] = { // grass
		.name  = "grass",
		.tex   = { BTEX_GRASS_SIDE, BTEX_GRASS_SIDE, BTEX_GRASS_TOP,
		           BTEX_DIRT,        BTEX_GRASS_SIDE, BTEX_GRASS_SIDE },
		.flags = REG_FLAG_SOLID,
		.hardness = 12,
	},
	[2] = {
		.name  = "dirt",
		.tex   = { BTEX_DIRT, BTEX_DIRT, BTEX_DIRT, BTEX_DIRT, BTEX_DIRT, BTEX_DIRT },
		.flags = REG_FLAG_SOLID,
		.hardness = 12,
	},
	[3] = {
		.name  = "stone",
		.tex   = { BTEX_STONE, BTEX_STONE, BTEX_STONE,
		           BTEX_STONE, BTEX_STONE, BTEX_STONE },
		.flags = REG_FLAG_SOLID,
		.hardness = 45,
	},
	[4] = {
		.name  = "sand",
		.tex   = { BTEX_SAND, BTEX_SAND, BTEX_SAND, BTEX_SAND, BTEX_SAND, BTEX_SAND },
		.flags = REG_FLAG_SOLID,
		.hardness = 10,
	},
	[5] = { // wood
		.name  = "wood",
		.tex   = { BTEX_WOOD_SIDE, BTEX_WOOD_SIDE, BTEX_WOOD_TOP,
		           BTEX_WOOD_TOP,  BTEX_WOOD_SIDE, BTEX_WOOD_SIDE },
		.flags = REG_FLAG_SOLID,
		.hardness = 40,
	},
	[6] = { // leaves: solid (fills its cell) but transparent (alpha-0 holes)
		.name  = "leaves",
		.tex   = { BTEX_LEAVES, BTEX_LEAVES, BTEX_LEAVES,
		           BTEX_LEAVES, BTEX_LEAVES, BTEX_LEAVES },
		.flags = REG_FLAG_SOLID | REG_FLAG_TRANSPARENT,
		.hardness = 4,
	},
	[7] = { // planks
		.name  = "planks",
		.tex   = { BTEX_PLANKS, BTEX_PLANKS, BTEX_PLANKS,
		           BTEX_PLANKS, BTEX_PLANKS, BTEX_PLANKS },
		.flags = REG_FLAG_SOLID,
		.hardness = 40,
	},
	// Roadmap task 17. A full cube, drawn, NOT solid, and a liquid.
	//
	// Every one of those is load-bearing, so one at a time:
	//
	//   not SOLID       world/physics.c collides on blockIsSolid() alone, so the player
	//                   box walks and falls straight through. There is no swimming today
	//                   and none is half-built here: standing in water is standing in air
	//                   that happens to be blue, and a head inside a water cell does
	//                   nothing at all — no drowning, no drag, no screen tint. Flow,
	//                   spread and drainage are roadmap task 22.
	//                   It also means water never occludes, because mesher.c's s_occludes
	//                   is `solid && !transparent && cube`: the seabed's faces under an
	//                   ocean are still built and still drawn, behind opaque water. That
	//                   cost is accepted rather than fixed here — the only way to make
	//                   water occlude is to make it solid, and a solid sea is a wall.
	//   TRANSPARENT     this is what buys the self-culling. mesher.c applies its
	//                   same-material rule (`deferred && s_cell_draw[ni] &&
	//                   blocks[ni] == id`) only inside the deferred pass, and s_deferred
	//                   is `drawn && (transparent || !cube)`. Without this flag a body of
	//                   water would mesh every internal face it has — thousands of quads
	//                   for an ocean, not one of them ever visible. With it, only the
	//                   shell is built. It also states the flag's plain meaning: water
	//                   does not hide what is behind it.
	//   LIQUID          blockIsTargetable() is `drawn && !liquid`, so the crosshair passes
	//                   through water: it cannot be aimed at, mined, or placed against.
	//                   That is the whole reason REG_FLAG_LIQUID exists.
	//   FULL_CUBE       implicit (shape 0). A body of water is cells of water; a surface
	//                   cell is not a special half-height block and will not need to be
	//                   until task 22 gives water levels.
	//
	// The ART is opaque — see tools/make_atlas.py's tile_water for why one bit of alpha
	// cannot make a translucent sea and why a dither of holes is worse than a solid
	// surface at 16x16 on a 240px screen.
	[8] = { // water
		.name  = "water",
		.tex   = { BTEX_WATER, BTEX_WATER, BTEX_WATER,
		           BTEX_WATER, BTEX_WATER, BTEX_WATER },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_LIQUID,
		// Explicitly 0 and not defaulted: water carries REG_FLAG_LIQUID, so
		// blockIsTargetable() is false and no break timer can ever ask. Written down so a
		// later reader knows it is a decision rather than a row that was missed.
		.hardness = 0,
	},
	// Roadmap task 19, and the first block in the game to use BLOCK_SHAPE_CROSS — the
	// non-cube geometry path v1.6.0 task 13 built into world/mesher.c and that nothing
	// has exercised since.
	//
	//   CROSS           two quads on the cell's diagonals, emitted four times so both
	//                   windings exist (mesher.c's emitCross). All six tex entries carry
	//                   the same tile because emitCross takes FACE_EAST's rect for the
	//                   whole shape.
	//   not SOLID       walked through freely, exactly like water: physics.c asks
	//                   blockIsSolid() and nothing else. planBuild() also refuses to let
	//                   a non-cube be solid for AO or occlusion whatever this flag says
	//                   (its `&& cube` terms), so an X can never darken a neighbour's
	//                   corners or cull its faces.
	//   TRANSPARENT     its plain meaning: it does not hide what is behind it. The
	//                   deferred alpha-test pass it needs is already forced by the SHAPE
	//                   (s_deferred's `|| !cube`), so this flag is not what puts it
	//                   there — it is set because it is true, and because the one block
	//                   in the registry whose art is mostly alpha 0 should not be
	//                   claiming otherwise.
	//   not LIQUID      so blockIsTargetable() is true. v1.6.0's raycast rule is that
	//                   what stops a ray is "can this be removed", not "is this solid":
	//                   scenery that can never be targeted is scenery that can never be
	//                   cleared. The whole cell is the target, not the two quads inside
	//                   it — world/raycast.c says so in as many words.
	//
	// Breaking it YIELDS nothing today, but it is not REFUSED — a distinction this comment
	// got wrong until 2026-08-30. scene/interact.c:178 guards with
	//
	//     if (!blockDropsNothing(here) && !inventoryCanHold(here)) { ...refuse... }
	//
	// and world/block.h defines blockDropsNothing() as `shape == BLOCK_SHAPE_CROSS`.
	// Tall grass IS a CROSS, so the first term is false, the guard never fires, and the
	// block is removed normally; only the pickup is skipped. Measured by a probe linked
	// against this file and world/block.c, not reasoned off the guard's shape.
	//
	// v1.8.8 changes WHY the pickup is skipped and nothing else about this row. It used to
	// be skipped because tall grass sits past BLOCK_COUNT and inventoryCanHold() answered
	// false; the bag would take it now, but breakComplete() still hands the bag BLOCK_AIR
	// for any CROSS block, so no plant id reaches a slot. Same behaviour, resting on the
	// rule the code actually states instead of on where a ceiling happened to fall.
	//
	// What v1.8.8 DID change is the three FULL_CUBE rows below — snow, ice and cactus were
	// genuinely refused, i.e. not merely dropless but UNBREAKABLE, which is the defect steve
	// reported against the cactus. All three break and drop themselves now. The two CROSS
	// rows below are unaffected.
	[9] = { // tall grass
		.name  = "tall_grass",
		.tex   = { BTEX_TALL_GRASS, BTEX_TALL_GRASS, BTEX_TALL_GRASS,
		           BTEX_TALL_GRASS, BTEX_TALL_GRASS, BTEX_TALL_GRASS },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	// ── v1.8.3 Phase 3: ids 10..14 ────────────────────────────────────────────────────
	//
	// Five more core rows, shipped by v1.8.3 Phase 3 with BLOCK_COUNT deliberately held at 8.
	// That was right for that rung — the ceiling and the blocks were two INDEPENDENT changes
	// and only the blocks were needed for terrain — but it left all five past
	// inventoryCanHold()'s `item < BLOCK_COUNT`, and for the three FULL_CUBE ones that was
	// not "uncollectable", it was UNBREAKABLE:
	//
	//   snow, ice, cactus   FULL_CUBE and past the ceiling, so scene/interact.c's guard —
	//                       `!blockDropsNothing(here) && !inventoryCanHold(here)` — refused
	//                       the break outright. Walk on them, aim at them, build against
	//                       them; never mine them.
	//   dead_bush, fern     CROSS, so blockDropsNothing() is true and the break is allowed;
	//                       it deletes the plant and yields nothing, identically to tall
	//                       grass.
	//
	// v1.8.8 fixed that, by the route world/block.h had been prescribing all along: widen the
	// PREDICATE, never the constant. inventoryCanHold() now reads this table (defined, not
	// air, not liquid), BLOCK_COUNT did not move, no saved chunk or packet changed shape, and
	// all three cubes break and drop themselves. The two CROSS rows are unchanged — carryable
	// in principle, still handed BLOCK_AIR by breakComplete().
	//
	// ── .hardness ──
	//
	// Every row here is now LIVE: all five are targetable and, since v1.8.8, all five can
	// actually reach a break timer. Until v1.8.8 only the two CROSS rows could — the three
	// cubes were refused before a timer started, so their numbers had never once been
	// exercised. Cactus's was retuned at its row below for exactly that reason; snow's and
	// ice's are left where Phase 3 put them, because those were already the values a break
	// would have used and there is no measurement saying otherwise. Tuned on the toolless
	// scale at the top of this file — sand 10, leaves 4:
	//
	//   snow    8 ticks = 0.40 s     softer than sand; it is settled snow, not packed ice
	//   ice    10 ticks = 0.50 s     sand's number; a solid pane, not a rock
	//   cactus  9 ticks = 0.45 s     plant matter, not timber; and its OWN number, not a
	//                               copy of snow's — see the row itself for why 8 became 9
	//   dead_bush / fern  1 tick     tall grass's number; every CROSS plant is instant
	[10] = { // snow — the tundra surface cap, replacing v1.8.3 Phase 2's bare-dirt placeholder
		.name  = "snow",
		.tex   = { BTEX_SNOW, BTEX_SNOW, BTEX_SNOW,
		           BTEX_SNOW, BTEX_SNOW, BTEX_SNOW },
		.flags = REG_FLAG_SOLID,
		.hardness = 8,
	},
	// Ice. SOLID and NOT transparent, and both are deliberate.
	//
	//   SOLID          you walk on a frozen lake; it is the surface, not the water under it.
	//                  world/physics.c collides on blockIsSolid() alone, so this one flag is
	//                  the whole of that behaviour.
	//   not LIQUID     so blockIsTargetable() is true and the crosshair stops on it, which
	//                  is what lets a player build against a frozen lake. Under v1.8.3 that
	//                  made it unbreakable by the ITEM ceiling rather than by being invisible
	//                  to the raycast — a distinction Phase 3 said would matter the day the
	//                  ceiling widened. v1.8.8 is that day: not being a liquid is now exactly
	//                  what makes ice carryable, so it breaks and drops itself, and the flag
	//                  set on this row did not have to change for that to happen.
	//   not TRANSPARENT   the ART is opaque. tools/make_atlas.py's tile_ice says why in
	//                  full: this sheet is RGBA5551, the pass is an alpha TEST, and one bit
	//                  of alpha cannot make a translucent pane — a dither of holes at 16x16
	//                  on a 240 px screen reads as holes in the ice, not as glass. Claiming
	//                  TRANSPARENT for art that is opaque would cost the mesher every
	//                  internal face of a frozen lake and buy nothing visible.
	[11] = { // ice
		.name  = "ice",
		.tex   = { BTEX_ICE, BTEX_ICE, BTEX_ICE, BTEX_ICE, BTEX_ICE, BTEX_ICE },
		.flags = REG_FLAG_SOLID,
		.hardness = 10,
	},
	// Cactus. A FULL_CUBE and not a shape of its own: this build has two shapes, and the
	// 15/16-of-a-cube column other games use would need a third one — new geometry in
	// world/mesher.c, a new value in the three reserved shape bits, and a wire change. That
	// is a bigger rung than this one. A full cube of cactus art is what ships; the shape
	// enum has room for the narrow version whenever somebody writes the mesher path.
	//
	// No damage-on-touch: there is no damage system in this build at all.
	//
	// v1.8.8 retunes .hardness from 8 to 9. Two reasons, and the first is the one that
	// matters: until v1.8.8 this row's hardness was NEVER READ. Cactus was past the old
	// item ceiling, so scene/interact.c refused the break before a timer could start, and
	// the 8 written here was an unexercised guess. It is a live number now — this is the
	// block v1.8.8 exists to make breakable — so it gets picked rather than inherited.
	//
	// 9 ticks = 0.45 s, and it is 9 and not 8 so that it is ITS OWN durability rather than
	// a duplicate of the row above it: snow is 8 and ice is 10, and a cactus reading
	// identically to settled snow says the number was never considered. Between the two is
	// where cactus belongs on the toolless scale at the top of this file — tougher than
	// snow, softer than a pane of ice, and well under sand's 10 because it is plant matter
	// and not mineral. It is a game-feel number and it is meant to be retuned by hand; what
	// is NOT negotiable is that it is nonzero and deliberate. See world/block.h's note on
	// blockHardnessTicks and registry_test.c's coreHardnessIsDeclared().
	[12] = { // cactus
		.name  = "cactus",
		.tex   = { BTEX_CACTUS, BTEX_CACTUS, BTEX_CACTUS,
		           BTEX_CACTUS, BTEX_CACTUS, BTEX_CACTUS },
		.flags = REG_FLAG_SOLID,
		.hardness = 9,
	},
	// The two CROSS plants. Same flag set and the same reasoning as tall grass at [9], which
	// world/block.h's blockDropsNothing() note calls out by name: answering from the SHAPE
	// rather than from an id is precisely what makes these two correct without touching
	// scene/interact.c. All six tex entries carry the same tile because mesher.c's emitCross
	// takes FACE_EAST's rect for the whole shape.
	[13] = { // dead bush — desert flora
		.name  = "dead_bush",
		.tex   = { BTEX_DEAD_BUSH, BTEX_DEAD_BUSH, BTEX_DEAD_BUSH,
		           BTEX_DEAD_BUSH, BTEX_DEAD_BUSH, BTEX_DEAD_BUSH },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	[14] = { // fern — taiga and jungle undergrowth
		.name  = "fern",
		.tex   = { BTEX_FERN, BTEX_FERN, BTEX_FERN,
		           BTEX_FERN, BTEX_FERN, BTEX_FERN },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	// ── v1.8.8: per-biome timber and flora, ids 15..26 ────────────────────────────────
	//
	// Twelve rows. What is NOT here is as deliberate as what is: there is no taiga grass,
	// no jungle dirt and no desert-tinted anything, because biome COLOUR is a per-vertex
	// tint applied by the mesher and an id buys nothing a tint does not already give. A
	// row below exists only where the block draws geometry the tinted original does not
	// have, or behaves differently:
	//
	//   birch / spruce logs      the bark MARKS differ, not the hue. Birch carries
	//                            horizontal lenticel dashes; spruce carries vertical scaly
	//                            plates split by fissures. A multiply of tile 6 cannot add
	//                            a mark that is not in tile 6.
	//   birch / spruce planks    birch is a near-white board (base 198,186,158) and oak's
	//                            is mid-brown. A tint MULTIPLIES, so it can only darken:
	//                            oak can be made into spruce's dark red-brown and can never
	//                            be made into birch at all. Two of these three boards are
	//                            unreachable from one tile.
	//   birch / spruce leaves    a broadleaf clump and a needled speckle carved on the
	//                            diagonal. Different cutout patterns, so different silhouettes
	//                            against the sky — the one thing a tint provably cannot change.
	//   tall_grass_top           BEHAVIOUR: it is the upper half of a two-block clump, placed
	//                            only above a tall_grass, and its art has to meet that block's
	//                            blades at the seam.
	//   poppy/daisy/bluebell/orchid   four different FLOWERS. The petal shape is drawn per
	//                            bloom kind (cup, disc, bell); the colour is only what makes
	//                            them recognisable afterwards.
	//   apple                    BEHAVIOUR: the only new row that is a FULL_CUBE and drops
	//                            itself. See its own note.
	//
	// ── .hardness ──
	//
	// Tuned on the toolless scale at the top of this file, and picked against neighbours
	// rather than copied from them:
	//
	//   birch log / planks   36 = 1.80 s   under oak's 40: birch is the light, soft hardwood
	//   spruce log / planks  44 = 2.20 s   over oak's 40 and just under stone's 45: dense,
	//                                      resinous conifer timber, the toughest wood here
	//   birch leaves          3 = 0.15 s   under oak's 4; thin papery broadleaf
	//   spruce leaves         5 = 0.25 s   over oak's 4; a packed mat of needles
	//   apple                 2 = 0.10 s   soft fruit — under every leaf, over every plant
	//   tall_grass_top        1            tall grass's number, because it IS tall grass
	//   the four flowers      1            the CROSS-plant floor this file already keeps for
	//                                      tall grass, dead bush and fern. One tick is the
	//                                      minimum a nonzero hardness can be (mining.c floors
	//                                      a break at one tick), so "every CROSS plant is
	//                                      instant" is not a copy-paste — it is the only
	//                                      value the class can hold, and making a daisy
	//                                      tougher than a poppy would be inventing a
	//                                      difference the game does not have.
	//
	// Planks deliberately equal their own log, exactly as oak's 40/40 do: a board is the
	// same timber, sawn.
	[15] = { // birch log
		.name  = "birch_log",
		.tex   = { BTEX_BIRCH_LOG_SIDE, BTEX_BIRCH_LOG_SIDE, BTEX_BIRCH_LOG_TOP,
		           BTEX_BIRCH_LOG_TOP,  BTEX_BIRCH_LOG_SIDE, BTEX_BIRCH_LOG_SIDE },
		.flags = REG_FLAG_SOLID,
		.hardness = 36,
	},
	[16] = { // birch planks
		.name  = "birch_planks",
		.tex   = { BTEX_BIRCH_PLANKS, BTEX_BIRCH_PLANKS, BTEX_BIRCH_PLANKS,
		           BTEX_BIRCH_PLANKS, BTEX_BIRCH_PLANKS, BTEX_BIRCH_PLANKS },
		.flags = REG_FLAG_SOLID,
		.hardness = 36,
	},
	// The two leaf rows carry oak's flag set exactly — SOLID (fills its cell) and
	// TRANSPARENT (alpha-0 holes), see [6] — so they self-cull in the deferred pass and
	// never occlude. Nothing about the canopy path changes for a second species.
	[17] = { // birch leaves
		.name  = "birch_leaves",
		.tex   = { BTEX_BIRCH_LEAVES, BTEX_BIRCH_LEAVES, BTEX_BIRCH_LEAVES,
		           BTEX_BIRCH_LEAVES, BTEX_BIRCH_LEAVES, BTEX_BIRCH_LEAVES },
		.flags = REG_FLAG_SOLID | REG_FLAG_TRANSPARENT,
		.hardness = 3,
	},
	[18] = { // spruce log
		.name  = "spruce_log",
		.tex   = { BTEX_SPRUCE_LOG_SIDE, BTEX_SPRUCE_LOG_SIDE, BTEX_SPRUCE_LOG_TOP,
		           BTEX_SPRUCE_LOG_TOP,  BTEX_SPRUCE_LOG_SIDE, BTEX_SPRUCE_LOG_SIDE },
		.flags = REG_FLAG_SOLID,
		.hardness = 44,
	},
	[19] = { // spruce planks
		.name  = "spruce_planks",
		.tex   = { BTEX_SPRUCE_PLANKS, BTEX_SPRUCE_PLANKS, BTEX_SPRUCE_PLANKS,
		           BTEX_SPRUCE_PLANKS, BTEX_SPRUCE_PLANKS, BTEX_SPRUCE_PLANKS },
		.flags = REG_FLAG_SOLID,
		.hardness = 44,
	},
	[20] = { // spruce leaves
		.name  = "spruce_leaves",
		.tex   = { BTEX_SPRUCE_LEAVES, BTEX_SPRUCE_LEAVES, BTEX_SPRUCE_LEAVES,
		           BTEX_SPRUCE_LEAVES, BTEX_SPRUCE_LEAVES, BTEX_SPRUCE_LEAVES },
		.flags = REG_FLAG_SOLID | REG_FLAG_TRANSPARENT,
		.hardness = 5,
	},
	// The upper half of the two-block grass clump steve asked for. Its own row and not a
	// second tall_grass, because the two halves must draw DIFFERENT art — the lower cell
	// carries blade bases and the upper carries the tips — and the tex byte is per-id.
	// Placed only directly above a tall_grass by worldgen; it is an ordinary CROSS plant
	// otherwise, and breaking either half leaves the other standing (there is no
	// multi-block-structure system in this build, and inventing one is not this rung).
	[21] = { // tall grass, upper half
		.name  = "tall_grass_top",
		.tex   = { BTEX_TALL_GRASS_TOP, BTEX_TALL_GRASS_TOP, BTEX_TALL_GRASS_TOP,
		           BTEX_TALL_GRASS_TOP, BTEX_TALL_GRASS_TOP, BTEX_TALL_GRASS_TOP },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	// The four flowers. Same flag set and the same reasoning as tall grass at [9] and the
	// two plants at [13]/[14]: CROSS, transparent, not solid, not liquid — so they are
	// targetable and breakable, walked through freely, and yield nothing (breakComplete()
	// hands the bag BLOCK_AIR for any CROSS block). All six tex entries carry the same tile
	// because mesher.c's emitCross takes FACE_EAST's rect for the whole shape.
	//
	// Which biome each grows in is worldgen's business, not the registry's — see
	// worldgenFlora() in world/worldgen.c. Nothing here is biome-aware.
	[22] = { // poppy — plains and forest
		.name  = "poppy",
		.tex   = { BTEX_POPPY, BTEX_POPPY, BTEX_POPPY,
		           BTEX_POPPY, BTEX_POPPY, BTEX_POPPY },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	[23] = { // daisy — plains
		.name  = "daisy",
		.tex   = { BTEX_DAISY, BTEX_DAISY, BTEX_DAISY,
		           BTEX_DAISY, BTEX_DAISY, BTEX_DAISY },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	[24] = { // bluebell — forest and taiga
		.name  = "bluebell",
		.tex   = { BTEX_BLUEBELL, BTEX_BLUEBELL, BTEX_BLUEBELL,
		           BTEX_BLUEBELL, BTEX_BLUEBELL, BTEX_BLUEBELL },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	[25] = { // orchid — jungle
		.name  = "orchid",
		.tex   = { BTEX_ORCHID, BTEX_ORCHID, BTEX_ORCHID,
		           BTEX_ORCHID, BTEX_ORCHID, BTEX_ORCHID },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	// Apple. A FULL_CUBE, and that is the load-bearing decision on this row.
	//
	// It has to be a cube because world/block.h's blockDropsNothing() answers from the
	// SHAPE, and scene/interact.c hands the bag BLOCK_AIR for every CROSS block. A CROSS
	// apple would break and yield NOTHING, which is precisely the opposite of the thing
	// steve asked for ("apples ... pickable and functional"). As a cube it is targetable,
	// its 2-tick timer runs, breakComplete() hands the bag BLOCK_APPLE, and
	// inventoryCanHold() takes it — defined, not air, not a liquid.
	//
	// SOLID and not TRANSPARENT because the art is fully opaque: measured 0 cutout texels
	// of 256 on slot 30. Claiming TRANSPARENT for opaque art would push it into the
	// deferred pass and cost the mesher every internal face it has, buying nothing.
	//
	// "Functional" here means exactly the three things this build can express: it can be
	// broken, it can be carried, and it can be placed again from the bag. There is no
	// hunger system in this codebase — nothing to eat it WITH — so eating is not half-built
	// here and is not claimed anywhere.
	[26] = { // apple — grows in oak and birch canopies
		.name  = "apple",
		.tex   = { BTEX_APPLE, BTEX_APPLE, BTEX_APPLE,
		           BTEX_APPLE, BTEX_APPLE, BTEX_APPLE },
		.flags = REG_FLAG_SOLID,
		.hardness = 2,
	},
	// ── v1.8.10 "Light": the torch ──────────────────────────────────────────────────────
	//
	// The first block in the game with luminance > 0. docs/plan-1.8.10-light.md §2.3 is the
	// design this row follows exactly: BLOCK_SHAPE_CROSS (the shape tall grass and the four
	// flowers already use — world/block.h:250-253), non-solid, TRANSPARENT for the same
	// reason every other CROSS row is, and luminance 14. That plan's own words: "luminance
	// set high (14 or 15, the top of the 4-bit scale)" — 14 and not 15 because that is
	// Minecraft's own torch light level and the ask names no reason to go past it; 15 is
	// still one step of headroom above every light source this game will ever have added,
	// unclaimed rather than spent here.
	//
	// LUMINOUS is set alongside .luminance for the same reason world_test.c's own probe
	// pairs the two (world/world_test.c:7177-7178): world/light.c's syncLuminance() only
	// ever reads the .luminance BYTE (registryGet(id)->luminance, light.c:350) — the flag
	// is not consumed by the lighting engine and gates nothing — but every existing test
	// that declares a luminous block sets both, and there is no reason for the one live
	// content row to be the first to diverge from that pairing.
	//
	// .hardness — a torch shatters instantly in Minecraft, and this schema's floor for
	// "instant but still has SOME durability" is 1 tick (0.05 s): world/mining.c's
	// breakTicksRequired() treats hardness 0 as "no break time at all" (air, water — see
	// its own comment), which is a block with NO durability, the exact defect this file's
	// header note exists to prevent. 1 is also not a special case invented for the torch —
	// it is the same number every BLOCK_SHAPE_CROSS row in this table already carries
	// (tall grass [9], dead bush/fern [13]/[14], tall_grass_top/the four flowers
	// [21]-[25]), so the torch reads as "instant, like every other plant" rather than as a
	// block that was never considered.
	[27] = { // torch — the first light source; docs/plan-1.8.10-light.md §2.3
		.name  = "torch",
		.tex   = { BTEX_TORCH, BTEX_TORCH, BTEX_TORCH,
		           BTEX_TORCH, BTEX_TORCH, BTEX_TORCH },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_LUMINOUS |
		         REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.luminance = 14,
		.hardness  = 1,
	},
};

// The table itself. s_defs holds the authoritative bytes; s_view is the derived
// BlockInfo the rest of the engine reads through blockInfo(). The view's name
// pointer aims into s_defs' own static storage, so it stays valid for the life
// of the process no matter how many rows are registered later.
static BlockDef  s_defs[REGISTRY_MAX];
static bool      s_used[REGISTRY_MAX];
static BlockInfo s_view[REGISTRY_MAX];
static uint8_t   s_count;
static uint8_t   s_next_dyn = REG_ID_DYN_LO;
static bool      s_frozen;
static bool      s_inited;

static void copyName(char dst[REGISTRY_NAME_MAX], const char* src)
{
	size_t i;
	for (i = 0; i + 1 < REGISTRY_NAME_MAX && src[i] != '\0'; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

// A name fits only if a NUL appears within the first REGISTRY_NAME_MAX bytes.
static bool nameFits(const char* src)
{
	for (size_t i = 0; i < REGISTRY_NAME_MAX; i++)
		if (src[i] == '\0') return true;
	return false;
}

static void refreshView(BlockId id)
{
	const BlockDef* d = &s_defs[id];
	BlockInfo*      v = &s_view[id];

	v->name        = d->name;
	v->solid       = (d->flags & REG_FLAG_SOLID) != 0;
	v->transparent = (d->flags & REG_FLAG_TRANSPARENT) != 0;
	v->liquid      = (d->flags & REG_FLAG_LIQUID) != 0;
	v->hardness    = d->hardness;

	// Three bits can name eight shapes and only two exist, so a def from a newer or a
	// tampered peer can carry a value this build has no geometry for. It reads back as
	// a full cube rather than as an out-of-range shape id: every consumer of
	// BlockInfo.shape switches on it, and a hole in that switch is a block that draws
	// nothing at all. Refusing the record instead would be the stricter answer, but it
	// belongs in registryDefUnpack() with the rest of the wire validation, and nothing
	// on the wire can produce a non-zero value yet.
	v->shape = regShapeOf(d->flags);
	if (v->shape >= BLOCK_SHAPE_COUNT) v->shape = BLOCK_SHAPE_FULL_CUBE;

	for (int f = 0; f < BLOCK_FACES; f++)
		v->tex[f] = d->tex[f];
}

static void install(BlockId id, const BlockDef* def)
{
	s_defs[id] = *def;
	copyName(s_defs[id].name, def->name);
	s_used[id] = true;
	s_count++;
	refreshView(id);
}

void registryInitCore(void)
{
	memset(s_used, 0, sizeof s_used);
	memset(s_defs, 0, sizeof s_defs);
	memset(s_view, 0, sizeof s_view);
	s_count    = 0;
	s_next_dyn = REG_ID_DYN_LO;
	s_frozen   = false;

	for (int id = 0; id < REG_ID_DYN_LO; id++) {
		if (kCoreDefs[id].name[0] == '\0') continue; // unassigned core slot
		BlockDef def = kCoreDefs[id];
		def.variant_of  = (uint8_t)id; // bases are their own variant root
		def.fluid_class = REG_FLUID_NONE;
		install((BlockId)id, &def);
	}

	s_inited = true;
}

static void ensureInit(void)
{
	if (!s_inited) registryInitCore();
}

bool registryFrozen(void)
{
	return s_frozen;
}

void registryFreeze(void)
{
	ensureInit();
	s_frozen = true;
}

BlockId registryRegister(const BlockDef* def)
{
	ensureInit();
	if (s_frozen || def == NULL) return 0;
	if (!nameFits(def->name) || def->name[0] == '\0') return 0;
	if (registryFind(def->name) != 0) return 0; // duplicate name

	for (int id = REG_ID_DYN_LO; id <= REG_ID_DYN_HI; id++) {
		if (s_used[id]) continue;
		install((BlockId)id, def);
		if ((uint8_t)id == s_next_dyn) s_next_dyn++;
		return (BlockId)id;
	}
	return 0; // dyn range full
}

const BlockDef* registryGet(BlockId id)
{
	ensureInit();
	if (!s_used[id]) return &s_defs[REG_ID_AIR];
	return &s_defs[id];
}

const BlockInfo* registryView(BlockId id)
{
	ensureInit();
	if (!s_used[id]) return &s_view[REG_ID_AIR];
	return &s_view[id];
}

BlockId registryFind(const char* name)
{
	ensureInit();
	if (name == NULL) return 0;
	for (int id = 0; id < REGISTRY_MAX; id++)
		if (s_used[id] && strcmp(s_defs[id].name, name) == 0)
			return (BlockId)id;
	return 0;
}

uint8_t registryCount(void)
{
	ensureInit();
	return s_count;
}

bool registryIsDefined(BlockId id)
{
	ensureInit();
	return s_used[id];
}

// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final xor.
static uint16_t crc16Update(uint16_t crc, const uint8_t* data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		crc ^= (uint16_t)((uint16_t)data[i] << 8);
		for (int b = 0; b < 8; b++) {
			const bool msb = (crc & 0x8000u) != 0;
			crc = (uint16_t)(crc << 1);
			if (msb) crc ^= 0x1021u;
		}
	}
	return crc;
}

uint16_t registryCrc16(void)
{
	ensureInit();
	uint16_t crc = 0xFFFF;
	uint8_t record[REGISTRY_WIRE_RECORD_BYTES];
	for (int id = 0; id < REGISTRY_MAX; id++) {
		if (!s_used[id]) continue;
		registryDefPack(record, (BlockId)id, &s_defs[id]);
		crc = crc16Update(crc, record, sizeof record);
	}
	return crc;
}

void registryDefPack(uint8_t out[REGISTRY_WIRE_RECORD_BYTES], BlockId id,
                     const BlockDef* def)
{
	out[0] = id;
	memcpy(&out[1], def->name, REGISTRY_NAME_MAX);
	memcpy(&out[17], def->tex, BLOCK_FACES);
	out[23] = def->flags;
	out[24] = def->luminance;
	out[25] = def->hardness;
	out[26] = def->variant_of;
	out[27] = def->fluid_class;
}

bool registryDefUnpack(BlockId* out_id, BlockDef* out_def,
                       const uint8_t in[REGISTRY_WIRE_RECORD_BYTES])
{
	const uint8_t id = in[0];
	if (id < REG_ID_DYN_LO || id > REG_ID_DYN_HI) return false;

	bool terminated = false;
	for (int i = 0; i < REGISTRY_NAME_MAX; i++)
		if (in[1 + i] == '\0') { terminated = true; break; }
	if (!terminated) return false;

	memset(out_def, 0, sizeof *out_def);
	memcpy(out_def->name, &in[1], REGISTRY_NAME_MAX);
	memcpy(out_def->tex, &in[17], BLOCK_FACES);
	out_def->flags       = in[23];
	out_def->luminance   = in[24];
	out_def->hardness    = in[25];
	out_def->variant_of  = in[26];
	out_def->fluid_class = in[27];
	*out_id = (BlockId)id;
	return true;
}

size_t registryRemoteApply(uint8_t first, const uint8_t* records, size_t n)
{
	ensureInit();
	if (n == 0) return 0;
	if (s_frozen) return 0;
	if (first < REG_ID_DYN_LO || (uint32_t)first + n - 1 > REG_ID_DYN_HI)
		return 0;
	// Both sides derive ids the same way (lowest free first), so a batch must
	// start exactly at this table's next free slot; anything else is a
	// tampered or reordered stream.
	if (first != s_next_dyn) return 0;

	// Validate everything before committing anything: a malformed batch must
	// not leave a half-applied table behind.
	BlockId        ids[REGISTRY_MAX];
	BlockDef       defs[REGISTRY_MAX];
	const uint8_t* rec = records;
	for (size_t i = 0; i < n; i++, rec += REGISTRY_WIRE_RECORD_BYTES) {
		BlockDef  def;
		BlockId   id;
		if (!registryDefUnpack(&id, &def, rec)) return 0;
		if (id != (BlockId)(first + i)) return 0;
		if (registryFind(def.name) != 0) return 0;
		for (size_t j = 0; j < i; j++)
			if (strcmp(defs[j].name, def.name) == 0) return 0;
		ids[i]  = id;
		defs[i] = def;
	}

	for (size_t i = 0; i < n; i++) {
		install(ids[i], &defs[i]);
		if (ids[i] == s_next_dyn) s_next_dyn++;
	}
	return n;
}

bool registrySidecarSave(const char* path)
{
	ensureInit();
	char tmp[512];
	snprintf(tmp, sizeof tmp, "%s.tmp", path);

	// Count the dynamic rows first so the header can carry the exact total.
	uint16_t count = 0;
	for (int id = REG_ID_DYN_LO; id <= REG_ID_DYN_HI; id++)
		if (s_used[id]) count++;

	FILE* f = fopen(tmp, "wb");
	if (f == NULL) return false;

	uint8_t header[2] = { (uint8_t)(count & 0xFFu), (uint8_t)(count >> 8) };
	if (fwrite(header, 1, sizeof header, f) != sizeof header) goto fail;

	uint8_t record[REGISTRY_WIRE_RECORD_BYTES];
	for (int id = REG_ID_DYN_LO; id <= REG_ID_DYN_HI; id++) {
		if (!s_used[id]) continue;
		registryDefPack(record, (BlockId)id, &s_defs[id]);
		if (fwrite(record, 1, sizeof record, f) != sizeof record) goto fail;
	}

	if (fclose(f) != 0) {
		remove(tmp);
		return false;
	}
	remove(path);
	return rename(tmp, path) == 0;

fail:
	fclose(f);
	remove(tmp);
	return false;
}

bool registrySidecarLoad(const char* path)
{
	ensureInit();
	FILE* f = fopen(path, "rb");
	if (f == NULL) return false;

	uint8_t header[2];
	if (fread(header, 1, sizeof header, f) != sizeof header) { fclose(f); return false; }
	const uint16_t count = (uint16_t)(header[0] | (header[1] << 8));

	// The dyn space holds at most REG_ID_DYN_HI - REG_ID_DYN_LO + 1 rows.
	if (count > (uint16_t)(REG_ID_DYN_HI - REG_ID_DYN_LO + 1)) { fclose(f); return false; }

	uint8_t buf[(REG_ID_DYN_HI - REG_ID_DYN_LO + 1) * REGISTRY_WIRE_RECORD_BYTES];
	if (count > 0 &&
	    fread(buf, 1, (size_t)count * REGISTRY_WIRE_RECORD_BYTES, f) !=
	        (size_t)count * REGISTRY_WIRE_RECORD_BYTES) {
		fclose(f);
		return false;
	}
	fclose(f);

	return registryRemoteApply(REG_ID_DYN_LO, buf, count) == count;
}
