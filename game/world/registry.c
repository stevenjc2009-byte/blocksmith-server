// The master block registry — implementation. See registry.h for the contract.
#include "world/registry.h"

#include <stdio.h>
#include <string.h>

// The compiled-in core rows, ids 0x00..0x0E. These are the old kBlocks[] table
// recast as BlockDefs; the ids and textures are frozen forever because every
// saved region file and every replay encodes them by number.
//
// 0x00..0x07 are also the ITEM ids (world/block.h's BLOCK_COUNT and the server's
// BS_BLOCK_COUNT). 0x08 and 0x09 — water and tall grass, roadmap tasks 17 and 19 —
// and 0x0A..0x0E — snow, ice, cactus, dead bush and fern, v1.8.3 Phase 3 — are core
// rows that are deliberately NOT items; world/block.h explains why that distinction
// exists and why BLOCK_COUNT stayed at 8 rather than following them.
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
	// and world/block.h:258 defines blockDropsNothing() as `shape == BLOCK_SHAPE_CROSS`.
	// Tall grass IS a CROSS, so the first term is false, the guard never fires, and the
	// block is removed normally; only the pickup is skipped, because it is past
	// BLOCK_COUNT and inventoryCanHold() answers false. Measured by a probe linked
	// against this file and world/block.c, not reasoned off the guard's shape.
	//
	// The distinction matters for the five rows below: the two CROSS ones behave exactly
	// like this, while snow, ice and cactus are FULL_CUBE and so are genuinely refused.
	// Either way it is the right end state until the survival rung gives them a drop;
	// see world/block.h.
	[9] = { // tall grass
		.name  = "tall_grass",
		.tex   = { BTEX_TALL_GRASS, BTEX_TALL_GRASS, BTEX_TALL_GRASS,
		           BTEX_TALL_GRASS, BTEX_TALL_GRASS, BTEX_TALL_GRASS },
		.flags = REG_FLAG_TRANSPARENT | REG_FLAG_SHAPE(BLOCK_SHAPE_CROSS),
		.hardness = 1,
	},
	// ── v1.8.3 Phase 3: ids 10..14 ────────────────────────────────────────────────────
	//
	// Five more core rows that are deliberately NOT items, for exactly the reason 8 and 9
	// are not: they are past BLOCK_COUNT, so world/inventory.h's inventoryCanHold() answers
	// false for all five. BLOCK_COUNT does NOT move for them and must not — world/block.h's
	// long note explains why sliding it drags BLOCK_WATER and BLOCK_TALL_GRASS off their
	// rows, and world/block.h:62 and scene/interact.c already prescribe the other route
	// (widen the PREDICATE, never the constant) for the day these become collectable.
	//
	// What that costs the player, stated rather than discovered:
	//
	//   snow, ice, cactus   FULL_CUBE and past the ceiling, so scene/interact.c's guard —
	//                       `!blockDropsNothing(here) && !inventoryCanHold(here)` — refuses
	//                       the break outright. They are scenery: you can walk on them, aim
	//                       at them and build against them, and you cannot mine them. That
	//                       is the same end state world/block.h argues for water, and it is
	//                       what makes this a content change rather than a protocol one.
	//   dead_bush, fern     CROSS, so blockDropsNothing() is true and the break is allowed;
	//                       it deletes the plant and yields nothing, identically to tall
	//                       grass today.
	//
	// ── .hardness ──
	//
	// Only the two CROSS rows can ever be asked (the three cubes are refused before a break
	// timer starts), but every row carries a real number anyway, for the reason the water
	// row's explicit 0 is written down: a value that is never read should say it is a
	// decision. Tuned on the toolless scale at the top of this file — sand 10, leaves 4:
	//
	//   snow    8 ticks = 0.40 s     softer than sand; it is settled snow, not packed ice
	//   ice    10 ticks = 0.50 s     sand's number; a solid pane, not a rock
	//   cactus  8 ticks = 0.40 s     plant matter, not timber
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
	//                  is what lets a player build against a frozen lake. It is still
	//                  unbreakable, but by the item ceiling and not by being invisible to
	//                  the raycast — a distinction that matters the day the ceiling widens.
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
	[12] = { // cactus
		.name  = "cactus",
		.tex   = { BTEX_CACTUS, BTEX_CACTUS, BTEX_CACTUS,
		           BTEX_CACTUS, BTEX_CACTUS, BTEX_CACTUS },
		.flags = REG_FLAG_SOLID,
		.hardness = 8,
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
