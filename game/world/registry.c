// The master block registry — implementation. See registry.h for the contract.
#include "world/registry.h"

#include <stdio.h>
#include <string.h>

// The compiled-in core rows, ids 0x00..0x07. These are the old kBlocks[] table
// recast as BlockDefs; the ids and textures are frozen forever because every
// saved region file and every replay encodes them by number.
static const BlockDef kCoreDefs[REG_ID_DYN_LO] = {
	[REG_ID_AIR] = {
		.name  = "air",
		.tex   = { 0, 0, 0, 0, 0, 0 },
		.flags = REG_FLAG_TRANSPARENT,
	},
	[1] = { // grass
		.name  = "grass",
		.tex   = { BTEX_GRASS_SIDE, BTEX_GRASS_SIDE, BTEX_GRASS_TOP,
		           BTEX_DIRT,        BTEX_GRASS_SIDE, BTEX_GRASS_SIDE },
		.flags = REG_FLAG_SOLID,
	},
	[2] = {
		.name  = "dirt",
		.tex   = { BTEX_DIRT, BTEX_DIRT, BTEX_DIRT, BTEX_DIRT, BTEX_DIRT, BTEX_DIRT },
		.flags = REG_FLAG_SOLID,
	},
	[3] = {
		.name  = "stone",
		.tex   = { BTEX_STONE, BTEX_STONE, BTEX_STONE,
		           BTEX_STONE, BTEX_STONE, BTEX_STONE },
		.flags = REG_FLAG_SOLID,
	},
	[4] = {
		.name  = "sand",
		.tex   = { BTEX_SAND, BTEX_SAND, BTEX_SAND, BTEX_SAND, BTEX_SAND, BTEX_SAND },
		.flags = REG_FLAG_SOLID,
	},
	[5] = { // wood
		.name  = "wood",
		.tex   = { BTEX_WOOD_SIDE, BTEX_WOOD_SIDE, BTEX_WOOD_TOP,
		           BTEX_WOOD_TOP,  BTEX_WOOD_SIDE, BTEX_WOOD_SIDE },
		.flags = REG_FLAG_SOLID,
	},
	[6] = { // leaves: solid (fills its cell) but transparent (alpha-0 holes)
		.name  = "leaves",
		.tex   = { BTEX_LEAVES, BTEX_LEAVES, BTEX_LEAVES,
		           BTEX_LEAVES, BTEX_LEAVES, BTEX_LEAVES },
		.flags = REG_FLAG_SOLID | REG_FLAG_TRANSPARENT,
	},
	[7] = { // planks
		.name  = "planks",
		.tex   = { BTEX_PLANKS, BTEX_PLANKS, BTEX_PLANKS,
		           BTEX_PLANKS, BTEX_PLANKS, BTEX_PLANKS },
		.flags = REG_FLAG_SOLID,
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
