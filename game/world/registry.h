// The master block registry (v1.6.0 Phase A).
//
// One authoritative table of block definitions, replacing the compile-time-only
// kBlocks[] view. Core blocks (grass..planks) are compiled in and keep their ids
// forever; everything a server adds at join time lands in the dynamic id space as
// flat ids grouped by `variant_of` — deliberately not a metadata nibble, because a
// nibble would fork every consumer of BlockId into "id" and "id+meta" pairs, and
// region files, wire packets and inventory slots all store plain ids today.
//
// Registration happens only at boot or at join, then the table is frozen before
// any worker thread starts: post-freeze the tables are read-only by convention,
// so the mesher needs no locks.
//
// Nothing here includes <3ds.h>: the registry is linked into the host test suite,
// the client and the dedicated server alike.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "world/block.h"

// The id space is partitioned so that old saves and old packets stay meaningful:
enum {
	REG_ID_AIR    = 0x00,  // must stay 0: word-at-a-time air scans depend on it
	REG_ID_CORE_LO = 0x01, // compiled-in core rows, GRASS=1 .. PLANKS=7 forever
	REG_ID_CORE_HI = 0x7F,
	REG_ID_DYN_LO  = 0x80, // dynamic rows: registered at boot/join, lowest free first
	REG_ID_DYN_HI  = 0xFD, // 0xFE/0xFF reserved so a u8 count can never overflow
};

#define REGISTRY_MAX       256
#define REGISTRY_NAME_MAX  16

// Flag bits for BlockDef.flags.
enum {
	REG_FLAG_SOLID      = 1u << 0,  // fills its cell: collision, raycast, occlusion
	REG_FLAG_TRANSPARENT = 1u << 1, // drawn, but does not hide what is behind it
	REG_FLAG_LIQUID     = 1u << 2,
	REG_FLAG_LUMINOUS   = 1u << 3,
	REG_FLAG_FLAMMABLE  = 1u << 4,
};

// Fluid classes (Phase B grows this; NONE is the only value core rows use).
enum {
	REG_FLUID_NONE  = 0,
	REG_FLUID_MAGMA = 1,
};

// The full definition of one block, without its id (the table index IS the id).
// Packed so the wire/persist record around it has a fixed, documented layout.
typedef struct __attribute__((packed)) {
	char    name[REGISTRY_NAME_MAX];   // NUL-terminated, unique, case-sensitive
	uint8_t tex[BLOCK_FACES];          // atlas tile per face, FACE_* order
	uint8_t flags;                     // REG_FLAG_*
	uint8_t luminance;                 // 0..15
	uint8_t hardness;
	uint8_t variant_of;                // base id for variants; own id for bases
	uint8_t fluid_class;               // REG_FLUID_*
} BlockDef;

_Static_assert(sizeof(BlockDef) == 27, "BlockDef must stay 27 bytes");

// One block on the wire / in registry.bin: the def plus its leading id byte.
#define REGISTRY_WIRE_RECORD_BYTES 28

_Static_assert(REGISTRY_WIRE_RECORD_BYTES == sizeof(BlockDef) + 1,
               "wire record = id byte + def");

// Registry layout revision. Bumped only when the meaning of existing fields
// changes; the crc16 below is what actually detects content drift.
#define REGISTRY_REV 1u

// Reset the table to the compiled-in core rows. Idempotent; also called lazily
// by the accessors, so no call site can observe an uninitialised registry.
void registryInitCore(void);

// Register a dynamic block in the lowest free dyn id. Returns that id, or 0 if
// the name already exists or the dyn range is full (or the table is frozen).
BlockId registryRegister(const BlockDef* def);

// Freeze the table: registration and remote application are refused afterwards.
void registryFreeze(void);
bool registryFrozen(void);

// Never NULL: an unknown id answers the air def, preserving blockInfo()'s
// long-standing contract that a bad id leaves a hole instead of crashing.
const BlockDef* registryGet(BlockId id);

// Stable derived view (BlockInfo) for blockInfo(); same never-NULL contract.
const BlockInfo* registryView(BlockId id);

// Name lookup over all defined rows. Returns 0 when absent.
BlockId registryFind(const char* name);

// Number of defined rows, including air (8 after InitCore on a fresh table).
uint8_t registryCount(void);

bool registryIsDefined(BlockId id);

// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, no final xor)
// over the canonical table stream: for every defined id in ascending order, the
// 28-byte wire record produced by registryDefPack(). All record fields are
// single bytes, so there is no endianness inside the stream; multi-byte scalars
// elsewhere in the protocol (the INFO header crc/count, the sidecar count) are
// little-endian.
uint16_t registryCrc16(void);

// Wire record codecs. Pack emits exactly REGISTRY_WIRE_RECORD_BYTES:
// {id u8, name[16], tex[6], flags, luminance, hardness, variant_of, fluid_class}.
void registryDefPack(uint8_t out[REGISTRY_WIRE_RECORD_BYTES], BlockId id,
                     const BlockDef* def);

// Validate-and-build from a wire record. Returns false when the id is outside
// the dyn range or the name field has no NUL terminator.
bool registryDefUnpack(BlockId* out_id, BlockDef* out_def,
                       const uint8_t in[REGISTRY_WIRE_RECORD_BYTES]);

// Apply a DEFS batch of n consecutive records starting at `first`. All records
// are validated before anything is committed; on any refusal nothing changes
// and 0 is returned. Refused when frozen or when a record's implied id does not
// match the next free slot (a tampered or reordered batch). Returns n on success.
size_t registryRemoteApply(uint8_t first, const uint8_t* records, size_t n);

// Canonical persistence: {u16 count LE}{count x 28B records, id-ascending},
// dynamic rows only — core rows are implied by the binary. Used both for the
// server's state_dir/registry.bin and the single-player world sidecar.
bool registrySidecarSave(const char* path);
bool registrySidecarLoad(const char* path);
