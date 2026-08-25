/* validate.h — the boundary between "bytes bsgate handed us" and the
 * authoritative game state.
 *
 * Every value that reaches here is treated as hostile, even though bsgate
 * has already authenticated the session: an authenticated player can still
 * run a modified or buggy client, and this process has no other line of
 * defence once a byte is inside it.
 */

#ifndef BS_GAME_VALIDATE_H
#define BS_GAME_VALIDATE_H

#include <stdbool.h>
#include <stdint.h>

/* Generous relative to any realistic build distance for 2-8 players on a
 * seed-generated world (see BS_WORLD_SEED in source/main.c) — legitimate
 * play near spawn is never constrained. What it catches is a client that
 * sends a coordinate near the edge of int32 range, buggy or hostile, which
 * would otherwise be accepted as a real diff and sit in the table forever. */
#define BS_WORLD_XZ_LIMIT 60000

/* The two numbers bsgame validates edits against. They are the client's, from
 * source/world/block.h and source/world/world.h — but this repo also ships
 * standalone (the public server-only repo, the installer's staging tar, and
 * the clone `update` makes), where that tree does not exist and an
 * unconditional include is a fatal build error rather than a safety feature.
 *
 * So the values live here, and validate.c static-asserts them against the real
 * headers whenever the client tree IS present. Drift is still caught at compile
 * time by anyone building inside the Blocksmith checkout — which is everyone
 * who could cause drift, since changing BLOCK_COUNT means editing that tree.
 * A standalone server build cannot detect drift, but it also cannot cause it.
 *
 * That argument was sound and the guard still did not work, because this
 * Makefile's WORLD path pointed one directory too shallow and the probe took
 * the standalone branch even inside the checkout. So BLOCK_PLANKS was appended
 * as client id 7 and this stayed at 7, and bsEditValid() below silently refused
 * every planks placement in a server session — the exact drift the asserts were
 * written to make impossible. The path is fixed; this is the number it was
 * supposed to have been holding this to all along. */
#define BS_WORLD_HEIGHT 128
#define BS_BLOCK_COUNT  8   /* AIR GRASS DIRT STONE SAND WOOD LEAVES PLANKS */

/* As of v1.6.0 BS_BLOCK_COUNT is no longer what bsEditValid() checks a block id
 * against — the master block registry made ids up to REG_ID_DYN_HI (0x80..0xFD)
 * legal on the wire, so validate.c reads that ceiling straight out of the
 * vendored world/registry.h instead. BS_BLOCK_COUNT stays, and stays asserted
 * against the client's BLOCK_COUNT, because it is still the bound for the ids
 * that are NOT block placements: the ITEM ids in INV_OP_PICKUP/INV_OP_CONSUME
 * (bsgame.c) and in the armour slots (playerstate.c). Two different ceilings
 * because they guard two different things; do not collapse them.
 *
 * v1.8.2 correction. This note used to say those item ids index client-side
 * tables sized BLOCK_COUNT and would read OUT OF BOUNDS on the 3DS if a dyn id
 * were let through. That is not true and was never true: grep finds no array
 * anywhere in the client sized [BLOCK_COUNT], and none in this repo sized
 * [BS_BLOCK_COUNT]. A slot icon resolves through atlasTile(blockFaceTex(id)),
 * which reads the full 256-id registry and clamps an unknown tile onto
 * ATLAS_TILE_MISSING in world/atlas_uv.h, so a dyn id in a slot draws the
 * missing-texture marker rather than reading past anything. Crafting is
 * [RECIPE_COUNT], indexed by recipe, not by item id.
 *
 * The real reason this ceiling must hold is a WIRE AGREEMENT: both ends have to
 * agree on which ids are legal in an inventory op, and the client refuses to
 * hold anything at or above BLOCK_COUNT (world/inventory.h). A mismatch loses
 * the player's item, it does not corrupt their console. Recorded because the
 * memory-safety wording made this look like a hard safety bound, and the next
 * person weighing the item-ceiling lift would have priced it far too high. */

/* True if (x, y, z, block) is an edit bsgame may apply. */
bool bsEditValid(int32_t x, int32_t y, int32_t z, uint8_t block);

#endif /* BS_GAME_VALIDATE_H */
