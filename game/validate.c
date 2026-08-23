#include "validate.h"

/* For BS_INV_SLOT_COUNT/BS_INV_HOTBAR_SLOTS/BS_INV_STACK_MAX/BS_RECIPE_COUNT,
 * the wire-format duplicates the asserts below check world/inventory.h and
 * world/crafting.h against. */
#include "../proto/bs_proto.h"

/* v1.6.0: REG_ID_DYN_HI, the top of the block id space bsEditValid() accepts.
 *
 * Unconditional, unlike world/block.h and world/world.h below: world/registry.h
 * is VENDORED into game/world/ (game/Makefile's VENDORED_WORLD_FILES) and
 * world/registry.c is compiled into every build of this daemon, standalone
 * clone included — so there is no configuration in which this include can fail,
 * and no reason to restate 0xFD here as a second copy that could drift. The id
 * ceiling is read from the same header the registry itself partitions its id
 * space with, which is why there is no BS_* mirror of it beside BS_BLOCK_COUNT
 * and no _Static_assert needed to keep the two honest: there is only one. */
#include "world/registry.h"

/* Pure, <3ds.h>-free headers (see source/world/block.h's own header comment).
 * Reading them here keeps BS_WORLD_HEIGHT and BS_BLOCK_COUNT honest instead of
 * letting them drift from the client's real world model. Nothing here links
 * against source/world's .c files: these are constants and an enum, not code.
 *
 * Conditional because this repo also builds with no client tree beside it —
 * see the comment on the constants in validate.h. The Makefile probes for the
 * headers and always defines BS_HAVE_CLIENT_WORLD_HEADERS to 0 or 1, so -Wundef
 * stays meaningful: a typo in the macro name is a warning, not a silent skip. */
#if BS_HAVE_CLIENT_WORLD_HEADERS
#include "world/block.h"
#include "world/world.h"

/* Caught at compile time rather than at the first weird bug report if either
 * header's shape ever changes underneath this file. */
_Static_assert(BLOCK_COUNT == BS_BLOCK_COUNT,
               "block id validation must track world/block.h");
_Static_assert(WORLD_HEIGHT == BS_WORLD_HEIGHT,
               "y-range validation must track world/world.h");

/* Same treatment for the inventory/crafting shape proto/bs_proto.h's wire
 * format duplicates (BS_INV_SLOT_COUNT etc.) — the moment a slot or recipe
 * index travels on the wire, how many of them exist stops being a private
 * choice either end can change alone (see bs_proto.h's own comment above
 * those defines).
 *
 * Unlike world/block.h and world/world.h above, world/inventory.h and
 * world/crafting.h are NOT reached via -I$(WORLD): they are vendored into
 * game/world/ (see game/Makefile's drift-guard comment) and always present
 * in this repo, so this #include resolves to that vendored copy regardless
 * of BS_HAVE_CLIENT_WORLD_HEADERS. The #if guard is kept anyway, for the
 * same reason and the same shape as the BLOCK_COUNT/WORLD_HEIGHT asserts
 * above: BS_HAVE_CLIENT_WORLD_HEADERS is still the signal that a live client
 * copy exists to have drifted from, even though the comparison this file can
 * make is one hop removed from it (proto duplicate vs. the vendored copy,
 * not vs. the client's original directly). That second hop — vendored copy
 * vs. client original — is exactly what game/Makefile's check-world-drift
 * target verifies with `cmp -s` whenever this branch is taken; the two
 * checks compose into the same end-to-end guarantee BLOCK_COUNT gets
 * directly. */
#include "world/inventory.h"
#include "world/crafting.h"

_Static_assert(INV_SLOT_COUNT == BS_INV_SLOT_COUNT,
               "inventory slot count must track world/inventory.h");
_Static_assert(INV_HOTBAR_SLOTS == BS_INV_HOTBAR_SLOTS,
               "hotbar slot count must track world/inventory.h");
_Static_assert(INV_STACK_MAX == BS_INV_STACK_MAX,
               "stack cap must track world/inventory.h");
_Static_assert(RECIPE_COUNT == BS_RECIPE_COUNT,
               "recipe count must track world/crafting.h");
#endif

bool bsEditValid(int32_t x, int32_t y, int32_t z, uint8_t block)
{
    if (x < -BS_WORLD_XZ_LIMIT || x > BS_WORLD_XZ_LIMIT) return false;
    if (z < -BS_WORLD_XZ_LIMIT || z > BS_WORLD_XZ_LIMIT) return false;
    if (y < 0 || y >= BS_WORLD_HEIGHT)                    return false;
    /* v1.6.0: the whole defined id space is legal, not just the core rows —
     * the master block registry lets a server define dynamic blocks in
     * REG_ID_DYN_LO..REG_ID_DYN_HI (0x80..0xFD) and a client may legitimately
     * place one, so a ceiling of BS_BLOCK_COUNT (8) refused every one of them.
     * Only the two ids above the dyn range (0xFE/0xFF, reserved so a u8 row
     * count can never overflow) are refused. This mirrors editValid() in the
     * client's source/net/networld.c, which tests the same REG_ID_DYN_HI.
     *
     * Deliberately NOT a registryIsDefined() check: bsgame accepts an edit
     * naming an id the table does not hold yet for the same reason the client
     * does — a dyn id is meaningful the moment either end registers it, and
     * gating the edit on this process's current table would drop legitimate
     * placements during the window before a registry sync lands. Undefined ids
     * read back as air (registryGet()'s never-NULL contract), so the worst case
     * is a hole, not a crash or a corrupt diff. */
    if (block > REG_ID_DYN_HI)                            return false;
    return true;
}
