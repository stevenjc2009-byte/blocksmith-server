#include "validate.h"

/* For BS_INV_SLOT_COUNT/BS_INV_HOTBAR_SLOTS/BS_INV_STACK_MAX/BS_RECIPE_COUNT,
 * the wire-format duplicates the asserts below check world/inventory.h and
 * world/crafting.h against. */
#include "../proto/bs_proto.h"

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
    if (block >= BS_BLOCK_COUNT)                          return false;
    return true;
}
