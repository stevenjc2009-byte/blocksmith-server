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

/* The inventory/crafting shape proto/bs_proto.h's wire format duplicates
 * (BS_INV_SLOT_COUNT etc.) — the moment a slot or recipe index travels on the
 * wire, how many of them exist stops being a private choice either end can
 * change alone (see bs_proto.h's own comment above those defines).
 *
 * Unconditional, for the same reason world/registry.h above is: world/inventory.h
 * and world/crafting.h are VENDORED into game/world/ (game/Makefile's
 * VENDORED_WORLD_FILES) and always present, so these includes cannot fail in any
 * configuration. A quoted #include is searched in the INCLUDING FILE'S OWN
 * DIRECTORY first, and this file sits in game/, so "world/inventory.h" reaches
 * game/world/inventory.h whether or not -I$(WORLD) is on the command line —
 * measured with `gcc -E -H`, which prints `. world/inventory.h` with -I$(WORLD)
 * present and the same line with it removed.
 *
 * These four asserts used to sit inside the #if below, kept there only for "the
 * same shape" as the two that genuinely need a client tree. That cost them the
 * one build that matters. The DEPLOYED server is a standalone clone with no
 * client tree beside it, so it compiles with BS_HAVE_CLIENT_WORLD_HEADERS=0 and
 * all four preprocessed away in exactly the binary they exist to protect.
 * Measured, not reasoned: sabotaging INV_STACK_MAX 99 -> 98 in
 * game/world/inventory.h errored with `static assertion failed: "stack cap must
 * track world/inventory.h"` in the client-tree arm and built CLEAN, exit 0, in
 * the standalone arm. Out here they hold in both.
 *
 * What this compares is the proto duplicate against the VENDORED copy — one hop
 * removed from the client's original. game/Makefile's check-world-drift closes
 * that second hop with `cmp -s` whenever a client tree is actually beside this
 * repo; the two checks compose into an end-to-end guarantee. */
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

/* Pure, <3ds.h>-free headers (see source/world/block.h's own header comment).
 * Reading them here keeps BS_WORLD_HEIGHT and BS_BLOCK_COUNT honest instead of
 * letting them drift from the client's real world model. Nothing here links
 * against source/world's .c files: these are constants and an enum, not code.
 *
 * Only ONE of the two is actually reached through -I$(WORLD), despite what this
 * comment used to imply. Measured with `gcc -E -H` on a probe compiled in game/
 * with the real CFLAGS: "world/world.h" prints `. ../../../source/world/world.h`
 * (there is no game/world/world.h to find), but "world/block.h" prints
 * `. world/block.h` — the vendored game/world/block.h — and prints the same with
 * -I. dropped, because a quoted include searches the including file's OWN
 * directory before any -I path. block.h is in VENDORED_WORLD_FILES, so it is
 * always there. BLOCK_COUNT is therefore the same one-hop-removed comparison the
 * inventory/crafting asserts above are, closed end-to-end by check-world-drift's
 * `cmp -s`; only WORLD_HEIGHT is compared against the client tree directly.
 *
 * A consequence worth stating rather than leaving to be rediscovered: because
 * block.h is vendored, the BLOCK_COUNT assert below does not need this #if
 * either, and it too compiles out of the shipped standalone daemon. It is left
 * gated here only because it shares an include block with world.h, which does
 * need the guard. Moving it out is a separate, deliberate change.
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
