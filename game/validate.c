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

/* The registry wire record size, the one the REGISTRY_DEFS batch is built out
 * of. Same shape and same reasoning as the four above, and unconditional for
 * the same reason the REG_ID_DYN_HI include at the top of this file is:
 * world/registry.h is VENDORED into game/world/, so this holds in the standalone
 * daemon build too, not just in a client checkout.
 *
 * This is the assert that was missing, and its absence was not theoretical.
 * bsgame.c's handle_registry_fetch() sizes its stack buffer and strides its
 * packing with REGISTRY_WIRE_RECORD_BYTES, but declares the packet's length with
 * BS_APP_REGISTRY_DEFS_BYTES(), which was a bare `28u`. Measured on the real
 * headers with one extra byte added to BlockDef: 36 records packed 1048 bytes
 * behind a declared wire length of 1012 — 36 bytes short on every batch — with
 * MAX_N still 36 when only 35 fit, and 1048 overrunning BS_MAX_PAYLOAD (1024).
 * gcc exited 0 with no warning. The failure mode is mismatched framing plus a
 * payload overrun, and the only thing that turns it into a build error is this
 * line. */
_Static_assert(REGISTRY_WIRE_RECORD_BYTES == BS_REGISTRY_WIRE_RECORD_BYTES,
               "REGISTRY_WIRE_RECORD_BYTES (world/registry.h) and "
               "BS_REGISTRY_WIRE_RECORD_BYTES (proto/bs_proto.h) must be equal: "
               "the REGISTRY_DEFS batch is packed with the first and its wire "
               "length is declared with the second");

/* BS_CHUNK_DIM and the shift bs_col_of() maps a block coordinate to a column
 * with are the same constant written two ways, in the same header, with nothing
 * relating them. Both are proto-side, so this compares bs_proto.h against
 * itself rather than against a world header — it belongs here anyway, because
 * bs_proto.h carries no asserts of its own and every other endpoint that
 * includes it is a 3DS build this repo does not compile. */
_Static_assert((1u << BS_CHUNK_DIM_SHIFT) == BS_CHUNK_DIM,
               "BS_CHUNK_DIM_SHIFT must be log2(BS_CHUNK_DIM) (proto/bs_proto.h): "
               "bs_col_of() shifts by the first to divide by the second");

/* Pure, <3ds.h>-free headers (see source/world/block.h's own header comment).
 * Reading them here keeps BS_WORLD_HEIGHT and BS_BLOCK_COUNT honest instead of
 * letting them drift from the client's real world model. Nothing here links
 * against source/world's .c files: these are constants and an enum, not code.
 *
 * The two are NOT in the same situation, which is why they are no longer in the
 * same include block.
 *
 * world/block.h is VENDORED into game/world/ (game/Makefile's
 * VENDORED_WORLD_FILES), so it is present in every configuration and needs no
 * guard. Measured with `gcc -E -H` on THIS file with the real CFLAGS, 2026-08-25
 * (non-/usr lines only):
 *
 *   arm A  -I. -I.. -I$(WORLD) -DBS_HAVE_CLIENT_WORLD_HEADERS=1
 *     . world/registry.h
 *     .. ./world/block.h                      <- the VENDORED copy, depth 2
 *     . world/inventory.h
 *     . world/crafting.h
 *     . ../../../source/world/world.h         <- the CLIENT's copy, depth 1
 *   arm B  -I. -I.. -DBS_HAVE_CLIENT_WORLD_HEADERS=0
 *     . world/registry.h
 *     .. ./world/block.h                      <- still the VENDORED copy
 *
 * Two things earlier revisions of this comment asserted that the output above
 * does not support, corrected here rather than repeated:
 *
 *   - block.h is NOT reached by this file's own-directory search. It arrives at
 *     depth 2, pulled in by world/registry.h (included unconditionally above),
 *     and it is -I. that resolves it: registry.h lives in game/world/, so its
 *     own-directory search for "world/block.h" looks for
 *     game/world/world/block.h and misses. By the time this file's own #include
 *     below is reached the include guard has already closed, which is why that
 *     line prints nothing of its own. Re-run arm A with -I. dropped and block.h
 *     prints `.. ../../../source/world/block.h` — the CLIENT's copy. So -I. is
 *     load-bearing for block.h too, not only for the vendored .c files.
 *   - -I$(WORLD) is never consulted for block.h in either arm. Re-run arm A with
 *     -I$(WORLD) dropped: block.h still prints `.. ./world/block.h`, and only
 *     world/world.h goes fatal ("world/world.h: No such file or directory").
 *
 * The consequence is why this assert moved. block.h being present in every
 * configuration means BLOCK_COUNT never needed the #if — and while it sat inside
 * one, the check was preprocessed out of the SHIPPED standalone daemon, the one
 * build it exists to protect, exactly as the four inventory/crafting asserts
 * above were until 6730e44 moved them out. Out here it holds in both arms.
 *
 * What it compares is BS_BLOCK_COUNT against the VENDORED copy, one hop removed
 * from the client's original; game/Makefile's check-world-drift closes that
 * second hop with `cmp -s` whenever a client tree is actually beside this repo.
 * WORLD_HEIGHT below stays the only one compared against the client tree
 * directly. The #include is kept explicit rather than leaning on registry.h's
 * transitive one: this file names the header whose constant it asserts against,
 * so a later edit to registry.h cannot quietly take BLOCK_COUNT away. */
#include "world/block.h"

_Static_assert(BLOCK_COUNT == BS_BLOCK_COUNT,
               "block id validation must track world/block.h");

/* world/world.h is the one that genuinely needs the guard. There is no
 * game/world/world.h, so this include resolves only through -I$(WORLD) into the
 * client tree, and this repo also builds with no client tree beside it — see the
 * comment on the constants in validate.h. The Makefile probes for the headers
 * and always defines BS_HAVE_CLIENT_WORLD_HEADERS to 0 or 1, so -Wundef stays
 * meaningful: a typo in the macro name is a warning, not a silent skip.
 *
 * This assert therefore does still compile out of the standalone daemon, and
 * that is not the bug the one above was: in that build there is no client
 * world.h present to have drifted from, so "cannot detect drift" and "cannot
 * cause drift" are the same fact from two directions — the stance validate.h and
 * check-world-drift's else-branch already take. */
#if BS_HAVE_CLIENT_WORLD_HEADERS
#include "world/world.h"

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
