#include "validate.h"

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
#endif

bool bsEditValid(int32_t x, int32_t y, int32_t z, uint8_t block)
{
    if (x < -BS_WORLD_XZ_LIMIT || x > BS_WORLD_XZ_LIMIT) return false;
    if (z < -BS_WORLD_XZ_LIMIT || z > BS_WORLD_XZ_LIMIT) return false;
    if (y < 0 || y >= BS_WORLD_HEIGHT)                    return false;
    if (block >= BS_BLOCK_COUNT)                          return false;
    return true;
}
