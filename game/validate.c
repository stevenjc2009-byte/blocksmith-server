#include "validate.h"

/* Pure, <3ds.h>-free headers (see source/world/block.h's own header
 * comment) — reading them here for BLOCK_COUNT and WORLD_HEIGHT makes this
 * the single source of truth instead of a duplicate literal that could
 * silently drift from the client's real world model. Nothing here links
 * against source/world's .c files: these are constants and an enum, not
 * code. */
#include "world/block.h"
#include "world/world.h"

/* Caught at compile time rather than at the first weird bug report if
 * either header's shape ever changes underneath this file. */
_Static_assert(BLOCK_COUNT == 7, "block id validation must track world/block.h");
_Static_assert(WORLD_HEIGHT == 128, "y-range validation must track world/world.h");

bool bsEditValid(int32_t x, int32_t y, int32_t z, uint8_t block)
{
    if (x < -BS_WORLD_XZ_LIMIT || x > BS_WORLD_XZ_LIMIT) return false;
    if (z < -BS_WORLD_XZ_LIMIT || z > BS_WORLD_XZ_LIMIT) return false;
    if (y < 0 || y >= WORLD_HEIGHT)                       return false;
    if (block >= BLOCK_COUNT)                             return false;
    return true;
}
