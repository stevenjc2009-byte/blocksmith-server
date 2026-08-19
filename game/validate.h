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

/* True if (x, y, z, block) is an edit bsgame may apply: y and block are
 * checked against the real values in source/world/block.h and
 * source/world/world.h (see the static asserts in validate.c) so this
 * tracks the client's own world model instead of a second copy of it. */
bool bsEditValid(int32_t x, int32_t y, int32_t z, uint8_t block);

#endif /* BS_GAME_VALIDATE_H */
