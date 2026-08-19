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
 * A standalone server build cannot detect drift, but it also cannot cause it. */
#define BS_WORLD_HEIGHT 128
#define BS_BLOCK_COUNT  7

/* True if (x, y, z, block) is an edit bsgame may apply. */
bool bsEditValid(int32_t x, int32_t y, int32_t z, uint8_t block);

#endif /* BS_GAME_VALIDATE_H */
