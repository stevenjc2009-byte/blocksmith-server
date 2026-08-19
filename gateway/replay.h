/* replay.h — sliding-window anti-replay, one window per session.
 *
 * libhydrogen binds the 64-bit message id into the AEAD tag, so an attacker
 * cannot renumber a captured packet. What it does not do is remember which
 * ids have already been used — without this window, a captured "place block"
 * packet can be re-sent forever and the server will accept every copy.
 *
 * Standard IPsec-style window: `highest` is the largest id accepted so far,
 * `bits` records which of the preceding BS_REPLAY_WINDOW ids were seen. UDP
 * reorders, so an id behind the leading edge is accepted once and only once.
 */

#ifndef BS_REPLAY_H
#define BS_REPLAY_H

#include <stdbool.h>
#include <stdint.h>

#include "../proto/bs_proto.h"

#define BS_REPLAY_WORDS  (BS_REPLAY_WINDOW / 64u)

struct bs_replay {
    uint64_t highest;
    uint64_t bits[BS_REPLAY_WORDS];
    bool     any;      /* false until the first packet is accepted */
};

void bs_replay_init(struct bs_replay *r);

/* Returns true if `msg_id` is fresh, and records it. Returns false if it is a
 * duplicate or has fallen off the back of the window. Must be called only
 * *after* the AEAD tag verifies — otherwise forged ids poison the window and
 * lock the real peer out. */
bool bs_replay_check(struct bs_replay *r, uint64_t msg_id);

#endif /* BS_REPLAY_H */
