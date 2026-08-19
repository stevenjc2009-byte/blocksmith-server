/* ratelimit.h — per-source-address token buckets for handshake attempts.
 *
 * The cookie exchange already stops a spoofed-source flood from allocating
 * session state. This stops a *real* source from doing it: without it, one
 * host that can complete the cookie round trip can burn every session slot
 * and every CPU cycle the Noise handshake costs.
 *
 * Keyed on IP only, never on port — an attacker changes source port for free.
 *
 * Time is passed in rather than read internally so the buckets can be tested
 * deterministically on the host.
 */

#ifndef BS_RATELIMIT_H
#define BS_RATELIMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BS_RL_SLOTS        512u   /* distinct source IPs tracked at once      */
#define BS_RL_BURST         8u    /* handshakes a cold IP may attempt at once */
#define BS_RL_REFILL_MS   500u    /* one token back per this many ms          */
#define BS_RL_GLOBAL_BURST 64u    /* ceiling across all sources combined      */
#define BS_RL_GLOBAL_REFILL_MS 100u

struct bs_rl_slot {
    uint32_t addr;        /* IPv4, network order; 0 means the slot is free */
    uint16_t tokens;      /* scaled by BS_RL_SCALE                          */
    uint64_t last_ms;
};

struct bs_ratelimit {
    struct bs_rl_slot slot[BS_RL_SLOTS];
    uint16_t          global_tokens;
    uint64_t          global_last_ms;
};

void bs_rl_init(struct bs_ratelimit *rl, uint64_t now_ms);

/* Returns true if a handshake attempt from `addr` may proceed, consuming one
 * token from both that address's bucket and the global bucket. Returns false
 * — and consumes nothing — if either bucket is empty. */
bool bs_rl_allow(struct bs_ratelimit *rl, uint32_t addr, uint64_t now_ms);

#endif /* BS_RATELIMIT_H */
