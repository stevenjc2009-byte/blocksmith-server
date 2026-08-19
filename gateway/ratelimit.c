#include "ratelimit.h"

#include <string.h>

/* Tokens are held scaled so a refill shorter than one whole token still makes
 * progress; without this a steady 1-per-400ms probe would never accumulate
 * anything against a 500 ms refill and would be limited far harder than
 * intended. */
#define BS_RL_SCALE  64u

static uint16_t refill(uint16_t tokens, uint64_t elapsed_ms,
                       uint32_t refill_ms, uint32_t burst)
{
    if (refill_ms == 0) return (uint16_t)(burst * BS_RL_SCALE);

    uint64_t gained = (elapsed_ms * BS_RL_SCALE) / refill_ms;
    uint64_t total  = (uint64_t)tokens + gained;
    uint64_t cap    = (uint64_t)burst * BS_RL_SCALE;

    return (uint16_t)(total > cap ? cap : total);
}

static uint32_t slot_index(uint32_t addr)
{
    /* Knuth multiplicative hash. The table is a cache, not a security
     * boundary — a collision costs an attacker's victim a slot, and the
     * global bucket is what actually bounds total damage. */
    return (addr * 2654435761u) % BS_RL_SLOTS;
}

void bs_rl_init(struct bs_ratelimit *rl, uint64_t now_ms)
{
    memset(rl, 0, sizeof *rl);
    rl->global_tokens  = (uint16_t)(BS_RL_GLOBAL_BURST * BS_RL_SCALE);
    rl->global_last_ms = now_ms;
}

bool bs_rl_allow(struct bs_ratelimit *rl, uint32_t addr, uint64_t now_ms)
{
    /* Global bucket first, and check both before spending either — a partial
     * spend would let a blocked attempt still drain the shared budget. */
    uint64_t g_elapsed = (now_ms > rl->global_last_ms)
                       ? now_ms - rl->global_last_ms : 0;
    uint16_t g_tokens = refill(rl->global_tokens, g_elapsed,
                               BS_RL_GLOBAL_REFILL_MS, BS_RL_GLOBAL_BURST);

    uint32_t i = slot_index(addr);
    struct bs_rl_slot *s = &rl->slot[i];

    uint16_t s_tokens;
    if (s->addr == addr) {
        uint64_t elapsed = (now_ms > s->last_ms) ? now_ms - s->last_ms : 0;
        s_tokens = refill(s->tokens, elapsed, BS_RL_REFILL_MS, BS_RL_BURST);
    } else {
        /* Unseen address, or an eviction. Both start full: a legitimate new
         * player must not be punished for landing on a busy hash slot. */
        s_tokens = (uint16_t)(BS_RL_BURST * BS_RL_SCALE);
    }

    if (g_tokens < BS_RL_SCALE || s_tokens < BS_RL_SCALE) {
        /* Still write the refilled values back so the clock keeps advancing
         * while an attacker is being denied. */
        rl->global_tokens  = g_tokens;
        rl->global_last_ms = now_ms;
        s->addr    = addr;
        s->tokens  = s_tokens;
        s->last_ms = now_ms;
        return false;
    }

    rl->global_tokens  = (uint16_t)(g_tokens - BS_RL_SCALE);
    rl->global_last_ms = now_ms;
    s->addr    = addr;
    s->tokens  = (uint16_t)(s_tokens - BS_RL_SCALE);
    s->last_ms = now_ms;
    return true;
}
