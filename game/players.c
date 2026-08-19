#include "players.h"

#include <stdio.h>
#include <string.h>

void playersInit(BsPlayers *pl)
{
    memset(pl, 0, sizeof *pl);
}

BsPlayer *playerBySid(BsPlayers *pl, uint32_t sid)
{
    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        if (pl->p[i].used && pl->p[i].sid == sid) return &pl->p[i];
    }
    return NULL;
}

BsPlayer *playerAlloc(BsPlayers *pl, uint32_t sid, const char *label, uint64_t now_ms)
{
    for (unsigned i = 0; i < BS_GAME_MAX_PLAYERS; i++) {
        if (pl->p[i].used) continue;

        BsPlayer *p = &pl->p[i];
        memset(p, 0, sizeof *p);
        p->used = true;
        p->sid  = sid;
        snprintf(p->label, sizeof p->label, "%s", label);
        p->last_seen_ms = now_ms;
        p->edit_tokens  = (uint16_t)(BS_EDIT_BURST * BS_EDIT_SCALE);
        p->edit_last_ms = now_ms;
        return p;
    }
    return NULL;
}

void playerFree(BsPlayer *p)
{
    memset(p, 0, sizeof *p);
}

bool playerEditAllow(BsPlayer *p, uint64_t now_ms)
{
    uint64_t elapsed = (now_ms > p->edit_last_ms) ? now_ms - p->edit_last_ms : 0;
    uint64_t gained  = (elapsed * BS_EDIT_SCALE) / BS_EDIT_REFILL_MS;
    uint64_t cap     = (uint64_t)BS_EDIT_BURST * BS_EDIT_SCALE;
    uint64_t tokens  = (uint64_t)p->edit_tokens + gained;
    if (tokens > cap) tokens = cap;

    if (tokens < BS_EDIT_SCALE) {
        /* Still write back the refilled value so the clock keeps advancing
         * while this player is being denied — the same reasoning as
         * server/gateway/ratelimit.c's bs_rl_allow(). */
        p->edit_tokens  = (uint16_t)tokens;
        p->edit_last_ms = now_ms;
        return false;
    }

    p->edit_tokens  = (uint16_t)(tokens - BS_EDIT_SCALE);
    p->edit_last_ms = now_ms;
    return true;
}
