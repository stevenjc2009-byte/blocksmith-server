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
        /* subs[]/sub_count/chunk_sub_seen/legacy_sync_sent are already zero
         * from the memset above; joined_ms is the one field that needs an
         * explicit value, since "zero" is a real timestamp, not "unset". */
        p->joined_ms    = now_ms;
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

bool playerSubAdd(BsPlayer *p, int32_t cx, int32_t cz)
{
    if (playerSubHas(p, cx, cz)) return true;
    if (p->sub_count >= BS_PLAYER_SUB_MAX) return false;

    p->subs[p->sub_count].cx = cx;
    p->subs[p->sub_count].cz = cz;
    p->sub_count++;
    return true;
}

void playerSubRemove(BsPlayer *p, int32_t cx, int32_t cz)
{
    for (uint16_t i = 0; i < p->sub_count; i++) {
        if (p->subs[i].cx != cx || p->subs[i].cz != cz) continue;

        /* Order doesn't matter to a set, so swap the last entry into this
         * slot instead of shifting everything after it down by one. */
        p->subs[i] = p->subs[p->sub_count - 1u];
        p->sub_count--;
        return;
    }
}

bool playerSubHas(const BsPlayer *p, int32_t cx, int32_t cz)
{
    for (uint16_t i = 0; i < p->sub_count; i++) {
        if (p->subs[i].cx == cx && p->subs[i].cz == cz) return true;
    }
    return false;
}
