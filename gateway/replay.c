#include "replay.h"

#include <string.h>

static void set_bit(struct bs_replay *r, uint64_t distance)
{
    uint64_t idx = distance % BS_REPLAY_WINDOW;
    r->bits[idx / 64u] |= (uint64_t)1 << (idx % 64u);
}

static bool get_bit(const struct bs_replay *r, uint64_t distance)
{
    uint64_t idx = distance % BS_REPLAY_WINDOW;
    return (r->bits[idx / 64u] >> (idx % 64u)) & 1u;
}

void bs_replay_init(struct bs_replay *r)
{
    memset(r, 0, sizeof *r);
}

bool bs_replay_check(struct bs_replay *r, uint64_t msg_id)
{
    if (!r->any) {
        r->any     = true;
        r->highest = msg_id;
        memset(r->bits, 0, sizeof r->bits);
        set_bit(r, msg_id);
        return true;
    }

    if (msg_id > r->highest) {
        uint64_t advance = msg_id - r->highest;

        if (advance >= BS_REPLAY_WINDOW) {
            /* Jumped clear past the window; nothing behind the new leading
             * edge can be judged, so start clean. */
            memset(r->bits, 0, sizeof r->bits);
        } else {
            /* Clear the slots the window is sliding over, so ids that are now
             * out of range do not read as already-seen when they wrap. */
            for (uint64_t d = 1; d <= advance; d++) {
                uint64_t idx = (r->highest + d) % BS_REPLAY_WINDOW;
                r->bits[idx / 64u] &= ~((uint64_t)1 << (idx % 64u));
            }
        }

        r->highest = msg_id;
        set_bit(r, msg_id);
        return true;
    }

    /* At or behind the leading edge. */
    if (r->highest - msg_id >= BS_REPLAY_WINDOW) {
        return false;   /* too old to prove it is not a replay */
    }
    if (get_bit(r, msg_id)) {
        return false;   /* already accepted */
    }

    set_bit(r, msg_id);
    return true;
}
