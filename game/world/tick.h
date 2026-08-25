// The 20 TPS simulation clock (v1.8.0 task 21).
//
// Everything the spec calls a "mechanic" is defined in ticks, not in frames: fluid spread,
// redstone propagation, crop growth, furnace smelting, hunger drain and mob AI all quote rates
// per tick. Before this file existed there was no tick anywhere in the project — the client ran
// every piece of simulation off the render frame (metricsFrameMs, so 59.83 Hz when the GPU kept
// up and whatever the GPU managed when it did not), and the server ran its tick() once per
// poll() return, which meant network traffic made it tick FASTER. Neither is a clock. A fluid
// that spreads once per frame spreads at a rate that depends on where the player is looking,
// and a server whose tick rate rises with player count is a server whose mechanics change speed
// under load.
//
// So: one fixed-step clock, driven by real elapsed time, shared verbatim by both programs.
// The client feeds it the frame delta, the server feeds it the time its poll() actually slept
// for and also asks it how long to sleep next. Neither owns the rate.
//
// No <3ds.h> and nothing platform-specific — this file is compiled into the console client, the
// Linux dedicated server and the host test suite from the same source, and the server's copy in
// deps/blocksmith-server/game/world/ is byte-compared against this one by that repo's drift
// guard. It must therefore also stay clean under the server's much stricter warning set
// (-Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual
// -Wundef -Werror), which is why the integer types below are explicit to the point of fussiness.
#pragma once

#include <stdbool.h>
#include <stdint.h>

// 20 TPS, straight from the spec: "Operates at 20 TPS (10 Redstone Ticks/sec)". A redstone tick
// being two game ticks is why this number cannot be rounded to something more convenient later.
#define TICK_HZ          20
#define TICK_PERIOD_US   (1000000 / TICK_HZ)   // 50000
#define TICK_PERIOD_MS   (1000 / TICK_HZ)      // 50

_Static_assert(TICK_PERIOD_US * TICK_HZ == 1000000, "the tick period does not divide a second");
_Static_assert(TICK_PERIOD_MS * TICK_HZ == 1000,    "the tick period is not a whole millisecond");

// Distance-based decimation, also straight from the spec: "Mobs within 24 blocks of the player
// tick at the full 20 Hz (20 TPS) rate. Mobs beyond 24 blocks drop their pathfinding update
// frequency to 2 Hz (once every 10 ticks), cutting ARM11 CPU load by up to 45%."
//
// v1.9.0 task 29 is the customer. The rule lives here rather than there because it is a property
// of the clock — "2 Hz" only means anything relative to a fixed tick — and because the server
// will want the identical rule for its own entity update, from this same shared file.
#define TICK_NEAR_BLOCKS   24
#define TICK_NEAR_DIST_SQ  (TICK_NEAR_BLOCKS * TICK_NEAR_BLOCKS)   // 576, compared squared so
                                                                   // nothing needs a sqrt
#define TICK_FAR_PERIOD    (TICK_HZ / 2)                           // every 10th tick = 2 Hz

_Static_assert(TICK_HZ / TICK_FAR_PERIOD == 2, "the far decimation period is not 2 Hz");

// How many ticks one advance may ever run. A fixed-step loop fed real time has exactly one
// classic failure — the death spiral, where a frame that took too long asks for a burst of
// catch-up ticks, which takes even longer, which asks for a bigger burst. This console does
// stall for whole tenths of a second at chunk load and at save, so the clamp is not theoretical.
// Past the clamp, simulation time is simply allowed to fall behind wall-clock time; the ticks
// are counted in `dropped` and never invented later.
#define TICK_MAX_CATCHUP_DEFAULT 4

typedef struct {
	int64_t  accum_us;     // real time banked but not yet spent, always < TICK_PERIOD_US after
	                       // an advance
	uint64_t count;        // ticks actually RUN since init — the number every periodic mechanic
	                       // phases itself against, and deliberately not a wall-clock reading
	uint64_t dropped;      // ticks the catch-up clamp refused. Nonzero means the machine could
	                       // not keep up; it is a diagnostic, never a correction to apply later
	int      max_catchup;
} TickClock;

void tickClockInit(TickClock* c, int max_catchup);

// Banks `elapsed_us` of real time and returns how many ticks to run right now (0..max_catchup).
// Negative elapsed time is treated as zero: a clock that appears to run backwards must never
// rewind the simulation.
int tickClockAdvance(TickClock* c, int64_t elapsed_us);

// Microseconds until the next tick is due. The dedicated server passes this to poll() so it
// sleeps exactly as long as it should instead of waking on a fixed 100 ms timer and ticking on
// whatever else happened to arrive.
int64_t tickClockUntilNextUs(const TickClock* c);

uint64_t tickClockCount(const TickClock* c);
uint64_t tickClockDropped(const TickClock* c);

// The spec's rule, given a SQUARED distance in blocks. Returns the tick period: 1 for anything
// inside the near radius, TICK_FAR_PERIOD beyond it.
//
// A NEGATIVE dist_sq returns TICK_FAR_PERIOD, never 1. A squared distance cannot legitimately be
// negative, so the only way to produce one is a caller overflowing dx*dx + dz*dz in int32 — and
// the safe reading of "so far away the arithmetic wrapped" is the cheap period, not the full
// rate. See tick.c for why the guard is there rather than left to the caller.
int tickPeriodForDistSq(int32_t dist_sq);

// True when something with tick period `period` should run on tick `tick`. `id` staggers the
// work: without it every decimated entity in the world would fire on the same tick and the 2 Hz
// saving would be a 2 Hz spike instead of a smooth load. A period of 1 or less is always due.
bool tickDue(uint64_t tick, int period, uint32_t id);
