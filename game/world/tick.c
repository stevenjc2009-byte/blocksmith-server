#include "world/tick.h"

void tickClockInit(TickClock* c, int max_catchup)
{
	if (!c) return;

	c->accum_us    = 0;
	c->count       = 0;
	c->dropped     = 0;
	// Zero or negative would mean "never tick", which is not a configuration anyone wants and
	// is the kind of thing a caller reaches by passing an uninitialised field. One tick per
	// advance is the smallest coherent answer.
	c->max_catchup = (max_catchup > 0) ? max_catchup : 1;
}

int tickClockAdvance(TickClock* c, int64_t elapsed_us)
{
	if (!c) return 0;

	// A backwards clock rewinds nothing. On the console the delta comes from a float frame
	// time and on the server from a monotonic reading, so neither should ever be negative —
	// but "should never" is how the accumulator would end up holding a negative balance that
	// silently stalls the simulation for however long it takes to pay off.
	if (elapsed_us > 0)
		c->accum_us += elapsed_us;

	int64_t n = c->accum_us / TICK_PERIOD_US;

	// Keep the sub-tick remainder. Discarding it would lose up to 49,999 us per advance, which
	// at 60 frames a second is a clock that runs slow by a factor of three.
	c->accum_us -= n * TICK_PERIOD_US;

	if (n > (int64_t)c->max_catchup) {
		c->dropped += (uint64_t)(n - (int64_t)c->max_catchup);
		n = (int64_t)c->max_catchup;
	}

	c->count += (uint64_t)n;
	return (int)n;
}

int64_t tickClockUntilNextUs(const TickClock* c)
{
	if (!c) return TICK_PERIOD_US;

	const int64_t left = TICK_PERIOD_US - c->accum_us;
	return (left > 0) ? left : 0;
}

uint64_t tickClockCount(const TickClock* c)   { return c ? c->count   : 0; }
uint64_t tickClockDropped(const TickClock* c) { return c ? c->dropped : 0; }

int tickPeriodForDistSq(int32_t dist_sq)
{
	return (dist_sq <= TICK_NEAR_DIST_SQ) ? 1 : TICK_FAR_PERIOD;
}

bool tickDue(uint64_t tick, int period, uint32_t id)
{
	if (period <= 1) return true;

	// The stagger. `id` is added to the tick rather than compared against a bucket so that a
	// caller can pass anything unique it already has — an entity index, a column hash — without
	// that value needing to be dense or bounded.
	return ((tick + (uint64_t)id) % (uint64_t)period) == 0;
}
