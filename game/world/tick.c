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
	// The low side is guarded as well as the high one, and that is not defensive padding.
	// `dist_sq` is a SQUARED distance, so a negative value does not describe something very
	// close — it is arithmetic that has already gone wrong, and the overwhelmingly likely
	// cause is a caller computing dx*dx + dz*dz in int32 and overflowing it. Without the
	// `>= 0` term such a value satisfies `<= TICK_NEAR_DIST_SQ` and is handed back period 1,
	// which is the exact inversion of the intent: the furthest thing in the world gets ticked
	// at the FULL rate, precisely when it should be the cheapest thing there is. And it does
	// so on the dedicated server too, because this file is vendored into it byte-identical.
	//
	// Not reachable at the distances anything calls this with today — the customer is a
	// player-to-entity distance inside a 17-column render radius, about 1.5e5 squared against
	// an int32 ceiling of 2.1e9. But world.h's coordinate conventions call block x and z
	// "signed and unbounded", so that headroom is a property of where players currently walk,
	// not a property this function is entitled to assume.
	//
	// What this does NOT do: rescue a caller whose overflow happens to wrap back into
	// 0..TICK_NEAR_DIST_SQ. Nothing testable inside this function can, since such a value is
	// indistinguishable from a genuinely near one; only doing the arithmetic in a wider type
	// at the call site can. It makes the NEGATIVE-reads-as-near inversion impossible, which
	// is the whole of the reachable failure and all of it that is this function's to own.
	return (dist_sq >= 0 && dist_sq <= TICK_NEAR_DIST_SQ) ? 1 : TICK_FAR_PERIOD;
}

bool tickDue(uint64_t tick, int period, uint32_t id)
{
	if (period <= 1) return true;

	// The stagger. `id` is added to the tick rather than compared against a bucket so that a
	// caller can pass anything unique it already has — an entity index, a column hash — without
	// that value needing to be dense or bounded.
	return ((tick + (uint64_t)id) % (uint64_t)period) == 0;
}
