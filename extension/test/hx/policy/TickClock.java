// extension/test/hx/policy/TickClock.java
package hx.policy;

/**
 * A clock the test moves by hand. Every time-dependent guard in hx takes an
 * injected Clock precisely so its boundaries can be hit exactly -- the
 * microsecond before a window rolls, and the microsecond it rolls -- which no
 * amount of Thread.sleep can do.
 *
 * `us` is volatile because the concurrency check reads it from eight threads
 * while they hammer one Limiter. `advance` is a read-modify-write and is NOT
 * atomic: move the clock only from the thread that is driving the test, never
 * from inside a racing worker.
 */
public final class TickClock implements Clock {

    private volatile long us;

    public TickClock(long us) { this.us = us; }

    @Override
    public long nowUs() { return us; }

    public void set(long us) { this.us = us; }

    public void advance(long deltaUs) { this.us += deltaUs; }
}
