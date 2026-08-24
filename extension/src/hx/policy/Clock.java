// extension/src/hx/policy/Clock.java
package hx.policy;

/**
 * Microseconds since the epoch, injected everywhere time matters.
 *
 * Nothing in this package reads System.currentTimeMillis() directly. Limiter's
 * window, Distress's rolling baseline and HaltSwitch's poll interval all take
 * one of these, so their boundaries are hit exactly in tests instead of being
 * approached with a sleep -- a test that sleeps 1100ms to cross a 1s window is
 * both slow and, on a loaded machine, occasionally wrong.
 */
public interface Clock {
    long nowUs();
}
