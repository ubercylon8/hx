// extension/test/hx/TestSupport.java
package hx;

import java.lang.management.LockInfo;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;

/**
 * Shared across the hand-rolled test runners in hx.bridge and hx.policy.
 * Lives under test/, not src/, so extension/build.sh never compiles it into
 * the shipped jar.
 */
public final class TestSupport {

    private TestSupport() {}

    /** One test method, as {@link #t} runs it. Declared to throw, because the
     *  whole point of the guard is the methods that do. */
    public interface Body { void run() throws Exception; }

    /**
     * How a test class records a result. Every runner here keeps its OWN
     * {@code check(String, boolean)} and its own {@code failures} counter, so
     * the guard is handed the one that belongs to the class being run rather
     * than reaching for a shared static: {@code t("x", Foo::x)} in each class
     * is a one-line binding of {@code Foo::check}, and a FAIL raised here
     * lands in the same count and the same summary line as every other FAIL in
     * that class.
     */
    public interface Reporter { void check(String what, boolean ok); }

    /**
     * The method currently running, so a HANG can name itself.
     *
     * {@link #t}'s docstring below says the exit code is the only thing that
     * notices a hang. That is DETECTION; this is DIAGNOSIS, and they are
     * different problems. rc=1 tells you the suite lost a class. It does not
     * tell you WHICH of that class's methods parked, and the output stops
     * before the method that hung would have printed anything -- so the last
     * line you see is the previous method's `ok`, which points at the wrong
     * place.
     *
     * `timeout` sends SIGTERM, and the JVM runs shutdown hooks on SIGTERM. So
     * the hook below prints the name that was in flight. It costs one volatile
     * write per test method and prints NOTHING on a healthy run -- a diagnostic
     * that fires unconditionally is noise, and noise is what stops people
     * reading output at all.
     *
     * IT HAS ALREADY EARNED ITS PLACE. The sweep that bounded this repo's
     * joins believed it had found every unbounded wait; this hook named the
     * one it had missed, `KILLED WHILE RUNNING
     * checkIsExclusiveWithItselfDeterministically`, on a monitor acquisition
     * no join bound could ever have covered. See {@link #join}.
     */
    private static volatile String inFlight;

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            String name = inFlight;
            if (name != null) {
                // stderr, not stdout: a killed run's stdout may be mid-buffer,
                // and this line has to survive to be worth writing.
                System.err.println("hx: KILLED WHILE RUNNING " + name
                        + " -- this class printed no summary line because the "
                        + "method never returned. Bound the wait.");
                System.err.flush();
            }
        }, "hx-inflight-reporter"));
    }

    /**
     * Run one test method so that a throw out of it is a NAMED FAILURE rather
     * than the end of the run.
     *
     * Without this, any throw -- an NPE on a null a sabotage introduced, an
     * IOException from a socket -- propagates out of {@code main()}: the
     * methods after it never run, {@code failures} is never printed, and there
     * is NO summary line at all. The exit code is still 1, so CI notices, but
     * every count taken from that run is a count of how far the runner got.
     * Measured on Policy.java: of 23 compiling single-guard mutants, 13 print
     * zero FAIL lines, so the summary line is the only thing separating a real
     * green from a truncation -- and under {@code ./test.sh | grep -c FAIL},
     * the idiom this project's briefs prescribe, a truncation reads as 0.
     *
     * A THROW IS ONLY THE FIRST WAY A CLASS PRINTS NO SUMMARY LINE. The second
     * is a HANG, and this guard cannot catch it: a test method parked on an
     * unbounded {@code join()}, {@code await()} or {@code synchronized} call
     * never returns, so there is nothing to catch, the methods after it never
     * run, and test.sh's {@code timeout 300} kills the class from outside.
     * That run prints one FEWER summary line and still zero FAIL lines. So:
     * JUDGE A RUN BY ITS SUMMARY-LINE COUNT AND ITS EXIT CODE.
     *
     * WHAT THE BOUNDS DO CATCH, each mutation applied alone under
     * {@code timeout 600 ./test.sh}, against a clean 11 summary lines / 0 FAIL
     * / rc=0:
     *
     *   - a {@code Limiter.check} that PARKS a caller it made wait for its own
     *     monitor instead of refusing it: {@link #join} fires by name -- "...
     *     had not finished after 10000 ms, so it HUNG" -- giving 11 summary
     *     lines with a named FAIL and rc=1 instead of a truncation. WHICH of
     *     LimiterTest's two waits trips first depends on the mutation's own
     *     timing and both were seen across two runs; the claim here is that
     *     one of them does, not which;
     *   - the race's own {@code go.countDown()} deleted, the shape that used
     *     to hold the JVM open on a non-daemon worker: 11 summary lines,
     *     2 FAIL, rc=1.
     *
     * WHAT THEY DO NOT CATCH, measured the same way and UNCHANGED by every
     * bound in this file: a {@code Limiter.check} that SLEEPS instead of
     * denying when rate-limited -- a rate limiter that THROTTLES rather than
     * REFUSES, the §4 violation the proxy layer above it exists to forbid --
     * gives 10 summary lines, 10 ALL PASS, 0 FAIL, rc=1. It parks in
     * {@code theWindowIsExactAtItsBoundaries}, the FIRST of LimiterTest's
     * fourteen methods and eleven before {@code raceAgainst} is reached, in a
     * direct call that owns no helper thread and waits on nothing. There is no
     * wait for {@link #join} to bound, and THE EXIT CODE IS THE ONLY THING
     * THAT SEES IT -- with the shutdown hook above to say which method it was.
     * A bound cannot be retrofitted onto a straight-line call from out here;
     * only a watchdog running each body on its own bounded thread could, and
     * with 24 methods in a class its per-method share of test.sh's 300 s is
     * ~12 s, under {@code LimiterTest.RACE_DEADLINE_MS} alone. It would fire
     * on healthy runs.
     *
     * Catching {@link Throwable} rather than {@link Exception} is deliberate:
     * an {@link AssertionError} or a {@link StackOverflowError} out of a test
     * method truncates a run exactly as an NPE does.
     */
    public static void t(Reporter reporter, String name, Body body) {
        inFlight = name;
        try {
            body.run();
        } catch (Throwable e) {
            reporter.check(name + " threw " + e, false);
        } finally {
            // Cleared in a finally, so a THROWN method does not leave its name
            // in flight and get blamed for a later method's hang.
            inFlight = null;
        }
    }

    /**
     * Join a helper thread with a BOUND, or fail by name.
     *
     * `t.join()` with no argument is the second truncation described on
     * {@link #t}: it cannot fail, only hang, and a hung class prints no
     * summary line. This throws instead, which {@link #t} turns into a named
     * FAIL against the class's own counter -- the difference between "the
     * suite lost a class" and "this named property is broken".
     *
     * The caller supplies the bound, because only the caller knows what the
     * thread is doing: a millisecond of non-blocking arithmetic and a socket
     * round trip deserve different numbers. Every bound passed today is 10 s
     * or less, against work whose whole test class finishes in well under a
     * second, so none can fire on anything but a genuine hang. And a class
     * whose every bound fires still finishes inside test.sh's 300 s backstop:
     * LimiterTest holds the most of them and its worst case is 8 workers x
     * 10 s x 2 races, plus 5 s for the exclusivity helper -- 165 s.
     *
     * The thread is NOT interrupted on the deadline. Unparking it would let
     * the assertions after this call run against work the hang had quietly
     * finished, hiding the very thing being reported -- and a leaked DAEMON
     * costs nothing, which is why every caller here makes its helper one.
     *
     * THIS IS A BOUND FOR A THREAD AND THERE IS NONE FOR A MONITOR, which is
     * where the sweep that introduced this method was wrong to call itself
     * complete. A {@code synchronized} call whose lock is held by a thread
     * that has parked cannot be bounded, interrupted or timed out from the
     * outside at all -- {@code Object.wait} takes a timeout, ENTERING a
     * monitor does not. Measured: with {@code Limiter.check} parking a caller
     * it made wait for the monitor,
     * {@code LimiterTest.checkIsExclusiveWithItselfDeterministically} printed
     * its own FAIL line and then parked forever on {@code limiter.issued()},
     * a {@code synchronized} accessor the parked helper was still holding --
     * 10 summary lines and rc=1, the class truncated. The only bound for that
     * shape is NOT MAKING THE CALL: throw out of the join first, so the line
     * that would take the monitor is never reached. That is what the call site
     * does now, and it is what an audit for unbounded waits has to look for
     * alongside the joins -- a locked accessor after a helper that might not
     * have released.
     */
    public static void join(Thread t, long ms, String what) throws Exception {
        t.join(ms);
        if (t.isAlive())
            throw new AssertionError(
                what + " had not finished after " + ms + " ms, so it HUNG. An "
                + "unbounded join here would have printed no summary line at "
                + "all and read as zero failures");
    }

    /**
     * True once `t` is BLOCKED on `monitor` specifically -- the deterministic
     * way to prove a thread is parked on a particular lock, as opposed to
     * merely "blocked on something."
     *
     * Thread.State.BLOCKED alone is not enough: a thread stuck on a class-
     * initialisation monitor, or any other unrelated lock, is also BLOCKED.
     * Comparing the held lock's identity hash against `monitor`'s is what
     * makes the wait honest -- and it is why this takes the monitor object
     * itself rather than a description of it.
     */
    public static boolean waitUntilBlockedOn(Thread t, Object monitor) throws Exception {
        ThreadMXBean mx = ManagementFactory.getThreadMXBean();
        int want = System.identityHashCode(monitor);
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            ThreadInfo info = mx.getThreadInfo(t.threadId());
            if (info != null && t.getState() == Thread.State.BLOCKED) {
                LockInfo li = info.getLockInfo();
                if (li != null && li.getIdentityHashCode() == want) return true;
            }
            Thread.sleep(1);
        }
        return false;
    }
}
