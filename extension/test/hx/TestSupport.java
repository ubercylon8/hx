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
     * Catching {@link Throwable} rather than {@link Exception} is deliberate:
     * an {@link AssertionError} or a {@link StackOverflowError} out of a test
     * method truncates a run exactly as an NPE does.
     */
    public static void t(Reporter reporter, String name, Body body) {
        try {
            body.run();
        } catch (Throwable e) {
            reporter.check(name + " threw " + e, false);
        }
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
