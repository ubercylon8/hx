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
