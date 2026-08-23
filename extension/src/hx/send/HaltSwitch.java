// extension/src/hx/send/HaltSwitch.java
package hx.send;

import hx.policy.Clock;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The halted flag, fed by two independent inputs: `halt`/`resume` frames off
 * the bridge, and a sentinel file polled on a background thread.
 *
 * The sentinel exists to work when the bridge does not (§4). An operator with
 * a dead socket, a wedged harness, or an agent that has stopped answering can
 * `touch` one path from a shell and stop issuance; nothing in Python, and
 * nothing on the control channel, has to be alive for that to take effect.
 * Its PRESENCE is the whole signal -- the file's contents are never read, so
 * `touch`, `install`, a redirect, or an empty directory all work.
 *
 * The two inputs are independent and BOTH must be clear before issuance
 * re-arms. A `resume` frame lifts the frame half only: the operator who
 * created the sentinel by hand is not necessarily the agent that sent the
 * resume, and re-arming on one of them is how a halt gets lifted by someone
 * who never knew it was in force. Symmetrically, deleting the file does not
 * lift a `halt` frame.
 *
 * **Unknown state is stop.** Every filesystem call here is treated as able to
 * throw something this file does not name -- a permission error, a vanished
 * mount, a provider whose FileSystem was closed underneath us -- and every one
 * of those answers "halted". Only one specific outcome, NoSuchFileException,
 * means "not halted", because it is the only one that actually answers the
 * question. Three separate guards on this project have been opened by an
 * exception from outside the repo escaping a catch clause that named the
 * wrong type.
 *
 * No Montoya, no bridge types, no sockets: this class must keep working when
 * everything around it has stopped.
 */
public final class HaltSwitch {

    /**
     * §4's kill switch is a path an operator uses during an incident, so the
     * budget for "I created the file" to become "nothing is issuing" is human
     * -- half a second, not a minute. At the production profile's single-digit
     * req/s this bounds the requests issued after the file appears to a
     * handful.
     */
    public static final long DEFAULT_POLL_MS = 500L;

    /**
     * A poller that has not answered in this many intervals is treated as
     * halted: a thread that died, or is blocked in a filesystem call on a
     * hung mount, leaves the last answer stale, and a stale answer to "is the
     * operator holding the stop button" is not an answer. Five intervals
     * (2.5s at the default) is long enough that an ordinary JVM pause inside
     * Burp does not trip it and short enough that a dead poller cannot cover a
     * whole run. It clears itself on the next successful poll, because the
     * condition is "we do not know right now", not "something happened once".
     */
    static final long STALE_INTERVALS = 5L;

    /**
     * stop() runs on Burp's extension-unloading thread. A poller wedged in a
     * filesystem call cannot be killed from inside the JVM, so the join is
     * bounded: unloading the extension must not hang Burp. The state stays
     * whatever it last was, which -- for a wedged poller -- is halted.
     */
    private static final long STOP_JOIN_MS = 2_000L;

    private final Clock clock;
    private final Path sentinel;
    private final long pollIntervalMs;
    private final long staleAfterUs;

    /** A private monitor, not `this`: nothing outside can take it, so nothing
     *  outside can deadlock the poller against stop(). */
    private final Object lock = new Object();

    /**
     * Both inputs, and the poll clock, published through ONE reference.
     *
     * halted() and reason() are two calls and a change can land between them
     * -- the bridge measured that straddle for epoch/scope and it is real here
     * too. What one reference buys is that each ANSWER is coherent: reason()
     * can never report a frame reason from a halt that has already been
     * resumed, or a sentinel reason with sentinelHalted false. The one
     * straddle left is halted()==true followed by reason()==null, which needs
     * a resume to land in between -- and Sender answers it with an explicit
     * fallback string rather than believing it was never halted.
     */
    private record State(boolean frameHalted, String frameReason,
                         boolean sentinelHalted, String sentinelReason,
                         boolean armed, long lastPollUs) { }

    private volatile State state = new State(false, null, false, null, false, 0L);

    /** The live poller, or null. Also the loop's own "am I still wanted"
     *  token: a thread that is no longer this reference returns. */
    private volatile Thread poller;

    /** Completed polls. A test seam, not state: nothing here reads it. */
    private final AtomicLong polls = new AtomicLong();

    public HaltSwitch(Clock clock, Path sentinel, long pollIntervalMs) {
        if (clock == null) throw new IllegalArgumentException("clock is required");
        if (sentinel == null) throw new IllegalArgumentException("sentinel path is required");
        if (pollIntervalMs <= 0)
            // Thread.sleep(0) spins a core at 100% and polls the filesystem
            // millions of times a second; a negative one throws from inside
            // the loop, which would kill the poller outright.
            throw new IllegalArgumentException("poll interval must be positive, got " + pollIntervalMs);
        this.clock = clock;
        this.sentinel = sentinel;
        this.pollIntervalMs = pollIntervalMs;
        this.staleAfterUs = pollIntervalMs * 1_000L * STALE_INTERVALS;
    }

    /**
     * Look at the sentinel now, then keep looking on a daemon thread.
     *
     * The first poll runs on the CALLER's thread and completes before this
     * returns, so a sentinel that already existed -- an operator halted the
     * last run and Burp has just restarted -- is in force before anything can
     * ask. A first poll left to the background thread would leave one poll
     * interval in which a standing halt reads as "not halted".
     *
     * Idempotent: a second call while a poller is alive is a no-op rather than
     * a second thread. Two pollers is a leak that answers correctly, which is
     * the kind that survives review.
     */
    public void start() {
        synchronized (lock) {
            Thread live = poller;
            if (live != null && live.isAlive()) return;
            pollNow();
            State s = state;
            state = new State(s.frameHalted(), s.frameReason(),
                              s.sentinelHalted(), s.sentinelReason(),
                              true, s.lastPollUs());
            Thread t = new Thread(this::pollLoop, "hx-halt-sentinel");
            // Daemon: a polling thread that outlives the extension keeps a
            // JVM alive and keeps stat()ing a client's engagement directory
            // after Burp thinks hx is gone.
            t.setDaemon(true);
            poller = t;
            t.start();
        }
    }

    /**
     * Stop polling. Never clears a halt: the last thing the poller learned
     * stays in force, so unloading the extension cannot re-arm issuance.
     */
    public void stop() {
        Thread t;
        synchronized (lock) {
            t = poller;
            poller = null;                     // the loop's exit condition
            State s = state;
            // armed=false retires the staleness rule with the thread that fed
            // it: a stopped switch is not a stalled one, and reporting a
            // stopped extension as "poller stalled" would be a false reason on
            // a true halt.
            state = new State(s.frameHalted(), s.frameReason(),
                              s.sentinelHalted(), s.sentinelReason(),
                              false, s.lastPollUs());
        }
        if (t == null) return;
        // Outside the monitor. The poller takes `lock` to publish, so a
        // stop() that held it across the join would wait out STOP_JOIN_MS
        // whenever the poller happened to be mid-publish -- and would then
        // return with the thread still running. That is a narrow window rather
        // than a certain deadlock (the poller is nearly always asleep, where
        // the interrupt reaches it), which is exactly why no test would catch
        // it and why the join goes here rather than two lines up.
        t.interrupt();
        try {
            t.join(STOP_JOIN_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** A `halt` frame arrived. */
    public void haltedByFrame(String reason) {
        synchronized (lock) {
            State s = state;
            state = new State(true,
                              reason == null || reason.isBlank()
                                  ? "halted by frame, no reason given" : reason,
                              s.sentinelHalted(), s.sentinelReason(),
                              s.armed(), s.lastPollUs());
        }
    }

    /**
     * A `resume` frame arrived. Clears the frame half ONLY -- if the sentinel
     * file is still there, this switch stays halted, and the operator who
     * created it is the only one who can clear it.
     */
    public void resumedByFrame() {
        synchronized (lock) {
            State s = state;
            state = new State(false, null,
                              s.sentinelHalted(), s.sentinelReason(),
                              s.armed(), s.lastPollUs());
        }
    }

    /** True if EITHER input is in force, or if the poller has stopped
     *  answering while armed. */
    public boolean halted() {
        State s = state;
        return s.frameHalted() || s.sentinelHalted() || stale(s);
    }

    /** Why, or null when nothing is holding issuance. */
    public String reason() {
        State s = state;
        if (s.frameHalted()) return s.frameReason();
        if (s.sentinelHalted()) return s.sentinelReason();
        if (stale(s))
            // Deliberately does not read the clock again to print an age: a
            // reason() that can throw turns a halt into an exception on the
            // send path.
            return "halt sentinel poller stalled: no answer in the last "
                   + (staleAfterUs / 1000L) + "ms (poll interval " + pollIntervalMs + "ms)";
        return null;
    }

    private boolean stale(State s) {
        if (!s.armed()) return false;
        try {
            return clock.nowUs() - s.lastPollUs() > staleAfterUs;
        } catch (Throwable t) {
            // The clock is injected, so it is someone else's code. A clock we
            // cannot read is a poll age we cannot compute, which is an unknown
            // state, which is stop.
            return true;
        }
    }

    /** One look at the sentinel, publishing whatever it learned. Package-
     *  private: HaltSwitchTest drives a single poll without a thread. */
    void pollOnce() {
        boolean present;
        String why;
        try {
            // NOT Files.exists(). It answers `false` for a path it was not
            // ALLOWED to look at -- measured: a sentinel inside a 0000
            // directory gives Files.exists()==false, Files.notExists()==false
            // -- and false here means "issue away". readAttributes throws
            // instead, which is the only way to tell "no file" from "no
            // answer".
            //
            // NOFOLLOW_LINKS because presence of the NAME is the signal: a
            // dangling symlink is something an operator put there, and
            // following it would report the absent TARGET as "no halt".
            Files.readAttributes(sentinel, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            present = true;
            why = "halt sentinel present: " + sentinel;
        } catch (NoSuchFileException absent) {
            // ENOENT names the sentinel, but it is NOT only "the operator
            // removed the file": readAttributes answers exactly the same for a
            // sentinel whose PARENT is gone, is a dangling symlink, or is a
            // regular file (ENOTDIR). Measured, all three, on the real class:
            // every one of them read as not-halted, so removing the engagement
            // directory under a standing halt LIFTED it within one poll while
            // the operator was looking at a path that no longer existed.
            //
            // "No file" only answers the question when there is a directory
            // for the file to be missing FROM, so confirm that much before
            // believing it. Deleting the file with the directory still there
            // re-arms exactly as before -- this is a second question, not a
            // latch.
            String unconfirmed = parentIsNotADirectory();
            present = unconfirmed != null;
            why = unconfirmed;
        } catch (Throwable t) {
            // Everything else: AccessDeniedException, a vanished mount, a
            // ClosedFileSystemException from a provider we do not control.
            // We did not learn the state, so the state is halted.
            present = true;
            why = "halt sentinel unreadable, treating as halted: " + sentinel + ": " + t;
        }
        publishAnswer(present, why);
    }

    /**
     * null when the sentinel's parent is confirmed to be a directory, and
     * otherwise the reason to halt. Called only on the ENOENT path, where the
     * question is whether "no file" is an answer or a symptom.
     *
     * Follows links deliberately -- the opposite of the sentinel read itself.
     * A parent that is a symlink to a real directory is a directory the
     * sentinel can live in, and the operator's `touch` would land inside it; a
     * DANGLING one resolves to nothing, so the sentinel cannot be there and
     * cannot be absent from there either. That one throws here and is caught.
     */
    private String parentIsNotADirectory() {
        Path parent;
        try {
            parent = sentinel.getParent();
            // A bare relative name -- "HALTED" with no directory part -- has
            // no parent to confirm, so ask the filesystem where it would be.
            // The production path is absolute (<engagement_root>/HALTED) and
            // never takes this branch.
            if (parent == null) parent = sentinel.toAbsolutePath().getParent();
        } catch (Throwable t) {
            return "halt sentinel's parent directory cannot be resolved, treating as halted: "
                   + sentinel + ": " + t;
        }
        if (parent == null)
            return "halt sentinel has no parent directory to confirm, treating as halted: "
                   + sentinel;
        try {
            if (Files.readAttributes(parent, BasicFileAttributes.class).isDirectory()) return null;
            return "halt sentinel's parent is not a directory, treating as halted: " + parent;
        } catch (Throwable t) {
            return "halt sentinel's parent directory is gone or unreadable, treating as halted: "
                   + parent + ": " + t;
        }
    }

    /** pollOnce() plus the outer net. The net is separate because pollOnce()
     *  also reads an injected Clock and publishes, and neither of those is a
     *  filesystem call its own catch clause covers. */
    private void pollNow() {
        try {
            pollOnce();
        } catch (Throwable t) {
            publishFailure("halt sentinel poll failed, treating as halted: " + t);
        }
    }

    /** Publish what a completed poll learned, and stamp the poll clock. */
    private void publishAnswer(boolean present, String why) {
        // Read the clock BEFORE taking the monitor: an injected clock that
        // blocks must not hold up a halt frame arriving on another thread.
        long now = clock.nowUs();
        synchronized (lock) {
            State s = state;
            state = new State(s.frameHalted(), s.frameReason(), present, why, s.armed(), now);
        }
        polls.incrementAndGet();
    }

    /**
     * Publish a poll that did not complete. Reads no clock: the injected Clock
     * is one of the things that can have thrown to get here, and a reason
     * string is worth more than a timestamp we could not take. The poll stamp
     * is left where the last completed poll put it, so the staleness rule goes
     * on measuring time since the last real ANSWER.
     */
    private void publishFailure(String why) {
        synchronized (lock) {
            State s = state;
            state = new State(s.frameHalted(), s.frameReason(), true, why,
                              s.armed(), s.lastPollUs());
        }
    }

    private void pollLoop() {
        // The condition is the exit that does not depend on an interrupt
        // arriving. stop()'s interrupt is what ends the sleep in practice --
        // measured: `while (true)` still passes the whole suite -- but a
        // poller whose interrupt was consumed somewhere else still has to be
        // able to leave.
        while (poller == Thread.currentThread()) {
            try {
                Thread.sleep(pollIntervalMs);
            } catch (InterruptedException e) {
                // stop() interrupts to cut the sleep short. Restore the flag
                // and leave; the state stop() published stands.
                Thread.currentThread().interrupt();
                return;
            }
            if (poller != Thread.currentThread()) return;
            pollNow();
        }
    }

    /** Test seam: is the poller thread still running? */
    boolean pollerAlive() {
        Thread t = poller;
        return t != null && t.isAlive();
    }

    /** Test seam: completed polls, so a test can wait for one to have
     *  happened rather than sleeping for an interval and hoping. */
    long polls() { return polls.get(); }
}
