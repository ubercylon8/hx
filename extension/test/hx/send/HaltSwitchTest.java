// extension/test/hx/send/HaltSwitchTest.java
package hx.send;

import hx.TestSupport;
import hx.policy.Clock;
import hx.policy.TickClock;

import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class HaltSwitchTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(HaltSwitchTest::check, name, body);
    }

    static void expectThrows(String what, Class<?> type, Runnable body) {
        try {
            body.run();
            check(what + " (expected " + type.getSimpleName() + ")", false);
        } catch (Throwable t) {
            check(what, type.isInstance(t));
        }
    }

    /** A precondition this uid cannot satisfy is not a pass. It prints on its
     *  own line so a suite that skipped something cannot read as a clean one. */
    static void skip(String what, String why) {
        System.out.println("  SKIP " + what + " -- " + why);
    }

    /** An arbitrary but fixed wall time, in microseconds: every clock here is
     *  moved by hand, so the absolute value only has to be plausible. */
    static final long T0 = 1_787_355_131_378_277L;

    public static void main(String[] args) throws Exception {
        t("aFreshSwitchIsNotHalted", HaltSwitchTest::aFreshSwitchIsNotHalted);
        t("aHaltFrameHaltsAndAResumeLiftsIt", HaltSwitchTest::aHaltFrameHaltsAndAResumeLiftsIt);
        t("aHaltFrameWithNoReasonStillReportsOne", HaltSwitchTest::aHaltFrameWithNoReasonStillReportsOne);
        t("anUnstartedSwitchDoesNotConsultTheSentinel", HaltSwitchTest::anUnstartedSwitchDoesNotConsultTheSentinel);

        t("aSentinelThatAlreadyExistsIsInForceBeforeStartReturns", HaltSwitchTest::aSentinelThatAlreadyExistsIsInForceBeforeStartReturns);
        t("theSentinelIsPolledInBothDirections", HaltSwitchTest::theSentinelIsPolledInBothDirections);
        t("presenceIsTheSignalNotContent", HaltSwitchTest::presenceIsTheSignalNotContent);

        t("aVanishedEngagementDirectoryDoesNotLiftAHalt", HaltSwitchTest::aVanishedEngagementDirectoryDoesNotLiftAHalt);
        t("aSentinelWhoseParentIsNotADirectoryIsHalted", HaltSwitchTest::aSentinelWhoseParentIsNotADirectoryIsHalted);

        t("theTwoInputsAreIndependent", HaltSwitchTest::theTwoInputsAreIndependent);

        t("anUnreadableSentinelIsHalted", HaltSwitchTest::anUnreadableSentinelIsHalted);
        t("aSentinelOnAClosedFileSystemIsHaltedNotAnEscapedException", HaltSwitchTest::aSentinelOnAClosedFileSystemIsHaltedNotAnEscapedException);
        t("aFailedPollIsPublishedAsHalted", HaltSwitchTest::aFailedPollIsPublishedAsHalted);
        t("aClockThatThrowsIsHaltedNotTrusted", HaltSwitchTest::aClockThatThrowsIsHaltedNotTrusted);
        t("thePollerSurvivesAFailedPollAndKeepsPolling", HaltSwitchTest::thePollerSurvivesAFailedPollAndKeepsPolling);
        t("aStalledPollerIsHalted", HaltSwitchTest::aStalledPollerIsHalted);
        t("aResumeFrameDoesNotRetireTheStalenessRule", HaltSwitchTest::aResumeFrameDoesNotRetireTheStalenessRule);

        t("thePollerIsADaemonAndDoesNotOutliveStop", HaltSwitchTest::thePollerIsADaemonAndDoesNotOutliveStop);
        t("nothingPollsAfterStop", HaltSwitchTest::nothingPollsAfterStop);
        t("startIsIdempotent", HaltSwitchTest::startIsIdempotent);
        t("stopIsSafeWhenNeverStartedAndNeverClearsAHalt", HaltSwitchTest::stopIsSafeWhenNeverStartedAndNeverClearsAHalt);
        t("stopThenStartPollsAgain", HaltSwitchTest::stopThenStartPollsAgain);
        t("stopIsBoundedWhenThePollerCannotBeInterrupted", HaltSwitchTest::stopIsBoundedWhenThePollerCannotBeInterrupted);
        t("aNonPositivePollIntervalIsRefused", HaltSwitchTest::aNonPositivePollIntervalIsRefused);
        t("theConstantsAreTheNumbersThatWereChosen", HaltSwitchTest::theConstantsAreTheNumbersThatWereChosen);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- the frame input -------------------------------------------------

    static void aFreshSwitchIsNotHalted() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltfresh");
        try {
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), dir.resolve("halt"), 10L);
            check("a fresh switch is not halted", !hs.halted());
            check("and has no reason", hs.reason() == null);
        } finally { rmTree(dir); }
    }

    static void aHaltFrameHaltsAndAResumeLiftsIt() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltframe");
        try {
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), dir.resolve("halt"), 10L);
            hs.haltedByFrame("operator pressed stop");
            check("a halt frame halts issuance", hs.halted());
            check("and the operator's words are the reason",
                  "operator pressed stop".equals(hs.reason()));

            hs.resumedByFrame();
            check("a resume frame lifts a frame halt", !hs.halted());
            check("and clears the reason with it", hs.reason() == null);
        } finally { rmTree(dir); }
    }

    /** Sender prints reason() into the error frame. A null there costs the
     *  operator the one line that says which of three kill paths fired. */
    static void aHaltFrameWithNoReasonStillReportsOne() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltnoreason");
        try {
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), dir.resolve("halt"), 10L);
            hs.haltedByFrame(null);
            check("a halt frame with no reason still halts", hs.halted());
            check("and still reports a reason", hs.reason() != null && !hs.reason().isBlank());
        } finally { rmTree(dir); }
    }

    /**
     * start() is what arms the sentinel path, and HxExtension calls it before
     * the bridge dials. A switch that polled from its constructor would be a
     * thread started by a `new`, which no Sender unit test could avoid; a
     * switch that answered "halted" merely because nobody had started it would
     * make every one of those tests a false red. The seam is start(), and this
     * pins which side of it the sentinel lives on.
     */
    static void anUnstartedSwitchDoesNotConsultTheSentinel() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltunstarted");
        Path sentinel = dir.resolve("halt");
        try {
            Files.writeString(sentinel, "");
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 10L);
            check("an unstarted switch has not looked at the sentinel", !hs.halted());
            check("and has not started a poller", !hs.pollerAlive());
            hs.start();
            try {
                check("start() is the seam that arms it", hs.halted());
            } finally { hs.stop(); }
        } finally { rmTree(dir); }
    }

    // ---- the sentinel input ----------------------------------------------

    /**
     * The operator halted the last run, then Burp restarted. The file is
     * already there, and it must be in force before start() returns -- not one
     * poll interval later, which is a window in which a standing halt reads as
     * "issue away".
     */
    static void aSentinelThatAlreadyExistsIsInForceBeforeStartReturns() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltexisting");
        Path sentinel = dir.resolve("halt");
        try {
            Files.writeString(sentinel, "");
            // A one-minute interval: if this only passed because a background
            // poll happened to land first, it would have to wait a minute for
            // it, and the check runs immediately.
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 60_000L);
            hs.start();
            try {
                check("a sentinel that already existed is in force when start() returns",
                      hs.halted());
                check("and the reason names the file",
                      hs.reason() != null && hs.reason().contains(sentinel.toString()));
            } finally { hs.stop(); }
        } finally { rmTree(dir); }
    }

    /** The whole point of the file: an operator with a dead socket creates it
     *  from a shell, and issuance stops without anything on the bridge. */
    static void theSentinelIsPolledInBothDirections() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltpoll");
        Path sentinel = dir.resolve("halt");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 10L);
        try {
            hs.start();
            check("not halted while the file is absent", !hs.halted());

            Files.writeString(sentinel, "");
            check("creating the file from outside the JVM halts issuance",
                  awaitTrue(hs::halted));
            check("and the reason says the sentinel is present",
                  hs.reason() != null && hs.reason().contains("present"));

            Files.delete(sentinel);
            check("removing it lifts the sentinel halt", awaitTrue(() -> !hs.halted()));
            check("and the reason goes with it", hs.reason() == null);
        } finally { hs.stop(); rmTree(dir); }
    }

    /**
     * Presence of the NAME is the signal; the contents are never read. A
     * dangling symlink is the case that separates the two readings -- with
     * symlinks followed it resolves to an absent target and reads as "no
     * halt", which is the wrong answer for something an operator put there
     * deliberately. Measured: Files.exists() on that link is false.
     */
    static void presenceIsTheSignalNotContent() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltpresence");
        try {
            Path empty = dir.resolve("empty");
            Files.writeString(empty, "");
            check("an empty file is presence", haltedNow(empty));

            Path asDir = Files.createDirectory(dir.resolve("asdir"));
            check("a directory at the sentinel path is presence", haltedNow(asDir));

            Path dangling = dir.resolve("dangling");
            Files.createSymbolicLink(dangling, dir.resolve("nothing-here"));
            check("a dangling symlink is presence, not absence", haltedNow(dangling));

            check("and an absent path is still absence", !haltedNow(dir.resolve("nope")));
        } finally { rmTree(dir); }
    }

    /**
     * The live path, and the reason this was a HIGH finding rather than a
     * curiosity: `readAttributes` answers NoSuchFileException for a sentinel
     * whose PARENT is gone, which is the same answer it gives when an operator
     * removes the file. Measured before this check existed: an operator
     * touches the sentinel, issuance stops; the engagement directory is then
     * removed -- `rm -rf`, an unmount, a detached volume -- and one poll later
     * the switch answers halted=false, reason=null. The operator is looking at
     * a directory that no longer exists and believes issuance is stopped.
     *
     * "No file" only answers the question when there is a directory for the
     * file to be missing FROM. The production sentinel is
     * `<engagement_root>/HALTED`, inside a directory hx itself creates.
     */
    static void aVanishedEngagementDirectoryDoesNotLiftAHalt() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltvanish");
        Path box = Files.createDirectory(dir.resolve("engagement"));
        Path sentinel = box.resolve("HALTED");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 10L);
        try {
            Files.writeString(sentinel, "");
            hs.start();
            check("the operator's sentinel halts issuance", hs.halted());

            rmTree(box);
            long seen = hs.polls();
            check("the poller has looked since the directory went",
                  awaitTrue(() -> hs.polls() > seen + 1));
            check("a vanished engagement directory does NOT lift the halt", hs.halted());
            check("and the reason names the parent rather than reporting a deleted file",
                  hs.reason() != null && hs.reason().contains("parent"));

            // The other half: this must not become a one-way latch. Put the
            // directory back, with no sentinel in it, and issuance re-arms --
            // which is exactly the case a fix that halted on every ENOENT
            // would break.
            Files.createDirectory(box);
            check("and putting the directory back, with no sentinel in it, re-arms issuance",
                  awaitTrue(() -> !hs.halted()));
        } finally { hs.stop(); rmTree(dir); }
    }

    /**
     * The three parent shapes that all read as "no halt" through a bare
     * NoSuchFileException, one poll each and no thread. ENOTDIR is the one a
     * fix that merely checked the parent's EXISTENCE would leave open: a
     * regular file at the parent's path exists, and a sentinel underneath it
     * can never be created.
     */
    static void aSentinelWhoseParentIsNotADirectoryIsHalted() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltparent");
        try {
            check("a sentinel under a directory that is not there is halted",
                  haltedNow(dir.resolve("gone").resolve("HALTED")));

            Path dangling = dir.resolve("dangling");
            Files.createSymbolicLink(dangling, dir.resolve("nothing-here"));
            check("a sentinel under a dangling symlink is halted",
                  haltedNow(dangling.resolve("HALTED")));

            Path regular = dir.resolve("regular");
            Files.writeString(regular, "not a directory");
            check("a sentinel under a regular file (ENOTDIR) is halted",
                  haltedNow(regular.resolve("HALTED")));

            // And the two shapes that ARE a directory still answer "no halt",
            // so the guard cannot pass by halting on everything.
            Path real = Files.createDirectory(dir.resolve("real"));
            check("a sentinel absent from a directory that is there is not halted",
                  !haltedNow(real.resolve("HALTED")));

            Path link = dir.resolve("link-to-real");
            Files.createSymbolicLink(link, real);
            check("and a parent that is a symlink to a real directory is a directory",
                  !haltedNow(link.resolve("HALTED")));
        } finally { rmTree(dir); }
    }

    // ---- the two inputs are independent ----------------------------------

    /**
     * Both must be clear. A resume frame that re-armed issuance while the file
     * was still there would let an agent lift a halt an operator placed by
     * hand -- and the operator would have no way to know, since the file they
     * are looking at is still on disk.
     */
    static void theTwoInputsAreIndependent() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltboth");
        Path sentinel = dir.resolve("halt");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 10L);
        try {
            Files.writeString(sentinel, "");
            hs.start();
            check("the sentinel alone halts", hs.halted());

            hs.haltedByFrame("agent noticed a 500 storm");
            check("both inputs in force", hs.halted());
            check("the frame reason is the one reported while both hold",
                  "agent noticed a 500 storm".equals(hs.reason()));

            hs.resumedByFrame();
            check("a resume does NOT re-arm while the sentinel file exists", hs.halted());
            check("and the reason falls back to the sentinel",
                  hs.reason() != null && hs.reason().contains("present"));

            hs.haltedByFrame("still stopped");
            Files.delete(sentinel);
            // Wait for the poller to have SEEN the deletion. Asserting the
            // moment after delete() passes before the poll that would break
            // it has run -- measured: the first version of this check passed
            // against a poller that cleared the frame halt on every absent
            // sentinel.
            long seen = hs.polls();
            check("the poller observed the deletion", awaitTrue(() -> hs.polls() > seen + 1));
            check("removing the file does NOT re-arm while a halt frame stands",
                  hs.halted() && "still stopped".equals(hs.reason()));

            hs.resumedByFrame();
            check("only both together re-arm issuance", awaitTrue(() -> !hs.halted()));
        } finally { hs.stop(); rmTree(dir); }
    }

    // ---- unknown state is stop -------------------------------------------

    /**
     * A sentinel the poller is not allowed to stat. Files.exists() answers
     * `false` here -- measured, on a 0000 directory: exists()==false AND
     * notExists()==false, the API's way of saying it does not know -- and
     * `false` means issue away. readAttributes throws instead, and every
     * throw that is not NoSuchFileException means halted.
     */
    static void anUnreadableSentinelIsHalted() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltunreadable");
        Path box = Files.createDirectory(dir.resolve("box"));
        Path sentinel = box.resolve("halt");
        try {
            Files.writeString(sentinel, "");
            Files.setPosixFilePermissions(box, PosixFilePermissions.fromString("---------"));
            if (canStillRead(sentinel)) {
                // root ignores the mode bits, and so would this check.
                skip("an unreadable sentinel is halted",
                     "this uid can stat a file inside a 0000 directory");
                return;
            }
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 60_000L);
            hs.start();
            try {
                check("an unreadable sentinel is halted", hs.halted());
                check("and the reason says so rather than guessing",
                      hs.reason() != null && hs.reason().contains("unreadable"));
            } finally { hs.stop(); }
        } finally {
            Files.setPosixFilePermissions(box, PosixFilePermissions.fromString("rwx------"));
            rmTree(dir);
        }
    }

    /**
     * The failure that a narrowed catch would let through. ClosedFileSystem-
     * Exception extends IllegalStateException -- a RuntimeException, NOT an
     * IOException -- so `catch (IOException)` around the sentinel read lets it
     * escape the poller entirely. The permissions case above cannot show that:
     * AccessDeniedException IS an IOException, so it stays caught either way.
     * Measured, both of them.
     *
     * A zip filesystem is the cheapest way to get a provider that closes under
     * a live Path; the engagement directory is an ordinary one. What is being
     * pinned is the CLASS of failure -- a filesystem call throwing something
     * this file does not name -- which has opened three guards on this project
     * already.
     */
    static void aSentinelOnAClosedFileSystemIsHaltedNotAnEscapedException() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltclosedfs");
        Path zip = dir.resolve("engagement.zip");
        try {
            try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(zip))) {
                z.putNextEntry(new ZipEntry("halt"));
                z.write("stop".getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
            Path inside;
            try (FileSystem fs = FileSystems.newFileSystem(zip, Map.of())) {
                inside = fs.getPath("/halt");
            }                                        // provider closed here
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), inside, 60_000L);
            boolean threw = false;
            try { hs.start(); } catch (Throwable t) { threw = true; }
            try {
                check("a sentinel on a closed filesystem does not throw out of start()", !threw);
                check("a sentinel on a closed filesystem is halted", hs.halted());
                check("and the sentinel read is what names it, not the outer net",
                      hs.reason() != null && hs.reason().contains("unreadable"));
            } finally { hs.stop(); }
        } finally { rmTree(dir); }
    }

    /**
     * The outer net's POLARITY, which nothing reached before.
     *
     * `pollNow`'s catch exists for a poll that blew up in a way pollOnce()'s
     * own clauses did not name, and the only way in is the injected Clock:
     * pollOnce() reads it to stamp the poll AFTER it has decided the sentinel's
     * answer. The closed-filesystem check does not come here -- pollOnce()
     * catches that itself -- so `publishFailure` publishing `false` inverted
     * the entire outer net to fail open with the suite fully green.
     *
     * The separation is stop(): it retires the staleness rule (armed=false)
     * and takes the thread with it, which leaves what publishFailure published
     * as the only thing that can still be holding issuance. Without that, a
     * throwing clock answers "halted" through stale() and the net's polarity
     * is invisible again.
     */
    static void aFailedPollIsPublishedAsHalted() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltouternet");
        BreakableClock clock = new BreakableClock(T0);
        clock.broken = true;
        // The sentinel is absent and its directory is there, so pollOnce()
        // reaches the "not halted" answer and then dies publishing it.
        HaltSwitch hs = new HaltSwitch(clock, dir.resolve("halt"), 60_000L);
        try {
            boolean threw = false;
            try { hs.start(); } catch (Throwable t) { threw = true; }
            check("a poll that fails outside pollOnce() does not throw out of start()", !threw);

            hs.stop();
            clock.broken = false;
            check("a poll that did not complete is published as HALTED", hs.halted());
            check("and the outer net is what names it, not the sentinel read",
                  hs.reason() != null && hs.reason().contains("poll failed"));
        } finally { hs.stop(); rmTree(dir); }
    }

    /**
     * The other guard whose input is "the injected Clock is someone else's
     * code". A clock that throws is a poll age that cannot be computed, which
     * is an unknown state, which is stop.
     *
     * A minute between polls, so the background poller cannot reach the clock
     * while it is broken: a poll that failed would answer through
     * publishFailure and hide which of the two guards was doing the work.
     */
    static void aClockThatThrowsIsHaltedNotTrusted() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltclock");
        BreakableClock clock = new BreakableClock(T0);
        HaltSwitch hs = new HaltSwitch(clock, dir.resolve("halt"), 60_000L);
        try {
            hs.start();
            check("not halted while the clock answers and the sentinel is absent", !hs.halted());

            clock.broken = true;
            check("a clock that cannot be read is halted", hs.halted());
            check("and the staleness rule is what says so",
                  hs.reason() != null && hs.reason().contains("stalled"));
        } finally { clock.broken = false; hs.stop(); rmTree(dir); }
    }

    /** A poll that failed must not kill the thread: the next one is how the
     *  halt would ever lift. */
    static void thePollerSurvivesAFailedPollAndKeepsPolling() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltrecover");
        Path box = Files.createDirectory(dir.resolve("box"));
        Path sentinel = box.resolve("halt");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 10L);
        try {
            Files.setPosixFilePermissions(box, PosixFilePermissions.fromString("---------"));
            if (canStillRead(sentinel)) {
                skip("the poller survives a failed poll",
                     "this uid can stat a file inside a 0000 directory");
                return;
            }
            hs.start();
            check("halted while the directory is unreadable", hs.halted());
            check("and the poller is still alive after a failing poll", hs.pollerAlive());

            long before = hs.polls();
            check("and it keeps polling", awaitTrue(() -> hs.polls() > before + 1));

            Files.setPosixFilePermissions(box, PosixFilePermissions.fromString("rwx------"));
            check("and it recovers once the answer is readable again",
                  awaitTrue(() -> !hs.halted()));
        } finally {
            hs.stop();
            Files.setPosixFilePermissions(box, PosixFilePermissions.fromString("rwx------"));
            rmTree(dir);
        }
    }

    /**
     * A poller that stopped answering is not a poller that answered "no". The
     * thread can die on an Error, or block for good in a filesystem call on a
     * hung mount; either way the last answer goes stale, and a stale answer to
     * "is the operator holding the stop button" is not one. Driven on the
     * injected clock, so the horizon is hit exactly rather than waited out.
     */
    static void aStalledPollerIsHalted() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltstale");
        Path sentinel = dir.resolve("halt");
        TickClock clock = new TickClock(T0);
        // One minute between polls, so the background thread cannot refresh
        // the poll clock underneath the assertions below.
        HaltSwitch hs = new HaltSwitch(clock, sentinel, 60_000L);
        try {
            hs.start();
            check("fresh after start(), with no file", !hs.halted());

            // The horizon as a LITERAL: five intervals of one minute, in
            // microseconds. Computed from HaltSwitch.STALE_INTERVALS -- as it
            // was -- this check passes for every value of that constant,
            // including the 500000 that hides a dead poller for 69 hours.
            clock.advance(300_000_000L);
            check("exactly at the staleness horizon it is still trusted", !hs.halted());

            clock.advance(1L);
            check("one microsecond past it, a stalled poller is halted", hs.halted());
            check("and says which of the three paths it is",
                  hs.reason() != null && hs.reason().contains("stalled"));

            hs.pollOnce();
            check("a fresh answer clears the stall", !hs.halted());

            // STOP_JOIN_MS's comment used to claim that the state left behind
            // by a stop() is halted "for a wedged poller". It is not: stop()
            // retires the staleness rule along with the thread that fed it, so
            // a halt that was ONLY a stall does not survive the stop. Harmless
            // -- the extension is unloading -- but the comment now says this,
            // and this is what makes it falsifiable.
            clock.advance(300_000_001L);
            check("a stall halts while the poller is armed", hs.halted());
            hs.stop();
            check("and stop() retires the staleness rule with the thread it belongs to",
                  !hs.halted());
        } finally { hs.stop(); rmTree(dir); }
    }

    /**
     * A `resume` frame must not retire the staleness rule.
     *
     * `resumedByFrame` publishing `armed=false` leaves the whole suite green,
     * and what it buys is permanent: one resume, and a poller that dies
     * afterwards never halts again for the rest of the run. The staleness rule
     * belongs to the POLLER, and the poller is still running.
     */
    static void aResumeFrameDoesNotRetireTheStalenessRule() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltresumearm");
        TickClock clock = new TickClock(T0);
        HaltSwitch hs = new HaltSwitch(clock, dir.resolve("halt"), 60_000L);
        try {
            hs.start();
            hs.haltedByFrame("operator pressed stop");
            hs.resumedByFrame();
            check("the resume lifted the frame halt", !hs.halted());

            clock.advance(300_000_001L);        // the horizon, plus one microsecond
            check("and the poller dying after a resume still halts issuance", hs.halted());
            check("and it is the staleness rule that says so",
                  hs.reason() != null && hs.reason().contains("stalled"));
        } finally { hs.stop(); rmTree(dir); }
    }

    // ---- the thread ------------------------------------------------------

    /**
     * A polling thread that outlives stop() keeps stat()ing a client's
     * engagement directory after Burp thinks hx is gone.
     *
     * The interval is a full minute deliberately: a stop() that only worked
     * because the thread was about to wake anyway would pass at 10ms and hang
     * Burp's unload for a minute in production.
     */
    static void thePollerIsADaemonAndDoesNotOutliveStop() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltthread");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), dir.resolve("halt"), 60_000L);
        try {
            hs.start();
            Thread t = namedPoller();
            check("start() runs a poller", t != null && hs.pollerAlive());
            check("the poller is a daemon", t != null && t.isDaemon());

            long t0 = System.nanoTime();
            hs.stop();
            long ms = (System.nanoTime() - t0) / 1_000_000L;
            check("stop() ends the poller", !hs.pollerAlive());
            check("and the thread itself is gone", t == null || !t.isAlive());
            check("no hx-halt-sentinel thread is left behind", namedPoller() == null);
            check("and stop() does not wait out the poll interval (" + ms + "ms)", ms < 1_000L);
        } finally { hs.stop(); rmTree(dir); }
    }

    /** The other half of "does not outlive stop()": not merely a dead Thread
     *  object, but no more filesystem calls. */
    static void nothingPollsAfterStop() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltquiet");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), dir.resolve("halt"), 10L);
        try {
            hs.start();
            long start = hs.polls();
            check("the poller is polling before stop()", awaitTrue(() -> hs.polls() > start + 1));
            hs.stop();
            long after = hs.polls();
            Thread.sleep(50);                        // five poll intervals
            check("nothing polls after stop()", hs.polls() == after);
        } finally { hs.stop(); rmTree(dir); }
    }

    /**
     * Two pollers answer correctly and leak a thread, which is the kind of
     * defect that survives review.
     *
     * A minute between polls again: at 10ms an orphaned poller notices it has
     * been replaced and exits before the count is taken, so the check passes
     * against a switch that really did start two. Measured.
     */
    static void startIsIdempotent() throws Exception {
        Path dir = Files.createTempDirectory("hxhalttwice");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), dir.resolve("halt"), 60_000L);
        try {
            hs.start();
            Thread first = namedPoller();
            // Wait until the first poller is actually asleep between polls. A
            // thread that has not run its first loop check yet retires itself
            // the moment a second start() replaces it, which makes a switch
            // that really did start two look like one. Measured.
            check("the first poller is asleep between polls",
                  awaitTrue(() -> first != null && first.getState() == Thread.State.TIMED_WAITING));
            hs.start();
            check("start() twice leaves exactly one poller", pollerCount() == 1);
            hs.stop();
            check("and one stop() ends it", pollerCount() == 0);
        } finally { hs.stop(); rmTree(dir); }
    }

    static void stopIsSafeWhenNeverStartedAndNeverClearsAHalt() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltstop");
        Path sentinel = dir.resolve("halt");
        try {
            HaltSwitch never = new HaltSwitch(new TickClock(T0), sentinel, 10L);
            never.stop();                            // must not throw
            check("stop() on a switch that never started is a no-op", !never.halted());

            Files.writeString(sentinel, "");
            HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 10L);
            hs.start();
            check("halted by the sentinel", hs.halted());
            hs.stop();
            check("stop() never clears a halt", hs.halted());
            check("and the reason survives it too",
                  hs.reason() != null && hs.reason().contains("present"));
        } finally { rmTree(dir); }
    }

    static void stopThenStartPollsAgain() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltrestart");
        Path sentinel = dir.resolve("halt");
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 10L);
        try {
            hs.start();
            hs.stop();
            Files.writeString(sentinel, "");
            hs.start();
            check("a stopped switch can be started again", hs.halted() && hs.pollerAlive());
            check("and there is still only one poller", pollerCount() == 1);
        } finally { hs.stop(); rmTree(dir); }
    }

    /** Thread.sleep(0) does not sleep: it spins a core and stats the sentinel
     *  millions of times a second. */
    static void aNonPositivePollIntervalIsRefused() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltinterval");
        try {
            Path sentinel = dir.resolve("halt");
            expectThrows("a zero poll interval is refused", IllegalArgumentException.class,
                         () -> new HaltSwitch(new TickClock(T0), sentinel, 0L));
            expectThrows("a negative poll interval is refused", IllegalArgumentException.class,
                         () -> new HaltSwitch(new TickClock(T0), sentinel, -1L));
        } finally { rmTree(dir); }
    }

    /**
     * STOP_JOIN_MS is the one number the file's own comment says prevents
     * something -- "unloading the extension must not hang Burp" -- and setting
     * it to 0 left the suite green. `Thread.join(0)` waits FOREVER, so the
     * bound the comment promises had no check behind it at all.
     *
     * A poller wedged in a filesystem call on a hung mount cannot be arranged
     * in a test; a clock that blocks and swallows interrupts is the same shape
     * and can. stop() runs on its own thread here so that a stop() which never
     * returns is a failed check rather than a class with no summary line.
     */
    static void stopIsBoundedWhenThePollerCannotBeInterrupted() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltwedge");
        WedgingClock clock = new WedgingClock(T0);
        HaltSwitch hs = new HaltSwitch(clock, dir.resolve("halt"), 20L);
        try {
            hs.start();                          // start()'s own poll runs first
            clock.wedge = true;
            check("the poller is wedged where no interrupt reaches it",
                  awaitTrue(() -> clock.wedged));

            Thread stopper = new Thread(hs::stop, "hx-halt-stopper");
            stopper.setDaemon(true);
            long t0 = System.nanoTime();
            stopper.start();
            stopper.join(20_000L);
            long ms = (System.nanoTime() - t0) / 1_000_000L;
            check("stop() returns even when the poller cannot be interrupted", !stopper.isAlive());
            check("and it waits the join budget rather than forever (" + ms + "ms)",
                  ms >= 1_000L && ms < 10_000L);
        } finally {
            // Release before anything else counts threads: a wedged poller
            // outliving this check is a second hx-halt-sentinel thread for the
            // checks that count them.
            clock.release = true;
            awaitTrue(() -> namedPoller() == null);
            hs.stop(); rmTree(dir);
        }
    }

    /**
     * Three numbers chosen in §4 that no behaviour check can see.
     *
     * DEFAULT_POLL_MS is what Task 6 is told to pass rather than inventing its
     * own, so its value is an interface. STALE_INTERVALS was pinned by nothing:
     * the staleness check computed its horizon FROM the constant, so 500000 --
     * a dead poller invisible for 69 hours at the default interval -- passed
     * exactly as well as 5. That test now advances a literal, and this names
     * the numbers.
     */
    static void theConstantsAreTheNumbersThatWereChosen() throws Exception {
        check("DEFAULT_POLL_MS is the half-second the kill switch budgets",
              HaltSwitch.DEFAULT_POLL_MS == 500L);
        check("STALE_INTERVALS is five", HaltSwitch.STALE_INTERVALS == 5L);
    }

    // ---- helpers ---------------------------------------------------------

    interface Cond { boolean ok(); }

    /** Bounded: five seconds, polled every millisecond. A test that waits for
     *  a real poller must never wait forever -- a hung suite tells you nothing
     *  about which check was watching. */
    static boolean awaitTrue(Cond c) throws Exception {
        long end = System.currentTimeMillis() + 5_000L;
        while (System.currentTimeMillis() < end) {
            if (c.ok()) return true;
            Thread.sleep(1);
        }
        return c.ok();
    }

    /** One poll, on this thread, with no poller running: the sentinel's answer
     *  for a path, isolated from timing entirely. */
    static boolean haltedNow(Path sentinel) {
        HaltSwitch hs = new HaltSwitch(new TickClock(T0), sentinel, 60_000L);
        hs.pollOnce();
        return hs.halted();
    }

    static boolean canStillRead(Path p) {
        try {
            Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    static Thread namedPoller() {
        for (Thread t : Thread.getAllStackTraces().keySet())
            if ("hx-halt-sentinel".equals(t.getName()) && t.isAlive()) return t;
        return null;
    }

    static int pollerCount() {
        int n = 0;
        for (Thread t : Thread.getAllStackTraces().keySet())
            if ("hx-halt-sentinel".equals(t.getName()) && t.isAlive()) n++;
        return n;
    }

    /** A clock that throws on demand. The Clock is injected, so it is someone
     *  else's code, and this is what "someone else's code stopped working"
     *  looks like from in here. */
    static final class BreakableClock implements Clock {
        private final long us;
        volatile boolean broken;
        BreakableClock(long us) { this.us = us; }
        public long nowUs() {
            if (broken) throw new IllegalStateException("this clock is gone");
            return us;
        }
    }

    /** A clock that blocks on demand and does NOT come back for an interrupt:
     *  the poller wedged in a call that cannot be cancelled from inside the
     *  JVM, which is what the bounded join in stop() exists for. */
    static final class WedgingClock implements Clock {
        private final long us;
        volatile boolean wedge;
        volatile boolean wedged;
        volatile boolean release;
        WedgingClock(long us) { this.us = us; }
        public long nowUs() {
            if (wedge) {
                wedged = true;
                // A backstop, so a check that forgets to release it fails
                // rather than hanging the class; test.sh's timeout is blunter.
                long end = System.currentTimeMillis() + 60_000L;
                while (!release && System.currentTimeMillis() < end) {
                    // Swallowed on purpose: being interruptible is exactly
                    // what a wedged poller is not.
                    try { Thread.sleep(5L); } catch (InterruptedException e) { }
                }
            }
            return us;
        }
    }

    static void rmTree(Path p) throws Exception {
        if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS))
            try (var kids = Files.newDirectoryStream(p)) {
                for (Path kid : kids) rmTree(kid);
            }
        Files.deleteIfExists(p);
    }
}
