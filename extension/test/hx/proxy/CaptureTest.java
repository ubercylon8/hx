// extension/test/hx/proxy/CaptureTest.java
package hx.proxy;

import hx.TestSupport;

import java.util.*;
import java.util.concurrent.*;

/**
 * The queue, and specifically the two things it must never do: block the
 * caller, and lose a record silently.
 *
 * Hand-rolled runner, like the other ten classes: JUnit would be a dependency,
 * and this jar has none.
 */
public class CaptureTest {

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
        TestSupport.t(CaptureTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("an offer reaches the sink", CaptureTest::anOfferReachesTheSink);
        t("offering never blocks, even with no sink draining",
          CaptureTest::offeringNeverBlocks);
        t("a full queue drops the OLDEST, not the newest",
          CaptureTest::aFullQueueDropsTheOldest);
        t("and every drop is counted", CaptureTest::everyDropIsCounted);
        t("and reported, not merely counted", CaptureTest::dropsAreReported);
        t("a drop is reported even when nothing follows it",
          CaptureTest::dropsAreReportedWithNothingBehindThem);
        t("each source's drops are reported against that source",
          CaptureTest::dropsAreReportedPerSource);
        t("a source with no spelling is refused, not filed as the operator",
          CaptureTest::anUnattributedRecordIsRefusedAndCounted);
        t("the header says what the harness reads",
          CaptureTest::theHeaderCarriesWhatTheConsumerReads);
        t("a sink that throws does not kill the drain thread",
          CaptureTest::aThrowingSinkDoesNotKillTheDrain);
        t("a drop report that throws does not kill it either",
          CaptureTest::aThrowingDropReportDoesNotKillTheDrain);
        t("the drain thread is a daemon", CaptureTest::theDrainIsADaemon);
        t("stop() does not hang on a wedged sink", CaptureTest::stopDoesNotHang);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures -------------------------------------------------------

    static Observed obs(int n) {
        return obs(n, Source.OPERATOR);
    }

    static Observed obs(int n, Source s) {
        return new Observed("GET", "http://app.test/" + n, 200, 5L,
                            ("req" + n).getBytes(), ("resp" + n).getBytes(), s);
    }

    static final class Recording implements Capture.ExchangeSink {
        final List<String> seen = Collections.synchronizedList(new ArrayList<>());
        final List<Long> drops = Collections.synchronizedList(new ArrayList<>());
        final List<Source> dropSources =
                Collections.synchronizedList(new ArrayList<>());
        final List<Map<String, Object>> headers =
                Collections.synchronizedList(new ArrayList<>());
        volatile CountDownLatch gate;
        volatile boolean throwOnce;
        volatile boolean throwOnDropOnce;

        public void exchange(Map<String, Object> h, byte[] req, byte[] resp) {
            if (gate != null) { try { gate.await(); } catch (InterruptedException e) { return; } }
            if (throwOnce) { throwOnce = false; throw new RuntimeException("sink"); }
            headers.add(new LinkedHashMap<>(h));
            seen.add(String.valueOf(h.get("url")));
        }

        public void dropped(long n, Source s) {
            if (throwOnDropOnce) { throwOnDropOnce = false; throw new RuntimeException("drop"); }
            // Both lists appended under ONE monitor, and read back under the
            // same one: `reported()` pairs them by index, and two independent
            // synchronized lists let a reader see a count whose source has not
            // landed yet.
            synchronized (drops) {
                drops.add(n);
                dropSources.add(s);
            }
        }
    }

    /**
     * How long an offer gets before it is called blocked.
     *
     * EVERY offer in this class goes through {@link #offerAll}, and that is
     * the third truncation TestSupport.t's docstring names, met head on. An
     * offer that BLOCKS parks its test method forever: the class prints no
     * summary line at all, returns no exit code, and test.sh's `timeout 300`
     * kills it from outside -- which under `./test.sh | grep -c FAIL` reads
     * as ZERO FAILURES. Measured on this file: replacing the eviction loop
     * with `queue.put(o)` -- the mutation "offer blocks instead of evicting",
     * the ONE rule this class exists for -- took the suite from eleven
     * summary lines to TEN, with no FAIL line anywhere and every method after
     * the first blocking offer unrun. A guard that can only be observed by
     * counting summary lines is a guard one careless `grep` walks past.
     *
     * Five seconds: five times the 1 s bound offeringNeverBlocks asserts, so
     * it can only fire on a genuine block, and small enough that six of them
     * in a row stay well inside test.sh's 300 s backstop.
     */
    static final long OFFER_DEADLINE_MS = 5000L;

    /**
     * Offer, with a deadline on it. Throws rather than checks: a throw out of
     * a test method becomes a NAMED FAIL against that method through
     * {@link hx.TestSupport#t}, which is what the truncation above cost.
     *
     * The offering thread is a DAEMON and is deliberately left parked when the
     * deadline expires. Interrupting it would work -- `put` is interruptible --
     * and would hide the very thing being reported: the next assertion in the
     * test method would then run against a queue the mutant had quietly
     * finished filling. A leaked parked daemon costs nothing, because a daemon
     * cannot hold the JVM up after main() prints its summary.
     */
    static void offerAll(Capture c, Observed... records) throws Exception {
        Thread th = new Thread(() -> { for (Observed o : records) c.offer(o); });
        th.setDaemon(true);
        th.start();
        th.join(OFFER_DEADLINE_MS);
        if (th.isAlive())
            throw new AssertionError(
                "offer() had not returned after " + OFFER_DEADLINE_MS
                + " ms, so it BLOCKED -- the one thing this class exists to "
                + "forbid, because the caller is the request path of a real "
                + "person's browser");
    }

    /** `offerAll` over obs(0)..obs(n-1). */
    static void offerRange(Capture c, int n) throws Exception {
        Observed[] all = new Observed[n];
        for (int i = 0; i < n; i++) all[i] = obs(i);
        offerAll(c, all);
    }

    interface Cond { boolean ok(); }

    /** Five seconds, the same bound BridgeClientTest.waitUntil carries. Every
     *  wait here is for a DAEMON drain thread, so a condition that never
     *  becomes true would otherwise park this method until test.sh's 300 s
     *  backstop killed the class with no summary line printed -- which under
     *  `grep -c FAIL` reads as zero failures. */
    static void waitUntil(Cond c) throws Exception {
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            if (c.ok()) return;
            Thread.sleep(10);
        }
    }

    /** Everything the sink was told was dropped, for one source. */
    static long reported(Recording sink, Source s) {
        long total = 0;
        synchronized (sink.drops) {
            for (int i = 0; i < sink.drops.size(); i++)
                if (sink.dropSources.get(i) == s) total += sink.drops.get(i);
        }
        return total;
    }

    /** The live drain, found by the name {@link Capture#start} gives it. */
    static Thread drainThread() {
        for (Thread th : Thread.getAllStackTraces().keySet())
            if ("hx-capture".equals(th.getName())) return th;
        return null;
    }

    // ---- the tests ------------------------------------------------------

    static void anOfferReachesTheSink() throws Exception {
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1));
            waitUntil(() -> sink.seen.size() == 1);
            check("the sink saw it", sink.seen.contains("http://app.test/1"));
        } finally { c.stop(); }
    }

    static void offeringNeverBlocks() throws Exception {
        // No drain thread at all: offer must still return promptly. This is
        // the property the operator's browser depends on.
        Capture c = new Capture(4, new Recording());
        long start = System.nanoTime();
        offerRange(c, 1000);
        long ms = (System.nanoTime() - start) / 1_000_000;
        check("1000 offers with nothing draining took " + ms + " ms", ms < 1000);
    }

    static void aFullQueueDropsTheOldest() throws Exception {
        // EVERY offer happens before the drain exists, and that is not
        // tidiness. Started first, the drain takes the head of the queue into
        // a wedged sink BEFORE the overflow begins, so the oldest record is
        // already out of the queue, is delivered when the sink unwedges, and
        // "the oldest did not survive" fails against correct code roughly one
        // run in three -- measured on this file. A test whose result depends
        // on which thread wins is a test that cannot say what eviction order
        // the queue has.
        Recording sink = new Recording();
        Capture c = new Capture(2, sink);
        offerRange(c, 6);
        c.start();
        try {
            waitUntil(() -> sink.seen.size() >= 2);
            Thread.sleep(50);
            // The NEWEST survive. Oldest-first is the right eviction for
            // traffic: the recent requests are the ones an operator is
            // looking at, and the old ones are the ones already reasoned
            // about.
            check("exactly the queue's worth survived (" + sink.seen + ")",
                  sink.seen.size() == 2);
            check("the newest survived (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/5"));
            check("and the one before it", sink.seen.contains("http://app.test/4"));
            check("and the oldest did not",
                  !sink.seen.contains("http://app.test/0"));
        } finally { c.stop(); }
    }

    static void everyDropIsCounted() throws Exception {
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(2, sink);
        try {
            offerRange(c, 10);
            check("dropped() counts them (" + c.dropped() + ")", c.dropped() > 0);
        } finally { sink.gate.countDown(); c.stop(); }
    }

    static void dropsAreReported() throws Exception {
        // Counted is not enough: S5 says a run with drops has coverage
        // numbers that are a floor, and nothing on the Python side can know
        // that unless the number crosses the bridge.
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(2, sink);
        c.start();
        try {
            offerRange(c, 10);
            sink.gate.countDown();
            waitUntil(() -> !sink.drops.isEmpty());
            check("the sink was told (" + sink.drops + ")", !sink.drops.isEmpty());
            long total = 0;
            for (Long n : sink.drops) total += n;
            check("and told the whole count, not a token one (" + total
                  + " reported, " + c.dropped() + " counted)",
                  total == c.dropped());
        } finally { c.stop(); }
    }

    static void dropsAreReportedWithNothingBehindThem() throws Exception {
        // THE INPUT THAT SEPARATES `poll(POLL_MS)` FROM `take()`, and finding
        // it took a measurement that came out the wrong way. The obvious
        // version -- overflow a queue, let the drain empty it, assert the
        // report arrived -- separates NOTHING: an EVICTION always leaves the
        // evicting record in the queue behind it, so a take()-parked drain is
        // woken by that record and reports on its way past. Measured: with
        // `take()` in place of the poll, that version stayed green.
        //
        // The refusal path is different in exactly the way that matters. An
        // unattributed record is counted and NOT enqueued, so a drop can be
        // the last thing that ever happens -- and a take()-parked drain then
        // sleeps on it forever. Which is the moment the report is most needed:
        // a saturated harness is what makes an operator stop browsing, and
        // "traffic stopped" is precisely "no record behind it".
        Recording sink = new Recording();
        Capture c = new Capture(4, sink);
        c.start();
        try {
            // Drain the queue first, so the drain is parked and idle.
            offerAll(c, obs(1));
            waitUntil(() -> sink.seen.size() == 1);
            check("the drain is idle with an empty queue", sink.seen.size() == 1);

            offerAll(c, obs(2, Source.UNATTRIBUTED));
            waitUntil(() -> !sink.drops.isEmpty());
            long total = 0;
            for (Long n : sink.drops) total += n;
            check("the drop was reported with nothing following it ("
                  + sink.drops + ")", total == 1);

            // And the eviction path reports too -- behaviour, not a separator:
            // this half stays green under `take()`, and is kept as a pin on
            // the answer rather than dressed up as more than it is.
            offerAll(c, obs(3), obs(4), obs(5), obs(6), obs(7), obs(8));
            waitUntil(() -> c.dropped() > 1 && reported(sink, Source.OPERATOR) > 0);
            check("and an evicted record's drop is reported as well ("
                  + sink.drops + ")", reported(sink, Source.OPERATOR) > 0);
        } finally { c.stop(); }
    }

    static void dropsAreReportedPerSource() throws Exception {
        // One counter with one source attached would file the crawler's drops
        // against whichever source happened to be reported -- and the far side
        // turns that string into a run KIND, so the wrong run's coverage is
        // the number an operator reads.
        Recording sink = new Recording();
        Capture c = new Capture(2, sink);
        // Offered before the drain exists, for the same reason as
        // aFullQueueDropsTheOldest: a drain that takes records while the
        // offers run changes WHICH source each eviction charges.
        offerAll(c, obs(0, Source.OPERATOR), obs(1, Source.OPERATOR),
                 obs(2, Source.OPERATOR), obs(3, Source.OPERATOR),
                 obs(4, Source.OPERATOR));
        offerAll(c, obs(0, Source.CRAWLER), obs(1, Source.CRAWLER),
                 obs(2, Source.CRAWLER), obs(3, Source.CRAWLER),
                 obs(4, Source.CRAWLER));
        // Ten offers into a queue of two: five of the operator's records are
        // evicted (three by later operator records, two by the crawler's
        // first two) and three of the crawler's.
        check("eight records were evicted in all (" + c.dropped() + ")",
              c.dropped() == 8);
        c.start();
        try {
            waitUntil(() -> sink.dropSources.contains(Source.OPERATOR)
                            && sink.dropSources.contains(Source.CRAWLER));
            check("the operator's five were reported against the operator ("
                  + reported(sink, Source.OPERATOR) + ")",
                  reported(sink, Source.OPERATOR) == 5);
            check("and the crawler's three against the crawler ("
                  + reported(sink, Source.CRAWLER) + ")",
                  reported(sink, Source.CRAWLER) == 3);
        } finally { c.stop(); }
    }

    static void anUnattributedRecordIsRefusedAndCounted() throws Exception {
        // ProxyGate refuses UNATTRIBUTED, so one should never reach here. If
        // one does it must not become an exchange row: `hx.capture._run` reads
        // "crawler" or anything-else, so any string this could emit files the
        // record under the operator's run -- traffic attributed to a human who
        // did not make it, and a request that never left in the first place.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1, Source.UNATTRIBUTED), obs(2, Source.OPERATOR));
            waitUntil(() -> sink.seen.size() == 1);
            Thread.sleep(50);
            check("the attributed record arrived (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/2"));
            check("and the unattributed one did not",
                  !sink.seen.contains("http://app.test/1"));
            waitUntil(() -> !sink.drops.isEmpty());
            check("refused is not discarded: it was counted (" + c.dropped() + ")",
                  c.dropped() == 1);
            check("and reported as UNATTRIBUTED, not as the operator ("
                  + sink.dropSources + ")",
                  sink.dropSources.contains(Source.UNATTRIBUTED)
                  && !sink.dropSources.contains(Source.OPERATOR));
            check("and sourceName has no spelling for it",
                  Capture.sourceName(Source.UNATTRIBUTED) == null);
        } finally { c.stop(); }
    }

    static void theHeaderCarriesWhatTheConsumerReads() throws Exception {
        // hx/capture.py's EXCHANGE path reads these keys, and REFUSES an unknown `t`,
        // an unknown `via`, an unknown `outcome`, a missing `url` and a
        // non-integer `ms`. A header this side gets wrong is not a wrong row:
        // it is a ValueError on the read thread and no row at all.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, new Observed("POST", "http://app.test/login", 302, 41L,
                                     "req".getBytes(), "resp".getBytes(),
                                     Source.CRAWLER));
            waitUntil(() -> sink.headers.size() == 1);
            Map<String, Object> h = sink.headers.get(0);
            check("t is the frame type hx.capture.FRAME_TYPES names ("
                  + h.get("t") + ")", "exchange".equals(h.get("t")));
            check("via is one of records.VIA_VALUES (" + h.get("via") + ")",
                  "proxy".equals(h.get("via")));
            check("source is the crawler's spelling (" + h.get("source") + ")",
                  "crawler".equals(h.get("source")));
            check("method survives (" + h.get("method") + ")",
                  "POST".equals(h.get("method")));
            check("url survives, and it has no default on the far side ("
                  + h.get("url") + ")",
                  "http://app.test/login".equals(h.get("url")));
            check("status is an integer, not a string (" + h.get("status") + ")",
                  Long.valueOf(302L).equals(h.get("status")));
            check("ms is an integer, not a string (" + h.get("ms") + ")",
                  Long.valueOf(41L).equals(h.get("ms")));
            check("outcome is in records.EXCHANGE_OUTCOMES (" + h.get("outcome") + ")",
                  "ok".equals(h.get("outcome")));
        } finally { c.stop(); }
    }

    static void aThrowingSinkDoesNotKillTheDrain() throws Exception {
        Recording sink = new Recording();
        sink.throwOnce = true;
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1), obs(2));
            waitUntil(() -> sink.seen.size() == 1);
            check("the record after the throw still arrived (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/2"));
        } finally { c.stop(); }
    }

    static void aThrowingDropReportDoesNotKillTheDrain() throws Exception {
        // The drop report is the other call into someone else's code, and a
        // throw out of it used to be the same fatality. The count is
        // cumulative, so the retry has to carry the whole outstanding total
        // rather than only what accrued since.
        Recording sink = new Recording();
        sink.throwOnDropOnce = true;
        Capture c = new Capture(1, sink);
        offerRange(c, 4);                             // 3 dropped
        c.start();
        try {
            waitUntil(() -> !sink.drops.isEmpty());
            long total = 0;
            for (Long n : sink.drops) total += n;
            check("the failed report was retried in full (" + sink.drops + ")",
                  total == 3);
            offerAll(c, obs(9));
            waitUntil(() -> sink.seen.contains("http://app.test/9"));
            check("and the drain is still delivering exchanges (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/9"));
        } finally { c.stop(); }
    }

    static void theDrainIsADaemon() throws Exception {
        // A non-daemon drain holds the JVM -- and inside Burp that is an
        // unloaded extension keeping the process alive on a thread nobody can
        // see. stop() is the polite path; this is what happens when it is not
        // reached, which is every crash and every hard unload.
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);   // never released: the drain is wedged
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1));
            waitUntil(() -> drainThread() != null);
            Thread found = drainThread();
            check("the drain thread exists and is named", found != null);
            check("and it is a daemon", found != null && found.isDaemon());
        } finally { sink.gate.countDown(); c.stop(); }
    }

    static void stopDoesNotHang() throws Exception {
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);   // never released
        Capture c = new Capture(8, sink);
        c.start();
        offerAll(c, obs(1));
        // The drain has to be INSIDE the wedged sink before stop() is called.
        // Without this the queue may still be undrained, stop() returns in
        // microseconds, and the check passes against a drain that was never
        // wedged at all -- a green that measures the scheduler.
        waitUntil(() -> {
            Thread d = drainThread();
            // WAITING and not TIMED_WAITING: an untaken record leaves the
            // drain in `queue.poll(POLL_MS, ...)`, which is TIMED_WAITING.
            // Only the wedged sink's `gate.await()` is WAITING.
            return d != null && d.getState() == Thread.State.WAITING;
        });
        long start = System.nanoTime();
        c.stop();
        long ms = (System.nanoTime() - start) / 1_000_000;
        // Unloading the extension must not hang Burp. Same bound and same
        // reason as HaltSwitch.STOP_JOIN_MS.
        check("stop() returned in " + ms + " ms", ms < 4000);
    }
}
