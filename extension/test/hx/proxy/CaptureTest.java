// extension/test/hx/proxy/CaptureTest.java
package hx.proxy;

import hx.TestSupport;
import hx.bridge.BridgeClient;

import java.util.*;
import java.util.concurrent.*;

/**
 * The queue, and specifically the two things it must never do: block the
 * caller, and lose a record silently.
 *
 * Hand-rolled runner, like the other eleven classes: JUnit would be a
 * dependency, and this jar has none.
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
        t("the outcome comes from the record, not from a literal",
          CaptureTest::theOutcomeComesFromTheRecord);
        t("a sink that throws does not kill the drain thread",
          CaptureTest::aThrowingSinkDoesNotKillTheDrain);
        t("a drop report that throws does not kill it either",
          CaptureTest::aThrowingDropReportDoesNotKillTheDrain);
        t("the drain thread is a daemon", CaptureTest::theDrainIsADaemon);
        t("stop() does not hang on a wedged sink, and ends the drain",
          CaptureTest::stopDoesNotHang);
        t("stop() counts and reports what it throws away",
          CaptureTest::stopFlushesWhatItThrowsAway);
        t("an offer after stop() is counted, not swallowed",
          CaptureTest::offerAfterStopIsCountedNotSwallowed);
        t("offers racing stop() are every one of them accounted for",
          CaptureTest::offersRacingStopAreAllAccountedFor);
        t("stop() then start() does not re-report the cumulative count",
          CaptureTest::stopThenStartDoesNotReReportTheCount);
        t("start() twice leaves one drain and one report",
          CaptureTest::startTwiceLeavesOneDrain);
        t("an exchange the sink would not take is a drop",
          CaptureTest::anUndeliveredExchangeIsCountedAsADrop);
        t("a drop report that answers 'not delivered' is retried in full",
          CaptureTest::aDropReportThatSaysNotDeliveredIsRetriedInFull);
        t("a denial is a frame of its own, with the keys the consumer reads",
          CaptureTest::aDenialIsItsOwnFrame);
        t("a denial the sink would not take is a drop against ITS source",
          CaptureTest::anUndeliveredDenialIsCountedAgainstItsOwnSource);
        t("a denial with no spelling is refused, like an exchange with none",
          CaptureTest::aDeniedRecordWithNoSpellingIsRefusedTheSameWay);
        t("countLost is charged to the source it is given",
          CaptureTest::countLostIsChargedToTheSourceItIsGiven);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures -------------------------------------------------------

    static Observed obs(int n) {
        return obs(n, Source.OPERATOR);
    }

    static Observed obs(int n, Source s) {
        return new Observed("GET", "http://app.test/" + n, 200, "ok", 5L,
                            ("req" + n).getBytes(), ("resp" + n).getBytes(), s);
    }

    /** One refused request, as the proxy handler offers it. */
    static Denied den(int n, Source s) {
        return new Denied("POST", "http://app.test/refused/" + n,
                          "scope_denied", "detail " + n, s);
    }

    static final class Recording implements BridgeClient.ExchangeSink {
        final List<String> seen = Collections.synchronizedList(new ArrayList<>());
        final List<Long> drops = Collections.synchronizedList(new ArrayList<>());
        final List<String> dropSources =
                Collections.synchronizedList(new ArrayList<>());
        final List<Map<String, Object>> headers =
                Collections.synchronizedList(new ArrayList<>());
        /** Denial frames, kept apart from {@link #headers} so a denial routed
         *  through `exchange(...)` -- the naming lie this interface's third
         *  method exists to prevent -- cannot satisfy a check about denials. */
        final List<Map<String, Object>> denials =
                Collections.synchronizedList(new ArrayList<>());
        volatile CountDownLatch gate;
        volatile boolean throwOnce;
        volatile boolean throwOnDropOnce;
        volatile boolean refuseDenial;
        /** RETURN false rather than throw -- the production sink's shape.
         *  BridgeClient.exchangeSink catches its own IOException, so "the
         *  sink threw" is the case that never happens on the wire and "the
         *  sink returned without delivering" is the case that always does. */
        volatile boolean refuseExchange;
        volatile boolean refuseDropOnce;

        public boolean exchange(Map<String, Object> h, byte[] req, byte[] resp) {
            if (gate != null) { try { gate.await(); } catch (InterruptedException e) { return false; } }
            if (throwOnce) { throwOnce = false; throw new RuntimeException("sink"); }
            if (refuseExchange) return false;
            headers.add(new LinkedHashMap<>(h));
            seen.add(String.valueOf(h.get("url")));
            return true;
        }

        public boolean dropped(long n, String s) {
            if (throwOnDropOnce) { throwOnDropOnce = false; throw new RuntimeException("drop"); }
            if (refuseDropOnce) { refuseDropOnce = false; return false; }
            // Both lists appended under ONE monitor, and read back under the
            // same one: `reported()` pairs them by index, and two independent
            // synchronized lists let a reader see a count whose source has not
            // landed yet.
            synchronized (drops) {
                drops.add(n);
                dropSources.add(s);
            }
            return true;
        }

        public boolean denial(Map<String, Object> h) {
            if (refuseDenial) return false;
            denials.add(new LinkedHashMap<>(h));
            return true;
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
    static void offerAll(Capture c, Captured... records) throws Exception {
        Thread th = new Thread(() -> { for (Captured o : records) c.offer(o); });
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

    /** Everything the sink was told was dropped, for one source -- named by
     *  the spelling that crosses the bridge, `null` for a source that has
     *  none. */
    static long reported(Recording sink, String s) {
        long total = 0;
        synchronized (sink.drops) {
            for (int i = 0; i < sink.drops.size(); i++)
                if (Objects.equals(sink.dropSources.get(i), s))
                    total += sink.drops.get(i);
        }
        return total;
    }

    /** Everything the sink was told was dropped, whatever the source. */
    static long reportedTotal(Recording sink) {
        long total = 0;
        synchronized (sink.drops) {
            for (Long n : sink.drops) total += n;
        }
        return total;
    }

    /**
     * The live drain, found by the name {@link Capture#start} gives it.
     *
     * BY NAME, so it cannot tell a leaked drain from the live one -- which is
     * why every assertion about a STOPPED drain below is made against a
     * captured thread's IDENTITY (`!found.isAlive()`) and not against this.
     * A test that leaks a wedged daemon hands the next one a thread that
     * answers here; `stopDoesNotHang` used to be that test.
     */
    static Thread drainThread() {
        for (Thread th : Thread.getAllStackTraces().keySet())
            if ("hx-capture".equals(th.getName())) return th;
        return null;
    }

    /** How many live threads carry that name. One is correct; two is a leak,
     *  and drainThread() above cannot tell the difference. */
    static int drainCount() {
        int n = 0;
        for (Thread th : Thread.getAllStackTraces().keySet())
            if ("hx-capture".equals(th.getName()) && th.isAlive()) n++;
        return n;
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
            waitUntil(() -> c.dropped() > 1 && reported(sink, "operator") > 0);
            check("and an evicted record's drop is reported as well ("
                  + sink.drops + ")", reported(sink, "operator") > 0);
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
            waitUntil(() -> sink.dropSources.contains("operator")
                            && sink.dropSources.contains("crawler"));
            check("the operator's five were reported against the operator ("
                  + reported(sink, "operator") + ")",
                  reported(sink, "operator") == 5);
            check("and the crawler's three against the crawler ("
                  + reported(sink, "crawler") + ")",
                  reported(sink, "crawler") == 3);
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
            // A NULL source, not the operator's spelling. The sink now takes a
            // String, so "no spelling" travels as null -- and null must not
            // become "operator" on this side of the interface any more than it
            // was allowed to on the other.
            check("and reported with NO spelling, not as the operator ("
                  + sink.dropSources + ")",
                  sink.dropSources.contains(null)
                  && !sink.dropSources.contains("operator"));
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
            offerAll(c, new Observed("POST", "http://app.test/login", 302, "ok",
                                     41L, "req".getBytes(), "resp".getBytes(),
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

    /**
     * THE OUTCOME IS THE RECORD'S, NOT A LITERAL THIS CLASS WRITES.
     *
     * `deliverExchange` hardcoded `h.put("outcome", "ok")` -- the ONLY
     * `outcome` write on the whole proxy path -- so every proxy exchange was
     * filed healthy whatever its bytes said. The method above cannot see that:
     * its fixture is a healthy 302, so `"ok"` is the right answer for the
     * wrong reason and a hardcoded literal passes it.
     *
     * THE SEPARATING INPUT IS AN UNHEALTHY RECORD, and it is S5's shape:
     * `status=599` with `outcome='status_unreadable'`, which is what
     * {@link Recorder} produces for a `103 Early Hints` in front of a dead
     * origin. With the literal back, this method reads `ok` on a 599 -- the
     * pair `record_exchange`'s coherence guard exists to refuse, and the pair
     * that hands S4's auto-halt a healthy sample for a failing request.
     *
     * The 599 goes on `status` too, so the two travel as one answer: S5 makes
     * `status_unreadable` legal only beside 599, and a row carrying one
     * without the other is refused on the far side rather than written wrong.
     *
     * WHAT THIS DOES NOT PIN: that the SCAN is right, or that it runs. This
     * class builds the record by hand.
     * `RecorderTest.theStatusIsScannedOutOfTheBytesWithItsOutcome` drives the
     * scan over real bytes; between them the answer is computed from the bytes
     * and carried to the wire unchanged.
     */
    static void theOutcomeComesFromTheRecord() throws Exception {
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, new Observed("GET", "http://app.test/slow", 599,
                                     "status_unreadable", 12L,
                                     "req".getBytes(), "resp".getBytes(),
                                     Source.OPERATOR));
            waitUntil(() -> sink.headers.size() == 1);
            Map<String, Object> h = sink.headers.get(0);
            check("an unreadable exchange is NOT filed as healthy ("
                  + h.get("outcome") + ")",
                  "status_unreadable".equals(h.get("outcome")));
            check("and it carries the sentinel S5 pairs that outcome with ("
                  + h.get("status") + ")",
                  Long.valueOf(599L).equals(h.get("status")));
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
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(8, sink);
        c.start();
        Thread found;
        try {
            offerAll(c, obs(1));
            // The drain has to be INSIDE the wedged sink before stop() is
            // called. Without this the queue may still be undrained, stop()
            // returns in microseconds, and the check passes against a drain
            // that was never wedged at all -- a green that measures the
            // scheduler.
            waitUntil(() -> {
                Thread d = drainThread();
                // WAITING and not TIMED_WAITING: an untaken record leaves the
                // drain in `queue.poll(POLL_MS, ...)`, which is TIMED_WAITING.
                // Only the wedged sink's `gate.await()` is WAITING.
                return d != null && d.getState() == Thread.State.WAITING;
            });
            found = drainThread();
            long start = System.nanoTime();
            c.stop();
            long ms = (System.nanoTime() - start) / 1_000_000;
            // Unloading the extension must not hang Burp. Same bound and same
            // reason as HaltSwitch.STOP_JOIN_MS.
            check("stop() returned in " + ms + " ms", ms < 4000);
            // AND THE DRAIN IS GONE, which is the half `ms < 4000` cannot see:
            // `join(STOP_JOIN_MS)` returns after two seconds whether or not
            // the thread ever died, so deleting `t.interrupt()` from stop()
            // left this class fully green -- 11 ALL PASS, 0 FAIL -- with one
            // live `hx-capture` daemon per call, each polling a queue and
            // calling into a torn-down BridgeClient. Inside Burp that is one
            // per extension reload. Asserted on the CAPTURED thread rather
            // than on drainThread(), which matches by name and so cannot tell
            // a leak from the live one.
            check("...and the drain thread is actually gone",
                  found != null && !found.isAlive());
        } finally {
            // RELEASED, unlike the version this replaced. A gate left closed
            // leaks a wedged daemon named `hx-capture` into every test that
            // runs after it.
            sink.gate.countDown();
            c.stop();
        }
    }

    // ---- what stop() throws away, and what a restart re-reports ----------

    static void stopFlushesWhatItThrowsAway() throws Exception {
        // MEASURED on the version this replaces: 200 records queued into a
        // 512-slot Capture behind a slow sink, then stop() -- delivered=0,
        // dropped()=0, reports=[]. Two hundred exchanges lost and counted as
        // ZERO, on every extension unload and at the end of every run, with
        // run.dropped_total still reading 0. S5 makes that number the reason
        // a run's coverage is a floor; a floor of zero is a claim of
        // completeness.
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);   // the drain wedges on record 1
        Capture c = new Capture(512, sink);
        c.start();
        try {
            offerRange(c, 200);
            // The drain has to be inside the wedged sink, or stop() may find
            // an empty queue and this measures nothing.
            waitUntil(() -> {
                Thread d = drainThread();
                return d != null && d.getState() == Thread.State.WAITING;
            });
            sink.gate.countDown();           // let stop()'s interrupt through
            c.stop();
            // THE PROPERTY, not the ordering. `c.dropped() == 200` was stable
            // over forty sequential and twenty-four eight-way-parallel runs,
            // and it still rests on stop()'s interrupt beating the
            // gate.countDown() two lines up: lose that race and record 1 is
            // DELIVERED instead, giving 199 counted of 200 with nothing at all
            // wrong. What has to hold on both sides of it is that no record is
            // NEITHER delivered nor counted -- and that at least one was
            // counted, because an empty queue here would mean this test
            // measured nothing.
            check("every queued record was counted or delivered, none lost ("
                  + sink.seen.size() + " delivered + " + c.dropped()
                  + " counted, of 200)",
                  sink.seen.size() + c.dropped() == 200 && c.dropped() >= 1);
            check("and the count crossed the sink (" + reportedTotal(sink)
                  + " reported, " + c.dropped() + " counted)",
                  reportedTotal(sink) == c.dropped());
        } finally { sink.gate.countDown(); c.stop(); }
    }

    static void offerAfterStopIsCountedNotSwallowed() throws Exception {
        // MEASURED on the version this replaces: stop(); offer(one record);
        // -- delivered=0, dropped()=0, reports=[]. offer() was gated on
        // nothing, so the record went into a queue with no drain behind it and
        // stayed there, counted nowhere.
        //
        // Not a corner case. Burp unloads the extension while proxy threads
        // are still inside offer(), so those exchanges are lost AND
        // run.dropped_total does not move -- S5's floor reading LOWER than the
        // real loss, which is the one direction the counter exists to close.
        Recording sink = new Recording();
        Capture c = new Capture(512, sink);
        c.start();
        c.stop();
        c.offer(obs(1));
        check("a record offered after stop() is counted (" + c.dropped()
              + " of 1)", c.dropped() == 1);
        check("...and was not delivered behind the operator's back (" + sink.seen + ")",
              sink.seen.isEmpty());
        // Nothing drains after stop(), so the count leaves on the NEXT stop().
        // That is what "idempotent" means here and it is not "a no-op": a
        // second call is how a loss during the unload reaches the far side.
        c.stop();
        check("...and the next stop() carries it across the sink ("
              + reportedTotal(sink) + " reported against " + c.dropped()
              + " counted)", reportedTotal(sink) == c.dropped());
    }

    static void offersRacingStopAreAllAccountedFor() throws Exception {
        // The shape above with the timing it actually has: Burp calls stop()
        // while proxy threads are INSIDE offer(). Nothing here pins which side
        // of the race any one record lands on -- that is the point. What is
        // pinned is the invariant that has to hold on both sides: every record
        // offered either reached the sink or was counted as a drop, and never
        // neither. Before the fix a record could be neither.
        Recording sink = new Recording();
        Capture c = new Capture(512, sink);
        c.start();
        int threads = 4, each = 200;
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> offerers = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int base = i * each;
            Thread w = new Thread(() -> {
                // Bounded, and a DAEMON: a worker that never releases would
                // hold the JVM open after this class printed ALL PASS.
                try {
                    if (!go.await(5000, TimeUnit.MILLISECONDS)) return;
                } catch (InterruptedException e) { return; }
                for (int n = 0; n < each; n++) {
                    c.offer(obs(base + n));
                    // PACED, so the offers straddle stop() instead of all
                    // landing before it. Unpaced, 800 offers are microseconds
                    // of work and finish inside the 10 ms waitUntil poll
                    // below -- and the test then passes on a Capture with the
                    // bug, which is a green measuring the scheduler.
                    try { Thread.sleep(1); } catch (InterruptedException e) { return; }
                }
            });
            w.setDaemon(true);
            offerers.add(w);
            w.start();
        }
        try {
            go.countDown();
            // stop() has to land WHILE they are still offering, or this
            // measures a scheduler that happened to finish first: 800 offers
            // is several times what one drain empties in the time stop() takes,
            // and one delivered record proves the offerers are running.
            waitUntil(() -> !sink.seen.isEmpty());
            c.stop();
            for (Thread w : offerers)
                TestSupport.join(w, 5000, "a proxy thread inside offer()");
            // NO second stop() before the check. A second stop() drains the
            // queue and counts it, so it makes this pass on a Capture that
            // strands every post-stop offer -- measured, 11 ALL PASS with the
            // bug still in. The accounting asserted here has to have been done
            // by offer() itself.
            int total = threads * each;
            check("every record offered across a stop() is delivered or counted"
                  + " (" + sink.seen.size() + " delivered + " + c.dropped()
                  + " dropped, of " + total + ")",
                  sink.seen.size() + c.dropped() == total);
        } finally { c.stop(); }
    }

    static void stopThenStartDoesNotReReportTheCount() throws Exception {
        // `reported[]` was a LOCAL in loop() and `dropped[]` a field, so every
        // restart re-reported the whole cumulative total from zero. Measured:
        // 3 real drops -> [3]; stop(); start(); -> [3, 3], SIX reported
        // against three that happened. `count_drop` accumulates and only
        // refuses n < 1, so the Python side cannot catch it: run.dropped_total
        // inflates without bound across reconnects.
        Recording sink = new Recording();
        Capture c = new Capture(1, sink);
        offerRange(c, 4);                              // 3 evicted
        c.start();
        try {
            waitUntil(() -> reportedTotal(sink) == 3);
            check("three drops, reported once (" + sink.drops + ")",
                  reportedTotal(sink) == 3 && c.dropped() == 3);
            c.stop();
            c.start();
            offerAll(c, obs(9));                       // wake the new drain
            waitUntil(() -> sink.seen.contains("http://app.test/9"));
            Thread.sleep(3 * POLL_SETTLE_MS);
            check("the restart re-reported nothing (" + sink.drops
                  + ", " + reportedTotal(sink) + " reported against "
                  + c.dropped() + " counted)",
                  reportedTotal(sink) == c.dropped());
        } finally { c.stop(); }
    }

    static void startTwiceLeavesOneDrain() throws Exception {
        // A leaked thread rather than an inflated count: the second start()
        // overwrote `drain`, so stop() could never reach the first again -- N
        // extension reloads, N live `hx-capture` daemons, each polling a queue
        // and calling into a torn-down BridgeClient. Counted, not found by
        // name: drainThread() matches on the name they all share, so it
        // answers just as confidently with two of them alive.
        Recording sink = new Recording();
        Capture c = new Capture(4, sink);
        c.start();
        try {
            waitUntil(() -> drainCount() == 1);
            check("one drain to begin with (" + drainCount() + ")",
                  drainCount() == 1);
            c.start();                                 // the second call
            Thread.sleep(3 * POLL_SETTLE_MS);
            check("start() twice is still ONE drain (" + drainCount() + ")",
                  drainCount() == 1);
            offerAll(c, obs(1));
            waitUntil(() -> sink.seen.contains("http://app.test/1"));
            check("and that drain is the one still delivering (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/1"));
        } finally { c.stop(); }
    }

    // ---- the sink says "not delivered" without throwing ------------------

    /** Three drain cycles' worth of settling, for the checks that assert a
     *  report did NOT happen. A negative needs a bound: nothing to wait for
     *  means nothing waitUntil can watch. */
    static final long POLL_SETTLE_MS = Capture.POLL_MS;

    static void anUndeliveredExchangeIsCountedAsADrop() throws Exception {
        // The third way a record is lost, and it used to touch no counter at
        // all: a frame over MAX_FRAME -- a 64 MB download through the proxy --
        // or a socket that died between two requests took
        // `catch (Throwable) { log.error(...) }` and vanished. hx then reported
        // complete coverage for a run that had lost them.
        Recording sink = new Recording();
        sink.refuseExchange = true;
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1), obs(2), obs(3));
            waitUntil(() -> c.dropped() == 3);
            check("a record the sink would not take is counted ("
                  + c.dropped() + ")", c.dropped() == 3);
            waitUntil(() -> reportedTotal(sink) == 3);
            check("and reported, against its own source ("
                  + sink.drops + " " + sink.dropSources + ")",
                  reported(sink, "operator") == 3);
            check("and nothing was recorded as delivered (" + sink.seen + ")",
                  sink.seen.isEmpty());
        } finally { c.stop(); }
    }

    static void aDropReportThatSaysNotDeliveredIsRetriedInFull() throws Exception {
        // THE PRODUCTION SHAPE, and the one aThrowingDropReportDoesNotKillTheDrain
        // could not reach. BridgeClient.exchangeSink catches its own
        // IOException, logs and returns -- so the only sink that ever SIGNALLED
        // failure was the test's, and against the real one the drain read a
        // failed write as success and advanced `reported` past it. Scenario:
        // the queue saturates while the Python harness restarts, 5,000 drops
        // are counted, the write fails, one line lands in Burp's log, the
        // bridge reconnects, and run.dropped_total reads 0.
        Recording sink = new Recording();
        sink.refuseDropOnce = true;
        Capture c = new Capture(1, sink);
        offerRange(c, 4);                             // 3 dropped
        c.start();
        try {
            waitUntil(() -> !sink.drops.isEmpty());
            check("the report that answered false was retried in full ("
                  + sink.drops + ")", reportedTotal(sink) == 3);
            offerAll(c, obs(9));
            waitUntil(() -> sink.seen.contains("http://app.test/9"));
            check("and the drain is still delivering exchanges (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/9"));
        } finally { c.stop(); }
    }

    // ---- a denial is a record too ----------------------------------------

    static void aDenialIsItsOwnFrame() throws Exception {
        // `hx/capture.py`'s DENIAL arm reads `t`, `via`, `source`, `method`,
        // `url`, `error_class` and `detail`, and it refuses an unknown `t`, an
        // unknown `via` and a missing `url` -- each of which is a ValueError
        // on the bridge's read thread and NO ROW AT ALL, counted as one more
        // drop rather than recorded as the refusal it was.
        //
        // AND IT IS A DENIAL FRAME, not an exchange with two empty bodies.
        // `server.py::_capture` splits two bodies out of an `exchange` and
        // none out of a `denial`; a refusal routed through the exchange arm
        // arrives as a malformed exchange and is dropped.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, new Denied("POST", "http://app.test/account/delete",
                                   "dangerous_denied",
                                   "matches dangerous.path /account/delete",
                                   Source.CRAWLER));
            waitUntil(() -> sink.denials.size() == 1);
            check("it went out as a DENIAL, not through the exchange arm ("
                  + sink.denials.size() + " denials, " + sink.headers.size()
                  + " exchanges)",
                  sink.denials.size() == 1 && sink.headers.isEmpty());
            Map<String, Object> h = sink.denials.get(0);
            check("t is the frame type hx.capture.FRAME_TYPES names ("
                  + h.get("t") + ")", "denial".equals(h.get("t")));
            check("via is one of records.VIA_VALUES (" + h.get("via") + ")",
                  "proxy".equals(h.get("via")));
            check("source is the crawler's spelling (" + h.get("source") + ")",
                  "crawler".equals(h.get("source")));
            check("method survives (" + h.get("method") + ")",
                  "POST".equals(h.get("method")));
            check("url survives, and it has no default on the far side ("
                  + h.get("url") + ")",
                  "http://app.test/account/delete".equals(h.get("url")));
            check("error_class is what records.row_for routes on ("
                  + h.get("error_class") + ")",
                  "dangerous_denied".equals(h.get("error_class")));
            check("detail is what the operator reads (" + h.get("detail") + ")",
                  "matches dangerous.path /account/delete".equals(h.get("detail")));
            // NO EIGHTH KEY. An unknown key is IGNORED on the far side rather
            // than refused, so a key added here with no reader there is a fact
            // the operator never sees and a reason to believe it was recorded.
            // Notably there is no `status`, no `ms` and no `outcome`: a
            // request that never left has no answer for any of the three.
            check("and no eighth key (" + h.keySet() + ")", h.size() == 7);
        } finally { c.stop(); }
    }

    static void anUndeliveredDenialIsCountedAgainstItsOwnSource() throws Exception {
        // The same rule as an undelivered exchange, and it needs its own test
        // because it is served by its own arm of `deliver`: a denial that did
        // not reach the wire is a record hx does not have, and a refusal hx
        // recorded nowhere reads -- from the operator's side -- exactly like a
        // request that was allowed.
        Recording sink = new Recording();
        sink.refuseDenial = true;
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, den(1, Source.CRAWLER), den(2, Source.CRAWLER));
            waitUntil(() -> c.dropped() == 2);
            check("a denial the sink would not take is counted ("
                  + c.dropped() + ")", c.dropped() == 2);
            waitUntil(() -> reported(sink, "crawler") == 2);
            check("and reported against the crawler, whose refusals they were ("
                  + sink.drops + " " + sink.dropSources + ")",
                  reported(sink, "crawler") == 2
                  && reported(sink, "operator") == 0);
            check("and nothing was recorded as delivered (" + sink.denials + ")",
                  sink.denials.isEmpty());
        } finally { c.stop(); }
    }

    static void aDeniedRecordWithNoSpellingIsRefusedTheSameWay() throws Exception {
        // THE REACHABLE ONE, and the reason Capture's offer() comment no
        // longer says an unattributed record cannot arrive. ProxyGate refuses
        // Source.UNATTRIBUTED -- that is exactly what it is for -- and the
        // handler offers the refusal as a Denied carrying that same source. So
        // this record is the one hx records as a DROP rather than as a denial
        // row: `hx.capture._run` maps anything that is not "crawler" onto the
        // operator's browse run, and filing a refusal nobody could attribute
        // under the operator's own browsing is the failure UNATTRIBUTED exists
        // to prevent. The bytes did not leave either way.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, den(1, Source.UNATTRIBUTED), den(2, Source.OPERATOR));
            waitUntil(() -> sink.denials.size() == 1);
            Thread.sleep(50);
            check("the attributed refusal was recorded (" + sink.denials.size() + ")",
                  sink.denials.size() == 1
                  && "http://app.test/refused/2".equals(sink.denials.get(0).get("url")));
            check("and the unattributable one was not",
                  c.dropped() == 1);
            waitUntil(() -> !sink.drops.isEmpty());
            check("it was reported with NO spelling, not as the operator ("
                  + sink.dropSources + ")",
                  sink.dropSources.contains(null)
                  && !sink.dropSources.contains("operator"));
        } finally { c.stop(); }
    }

    static void countLostIsChargedToTheSourceItIsGiven() throws Exception {
        // Path 6: a record that never entered the queue at all. The response
        // handler with no Pending entry has no start time and no attribution,
        // so it counts the loss instead of recording an exchange with a
        // guessed duration -- and it must be counted against the source the
        // CALLER names, because the far side turns that string into a run
        // KIND. A countLost that always charged the operator would file a
        // crawler's losses on the operator's browse run.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            c.countLost(Source.CRAWLER);
            c.countLost(Source.CRAWLER);
            c.countLost(Source.UNATTRIBUTED);
            check("all three were counted (" + c.dropped() + ")", c.dropped() == 3);
            waitUntil(() -> reported(sink, "crawler") == 2
                            && reported(sink, null) == 1);
            check("two against the crawler (" + reported(sink, "crawler") + ")",
                  reported(sink, "crawler") == 2);
            // The response handler's own miss is charged here: it is the one
            // place the source is genuinely unknown, and a drop with no run
            // attached beats a drop filed against a run that was picked.
            check("and the unattributed one with no spelling at all ("
                  + sink.dropSources + ")", reported(sink, null) == 1);
            check("and none against the operator, who lost nothing ("
                  + reported(sink, "operator") + ")",
                  reported(sink, "operator") == 0);
            check("and nothing was delivered as a record (" + sink.seen + " "
                  + sink.denials + ")",
                  sink.seen.isEmpty() && sink.denials.isEmpty());
        } finally { c.stop(); }
    }
}
