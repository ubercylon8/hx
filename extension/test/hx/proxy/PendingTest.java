// extension/test/hx/proxy/PendingTest.java
package hx.proxy;

import hx.TestSupport;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * The map that carries a request's clock and its attribution across to the
 * response handler.
 *
 * Everything here is about ONE property: a `take` that misses must be a MISS,
 * not a guess. The caller answers a miss by counting a lost record; the one
 * thing it must never do is record an exchange with a fabricated duration or
 * a source nobody attributed. So the tests below are mostly about the ways an
 * entry can go away -- consumed, evicted -- and about the counter that says
 * how many went the second way.
 *
 * Hand-rolled runner, like the other eleven classes: JUnit would be a
 * dependency, and this jar has none.
 */
public class PendingTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** The shared per-method guard: a throw becomes a NAMED FAIL against this
     *  class's counter instead of ending main() with the rest unrun and no
     *  summary line printed. See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(PendingTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("put then take gives back exactly what was put",
          PendingTest::putThenTakeRoundTrips);
        t("an entry is consumed once, so a repeated response cannot double-count",
          PendingTest::anEntryIsConsumedOnce);
        t("a take of an id that was never put answers null, not an exception",
          PendingTest::takingAnIdNeverPutAnswersNull);
        t("one put past capacity evicts the OLDEST and only the oldest",
          PendingTest::oneOverCapacityEvictsTheOldestOnly);
        t("evicted() counts exactly the evictions, and starts at zero",
          PendingTest::evictedCountsExactlyTheEvictions);
        t("an evicted entry is a MISS, not a stale hit",
          PendingTest::anEvictedEntryIsAMiss);
        t("the bound holds under a long run of puts",
          PendingTest::theBoundHolds);
        t("concurrent puts and takes do not lose or cross entries",
          PendingTest::concurrentPutsAndTakesDoNotLoseOrCrossEntries);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- the tests ------------------------------------------------------

    static void putThenTakeRoundTrips() {
        Pending p = new Pending(4);
        p.put(7, 123_456_789L, Source.CRAWLER);
        Pending.Entry e = p.take(7);
        check("the entry came back", e != null);
        // BOTH fields, and the source is the one that decides which run the
        // record is filed against: a Pending that round-tripped the clock and
        // dropped the attribution would put a crawler's exchange on the
        // operator's browse run with the timing perfectly correct.
        check("with the start time it was given (" + (e == null ? "-" : e.startNanos()) + ")",
              e != null && e.startNanos() == 123_456_789L);
        check("and the source it was given (" + (e == null ? "-" : e.source()) + ")",
              e != null && e.source() == Source.CRAWLER);
        check("and the map no longer holds it (" + p.size() + ")", p.size() == 0);
    }

    static void anEntryIsConsumedOnce() {
        // `take` REMOVES. If it merely read, a response that reached the
        // handler twice -- a retry, a Burp that re-delivers -- would produce
        // two exchange rows for one request, and every coverage figure drawn
        // off `run.requests_issued` and the exchange table would count it
        // twice. Nothing else in this tree can notice that.
        Pending p = new Pending(4);
        p.put(1, 10L, Source.OPERATOR);
        check("the first take hits", p.take(1) != null);
        check("and the second one MISSES", p.take(1) == null);
        check("and the map is empty (" + p.size() + ")", p.size() == 0);
    }

    static void takingAnIdNeverPutAnswersNull() {
        // The caller is a Burp proxy thread. A throw here would escape the
        // response handler, and there is nothing useful it could do with one.
        Pending p = new Pending(4);
        check("an empty map answers null", p.take(99) == null);
        p.put(1, 10L, Source.OPERATOR);
        check("and so does a populated one asked for another id",
              p.take(2) == null);
        check("without disturbing the entry that is there", p.take(1) != null);
    }

    static void oneOverCapacityEvictsTheOldestOnly() {
        // Oldest-first, the same eviction Capture's queue has and for the same
        // reason: the recent requests are the ones still in flight.
        int capacity = 3;
        Pending p = new Pending(capacity);
        for (int i = 0; i < capacity; i++) p.put(i, i, Source.OPERATOR);
        check("nothing evicted while the map is inside its bound ("
              + p.evicted() + ")", p.evicted() == 0);

        p.put(capacity, capacity, Source.OPERATOR);   // capacity + 1 puts
        check("exactly one entry was evicted (" + p.evicted() + ")",
              p.evicted() == 1);
        check("and it was the OLDEST", p.take(0) == null);
        // AND ONLY THE OLDEST. An eviction loop that cleared the map, or that
        // evicted from the wrong end, would satisfy the check above on its
        // own -- this is the half that separates them.
        for (int i = 1; i <= capacity; i++)
            check("id " + i + " survived", p.take(i) != null);
    }

    static void evictedCountsExactlyTheEvictions() {
        Pending p = new Pending(2);
        check("a fresh Pending has evicted nothing (" + p.evicted() + ")",
              p.evicted() == 0);
        // Ten puts into a map that holds two: eight evictions, no more and no
        // fewer. A counter that incremented per PUT rather than per eviction
        // reads ten here.
        //
        // WHAT NO INPUT HERE SEPARATES: "counted per eviction" from "counted
        // once per put that overflowed". Every put adds exactly one entry and
        // so evicts at most one, so the two numbers are equal for every
        // sequence this class can be driven with, at every capacity -- the
        // second run below at a bound of 1 does not separate them either, and
        // this note replaces a sentence that claimed it did. They would part
        // only if the capacity could shrink under a populated map, and it
        // cannot: it is final.
        for (int i = 0; i < 10; i++) p.put(i, i, Source.OPERATOR);
        check("ten puts into a map of two evicted eight (" + p.evicted() + ")",
              p.evicted() == 8);
        check("and two are left (" + p.size() + ")", p.size() == 2);

        Pending one = new Pending(1);
        for (int i = 0; i < 5; i++) one.put(i, i, Source.OPERATOR);
        check("five puts into a map of one evicted four (" + one.evicted() + ")",
              one.evicted() == 4);
        check("and the survivor is the newest", one.take(4) != null);
    }

    static void anEvictedEntryIsAMiss() {
        // THE PROPERTY THE CALLER DEPENDS ON. An evicted entry must not come
        // back as anything: a Pending that answered a stale or a default entry
        // would hand the response handler a start time from a different
        // request, and `ms` would be a number with no meaning that nothing
        // downstream could tell from a real one.
        Pending p = new Pending(2);
        p.put(1, 1_000L, Source.CRAWLER);
        p.put(2, 2_000L, Source.CRAWLER);
        p.put(3, 3_000L, Source.CRAWLER);
        check("the evicted id answers null, not a stale entry", p.take(1) == null);
        Pending.Entry two = p.take(2);
        check("and the survivor still carries ITS OWN start time ("
              + (two == null ? "-" : two.startNanos()) + ")",
              two != null && two.startNanos() == 2_000L);
    }

    static void theBoundHolds() {
        // The bound is a ceiling on MEMORY in a Burp that runs for days: every
        // request that never gets a response leaks an entry, and that includes
        // every request the gate dropped and every connection that died.
        Pending p = new Pending(Capture.DEFAULT_CAPACITY);
        for (int i = 0; i < 10 * Capture.DEFAULT_CAPACITY; i++)
            p.put(i, i, Source.OPERATOR);
        check("the map never grew past its capacity (" + p.size() + " of "
              + Capture.DEFAULT_CAPACITY + ")", p.size() == Capture.DEFAULT_CAPACITY);
        check("and everything over it was counted (" + p.evicted() + ")",
              p.evicted() == 9L * Capture.DEFAULT_CAPACITY);
    }

    /**
     * Eight proxy threads through one Pending, each taking back its own.
     *
     * EVIDENCE, NOT PROOF, and it is labelled that way deliberately. A lock is
     * a probabilistic thing to test from outside: this method can go green
     * against an unsynchronised map on a lucky interleaving, and no number of
     * green runs makes it a proof. What it does catch is the shape that
     * actually happens -- concurrent writers into a LinkedHashMap corrupting
     * it -- and the measurement it was kept on is in this task's report.
     *
     * Every wait here is BOUNDED. A corrupted HashMap can spin forever inside
     * `get`, so an unbounded join would print no summary line at all and read
     * as zero failures under `grep -c FAIL`; {@link TestSupport#join} turns
     * that into a named FAIL instead. The workers are daemons for the same
     * reason CaptureTest's are: a leaked parked daemon cannot hold the JVM
     * open after main() prints its summary.
     */
    static void concurrentPutsAndTakesDoNotLoseOrCrossEntries() throws Exception {
        int threads = 8, each = 500;
        // Capacity above threads * each, so NOTHING is evicted and every miss
        // below is a real loss rather than the bound doing its job.
        Pending p = new Pending(threads * each * 2);
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        List<String> wrong = java.util.Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < threads; i++) {
            final int base = i * each;
            final Source mine = (i % 2 == 0) ? Source.OPERATOR : Source.CRAWLER;
            Thread w = new Thread(() -> {
                try {
                    if (!go.await(5000, TimeUnit.MILLISECONDS)) return;
                } catch (InterruptedException e) { return; }
                for (int n = 0; n < each; n++) {
                    int id = base + n;
                    p.put(id, id, mine);
                }
                for (int n = 0; n < each; n++) {
                    int id = base + n;
                    Pending.Entry e = p.take(id);
                    if (e == null) wrong.add("lost " + id);
                    else if (e.startNanos() != id || e.source() != mine)
                        wrong.add("crossed " + id + " -> " + e.startNanos()
                                  + "/" + e.source());
                }
            });
            w.setDaemon(true);
            workers.add(w);
            w.start();
        }
        go.countDown();
        for (Thread w : workers)
            TestSupport.join(w, 10000, "a proxy thread inside Pending");
        check("every entry came back to the thread that put it, with its own "
              + "values (" + wrong.size() + " wrong: "
              + wrong.subList(0, Math.min(5, wrong.size())) + ")",
              wrong.isEmpty());
        check("and nothing was evicted, so a miss would have been a real loss ("
              + p.evicted() + ")", p.evicted() == 0);
        check("and the map is empty afterwards (" + p.size() + ")", p.size() == 0);
    }
}
