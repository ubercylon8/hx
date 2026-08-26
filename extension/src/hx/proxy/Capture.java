// extension/src/hx/proxy/Capture.java
package hx.proxy;

import hx.bridge.BridgeClient;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The bounded queue between the proxy handler and the bridge.
 *
 * ONE RULE: offering never blocks. The extension sits in the request path of
 * a real person's browser during a live engagement, possibly against a
 * production system. S4 puts it plainly -- a wedged harness, a full queue or
 * a dropped record changes what hx KNOWS, never what it ALLOWS -- and the
 * practical consequence is that a slow Python side must never become a stall
 * on the client's application. That would turn a harness bug into an
 * incident.
 *
 * ITS CONVERSE: a drop is never silent. S5 says a run with drops has coverage
 * numbers that are a FLOOR, and nothing on the far side can know that unless
 * it is told. There are FIVE ways this class can hold a record it does not
 * pass on, and each one increments {@link #dropped} for the record's own
 * source:
 *
 *   1. EVICTION, when {@link #offer} finds the queue full;
 *   2. REFUSAL, when a record's source has no spelling;
 *   3. AN UNDELIVERED EXCHANGE -- the sink threw, or answered false;
 *   4. {@link #stop}, which throws away whatever is still queued;
 *   5. AN OFFER THAT ARRIVES AT OR AFTER {@link #stop} -- Burp unloading the
 *      extension while a proxy thread is still inside {@link #offer}. Such a
 *      record lands in a queue with no drain behind it, so {@link #offer}
 *      clears and counts the queue itself once it sees {@link #accepting}
 *      go false.
 *
 * They are ONE number, not five, because they are one fact: a record hx does
 * not have. A frame over MAX_FRAME and a socket that died between two
 * requests differ to whoever is debugging the bridge and not at all to
 * whoever is reading the run's coverage.
 *
 * COUNTING THE INCREMENTS IS NOT A FALSIFIER, and this comment said it was.
 * It read "`incrementAndGet` appears exactly four times, once per path; a
 * fifth loss would need a fifth increment or would be a record leaving with
 * none, and either is visible in one grep." Path 5 was neither: the record
 * did not leave and nothing was incremented, it simply sat in the queue.
 * Measured before it was closed -- `stop(); offer(one record);` gave
 * `delivered=0, dropped()=0, reports=[]`, and 4 paced proxy threads offering
 * 800 records across a `stop()` gave `4 delivered + 284 dropped of 800`, the
 * missing 512 being exactly DEFAULT_CAPACITY sitting in a drainless queue.
 *
 * WHAT DOES PIN THE FIVE is a count of EXITS, not of increments. A record
 * enters through {@link #offer} and nowhere else, and it leaves DELIVERED or
 * as one of 1-5; the four `incrementAndGet` sites are what serve those five,
 * paths 4 and 5 sharing {@link #discardQueued}. Each of the four was DELETED
 * on its own and measured: refusal -> 3 FAIL, eviction -> 9, undelivered -> 3,
 * discard -> 3, every one of them 11 summary lines with named FAIL lines, and
 * none of them a silent green. `offers racing stop() are every one of them
 * accounted for` is the test that holds when no single increment does: it
 * asserts only that delivered + dropped is everything offered, which is the
 * exits restated.
 *
 * WHAT IS NOT COVERED, and cannot be from inside this class: a JVM that dies
 * without reaching {@link #stop} takes the queue with it uncounted, and so
 * does one that exits while the drain is still parked in a wedged sink with a
 * record in hand -- that record is counted when the sink finally answers, or
 * never. Both are Burp dying, not hx losing a record quietly, and there is no
 * code path left to run at that point.
 *
 * WHAT IS NOT CLAIMED HERE is that the count reaches the far side. It reaches
 * it when {@link BridgeClient.ExchangeSink#dropped} SAYS it did, by answering
 * true; a report that answers false leaves {@link #reported} where it was and
 * the whole outstanding total goes out on the next attempt. That distinction
 * is the entire point of the boolean: the production sink catches its own
 * IOException, and before it answered, a write that failed advanced the
 * counter anyway -- 5,000 drops became one line in Burp's log and
 * `run.dropped_total = 0`. A log line is not the coverage floor.
 *
 * Oldest-first eviction, deliberately. The recent requests are the ones an
 * operator is currently looking at; the old ones are already reasoned about.
 */
public final class Capture {

    /**
     * 512 exchanges, ~1 MB at ~2 KB apiece.
     *
     * Nothing against a JVM already holding Burp, and more requests than a
     * human generates in the seconds a slow harness takes to catch up. The
     * number is a ceiling on MEMORY, not on correctness: the queue is allowed
     * to overflow, it is not allowed to block, and every overflow is counted.
     */
    public static final int DEFAULT_CAPACITY = 512;

    /** Same bound and same reason as HaltSwitch.STOP_JOIN_MS: unloading the
     *  extension must not hang Burp. */
    static final long STOP_JOIN_MS = 2000L;

    /**
     * How long the drain parks waiting for the next record.
     *
     * `take()` would be the obvious call and it is the wrong one: drops are
     * reported by the drain, and a drain parked forever on an empty queue
     * reports nothing. The overflow that produced the drops is exactly the
     * moment traffic then STOPS -- the operator gives up on a page that will
     * not load -- so "the next record will carry the report out" is the one
     * assumption the drop path may not make. A bounded park makes the report
     * arrive on its own.
     */
    static final long POLL_MS = 100L;

    private final ArrayBlockingQueue<Observed> queue;
    private final BridgeClient.ExchangeSink sink;

    /**
     * Drops COUNTED PER SOURCE, because the report carries a source and the
     * far side turns it into a run KIND: `hx.capture` maps "crawler" to a
     * crawl run and everything else to a browse run. One counter with one
     * source attached would file a crawler's drops against the operator's run
     * whenever the two interleave -- a coverage figure wrong on the row an
     * operator reads, in a component whose entire purpose is not lying about
     * coverage.
     */
    private final AtomicLong[] dropped = new AtomicLong[Source.values().length];

    /**
     * How much of {@link #dropped} the far side has ACKNOWLEDGED, per source.
     *
     * A FIELD, and it used to be a local in `loop()`. Measured with it local:
     * three real drops reported `[OPERATOR:3]`, then `stop(); start();`
     * reported `[OPERATOR:3, OPERATOR:3]` -- six reported against three that
     * happened. `hx.capture` only refuses `n < 1` and `count_drop`
     * ACCUMULATES, so nothing on the Python side can catch an inflated
     * report: `run.dropped_total` climbs without bound across reconnects, and
     * the number that exists to say "coverage is a floor" becomes a number
     * that is wrong in the direction of alarm.
     *
     * Guarded by {@link #reportLock}, which is what lets {@link #stop} report
     * the flush without racing a drain that outlived its join.
     */
    private final long[] reported = new long[Source.values().length];

    /**
     * Held across one whole reporting pass.
     *
     * `stop()` reports too, and a drain that did not die inside STOP_JOIN_MS
     * is still reporting. Two passes over the same `reported[]` would each
     * read the same outstanding total and each send it -- E3's bug with two
     * threads instead of two runs. `stop()` takes it with `tryLock` and never
     * waits: a drain wedged INSIDE the sink holds this, and a stop() that
     * blocked on it would hang Burp's unload, which is the one thing
     * STOP_JOIN_MS exists to prevent.
     */
    private final ReentrantLock reportLock = new ReentrantLock();

    private volatile Thread drain;
    private volatile boolean running;

    /**
     * Whether {@link #offer} still has a drain to offer INTO.
     *
     * True from construction and false from {@link #stop} until the next
     * {@link #start}. {@link #running} cannot do this job, and that is not a
     * naming quibble: `running` is also false BEFORE the first `start()`, and
     * offering into a Capture that has not started yet is legitimate -- it is
     * how `stopThenStartDoesNotReReportTheCount` fills the queue, and it is
     * what the proxy handler does for any record that arrives between
     * construction and the drain's first poll. Those records have a drain
     * coming. A record offered after `stop()` does not.
     */
    private volatile boolean accepting = true;

    public Capture(int capacity, BridgeClient.ExchangeSink sink) {
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.sink = sink;
        for (int i = 0; i < dropped.length; i++) dropped[i] = new AtomicLong();
    }

    /** Total drops, across every source. */
    public long dropped() {
        long total = 0;
        for (AtomicLong c : dropped) total += c.get();
        return total;
    }

    /**
     * The two spellings the harness knows, and NO THIRD.
     *
     * `hx.capture._run` reads this string and answers "crawl" for "crawler"
     * and "browse" for anything else. So there is no string an UNATTRIBUTED
     * record could carry that does not become the operator's run on arrival,
     * which is why this answers null instead of inventing one -- and why
     * {@link #offer} refuses such a record rather than queueing it. Written as
     * two explicit answers rather than `s == CRAWLER ? "crawler" : "operator"`,
     * so a constant added to {@link Source} later is a null here and a refused
     * record, not a silent promotion to the operator's run.
     *
     * It lives HERE, and the sink takes the STRING it produces. `hx.bridge`
     * knowing how to spell an `hx.proxy` enum was a package cycle and a
     * second place the decision could drift; a `null` crossing to the sink
     * means "no spelling", and the sink's only job with it is to omit the key.
     */
    public static String sourceName(Source s) {
        if (s == Source.CRAWLER) return "crawler";
        if (s == Source.OPERATOR) return "operator";
        return null;
    }

    /**
     * Never blocks, never throws, never reports failure to its caller.
     *
     * The caller is a Montoya proxy handler on Burp's own thread. There is
     * nothing useful it could do with an exception and one thing it must not
     * do, which is fail to forward the request.
     *
     * A record whose source has no spelling ({@link #sourceName}) is REFUSED
     * here and counted as a drop. ProxyGate already refuses UNATTRIBUTED, so
     * one should never arrive; if one does, recording it would file the
     * request under a run kind nothing chose, and the request never left in
     * the first place. Counted rather than discarded, because the count is
     * the thing that says hx knows less than it might.
     *
     * AND IT NOTICES A CAPTURE THAT HAS STOPPED UNDERNEATH IT. Burp unloads
     * the extension on its own thread while proxy threads are still in here;
     * without the check at the bottom those records queued into a drain that
     * no longer existed, which lost them AND left `run.dropped_total` where
     * it was -- the coverage floor reading lower than the real loss, which is
     * the one direction it may never move.
     */
    public void offer(Observed o) {
        if (sourceName(o.source()) == null) {
            dropped[o.source().ordinal()].incrementAndGet();
            return;
        }
        while (!queue.offer(o)) {
            // Evict the oldest and try again. `poll` returning null means
            // another thread drained it first, which is fine -- the retry
            // then succeeds.
            Observed evicted = queue.poll();
            if (evicted != null) dropped[evicted.source().ordinal()].incrementAndGet();
        }
        // AFTER the enqueue, not before, and that ordering is the whole
        // guarantee. `accepting` is volatile and the queue has a lock of its
        // own, so the two orderings cover each other: if this read sees TRUE
        // it precedes stop()'s write of false, so the enqueue above precedes
        // stop()'s drainTo and stop() counts the record; if it sees FALSE,
        // stop() may already have drained past the record, so this thread
        // clears the queue itself. A check BEFORE the enqueue would leave the
        // window between the two open, which is precisely the window Burp's
        // unload sits in.
        if (!accepting) discardQueued();
    }

    /**
     * Count everything queued, and keep nothing.
     *
     * Called by {@link #stop}, and by an {@link #offer} that found the
     * capture already stopped. NEVER by the drain: a record taken off the
     * queue to be DELIVERED is {@link #deliver}'s business, and counting it
     * here as well would report one loss twice.
     */
    private void discardQueued() {
        List<Observed> left = new ArrayList<>();
        queue.drainTo(left);
        for (Observed o : left) dropped[o.source().ordinal()].incrementAndGet();
    }

    /**
     * Start the drain, or do nothing if it is already running.
     *
     * IDEMPOTENT, and that is not tidiness. Called twice, the previous
     * version started a second `hx-capture` thread over the first -- two
     * drains on one queue, and `drain` naming only the second, so `stop()`
     * could never reach the first again. Inside Burp that is one leaked
     * daemon per extension reload, each polling a queue and calling into a
     * torn-down BridgeClient.
     */
    public synchronized void start() {
        if (drain != null) return;
        accepting = true;
        running = true;
        Thread t = new Thread(this::loop, "hx-capture");
        t.setDaemon(true);   // must never hold Burp open
        drain = t;
        t.start();
    }

    /**
     * Stop the drain, and account for what is still queued.
     *
     * THE FLUSH IS THE POINT. Measured on the previous version: 200 records
     * queued into a 512-slot Capture behind a slow sink, then `stop()` --
     * `delivered=0, dropped()=0, reports=[]`. Two hundred exchanges gone and
     * counted as zero, on every extension unload and at the end of every run.
     *
     * The queue is COUNTED, not delivered. Delivering it would mean pushing
     * up to DEFAULT_CAPACITY frames into a sink that may be exactly as wedged
     * as the one that let the queue fill, on the thread Burp is unloading the
     * extension on -- an unbounded wait where STOP_JOIN_MS is the bound. A
     * record hx cannot pass on is a drop; saying so is the honest half, and
     * it is the half S5 depends on.
     *
     * Idempotent, AND A SECOND CALL IS NOT ALWAYS A NO-OP. It finds no drain,
     * but it finds whatever arrived after the first: a proxy thread inside
     * {@link #offer} when Burp tore the extension down has counted its record
     * (path 5) and had nothing left to report it through. The next `stop()`
     * is what carries that count across the sink. Task 7 owns the choice of
     * whether there is one -- and this method COUNTING rather than DELIVERING
     * is the trade it may want to revisit with a deadline-drain of its own
     * before it calls this.
     */
    public synchronized void stop() {
        // FIRST, and before the drain is even asked to stop: from this write
        // on, an offer() that lands in the queue is responsible for counting
        // itself. See offer()'s closing comment for why that is enough.
        accepting = false;
        running = false;
        Thread t = drain;
        drain = null;
        if (t != null) {
            t.interrupt();
            try {
                t.join(STOP_JOIN_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        discardQueued();
        // tryLock, never lock: see reportLock. A drain wedged in the sink is
        // holding it, and there is nothing to report through anyway.
        if (reportLock.tryLock()) {
            try {
                reportOutstanding();
            } finally {
                reportLock.unlock();
            }
        }
    }

    private void loop() {
        while (running) {
            Observed o;
            try {
                o = queue.poll(POLL_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (o != null) deliver(o);
            reportLock.lock();
            try {
                reportOutstanding();
            } finally {
                reportLock.unlock();
            }
        }
    }

    /** One record to the sink, or one more drop. */
    private void deliver(Observed o) {
        boolean delivered;
        try {
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("t", "exchange");
            h.put("via", "proxy");
            h.put("source", sourceName(o.source()));
            h.put("method", o.method());
            h.put("url", o.url());
            h.put("status", (long) o.status());
            h.put("ms", o.ms());
            h.put("outcome", "ok");
            delivered = sink.exchange(h, o.request(), o.response());
        } catch (Throwable t) {
            // A sink that throws is someone else's code failing. Losing
            // this record is bad; losing every record after it because
            // the drain thread died is worse, and silent.
            delivered = false;
        }
        if (!delivered) dropped[o.source().ordinal()].incrementAndGet();
    }

    /** Called with {@link #reportLock} held. */
    private void reportOutstanding() {
        for (Source s : Source.values()) {
            int i = s.ordinal();
            long now = dropped[i].get();
            if (now == reported[i]) continue;
            boolean told;
            try {
                told = sink.dropped(now - reported[i], sourceName(s));
            } catch (Throwable t) {
                // Same reasoning as deliver(): a sink that throws must not
                // kill the drain.
                told = false;
            }
            // ONLY on an acknowledged report. The count is cumulative, so the
            // next attempt carries the whole outstanding total -- and the
            // previous version advanced on a sink that had merely RETURNED,
            // which the production one does after logging its own IOException.
            if (told) reported[i] = now;
        }
    }
}
