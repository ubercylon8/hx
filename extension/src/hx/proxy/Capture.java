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
 * it is told. There are SIX ways a record hx might have had does not reach
 * the far side, and each one increments {@link #dropped} for the record's own
 * source:
 *
 *   1. EVICTION, when {@link #offer} finds the queue full;
 *   2. REFUSAL, when a record's source has no spelling;
 *   3. AN UNDELIVERED RECORD -- the sink threw, or answered false;
 *   4. {@link #stop}, which throws away whatever is still queued;
 *   5. AN OFFER THAT ARRIVES AT OR AFTER {@link #stop} -- Burp unloading the
 *      extension while a proxy thread is still inside {@link #offer}. Such a
 *      record lands in a queue with no drain behind it, so {@link #offer}
 *      clears and counts the queue itself once it sees {@link #accepting}
 *      go false.
 *   6. A RECORD THAT NEVER ENTERED THE QUEUE AT ALL, counted through
 *      {@link #countLost}. The queue is not the only place a record is lost:
 *      the response handler that finds no {@link Pending} entry for a
 *      response has an exchange it cannot describe -- no start time, so no
 *      `ms`, and no attributed source -- and the honest answer is a drop
 *      rather than a row with a guessed duration on it.
 *
 * They are ONE number, not six, because they are one fact: a record hx does
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
 * PATH 6 IS THE SAME LESSON A SECOND TIME, and it is why this paragraph is
 * amended rather than left standing. Task 7 added TWO `incrementAndGet` sites
 * to the four -- {@link #countLost} for path 6, and the denial arm of
 * {@link #deliver} for path 3 -- so the retired grep would now answer "six
 * sites, six paths" and LOOK right while meaning nothing. MEASURED, by
 * reading them: the six sites are the refusal (path 2), the eviction (path 1),
 * {@link #discardQueued} (paths 4 AND 5, one site for two), {@link #countLost}
 * (path 6), and ONE PER FRAME ARM for path 3 (two sites for one). Two paths
 * share a site and one path has two; that the totals agree is arithmetic, not
 * structure. The count of increments has never matched the count of paths in
 * any way a grep could check, and the moment it appears to is the moment it is
 * most misleading.
 *
 * WHAT DOES PIN THE SIX is a count of EXITS, not of increments. A record
 * enters this class through {@link #offer} or is counted without entering it
 * through {@link #countLost}, and nowhere else; it leaves DELIVERED or as one
 * of 1-6. Each of the first four increments was DELETED on
 * its own and measured: refusal -> 3 FAIL, eviction -> 9, undelivered -> 3,
 * discard -> 3, every one of them 11 summary lines with named FAIL lines, and
 * none of them a silent green. `offers racing stop() are every one of them
 * accounted for` is the test that holds when no single increment does: it
 * asserts only that delivered + dropped is everything offered, which is the
 * exits restated. {@link #countLost} is outside that identity by
 * construction -- its record never entered the queue -- so it has a test of
 * its own, `countLost is charged to the source it is given`, and that test is
 * the whole of what holds it.
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

    private final ArrayBlockingQueue<Captured> queue;
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
     * here and counted as a drop, because recording it would file the request
     * under a run kind nothing chose. Counted rather than discarded, because
     * the count is the thing that says hx knows less than it might.
     *
     * ONE SUCH RECORD IS REACHABLE, and this comment used to say none was.
     * It read "ProxyGate already refuses UNATTRIBUTED, so one should never
     * arrive" -- true while the only thing offered here was an
     * {@link Observed} from a request the gate had ALLOWED. Task 7 wired the
     * refusals in as {@link Denied}, and the request the gate refuses BECAUSE
     * it could not attribute the listener carries exactly that source. So the
     * denial hx records for it is a DROP and not a `denial` row: the bytes
     * still did not leave -- the handler answers `drop()` before this is
     * reached -- and `run.dropped_total` moves instead of `denial`. Stated
     * rather than fixed, because the alternative is `hx.capture._run` filing
     * a refusal nobody could attribute under the operator's own browse run,
     * which is the failure {@link Source#UNATTRIBUTED} exists to prevent.
     * `aDeniedRecordWithNoSpellingIsRefusedTheSameWay` is what pins it.
     *
     * AND IT NOTICES A CAPTURE THAT HAS STOPPED UNDERNEATH IT. Burp unloads
     * the extension on its own thread while proxy threads are still in here;
     * without the check at the bottom those records queued into a drain that
     * no longer existed, which lost them AND left `run.dropped_total` where
     * it was -- the coverage floor reading lower than the real loss, which is
     * the one direction it may never move.
     */
    public void offer(Captured o) {
        if (sourceName(o.source()) == null) {
            dropped[o.source().ordinal()].incrementAndGet();
            return;
        }
        while (!queue.offer(o)) {
            // Evict the oldest and try again. `poll` returning null means
            // another thread drained it first, which is fine -- the retry
            // then succeeds.
            Captured evicted = queue.poll();
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
        List<Captured> left = new ArrayList<>();
        queue.drainTo(left);
        for (Captured o : left) dropped[o.source().ordinal()].incrementAndGet();
    }

    /**
     * Count one record that never entered the queue. Path 6, and the only
     * entry point here that is not {@link #offer}.
     *
     * The caller is the proxy RESPONSE handler with a response it cannot turn
     * into a record: {@link Pending} had no entry for its message id, so
     * there is no start time and no attributed source, and an exchange row
     * with a guessed duration on it is fabricated evidence. It is also the
     * response handler's answer to a redaction that threw -- the bytes are
     * there and cannot be made safe to store, so the record is lost and says
     * so.
     *
     * The source is the CALLER'S to choose and this method does not
     * second-guess it: a miss is charged to {@link Source#UNATTRIBUTED},
     * which has no spelling, so the report crosses the bridge with the
     * `source` key OMITTED and lands on the operator's run the way
     * `hx.capture` documents an absent source. A record whose run genuinely
     * is not known must not invent one.
     */
    public void countLost(Source s) {
        dropped[s.ordinal()].incrementAndGet();
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
     * is what carries that count across the sink.
     *
     * TASK 7 SETTLED THAT THERE IS ONLY ONE, in the unloading handler that
     * already closes the bridge, and the cost is written down rather than
     * argued away: a record offered by a proxy thread that was inside
     * {@link #offer} when Burp tore the extension down is COUNTED (path 5)
     * and its count has nothing left to leave through -- the bridge is closed
     * on the next line. A second call would race the first identically while
     * the JVM is being torn down, and a record offered DURING `stop()` counts
     * itself and is in the same position whichever call observes it. So the
     * loss is real and bounded by however many proxy threads were mid-offer,
     * and the honest statement is that this class's count is complete up to
     * the unload and not through it.
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
            Captured o;
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

    /**
     * One record to the sink, or one more drop.
     *
     * The switch is over a SEALED interface with no `default` arm, so a third
     * kind of {@link Captured} is a compile error here rather than a record
     * that reaches no arm and is silently delivered as nothing.
     *
     * TWO FRAME TYPES, TWO SINK METHODS, and the denial does NOT go through
     * `exchange(...)` with two empty byte arrays. That method's name says
     * what its frame is; a denial routed through it is a naming lie the next
     * reader inherits, and `server.py::_capture` splits two bodies for an
     * `exchange` and none for a `denial`.
     */
    private void deliver(Captured c) {
        switch (c) {
            case Observed o -> deliverExchange(o);
            case Denied d -> deliverDenial(d);
        }
    }

    private void deliverExchange(Observed o) {
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
            // THE RECORD'S, NOT A LITERAL. This line read `"ok"` and was the
            // only `outcome` write on the proxy path, so every proxy exchange
            // was filed healthy whatever its bytes said -- including the
            // `103 Early Hints` shape S5 measured thirty of. The answer is
            // computed in Recorder by the SAME scan the send path uses, and
            // arrives here already paired with the `status` above: S5 accepts
            // `status_unreadable` only alongside 599, and Recorder is the one
            // place that pairing is made.
            h.put("outcome", o.outcome());
            delivered = sink.exchange(h, o.request(), o.response());
        } catch (Throwable t) {
            // A sink that throws is someone else's code failing. Losing
            // this record is bad; losing every record after it because
            // the drain thread died is worse, and silent.
            delivered = false;
        }
        if (!delivered) dropped[o.source().ordinal()].incrementAndGet();
    }

    /**
     * A refusal, as the seven keys `hx.capture`'s denial arm reads.
     *
     * `t`, `via`, `source`, `method`, `url`, `error_class` and `detail`, and
     * NO EIGHTH: an unknown key is not refused on the far side, it is
     * ignored, so a key added here without a reader there is a fact the
     * operator will never see and a reason to think it was recorded. There is
     * no `status`, no `ms` and no `outcome`, because none of the three has an
     * answer for a request that never left.
     */
    private void deliverDenial(Denied d) {
        boolean delivered;
        try {
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("t", "denial");
            h.put("via", "proxy");
            h.put("source", sourceName(d.source()));
            h.put("method", d.method());
            h.put("url", d.url());
            h.put("error_class", d.errorClass());
            h.put("detail", d.detail());
            delivered = sink.denial(h);
        } catch (Throwable t) {
            // Same reasoning as the exchange arm: a sink that throws is
            // someone else's code failing, and killing the drain would lose
            // every record after it, silently.
            delivered = false;
        }
        if (!delivered) dropped[d.source().ordinal()].incrementAndGet();
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
