// extension/src/hx/proxy/Capture.java
package hx.proxy;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

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
 * ITS CONVERSE: a drop is never silent. Every eviction is counted and the
 * count crosses the bridge, because S5 says a run with drops has coverage
 * numbers that are a FLOOR and nothing on the far side can know that unless
 * it is told.
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

    public interface ExchangeSink {
        void exchange(Map<String, Object> header, byte[] request, byte[] response);
        void dropped(long n, Source source);
    }

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
    private final ExchangeSink sink;

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
    private volatile Thread drain;
    private volatile boolean running;

    public Capture(int capacity, ExchangeSink sink) {
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
    }

    public void start() {
        running = true;
        Thread t = new Thread(this::loop, "hx-capture");
        t.setDaemon(true);   // must never hold Burp open
        drain = t;
        t.start();
    }

    public void stop() {
        running = false;
        Thread t = drain;
        if (t != null) {
            t.interrupt();
            try {
                t.join(STOP_JOIN_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        drain = null;
    }

    private void loop() {
        long[] reported = new long[dropped.length];
        while (running) {
            Observed o;
            try {
                o = queue.poll(POLL_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (o != null) {
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
                    sink.exchange(h, o.request(), o.response());
                } catch (Throwable t) {
                    // A sink that throws is someone else's code failing. Losing
                    // this record is bad; losing every record after it because
                    // the drain thread died is worse, and silent.
                }
            }
            for (Source s : Source.values()) {
                int i = s.ordinal();
                long now = dropped[i].get();
                if (now == reported[i]) continue;
                try {
                    sink.dropped(now - reported[i], s);
                    reported[i] = now;
                } catch (Throwable t) {
                    // Same reasoning; the count is cumulative, so the next
                    // successful report catches up.
                }
            }
        }
    }
}
