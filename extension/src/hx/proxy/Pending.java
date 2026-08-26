// extension/src/hx/proxy/Pending.java
package hx.proxy;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The start time and the attributed source of a request that has not been
 * answered yet, keyed by Burp's own message id.
 *
 * IT EXISTS BECAUSE BURP HANDS THE RESPONSE HANDLER NEITHER FACT.
 * `InterceptedResponse` carries no timing at all -- there is no
 * `timingData()` on it, only on the history type -- so `ms` has to be
 * measured by this extension or not reported. And while `InterceptedResponse`
 * does expose `listenerInterface()`, that accessor was MEASURED on requests
 * only (docs/burp-proxy-measurements.md, Q1); using it on a response would be
 * an unmeasured assumption sitting under the field that decides which run a
 * record is filed against. So the request handler writes both down and the
 * response handler takes them back.
 *
 * BOUNDED, AND EVICTION IS A LOSS SOMEONE IS TOLD ABOUT. The alternative --
 * an unbounded map in a Burp that runs for days -- leaks an entry for every
 * request that never gets a response, which includes every request the gate
 * dropped and every connection that died. {@link Capture}'s bound exists for
 * the same reason and this one follows its shape: a ceiling on MEMORY, oldest
 * evicted first, and the record's absence reported rather than papered over.
 * A {@link #take} that misses is NOT an exchange recorded with a guessed
 * duration; it is a record hx does not have, and S5 makes that a number --
 * the caller answers a miss with {@link Capture#countLost}.
 *
 * WHAT THIS CLASS COUNTS AND WHAT IT DOES NOT. {@link #evicted} counts
 * entries this class threw away to stay inside its bound, and NOTHING ELSE.
 * It is not the number of exchanges hx lost: an evicted entry costs a record
 * only if its response ever arrives, and a request that was dropped or whose
 * connection died is an entry that SHOULD go. The number that says what hx
 * lost is `Capture.dropped()`, fed by the caller. This one is here so a run
 * with short coverage can be read against the bound that produced it.
 *
 * NOT A ConcurrentHashMap: eviction needs insertion order, and the critical
 * section is a map write on a proxy thread -- nanoseconds, next to a network
 * round trip.
 *
 * THE MONITOR IS SEPARATED, AND BY MEASUREMENT RATHER THAN BY ASSERTION.
 * `PendingTest.concurrentPutsAndTakesDoNotLoseOrCrossEntries` drives eight
 * threads x 500 entries through this class and checks each gets its own back.
 * With all four {@code synchronized (live)} blocks replaced by bare blocks --
 * same code, no lock -- it went RED on every one of three runs, 986, 1270 and
 * 198 entries lost and 705, 376 and 325 stranded in a map that should have
 * emptied, each run 12 summary lines with named FAIL lines and rc=1.
 *
 * It is still EVIDENCE rather than PROOF, and the difference is worth keeping
 * in view: a lock cannot be proved from outside, and that method could in
 * principle go green against an unlocked map on a lucky interleaving. What
 * three-for-three says is that the shape it catches -- concurrent writers
 * corrupting a LinkedHashMap -- is the shape that actually happens here, at
 * this thread count, with this much work.
 */
public final class Pending {

    /** What the request handler wrote down, as the response handler takes it
     *  back. `startNanos` is {@link System#nanoTime}, so it is a DURATION's
     *  origin and nothing else: it cannot be compared with a wall clock and
     *  is meaningless outside this JVM. */
    public record Entry(long startNanos, Source source) { }

    private final int capacity;

    /** Insertion-ordered, which is what makes "evict the oldest" a fact about
     *  this map rather than about whichever entry the iterator happened to
     *  reach first. Guarded by its own monitor -- every read and every write
     *  below is inside a {@code synchronized (live)}. */
    private final LinkedHashMap<Integer, Entry> live = new LinkedHashMap<>();

    private long evicted;

    public Pending(int capacity) {
        this.capacity = capacity;
    }

    /**
     * Record a request. Evicts the oldest entries until the map is back
     * inside its bound, counting each.
     *
     * A repeated {@code messageId} REPLACES the entry and keeps the original
     * insertion position -- LinkedHashMap's documented behaviour for a
     * re-put in insertion order. Nothing in this tree produces one (Burp's
     * ids are per-message) and no test here covers it, so it is written down
     * as what the map does rather than claimed as a decision.
     */
    public void put(int messageId, long startNanos, Source source) {
        synchronized (live) {
            live.put(messageId, new Entry(startNanos, source));
            while (live.size() > capacity) {
                Iterator<Map.Entry<Integer, Entry>> it = live.entrySet().iterator();
                it.next();
                it.remove();
                evicted++;
            }
        }
    }

    /**
     * The entry for {@code messageId}, removed, or null if there is none.
     *
     * REMOVED, not read. An entry is consumed exactly once, so a response
     * that somehow reached this handler twice cannot produce two exchange
     * rows for one request -- and a `take` of an id that was never put, or
     * that was evicted, answers null rather than throwing, because the
     * caller is a Burp proxy thread with nothing useful to do with an
     * exception.
     */
    public Entry take(int messageId) {
        synchronized (live) {
            return live.remove(messageId);
        }
    }

    /** How many entries were evicted to stay inside the bound. See the class
     *  javadoc for what this number is NOT. */
    public long evicted() {
        synchronized (live) {
            return evicted;
        }
    }

    /** How many requests are waiting for a response right now. For the test
     *  and for anyone reading a run whose coverage is short. */
    public int size() {
        synchronized (live) {
            return live.size();
        }
    }
}
