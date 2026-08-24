// extension/src/hx/policy/Distress.java
package hx.policy;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

/**
 * Auto-halt on target distress (spec §4).
 *
 * Every issued request is reported here with its outcome, and three rules run
 * over a rolling per-host window -- the last {@code windowRequests} requests or
 * {@code windowMs} milliseconds, whichever is shorter:
 *
 *   1. consecutive connection errors   the transport is gone
 *   2. 5xx rate                        we are breaking the application
 *   3. p50 latency against a baseline  we are exhausting the application
 *
 * A trip is STICKY. §4 says one distressed host aborts the WHOLE run, so there
 * is no per-host recovery to model: the only thing left to do with this object
 * is read the first reason out of it. {@link #record} returns immediately once
 * tripped, which is also what makes {@link #stopReason()} and {@link #stopHost()}
 * safe to read as two separate calls -- there is exactly one write, so the pair
 * cannot tear the way BridgeClient's epoch and scope did before they were
 * published through a single reference.
 *
 * The thresholds are engagement-config DEFAULTS, not constants. §14 flags that
 * they need tuning against a real client app, and a threshold you cannot change
 * mid-engagement is one you will fight, so every one of them -- including the
 * window and the baseline size -- is a constructor argument.
 *
 * Two deliberate consequences of the rules below, stated here because both look
 * like bugs from the outside:
 *
 *   - A connection error is excluded from BOTH the 5xx rate and the latency
 *     figures. Its {@code ms} is time-to-failure, not service latency, and a
 *     refused connection returns in about a millisecond; feeding those into a
 *     latency baseline drags it toward zero, which makes the 5x rule fire on
 *     healthy traffic. The cost is that a host alternating a 503 and a refusal
 *     needs twice as many requests before a rate exists. That is bounded, and
 *     DistressTest pins it.
 *   - The 5xx rate needs {@code baselineRequests} answered samples before it is
 *     computed at all. A rate over one sample is not a rate, and a single
 *     transient 502 on a run's first request would otherwise abort the
 *     engagement. It delays the rule; it does not disable it.
 *
 * No Montoya import, no I/O, and no clock of its own: the {@link Clock} is
 * injected so the boundaries are exercised exactly rather than approached with
 * sleeps.
 */
public final class Distress {

    /** §4: "the last 50 requests or 60 seconds, whichever is shorter". */
    public static final int  DEFAULT_WINDOW_REQUESTS   = 50;
    public static final long DEFAULT_WINDOW_MS         = 60_000L;

    /** §4: "a baseline taken from that host's first 10 requests". The same
     *  count gates the 5xx rate -- one knob rather than two for the same
     *  question, "have we seen enough of this host to have an opinion". */
    public static final int  DEFAULT_BASELINE_REQUESTS = 10;

    /**
     * A host answering in under a quarter of a second is not in distress,
     * whatever its baseline was. Without this floor a loopback target with a
     * 1 ms baseline trips at 6 ms -- ordinary scheduler jitter -- and a false
     * auto-halt aborts a client's authorised test. §4 does not name a floor;
     * this is the smallest addition that keeps rule 3 off noise, and it only
     * ever suppresses a stop while the host is still answering faster than
     * 250 ms.
     */
    public static final long DEFAULT_LATENCY_FLOOR_MS  = 250L;

    /**
     * The ceilings. Every one of them exists for the reason the eight-argument
     * constructor gives: the dangerous direction of a mistyped engagement
     * config is the one that DISABLES a rule, leaving an object that looks
     * configured and never trips, and a distress detector that never trips is
     * indistinguishable from a healthy target right up until a client's
     * application falls over. A value set too tight only costs an early stop.
     *
     * Each ceiling is a value ABOVE which the rule it belongs to can no longer
     * fire on any input -- not a taste judgement about tuning. They are stated
     * one per constant below, with the arithmetic that makes them so.
     *
     * A ceiling on {@code windowMs} is the one that is policy rather than
     * arithmetic, and it is worth saying so plainly. {@code windowMs * 1000L}
     * does overflow a long, but only above {@code Long.MAX_VALUE / 1000}, which
     * is about 292,271 YEARS -- so overflow is not what a 24-hour ceiling is
     * for, and an earlier version of this message that said the multiplication
     * "overflows well before Long.MAX_VALUE" was wrong by eleven orders of
     * magnitude. The real reason is the one the class comment gives: the
     * effective window is whichever of {@code windowRequests} and {@code
     * windowMs} is SHORTER, so with §4's 50-request default anything past a
     * few minutes is already count-only, and no live engagement runs a rolling
     * distress window longer than a day. {@link Math#multiplyExact} in {@link
     * #evict} keeps guarding the multiplication anyway -- unreachable under
     * this ceiling, and the first thing that matters if the ceiling is raised.
     */
    private static final long MAX_WINDOW_MS = 24L * 60 * 60 * 1000; // 24 h

    /**
     * Ceiling on {@code windowRequests}, in the same spirit as {@code
     * Limiter.MAX_RATE} and for the same reason: one long per permitted sample.
     * It bounds {@code baselineRequests} (which may not exceed it, see below),
     * so the {@code long[]} each {@link Host} allocates is at most 80 KB and
     * its deque at most this many {@link Sample}s -- PER HOST, and the number
     * of hosts is bounded only by the scope. Unbounded, {@code
     * windowRequests = 200_000_000} constructed fine and allocated 1.6 GB
     * inside Burp's JVM for the first host it saw.
     *
     * Ten thousand is already five times hx's default per-run budget of 2000
     * requests, so a window this size cannot roll even once in a default run.
     */
    private static final int MAX_WINDOW_REQUESTS = 10_000;

    /**
     * Ceiling on {@code maxConsecutiveErrors}. Rule 1 fires at {@code
     * consecutiveErrors >= maxConsecutiveErrors}, and that counter is NOT
     * bounded by the window -- it is a running streak -- so nothing else caps
     * it. {@code Integer.MAX_VALUE} is 2.1 billion consecutive refused
     * connections: rule 1 is off. Even a thousand is 200 seconds of nothing
     * but refusals at §4's single-digit production rate, and half the default
     * per-run budget, so a streak threshold above it cannot be reached in a
     * default run at all.
     */
    private static final int MAX_CONSECUTIVE_ERRORS = 1_000;

    /**
     * Ceiling on {@code latencyMultiple}, and the reason it is not merely
     * tidiness: {@code Math.max(baselineMs, 1L) * latencyMultiple} is a
     * MEASUREMENT times a CONFIG VALUE, exactly the shape of {@code windowMs *
     * 1000L}, and {@code Double.POSITIVE_INFINITY} passed the old {@code >= 1.0}
     * check and made the threshold {@code Infinity} -- above which no {@code
     * long} p50 can ever rise. Rule 3 was off, with {@link #stopReason()}
     * answering {@code null} forever.
     *
     * A finite bound is the load-bearing half: anything past about 9.2e18
     * puts the threshold beyond {@code Long.MAX_VALUE} milliseconds whatever
     * the baseline turns out to be. A thousand is the "this is a typo" line,
     * against §4's default of 5.0: a host answering a thousand times slower
     * than its own baseline has been in distress by every other rule for a
     * long time.
     */
    private static final double MAX_LATENCY_MULTIPLE = 1_000.0;

    /**
     * Ceiling on {@code latencyFloorMs}. The floor SUPPRESSES rule 3 while the
     * host is still answering faster than it, so a floor nothing can exceed
     * suppresses it always: {@code Long.MAX_VALUE} is 292 million years and
     * rule 3 is off. A minute is past the point where an HTTP client has
     * usually given up and the sample has been recorded as a connection error
     * with a time-to-failure rather than as a latency at all -- so a floor
     * above it only ever suppresses stops it could never permit.
     */
    private static final long MAX_LATENCY_FLOOR_MS = 60_000L;

    private record Sample(long atUs, int status, long ms, boolean connectionError) { }

    /** Reason and host as one value, written once. See the class comment. */
    private record Stop(String reason, String host) { }

    /** One host's rolling window and its baseline. */
    private static final class Host {
        final Deque<Sample> window = new ArrayDeque<>();
        final long[] firstLatencies;
        int latencyCount = 0;
        boolean baselineReady = false;
        long baselineMs = 0;
        int consecutiveErrors = 0;

        Host(int baselineRequests) { this.firstLatencies = new long[baselineRequests]; }
    }

    private final Clock clock;
    private final double max5xxRate;
    private final double latencyMultiple;
    private final int maxConsecutiveErrors;
    private final int windowRequests;
    private final long windowMs;
    private final int baselineRequests;
    private final long latencyFloorMs;

    /** One entry per host. Scope bounds how many hosts a run may touch and the
     *  window bounds each entry, so this cannot grow without a scope that
     *  permits it. */
    private final Map<String, Host> hosts = new HashMap<>();

    private volatile Stop stop = null;

    /** The Interface Contract's constructor: §4's window and baseline, with the
     *  three thresholds supplied by the engagement config. */
    public Distress(Clock clock, double max5xxRate, double latencyMultiple,
                    int maxConsecutiveErrors) {
        this(clock, max5xxRate, latencyMultiple, maxConsecutiveErrors,
             DEFAULT_WINDOW_REQUESTS, DEFAULT_WINDOW_MS,
             DEFAULT_BASELINE_REQUESTS, DEFAULT_LATENCY_FLOOR_MS);
    }

    /**
     * Every knob. The validation is not defensive tidiness: the dangerous
     * direction of a mistyped engagement config is the one that DISABLES a
     * rule, and a zero-length window or a rate above 1.0 does exactly that
     * while leaving an object that looks configured and never trips. A value
     * set too tight only costs an early stop, which is the cheap failure.
     */
    public Distress(Clock clock, double max5xxRate, double latencyMultiple,
                    int maxConsecutiveErrors, int windowRequests, long windowMs,
                    int baselineRequests, long latencyFloorMs) {
        if (clock == null) throw new IllegalArgumentException("clock is required");
        // Strictly BELOW 1.0, not at it. The rate is fivexx/answered, so it
        // can never exceed 1.0, and "above the threshold" at a threshold of
        // 1.0 is a condition no traffic can meet: a host answering 100% 5xx
        // would not trip. NaN fails this test too, as it must.
        if (!(max5xxRate >= 0.0 && max5xxRate < 1.0))
            throw new IllegalArgumentException(
                "max5xxRate must be within 0.0..1.0 exclusive of 1.0, got " + max5xxRate
                + " -- the rate is 5xx/answered and cannot exceed 1.0, so a threshold "
                + "of 1.0 is one no traffic can be above and rule 2 never fires");
        if (!(latencyMultiple >= 1.0 && latencyMultiple <= MAX_LATENCY_MULTIPLE))
            throw new IllegalArgumentException(
                "latencyMultiple must be within 1.0.." + MAX_LATENCY_MULTIPLE + ", got "
                + latencyMultiple + " -- the threshold is baselineMs * latencyMultiple, so "
                + "an infinite or absurd multiple is one no p50 can exceed and rule 3 "
                + "never fires");
        if (maxConsecutiveErrors < 1 || maxConsecutiveErrors > MAX_CONSECUTIVE_ERRORS)
            throw new IllegalArgumentException(
                "maxConsecutiveErrors must be within 1.." + MAX_CONSECUTIVE_ERRORS + ", got "
                + maxConsecutiveErrors + " -- the streak is not bounded by the window, so a "
                + "threshold above the requests a run will issue is one rule 1 never reaches");
        if (windowRequests < 1 || windowRequests > MAX_WINDOW_REQUESTS)
            throw new IllegalArgumentException(
                "windowRequests must be within 1.." + MAX_WINDOW_REQUESTS + ", got "
                + windowRequests + " -- each host allocates a long[] of the baseline size and "
                + "holds this many samples, so an unbounded window is an unbounded allocation "
                + "inside Burp's JVM");
        if (windowMs < 1)
            throw new IllegalArgumentException("windowMs must be >= 1, got " + windowMs);
        if (windowMs > MAX_WINDOW_MS)
            throw new IllegalArgumentException(
                "windowMs above the " + MAX_WINDOW_MS + " ms (24 h) ceiling: " + windowMs
                + " -- the effective window is whichever of windowRequests and windowMs is "
                + "SHORTER, so past a few minutes a 50-request window is already count-only "
                + "and no live engagement runs a rolling distress window longer than a day; "
                + "set windowRequests (itself bounded at " + MAX_WINDOW_REQUESTS + ") if you "
                + "want the window bounded by count");
        // Not merely >= 1: the window holds at most windowRequests samples, so
        // a baseline larger than the window is one that `answered` can never
        // reach -- rule 2's gate stays shut for the life of the run and the
        // rate is never computed at all. It also bounds the per-host long[].
        if (baselineRequests < 1 || baselineRequests > windowRequests)
            throw new IllegalArgumentException(
                "baselineRequests must be within 1..windowRequests (" + windowRequests
                + "), got " + baselineRequests + " -- the window holds at most windowRequests "
                + "samples, so a larger baseline is one the 5xx-rate gate never reaches and "
                + "rule 2 never fires");
        if (latencyFloorMs < 0 || latencyFloorMs > MAX_LATENCY_FLOOR_MS)
            throw new IllegalArgumentException(
                "latencyFloorMs must be within 0.." + MAX_LATENCY_FLOOR_MS + ", got "
                + latencyFloorMs + " -- the floor suppresses rule 3 while the host answers "
                + "faster than it, so a floor no response can exceed suppresses it always");

        this.clock = clock;
        this.max5xxRate = max5xxRate;
        this.latencyMultiple = latencyMultiple;
        this.maxConsecutiveErrors = maxConsecutiveErrors;
        this.windowRequests = windowRequests;
        this.windowMs = windowMs;
        this.baselineRequests = baselineRequests;
        this.latencyFloorMs = latencyFloorMs;
    }

    /**
     * Report one issued request.
     *
     * {@code status} is the HTTP status, or 0 when {@code connectionError} is
     * true -- a refused, reset or timed-out connection has no status, and
     * {@code ms} is then time-to-failure rather than service latency.
     *
     * A NEGATIVE {@code ms} is clamped to zero rather than refused. It should
     * not happen -- it means the caller's own start and end readings went
     * backwards -- but the request has already gone out by the time record()
     * sees it, and dropping the sample would shrink the window the rules
     * decide from, which is the disarming direction. Clamping keeps the sample
     * and moves the baseline DOWN, which can only make rule 3 more eager; and
     * it keeps the figure out of the report, where a single {@code -1} used to
     * establish a {@code -1 ms} baseline and print "exceeds 5.0x the -1 ms
     * baseline" into {@code run.stop_reason}.
     *
     * Synchronised because the send path can be driven from more than one Burp
     * thread. These are microsecond operations over a 50-element deque, and an
     * auto-halt computed from a torn window is worse than a slow one.
     */
    public synchronized void record(String host, int status, long ms, boolean connectionError) {
        if (stop != null) return;                 // sticky: see the class comment
        long nowUs = clock.nowUs();
        long observedMs = Math.max(ms, 0L);      // see the javadoc: never below zero
        Host h = hosts.computeIfAbsent(host, unused -> new Host(baselineRequests));

        h.window.addLast(new Sample(nowUs, status, observedMs, connectionError));
        evict(host, h, nowUs);
        if (stop != null) return;                  // evict() can trip on unrepresentable arithmetic

        // Captured BEFORE this sample can complete the baseline. §4 takes the
        // baseline from "that host's first 10 requests", so the tenth request
        // establishes it and the eleventh is the first measured against it.
        boolean baselineWasReady = h.baselineReady;

        if (connectionError) {
            h.consecutiveErrors++;
            if (h.consecutiveErrors >= maxConsecutiveErrors) {
                trip(host, h.consecutiveErrors + " consecutive connection errors");
                return;
            }
        } else {
            // A 503 is a RESPONSE: something answered, so the transport is up
            // and the streak is broken. It still counts against the rate below.
            h.consecutiveErrors = 0;
            if (!h.baselineReady) {
                h.firstLatencies[h.latencyCount++] = observedMs;
                if (h.latencyCount == baselineRequests) {
                    h.baselineMs = p50(Arrays.copyOf(h.firstLatencies, h.latencyCount));
                    h.baselineReady = true;
                }
            }
        }

        // Fixed order, so the recorded reason is stable when more than one rule
        // fires on the same request: transport first, then errors we are
        // causing, then exhaustion we are causing.
        if (tripOn5xxRate(host, h)) return;
        if (baselineWasReady) tripOnLatency(host, h);
    }

    /**
     * Both bounds, so the effective window is whichever is shorter. A sample
     * exactly {@code windowMs} old is still inside it; one microsecond older is
     * not, and DistressTest pins both sides of that edge.
     *
     * {@code cutoffUs} used to be {@code nowUs - windowMs * 1000L}, unsafe on
     * EITHER operand: {@code windowMs * 1000L} overflows for a {@code windowMs}
     * an operator reaches for as a "no time bound" sentinel ({@code
     * Long.MAX_VALUE} -- now refused by the constructor, see {@link
     * #MAX_WINDOW_MS}), and {@code nowUs - (...)} underflows for a clock
     * reading near {@code Long.MIN_VALUE}, which no constructor can see coming
     * because it runs before any clock is ever read. Either overflow used to
     * silently disable the 5xx-rate and latency rules -- the window got wiped,
     * or never aged, on every {@link #record} while {@link #stopReason()}
     * stayed {@code null} forever, which reads as a healthy target. The
     * arithmetic is now exact ({@link Math#multiplyExact} / {@link
     * Math#subtractExact}). Only the SUBTRACTION can still throw: {@link
     * #MAX_WINDOW_MS} caps {@code windowMs} at 86,400,000, so {@code
     * multiplyExact(windowMs, 1000L)} tops out at 8.64e10 and is unreachable
     * dead code today. It is kept because it makes this expression safe on its
     * own terms rather than by a constant declared two hundred lines away --
     * exactly the coupling that would break the day somebody raises that
     * ceiling. On overflow this TRIPS instead of continuing:
     * if the window bound cannot be computed, {@code Distress} cannot tell
     * whether the target is healthy, and that is not a state in which to keep
     * issuing requests. A spurious halt costs an operator a restart; the other
     * direction costs a client an outage.
     *
     * The time loop also no longer stops at the first non-expired element at
     * the front: a transient forward clock spike followed by a backward
     * correction leaves a sample with an inflated timestamp sitting at the
     * front, and breaking there would leave genuinely stale samples stuck
     * behind it in the deque until the count cap above eventually flushes
     * them. So every sample is checked and nothing short-circuits the scan --
     * cheap, since the deque holds at most {@code windowRequests} of them.
     *
     * Eviction runs on record, so the window a rule sees is the window as of
     * the request that provoked it -- which is the one the stop reason quotes.
     */
    private void evict(String host, Host h, long nowUs) {
        while (h.window.size() > windowRequests) h.window.removeFirst();

        long cutoffUs;
        try {
            cutoffUs = Math.subtractExact(nowUs, Math.multiplyExact(windowMs, 1000L));
        } catch (ArithmeticException overflow) {
            trip(host, "distress window arithmetic overflowed: cannot tell whether "
                       + host + " is healthy");
            return;
        }

        Iterator<Sample> it = h.window.iterator();
        while (it.hasNext()) {
            if (it.next().atUs() < cutoffUs) it.remove();
        }
    }

    /** @return true if this tripped the run. */
    private boolean tripOn5xxRate(String host, Host h) {
        int answered = 0, fivexx = 0;
        for (Sample s : h.window) {
            if (s.connectionError()) continue;     // no status: not this rule's evidence
            answered++;
            if (s.status() >= 500 && s.status() <= 599) fivexx++;
        }
        if (answered < baselineRequests) return false;
        double rate = (double) fivexx / answered;
        // "above 20%": exactly at the threshold is not above it.
        if (rate <= max5xxRate) return false;
        // Locale.ROOT: this string is written into run.stop_reason and read in
        // a report. A JVM started under a comma-decimal locale would otherwise
        // record "27,3%".
        trip(host, String.format(Locale.ROOT,
                "5xx rate %.1f%% over the last %d requests exceeds %.1f%%",
                rate * 100.0, answered, max5xxRate * 100.0));
        return true;
    }

    private void tripOnLatency(String host, Host h) {
        long[] latencies = new long[h.window.size()];
        int n = 0;
        for (Sample s : h.window) if (!s.connectionError()) latencies[n++] = s.ms();
        if (n == 0) return;
        long p50 = p50(Arrays.copyOf(latencies, n));
        // max(baselineMs, 1) keeps the arithmetic honest for a sub-millisecond
        // baseline; the floor keeps the VERDICT honest for one. Both are needed:
        // without the clamp a 0 ms baseline makes every threshold 0, and without
        // the floor a 1 ms baseline makes 6 ms a distress signal.
        double threshold = Math.max(h.baselineMs, 1L) * latencyMultiple;
        if (p50 <= threshold || p50 < latencyFloorMs) return;
        trip(host, String.format(Locale.ROOT,
                "p50 latency %d ms over the last %d requests exceeds %.1fx the %d ms baseline",
                p50, n, latencyMultiple, h.baselineMs));
    }

    /**
     * Nearest-rank p50: the lower of the two middles for an even count, so the
     * figure quoted in the stop reason is a latency that was actually observed
     * and not an interpolation between two that were not.
     */
    private static long p50(long[] xs) {
        long[] sorted = xs.clone();
        Arrays.sort(sorted);
        return sorted[(sorted.length - 1) / 2];
    }

    /**
     * Written once and never overwritten. Nothing is logged and nothing is
     * called out to: this object decides, and the Sender is what emits §6's
     * unsolicited {@code halted} frame and marks the run aborted. Giving the
     * policy core an I/O dependency is exactly what the split in §3 forbids.
     */
    private void trip(String host, String reason) {
        stop = new Stop(reason, host);
    }

    /** Null while healthy; once tripped, why. One volatile read. */
    public String stopReason() {
        Stop s = stop;
        return s == null ? null : s.reason();
    }

    /** Null while healthy; once tripped, the host that caused it. */
    public String stopHost() {
        Stop s = stop;
        return s == null ? null : s.host();
    }

    /** The {@code window} field of §6's {@code halted} frame. */
    public String window() {
        return "last " + windowRequests + " requests or " + windowMs + " ms";
    }

    /** Test seam: the baseline p50 in milliseconds for {@code host}, or -1
     *  while the first {@code baselineRequests} answered requests are still
     *  being collected. -1 rather than 0 because 0 ms is a real baseline on
     *  loopback. Package-private, and Distress is final, so it cannot escape
     *  hx.policy; the boundary between "establishing" and "measured against"
     *  has no other observable. */
    synchronized long baselineMs(String host) {
        Host h = hosts.get(host);
        return (h == null || !h.baselineReady) ? -1 : h.baselineMs;
    }

    /** Test seam: how many samples the window holds for {@code host} after the
     *  last record evicted by count and by age. */
    synchronized int windowSize(String host) {
        Host h = hosts.get(host);
        return h == null ? 0 : h.window.size();
    }
}
