// extension/src/hx/policy/Distress.java
package hx.policy;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
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
        if (!(max5xxRate >= 0.0 && max5xxRate <= 1.0))
            throw new IllegalArgumentException("max5xxRate must be within 0.0..1.0, got " + max5xxRate);
        if (!(latencyMultiple >= 1.0))
            throw new IllegalArgumentException("latencyMultiple must be >= 1.0, got " + latencyMultiple);
        if (maxConsecutiveErrors < 1)
            throw new IllegalArgumentException("maxConsecutiveErrors must be >= 1, got " + maxConsecutiveErrors);
        if (windowRequests < 1)
            throw new IllegalArgumentException("windowRequests must be >= 1, got " + windowRequests);
        if (windowMs < 1)
            throw new IllegalArgumentException("windowMs must be >= 1, got " + windowMs);
        if (baselineRequests < 1)
            throw new IllegalArgumentException("baselineRequests must be >= 1, got " + baselineRequests);
        if (latencyFloorMs < 0)
            throw new IllegalArgumentException("latencyFloorMs must be >= 0, got " + latencyFloorMs);

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
     * Synchronised because the send path can be driven from more than one Burp
     * thread. These are microsecond operations over a 50-element deque, and an
     * auto-halt computed from a torn window is worse than a slow one.
     */
    public synchronized void record(String host, int status, long ms, boolean connectionError) {
        if (stop != null) return;                 // sticky: see the class comment
        long nowUs = clock.nowUs();
        Host h = hosts.computeIfAbsent(host, unused -> new Host(baselineRequests));

        h.window.addLast(new Sample(nowUs, status, ms, connectionError));
        evict(h, nowUs);

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
                h.firstLatencies[h.latencyCount++] = ms;
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
     * Eviction runs on record, so the window a rule sees is the window as of
     * the request that provoked it -- which is the one the stop reason quotes.
     */
    private void evict(Host h, long nowUs) {
        while (h.window.size() > windowRequests) h.window.removeFirst();
        long cutoffUs = nowUs - windowMs * 1000L;
        while (!h.window.isEmpty() && h.window.peekFirst().atUs() < cutoffUs) h.window.removeFirst();
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
