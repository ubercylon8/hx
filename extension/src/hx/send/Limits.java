// extension/src/hx/send/Limits.java
package hx.send;

import hx.bridge.BridgeClient;
import hx.policy.Clock;
import hx.policy.Decision;
import hx.policy.Gate;
import hx.policy.HxRequest;
import hx.policy.Limiter;

import java.util.List;

/**
 * The Gate Policy consults, holding the rate and budget an operator
 * configured.
 *
 * `limit.rate_rps` and `limit.max_requests` are two of the keys ConfigBody
 * already accepts, so they arrive in the Authorisation snapshot beside the
 * scope they were configured with -- which is the only place they can be read
 * from coherently, and the same read the decision is made under.
 *
 * ARMED ONCE. Spec s4's rate and budget are engagement-config defaults rather
 * than constants, but the budget is also monotonic: Limiter has no refill,
 * because a scope push must not resupply a run that has spent its requests. So
 * the numbers are taken from the first authorisation that has an epoch and
 * held for the run; every later configure re-authorises scope, which is what a
 * configure is for.
 *
 * The defaults in the constructor are what a configure body that omits a key
 * gets. They are not a policy of their own -- an omitted key means the
 * operator expressed no opinion, and this jar's built-in number is the only
 * answer left.
 */
public final class Limits implements Gate {

    private final Clock clock;
    private final long defaultRatePerSecond;
    private final long defaultMaxRequests;

    // Written on the read-loop thread inside arm(), read by check() on the
    // same thread today -- but `limit.concurrency` is already in the configure
    // body, and the day it is honoured these are cross-thread reads.
    private volatile Limiter limiter;
    private volatile long ratePerSecond;
    private volatile long maxRequests;

    public Limits(Clock clock, long defaultRatePerSecond, long defaultMaxRequests) {
        this.clock = clock;
        this.defaultRatePerSecond = defaultRatePerSecond;
        this.defaultMaxRequests = defaultMaxRequests;
    }

    /**
     * Build the Limiter from this snapshot's limit keys, once.
     *
     * Called before every decision and does nothing after the first. Epoch 0
     * is skipped rather than defaulted: it is the DENY-ALL snapshot, it
     * carries no configuration at all, and arming from it would fix the run's
     * numbers at this jar's built-ins before the operator's configure ever
     * arrived.
     *
     * A key that is present but is not a positive integer throws. Falling back
     * to the built-in default there is the one answer that is wrong in both
     * directions -- an operator who asked for 1 rps would silently get 5, and
     * one who asked for 500 would silently get 5 as well. BridgeClient's send
     * arm turns the throw into an error frame and DENY-ALL.
     */
    public synchronized void arm(BridgeClient.Authorisation auth) {
        if (limiter != null || auth.epoch() == 0) return;
        long rps = positive(auth, "limit.rate_rps", defaultRatePerSecond);
        long max = positive(auth, "limit.max_requests", defaultMaxRequests);
        ratePerSecond = rps;
        maxRequests = max;
        limiter = new Limiter(clock, rps, max);
    }

    @Override
    public Decision check(HxRequest req) {
        Limiter l = limiter;
        if (l == null)
            // Unreachable through HxExtension, which arms this from the same
            // snapshot before it calls issue() -- and Sender refuses epoch 0
            // as not_configured before Policy consults a Gate at all. A gate
            // that does not know its budget still has to answer no.
            return Decision.deny("not_configured", "the rate and budget are not armed");
        return l.check(req);
    }

    // Test seams, package-private, in the same shape as Distress's.
    long ratePerSecond() { return limiter == null ? 0L : ratePerSecond; }

    long maxRequests() { return limiter == null ? 0L : maxRequests; }

    long issued() {
        Limiter l = limiter;
        return l == null ? 0L : l.issued();
    }

    private static long positive(BridgeClient.Authorisation auth, String key, long fallback) {
        List<String> values = auth.scope().get(key);
        if (values == null || values.isEmpty()) return fallback;
        if (values.size() != 1)
            // The protocol document says "integer, once". This comment used to
            // say ConfigBody accumulates repeated keys and does not enforce
            // that, so it had to be enforced here; MEASURED FALSE on this
            // branch -- ConfigBody.parse now refuses a repeated
            // limit.rate_rps or limit.max_requests as a FrameError, which the
            // configure arm answers with bad_config and a live channel.
            //
            // parse() is the only production producer of the map this reads,
            // and both keys this is ever called with are in its
            // POSITIVE_INTEGER_KEYS, so THIS BRANCH IS UNREACHABLE IN
            // PRODUCTION TODAY. It stays as defence in depth against a
            // producer that never crossed the wire -- there is none now, and
            // the only caller that reaches it is this class's own test, which
            // builds its Authorisation directly. Two answers to "how fast" is
            // not a limit, wherever the map came from.
            throw new IllegalArgumentException(key + " was set " + values.size()
                + " times; it is an integer, once");
        String raw = values.get(0).strip();
        long n;
        try {
            n = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(key + " is not an integer: " + raw, e);
        }
        if (n <= 0)
            throw new IllegalArgumentException(key + " must be positive, not " + n);
        return n;
    }
}
