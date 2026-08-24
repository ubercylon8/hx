// extension/src/hx/send/Limits.java
package hx.send;

import hx.bridge.BridgeClient;
import hx.policy.Clock;
import hx.policy.Decision;
import hx.policy.Gate;
import hx.policy.HxRequest;
import hx.policy.Limiter;

import java.util.List;
import java.util.Map;

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
        long rps = positive(auth.scope(), "limit.rate_rps", defaultRatePerSecond);
        long max = positive(auth.scope(), "limit.max_requests", defaultMaxRequests);
        ratePerSecond = rps;
        maxRequests = max;
        limiter = new Limiter(clock, rps, max);
    }

    @Override
    public Decision check(HxRequest req) {
        Limiter l = limiter;
        if (l == null)
            // Unreachable through HxExtension, which calls arm() on the same
            // snapshot on the line before issue(): epoch 0 returns early from
            // arm() but is refused by Sender before Policy consults a Gate,
            // and every epoch >= 1 either arms this or throws. A gate that
            // does not know its budget still has to answer no.
            //
            // THIS BRANCH IS NOT ONE OF THE DENY-ALL GUARDS, and a fix wave on
            // this branch recorded that it was, so the correction is written
            // here rather than in a report. It is reached only when scope
            // ALLOWS -- Policy consults the Gate last, after scope, method and
            // dangerous.path -- so it cannot answer for an unconfigured run at
            // all. MEASURED, calling Policy.decide directly with a DENY-ALL
            // snapshot so that Sender's own epoch check is out of the way:
            // with Policy's epoch check AND checkScope's empty-include guard
            // both deleted, decide() still answers scope_denied from the
            // fallthrough at the end of checkScope, and this line is never
            // executed -- proved by making it return allow() instead, which
            // changed the answer not at all. It becomes reachable only if the
            // empty-include case is REWRITTEN to allow, which is not a
            // deletion. What it guards is the narrower thing its first
            // paragraph says: an armed-looking authorisation whose limiter was
            // never built.
            return Decision.deny("not_configured", "the rate and budget are not armed");
        return l.check(req);
    }

    /**
     * Why this configure's limits cannot be honoured, or null when they can.
     *
     * REFUSED, NOT IGNORED, and spec s4 says so since the 2026-08-23
     * amendment. The numbers are taken from the first authorisation that has
     * an epoch and held for the run -- see {@link #arm} for why the budget
     * must be monotonic -- so an operator pushing `limit.rate_rps: 1` mid-run
     * because the target is wobbling got a fresh `config_epoch`, no error, no
     * log line, and the old rate. The failure to avoid is an operator who
     * believes they slowed the run down and did not; lowering a rate is the
     * one change that is always safe, so being unable to do it must at least
     * be said out loud.
     *
     * This does not implement re-arming. It refuses, which BridgeClient's
     * configure arm turns into `bad_config` -- DENY-ALL first, channel kept,
     * so a corrected configure can follow. That is the same answer an
     * unparseable configure gets and for the same reason: carrying on under
     * the PREVIOUS limits is exactly the harm when an operator has just asked
     * for tighter ones.
     *
     * AN OMITTED KEY IS NOT A CHANGE. {@link #arm}'s own contract is that an
     * omitted key means the operator expressed no opinion and this jar's
     * built-in answers -- so a later configure narrowing SCOPE and saying
     * nothing about limits must go through. Reading the default and comparing
     * it would refuse the commonest configure there is: the one that fixes a
     * scope mistake.
     *
     * Before the first {@link #arm} there is nothing to contradict: the
     * configure being checked is the one that will supply the numbers.
     */
    public synchronized String refuseIfLimitsMoved(Map<String, List<String>> scope) {
        if (limiter == null || scope == null) return null;
        String rate = movedFrom(scope, "limit.rate_rps", ratePerSecond);
        if (rate != null) return rate;
        return movedFrom(scope, "limit.max_requests", maxRequests);
    }

    /** How {@code key} in this configure contradicts what is armed, or null. */
    private static String movedFrom(Map<String, List<String>> scope, String key, long armed) {
        List<String> values = scope.get(key);
        if (values == null || values.isEmpty()) return null;   // no opinion: not a change
        long asked;
        try {
            asked = positive(scope, key, armed);
        } catch (IllegalArgumentException e) {
            // A present-but-unusable value. Refusing HERE is strictly better
            // than where this used to surface: arm() throws on the next SEND,
            // which BridgeClient answers with `not_configured` and a closed
            // channel. bad_config keeps the channel and names the key.
            return e.getMessage();
        }
        if (asked == armed) return null;
        return key + " cannot change mid-run: this run armed at " + armed
             + " and this configure asks for " + asked
             + ". A configure re-authorises scope, not issuance -- the rate and"
             + " budget are taken from the first authorisation and held, because"
             + " the budget must not be resupplied by a scope push. Start a new"
             + " run for a new limit, or re-send this configure without " + key + ".";
    }

    // Test seams, package-private, in the same shape as Distress's.
    long ratePerSecond() { return limiter == null ? 0L : ratePerSecond; }

    long maxRequests() { return limiter == null ? 0L : maxRequests; }

    long issued() {
        Limiter l = limiter;
        return l == null ? 0L : l.issued();
    }

    private static long positive(Map<String, List<String>> scope, String key, long fallback) {
        List<String> values = scope.get(key);
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
