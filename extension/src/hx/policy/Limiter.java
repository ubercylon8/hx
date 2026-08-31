// extension/src/hx/policy/Limiter.java
package hx.policy;

/**
 * Rate limit and per-run budget -- the two checks that stand between a looping
 * check and the 320 req/s the probe measured Montoya's single-request egress
 * call sustaining (spec section 2). Burp Community imposes no request-rate
 * throttle of its own, so this class is the throttle.
 *
 * Both limits are WHOLE-RUN, not per-host: five requests a second spread over
 * ten hosts is fifty requests a second into one client's estate, and the estate
 * is what the limit exists to protect. `check` therefore ignores everything
 * about the request it is handed.
 *
 * Time comes from an injected {@link Clock} so the window can be tested at its
 * exact boundaries instead of approached with sleeps. The rate window is a
 * sliding log of the last `ratePerSecond` issue times, which is exact: at no
 * instant can more than `ratePerSecond` issuances lie within any one-second
 * window. A token bucket would be cheaper and would let 2*rate through a window
 * that straddles a refill, and this limit is the one a client's operations team
 * would be reading off a graph.
 */
public final class Limiter implements Gate {

    /** One second, in the microseconds every clock in hx measures. */
    private static final long WINDOW_US = 1_000_000L;

    /**
     * Ceiling on `ratePerSecond`, because the sliding log allocates one long
     * per permitted request per second. Ten thousand is 80 KB and is already
     * absurd for this tool -- spec section 4 puts a production profile in the
     * single digits -- so a value above it is a typo in the engagement config,
     * and a typo should not get to allocate an array inside Burp's JVM.
     */
    private static final long MAX_RATE = 10_000L;

    private final Clock clock;
    private final long ratePerSecond;
    private final long maxRequests;

    /**
     * Issue times of the last `ratePerSecond` issuances. The slot at
     * `issued % ratePerSecond` holds the OLDEST of them, because it is the one
     * the next issuance overwrites. Never read before `issued` reaches
     * `ratePerSecond`, so the zeroes it starts life with are never mistaken for
     * issue times.
     */
    private final long[] recent;

    private long issued = 0;

    public Limiter(Clock clock, long ratePerSecond, long maxRequests) {
        if (clock == null)
            throw new IllegalArgumentException("a limiter without a clock cannot limit anything");
        // A rate of zero is refused rather than clamped to one. Clamping widens
        // the limit the operator actually wrote, which is the one direction a
        // safety limit may never move on its own; refusing surfaces as a
        // bad_config error and DENY-ALL, which is the direction it may.
        if (ratePerSecond < 1)
            throw new IllegalArgumentException("limit.rate_rps must be at least 1, got " + ratePerSecond);
        if (ratePerSecond > MAX_RATE)
            throw new IllegalArgumentException(
                "limit.rate_rps above the " + MAX_RATE + " ceiling: " + ratePerSecond);
        if (maxRequests < 0)
            throw new IllegalArgumentException("limit.max_requests must not be negative, got " + maxRequests);
        this.clock = clock;
        this.ratePerSecond = ratePerSecond;
        this.maxRequests = maxRequests;
        this.recent = new long[(int) ratePerSecond];
    }

    /**
     * Consult the gate and, when it allows, SPEND the slot. This is not a pure
     * predicate: an allow is recorded as an issuance, so calling `check` twice
     * for one request costs two slots and one budget unit.
     *
     * That is safe here because an allow is only ever spent on a request the
     * published decision order -- not_configured, halted, scope, method,
     * dangerous, rate, budget -- has already cleared, so nothing downstream
     * can turn round and ISSUE MORE than this budget allowed.
     *
     * IT CAN SPEND MORE THAN IT SENDS, AND THE RULE THIS PARAGRAPH USED TO
     * STATE -- "anything that grows a new refusal AFTER the gate must run
     * before it instead" -- HAS BEEN FALSE SINCE THE IDENTITY BRANCH.
     * {@code Sender.decide} asks two identity questions after this gate
     * (`unknown_identity` and `identity_origin`, Sender.java:325,331), and
     * they are there because neither can be asked until the send frame has
     * been read and neither is worth resolving for a request the boundary
     * checks are about to turn away. So a probe refused by either has
     * already cost a rate slot and a budget unit while the target saw
     * nothing, and `requests_sent` for that row reads 0.
     *
     * THE BURN IS ACCEPTED RATHER THAN FIXED, and the false rule is
     * corrected rather than deleted because it had already made one
     * implementer's brief reason from a premise the tree does not obey. It
     * fails in one direction only: it can make hx send FEWER requests than
     * the client authorised, never more, and it reaches no client-facing
     * number -- `run.requests_issued` is written by `hx.capture` alone and
     * the report renders no request tally. When identity refusals do exhaust
     * the budget, the next liveness canary is refused `budget_exhausted`,
     * which halts the run or downgrades it to `assumed`; both fail safe.
     * `src/hx/checks/probe.py`'s `ProbeSender.refused` documents the same
     * divergence from the Python side.
     *
     * `synchronized` because a rate limit that races is not a rate limit: two
     * threads reading `issued` before either writes it both see room and both
     * issue. Burp calls extension code from more than one thread and the send
     * path is explicitly allowed to be concurrent (limit.concurrency).
     */
    @Override
    public synchronized Decision check(HxRequest req) {
        long now = clock.nowUs();

        // Rate is answered before budget: the published decision order is
        // ... dangerous -> rate_limited -> budget_exhausted and the earliest
        // matching rule wins. A run that is both over rate and out of budget
        // therefore answers "retry in N" once before answering "this run is
        // over" -- one wasted wait, in exchange for one order that every layer
        // and every test agrees on.
        if (issued >= ratePerSecond) {
            long oldest = recent[(int) (issued % ratePerSecond)];
            // An issuance is inside the window while now - oldest < WINDOW_US,
            // so it leaves in exactly WINDOW_US - (now - oldest). That is
            // computed as two subtractions rather than as
            // `oldest + WINDOW_US` compared against `now`: adding a constant
            // to a clock reading near Long.MAX_VALUE overflows and wraps
            // negative, which would make an issuance that is still inside the
            // window look like it left long ago -- and ALLOW a request that
            // should be refused. Subtracting two nearby clock readings CAN
            // still overflow -- oldest = Long.MIN_VALUE, now = Long.MAX_VALUE
            // wraps to -1 -- but only in the FAIL-CLOSED direction: a wrapped
            // `elapsed` is always deeply negative, so it always reads as
            // still inside the window and DENIES. It can never produce a
            // false ALLOW, because any pair whose true difference is under
            // WINDOW_US must already be within that same 1,000,000 of each
            // other, nowhere near the ~9.22e18 magnitude a wrap requires.
            // Strictly less-than is what makes retryAfterUs positive whenever
            // this branch is taken: if the elapsed time equalled WINDOW_US
            // exactly, the issuance would already be outside the window and
            // we would not be here.
            long elapsed = now - oldest;
            if (elapsed < WINDOW_US) {
                return Decision.rateLimited(WINDOW_US - elapsed,
                    "rate limit " + ratePerSecond + "/s: " + ratePerSecond
                    + " requests issued in the last second");
            }
        }

        // Monotonic by construction: `issued` only ever increases and
        // `maxRequests` is final, so a budget that is spent stays spent. There
        // is deliberately no way to refill it -- see LimiterTest's reflection
        // check. A `configure` frame re-authorises SCOPE, not ISSUANCE, and a
        // scope push that silently handed the run another thousand requests
        // would be a budget reset with no operator behind it.
        if (issued >= maxRequests) {
            return Decision.deny("budget_exhausted",
                "run budget spent: " + issued + " of " + maxRequests + " requests issued");
        }

        recent[(int) (issued % ratePerSecond)] = now;
        issued++;
        return Decision.allow();
    }

    /** How many requests this run has actually issued. Refusals are not
     *  issuances and do not appear here. */
    public synchronized long issued() { return issued; }
}
