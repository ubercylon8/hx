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
 * Time comes from an injected {@link Clock} so the bucket can be tested at its
 * exact boundaries instead of approached with sleeps.
 *
 * THE GUARANTEE, AND IT CHANGED ON 2026-09-04. This was a sliding log of the
 * last `ratePerSecond` issue times, which was exact: at no instant could more
 * than `ratePerSecond` issuances lie within any one-second window. Its own
 * docstring rejected a token bucket in those words, because a bucket "would
 * let 2*rate through a window that straddles a refill, and this limit is the
 * one a client's operations team would be reading off a graph".
 *
 * That argument was right and is not withdrawn. It was overruled, knowingly,
 * for a measured reason: under a sliding log the crawler CANNOT LOAD A MODERN
 * SINGLE-PAGE APPLICATION AT ALL. Measured against OWASP Juice Shop, its
 * Angular bundle fires nine requests in about 130 milliseconds; at 5/s the
 * four over the limit were refused, Burp answers a refusal with 200 and an
 * HTML body, the browser refused those as module scripts under strict MIME
 * checking, and the application never started. Not "covered less" -- did not
 * run. The crawl saw 5 requests where a direct browser makes 41.
 *
 * So the guarantee is now WEAKER AND MUST BE STATED AS SUCH:
 *
 *   - the SUSTAINED rate is still exactly `ratePerSecond`, over any window
 *     long enough for the bucket to empty;
 *   - the worst case within any ONE second is `burst + ratePerSecond`, which
 *     is what a straddling window can carry.
 *
 * At the default `burst = ratePerSecond` that is 2*rate for one second, which
 * is precisely the spike the old comment warned about. It is the shape of one
 * page load -- the same fan-out an ordinary visitor's browser produces -- and
 * it cannot be sustained. An operator who needs the old promise sets
 * `limit.rate_burst` to 1 and gets a bucket that never holds a second token.
 *
 * WHAT AN OPERATIONS TEAM SEES has therefore changed, and a report that said
 * "5 requests per second" while a graph showed ten in one second would be the
 * kind of quiet inaccuracy this project refuses elsewhere. The number to quote
 * a client is `rate_limit_rps` sustained, `rate_limit_rps + rate_burst` peak.
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

    /** Micro-tokens in one request. Tokens are scaled so refill stays in
     *  integer arithmetic: `elapsedUs * ratePerSecond` IS micro-tokens,
     *  because 1_000_000 us of elapsed time at R/s earns R requests. */
    private static final long ONE_REQUEST = 1_000_000L;

    private final Clock clock;
    private final long ratePerSecond;
    private final long maxRequests;
    /** Burst capacity in REQUESTS. The sustained rate is still
     *  `ratePerSecond`; this only changes the shape over sub-second windows. */
    private final long burst;
    private final long capacityMicro;
    /** The longest elapsed time worth counting: past this the bucket is full,
     *  and the cap is what keeps `elapsed * ratePerSecond` from overflowing. */
    private final long fullRefillUs;

    private long tokensMicro;
    private long lastRefillUs;


    private long issued = 0;

    /** The old sliding log's allowance, expressed as a bucket: it permitted
     *  `ratePerSecond` issuances back to back, so that is the burst every
     *  caller gets unless one is configured. Not zero -- a zero burst holds a
     *  single token and would REFUSE the second of five simultaneous
     *  requests the sliding log allowed, which is a tightening no operator
     *  asked for. */
    public Limiter(Clock clock, long ratePerSecond, long maxRequests) {
        this(clock, ratePerSecond, maxRequests, ratePerSecond);
    }

    /**
     * WHY A BURST EXISTS, measured 2026-09-03 against OWASP Juice Shop.
     *
     * Its Angular bundle fires nine requests in about 130 milliseconds. Under
     * the staging profile's 5/s the four over the limit were denied --
     * correctly, and recorded in `denial`. But Burp answers a denial with
     * HTTP 200 and an HTML body, so the browser saw `200 text/html` where it
     * expected an ES module, refused it under strict MIME checking, and the
     * application never started. The crawl saw 5 requests instead of 41 and
     * reached none of the parameterised API endpoints a scan exists to probe.
     *
     * A rate-limited image is merely missing. A rate-limited MODULE SCRIPT
     * stops the whole application. The limit was enforcing the right TOTAL
     * against the wrong SHAPE: a browser's page-load fan-out is a burst that
     * any ordinary visitor also generates, not the sustained hammering this
     * class exists to prevent.
     *
     * A token bucket fixes the shape and not the total. With burst B and rate
     * R, at most B requests may go out back-to-back after an idle period, and
     * the SUSTAINED rate is still exactly R -- which is the property a client
     * is owed. The three-argument constructor passes
     * `burst = ratePerSecond`, which is what the sliding log this replaced
     * already allowed -- it permitted R issuances in the same instant. A
     * `burst` of 0 would hold a single token and REFUSE the second of those,
     * a tightening no operator asked for, so it is not the default.
     */
    public Limiter(Clock clock, long ratePerSecond, long maxRequests, long burst) {
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
        // Refused rather than clamped, for the reason the rate check above
        // gives: a limit may not widen itself. A negative burst is a config
        // error, not a request to disable bursting -- that is `burst = 0`.
        if (burst < 0)
            throw new IllegalArgumentException("limit.rate_burst must not be negative, got " + burst);
        if (burst > MAX_RATE)
            throw new IllegalArgumentException(
                "limit.rate_burst above the " + MAX_RATE + " ceiling: " + burst);
        this.clock = clock;
        this.ratePerSecond = ratePerSecond;
        this.maxRequests = maxRequests;
        this.burst = burst;
        // At least one request's worth, or nothing could ever be issued.
        this.capacityMicro = Math.max(ONE_REQUEST, burst * ONE_REQUEST);
        this.fullRefillUs = capacityMicro / ratePerSecond + 1;
        // STARTS FULL. An engagement's first request should not wait for a
        // bucket to fill, and starting empty would make the first page load
        // the one most likely to be throttled -- exactly the case this
        // constructor exists for.
        this.tokensMicro = capacityMicro;
        this.lastRefillUs = clock.nowUs();
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
        // REFILL FIRST, then spend. `elapsed` is bounded before the multiply
        // so `elapsed * ratePerSecond` cannot overflow: past `fullRefillUs`
        // the bucket is full anyway, so counting further time buys nothing.
        //
        // A clock that went backwards -- or a subtraction that wrapped --
        // gives a negative `elapsed` and is skipped, which FAILS CLOSED: no
        // refill means fewer tokens, never more. That is the same direction
        // the sliding log this replaced was careful about, for the same
        // reason: a limit may drift toward refusing, never toward allowing.
        long elapsed = now - lastRefillUs;
        if (elapsed > 0) {
            if (elapsed > fullRefillUs) elapsed = fullRefillUs;
            long refilled = tokensMicro + elapsed * ratePerSecond;
            tokensMicro = refilled > capacityMicro ? capacityMicro : refilled;
            lastRefillUs = now;
        }

        if (tokensMicro < ONE_REQUEST) {
            // Ceiling division: a retry-after that rounded DOWN would invite
            // the caller back a tick before a token exists, and be told no
            // again.
            long shortfall = ONE_REQUEST - tokensMicro;
            long retryUs = (shortfall + ratePerSecond - 1) / ratePerSecond;
            return Decision.rateLimited(retryUs,
                "rate limit " + ratePerSecond + "/s (burst " + burst
                + "): no token available");
        }

        if (issued >= maxRequests) {
            return Decision.deny("budget_exhausted",
                "run budget spent: " + issued + " of " + maxRequests + " requests issued");
        }

        tokensMicro -= ONE_REQUEST;
        issued++;
        return Decision.allow();
    }

    /** How many requests this run has actually issued. Refusals are not
     *  issuances and do not appear here. */
    public synchronized long issued() { return issued; }
}
