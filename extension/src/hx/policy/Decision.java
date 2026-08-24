// extension/src/hx/policy/Decision.java
package hx.policy;

/**
 * A verdict. `errorClass` is one of the classes in spec s6 -- the agent
 * switches on it, and the distinction is load-bearing: `rate_limited` means
 * slow down and retry, the three `*_denied` classes mean the answer will not
 * change, and `budget_exhausted` means this run is over.
 *
 * `retryAfterUs` is meaningful only for `rate_limited`; every other verdict
 * leaves it 0, and LimiterTest pins that.
 */
public record Decision(boolean allowed, String errorClass, String detail, long retryAfterUs) {

    private static final Decision ALLOW = new Decision(true, null, null, 0L);

    /** Shared: an allow carries no state, and the send path makes one per
     *  request on the hot path. */
    public static Decision allow() { return ALLOW; }

    public static Decision deny(String errorClass, String detail) {
        return new Decision(false, errorClass, detail, 0L);
    }

    /** The one verdict that carries a retry hint. The class is set here rather
     *  than by the caller so a typo cannot produce a denial the agent does not
     *  recognise and therefore does not back off from. */
    public static Decision rateLimited(long retryAfterUs, String detail) {
        return new Decision(false, "rate_limited", detail, retryAfterUs);
    }
}
