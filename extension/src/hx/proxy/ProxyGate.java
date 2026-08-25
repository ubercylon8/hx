// extension/src/hx/proxy/ProxyGate.java
package hx.proxy;

import hx.bridge.BridgeClient;
import hx.policy.Decision;
import hx.policy.HxRequest;
import hx.policy.Policy;

/**
 * S4's second enforcement point. Decides; does not record, dial, or queue.
 *
 * The split this class exists for, in one sentence: SCOPE IS ABSOLUTE FOR
 * EVERYONE, and the other four rules constrain an AGENT.
 *
 * The reasoning is in S4 and is worth repeating where it is implemented,
 * because the first version of the spec said otherwise. Method allowlist,
 * dangerous-path denylist, rate limit and budget exist so a bad check or a
 * runaway loop cannot hurt the client. A human clicking a form is a
 * deliberate act by the person legally responsible for the engagement, and
 * applying the agent's rules to them makes S9's highest-quality source of
 * attack surface unusable: `method.allow` refuses their login POST, the rate
 * limit throttles their browsing, the budget ends their session mid-page.
 * Enforcement that drives an operator off the proxy buys nothing -- they
 * browse without hx and the traffic is not recorded at all.
 *
 * Scope is different in kind. It is the client's boundary, the thing the
 * engagement letter names, and no caller may spend it.
 *
 * The two branches are two QUESTIONS asked of one Policy, not two policies:
 * `Policy.decide` is the full pinned order and `Policy.decideScopeOnly` stops
 * after scope. Which of the two a request gets is the whole of what
 * {@link Source} buys.
 */
public final class ProxyGate {
    private final Policy policy;

    /**
     * One Policy, and it carries the Gate. The rate limit and the budget live
     * inside the Policy this is constructed with (see {@link Policy#Policy}),
     * so a caller cannot hand this class a second Gate and end up spending two
     * budgets for one request -- and the operator branch spends neither,
     * because the question it asks stops before the Gate is reached.
     */
    public ProxyGate(Policy policy) {
        this.policy = policy;
    }

    public record Verdict(boolean allow, String errorClass, String detail) {
        static Verdict pass() { return new Verdict(true, null, null); }
        static Verdict deny(Decision d) {
            return new Verdict(false, d.errorClass(), d.detail());
        }
    }

    /**
     * @param auth   read ONCE by the caller and passed in, never fetched here.
     *               `configEpoch()` and `scopeConfig()` are two reads of one
     *               record and can straddle a commit; a decision made from two
     *               halves of different authorisations is a decision about a
     *               request nobody authorised.
     */
    public Verdict decide(HxRequest req, BridgeClient.Authorisation auth,
                          Source source) {
        if (auth == null || auth.epoch() == 0) {
            // DENY-ALL is the initial and terminal state, at BOTH points, and
            // this copy of it is REDUNDANT with the one inside Policy: both
            // questions below refuse an epoch-0 authorisation on their own, so
            // with these three lines deleted the four `DENY-ALL holds for`
            // checks in ProxyGateTest stay green -- measured, row D of this
            // task's sabotage table. What it changes is WHEN the answer is
            // given: here, before the Policy reference is touched at all. The
            // input that separates the two is a ProxyGate holding no Policy,
            // and ProxyGateTest uses it for exactly that.
            return new Verdict(false, "not_configured",
                               "no configure frame acknowledged yet");
        }
        if (source == Source.CRAWLER) {
            // The agent's rules, in S4's pinned order, Gate included.
            Decision d = policy.decide(req, auth);
            return d.allowed() ? Verdict.pass() : Verdict.deny(d);
        }
        // The operator: scope, and nothing after it. Not a weaker call of the
        // same question -- a different question, which is why it is a sibling
        // method on Policy rather than a flag passed to `decide`. It does not
        // reach the Gate, so an operator's browsing spends no rate token and
        // no budget slot; the pair of counting checks in ProxyGateTest is what
        // separates that from a gate that ignores source entirely.
        Decision d = policy.decideScopeOnly(req, auth);
        return d.allowed() ? Verdict.pass() : Verdict.deny(d);
    }
}
