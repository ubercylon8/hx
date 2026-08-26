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
 *
 * THIS POINT DOES NOT CHECK THE HALT, AND THAT IS A STATED GAP, NOT AN
 * OVERSIGHT. S4's decision order puts `halted` second. This class asks
 * {@link Policy}, and Policy does not know about halts -- the send path asks
 * {@link hx.send.HaltSwitch} separately, through
 * `Sender.issuanceHeldReason`. So while the run is HALTED, proxy traffic keeps
 * flowing and keeps being recorded.
 *
 * WHAT THAT ACTUALLY COSTS, stated in full because the comfortable version of
 * it was wrong. It is not only "a human who hit stop can close their browser".
 * FOUR things set the halt and only one of them is that human:
 *
 *   - a `halt` FRAME the operator sent. This is the comfortable case, and the
 *     browser is in their hands;
 *   - the SENTINEL FILE, S4's third kill path -- the one that works when the
 *     bridge does not. Someone reaching for that has already lost the channel;
 *   - the AUTO-HALT on target distress. NOT a human decision: S4 aborts the
 *     whole run above a 20% 5xx rate, above 5x the baseline p50 latency, or
 *     after 5 consecutive connection errors. hx has decided the target is in
 *     trouble and the operator's browser is still hitting it;
 *   - a halt RE-ASSERTED AFTER A RECONNECT, because an operator halt is
 *     durable and a fresh `hello` does not clear it. The operator may not be
 *     at the keyboard at all.
 *
 * AND IT RUNS THE OTHER WAY TOO: operator browsing feeds nothing into
 * `Distress`, which is fed from the SEND path's replies only. So operator
 * traffic can distress a host without ever tripping the auto-halt, and would
 * not be stopped by it if something else did.
 *
 * The ruling stands anyway, for the reason below -- closing the gap without
 * the row to put the refusal in breaks S4 with the fix for S4 -- and the
 * crawler, where the four above bite hardest, does not exist yet.
 *
 * WHAT PLAN 5 MUST DO TO CLOSE IT, written here because this is where its
 * implementer will look. Answering `halted` from this class is NOT a one-line
 * change: `halted` has to be added to `records.DENIAL_KIND` and to the
 * `denial.kind` CHECK in schema.sql (with the SCHEMA_VERSION bump that
 * implies), or `hx.capture`'s denial arm routes it to `row_for(...) is None`,
 * returns without writing anything, and the refusal VANISHES -- S4's "denials
 * are never silent" broken by the fix for S4. The condition is therefore:
 * close the gap and the row at the same time, or not at all.
 *
 * THERE IS A THIRD ANSWER AND IT IS NEITHER QUESTION. A source this class
 * cannot recognise -- `Source.UNATTRIBUTED`, or a null -- is REFUSED here
 * without asking Policy anything. The lenient branch is chosen for a human
 * whose deliberate act it is; "we could not work out who is driving" is a code
 * failure or a change in Burp, and defaulting it to the branch that drops four
 * of the five rules is a fail-open dressed as a default.
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
            // with these three lines deleted the three `DENY-ALL holds for`
            // checks in ProxyGateTest -- one per Source constant -- stay
            // green. Re-measured on this tree after the third constant was
            // added: 9 x ALL PASS + 1 FAILURE, 1652 ok, and the single FAIL is
            // an NPE out of unconfiguredRefusesBoth, not a check saying an
            // unconfigured extension allowed something. (Row D of this task's
            // sabotage table measured the same mutation when Source had two
            // constants.) What these lines change is WHEN the answer is given:
            // here, before the Policy reference is touched at all. The input
            // that separates the two is a ProxyGate holding no Policy, which
            // is where that NPE comes from and what ProxyGateTest uses it for.
            //
            // `== 0`, not `< 1`, at BOTH enforcement points (the other copy is
            // Policy.unusable). That is a REACHABILITY argument and not a
            // range check: epoch is a long, and a hand-built
            // `new Authorisation(-1, scope)` is treated as CONFIGURED and
            // decided under, here and there alike -- measured. Nothing in this
            // tree can produce one, because BridgeClient's counter is
            // pre-incremented from 0 and is the only writer of the field, so
            // the inherited shape is kept and the reachability is written down
            // rather than left for the next reader to re-derive.
            return new Verdict(false, "not_configured",
                               "no configure frame acknowledged yet");
        }
        if (source != Source.OPERATOR && source != Source.CRAWLER) {
            // UNATTRIBUTED, null, and anything a later constant adds. Written
            // as "not one of the two I know" rather than as
            // `source == Source.UNATTRIBUTED`, because the enum is CLOSED and
            // a fourth constant added later would otherwise fall into
            // whichever branch it was not named in -- and the operator branch
            // is the one it would fall into.
            //
            // Two separating inputs, both in ProxyGateTest and both ALLOWED
            // before this guard existed, measured: `POST /login` (no
            // method_denied on the operator branch) and `GET /logout` (no
            // dangerous_denied), each with source UNATTRIBUTED and again with
            // a null. The control is that the same two requests are still
            // allowed for Source.OPERATOR -- theOperatorIsNotMethodChecked and
            // theOperatorIsNotDangerousPathChecked -- so what these pin is
            // attribution, not the rules.
            //
            // The CLASS is `not_configured`, reusing S6's documented overload
            // rather than minting a wire class from a call site that does not
            // exist yet. The detail carries BridgeClient.EXTENSION_FAULT --
            // the prefix records.py declares as its own constant, pinned
            // byte-identical across the two languages by
            // test_the_extension_fault_marker_is_the_same_string_on_both_sides
            // -- because "this jar could not tell who was driving" is the same
            // kind of thing as "this jar has no send handler" and not the same
            // kind as "the operator never configured a run".
            //
            // A class of its own is Task 7's to settle when it wires the
            // recording: a new class needs a row to go in
            // (tests/test_records.py) and there is nothing to record from
            // here yet. Worth knowing before minting one HERE, and it is not
            // an argument for doing so: that test derives the class set by
            // scanning for `Decision.deny("...")` and `error(f, "...")`, and
            // this file's spelling is `new Verdict(false, "...")` -- which it
            // does not scan, for this line or for the epoch-0 one above. A
            // class introduced here would be invisible to the check that
            // exists to catch a denial with nowhere to go.
            return new Verdict(false, "not_configured",
                               BridgeClient.EXTENSION_FAULT
                               + "the proxy listener could not be attributed "
                               + "to the operator or the crawler");
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
