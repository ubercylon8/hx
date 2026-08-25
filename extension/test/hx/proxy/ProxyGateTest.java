// extension/test/hx/proxy/ProxyGateTest.java
package hx.proxy;

import hx.TestSupport;
import hx.bridge.BridgeClient;
import hx.policy.Decision;
import hx.policy.Gate;
import hx.policy.HxRequest;
import hx.policy.Policy;

import java.util.List;
import java.util.Map;

/**
 * The gate, against fakes.
 *
 * The two cases that matter most are the pair: the SAME request is allowed
 * for the operator and refused for the crawler. A test that only exercises
 * one source cannot tell a working split from a gate that ignores source
 * entirely -- which is rule 3 on this project. Rows B and C of this task's
 * sabotage table are that split turned off in each direction, and each
 * reddens only its own source's checks: neither is caught by the other's.
 *
 * Hand-rolled runner, like the other nine classes: JUnit would be a
 * dependency, and this jar has none.
 */
public class ProxyGateTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  Load-bearing here rather than decoration: the input that separates this
     *  class's own DENY-ALL guard from its absence makes the method THROW, and
     *  without this guard that reads as a truncated run rather than a failure.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(ProxyGateTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("scope is absolute for the operator",
          ProxyGateTest::scopeIsAbsoluteForTheOperator);
        t("and absolute for the crawler",
          ProxyGateTest::scopeIsAbsoluteForTheCrawler);
        t("the operator's own browsing is not method-checked",
          ProxyGateTest::theOperatorIsNotMethodChecked);
        t("but the crawler is",
          ProxyGateTest::theCrawlerIsMethodChecked);
        t("the operator is not dangerous-path checked",
          ProxyGateTest::theOperatorIsNotDangerousPathChecked);
        t("but the crawler is (dangerous path)",
          ProxyGateTest::theCrawlerIsDangerousPathChecked);
        t("the operator does not spend the gate",
          ProxyGateTest::theOperatorDoesNotSpendTheGate);
        t("but the crawler does (the gate)",
          ProxyGateTest::theCrawlerSpendsTheGate);
        t("an unconfigured extension refuses every source",
          ProxyGateTest::unconfiguredRefusesBoth);
        t("a source that could not be attributed is refused, not defaulted",
          ProxyGateTest::anUnattributableSourceIsRefused);
        t("the listener port decides the source",
          ProxyGateTest::theListenerPortDecides);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures -------------------------------------------------------

    static BridgeClient.Authorisation authorised() {
        return new BridgeClient.Authorisation(7, Map.of(
            "scope.include", List.of("http://app.test/*"),
            "method.allow", List.of("GET", "HEAD"),
            "dangerous.path", List.of("*/logout*")));
    }

    /**
     * The host is taken FROM the url rather than fixed at "app.test".
     *
     * Policy refuses any request whose url authority is not the connection
     * host, with the same `scope_denied` class an unmatched include produces,
     * and it refuses it FIRST (Policy.checkScope). A fixture that hard-coded
     * the host to "app.test" would therefore have `http://evil.test/x`
     * refused by the host comparison rather than by the include patterns, and
     * the two scope checks below would say nothing about scope.
     *
     * Measured, row G of this task's sabotage table. Adding
     * "http://evil.test/*" to `scope.include` -- authorising the very request
     * those checks exist to see refused -- reddens three checks with the host
     * taken from the url, and the suite is back to 10 x ALL PASS with the same
     * widened include the moment the host is hard-coded again.
     */
    static HxRequest req(String method, String url) {
        java.net.URI u = java.net.URI.create(url);
        return new HxRequest(method, url, u.getHost(), u.getPath(), "",
                             Map.of(), new byte[0]);
    }

    /** A Gate that counts, so "did this spend budget" is observable. */
    static final class CountingGate implements Gate {
        int calls;
        public Decision check(HxRequest r) { calls++; return Decision.allow(); }
    }

    static ProxyGate gateOver(Gate gate) {
        // The Gate goes into the Policy, which is where the rate limit and the
        // budget live in production too: Policy owns its Gate and consults it
        // last. A call counted here is a call a real run spends a rate token
        // and a budget slot on.
        return new ProxyGate(new Policy(gate));
    }

    // ---- scope, which is absolute for everyone ---------------------------

    static void scopeIsAbsoluteForTheOperator() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://evil.test/x"), authorised(), Source.OPERATOR);
        check("out of scope is refused even for the operator", !v.allow());
        check("and the class names the boundary crossed (" + v.errorClass() + ")",
              "scope_denied".equals(v.errorClass()));
    }

    static void scopeIsAbsoluteForTheCrawler() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://evil.test/x"), authorised(), Source.CRAWLER);
        check("out of scope is refused for the crawler too", !v.allow());
    }

    // ---- the four rules that constrain an agent, in pairs ----------------

    static void theOperatorIsNotMethodChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("POST", "http://app.test/login"), authorised(), Source.OPERATOR);
        check("a POST the allowlist omits still goes out for a human ("
              + v.errorClass() + ")", v.allow());
    }

    static void theCrawlerIsMethodChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("POST", "http://app.test/login"), authorised(), Source.CRAWLER);
        check("the same POST is refused for the crawler", !v.allow());
        check("with method_denied (" + v.errorClass() + ")",
              "method_denied".equals(v.errorClass()));
    }

    static void theOperatorIsNotDangerousPathChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://app.test/logout"), authorised(), Source.OPERATOR);
        check("a deliberate click on a dangerous path is the operator's to make",
              v.allow());
    }

    static void theCrawlerIsDangerousPathChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://app.test/logout"), authorised(), Source.CRAWLER);
        check("a crawler that finds logout must not click it", !v.allow());
        check("with dangerous_denied (" + v.errorClass() + ")",
              "dangerous_denied".equals(v.errorClass()));
    }

    static void theOperatorDoesNotSpendTheGate() {
        CountingGate gate = new CountingGate();
        var v = gateOver(gate)
            .decide(req("GET", "http://app.test/x"), authorised(), Source.OPERATOR);
        // The allow is asserted alongside the count: a request refused before
        // the Gate would also leave `calls` at 0, so the count on its own does
        // not separate "the operator skips the Gate" from "the operator was
        // denied".
        check("the in-scope request is allowed (" + v.errorClass() + ")", v.allow());
        check("browsing does not spend the run's budget (" + gate.calls + ")",
              gate.calls == 0);
    }

    static void theCrawlerSpendsTheGate() {
        CountingGate gate = new CountingGate();
        var v = gateOver(gate)
            .decide(req("GET", "http://app.test/x"), authorised(), Source.CRAWLER);
        check("the same request is allowed for the crawler (" + v.errorClass() + ")",
              v.allow());
        check("crawling does (" + gate.calls + ")", gate.calls == 1);
    }

    // ---- DENY-ALL --------------------------------------------------------

    static void unconfiguredRefusesBoth() {
        var none = new BridgeClient.Authorisation(0, Map.of());
        ProxyGate g = gateOver(new CountingGate());
        for (Source s : Source.values()) {
            var v = g.decide(req("GET", "http://app.test/x"), none, s);
            check("DENY-ALL holds for " + s + " (" + v.errorClass() + ")",
                  !v.allow() && "not_configured".equals(v.errorClass()));
        }

        // The separating input for ProxyGate's OWN epoch guard, and it is not
        // the checks above. Policy refuses an epoch-0 authorisation on both of
        // the paths this class calls, so with that guard deleted the three
        // above still print `ok` and the failure is the NPE thrown out of THIS
        // method the moment the loop below reaches a ProxyGate with no Policy
        // -- re-measured on this tree, 9 x ALL PASS + 1 FAILURE / 1652 ok, the
        // one FAIL being this method's name and a NullPointerException. (Row D
        // of the sabotage table measured it when Source had two constants; the
        // third constant adds a green check, not a red one, because an
        // unattributable source is refused either way.) The guard adds that
        // the answer is given BEFORE the
        // Policy is consulted, and a ProxyGate holding no Policy is the one
        // caller that can tell the two apart: with the guard it is a verdict,
        // without it an NPE. The per-method guard in TestSupport.t turns that
        // NPE into a named FAIL rather than a truncated run.
        for (Source s : Source.values()) {
            var v = new ProxyGate(null).decide(req("GET", "http://app.test/x"), none, s);
            check("and it is answered without consulting Policy for " + s
                  + " (" + v.errorClass() + ")",
                  !v.allow() && "not_configured".equals(v.errorClass()));
        }
    }

    // ---- the third answer ------------------------------------------------

    /**
     * A source this gate cannot recognise is REFUSED, and both spellings of
     * one are: `Source.UNATTRIBUTED` and a null.
     *
     * Both were ALLOWED before the guard that answers them existed --
     * measured, and with the whole suite at 10 x ALL PASS, because
     * `source == Source.CRAWLER` is false for each and the else branch is the
     * lenient one. The two requests are chosen as the separating inputs: a
     * POST the allowlist omits, and a GET on a dangerous path. The CONTROL is
     * that both are still allowed for Source.OPERATOR two methods up, so what
     * these pin is attribution and not the four rules.
     *
     * NOT claimed: that null and UNATTRIBUTED exhaust what this branch
     * catches. It is written as "neither of the two I know", so a constant
     * added to Source later lands here too -- and that constant needs its own
     * check, because this method names two and cannot see a third.
     */
    static void anUnattributableSourceIsRefused() {
        CountingGate gate = new CountingGate();
        ProxyGate g = gateOver(gate);
        Source[] unknown = { Source.UNATTRIBUTED, null };
        for (Source s : unknown) {
            var post = g.decide(req("POST", "http://app.test/login"), authorised(), s);
            check("a POST the allowlist omits is refused for " + s + " ("
                  + post.errorClass() + ")",
                  !post.allow() && "not_configured".equals(post.errorClass()));

            var logout = g.decide(req("GET", "http://app.test/logout"), authorised(), s);
            check("and so is a dangerous path for " + s + " ("
                  + logout.errorClass() + ")",
                  !logout.allow() && "not_configured".equals(logout.errorClass()));

            // The class is shared with DENY-ALL, so the class alone does not
            // say which guard answered. The detail does, and the prefix it
            // starts with is the one records.py declares for itself -- the
            // marker that separates "this jar is broken" from "the operator
            // never configured a run", pinned identical on both sides by
            // test_the_extension_fault_marker_is_the_same_string_on_both_sides.
            check("with the extension-fault marker on the detail for " + s
                  + " (" + logout.detail() + ")",
                  logout.detail() != null
                  && logout.detail().startsWith(BridgeClient.EXTENSION_FAULT));
        }
        check("and refusing an unattributable request spends nothing ("
              + gate.calls + ")", gate.calls == 0);
    }

    // ---- attribution -----------------------------------------------------

    static void theListenerPortDecides() {
        check("the crawler port attributes to CRAWLER",
              Source.forListenerPort(8081, 8081) == Source.CRAWLER);
        check("any other port attributes to OPERATOR",
              Source.forListenerPort(8080, 8081) == Source.OPERATOR);
        // A port that PARSED and belongs to no listener hx knows about is the
        // operator's: they may configure extra listeners, and crawler
        // attribution is the stricter branch, so getting it by default would
        // silently apply the agent's rules to a human.
        check("and an unrecognised but usable port is OPERATOR, not CRAWLER",
              Source.forListenerPort(9999, 8081) == Source.OPERATOR);
        // Behaviour, not a guard: an unconfigured crawler port must swallow
        // nothing. This input separates no branch of forListenerPort as it now
        // stands -- 8080 is in range and 8080 != 0 -- and is kept as a pin on
        // the answer rather than dressed up as more than it is.
        check("an unconfigured crawler port matches nothing",
              Source.forListenerPort(8080, 0) == Source.OPERATOR);

        // The four inputs that separate the range test, and with it the whole
        // third answer. Each is a port the caller could not determine, and
        // each answered OPERATOR -- the branch that drops four of the five
        // rules -- before the range test existed; measured, all four, against
        // the committed body. (0, 0) was the sharpest: it answered OPERATOR
        // only because of a `crawlerPort > 0` clause that existed for that one
        // pair, and a bare equality made it CRAWLER instead.
        check("a port that could not be read is UNATTRIBUTED, with a crawler configured",
              Source.forListenerPort(Source.NO_PORT, 8081) == Source.UNATTRIBUTED);
        check("and without one",
              Source.forListenerPort(Source.NO_PORT, 0) == Source.UNATTRIBUTED);
        check("a negative sentinel is UNATTRIBUTED, not a listener",
              Source.forListenerPort(-1, 8081) == Source.UNATTRIBUTED);
        check("and so is a number no TCP port can be",
              Source.forListenerPort(70000, 8081) == Source.UNATTRIBUTED);
        // The constant is the spelling Task 7 hands over, and it must be the
        // value the rule actually treats that way -- a NO_PORT of, say, 1
        // would make the two lines above pass while every real parse failure
        // answered OPERATOR.
        check("and NO_PORT is one of those numbers (" + Source.NO_PORT + ")",
              Source.NO_PORT < 1 || Source.NO_PORT > 65535);
    }
}
