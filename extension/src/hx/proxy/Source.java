// extension/src/hx/proxy/Source.java
package hx.proxy;

/**
 * Who is driving: the operator's own browser, the crawler, or NEITHER -- and
 * the third is an answer in its own right rather than a synonym for the first.
 *
 * This is a security boundary and it has its own file so the rule can be read
 * without reading anything else.
 *
 * S4: the two real sources are told apart by WHICH PROXY LISTENER the request
 * arrived on, never by anything in the traffic itself. A property of the
 * connection cannot be forged by a hostile page; a header can, and a page that
 * could make its requests look human-driven would dodge the crawler's rules
 * entirely -- including the dangerous-path denylist that exists so a crawler
 * finding "Delete account" does not click it.
 *
 * The listener is readable: `InterceptedRequest.listenerInterface()` returns
 * the accepting listener's own `host:port` and names a different port for each
 * listener, measured over plain HTTP and through a CONNECT tunnel -- see
 * docs/burp-proxy-measurements.md, Q1. There is no `listenerPort()`, so the
 * caller parses the port after the last `:` and hands the int here. This enum
 * does no parsing and imports nothing: it is handed two numbers so the
 * attribution rule is the only thing in the file, and so nothing that carries
 * traffic can reach it.
 *
 * THE DEFAULT DIRECTION, AND WHY IT IS TWO ANSWERS RATHER THAN ONE.
 *
 * A port that PARSES and is not the crawler's is OPERATOR. Crawler attribution
 * applies the AGENT's rules, and applying them to a human by accident is the
 * failure that drives an operator off the proxy -- at which point their
 * traffic is not recorded at all and the enforcement bought nothing. An
 * operator may legitimately configure extra listeners and hx cannot enumerate
 * them, so "a port I do not recognise" has to mean the human.
 *
 * What that costs, stated rather than argued away: ProxyGate asks Policy for
 * SCOPE ONLY on the OPERATOR branch, so a request attributed that way is not
 * method-checked, not dangerous-path-checked, spends no rate token and spends
 * no budget slot -- and NOTHING ELSE IN THIS SYSTEM APPLIES THOSE FOUR RULES
 * TO IT. S4 puts all four here on purpose ("Rate limiting, method allowlist,
 * dangerous-path denylist, and per-run budgets all live in the extension"):
 * the Python side carries `dangerous_paths` and `method.allow` as config to
 * ship to this jar and as denial-class names to record, and refuses none of
 * them -- grepped, 2026-08-25, and that grep is how to falsify this sentence:
 * a refusal appearing on the Python side would make it false, and
 * hx-design.md:192 is the line saying one should not.
 *
 * An earlier version of this comment claimed a crawler mis-attributed as an
 * operator was the safer error "because its own harness still refuses what it
 * must". There is no such harness refusal, and that false sentence was the
 * whole argument for answering OPERATOR to a question this enum could not
 * actually answer.
 *
 * So a port that CANNOT BE DETERMINED is no longer that answer. It is
 * UNATTRIBUTED, and {@link ProxyGate} REFUSES it: not knowing who is driving
 * is a code failure or a change in Burp, never a person browsing, and the
 * permissive branch is the one branch it must not silently become.
 *
 * WHAT UNATTRIBUTED COVERS AND WHAT IT EXCLUDES. It is the answer for an int
 * that is not a usable TCP port -- `port < 1 || port > 65535` -- which is the
 * shape a caller in trouble actually produces: {@link #NO_PORT} from an unset
 * field or from a `listenerInterface()` that did not parse, a negative from a
 * parse that returned a sentinel, a garbage large number from one that read
 * the wrong digits. It EXCLUDES a port that parsed into range and belongs to
 * no listener hx knows about: `(9999, 8081)` is OPERATOR, deliberately,
 * because that is the extra-listener case above and nothing here can tell it
 * from a typo. ProxyGateTest pins both sides of that line -- `(0, 8081)`,
 * `(-1, 8081)` and `(70000, 8081)` are UNATTRIBUTED; `(9999, 8081)` and
 * `(8080, 0)` are OPERATOR.
 *
 * What NO attribution weakens, whichever of the three it answers: scope.
 * ProxyGate applies scope to both real sources identically and refuses the
 * third outright, so a request attributed the wrong way is still refused when
 * it leaves the engagement's boundary -- pinned by ProxyGateTest's
 * out-of-scope checks, one method for each of the two real sources, and by
 * the refusal checks for the third.
 */
public enum Source {
    OPERATOR,
    CRAWLER,
    UNATTRIBUTED;

    /**
     * What a caller hands over when it has no port to hand over.
     *
     * Named so Task 7's parse has something to say "I could not read one"
     * WITH, rather than reaching for a bare 0 that used to mean the operator.
     * Any int outside 1..65535 answers the same way, so a caller that forgets
     * this constant and passes 0, -1 or a failed parse's sentinel still gets
     * UNATTRIBUTED; the constant is for the reader, not for the rule.
     */
    public static final int NO_PORT = 0;

    /**
     * @param port        the listener the request arrived on, or {@link #NO_PORT}
     *                    when the caller could not determine one
     * @param crawlerPort the configured crawler listener, or 0 if there is none
     */
    public static Source forListenerPort(int port, int crawlerPort) {
        // The range test comes FIRST and is what makes the third answer
        // reachable: without it, `port == crawlerPort` on two absences (an
        // unreadable port and an unconfigured crawler, 0 and 0) is CRAWLER,
        // and every other unreadable port is OPERATOR -- the agent's rules
        // applied to a human on the strength of two absences agreeing, or the
        // human's leniency applied to the agent. Both are now refusals.
        if (port < 1 || port > 65535) return UNATTRIBUTED;
        // No `crawlerPort > 0` guard here any more, and its absence is
        // deliberate: with `port` already constrained to 1..65535, a
        // crawlerPort of 0 or negative cannot equal it, so that clause is
        // subsumed and NO input in this suite separates it from its absence:
        // putting it back is 10 x ALL PASS / 1655 ok / 0 FAIL, measured, and
        // the range test above is why no input can. A guard nothing separates
        // is the finding this fix round is closing elsewhere; it is not
        // re-added here. `(8080, 0)` is still pinned in ProxyGateTest
        // as BEHAVIOUR -- an unconfigured crawler port matches nothing -- and
        // that check is honest about not separating a guard.
        return port == crawlerPort ? CRAWLER : OPERATOR;
    }
}
