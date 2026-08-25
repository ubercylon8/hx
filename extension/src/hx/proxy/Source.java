// extension/src/hx/proxy/Source.java
package hx.proxy;

/**
 * Who is driving: the operator's own browser, or the crawler.
 *
 * This is a security boundary and it has its own file so the rule can be read
 * without reading anything else.
 *
 * S4: the two are told apart by WHICH PROXY LISTENER the request arrived on,
 * never by anything in the traffic itself. A property of the connection
 * cannot be forged by a hostile page; a header can, and a page that could
 * make its requests look human-driven would dodge the crawler's rules
 * entirely -- including the dangerous-path denylist that exists so a crawler
 * finding "Delete account" does not click it.
 *
 * The listener is readable: `InterceptedRequest.listenerInterface()` returns
 * the accepting listener's own `host:port` and names a different port for each
 * listener, measured over plain HTTP and through a CONNECT tunnel -- see
 * docs/burp-proxy-measurements.md, Q1. There is no `listenerPort()`, so the
 * caller parses the port after the last `:` and hands the int here. This enum
 * does no parsing: it is handed two numbers so the attribution rule is the
 * only thing in the file.
 *
 * The default direction is deliberate and it is not the strict one. An
 * unrecognised port is OPERATOR, because crawler attribution applies the
 * AGENT's rules, and applying them to a human by accident is the failure that
 * drives an operator off the proxy -- at which point their traffic is not
 * recorded at all and the enforcement bought nothing. A crawler mis-attributed
 * as an operator is the safer error: its own harness still refuses what it
 * must, because the crawler is the thing asking.
 *
 * What that default does NOT weaken: scope. ProxyGate applies scope to both
 * sources identically, so a request attributed the wrong way is still refused
 * when it leaves the engagement's boundary.
 */
public enum Source {
    OPERATOR,
    CRAWLER;

    /**
     * @param port        the listener the request arrived on
     * @param crawlerPort the configured crawler listener, or 0 if there is none
     */
    public static Source forListenerPort(int port, int crawlerPort) {
        // `crawlerPort > 0` is load-bearing, and what separates it from its
        // absence is narrow: the two arguments AGREEING on a non-positive
        // port. `forListenerPort(0, 0)` is the case that can actually happen
        // -- with no crawler configured the field is 0, and a caller that
        // could not read a port (a `listenerInterface()` that did not parse,
        // an unset field) has 0 to hand over too -- so a bare equality test
        // turns that pair into CRAWLER: the agent's rules applied to a human
        // on the strength of two absences agreeing. `forListenerPort(8080, 0)`
        // does NOT separate them; it answers OPERATOR either way, measured.
        // ProxyGateTest pins (0, 0).
        return (crawlerPort > 0 && port == crawlerPort) ? CRAWLER : OPERATOR;
    }
}
