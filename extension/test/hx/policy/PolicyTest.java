// extension/test/hx/policy/PolicyTest.java
package hx.policy;

import hx.bridge.BridgeClient;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class PolicyTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    static void expectThrows(String what, Class<?> type, Runnable body) {
        try {
            body.run();
            check(what + " (expected " + type.getSimpleName() + ")", false);
        } catch (Throwable t) {
            check(what, type.isInstance(t));
        }
    }

    public static void main(String[] args) throws Exception {
        theVerdictTypeCarriesItsClassAndItsHint();
        aRequestFieldThatIsNullIsARejectedFrameNotANullPointer();
        epochZeroIsNotConfigured();
        anInScopeRequestIsAllowed();
        scopeMatchesSchemeHostPortAndPath();
        aWildcardSubdomainDoesNotMatchTheApex();
        excludeBeatsInclude();
        anUnusableScopePatternDeniesEverything();
        userinfoInTheAuthorityCannotSatisfyScope();
        aPortSmuggledIntoTheHostCannotSatisfyScope();
        aUrlThatDisagreesWithItsOwnPathIsRefused();
        theMethodAllowlistDefaultsToTheProductionProfile();
        anExplicitMethodAllowReplacesTheDefault();
        methodsAreCaseSensitive();
        theDangerousDenylistShipsWithDefaults();
        operatorDangerousPatternsAddToTheDefaults();
        theRefusalOrderIsPinned();
        aBrokenGateIsNeverAnAllow();
        policyNamesNoBurpType();

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures -------------------------------------------------------

    static final long EPOCH = 7L;

    /** A request in the shape Sender.parse produces: the url built from the
     *  frame's target_host and the origin-form target, the parts split out. */
    static HxRequest req(String method, String url, String host, String path, String query) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Host", List.of(host));
        headers.put("User-Agent", List.of("hx/0.1"));
        headers.put("Accept", List.of("*/*"));
        return new HxRequest(method, url, host, path, query,
                             Collections.unmodifiableMap(headers), new byte[0]);
    }

    static HxRequest orders() {
        return req("GET", "https://app.example.test/api/orders",
                   "app.example.test", "/api/orders", "");
    }

    /** An Authorisation at a real epoch, carrying config in exactly the shape
     *  ConfigBody.parse hands to BridgeClient: repeated keys accumulate in
     *  order, and both levels are frozen. */
    static BridgeClient.Authorisation authorised(String... keyThenValue) {
        Map<String, List<String>> scope = new LinkedHashMap<>();
        for (int i = 0; i < keyThenValue.length; i += 2)
            scope.computeIfAbsent(keyThenValue[i], k -> new ArrayList<>()).add(keyThenValue[i + 1]);
        Map<String, List<String>> frozen = new LinkedHashMap<>();
        scope.forEach((k, v) -> frozen.put(k, List.copyOf(v)));
        return new BridgeClient.Authorisation(EPOCH, Collections.unmodifiableMap(frozen));
    }

    /** The DENY-ALL snapshot BridgeClient publishes before any configure and
     *  after every disconnect. Epoch 0 is what "not configured" IS. */
    static BridgeClient.Authorisation denyAll() {
        return new BridgeClient.Authorisation(0L, Map.of());
    }

    static final BridgeClient.Authorisation APP =
            authorised("scope.include", "https://app.example.test/*");

    /** Counts, because a request refused by an earlier rule must cost no rate
     *  token and no budget slot: Limiter.check() has a side effect. */
    static final class CountingGate implements Gate {
        int calls = 0;
        Decision verdict = Decision.allow();
        public Decision check(HxRequest req) { calls++; return verdict; }
    }

    static Policy allowingPolicy() { return new Policy(new CountingGate()); }

    static void allows(String label, Policy p, HxRequest r, BridgeClient.Authorisation a) {
        Decision d = p.decide(r, a);
        check(label + " -> allowed (got "
              + (d.allowed() ? "allow" : d.errorClass() + ": " + d.detail()) + ")",
              d.allowed());
    }

    static void denies(String label, Policy p, HxRequest r, BridgeClient.Authorisation a,
                       String expectedClass) {
        Decision d = p.decide(r, a);
        check(label + " -> " + expectedClass + " (got "
              + (d.allowed() ? "ALLOWED" : d.errorClass()) + ")",
              !d.allowed() && expectedClass.equals(d.errorClass()));
    }

    // ---- the verdict type ------------------------------------------------

    static void theVerdictTypeCarriesItsClassAndItsHint() {
        Decision allow = Decision.allow();
        check("allow() is allowed, with no class and no hint",
              allow.allowed() && allow.errorClass() == null && allow.retryAfterUs() == 0L);

        Decision denied = Decision.deny("scope_denied", "https://evil.example.test/ is not in scope");
        check("deny() carries the class it was given",
              !denied.allowed() && "scope_denied".equals(denied.errorClass()));
        // s6: retry_after_us belongs to rate_limited alone. A *_denied verdict
        // carrying one would tell the agent to come back and try a request
        // whose answer will never change.
        check("deny() leaves retryAfterUs at 0", denied.retryAfterUs() == 0L);

        Decision limited = Decision.rateLimited(200_000L, "5 rps, 5 issued this second");
        check("rateLimited() sets the class itself",
              !limited.allowed() && "rate_limited".equals(limited.errorClass()));
        check("rateLimited() carries the hint", limited.retryAfterUs() == 200_000L);
    }

    static void aRequestFieldThatIsNullIsARejectedFrameNotANullPointer() {
        // Sender.parse's caller catches IllegalArgumentException and answers
        // bad_frame. A NullPointerException from three frames later would
        // unwind out of the send arm instead.
        expectThrows("a null path is an IllegalArgumentException at construction",
                     IllegalArgumentException.class,
                     () -> new HxRequest("GET", "https://app.example.test/", "app.example.test",
                                         null, "", Map.of(), new byte[0]));
        expectThrows("a null body is an IllegalArgumentException at construction",
                     IllegalArgumentException.class,
                     () -> new HxRequest("GET", "https://app.example.test/", "app.example.test",
                                         "/", "", Map.of(), null));
        HxRequest withQuery = req("GET", "https://app.example.test/search?q=1",
                                  "app.example.test", "/search", "q=1");
        check("target() is the origin-form target the wire would carry",
              "/search?q=1".equals(withQuery.target()));
        check("target() of an empty query is the bare path", "/api/orders".equals(orders().target()));
    }

    // ---- not_configured --------------------------------------------------

    static void epochZeroIsNotConfigured() {
        CountingGate gate = new CountingGate();
        Policy p = new Policy(gate);
        denies("epoch 0 refuses a request that breaks nothing else",
               p, orders(), denyAll(), "not_configured");
        // Not merely "an error came back": a request refused before the Gate
        // must not spend a budget slot the operator paid for.
        check("not_configured never reached the gate (" + gate.calls + " call(s))", gate.calls == 0);

        // Epoch 0 is not a scope question: a snapshot with a perfectly good
        // scope but no epoch is still DENY-ALL, because it is the epoch that
        // says a configure was acknowledged.
        denies("epoch 0 with a populated scope map is still not_configured", p, orders(),
               new BridgeClient.Authorisation(0L, Map.of(
                       "scope.include", List.of("https://app.example.test/*"))),
               "not_configured");
        denies("a null Authorisation is not_configured, not a crash",
               p, orders(), null, "not_configured");
    }

    // ---- scope -----------------------------------------------------------

    static void anInScopeRequestIsAllowed() {
        CountingGate gate = new CountingGate();
        allows("a GET on an in-scope host", new Policy(gate), orders(), APP);
        check("the gate is consulted for a request that passes every rule", gate.calls == 1);
    }

    static void scopeMatchesSchemeHostPortAndPath() {
        Policy p = allowingPolicy();

        denies("another host is out of scope", p,
               req("GET", "https://other.example.test/api/orders",
                   "other.example.test", "/api/orders", ""),
               APP, "scope_denied");

        // Exact, not "contains" and not "endsWith": both of those are the
        // matcher someone writes in a hurry, and both hand an attacker who can
        // register a domain a way into an authorised scope.
        denies("a host with the pattern appended to another domain is out of scope", p,
               req("GET", "https://app.example.test.evil.test/api/orders",
                   "app.example.test.evil.test", "/api/orders", ""),
               APP, "scope_denied");
        denies("nor a host that merely ends with the pattern", p,
               req("GET", "https://notapp.example.test/api/orders",
                   "notapp.example.test", "/api/orders", ""),
               APP, "scope_denied");

        // http:// and https:// are different origins and the pattern named one.
        denies("http is out of scope when the pattern says https", p,
               req("GET", "http://app.example.test/api/orders",
                   "app.example.test", "/api/orders", ""),
               APP, "scope_denied");

        // A pattern with no port means the scheme's default port. 8443 on the
        // same host is a different service, and frequently a different team's.
        denies("a non-default port is out of scope under a default-port pattern", p,
               req("GET", "https://app.example.test:8443/api/orders",
                   "app.example.test", "/api/orders", ""),
               APP, "scope_denied");
        allows("the same request is allowed when the pattern names the port", p,
               req("GET", "https://app.example.test:8443/api/orders",
                   "app.example.test", "/api/orders", ""),
               authorised("scope.include", "https://app.example.test:8443/*"));

        // Path globs.
        allows("a path glob matches below its prefix", p,
               req("GET", "https://app.example.test/api/v2/orders",
                   "app.example.test", "/api/v2/orders", ""),
               authorised("scope.include", "https://app.example.test/api/*"));
        denies("and refuses everything outside it", p,
               req("GET", "https://app.example.test/admin", "app.example.test", "/admin", ""),
               authorised("scope.include", "https://app.example.test/api/*"), "scope_denied");

        // The query is not part of the scope decision, and a pattern is
        // matched against the path alone.
        allows("a query string does not take a request out of scope", p,
               req("GET", "https://app.example.test/api/orders?status=open",
                   "app.example.test", "/api/orders", "status=open"),
               authorised("scope.include", "https://app.example.test/api/*"));

        // Hostnames are case-insensitive; nothing upstream lowercases them.
        allows("an uppercase host still matches a lowercase pattern", p,
               req("GET", "https://APP.EXAMPLE.TEST/api/orders",
                   "APP.EXAMPLE.TEST", "/api/orders", ""),
               APP);

        // An epoch with limits but no scope.include authorises nothing.
        denies("an Authorisation with no scope.include authorises nothing", p, orders(),
               authorised("limit.rate_rps", "5"), "scope_denied");

        // Two includes: the second one is reached.
        allows("a later scope.include is reached", p, orders(),
               authorised("scope.include", "https://other.example.test/*",
                          "scope.include", "https://app.example.test/*"));
    }

    static void aWildcardSubdomainDoesNotMatchTheApex() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation subs =
                authorised("scope.include", "https://*.example.test/*");

        allows("a wildcard subdomain matches one label", p,
               req("GET", "https://api.example.test/orders", "api.example.test", "/orders", ""),
               subs);
        allows("and several", p,
               req("GET", "https://a.b.example.test/orders", "a.b.example.test", "/orders", ""),
               subs);
        // The apex is a different service run by different people often
        // enough that scoping the subdomains must not silently scope it.
        denies("but not the apex itself", p,
               req("GET", "https://example.test/orders", "example.test", "/orders", ""),
               subs, "scope_denied");
        // The prize for a general glob in the host half.
        denies("and not a host that merely ends in the same letters", p,
               req("GET", "https://notexample.test/orders", "notexample.test", "/orders", ""),
               subs, "scope_denied");
    }

    static void excludeBeatsInclude() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        allows("an included path outside the exclusion", p, orders(), cfg);
        denies("an excluded path, though it is also included", p,
               req("GET", "https://app.example.test/admin/users",
                   "app.example.test", "/admin/users", ""),
               cfg, "scope_denied");
    }

    static void anUnusableScopePatternDeniesEverything() {
        Policy p = allowingPolicy();

        // Every pattern is parsed before any is matched, so a matching first
        // include does not hide a garbage second one. Order-dependent scope is
        // scope nobody can review.
        denies("a matching include does not excuse an unusable one after it", p, orders(),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.include", "app.example.test"),
               "scope_denied");
        denies("a pattern with no path is refused rather than guessed at", p, orders(),
               authorised("scope.include", "https://app.example.test"), "scope_denied");
        denies("a pattern with a wildcard host is refused", p, orders(),
               authorised("scope.include", "https://*/*"), "scope_denied");
        // The dangerous direction: an unusable EXCLUDE that was ignored would
        // widen the effective scope, silently.
        denies("an unusable scope.exclude denies rather than being ignored", p, orders(),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "ftp://app.example.test/files/*"),
               "scope_denied");
    }

    static void userinfoInTheAuthorityCannotSatisfyScope() {
        Policy p = allowingPolicy();
        // What a send frame with target_host
        // "app.example.test@evil.example.test" produces. A URL parser reads
        // the host as evil.example.test and discards everything before the @;
        // a human, and a prefix match, read it as app.example.test. Burp would
        // connect to neither -- it connects to the whole string -- so there is
        // no reading under which this is authorised.
        denies("userinfo cannot smuggle an out-of-scope host past an in-scope prefix", p,
               req("GET", "https://app.example.test@evil.example.test/api/orders",
                   "app.example.test@evil.example.test", "/api/orders", ""),
               APP, "scope_denied");
        denies("nor past a pattern for the host after the @", p,
               req("GET", "https://app.example.test@evil.example.test/api/orders",
                   "app.example.test@evil.example.test", "/api/orders", ""),
               authorised("scope.include", "https://evil.example.test/*"), "scope_denied");
        // And the same trick written into a pattern is not usable either.
        denies("a scope pattern carrying userinfo is unusable", p, orders(),
               authorised("scope.include", "https://app.example.test@evil.example.test/*"),
               "scope_denied");
    }

    static void aPortSmuggledIntoTheHostCannotSatisfyScope() {
        Policy p = allowingPolicy();
        // target_host "app.example.test:443" builds the url
        // https://app.example.test:443/api/orders, whose authority parses to
        // the in-scope host on the in-scope port -- while Burp connects to a
        // HOSTNAME with a colon in it. The url and the connection disagree, so
        // the decision is about a request nobody is going to issue.
        denies("a port inside target_host is not a port", p,
               req("GET", "https://app.example.test:443/api/orders",
                   "app.example.test:443", "/api/orders", ""),
               APP, "scope_denied");
        denies("nor when the pattern names that port explicitly", p,
               req("GET", "https://app.example.test:8443/api/orders",
                   "app.example.test:8443", "/api/orders", ""),
               authorised("scope.include", "https://app.example.test:8443/*"), "scope_denied");
        // The same shape one level out: a host that is not a hostname.
        denies("a host with a slash in it is refused", p,
               req("GET", "https://app.example.test/evil.example.test/x",
                   "app.example.test/evil.example.test", "/x", ""),
               APP, "scope_denied");
        denies("a host with a non-ASCII lookalike character is refused", p,
               req("GET", "https://аpp.example.test/api/orders",
                   "аpp.example.test", "/api/orders", ""),
               APP, "scope_denied");
    }

    static void aUrlThatDisagreesWithItsOwnPathIsRefused() {
        // Sender builds the url from the same target it splits into path and
        // query, so these cannot disagree today. The check is here so that the
        // day one of them is built differently, the answer is a denial rather
        // than a decision about the wrong path.
        denies("a url whose path is not the request path is refused", allowingPolicy(),
               req("GET", "https://app.example.test/api/orders",
                   "app.example.test", "/admin/users", ""),
               APP, "scope_denied");
    }

    // ---- method ----------------------------------------------------------

    static void theMethodAllowlistDefaultsToTheProductionProfile() {
        Policy p = allowingPolicy();
        for (String m : List.of("GET", "HEAD", "OPTIONS"))
            allows(m + " is allowed with no method.allow configured", p,
                   req(m, "https://app.example.test/api/orders",
                       "app.example.test", "/api/orders", ""), APP);
        for (String m : List.of("POST", "PUT", "PATCH", "DELETE", "TRACE"))
            denies(m + " is refused with no method.allow configured", p,
                   req(m, "https://app.example.test/api/orders",
                       "app.example.test", "/api/orders", ""), APP, "method_denied");
    }

    static void anExplicitMethodAllowReplacesTheDefault() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation postOnly =
                authorised("scope.include", "https://app.example.test/*",
                           "method.allow", "POST");
        allows("an explicitly allowed POST", p,
               req("POST", "https://app.example.test/api/orders",
                   "app.example.test", "/api/orders", ""), postOnly);
        // Replaces, does not union: an allowlist that can only grow is not an
        // allowlist, and an operator who says HEAD-only on a fragile
        // application has to be able to mean it.
        denies("GET is gone once method.allow names something else", p, orders(),
               postOnly, "method_denied");
    }

    static void methodsAreCaseSensitive() {
        // RFC 9110 s9.1, and Sender.parse keeps the frame's spelling verbatim:
        // `get` is what would go on the wire, and a server that does not
        // recognise it may do something other than a GET.
        denies("a lowercase get does not satisfy an allowlist of GET", allowingPolicy(),
               req("get", "https://app.example.test/api/orders",
                   "app.example.test", "/api/orders", ""),
               APP, "method_denied");
    }

    // ---- dangerous paths -------------------------------------------------

    static void theDangerousDenylistShipsWithDefaults() {
        Policy p = allowingPolicy();
        // In scope, an allowed method, and still refused: s4 is explicit that
        // "in scope" and "safe to touch automatically" are different questions.
        for (String path : List.of("/account/logout", "/signout", "/sign-out",
                                   "/account/password/change", "/api/users/7/delete",
                                   "/admin/cache/purge"))
            denies("a shipped default refuses " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   APP, "dangerous_denied");

        // Case-folded: /Account/Logout is the same button.
        denies("the denylist is case-insensitive", p,
               req("GET", "https://app.example.test/Account/Logout",
                   "app.example.test", "/Account/Logout", ""),
               APP, "dangerous_denied");

        // A logout is as often a query parameter as a path.
        denies("the denylist reads the query too", p,
               req("GET", "https://app.example.test/index.php?action=logout",
                   "app.example.test", "/index.php", "action=logout"),
               APP, "dangerous_denied");

        // The false-positive direction matters just as much: a denylist that
        // refuses ordinary traffic gets turned off.
        for (String path : List.of("/api/orders", "/products/1", "/static/app.js", "/login"))
            allows("an ordinary path is not refused: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   APP);
    }

    static void operatorDangerousPatternsAddToTheDefaults() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "dangerous.path", "*/admin/jobs/*");
        denies("an operator's own pattern is refused", p,
               req("GET", "https://app.example.test/admin/jobs/run",
                   "app.example.test", "/admin/jobs/run", ""),
               cfg, "dangerous_denied");
        // ConfigBody.KEYS has no key that means "drop a default", so a
        // dangerous.path line can only be read as ADDING one.
        denies("and the shipped defaults survive alongside it", p,
               req("GET", "https://app.example.test/account/logout",
                   "app.example.test", "/account/logout", ""),
               cfg, "dangerous_denied");
    }

    // ---- the order -------------------------------------------------------

    /**
     * The pinned order: not_configured -> scope_denied -> method_denied ->
     * dangerous_denied -> the Gate's answer. Each case violates its own rule
     * AND every rule after it, so a reordering cannot pass by accident: the
     * operator reading a denial acts on the reason it gives, and "rate
     * limited" for a request that was never in scope sends them to tune a
     * limit instead of fixing their scope file.
     *
     * `halted` sits between not_configured and scope_denied in the full
     * order and is not decidable here -- it is live state, not a property of
     * the request. Sender holds that position, and SenderTest pins it.
     */
    static void theRefusalOrderIsPinned() {
        // Wrong host, wrong method, dangerous path, and a gate that has
        // already ended the run.
        HxRequest worst = req("POST", "https://app.example.test/account/logout",
                              "app.example.test", "/account/logout", "");
        CountingGate gate = new CountingGate();
        gate.verdict = Decision.deny("budget_exhausted", "2000 of 2000 requests issued");
        Policy p = new Policy(gate);

        denies("epoch 0 beats scope, method, dangerous and budget",
               p, worst, denyAll(), "not_configured");
        denies("scope beats method, dangerous and budget", p, worst,
               authorised("scope.include", "https://other.example.test/*",
                          "method.allow", "GET",
                          "dangerous.path", "*/logout*"),
               "scope_denied");
        denies("method beats dangerous and budget", p, worst,
               authorised("scope.include", "https://app.example.test/*",
                          "method.allow", "GET",
                          "dangerous.path", "*/logout*"),
               "method_denied");
        denies("dangerous beats budget", p, worst,
               authorised("scope.include", "https://app.example.test/*",
                          "method.allow", "POST",
                          "dangerous.path", "*/logout*"),
               "dangerous_denied");

        check("nothing refused above spent a budget slot (" + gate.calls + " gate call(s))",
              gate.calls == 0);

        denies("the gate answers last", p,
               req("POST", "https://app.example.test/api/orders",
                   "app.example.test", "/api/orders", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "method.allow", "POST"),
               "budget_exhausted");
        check("and it was consulted exactly once, by the one request that reached it",
              gate.calls == 1);

        CountingGate slow = new CountingGate();
        slow.verdict = Decision.rateLimited(200_000L, "5 rps, 5 issued this second");
        Decision d = new Policy(slow).decide(orders(), APP);
        check("the Gate's verdict passes through Policy verbatim, retry hint and all",
              "rate_limited".equals(d.errorClass()) && d.retryAfterUs() == 200_000L
              && "5 rps, 5 issued this second".equals(d.detail()));
    }

    // ---- a gate that does not answer -------------------------------------

    static void aBrokenGateIsNeverAnAllow() {
        // s4: an exception is never an implicit allow. budget_exhausted is the
        // class that means "this run is over", which is the honest answer when
        // the thing that tracks what is left of the run has stopped answering.
        Policy throwing = new Policy(r -> { throw new IllegalStateException("clock went backwards"); });
        Decision d = throwing.decide(orders(), APP);
        check("a gate that throws denies (got " + (d.allowed() ? "ALLOWED" : d.errorClass()) + ")",
              !d.allowed() && "budget_exhausted".equals(d.errorClass()));
        check("and the denial says what happened",
              d.detail() != null && d.detail().contains("clock went backwards"));

        Policy nullish = new Policy(r -> null);
        Decision n = nullish.decide(orders(), APP);
        check("a gate that returns nothing denies (got "
              + (n.allowed() ? "ALLOWED" : n.errorClass()) + ")",
              !n.allowed() && "budget_exhausted".equals(n.errorClass()));
    }

    // ---- structural ------------------------------------------------------

    /**
     * The policy core decides what a production estate may receive, and it
     * must be exercisable without Burp running: a ruleset that needs the whole
     * JVM stood up gets exercised by hand, once, and then trusted. Relative
     * path because test.sh runs from extension/, the same idiom CodecTest uses
     * for the golden vectors.
     */
    static void policyNamesNoBurpType() throws Exception {
        Path dir = Path.of("src", "hx", "policy");
        List<Path> sources;
        try (Stream<Path> s = Files.list(dir)) {
            sources = s.filter(f -> f.toString().endsWith(".java")).sorted().toList();
        }
        // A scan that silently found nothing would make every check below
        // vacuous -- the failure mode that put this project's seven deleted
        // guards through green tests.
        check("the scan found the policy sources (" + sources.size() + " file(s))",
              sources.size() >= 5);
        for (Path f : sources) {
            String text = Files.readString(f, StandardCharsets.UTF_8);
            check(f.getFileName() + " names no burp.* type", !text.contains("burp."));
        }
    }
}
