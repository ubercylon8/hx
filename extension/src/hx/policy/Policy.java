// extension/src/hx/policy/Policy.java
package hx.policy;

import hx.bridge.BridgeClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The decision, as a pure function of a request and one Authorisation
 * snapshot. No sockets, no clock, no filesystem, and nothing from Burp's
 * Montoya API -- PolicyTest scans every source file in this package and fails
 * if one names a Montoya type, because a ruleset that needs Burp running to be
 * exercised is a ruleset that will be exercised by hand, once, and then
 * trusted.
 *
 * THE ORDER IS THE CONTRACT: not_configured -> [halted] -> scope_denied ->
 * method_denied -> dangerous_denied -> rate_limited -> budget_exhausted. When
 * a request violates several rules the earliest wins, because the denial an
 * operator reads is the reason they will act on. "Rate limited" for a request
 * that was never in scope sends them to tune a limit instead of fixing their
 * scope file.
 *
 * `halted` is in brackets because it is not decidable here: a halt is a piece
 * of live state (a halt frame, the sentinel file, or auto-halt on target
 * distress), not a property of the request and the authorisation. Sender
 * checks it, in that position, between not_configured and this method.
 *
 * The Authorisation is a PARAMETER. It is read once per send, by
 * BridgeClient's send arm, and carried down -- epoch and scope from the one
 * reference, so the scope a request was decided under and the epoch stamped on
 * its evidence line are the same commit. configEpoch() and scopeConfig() are
 * two reads of that one record and a commit lands between them: measured wrong
 * in 393/400 trials, in the unsafe direction.
 */
public final class Policy {

    /**
     * Spec s4: "Defaults on a production profile are single-digit req/s and
     * GET/HEAD/OPTIONS only."
     *
     * This applies whenever `method.allow` is ABSENT, whatever profile the
     * configure frame named -- Authorisation carries the config body, and the
     * profile is a header field that never reaches this class. That is
     * deliberate: the body is what was hashed and committed at this epoch, and
     * the strictest profile's allowlist is the only safe reading of "the
     * operator did not say".
     */
    static final List<String> DEFAULT_METHODS = List.of("GET", "HEAD", "OPTIONS");

    // Spec s4: the denylist "ships with sensible defaults (logout, password
    // change, delete, purge) and is separate from scope -- 'in scope' and
    // 'safe to touch automatically' are different questions."
    //
    // Same glob syntax as an operator's own `dangerous.path` lines, matched
    // case-insensitively against the request target -- path AND query, because
    // on a legacy application a logout is `/index.php?action=logout` at least
    // as often as it is `/logout`. Each verb therefore appears twice, once
    // after a `/` and once after a `=`: those are the two separators it can
    // follow, and requiring one is what keeps `/api/blogouts` out of the
    // denylist. The two spellings of sign-out are both here because real
    // applications use both, and password covers change-password,
    // password/change and reset-password without guessing which shape a given
    // app chose.
    //
    // The false-positive direction is accepted deliberately: `?sort=deleted_at`
    // matches and will be refused. A visible dangerous_denied on a listing
    // endpoint costs an operator one config line; an automated logout costs
    // them the session, and possibly the evidence of everything issued under
    // it.
    //
    // These are ADDED to whatever the operator configured, never replaced by
    // it: ConfigBody.KEYS has no key meaning "drop a default", so a
    // `dangerous.path` line can only be read as one more thing to refuse. The
    // cost is real and accepted -- there is no way to authorise hx to issue a
    // logout, and an operator who needs one issues it by hand in Repeater,
    // which is where s1 says manual manipulation belongs.
    //
    // (Line comments, not javadoc: a pattern beginning `*/` ends a block
    // comment.)
    static final List<String> DEFAULT_DANGEROUS = List.of(
            "*/logout*",   "*=logout*",
            "*/signout*",  "*=signout*",
            "*/sign-out*", "*=sign-out*",
            "*/password*", "*=password*",
            "*/delete*",   "*=delete*",
            "*/purge*",    "*=purge*");

    private final Gate gate;

    public Policy(Gate gate) {
        this.gate = gate;
    }

    public Decision decide(HxRequest req, BridgeClient.Authorisation auth) {
        // Epoch 0 is the DENY-ALL Authorisation BridgeClient publishes before
        // any configure and after every disconnect; epochCounter is
        // pre-incremented, so a real commit is >= 1 and there is no other way
        // to observe a 0. A null snapshot is a caller bug, and the fail-closed
        // reading of a caller bug is the same one.
        if (auth == null || auth.epoch() == 0)
            return Decision.deny("not_configured", "no configure frame acknowledged yet");

        Map<String, List<String>> scope = auth.scope();

        Decision scoped = checkScope(req, scope);
        if (!scoped.allowed()) return scoped;

        // NOT uppercased on either side. HTTP methods are case-sensitive (RFC
        // 9110 s9.1) and Sender.parse keeps whatever the frame said, so `get`
        // is what would go on the wire; folding case here would let it satisfy
        // a method.allow of GET while the server sees something else.
        List<String> allowed = scope.getOrDefault("method.allow", DEFAULT_METHODS);
        if (!allowed.contains(req.method()))
            return Decision.deny("method_denied",
                    req.method() + " is not in method.allow " + allowed);

        String target = lower(req.target());
        for (String pattern : dangerousPatterns(scope))
            if (glob(lower(pattern), target))
                return Decision.deny("dangerous_denied",
                        req.target() + " matches dangerous.path " + pattern);

        // The Gate LAST, because it is the only check with a side effect:
        // Limiter.check() spends a rate token and a budget slot, and spending
        // either on a request three earlier rules would have refused shortens
        // the run for no evidence.
        Decision gated;
        try {
            gated = gate.check(req);
        } catch (RuntimeException e) {
            // s4: an exception is never an implicit allow. budget_exhausted is
            // the honest class -- it is the one that means "this run is over",
            // and a gate that cannot say what is left of the budget has ended
            // the run whether or not it meant to.
            return Decision.deny("budget_exhausted",
                    "gate failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        if (gated == null)
            return Decision.deny("budget_exhausted", "gate returned no decision");
        return gated;
    }

    // ---- scope ---------------------------------------------------------

    /**
     * Scope is decided about the URL, and every pattern is parsed BEFORE any
     * of them is matched. Parsing lazily would make the verdict depend on the
     * order of the include list: a garbage pattern after a matching one would
     * never be reached, and the same config would authorise or refuse the same
     * request depending on which line the operator typed first.
     */
    private static Decision checkScope(HxRequest req, Map<String, List<String>> scope) {
        Target t;
        try {
            t = Target.parse(req.url());
        } catch (IllegalArgumentException e) {
            return Decision.deny("scope_denied", e.getMessage());
        }

        // Policy decides about req.url(); Burp connects to req.host() on the
        // port in that url. If the url's authority is not exactly that host,
        // the decision and the connection are about different destinations --
        // which is precisely what a `target_host` of
        // "app.example.test@evil.example.test" (userinfo: everything before
        // the @ is discarded by a URL parser, and by nobody else) or
        // "app.example.test:8443" (a port smuggled into the host field) buys
        // an attacker who can influence a send frame. Neither can be matched
        // safely, so neither is matched at all.
        if (!t.host().equals(lower(req.host())))
            return Decision.deny("scope_denied", "url authority host " + t.host()
                    + " is not the connection host " + req.host());
        // Same argument one field down: the url's path is what the patterns
        // are matched against and req.path() is what the wire gets. The query
        // is deliberately NOT compared -- HxRequest cannot tell "/x" from
        // "/x?", both of which parse to an empty query -- and no scope pattern
        // matches against it.
        if (!t.path().equals(req.path()))
            return Decision.deny("scope_denied", "url path " + t.path()
                    + " is not the request path " + req.path());

        List<String> include = scope.getOrDefault("scope.include", List.of());
        if (include.isEmpty())
            // An engagement with no scope.include authorises nothing. This is
            // reachable with a non-zero epoch: a configure frame carrying only
            // limits commits fine.
            return Decision.deny("scope_denied", "no scope.include pattern is configured");

        List<Rule> excludes = new ArrayList<>();
        List<Rule> includes = new ArrayList<>();
        try {
            for (String p : scope.getOrDefault("scope.exclude", List.of()))
                excludes.add(Rule.parse(p));
            for (String p : include)
                includes.add(Rule.parse(p));
        } catch (IllegalArgumentException e) {
            return Decision.deny("scope_denied", "unusable scope pattern: " + e.getMessage());
        }

        // Exclude first: an exclusion is the operator naming something they
        // know they must not touch, and it beats every include it overlaps.
        for (Rule r : excludes)
            if (r.matches(t))
                return Decision.deny("scope_denied",
                        req.url() + " matches scope.exclude " + r.source());

        for (Rule r : includes)
            if (r.matches(t)) return Decision.allow();

        return Decision.deny("scope_denied", req.url() + " matches no scope.include pattern");
    }

    /** scheme, host, port and path of a request URL, with no ambiguity left in
     *  any of them. */
    private record Target(String scheme, String host, int port, String path) {

        static Target parse(String url) {
            int sep = url.indexOf("://");
            if (sep <= 0) throw new IllegalArgumentException("url has no scheme: " + url);
            String scheme = lower(url.substring(0, sep));
            if (!scheme.equals("http") && !scheme.equals("https"))
                throw new IllegalArgumentException("url scheme is not http(s): " + url);

            String rest = url.substring(sep + 3);
            int slash = rest.indexOf('/');
            if (slash < 0)
                // Sender only ever builds a url from an origin-form target, so
                // this is a caller that built one some other way.
                throw new IllegalArgumentException("url has no path: " + url);

            String authority = rest.substring(0, slash);
            String pathAndQuery = rest.substring(slash);
            int q = pathAndQuery.indexOf('?');
            String path = q < 0 ? pathAndQuery : pathAndQuery.substring(0, q);

            if (authority.indexOf('@') >= 0)
                throw new IllegalArgumentException("url authority carries userinfo: " + url);

            int port = scheme.equals("https") ? 443 : 80;
            String host = authority;
            int colon = authority.indexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon);
                String portText = authority.substring(colon + 1);
                if (portText.isEmpty())
                    throw new IllegalArgumentException("url authority has an empty port: " + url);
                for (int i = 0; i < portText.length(); i++)
                    if (portText.charAt(i) < '0' || portText.charAt(i) > '9')
                        // Catches the second colon of an unbracketed IPv6
                        // literal as well as junk. An IPv6 target needs
                        // brackets before it can be reasoned about, and
                        // nothing produces one yet.
                        throw new IllegalArgumentException("url port is not a number: " + url);
                if (portText.length() > 5)
                    throw new IllegalArgumentException("url port is out of range: " + url);
                port = Integer.parseInt(portText);
                if (port < 1 || port > 65535)
                    throw new IllegalArgumentException("url port is out of range: " + url);
            }
            host = lower(host);
            checkHostChars(host, url);
            return new Target(scheme, host, port, path);
        }
    }

    /**
     * A hostname we are willing to match against a pattern.
     *
     * The refused characters are the ones that create a SECOND reading of
     * where a request is going: '@' (userinfo), ':' (port), '/' and '\'
     * (authority ends), whitespace, and anything non-ASCII (a Cyrillic 'a' in
     * a hostname is a different host that renders identically). '_' is allowed
     * although RFC 1123 does not: internal names use it, and it cannot make an
     * authority ambiguous.
     */
    private static void checkHostChars(String host, String url) {
        if (host.isEmpty())
            throw new IllegalArgumentException("url has an empty host: " + url);
        if (host.startsWith(".") || host.endsWith(".") || host.contains(".."))
            throw new IllegalArgumentException("url host has an empty label: " + url);
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                      || c == '-' || c == '.' || c == '_';
            if (!ok) throw new IllegalArgumentException(
                    "url host has a character that cannot appear in a hostname: " + url);
        }
    }

    /** One scope.include / scope.exclude pattern, pre-parsed. */
    private record Rule(String source, String scheme, String hostPattern,
                        boolean hostSuffix, int port, String pathGlob) {

        static Rule parse(String pattern) {
            int sep = pattern.indexOf("://");
            if (sep <= 0) throw new IllegalArgumentException(pattern + " has no scheme");
            String scheme = lower(pattern.substring(0, sep));
            if (!scheme.equals("http") && !scheme.equals("https"))
                throw new IllegalArgumentException(pattern + " has a scheme that is not http(s)");

            String rest = pattern.substring(sep + 3);
            int slash = rest.indexOf('/');
            if (slash < 0)
                // "https://app.example.test" has two readings -- the root
                // only, or everything under it -- and they differ by the whole
                // application. Make the operator write which one.
                throw new IllegalArgumentException(pattern + " has no path; write /* if you mean everything");

            String authority = rest.substring(0, slash);
            String pathGlob = rest.substring(slash);
            if (authority.indexOf('@') >= 0)
                throw new IllegalArgumentException(pattern + " carries userinfo");

            int port = scheme.equals("https") ? 443 : 80;
            String host = authority;
            int colon = authority.indexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon);
                String portText = authority.substring(colon + 1);
                if (portText.isEmpty() || portText.length() > 5)
                    throw new IllegalArgumentException(pattern + " has a bad port");
                for (int i = 0; i < portText.length(); i++)
                    if (portText.charAt(i) < '0' || portText.charAt(i) > '9')
                        throw new IllegalArgumentException(pattern + " has a bad port");
                port = Integer.parseInt(portText);
                if (port < 1 || port > 65535)
                    throw new IllegalArgumentException(pattern + " has a bad port");
            }
            host = lower(host);

            // The host half accepts exactly one wildcard shape: a leading
            // "*." matching one or more labels underneath a suffix. A general
            // glob here would let "*.example.test" be written as
            // "*example.test", which also matches "notexample.test", and would
            // let a bare "*" authorise the entire internet from one typo.
            boolean suffix = false;
            if (host.startsWith("*.")) {
                suffix = true;
                host = host.substring(1);           // ".example.test"
                checkHostChars(host.substring(1), pattern);
            } else {
                checkHostChars(host, pattern);
            }
            return new Rule(pattern, scheme, host, suffix, port, pathGlob);
        }

        boolean matches(Target t) {
            if (!scheme.equals(t.scheme())) return false;
            if (port != t.port()) return false;
            if (hostSuffix) {
                // ".example.test" matches api.example.test but NOT
                // example.test: an operator scoping the subdomains has not
                // scoped the apex, which is frequently a different service run
                // by a different team.
                if (!t.host().endsWith(hostPattern)) return false;
            } else if (!hostPattern.equals(t.host())) {
                return false;
            }
            return glob(pathGlob, t.path());
        }
    }

    // ---- dangerous paths ------------------------------------------------

    private static List<String> dangerousPatterns(Map<String, List<String>> scope) {
        List<String> configured = scope.getOrDefault("dangerous.path", List.of());
        if (configured.isEmpty()) return DEFAULT_DANGEROUS;
        List<String> all = new ArrayList<>(DEFAULT_DANGEROUS);
        all.addAll(configured);
        return all;
    }

    // ---- helpers --------------------------------------------------------

    /**
     * `*` matches any run of characters, including none. There is no other
     * metacharacter: a scope pattern is read by an operator under time
     * pressure, and a regex is a language in which it is easy to write
     * something wider than you meant -- and in which a pattern from a config
     * file is a denial-of-service on our own JVM.
     *
     * Iterative with one backtrack point, so a pattern of many stars against a
     * long path cannot go exponential.
     */
    static boolean glob(String pattern, String text) {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.length()) {
            if (p < pattern.length() && pattern.charAt(p) == '*') {
                star = p++;
                mark = t;
            } else if (p < pattern.length() && pattern.charAt(p) == text.charAt(t)) {
                p++;
                t++;
            } else if (star >= 0) {
                p = star + 1;
                t = ++mark;
            } else {
                return false;
            }
        }
        while (p < pattern.length() && pattern.charAt(p) == '*') p++;
        return p == pattern.length();
    }

    // Locale.ROOT, not the default locale: in a Turkish locale "I" lowercases
    // to a dotless i, so an operator who wrote a dangerous.path in capitals
    // would have it stop matching "/delete" on their laptop and nowhere else.
    private static String lower(String s) {
        return s.toLowerCase(Locale.ROOT);
    }
}
