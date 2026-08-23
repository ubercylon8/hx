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
        theHostHalfIsGuardedInBothOfItsParts();
        aWindowsBestFitHomoglyphIsReadAsTheSeparatorItBecomes();
        aPatternWithANonAsciiCharacterAuthorisesItsEncodedForm();
        onlyTheTwoRealDotSegmentsSurviveTheTrim();
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
        theReadingSetIsSpelledOutCharacterByCharacter();
        bothDotSegmentOrdersAreInTheSet();
        decodingIsOneReadingAmongSeveralAndNotAPreprocessingStep();
        everyBestFitEntryIsGuardedByACheckOfItsOwn();
        anIncludeIsNotWidenedByASegmentTransform();
        aNulEndsTheStringForAnythingThatReachesACApi();
        theReadingSetIsClosedUnderItsOwnTransforms();
        aMalformedEscapeNeitherThrowsNorDisablesCanonicalisation();
        theQueryHalfGetsTheSameByteFoldsThePathHalfGets();
        theDangerousDenylistReadsThePathWhenAQueryIsPresent();
        anEmptyScopePatternIsAnUnusableOneAndDeniesEverything();
        aDenyRuleFoldsTheCaseOfAnUncollapsedRawReading();
        lowerFoldsTheWholeStringAndNotAPrefixOfIt();
        everySpellingAnIncludeIsReadByHasAnInputThatNeedsIt();
        aDenyRuleSeesEveryReadingOfThePath();
        anIncludeMustMatchEveryReadingOfThePath();
        aPathParameterIsStrippedBeforeTheServerNormalises();
        aBackslashIsReadAsASeparator();
        aTrailingDotSpaceOrNulIsTrimmed();
        overlongUtf8IsReadAsTheAsciiItDecodesTo();
        theRawPathIsAReadingInItsOwnRight();
        aPatternIsReadEveryWayAPathIs();
        aTargetTooBigToDecideAboutIsRefused();
        aReadingSetOverTheLimitIsRefused();
        aLegitimatelyEncodedPathIsStillAllowed();
        aTrailingSlashIsNotNewlyRefused();
        aPathOfOnlySlashesDoesNotThrow();
        aMalformedAuthorisationIsADecisionNotACrash();
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

    /**
     * F2, and it is the F5 shape in the HOST half: two guards, both deletable
     * with all 400 checks green, both flipping an out-of-scope host to ALLOW.
     * This is the half of the rule that decides which MACHINE gets touched.
     *
     * `endsWith` was tested only against the exact-host branch and never
     * against a host carrying the allowed suffix in the MIDDLE, so
     * endsWith -> contains was free. `checkHostChars` had no test at all while
     * the class comment leans on it for the claim that an encoded authority
     * never reaches a comparison.
     */
    static void theHostHalfIsGuardedInBothOfItsParts() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation subs =
                authorised("scope.include", "https://*.example.test/*");

        // The suffix must be a SUFFIX. A host that merely contains the
        // authorised name is a domain an attacker registers: everything from
        // the first label to the registrable domain is theirs.
        for (String host : List.of("app.example.test.evil.com",
                                   "evil-app.example.test.attacker.net",
                                   "example.test.evil.com",
                                   "a.example.test.b.example.net"))
            denies("a host carrying the suffix in the middle is out of scope: " + host, p,
                   req("GET", "https://" + host + "/orders", host, "/orders", ""),
                   subs, "scope_denied");

        // ...and the same for the exact-host branch, which is what the suffix
        // branch degrades to when someone "simplifies" it.
        denies("nor does an exact-host pattern match a longer host", p,
               req("GET", "https://app.example.test.evil.com/api/orders",
                   "app.example.test.evil.com", "/api/orders", ""),
               APP, "scope_denied");

        // checkHostChars. Every one of these ENDS WITH ".example.test" and is
        // therefore ALLOWED the moment the character allowlist stops running --
        // which is the whole reason the allowlist is what refuses them rather
        // than the matcher. The characters are the ones that create a SECOND
        // reading of where the request is going.
        for (String host : List.of("evil.com .example.test",       // whitespace
                                   "evil.com%2f.example.test",     // an escape
                                   "evil.com\\.example.test",       // a separator IIS reads
                                   "evil.com\u0430.example.test",   // Cyrillic a, renders as ASCII
                                   "\u0430pp.example.test"))        // and the homoglyph host itself
            denies("a host with a character no hostname can carry is refused: " + host, p,
                   req("GET", "https://" + host + "/orders", host, "/orders", ""),
                   subs, "scope_denied");

        // The refusal is about the URL's authority, so it happens whichever
        // pattern is configured -- including one that names the bad host
        // exactly. A guard that only fires for wildcard patterns is a guard
        // half the configurations do not have.
        denies("and refused even against a pattern naming it exactly", p,
               req("GET", "https://app%2eexample.test/orders",
                   "app%2eexample.test", "/orders", ""),
               authorised("scope.include", "https://app%2eexample.test/*"),
               "scope_denied");

        // And an ordinary subdomain still resolves: an allowlist that refused
        // every host would pass every check above.
        allows("an ordinary subdomain is untouched", p,
               req("GET", "https://api.example.test/orders", "api.example.test", "/orders", ""),
               subs);
    }

    /**
     * F3, the third family. Windows ANSI best-fit ("WorstFit", Black Hat EU
     * 2024): when a wide string reaches an ANSI API, a character the code page
     * cannot represent is replaced by a VISUALLY similar one rather than
     * rejected. U+FF0F becomes `/`, U+FF0E becomes `.`, U+FF3C becomes a
     * backslash -- the same mapping behind the historic `%uff0e` IIS traversal.
     *
     * The one that pays for the whole family is the first: `/x/..` U+FF0F
     * `logout` is served as `/x/../logout`, and that request ISSUES a logout.
     */
    static void aWindowsBestFitHomoglyphIsReadAsTheSeparatorItBecomes() {
        Policy p = allowingPolicy();

        reads("/x/..%ef%bc%8flogout", "/logout");         // U+FF0F -> /
        reads("/admin%ef%bc%8fusers", "/admin/users");
        reads("/x/%ef%bc%8e%ef%bc%8e/admin/users", "/admin/users");   // U+FF0E -> .
        reads("/admin%ef%bc%bcusers", "/admin/users");    // U+FF3C -> backslash -> /
        reads("/admin%ef%bc%9bx=1/users", "/admin/users");// U+FF1B -> ; -> stripped

        // The denylist, which is where a logout is stopped.
        // Only the separator-producing fold is claimed here: U+FF0E becomes a
        // `.`, and `/account.logout` is not a logout URL on anything -- the
        // denylist wants the verb after a `/` or an `=`, which is what keeps
        // `/api/blogouts` out of it.
        for (String path : List.of("/x/..%ef%bc%8flogout", "/account%ef%bc%8flogout",
                                   "/account%ef%bc%bclogout"))
            denies("a best-fit homoglyph does not hide a logout: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   APP, "dangerous_denied");

        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/admin%ef%bc%8fusers", "/x/%ef%bc%8e%ef%bc%8e/admin/users",
                                   "/admin%ef%bc%bcusers"))
            denies("nor evade an exclusion: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");

        denies("nor walk out of an include", p,
               req("GET", "https://app.example.test/app/%ef%bc%8e%ef%bc%8e/other",
                   "app.example.test", "/app/%ef%bc%8e%ef%bc%8e/other", ""),
               authorised("scope.include", "https://app.example.test/app/*"),
               "scope_denied");

        // The map is the separator-producing entries and NOTHING else. A fold
        // that mangled ordinary text would quietly change what every non-ASCII
        // pattern matches.
        check("an ordinary non-ASCII character is not best-fitted",
              "/files/caf\u00e9/x".equals(Policy.foldBestFit("/files/caf\u00e9/x")));
        allows("and a request carrying one is still decided normally", p,
               req("GET", "https://app.example.test/files/caf%c3%a9/a.pdf",
                   "app.example.test", "/files/caf%c3%a9/a.pdf", ""),
               authorised("scope.include", "https://app.example.test/files/*"));
    }

    /**
     * F4. readings() only ever DECODES, so a pattern naming a directory with a
     * non-ASCII character in it authorised NOTHING: the request's RAW reading
     * is percent-encoded, no decoding of the pattern produces that spelling,
     * and under allow-AND one uncovered reading refuses the request. The
     * operator was told their request "matches no scope.include pattern" and
     * sent to rewrite a pattern that was right.
     */
    static void aPatternWithANonAsciiCharacterAuthorisesItsEncodedForm() {
        Policy p = allowingPolicy();

        BridgeClient.Authorisation cafe = authorised(
                "scope.include", "https://app.example.test/files/caf\u00e9/*");
        for (String path : List.of("/files/caf%c3%a9/a.pdf",   // as a request carries it
                                   "/files/caf%C3%A9/a.pdf",   // the same two bytes, other case
                                   "/files/caf\u00e9/a.pdf"))   // and as the operator typed it
            allows("an include naming an accented directory authorises " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cafe);

        BridgeClient.Authorisation cjk = authorised(
                "scope.include", "https://app.example.test/files/\u4e2d\u6587/*");
        for (String path : List.of("/files/%e4%b8%ad%e6%96%87/x", "/files/\u4e2d\u6587/x"))
            allows("and a CJK one authorises " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cjk);

        // ...and still authorises nothing else. An encoding reading is not a
        // wildcard, and this is the check that fails if it becomes one.
        for (String path : List.of("/files/other/a.pdf", "/files/caf%c3%a9/../../etc/x"))
            denies("and nothing outside it: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cafe, "scope_denied");

        // The deny side of the same reading: an exclude an operator typed with
        // the character in it must catch the request that carries it encoded.
        denies("an exclude naming an accented directory is not a dead rule", p,
               req("GET", "https://app.example.test/files/caf%c3%a9/secret.pdf",
                   "app.example.test", "/files/caf%c3%a9/secret.pdf", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/files/caf\u00e9/*"),
               "scope_denied");
        denies("and neither is a dangerous.path", p,
               req("GET", "https://app.example.test/%e5%88%a0%e9%99%a4/7",
                   "app.example.test", "/%e5%88%a0%e9%99%a4/7", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "dangerous.path", "*/\u5220\u9664/*"),
               "dangerous_denied");

        // The encoder itself, both cases, including a character outside the BMP
        // -- a surrogate pair is one code point and must not be encoded as two
        // unpaired halves.
        check("percentEncodeUtf8 encodes an accented character",
              "/files/caf%c3%a9/".equals(Policy.percentEncodeUtf8("/files/caf\u00e9/", false)));
        check("and in upper hex on request",
              "/files/caf%C3%A9/".equals(Policy.percentEncodeUtf8("/files/caf\u00e9/", true)));
        check("and leaves an ASCII pattern exactly alone",
              "/admin/*".equals(Policy.percentEncodeUtf8("/admin/*", false)));
        check("and encodes a surrogate pair as one code point",
              "/x/%f0%9f%92%a9".equals(Policy.percentEncodeUtf8("/x/\ud83d\udca9", false)));
    }

    /**
     * F5 (round 4). The tail trim exempted every segment of nothing but dots,
     * which is wider than the argument for the exemption. `.` and `..` are dot
     * SEGMENTS and must survive; `...` and `....` are ORDINARY NAMES, and
     * Windows trims them to nothing exactly as it trims `admin.` to `admin`.
     */
    static void onlyTheTwoRealDotSegmentsSurviveTheTrim() {
        Policy p = allowingPolicy();

        reads("/.../admin/users", "/admin/users");
        reads("/..../admin/users", "/admin/users");
        reads("/x/.../admin/users", "/x/admin/users");

        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/.../admin/users", "/..../admin/users",
                                   "/... /admin/users"))
            denies("a run of dots trims to nothing rather than to a name: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");

        // `/x/.../admin/users` is NOT excluded by `/admin/*` and should not be:
        // trimming a segment in the MIDDLE relocates nothing to the root, and
        // the resource the server serves is `/x/admin/users`, which that
        // exclude never named. It is the exclude that names it that has to
        // catch it, and before this change nothing did.
        denies("a middle run of dots is caught by the exclude that names the result", p,
               req("GET", "https://app.example.test/x/.../admin/users",
                   "app.example.test", "/x/.../admin/users", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/x/admin/*"),
               "scope_denied");

        // The exemption that stays. `..` is a step, not a name, and trimming
        // its dots would delete the step: `/app/.. /other` has to keep reading
        // as `/other`, which is what takes it out of the include.
        readsExactly("/app/.. /other", "/app/.. /other", "/other");
        readsExactly("/a/../b", "/a/../b", "/b");
        denies("a trailing space on a dot segment still walks out of an include", p,
               req("GET", "https://app.example.test/app/.. /other",
                   "app.example.test", "/app/.. /other", ""),
               authorised("scope.include", "https://app.example.test/app/*"),
               "scope_denied");

        // And an ordinary filename ending in a dot is still trimmed, which is
        // the behaviour the exemption must not swallow.
        reads("/admin./users", "/admin/users");
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

    // ---- the reading set --------------------------------------------------

    /** readings() is a pure function, so it is tested as one. Catches
     *  Throwable: a reader that throws inside decide() is an implicit allow the
     *  moment a caller mishandles it, so "it did not throw" is part of every one
     *  of these checks, not a separate suite. */
    static Set<String> readingsOf(String in) {
        try {
            return Policy.readings(in);
        } catch (Throwable t) {
            check("readings(" + in + ") threw " + t.getClass().getSimpleName(), false);
            return Set.of();
        }
    }

    /** `want` is one of the ways this path can be read. */
    static void reads(String in, String want) {
        Set<String> got = readingsOf(in);
        check("readings(" + in + ") includes \"" + want + "\" (got " + got + ")",
              got.contains(want));
    }

    /**
     * The set is EXACTLY these, which is the half of the contract membership
     * checks cannot see. readings() returning every string in the universe
     * would satisfy every reads() below and refuse every request on earth,
     * because an include has to cover the whole set.
     */
    static void readsExactly(String in, String... want) {
        Set<String> got = readingsOf(in);
        check("readings(" + in + ") is exactly " + Arrays.asList(want) + " (got " + got + ")",
              got.equals(new LinkedHashSet<>(Arrays.asList(want))));
    }

    static void theReadingSetIsSpelledOutCharacterByCharacter() {
        // The identity cases first: a reader that mangles ordinary paths would
        // be caught by the scope tests above, but not clearly. These are
        // readsExactly, because "an ordinary path has ONE reading" is also the
        // statement that this costs one glob per rule on the hot path.
        readsExactly("/api/orders", "/api/orders");
        readsExactly("/", "/");
        readsExactly("", "");

        // Percent-decoding. %6f is the one that shipped: it decodes to `o` on
        // essentially every server, so /account/log%6fut IS a logout.
        reads("/account/log%6fut", "/account/logout");
        reads("/adm%69n/users", "/admin/users");
        reads("/x/%41", "/x/a");                       // uppercase hex, then lowercased
        reads("/files/annual%20report.pdf", "/files/annual report.pdf");

        // %2f decodes to a separator, and it does so BEFORE the path is split
        // into segments -- otherwise /admin%2fusers is one opaque segment that
        // no /admin/* pattern can reach.
        reads("/admin%2fusers", "/admin/users");
        reads("/admin%2Fusers", "/admin/users");

        // To a FIXED POINT, not once: %2570 is `%70` is `p`.
        reads("/account/%2570assword/change", "/account/password/change");
        reads("/api/%252e%252e/admin", "/admin");

        // Dot segments, encoded and not. Decoding first is what makes the
        // second of these behave like the first.
        reads("/api/../admin/users", "/admin/users");
        reads("/api/%2e%2e/admin/users", "/admin/users");
        reads("/a/./b", "/a/b");
        reads("/a/b/..", "/a/");                       // trailing slash survives
        reads("/a/b/.", "/a/b/");
        reads("/a/", "/a/");
        reads("/..", "/");
        reads("/../../etc/passwd", "/etc/passwd");     // .. at the root is discarded

        // Case.
        reads("/ADMIN/Users", "/admin/users");

        // Empty segments merged, which is what a slash-merging server does.
        reads("/app//admin", "/app/admin");
        reads("//admin/users", "/admin/users");
        reads("/admin//users", "/admin/users");
        reads("/admin/", "/admin/");
        reads("////", "/");
        reads("/%2fadmin/users", "/admin/users");

        // CLOSURE, which is what "until stable" has to mean: reading a reading
        // adds nothing. The first three inputs carry ONE trigger character
        // each, and for two rounds they were the only inputs this loop was
        // given -- which made the check pass while the property was false. The
        // last three carry TWO, which is what it takes: the transforms COMPOSE,
        // and a composition creates a trigger the base did not have.
        for (String p : List.of("/api/%252e%252e/admin", "/a%2525b", "/ADMIN/%2e%2e/x",
                                "/admin%20;x/users", "/admin.%5cusers",
                                "/app/..%20;/other"))
            for (String r : readingsOf(p))
                check("readings is closed on " + p + " -> " + r,
                      readingsOf(p).containsAll(readingsOf(r)));
    }


    /**
     * Round 6, CRITICAL. Decoding was the one MANDATORY transform in
     * readings(): every other transform was offered both on and off through
     * addReadings' `applicable` subsets, while the un-decoded member was in
     * the set only VERBATIM and UNRESOLVED. So collapseDotSegments(raw) was
     * never a member -- and that is precisely what RFC 3986 s6.2.2 specifies
     * and what all three of the libraries the class comment cites as its
     * authority actually produce:
     *
     *   /foo%2fbar/../admin/users
     *     python urljoin()       -> /admin/users
     *     node   new URL()       -> /admin/users
     *     java   URI.normalize() -> /admin/users
     *     readings()             -> { raw, /foo/admin/users }
     *
     * `..` popped `foo/bar` on our reading and `foo%2fbar` on theirs, and the
     * two land in different places. Five live bypasses on the shipped jar with
     * all 490 checks green, every one of them a walk past an exclusion by
     * spelling one separator as %2f.
     */
    static void decodingIsOneReadingAmongSeveralAndNotAPreprocessingStep() {
        Policy p = allowingPolicy();

        // The RFC reading: dot segments resolved over the RAW segments, where
        // %2f is not a separator and `foo%2fbar` is one segment to pop.
        reads("/foo%2fbar/../admin/users", "/admin/users");
        reads("/x%2fy%2fz/../admin/", "/admin/");
        reads("/api/x%2fy/../payments/charge", "/api/payments/charge");

        // The reading of a server that decodes AFTER it has cut the path into
        // segments -- Apache with AllowEncodedSlashes off, nginx, Tomcat, and
        // every framework that unescapes only the segment values it hands on.
        // It is the ONLY one that resolves this: the %2e%2e becomes a `..`
        // while `a%2fb` stays one segment for it to pop. Neither decoding
        // everything nor decoding nothing reaches it.
        reads("/a%2fb/%2e%2e/admin/users", "/admin/users");
        check("...and it is not reachable by decoding everything: %2f read as a "
              + "separator gives /a/admin/users",
              Policy.readings("/a%2fb/%2e%2e/admin/users").contains("/a/admin/users"));
        check("nor by decoding nothing: the raw path has no dot segment at all",
              "/a%2fb/%2e%2e/admin/users".equals(
                      Policy.collapseDotSegments("/a%2fb/%2e%2e/admin/users")));

        // The decoding reading is still there. It has to be: %2f IS a
        // separator on a server that unescapes before it routes.
        reads("/foo%2fbar/../admin/users", "/foo/admin/users");
        // And the bytes on the wire are still a reading of their own.
        reads("/foo%2fbar/../admin/users", "/foo%2fbar/../admin/users");

        // Live, past an exclusion. Every one of these was ALLOW.
        BridgeClient.Authorisation admin =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/foo%2fbar/../admin/users",
                                   "/a%2fb/%2e%2e/admin/users",
                                   "/x%2fy%2fz/../admin/"))
            denies("an encoded separator does not walk past an exclusion: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   admin, "scope_denied");

        denies("nor past a deeper one", p,
               req("GET", "https://app.example.test/api/x%2fy/../payments/charge",
                   "app.example.test", "/api/x%2fy/../payments/charge", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/api/payments/*"),
               "scope_denied");

        // The exclusion on a wildcard host, because the host half is a
        // different branch and an operator's exclude is as often written that
        // way as it is against one name.
        denies("nor past a wildcard-host exclusion", p,
               req("GET", "https://app.example.test/blog%2fposts/../wp-admin/admin-ajax.php",
                   "app.example.test", "/blog%2fposts/../wp-admin/admin-ajax.php", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://*.example.test/wp-admin/*"),
               "scope_denied");

        // The control the whole table is read against: with no escape in it
        // the same shape was ALWAYS refused, which is what made the five above
        // look like a rule that worked.
        denies("the same shape with no escape in it was never allowed", p,
               req("GET", "https://app.example.test/foo/bar/../../admin/users",
                   "app.example.test", "/foo/bar/../../admin/users", ""),
               admin, "scope_denied");

        // The include side of the same reading.
        denies("an encoded separator cannot walk out of an include either", p,
               req("GET", "https://app.example.test/app/x%2fy/../../other",
                   "app.example.test", "/app/x%2fy/../../other", ""),
               authorised("scope.include", "https://app.example.test/app/*"),
               "scope_denied");

        // And the ordinary encoded path is untouched: a reader that refused
        // everything with a %2f in it would pass every check above.
        allows("an encoded separator inside the scope is still decided normally", p,
               req("GET", "https://app.example.test/files/a%2fb.pdf",
                   "app.example.test", "/files/a%2fb.pdf", ""),
               authorised("scope.include", "https://app.example.test/files/*"));

        // decodeSeparatorsInert on its own: everything unwrapped except what
        // would become a separator, however deeply that was nested.
        check("the inert decode leaves %2f alone and decodes the rest",
              "/a%2fb/../c d".equals(Policy.decodeSeparatorsInert("/a%2fb/%2e%2e/c%20d")));
        check("and unwraps %252f exactly one round, to %2f",
              "/a%2f".equals(Policy.decodeSeparatorsInert("/a%252f")));
        check("and leaves an encoded backslash alone too",
              "/a%5cb".equals(Policy.decodeSeparatorsInert("/a%5cb")));
        check("while the full decode still turns both into separators",
              "/a/b".equals(Policy.decodeToFixedPoint("/a%2fb"))
              && "/a\\b".equals(Policy.decodeToFixedPoint("/a%5cb")));
    }

    /**
     * Round 6, HIGH. Six of the thirteen best-fit entries could be deleted
     * with all 490 checks green while flipping a denial to ALLOW -- including
     * the one that reads U+2215 as a separator, which turns
     * `/x/..(that character)logout` into a request that ISSUES a real logout.
     * Every entry in a security table needs a check, or the table gets trimmed
     * silently, which this task has already shipped twice.
     *
     * Round 7, CRITICAL: THE TABLE WAS NOT THE TABLE. thirteen entries were
     * guarded and the mapping has a hundred and five, because bestfit1252.txt
     * maps the WHOLE fullwidth block -- all 94 code points of U+FF01..U+FF5E,
     * onto printable ASCII at a fixed offset. `foldBestFit` said, in a comment,
     * that "none of the rest changes how a path is READ"; a fullwidth spelling
     * of `logout` is `logout` to any ANSI API, and the denylist is a list of
     * words. Three live rows, on the shipped defaults, before the range folded:
     *
     *   /account/(fullwidth logout)  ALLOW -- an automated logout
     *   /account/l(U+FF0F)gout       ALLOW -- one letter is enough
     *   /(U+FF41)dmin/users          ALLOW past exclude=/admin/*
     *
     * ...and the control below asserted the opposite of the truth: it named
     * U+FF10 FULLWIDTH DIGIT ZERO as "a fullwidth character bestFit() does NOT
     * map", which the real table maps to `0`. It stayed green because `0` is
     * not a separator, so a table entry that was missing AND a control that was
     * wrong agreed with each other. The control is U+3042 HIRAGANA LETTER A
     * now, verified absent rather than assumed: bestfit1252.txt's WCTABLE has
     * 698 entries, and neither U+3042 nor any other kana is one of them --
     * CP1252 has no representation of kana and no Latin character that looks
     * like one, so WideCharToMultiByte substitutes the code page's default
     * character rather than a best fit.
     *
     * DISCOVERED, not listed. The table below is built by asking foldBestFit
     * about every code point in the BMP, so an entry cannot be added without a
     * check or removed without a failure -- which is what "thirteen" was
     * supposed to buy and did not.
     */
    static void everyBestFitEntryIsGuardedByACheckOfItsOwn() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");

        // (1) The whole mapping, discovered by asking rather than by listing.
        List<Character> mapped = new ArrayList<>();
        for (int c = 0x80; c <= 0xffff; c++) {
            String one = String.valueOf((char) c);
            if (!Policy.foldBestFit(one).equals(one)) mapped.add((char) c);
        }
        check("foldBestFit maps " + mapped.size() + " code points, every one of "
              + "them checked below", mapped.size() == 105);

        // (2) The fullwidth block, as one rule rather than 94 entries. Verified
        // against the real bestfit1252.txt: 94 of its 698 WCTABLE entries are
        // U+FF01..U+FF5E and every one maps to its code point minus 0xFEE0.
        int fullwidth = 0;
        for (char c = 0xff01; c <= 0xff5e; c++)
            if (Policy.foldBestFit(String.valueOf(c))
                      .equals(String.valueOf((char) (c - Policy.FULLWIDTH_OFFSET))))
                fullwidth++;
        check("all 94 code points U+FF01..U+FF5E fold to their code point minus 0x"
              + Integer.toHexString(Policy.FULLWIDTH_OFFSET).toUpperCase(Locale.ROOT)
              + " (" + fullwidth + " of 94)", fullwidth == 94);
        check("...which is what makes a fullwidth `l` an `l` and a fullwidth "
              + "`A` an `A`",
              "l".equals(Policy.foldBestFit("ｌ"))
              && "A".equals(Policy.foldBestFit("Ａ"))
              && "0".equals(Policy.foldBestFit("０")));

        // (3) The entries OUTSIDE that block, one check each. Three are
        // bestfit1252's own (U+037E, U+066A, U+2216); the rest are best fits in
        // other code pages' tables and are kept because a PATH reading only
        // ever denies more.
        Map<Character, Character> outliers = new LinkedHashMap<>();
        outliers.put('∕', '/');   // DIVISION SLASH
        outliers.put('⁄', '/');   // FRACTION SLASH
        outliers.put('⧸', '/');   // BIG SOLIDUS
        outliers.put('∖', '\\');  // SET MINUS
        outliers.put('﹨', '\\');  // SMALL REVERSE SOLIDUS
        outliers.put('﹒', '.');   // SMALL FULL STOP
        outliers.put('｡', '.');   // HALFWIDTH IDEOGRAPHIC FULL STOP
        outliers.put('․', '.');   // ONE DOT LEADER
        outliers.put(';', ';');   // GREEK QUESTION MARK
        outliers.put('﹔', ';');   // SMALL SEMICOLON
        outliers.put('٪', '%');   // ARABIC PERCENT SIGN
        List<Character> outside = new ArrayList<>();
        for (char c : mapped) if (c < 0xff01 || c > 0xff5e) outside.add(c);
        check("the entries outside the fullwidth block are exactly the "
              + outliers.size() + " named here (found " + outside.size() + ")",
              new LinkedHashSet<>(outside).equals(new LinkedHashSet<>(outliers.keySet())));
        for (Map.Entry<Character, Character> e : outliers.entrySet())
            check(String.format("U+%04X best-fits to %s", (int) e.getKey(),
                                displayable(e.getValue())),
                  String.valueOf(e.getValue())
                        .equals(Policy.foldBestFit(String.valueOf(e.getKey()))));

        // (4) Every entry, tied to the reading machinery: the path spelt with
        // the homoglyph must READ as the path spelt with what it folds to. An
        // entry deleted from the table fails here even when what it folds to is
        // an ordinary letter and no separator moves.
        int reads = 0;
        for (char c : mapped) {
            char fit = Policy.foldBestFit(String.valueOf(c)).charAt(0);
            String spelt = "/admin/" + c + "leaf";
            String folded = "/admin/" + fit + "leaf";
            String want = Policy.lower(Policy.collapseDotSegments(
                    Policy.collapseEmptySegments(folded)));
            if (Policy.readings(spelt).contains(want)) reads++;
            else check(String.format("U+%04X: %s has no reading %s",
                                     (int) c, spelt, want), false);
        }
        check("every one of the " + mapped.size() + " entries puts the folded "
              + "spelling in the homoglyph's reading set (" + reads + ")",
              reads == mapped.size());

        // (5) The separator-producing entries, end to end, one shape each.
        // SEP: the homoglyph is where the separator goes. DOT: two of them are
        // the `..` that pops a segment. SEMI: it opens a path parameter a
        // servlet container strips. PCT: it manufactures the escape that
        // decodes to a separator.
        int separators = 0;
        for (char c : mapped) {
            char fit = Policy.foldBestFit(String.valueOf(c)).charAt(0);
            String shape = fit == '/' || fit == '\\' ? "SEP"
                         : fit == '.' ? "DOT"
                         : fit == ';' ? "SEMI"
                         : fit == '%' ? "PCT" : null;
            if (shape == null) continue;
            separators++;
            String path = bestFitProbe(String.valueOf(c), shape);
            denies(String.format("U+%04X is read as the %s it best-fits to: %s",
                                 (int) c, shape, path), p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");
        }
        check("the separator-producing entries are the 5 fullwidth ones plus the "
              + "11 outside the block (" + separators + ")", separators == 16);

        // The controls, one per shape, with a character that is genuinely NOT
        // in the table -- see the header for how that was verified. Without
        // these the probes above would pass with foldBestFit replaced by "map
        // every non-ASCII character to a slash".
        check("U+3042 HIRAGANA LETTER A is not in the table at all",
              "あ".equals(Policy.foldBestFit("あ"))
              && Policy.readings("/admin/あleaf").size() == 1);
        for (String shape : List.of("SEP", "DOT", "SEMI", "PCT")) {
            String path = bestFitProbe("あ", shape);
            allows("a character that is NOT in the table is left alone: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg);
        }

        // The entries that pay for the whole family: these requests ISSUE a
        // logout, and the denylist is the only thing between an agent working
        // from a traversal wordlist and the session.
        for (String cp : List.of("／", "∕", "⁄", "⧸",
                                 "＼", "﹨", "∖"))
            for (String path : List.of("/x/.." + Policy.percentEncodeUtf8(cp, false) + "logout"))
                denies("a best-fit separator does not hide a logout: " + path, p,
                       req("GET", "https://app.example.test" + path,
                           "app.example.test", path, ""),
                       APP, "dangerous_denied");

        // ...and the rows the fullwidth range was added for, which need no
        // separator at all: a fullwidth SPELLING of a dangerous word is that
        // word to an ANSI API, and one substituted letter is enough.
        String fullLogout = Policy.percentEncodeUtf8("ｌｏｇｏｕｔ", false);
        denies("a wholly fullwidth logout is still a logout: /account/" + fullLogout, p,
               req("GET", "https://app.example.test/account/" + fullLogout,
                   "app.example.test", "/account/" + fullLogout, ""),
               APP, "dangerous_denied");
        String oneLetter = "/account/l" + Policy.percentEncodeUtf8("ｏ", false) + "gout";
        denies("and one fullwidth letter inside it is enough: " + oneLetter, p,
               req("GET", "https://app.example.test" + oneLetter,
                   "app.example.test", oneLetter, ""),
               APP, "dangerous_denied");
        String fullAdmin = "/" + Policy.percentEncodeUtf8("ａ", false) + "dmin/users";
        denies("nor does a fullwidth letter walk past an exclusion: " + fullAdmin, p,
               req("GET", "https://app.example.test" + fullAdmin,
                   "app.example.test", fullAdmin, ""),
               cfg, "scope_denied");

        // THE COST OF THE RANGE, pinned rather than found later. A best-fit
        // reading is a reading of a PATH and of a DENY pattern, never of an
        // ALLOW pattern (see spellingReadings), so an include that CARRIES a
        // fullwidth character now authorises nothing -- the request keeps the
        // folded reading and the pattern does not name it. That is the same
        // accepted cost a segment trigger in an include already has. An include
        // spelt in ASCII is untouched, which is the half that matters: the fold
        // changes a NAME, not the prefix a scope is anchored at.
        allows("an ASCII include still authorises a fullwidth path under it", p,
               req("GET", "https://app.example.test/files/ｄｏｃ.pdf",
                   "app.example.test", "/files/ｄｏｃ.pdf", ""),
               authorised("scope.include", "https://app.example.test/files/*"));
        allows("and a non-ASCII name the table does not map is untouched", p,
               req("GET", "https://app.example.test/files/テスト.pdf",
                   "app.example.test", "/files/テスト.pdf", ""),
               authorised("scope.include", "https://app.example.test/files/*"));
        denies("while an include that carries one authorises nothing -- the "
               + "accepted cost", p,
               req("GET", "https://app.example.test/ａpp/x",
                   "app.example.test", "/ａpp/x", ""),
               authorised("scope.include", "https://app.example.test/ａpp/*"),
               "scope_denied");
    }

    /** A character a check can print. */
    static String displayable(char c) {
        return c == '\\' ? "a backslash" : "`" + c + "`";
    }

    /** The path shape whose refusal depends on `cp` best-fitting to its
     *  character, spelt the way a request carries it. */
    static String bestFitProbe(String cp, String shape) {
        String e = Policy.percentEncodeUtf8(cp, false);
        switch (shape) {
            case "SEP":  return "/admin" + e + "users";
            case "DOT":  return "/x/" + e + e + "/admin/users";
            case "SEMI": return "/admin" + e + "x=1/users";
            default:     return "/admin" + e + "2fusers";
        }
    }

    /**
     * Round 6, MEDIUM. A single trigger character in an INCLUDE silently
     * widened the authorised set, because allows() accepts coverage by any
     * pattern reading and patternReadings() carried the segment transforms:
     *
     *   include=/app;v=1/*    ->  /app/secret        ALLOW
     *   include=/a(backslash)b/*  ->  /a/b/secret    ALLOW
     *   include=/admin./*     ->  /admin/users       ALLOW
     *   include=/../*         ->  /anything/at/all   ALLOW -- the whole host
     *
     * The distinction that makes this different from round 3's fix: an
     * ENCODING reading is a different SPELLING of one resource and is right
     * for both kinds of rule; a SEGMENT reading names a DIFFERENT resource,
     * and on the one rule that authorises anything that is a live bypass.
     */
    static void anIncludeIsNotWidenedByASegmentTransform() {
        Policy p = allowingPolicy();

        String[][] rows = {
            {"/app;v=1/*",   "/app/secret"},
            {"/a\\b/*",      "/a/b/secret"},
            {"/admin./*",    "/admin/users"},
            {"/../*",        "/anything/at/all"},
            {"/app//x/*",    "/app/x/secret"},
        };
        for (String[] row : rows)
            denies("include=" + row[0] + " does not authorise " + row[1], p,
                   req("GET", "https://app.example.test" + row[1],
                       "app.example.test", row[1], ""),
                   authorised("scope.include", "https://app.example.test" + row[0]),
                   "scope_denied");

        // The COST of the ruling, pinned rather than discovered later. An
        // include with a segment trigger in it now authorises NOTHING, not
        // even the path it literally spells: the request still has a reading
        // the pattern does not name (a servlet container serves
        // /app;v=1/secret as /app/secret) and allow-AND refuses on it. That is
        // the fail-closed answer and it is a visible one -- the operator is
        // told the request matches no scope.include pattern -- but it is a
        // cost, and an operator who means both resources writes both lines.
        for (String[] row : new String[][]{
                {"/app;v=1/*", "/app;v=1/secret"},
                {"/a\\b/*",    "/a\\b/secret"},
                {"/admin./*",  "/admin./users"}})
            denies("include=" + row[0] + " authorises nothing at all, including "
                   + row[1] + " -- the accepted cost", p,
                   req("GET", "https://app.example.test" + row[1],
                       "app.example.test", row[1], ""),
                   authorised("scope.include", "https://app.example.test" + row[0]),
                   "scope_denied");
        // ...and the remedy is ONE pattern covering both readings, not two
        // patterns covering one each: allows() asks a single rule to cover the
        // whole set, which is what stops two half-scopes adding up to an
        // authorisation neither of them granted.
        allows("an operator writes one include that covers both readings", p,
               req("GET", "https://app.example.test/app;v=1/secret",
                   "app.example.test", "/app;v=1/secret", ""),
               authorised("scope.include", "https://app.example.test/app*"));
        denies("and two half-scopes do not add up to one", p,
               req("GET", "https://app.example.test/app;v=1/secret",
                   "app.example.test", "/app;v=1/secret", ""),
               authorised("scope.include", "https://app.example.test/app;v=1/*",
                          "scope.include", "https://app.example.test/app/*"),
               "scope_denied");

        // The ENCODING axis is untouched, which is round 3's fix and must stay
        // fixed. An include written with an escape has to authorise both
        // spellings, and one naming an accented directory has to authorise the
        // percent-encoded UTF-8 a request actually carries.
        BridgeClient.Authorisation docs =
                authorised("scope.include", "https://app.example.test/files/my%20docs/*");
        for (String path : List.of("/files/my%20docs/a.pdf", "/files/my docs/a.pdf"))
            allows("an include written with an escape still authorises " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   docs);
        allows("and one naming an accented directory still authorises its encoded form", p,
               req("GET", "https://app.example.test/files/caf%c3%a9/a.pdf",
                   "app.example.test", "/files/caf%c3%a9/a.pdf", ""),
               authorised("scope.include", "https://app.example.test/files/café/*"));

        // The DENY side keeps everything, which is the other half of the
        // ruling: the same patterns as exclusions still catch the resource
        // they name on a server that transforms segments.
        for (String[] row : new String[][]{
                {"/admin;v=1/*", "/admin/users"},
                {"/admin\\x/*",  "/admin/x/users"},
                {"/admin./*",    "/admin/users"}})
            denies("exclude=" + row[0] + " still denies " + row[1], p,
                   req("GET", "https://app.example.test" + row[1],
                       "app.example.test", row[1], ""),
                   authorised("scope.include", "https://app.example.test/*",
                              "scope.exclude", "https://app.example.test" + row[0]),
                   "scope_denied");

        // And the two reading sets really are different sets, said directly so
        // that a future "simplification" back to one has to delete a check.
        check("an allow pattern's readings are its spellings only (got "
              + Policy.spellingReadings("/../*") + ")",
              !Policy.spellingReadings("/../*").contains("/*")
              && Policy.spellingReadings("/../*").contains("/../*"));
        check("a deny pattern's readings still resolve its dot segments (got "
              + Policy.patternReadings("/../*") + ")",
              Policy.patternReadings("/../*").contains("/*"));
        check("an allow pattern still decodes (got "
              + Policy.spellingReadings("/my%20docs/*") + ")",
              Policy.spellingReadings("/my%20docs/*").contains("/my docs/*"));
    }

    /**
     * Round 6, MEDIUM. Two comments claimed a reading the code did not build:
     * "a NUL is where a C string ends, so `/admin%00foo` reaches `/admin`".
     * trimSegmentTails only ever trimmed a TRAILING NUL, so `/admin%00.html`
     * was ALLOW past an exclusion naming `/admin` -- and the truncation is
     * real server behaviour, so building it is the right half of "build it or
     * delete the claim".
     */
    static void aNulEndsTheStringForAnythingThatReachesACApi() {
        Policy p = allowingPolicy();

        reads("/admin%00foo", "/admin");
        reads("/admin%00.html", "/admin");
        reads("/admin%00/users", "/admin");
        // The tail trim's own reading survives beside it: they are different
        // servers, and a name that ends in a NUL is not a string that does.
        reads("/admin%00/users", "/admin/users");
        readsExactly("/admin%00foo", "/admin%00foo", "/admin\0foo", "/admin");

        check("truncateAtNul cuts at the first NUL and keeps everything before it",
              "/admin".equals(Policy.truncateAtNul("/admin\0/users/x"))
              && "/a/b".equals(Policy.truncateAtNul("/a/b")));

        // Live: the exclusion that was walked past by appending six characters
        // to a path it already caught.
        BridgeClient.Authorisation exact =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin");
        for (String path : List.of("/admin%00.html", "/admin%00/users", "/admin%00foo"))
            denies("a NUL does not hide an exclusion naming /admin: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   exact, "scope_denied");

        // And the denylist. The verb is at the END of the pattern, so only the
        // truncation reaches it -- and the verb is one the SHIPPED DEFAULTS do
        // not carry, because the first version of this check used `*/logout`
        // and passed with the truncation deleted: the default `*/logout*`
        // caught it on its own. That is the same vacuous shape round 4 found
        // in its own new test, and the sabotage run is what said so again.
        denies("a NUL does not hide an operator's dangerous.path", p,
               req("GET", "https://app.example.test/data/export%00.png",
                   "app.example.test", "/data/export%00.png", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "dangerous.path", "*/export"),
               "dangerous_denied");
        check("...and the shipped defaults do not catch that one on their own",
              !Policy.DEFAULT_DANGEROUS.stream().anyMatch(
                      g -> Policy.glob(g, "/data/export\0.png")));

        // A NUL that truncates to something still inside the scope must not
        // cost an operator their request: the truncation is a reading, not a
        // denylist of its own.
        allows("a NUL inside an included prefix is still in scope", p,
               req("GET", "https://app.example.test/app/a%00b",
                   "app.example.test", "/app/a%00b", ""),
               authorised("scope.include", "https://app.example.test/app/*"));
    }

    /**
     * F1, round 4, and it is the round-3 machinery biting itself.
     *
     * addReadings computes which transforms are `applicable` from the BASE, and
     * the comment on it claimed that was safe because "each of the three is the
     * identity on a string without its trigger character, so a skipped
     * combination would have produced a member the set already holds". The
     * first clause is true. The second does not follow, because the transforms
     * COMPOSE: stripping a `;param` or folding a backslash CREATES a segment
     * tail the base did not carry, so TRIM_TAILS never switched on and that
     * reading was never built.
     *
     * Live on the shipped jar with all 400 checks green: `/admin /users` was
     * caught by the trim alone, and appending two characters -- `;x` -- made it
     * ALLOW. Tomcat strips the parameter, Windows trims the trailing space, and
     * the request served is `/admin/users` inside an engagement that excluded
     * it. Third false invariant in a comment on this task; the fixed point is
     * the honest version of what the comment already claimed.
     */
    static void theReadingSetIsClosedUnderItsOwnTransforms() {
        Policy p = allowingPolicy();

        // The composed readings themselves, spelt out. Each needs at least two
        // passes: the first creates the trigger, the second acts on it.
        reads("/admin%20;x/users", "/admin/users");   // strip ;x, THEN trim the space
        reads("/admin.%5cusers", "/admin/users");     // fold the backslash, THEN trim the dot
        reads("/admin.;x/users", "/admin/users");
        reads("/app/..%20;/other", "/other");
        reads("/app/..%00;/other", "/other");
        // Closure is over SEQUENCES of transforms, not the single order one pass
        // applies them in. Every member is fed back through, so a path with two
        // triggers in one segment is read as both of the resources it can
        // become -- a servlet container's, and a container-plus-IIS one.
        reads("/a;b%5cc", "/a/c");
        reads("/a;b%5cc", "/a");

        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/admin /users",          // one trigger: was caught
                                   "/admin%20;x/users",      // two: was ALLOWED
                                   "/admin%20%5cusers",
                                   "/admin.;x/users",
                                   "/admin.%5cusers"))
            denies("a second transform does not hide an exclusion: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");

        BridgeClient.Authorisation app =
                authorised("scope.include", "https://app.example.test/app/*");
        for (String path : List.of("/app/..%20/other",        // one trigger: was caught
                                   "/app/..%20;/other",       // two: was ALLOWED
                                   "/app/..%00;/other",
                                   "/app/..;%20/other"))
            denies("nor walk out of an include: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   app, "scope_denied");

        // And the property itself, on inputs nobody chose. A hand-written list
        // is exactly what let this ship: every input the closure check was
        // given carried one trigger, so it could not fail. The seed is fixed so
        // a failure is reproducible, and the alphabet is the one an evasion is
        // built from.
        // U+0130 is in the alphabet because of what it did to two different
        // claims. LATIN CAPITAL LETTER I WITH DOT ABOVE has a FULL lowercase
        // mapping of TWO characters -- an `i` and a combining dot -- so
        // String.toLowerCase LENGTHENS on it, and readings()' termination
        // argument ("every transform shortens or preserves its length") was
        // false while it was written down. It was not only an argument: a cost
        // search looking for the most expensive decide() it could build landed
        // on a path of 8190 of them, which cost 99 ms and was ALLOWED, with a
        // reading set of TWO members that no bound on the set size could have
        // caught. lower() is Unicode's SIMPLE mapping now, one code point in
        // and one out, so the claim is true because the code changed.
        check("String.toLowerCase lengthens on U+0130, which is what the "
              + "termination argument rested on being false",
              "\u0130".toLowerCase(Locale.ROOT).length() == 2);
        check("Policy.lower does not: one code point in, one code point out",
              "i".equals(Policy.lower("\u0130")));
        check("and it folds with no locale at all, so a Turkish default cannot "
              + "turn an I into a dotless one",
              "i".equals(Policy.lower("I")) && "abc".equals(Policy.lower("ABC")));
        check("and it still folds the non-ASCII case an operator might write",
              "caf\u00e9".equals(Policy.lower("CAF\u00c9")));
        for (String m : readingsOf("/\u0130\u0130;x/\u0130."))
            check("no reading of a U+0130 path is longer than the path ("
                  + m.length() + ")", m.length() <= "/\u0130\u0130;x/\u0130.".length());
        check("and a path carrying it still terminates and is closed",
              readingsOf("/\u0130/..;x/\u0130.").containsAll(
                      readingsOf(Policy.lower("/\u0130/..;x/\u0130."))));

        // The cost, which is the half a comment cannot enforce. This is the
        // check that goes red if lower() is ever "simplified" back to
        // String.toLowerCase(Locale.ROOT).
        String dotted = "/" + "\u0130".repeat(Policy.MAX_TARGET_CHARS - 1);
        HxRequest dottedReq = req("GET", "https://app.example.test" + dotted,
                                  "app.example.test", dotted, "");
        p.decide(dottedReq, APP);
        long dotStart = System.nanoTime();
        Decision dotVerdict = p.decide(dottedReq, APP);
        long dotMs = (System.nanoTime() - dotStart) / 1_000_000;
        check("a path of " + (Policy.MAX_TARGET_CHARS - 1) + " U+0130 characters is "
              + "decided in " + dotMs + " ms (was 99 ms, and allowed)",
              dotMs < 30 && dotVerdict != null);

        char[] alphabet = ("ab/./..;\\ %2e2f5c%c0%aeADMIN" + '\0'
                + "\u00c0\u00ae\uff0f\uff0e\u0130\u2215\ufe52").toCharArray();
        Random rnd = new Random(20260822L);
        int violations = 0, biggest = 0;
        String firstBad = null;
        for (int i = 0; i < 20_000; i++) {
            StringBuilder b = new StringBuilder("/");
            int len = 1 + rnd.nextInt(24);
            for (int j = 0; j < len; j++) b.append(alphabet[rnd.nextInt(alphabet.length)]);
            Set<String> set = Policy.readings(b.toString());
            biggest = Math.max(biggest, set.size());
            for (String r : new ArrayList<>(set))
                if (!set.containsAll(Policy.readings(r))) {
                    violations++;
                    if (firstBad == null) firstBad = b.toString();
                    break;
                }
        }
        check("readings is closed on 20,000 random paths (" + violations
              + " violation(s), largest set " + biggest
              + (firstBad == null ? "" : ", first " + firstBad) + ")",
              violations == 0);
    }

    /**
     * The defect the whole set model exists for.
     *
     * canonical() used to return ONE string, so it had to pick a rule for
     * `/a//../admin/users`, and there is no rule to pick: python's urljoin and
     * node's URL both answer /a/admin/users, java's URI.normalize answers
     * /admin/users. This class picked merge-then-resolve and the reviewer walked
     * straight past an exclude of /a/admin/* -- merging first does not SHORTEN
     * the path, it RELOCATES it out from under a glob anchored at the prefix the
     * merge deleted.
     *
     * Both readings are in the set, so there is nothing left to pick.
     */
    static void bothDotSegmentOrdersAreInTheSet() {
        readsExactly("/a//../admin/users",
                     "/a//../admin/users",   // the bytes on the wire
                     "/admin/users",         // merge the empty segment, then pop `a`
                     "/a/admin/users");      // RFC 3986: `..` pops the empty segment

        // And the deny rule that was evaded now catches it under EITHER
        // spelling of the exclude, which is the point of holding both.
        Policy p = allowingPolicy();
        for (String pattern : List.of("https://app.example.test/a/admin/*",
                                      "https://app.example.test/admin/*"))
            denies("neither reading of /a//../admin/users escapes " + pattern, p,
                   req("GET", "https://app.example.test/a//../admin/users",
                       "app.example.test", "/a//../admin/users", ""),
                   authorised("scope.include", "https://app.example.test/*",
                              "scope.exclude", pattern),
                   "scope_denied");
    }

    /**
     * A malformed escape must not throw, and it must not switch
     * canonicalisation off for the rest of the string either: abandoning the
     * whole path on one bad escape would let an attacker disable the denylist
     * by appending a single `%`.
     */
    static void aMalformedEscapeNeitherThrowsNorDisablesCanonicalisation() {
        readsExactly("%", "%");
        readsExactly("/a%", "/a%");
        readsExactly("/a%z", "/a%z");
        readsExactly("/a%4", "/a%4");
        readsExactly("%%%", "%%%");
        readsExactly("/a%zz/b", "/a%zz/b");
        // The escape is bad; the ones around it are not, and they still decode.
        reads("/a%%41", "/a%a");
        reads("/adm%69n/%/users", "/admin/%/users");

        // The whole point, at the level that matters: a trailing `%` does not
        // buy a logout.
        Policy p = allowingPolicy();
        for (String path : List.of("/account/log%6fut%", "/account/log%6fut%z",
                                   "/account/%/log%6fut"))
            denies("a malformed escape does not disable the denylist: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   APP, "dangerous_denied");
    }

    /**
     * The defect this section exists for. Policy matched scope and dangerous
     * paths against the literal wire bytes and nothing canonicalised anything,
     * so every request below was ALLOWED against the built jar -- including
     * `/account/log%6fut`, which is the exact action the denylist exists to
     * prevent.
     *
     * A deny rule -- scope.exclude and dangerous.path -- matches the raw path
     * OR its canonical form, case-folded. The request on the wire is unchanged.
     */
    static void aDenyRuleSeesEveryReadingOfThePath() {
        Policy p = allowingPolicy();

        // dangerous.path, against the shipped defaults.
        for (String path : List.of("/account/log%6fut",              // was ALLOW
                                   "/account/p%61ssword/change",     // was ALLOW
                                   "/account/%2570assword/change",   // double-encoded
                                   "/account/LOG%4FUT",              // encoded and cased
                                   "/api/%2e%2e/account/log%6fut"))  // and dotted
            denies("an encoded dangerous path is still dangerous: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   APP, "dangerous_denied");

        // The denylist reads the query as well, so the query is decoded too --
        // on a legacy application the logout is a parameter as often as a path.
        denies("an encoded logout in the query is still a logout", p,
               req("GET", "https://app.example.test/index.php?action=log%6fut",
                   "app.example.test", "/index.php", "action=log%6fut"),
               APP, "dangerous_denied");
        // A `..` in a query VALUE is a value, not a step up a tree, and it must
        // not take an ordinary request out of the run.
        allows("but a dot-segment inside a query value is just a value", p,
               req("GET", "https://app.example.test/api/orders?next=../x",
                   "app.example.test", "/api/orders", "next=../x"),
               APP);

        // scope.exclude. Everything here is inside the include and named by
        // the exclude under one reading or another.
        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/adm%69n/users",          // was ALLOW
                                   "/admin%2fusers",          // was ALLOW
                                   "/api/../admin/users",     // was ALLOW
                                   "/api/%2e%2e/admin/users", // was ALLOW
                                   "/ADMIN/users",            // was ALLOW
                                   "/%41dmin/users",
                                   "//admin/users",           // empty segment
                                   "/admin//users",           // empty segment
                                   "/a//../admin/users",      // empty segment + dot segment
                                   "/%2fadmin/users"))        // encoded empty segment
            denies("an encoded excluded path is still excluded: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");

        // Case-folding an exclude is the other half of the finding: the
        // dangerous denylist folded case and scope.exclude did not, so an
        // operator excluding /admin/* was not excluding it on a target with
        // case-insensitive routing -- which is most of them.
        denies("an exclude written in capitals still excludes the lowercase path", p,
               req("GET", "https://app.example.test/admin/users",
                   "app.example.test", "/admin/users", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/ADMIN/*"),
               "scope_denied");

        // The raw arm folds case too, and that is a DIFFERENT guard from the
        // canonical arm: an exclude naming a percent-encoded literal matches
        // the bytes and never the canonical form, so the canonical arm cannot
        // stand in for it. `/reports/q1%20final*` against a request for
        // `/reports/Q1%20Final.pdf` is caught by the raw arm alone -- the
        // canonical path is `/reports/q1 final.pdf`, which that pattern does
        // not name.
        BridgeClient.Authorisation reports =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/reports/q1%20final*");
        denies("an exclude naming an encoded literal folds case on the raw path", p,
               req("GET", "https://app.example.test/reports/Q1%20Final.pdf",
                   "app.example.test", "/reports/Q1%20Final.pdf", ""),
               reports, "scope_denied");
        // And the other direction, which the canonical arm also covers: the
        // pattern's case must not matter either.
        denies("nor does the case the operator wrote the exclude in", p,
               req("GET", "https://app.example.test/reports/q1%20final.pdf",
                   "app.example.test", "/reports/q1%20final.pdf", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/REPORTS/Q1%20FINAL*"),
               "scope_denied");

        // Folding the RAW readings is a separate guard from the derived ones,
        // and this is the shape that proves it. `/reports/q1%2*` is a truncated
        // escape -- an operator's typo, or a deliberately byte-exact pattern --
        // so it decodes to itself, while the request's `%2F` decodes to a
        // separator and takes the path somewhere else entirely. Neither
        // derived reading matches, and the raw ones differ only in case: fold
        // them and the exclusion holds, do not and the request is ALLOWED.
        denies("the raw readings are folded on the path side too", p,
               req("GET", "https://app.example.test/Reports/Q1%2Final.pdf",
                   "app.example.test", "/Reports/Q1%2Final.pdf", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/reports/q1%2*"),
               "scope_denied");

        // And the PATTERN side of the same fold, which round 3 recorded as
        // defence in depth that no realistic input could falsify. There is one.
        // The escapes differ only in the case of their hex digits, and they
        // decode to DIFFERENT strings -- `/%2E*` to `/.*`, `/%2e` to `/` --
        // so neither derived reading matches and only the raw fold is left.
        denies("the raw readings are folded on the pattern side too", p,
               req("GET", "https://app.example.test/%2e", "app.example.test", "/%2e", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/%2E*"),
               "scope_denied");

        // And the ordinary path under the same config is still allowed: a
        // canonicaliser that refused everything would pass every check above.
        allows("an ordinary path under the same exclude is untouched", p, orders(), cfg);
    }

    /**
     * The half that is NOT symmetric decoration. Nothing is excluded here:
     * `/app/%2e%2e/other` matches the include as bytes, and the server serves
     * `/other`, which no include names. An allow rule must have EVERY reading
     * of the path in scope, not a favourite one.
     */
    static void anIncludeMustMatchEveryReadingOfThePath() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation app =
                authorised("scope.include", "https://app.example.test/app/*");

        allows("an ordinary path inside the included prefix", p,
               req("GET", "https://app.example.test/app/orders",
                   "app.example.test", "/app/orders", ""), app);

        for (String path : List.of("/app/%2e%2e/other",
                                   "/app/../other",
                                   "/app/%252e%252e/other",
                                   "/app/x/%2e%2e/%2e%2e/other"))
            denies("an escape out of the included prefix is out of scope: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   app, "scope_denied");

        // A `..` that stays inside the prefix is still in scope: the rule is
        // "both readings are included", not "no request may contain a dot".
        allows("but a dot segment that lands back inside it is in scope", p,
               req("GET", "https://app.example.test/app/x/%2e%2e/orders",
                   "app.example.test", "/app/x/%2e%2e/orders", ""), app);

        // The raw half of the include stays case-SENSITIVE. Folding case on
        // the one rule that authorises anything widens it, and this is the
        // check that fails if somebody "makes it consistent" with the denies.
        denies("an include is not widened by folding case", p,
               req("GET", "https://app.example.test/APP/orders",
                   "app.example.test", "/APP/orders", ""), app, "scope_denied");
    }

    /**
     * F1. `..;/` is the most weaponised URL-normalisation trick in the field,
     * and it was ALLOWED past an include.
     *
     * Every servlet container -- Tomcat, Jetty, Undertow, WebSphere, so every
     * Spring Boot application -- strips `;params` from a segment BEFORE it
     * normalises the path. The segment `..;` therefore becomes `..`, and
     * `/app/..;/other` is served as `/other`, which no include here names.
     */
    static void aPathParameterIsStrippedBeforeTheServerNormalises() {
        Policy p = allowingPolicy();

        reads("/app/..;/other", "/other");
        reads("/app/..;a=b/other", "/other");
        reads("/admin;x=1/users", "/admin/users");
        // The parameter is dropped and the separator that ends the segment is
        // kept: a reader that ate the `/` too would land on `/adminusers` and
        // match nothing.
        reads("/admin;/users", "/admin/users");

        BridgeClient.Authorisation app =
                authorised("scope.include", "https://app.example.test/app/*");
        for (String path : List.of("/app/..;/other", "/app/..;a=b/other",
                                   "/app/..%3b/other", "/app/%2e%2e;/other"))
            denies("a path parameter cannot walk out of an include: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   app, "scope_denied");

        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/public/..;/admin/users", "/admin;x=1/users",
                                   "/admin;/users", "/admin%3b/users"))
            denies("nor into an exclusion: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");

        // A `;` that is not an evasion must not cost an operator their scope:
        // the include covers the directory, so it covers the file.
        allows("a jsessionid on an in-scope path is still in scope", p,
               req("GET", "https://app.example.test/app/orders;jsessionid=ABC",
                   "app.example.test", "/app/orders;jsessionid=ABC", ""), app);
    }

    /**
     * F2. IIS and .NET read a backslash as a path separator, so a backslash
     * between `/admin` and `users` reaches `/admin/users`, and `/x/..%5clogout`
     * is a real logout -- which is the one that matters, because that request
     * gets ISSUED and ends the session.
     *
     * (Written out rather than shown: a backslash followed by a `u` is a
     * unicode escape in Java source, and the compiler reads it inside comments
     * too. The string literals below are correctly escaped and are the actual
     * payloads.)
     */
    static void aBackslashIsReadAsASeparator() {
        Policy p = allowingPolicy();

        reads("/admin\\users", "/admin/users");
        reads("/admin%5cusers", "/admin/users");
        reads("/app/..\\other", "/other");

        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/admin\\users", "/admin%5cusers", "/admin%5Cusers"))
            denies("a backslash does not evade an exclusion: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");

        BridgeClient.Authorisation app =
                authorised("scope.include", "https://app.example.test/app/*");
        for (String path : List.of("/app/..\\other", "/app/..%5cother"))
            denies("nor walk out of an include: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   app, "scope_denied");

        // The expensive one. Nothing is excluded here and the include covers
        // everything: it is the DENYLIST that has to see the logout, and it
        // only sees it through the backslash reading.
        denies("a backslash does not hide a logout from the denylist", p,
               req("GET", "https://app.example.test/x/..%5clogout",
                   "app.example.test", "/x/..%5clogout", ""),
               APP, "dangerous_denied");
    }

    /**
     * F8. Windows trims trailing dots and spaces from a name before opening it
     * and IIS serves what Windows opens, so `/admin./users` and `/admin%20/users`
     * reach `/admin/users`. A NUL is where a C string ends.
     */
    static void aTrailingDotSpaceOrNulIsTrimmed() {
        Policy p = allowingPolicy();

        reads("/admin./users", "/admin/users");
        reads("/admin%20/users", "/admin/users");
        reads("/admin%00/users", "/admin/users");
        reads("/app/..%00/other", "/other");
        reads("/app/.. /other", "/other");

        // `..` and `.` are dot SEGMENTS and must survive the trim as segments,
        // or `/app/.. /other` would read as `/app//other` and the escape would
        // still be in scope.
        readsExactly("/a/../b", "/a/../b", "/b");

        BridgeClient.Authorisation cfg =
                authorised("scope.include", "https://app.example.test/*",
                           "scope.exclude", "https://app.example.test/admin/*");
        for (String path : List.of("/admin./users", "/admin%20/users", "/admin%00/users"))
            denies("a trimmed tail does not evade an exclusion: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   cfg, "scope_denied");

        BridgeClient.Authorisation app =
                authorised("scope.include", "https://app.example.test/app/*");
        for (String path : List.of("/app/..%00/other", "/app/.. /other"))
            denies("nor walk out of an include: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   app, "scope_denied");

        // A dot inside a name is a name, not a tail. An include that covers the
        // directory has to keep covering the file.
        allows("an ordinary filename with a dot in it is untouched", p,
               req("GET", "https://app.example.test/app/report.pdf",
                   "app.example.test", "/app/report.pdf", ""), app);
    }

    /**
     * F9. `%c0%ae%c0%ae/` is the overlong UTF-8 `../` that walked past IIS for
     * years. decodeOnce maps a percent-escape to one char with no transcoding,
     * so nothing else in the class would ever see the `..`: it is two chars
     * 0xC0 0xAE 0xC0 0xAE until something reads them as UTF-8.
     */
    static void overlongUtf8IsReadAsTheAsciiItDecodesTo() {
        Policy p = allowingPolicy();

        reads("/x/%c0%ae%c0%ae/admin/users", "/admin/users");
        reads("/admin%c0%afusers", "/admin/users");     // overlong `/`
        reads("/x/%e0%80%ae%e0%80%ae/admin", "/admin"); // three-byte overlong

        denies("an overlong UTF-8 traversal does not evade an exclusion", p,
               req("GET", "https://app.example.test/x/%c0%ae%c0%ae/admin/users",
                   "app.example.test", "/x/%c0%ae%c0%ae/admin/users", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/admin/*"),
               "scope_denied");
        denies("nor walk out of an include", p,
               req("GET", "https://app.example.test/app/%c0%ae%c0%ae/other",
                   "app.example.test", "/app/%c0%ae%c0%ae/other", ""),
               authorised("scope.include", "https://app.example.test/app/*"),
               "scope_denied");

        // A lead byte with nothing valid after it is copied through and
        // reading carries on past it, for the same reason a malformed escape
        // does not stop decoding: one stray byte must not be a switch that
        // turns a reading off for the whole path.
        denies("a stray UTF-8 lead byte does not disable the reading after it", p,
               req("GET", "https://app.example.test/account/%c0/log%6fut",
                   "app.example.test", "/account/%c0/log%6fut", ""),
               APP, "dangerous_denied");
    }

    /**
     * F5, and it is a TEST-INTEGRITY finding as much as a behavioural one.
     *
     * Deleting the raw arm of the dangerous-path check left all 163 checks in
     * this file green while flipping live verdicts: `/account/logout/../profile`
     * went dangerous_denied -> ALLOW. Every other reading of that path resolves
     * the `..` and pops the logout off, so the shipped logout glob matches the
     * RAW bytes and nothing else -- and a server that routes before it
     * normalises serves the logout. The whole raw half of the denylist was
     * unguarded. (The glob is not quoted here: a pattern beginning with a star
     * and a slash ends a block comment, which is why DEFAULT_DANGEROUS is
     * commented with line comments.)
     */
    static void theRawPathIsAReadingInItsOwnRight() {
        Policy p = allowingPolicy();

        // The reading itself: the raw path is in the set even when every
        // normalisation of it says something else.
        reads("/account/logout/../profile", "/account/logout/../profile");
        reads("/ADMIN/Users", "/ADMIN/Users");
        reads("/files/my%20docs/a.pdf", "/files/my%20docs/a.pdf");

        // dangerous.path, through decide(), which is where it counts.
        for (String path : List.of("/account/logout/../profile",
                                   "/account/password/../profile",
                                   "/api/users/7/delete/../list"))
            denies("a normalisation that pops the dangerous segment off does not "
                   + "make it safe: " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   APP, "dangerous_denied");

        // The query half of the same finding. The denylist reads path AND
        // query, and the query has a raw reading for the same reason the path
        // does: an operator's pattern written against the BYTES matches the
        // bytes and nothing else. `*=arch%6*` is one character short of the
        // whole escape, so it matches `x=arch%69ve` and matches nothing once
        // the query is decoded to `x=archive` -- the raw reading is the only
        // one that sees it.
        //
        // Deliberately not spelt with `log%6`: `*=logout*` is a shipped
        // default and would catch the decoded query on its own, which would
        // make this check pass with the raw reading deleted. It did, and the
        // sabotage run is what said so.
        denies("a dangerous.path written against the query bytes still matches", p,
               req("GET", "https://app.example.test/index.php?x=arch%69ve",
                   "app.example.test", "/index.php", "x=arch%69ve"),
               authorised("scope.include", "https://app.example.test/*",
                          "dangerous.path", "*=arch%6*"),
               "dangerous_denied");

        // And the same shape against scope.exclude.
        denies("nor does it get past an exclusion", p,
               req("GET", "https://app.example.test/admin/users/../../public/x",
                   "app.example.test", "/admin/users/../../public/x", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/admin/*"),
               "scope_denied");
    }

    /**
     * F6 and F10. Patterns were never read any way but literally, and both
     * failure directions are SILENT.
     *
     * An exclude written with an escape is a DEAD RULE that fails open: it
     * reads as if it named /admin/* and stops nothing. An include written with
     * one authorises NOTHING, in either spelling, and the operator is told only
     * that their request "matches no scope.include pattern" -- which sends them
     * to rewrite a pattern that was right.
     */
    static void aPatternIsReadEveryWayAPathIs() {
        Policy p = allowingPolicy();

        // F6: the dead exclude.
        for (String pattern : List.of("https://app.example.test/%61dmin/*",
                                      "https://app.example.test/ADMIN/*",
                                      "https://app.example.test/admin%2f*"))
            denies("an exclude written as " + pattern + " still excludes /admin/x", p,
                   req("GET", "https://app.example.test/admin/x",
                       "app.example.test", "/admin/x", ""),
                   authorised("scope.include", "https://app.example.test/*",
                              "scope.exclude", pattern),
                   "scope_denied");

        // F10: the include that authorises nothing. BOTH spellings of the
        // request have to work -- the operator wrote one pattern, and the
        // encoding a request arrives in is not their choice.
        BridgeClient.Authorisation files =
                authorised("scope.include", "https://app.example.test/files/my%20docs/*");
        for (String path : List.of("/files/my%20docs/a.pdf", "/files/my docs/a.pdf"))
            allows("an include written with an escape authorises " + path, p,
                   req("GET", "https://app.example.test" + path, "app.example.test", path, ""),
                   files);

        // ...and still authorises nothing else. A pattern read every way is not
        // a pattern read as `*`.
        denies("and nothing outside it", p,
               req("GET", "https://app.example.test/files/other/a.pdf",
                   "app.example.test", "/files/other/a.pdf", ""),
               files, "scope_denied");

        // The same for a dangerous.path line an operator wrote with an escape.
        denies("an operator's dangerous.path written with an escape is not a dead rule", p,
               req("GET", "https://app.example.test/admin/jobs/run",
                   "app.example.test", "/admin/jobs/run", ""),
               authorised("scope.include", "https://app.example.test/*",
                          "dangerous.path", "*/%61dmin/jobs/*"),
               "dangerous_denied");
    }

    /**
     * F7. decodeToFixedPoint is quadratic -- each round is a full pass and a
     * nested escape needs one round per layer -- and it ran on the enforcement
     * thread with nothing capping the path length. Measured on the shipped
     * code: a 20 KB path took decide() 370 ms, 100 KB took 8.9 s, 400 KB took
     * 143 s, and every one of them ended in ALLOW.
     *
     * Both bounds are DENIALS. "I could not finish reasoning about this
     * request" and "this request is fine" are different answers, and a decider
     * that conflates them has stopped being a decider.
     */
    static void aTargetTooBigToDecideAboutIsRefused() {
        Policy p = allowingPolicy();

        // The NUMBER, not just the behaviour. Every check below computes its
        // fixture from the constant, so lowering the constant would leave them
        // all green while refusing traffic that is ordinary rather than exotic:
        // a SAML HTTP-Redirect SAMLRequest, an OIDC `request` JWT, a Kibana
        // rison link. 8192 is what Apache (LimitRequestLine 8190), nginx (8k)
        // and Tomcat (8192) accept in a whole request line, so at this bound hx
        // can reach everything the target itself would answer.
        check("the bound is at least what a mainstream server accepts",
              Policy.MAX_TARGET_CHARS >= 8192);
        String saml = "/sso/saml?SAMLRequest=" + "QUJD".repeat(1200) + "&Signature=" + "x".repeat(344);
        check("the SAML fixture is over the old 4096 bound and inside this one",
              saml.length() > 4096 && saml.length() <= Policy.MAX_TARGET_CHARS);
        allows("a SAML HTTP-Redirect target is decided rather than refused", p,
               req("GET", "https://app.example.test" + saml, "app.example.test",
                   saml.substring(0, saml.indexOf('?')), saml.substring(saml.indexOf('?') + 1)),
               authorised("scope.include", "https://app.example.test/sso/*"));

        String atTheBound = "/a" + "b".repeat(Policy.MAX_TARGET_CHARS - 2);
        check("the fixture is exactly at the bound",
              atTheBound.length() == Policy.MAX_TARGET_CHARS);
        allows("a target exactly at the bound is decided normally", p,
               req("GET", "https://app.example.test" + atTheBound,
                   "app.example.test", atTheBound, ""), APP);

        String overTheBound = atTheBound + "c";
        denies("one character over it is refused rather than decided slowly", p,
               req("GET", "https://app.example.test" + overTheBound,
                   "app.example.test", overTheBound, ""), APP, "scope_denied");

        // The query counts toward the same budget: the denylist reads it, so
        // it costs the same decoding.
        denies("a long query counts toward the same bound", p,
               req("GET", "https://app.example.test/a?" + "b".repeat(Policy.MAX_TARGET_CHARS),
                   "app.example.test", "/a", "b".repeat(Policy.MAX_TARGET_CHARS)),
               APP, "scope_denied");

        // The round cap, which is the other half: a short path can still be
        // nested deeply enough to cost a round per layer.
        String nested = "/a/%" + "25".repeat(40) + "2e";
        check("the nested fixture is well inside the length bound",
              nested.length() < Policy.MAX_TARGET_CHARS);
        denies("a path still encoded after the round cap is refused", p,
               req("GET", "https://app.example.test" + nested,
                   "app.example.test", nested, ""), APP, "scope_denied");

        // The QUERY is bounded by the same round cap, through its own arm of
        // undecidable(), and that arm had no check at all: deleting
        // `|| !decodesFully(req.query())` left all 490 checks green while a
        // 17-deep nested query escape went ALLOW. The denylist reads the
        // query, so a query still encoded after 16 rounds is a denylist
        // reading nobody checked.
        String nestedQuery = "a=%" + "25".repeat(17) + "2e";
        check("the nested query fixture is inside the length bound and does not decode",
              nestedQuery.length() < Policy.MAX_TARGET_CHARS
              && !Policy.decodesFully(nestedQuery));
        denies("a query still encoded after the round cap is refused", p,
               req("GET", "https://app.example.test/x?" + nestedQuery,
                   "app.example.test", "/x", nestedQuery), APP, "scope_denied");
        check("...and the path arm is not what refused it",
              Policy.decodesFully("/x"));
        allows("while an ordinary double-encoded query still decides", p,
               req("GET", "https://app.example.test/x?a=%2520b",
                   "app.example.test", "/x", "a=%2520b"), APP);

        // And an ordinary double-encoding is nowhere near the cap: the bound
        // must not turn into a denial of the traffic it was meant to survive.
        allows("an ordinary double-encoded path still decodes", p,
               req("GET", "https://app.example.test/files/a%2520b.pdf",
                   "app.example.test", "/files/a%2520b.pdf", ""),
               authorised("scope.include", "https://app.example.test/files/*"));
        check("decodesFully agrees with the bound",
              Policy.decodesFully("/files/a%2520b.pdf") && !Policy.decodesFully(nested));

        // The one that pays for the whole check: the 20 KB path that took 370 ms
        // and was ALLOWED. It is refused now, and refused without decoding it.
        String huge = "/a/%" + "25".repeat(10_000) + "2e";
        long start = System.nanoTime();
        Decision d = p.decide(req("GET", "https://app.example.test" + huge,
                                  "app.example.test", huge, ""), APP);
        long ms = (System.nanoTime() - start) / 1_000_000;
        check("a 20 KB nested path is refused (" + (d.allowed() ? "ALLOWED" : d.errorClass())
              + ") in " + ms + " ms",
              !d.allowed() && "scope_denied".equals(d.errorClass()) && ms < 100);
    }

    /**
     * Round 4's report measured a shape whose reading set is 425 members and
     * costs decide() 406 ms -- bounded by MAX_TARGET_CHARS but only reported,
     * not refused: "it degrades hx rather than bypassing it ... if you want it
     * bounded, the honest form is a scope_denied on the reading count." Ruled:
     * bound it, as a denial, never a truncation. Truncating fails OPEN in both
     * directions for the same reason the deny-OR/allow-AND split does -- a
     * deny rule that stops early may never reach the truncated member that
     * would have matched, an allow rule that stops early may never reach the
     * one that would have failed coverage -- so refusing the target outright
     * is the only answer safe regardless of which unchecked reading mattered.
     *
     * The two fixtures below were found by local search (a hill-climb over the
     * same trigger alphabet the closure fuzz test uses, not committed here)
     * rather than computed from a formula: readings() does not grow by one per
     * character appended, so landing on an EXACT count at the boundary means
     * searching for it.
     */
    static void aReadingSetOverTheLimitIsRefused() {
        Policy p = allowingPolicy();

        String atLimit =
                "/%e2%\0%ef%bc%9b%95%c0%abb\uff0e%5c%%bc%9bN52.";
        String overLimit =
                "/%%e2%\0%ef%bc%9b%c0%abb\uff0e%5c%ef%25%bc%9b%fe%52%2/52.";

        check("the fixture at the limit has exactly MAX_READINGS readings ("
              + Policy.readings(atLimit).size() + ")",
              Policy.readings(atLimit).size() == Policy.MAX_READINGS);
        check("the fixture one over has exactly MAX_READINGS + 1 ("
              + Policy.readings(overLimit).size() + ")",
              Policy.readings(overLimit).size() == Policy.MAX_READINGS + 1);

        allows("a path with exactly MAX_READINGS readings is decided, not refused for its size", p,
               req("GET", "https://app.example.test" + atLimit,
                   "app.example.test", atLimit, ""),
               APP);

        Decision d = p.decide(
                req("GET", "https://app.example.test" + overLimit,
                    "app.example.test", overLimit, ""), APP);
        check("one reading over the limit is scope_denied (got "
              + (d.allowed() ? "ALLOWED" : d.errorClass()) + ")",
              !d.allowed() && "scope_denied".equals(d.errorClass()));
        check("...and the denial names the limit and the count, distinguishable "
              + "from an ordinary scope miss: " + d.detail(),
              d.detail() != null
              && d.detail().contains(String.valueOf(Policy.MAX_READINGS))
              && d.detail().contains(String.valueOf(Policy.MAX_READINGS + 1))
              && d.detail().contains("readings"));

        // The bound is on CONSTRUCTION, not only on matching. For one round
        // checkScope built the whole set and only then compared its size, so
        // the expensive half of the work happened before the bound could
        // refuse it. `atLimit` has 64 readings, so asking for fewer must stop
        // the BUILDING at one member past whatever was asked for; a limit
        // applied after the fact returns the whole 64 every time, which is
        // what these catch.
        for (int limit : new int[]{1, 2, 8, 30, 40}) {
            int built = Policy.readings(atLimit, limit).size();
            check("readings() stops building at " + limit + " + 1 members (got "
                  + built + " of a set of " + Policy.readings(atLimit).size() + ")",
                  built == limit + 1);
        }
        check("...and asking for the whole set still gets the whole set",
              Policy.readings(atLimit, Policy.MAX_READINGS).size()
                      == Policy.MAX_READINGS
              && Policy.readings(atLimit, 1000).size() == Policy.MAX_READINGS);

        String explosive = overLimit + overLimit + overLimit;

        // The count is not the cost. 64 readings of an 8192-character path is
        // a different amount of work from 64 readings of a short one, and with
        // only the count bounded a 31-character unit tiled to the length bound
        // still cost decide() 144 ms. The budget is the PRODUCT.
        check("a short path may have the whole of MAX_READINGS readings",
              Policy.readingBudget("/api/orders".length()) == Policy.MAX_READINGS
              && Policy.readingBudget(atLimit.length()) == Policy.MAX_READINGS);
        check("and the budget falls as the path grows: 2048 -> "
              + Policy.readingBudget(2048) + ", 4096 -> "
              + Policy.readingBudget(4096) + ", 8192 -> "
              + Policy.readingBudget(8192),
              Policy.readingBudget(2048) == 64
              && Policy.readingBudget(4096) == 32
              && Policy.readingBudget(8192) == 16);
        check("never below one, so no path is refused for the reading every "
              + "path has", Policy.readingBudget(0) >= 1
              && Policy.readingBudget(1_000_000) >= 1);

        // End to end, at the length bound, which is the shape an attacker
        // actually gets to send: a unit repeated until every reading is still
        // eight kilobytes long.
        StringBuilder tiled = new StringBuilder();
        while (tiled.length() + explosive.length() <= Policy.MAX_TARGET_CHARS)
            tiled.append(explosive);
        String worst = tiled.toString();
        long start = System.nanoTime();
        Decision big = p.decide(req("GET", "https://app.example.test" + worst,
                                    "app.example.test", worst, ""), APP);
        long ms = (System.nanoTime() - start) / 1_000_000;
        check("a " + worst.length() + "-character target whose readings explode is "
              + "refused (" + (big.allowed() ? "ALLOWED" : big.errorClass())
              + ") in " + ms + " ms",
              !big.allowed() && "scope_denied".equals(big.errorClass()) && ms < 60);

        // The costliest target a hill climb over the trigger alphabet could
        // build, tiled to the length bound. It is UNDER the reading bound and
        // so it is DECIDED rather than refused -- which is the point: nothing
        // refuses it, and the only things keeping it cheap are the size half
        // of the bound and lower() folding one code point at a time. The same
        // shape family cost 99 to 165 ms before the round that bounded it.
        //
        // RE-SEARCHED each round, and each round has found worse with a cheaper
        // search, so the number here is this round's rather than a quotation.
        // Round 6's winner is 23 ms on this build; a 20,000-step climb from it,
        // over an alphabet that now includes the homoglyphs the widened
        // best-fit table folds, reached 43.1 ms during the climb and
        // re-measures at 32 ms quiescent. The ceiling moved because the TABLE
        // grew: a fold that used to fire on thirteen code points now fires on a
        // hundred and five, so more members of more paths differ from their
        // base and get derived. That is the cost of closing the fullwidth
        // range. It is bounded by every bound above, and it degrades one
        // enforcement thread rather than bypassing anything.
        String costly = "/\u2216%\ufe52/D\uff0f2\u2216;%c2/.\u066a/\uff05f";
        StringBuilder costlyTiled = new StringBuilder();
        while (costlyTiled.length() + costly.length() <= Policy.MAX_TARGET_CHARS)
            costlyTiled.append(costly);
        String costlyPath = costlyTiled.toString();
        HxRequest costlyReq = req("GET", "https://app.example.test" + costlyPath,
                                  "app.example.test", costlyPath, "");
        p.decide(costlyReq, APP);
        long cStart = System.nanoTime();
        Decision cVerdict = p.decide(costlyReq, APP);
        long cMs = (System.nanoTime() - cStart) / 1_000_000;
        check("the costliest target a hill climb could build (" + costlyPath.length()
              + " characters, " + Policy.readings(costlyPath, Policy.readingBudget(costlyPath.length())).size()
              + " readings) is answered " + (cVerdict.allowed() ? "allow" : cVerdict.errorClass())
              + " in " + cMs + " ms",
              cMs < 80 && cVerdict != null);

        // ...while a long BENIGN target is decided rather than refused: the
        // size bound must not turn into a length bound of its own.
        String longBenign = "/sso/saml/" + "QUJD".repeat(2000);
        check("the long benign fixture is near the length bound and reads "
              + Policy.readings(longBenign).size() + " ways",
              longBenign.length() > 4096 && Policy.readings(longBenign).size() <= 2);
        allows("a long benign target is still decided", p,
               req("GET", "https://app.example.test" + longBenign,
                   "app.example.test", longBenign, ""),
               authorised("scope.include", "https://app.example.test/sso/*"));

        // A realistic path carrying several triggers at once -- every
        // transform this class knows about, firing in one segment -- has to
        // stay far below the bound, or the bound starts refusing traffic it
        // was never aimed at.
        String realistic = "/a;b\\c. /d";
        int realisticReadings = Policy.readings(realistic).size();
        check("a realistic multi-trigger path is far below the bound ("
              + realisticReadings + " readings, limit " + Policy.MAX_READINGS + ")",
              realisticReadings * 4 < Policy.MAX_READINGS);
        allows("and it is decided normally, not refused for its size", p,
               req("GET", "https://app.example.test" + realistic,
                   "app.example.test", realistic, ""),
               APP);
    }

    /**
     * Canonicalisation must not become a denylist of its own. Percent-encoding
     * is ordinary and legitimate -- a space in a filename is the common case --
     * and an operator whose scope covers the directory has scoped the file.
     */
    static void aLegitimatelyEncodedPathIsStillAllowed() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation files =
                authorised("scope.include", "https://app.example.test/files/*");

        String spaced = "/files/annual%20report.pdf";
        HxRequest r = req("GET", "https://app.example.test" + spaced,
                          "app.example.test", spaced, "");
        allows("a space encoded as %20 in an in-scope filename", p, r, files);
        allows("and an encoded ~ in a home directory", p,
               req("GET", "https://app.example.test/files/%7Ejim/notes.txt",
                   "app.example.test", "/files/%7Ejim/notes.txt", ""), files);
        allows("and an encoded + in a report name", p,
               req("GET", "https://app.example.test/files/q1%2Bq2.csv",
                   "app.example.test", "/files/q1%2Bq2.csv", ""), files);

        // The request that goes on the wire is unchanged: canonicalisation
        // exists only to decide. Nothing in Policy can rewrite an HxRequest --
        // this is here so that the day something tries, a check says so.
        p.decide(r, files);
        check("the request decided about still carries its raw bytes",
              spaced.equals(r.path()) && spaced.equals(r.target()));
    }

    /**
     * The direction empty-segment collapsing can fail in. Under scope.exclude
     * (deny-OR) a broader canonical form only denies more, which is safe; under
     * scope.include (allow-AND) the SAME canonical form denying one reading
     * refuses a request the operator authorised. A single trailing slash is
     * not a repeated separator and collapseEmptySegments() must leave it
     * alone, or these go from allowed to scope_denied mid-engagement.
     */
    static void aTrailingSlashIsNotNewlyRefused() {
        Policy p = allowingPolicy();

        // The include pattern itself ends in "/", with no wildcard after it,
        // so raw and canonical must both still be exactly "/reports/" for the
        // request to be allowed at all.
        allows("a path matching an include that itself ends in /", p,
               req("GET", "https://app.example.test/reports/",
                   "app.example.test", "/reports/", ""),
               authorised("scope.include", "https://app.example.test/reports/"));

        // An ordinary wildcard prefix, with the request's own trailing slash
        // the only thing distinguishing it from every other check above.
        allows("a request with its own trailing slash under a wildcard include", p,
               req("GET", "https://app.example.test/app/orders/",
                   "app.example.test", "/app/orders/", ""),
               authorised("scope.include", "https://app.example.test/app/*"));
    }

    /**
     * Constraint: nothing decide() does may throw. A path that is nothing but
     * slashes exercises collapseEmptySegments() and collapseDotSegments() at
     * their edges -- no character survives either pass -- and the fail-closed
     * requirement is that decide() still returns a Decision instead of
     * unwinding, whatever that Decision says.
     */
    static void aPathOfOnlySlashesDoesNotThrow() {
        Policy p = allowingPolicy();
        HxRequest r = req("GET", "https://app.example.test////",
                          "app.example.test", "////", "");
        Decision d;
        try {
            d = p.decide(r, APP);
        } catch (Throwable t) {
            check("a path of only slashes does not throw (threw " + t + ")", false);
            return;
        }
        check("a path of only slashes returns a decision (" +
              (d.allowed() ? "allow" : d.errorClass()) + ") instead of throwing", true);
    }

    /**
     * F12. decide() says it is total, and it was not: `Authorisation(7, null)`,
     * a null list under a key, and a null element inside one each reached a
     * NullPointerException three frames down.
     *
     * None of these is reachable from the wire today -- ConfigBody.parse
     * freezes every list with List.copyOf, which rejects nulls -- but Sender is
     * the caller, it treats a Decision as the whole answer, and an exception
     * unwinding out of the send arm is an implicit allow the moment anyone
     * mishandles it. A guarantee stated in this class has to be enforced in
     * this class, not in a different one.
     */
    static void aMalformedAuthorisationIsADecisionNotACrash() {
        CountingGate gate = new CountingGate();
        Policy p = new Policy(gate);

        Map<String, List<String>> nullList = new LinkedHashMap<>();
        nullList.put("scope.include", null);
        Map<String, List<String>> nullElement = new LinkedHashMap<>();
        nullElement.put("scope.include", Collections.singletonList(null));
        Map<String, List<String>> nullDangerous = new LinkedHashMap<>();
        nullDangerous.put("scope.include", List.of("https://app.example.test/*"));
        nullDangerous.put("dangerous.path", Collections.singletonList(null));
        Map<String, List<String>> nullMethod = new LinkedHashMap<>();
        nullMethod.put("scope.include", List.of("https://app.example.test/*"));
        nullMethod.put("method.allow", Collections.singletonList(null));

        // A LinkedHashMap and not Map.of: Map.of rejects a null value, which is
        // the first case here. That the JDK's own immutable map will not hold
        // one is exactly why ConfigBody.parse cannot produce one -- and exactly
        // why this class must still answer if a caller hands one over.
        Map<String, Map<String, List<String>>> cases = new LinkedHashMap<>();
        cases.put("a null scope map", null);
        cases.put("a null scope.include list", nullList);
        cases.put("a null inside scope.include", nullElement);
        cases.put("a null inside dangerous.path", nullDangerous);
        cases.put("a null inside method.allow", nullMethod);
        for (Map.Entry<String, Map<String, List<String>>> e : cases.entrySet()) {
            BridgeClient.Authorisation auth = new BridgeClient.Authorisation(EPOCH, e.getValue());
            Decision d;
            try {
                d = p.decide(orders(), auth);
            } catch (Throwable t) {
                check(e.getKey() + " is a Decision, not a " + t.getClass().getSimpleName(), false);
                continue;
            }
            check(e.getKey() + " denies as not_configured (got "
                  + (d.allowed() ? "ALLOWED" : d.errorClass()) + ")",
                  !d.allowed() && "not_configured".equals(d.errorClass()));
            check("...and says which key is wrong: " + d.detail(),
                  d.detail() != null && !d.detail().isEmpty());
        }

        check("no malformed snapshot reached the gate (" + gate.calls + " call(s))",
              gate.calls == 0);

        // The whole-map shapes that are legitimate must not be caught by the
        // same guard: an empty map is "configured with nothing", which is a
        // scope question, and an empty LIST under a key is an operator writing
        // no patterns.
        Map<String, List<String>> emptyList = new LinkedHashMap<>();
        emptyList.put("scope.include", List.of());
        denies("an empty scope map is still a scope answer", p, orders(),
               new BridgeClient.Authorisation(EPOCH, Map.of()), "scope_denied");
        denies("and an empty scope.include list is too", p, orders(),
               new BridgeClient.Authorisation(EPOCH, emptyList), "scope_denied");
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
    /**
     * Round 7, CRITICAL. The query half got NONE of the byte folds the path
     * half got.
     *
     * `targetReadings` read the query as `{raw, lower(decoded)}` -- two members
     * and no folds -- while the path had grown a decoding axis, an overlong
     * UTF-8 fold and a best-fit fold over four rounds. The same bytes therefore
     * got two different answers out of the same denylist:
     *
     *   PATH   /account/logo%c1%b5t           dangerous_denied
     *   QUERY  /i.php?action=logo%c1%b5t      ALLOW
     *   PATH   /x/..(U+FF05)2flogout          dangerous_denied
     *   QUERY  /i.php?action=log(U+FF05)6fut  ALLOW
     *
     * and `?action=logout` is where a logout LIVES on the legacy applications
     * the query half of the denylist was written for. The class comment's
     * reason for reading the halves separately is about `..`, `;` and `%2f`,
     * which are PATH syntax; a byte fold is not path syntax, and the reason
     * never covered it.
     */
    static void theQueryHalfGetsTheSameByteFoldsThePathHalfGets() {
        Policy p = allowingPolicy();

        // Each row twice: once with the bytes in the path, once with the same
        // bytes in the query. Both must refuse, and the pairing is the point --
        // a check on the query alone would pass against a build that had simply
        // banned the character.
        String[][] rows = {
            {"logo%c1%b5t",       "an overlong UTF-8 `u`"},
            {"log%ef%bc%856fut",  "a best-fit `%` that manufactures an escape"},
            {"logo%ef%bd%95t",    "a fullwidth `u`"},
            {"log%6fut",          "an ordinary escape"},
        };
        for (String[] row : rows) {
            String path = "/account/" + row[0];
            denies("path: " + path + " (" + row[1] + ")", p,
                   req("GET", "https://app.example.test" + path,
                       "app.example.test", path, ""),
                   APP, "dangerous_denied");
            String query = "action=" + row[0];
            denies("query: /i.php?" + query + " (" + row[1] + ")", p,
                   req("GET", "https://app.example.test/i.php?" + query,
                       "app.example.test", "/i.php", query),
                   APP, "dangerous_denied");
        }

        // The UNDECODED member survives the folds, and the check that pins it
        // is the `*=arch%6*` one in aDenyRuleSeesEveryReadingOfThePath -- not a
        // copy of it here. My copy used `*=log%6*` and was VACUOUS: `*=logout*`
        // is a shipped default and catches the decoded query on its own, so it
        // passed with the undecoded member deleted. That is the exact trap the
        // older check's own comment warns about, and I walked into it one
        // screen further down the same file. The sabotage run is what said so.
        check("the undecoded member is still a member, and no shipped default "
              + "catches the query that pins it",
              Policy.queryReadings("x=arch%69ve").contains("x=arch%69ve")
              && !Policy.DEFAULT_DANGEROUS.stream().anyMatch(
                      g -> Policy.glob(g, "/index.php?x=archive")));

        // ...and an ordinary query is still decided rather than refused.
        allows("a benign query is untouched", p,
               req("GET", "https://app.example.test/search?q=logs&page=2",
                   "app.example.test", "/search", "q=logs&page=2"),
               APP);
        allows("including one carrying an escape and a non-ASCII value", p,
               req("GET", "https://app.example.test/search?q=caf%c3%a9",
                   "app.example.test", "/search", "q=caf%c3%a9"),
               APP);

        // The set itself: closed, and small. My first comment on queryReadings
        // said the set "stays in single digits" because the folds are functions
        // of the whole string rather than the subset choice the path transforms
        // are. It sounded right and a seeded search falsified it at 17 members
        // in the first run -- so the number below comes from the search rather
        // than from the argument, and the check keeps it that way.
        check("a query with no escape and no non-ASCII byte has exactly one reading",
              Policy.queryReadings("q=logs&page=2").size() == 1);
        char[] alphabet = ("%25EFBC85C0AE2f5c=&logut" + '\0'
                + "％／．ａｌÀ®İ٪;∖").toCharArray();
        Random rnd = new Random(20260822L);
        int violations = 0, biggest = 0;
        String firstBad = null;
        for (int i = 0; i < 20_000; i++) {
            StringBuilder b = new StringBuilder();
            int len = 1 + rnd.nextInt(40);
            for (int j = 0; j < len; j++) b.append(alphabet[rnd.nextInt(alphabet.length)]);
            Set<String> set = Policy.queryReadings(b.toString());
            biggest = Math.max(biggest, set.size());
            for (String r : new ArrayList<>(set))
                if (!set.containsAll(Policy.queryReadings(r))) {
                    violations++;
                    if (firstBad == null) firstBad = b.toString();
                    break;
                }
        }
        check("queryReadings is closed on 20,000 random queries (" + violations
              + " violation(s), largest set " + biggest
              + (firstBad == null ? "" : ", first " + firstBad) + ")",
              violations == 0);

        // The bound is on the PRODUCT, because the dangerous.path pass reads
        // every reading of the path against every reading of the query. A
        // 14-reading path is decided; the same path with a 6-reading query is
        // 84 pairs, over the 64 this will decide about, and is refused.
        String rich = "/%2e;b\\c. /d";
        int pathSet = Policy.readings(rich).size();
        String richQuery = "a=%ef%bc%85c0%ae";
        int querySet = Policy.queryReadings(richQuery).size();
        check("the fixture is a " + pathSet + "-reading path and a " + querySet
              + "-reading query, a product of " + (pathSet * querySet),
              pathSet * querySet > Policy.MAX_READINGS && pathSet <= Policy.MAX_READINGS);
        allows("the path alone is under the bound and is decided", p,
               req("GET", "https://app.example.test" + rich + "?x=1",
                   "app.example.test", rich, "x=1"),
               APP);
        Decision product = p.decide(req("GET",
                "https://app.example.test" + rich + "?" + richQuery,
                "app.example.test", rich, richQuery), APP);
        check("the same path with a query whose product is over the bound is "
              + "refused (got " + (product.allowed() ? "ALLOWED" : product.errorClass())
              + "): " + product.detail(),
              !product.allowed() && "scope_denied".equals(product.errorClass())
              && product.detail() != null && product.detail().contains("target has at least"));

        // Bounded on CONSTRUCTION, not only on matching -- the round-5 lesson,
        // applied to the new set. A limit applied after the fact returns the
        // whole set every time.
        String big = "a=" + richQuery;
        for (int limit : new int[]{1, 2, 3}) {
            int built = Policy.queryReadings(big, limit).size();
            check("queryReadings() stops building at " + limit + " + 1 members (got "
                  + built + " of a set of " + Policy.queryReadings(big).size() + ")",
                  built == limit + 1);
        }
    }

    /**
     * Round 7, green sabotage. `dangerous.path` lost the whole path reading set
     * the moment a query was present.
     *
     * Replacing `for (String path : paths)` in targetReadings with
     * `for (String path : List.of(req.path()))` was 0 red against all 596
     * checks, and flipped three live rows to ALLOW -- because every
     * `dangerous.path` fixture in the suite used a query-less target, so the
     * arm that combines the path's READINGS with the query was never exercised
     * at all. The raw path is a member of its own reading set, so the
     * query-less checks pass either way.
     */
    static void theDangerousDenylistReadsThePathWhenAQueryIsPresent() {
        Policy p = allowingPolicy();
        String[][] rows = {
            {"/account/log%6fut",           "next=/home", "an escaped letter"},
            {"/x/..%ef%bc%8flogout",        "x=1",        "a best-fit separator"},
            {"/x/..%5clogout",              "x=1",        "an encoded backslash"},
            {"/account/logout/../profile",  "ref=1",      "the RAW reading"},
            {"/account/logout%00.png",      "v=2",        "the C-string truncation"},
        };
        for (String[] row : rows)
            denies("a query does not hide a dangerous path (" + row[2] + "): "
                   + row[0] + "?" + row[1], p,
                   req("GET", "https://app.example.test" + row[0] + "?" + row[1],
                       "app.example.test", row[0], row[1]),
                   authorised("scope.include", "https://app.example.test/*",
                              "dangerous.path", "*/export*"),
                   "dangerous_denied");

        // ...and the pairing that says the reading set is what did it: the same
        // targets with no query at all were already refused, so a check on
        // those alone proves nothing about the arm above.
        for (String[] row : rows)
            denies("and the same target with no query: " + row[0], p,
                   req("GET", "https://app.example.test" + row[0],
                       "app.example.test", row[0], ""),
                   APP, "dangerous_denied");

        // The query still cannot be read as a PATH, which is the half of the
        // split that is correct: a `..` in a query value is a value.
        allows("a dot segment in a query value is a value, not a traversal", p,
               req("GET", "https://app.example.test/search?next=/x/../account/profile",
                   "app.example.test", "/search", "next=/x/../account/profile"),
               authorised("scope.include", "https://app.example.test/search*"));
    }

    /**
     * Round 7, operator-reachable, and the fix is this test rather than a code
     * change.
     *
     * An empty `scope.exclude` entry reaches `Rule.forExclude("")`, which
     * throws, and checkScope answers `scope_denied` with "unusable scope
     * pattern". That is CORRECT and it is fail-closed: the operator is told
     * their config is broken and nothing is issued.
     *
     * A one-line `if (!p.isEmpty())` skip before `excludes.add` leaves all 596
     * checks green and turns that deny-all into ALLOW -- a run proceeding
     * against a scope the operator believes carries an exclusion. It is
     * reachable end to end and not a hypothetical: `src/hx/config.py` accepted
     * `""` in a string list, `codec.build_config_body` emitted
     * `scope.exclude\t\n`, `parse_config_body` round-tripped `['']` and
     * `ConfigBody.parse` accepted it -- a real engagement YAML produced
     * `scope_exclude == ['', 'https://app.example.test/admin/*']`. The Python
     * end now refuses an empty entry at load time so the operator learns at
     * `hx new`; this pins what the extension does if one ever arrives anyway.
     */
    static void anEmptyScopePatternIsAnUnusableOneAndDeniesEverything() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation withEmpty = authorised(
                "scope.include", "https://app.example.test/*",
                "scope.exclude", "",
                "scope.exclude", "https://app.example.test/admin/*");

        Decision d = p.decide(orders(), withEmpty);
        check("an empty scope.exclude entry denies a request that breaks nothing "
              + "else (got " + (d.allowed() ? "ALLOWED" : d.errorClass()) + ")",
              !d.allowed() && "scope_denied".equals(d.errorClass()));
        check("...and the denial says the pattern is unusable rather than that "
              + "the request is out of scope: " + d.detail(),
              d.detail() != null && d.detail().contains("unusable scope pattern"));

        // Every shape of blank an operator's YAML can produce, and the same
        // answer for an empty INCLUDE entry -- which is the more tempting one
        // to skip, since an include list that is empty AFTER the skip would
        // fall through to "no scope.include pattern is configured" and look
        // like a different bug.
        for (String blank : List.of("", " ", "\t")) {
            denies("a blank scope.exclude entry " + blank.length()
                   + " character(s) long is unusable", p, orders(),
                   authorised("scope.include", "https://app.example.test/*",
                              "scope.exclude", blank),
                   "scope_denied");
            denies("...and so is a blank scope.include entry beside a good one", p,
                   orders(),
                   authorised("scope.include", "https://app.example.test/*",
                              "scope.include", blank),
                   "scope_denied");
        }

        // The control: the same config with the empty entry removed allows the
        // request, so the denial above is the empty entry and not the exclude
        // beside it.
        allows("the same config without the empty entry allows the request", p, orders(),
               authorised("scope.include", "https://app.example.test/*",
                          "scope.exclude", "https://app.example.test/admin/*"));
    }

    /**
     * Round 7. The "unfalsifiable claim" in `denies()` was falsifiable, and the
     * comment's own reasoning named the shape.
     *
     * Round 6 kept the two `lower()` calls in `Rule.denies` after both went
     * 0-red, and wrote the reason down as a claim it could not falsify:
     * `lower(reading)` is not always a member, because readings() lowercases
     * the COLLAPSED form and collapse is not the identity on a path carrying a
     * dot segment. Carrying UPPER CASE as well is the other half, and the two
     * together are all it takes:
     *
     *   exclude = https://app.example.test/admin*    GET /ADMIN/../x
     *     readings = { /ADMIN/../x, /x }
     *     lower(raw) = /admin/../x is NOT one of them
     *
     * With the path-side fold removed the raw member is uppercase and no
     * pattern reading matches it, the collapsed member is `/x` which the
     * exclude does not name, and the request is ALLOWED past an exclusion.
     */
    static void aDenyRuleFoldsTheCaseOfAnUncollapsedRawReading() {
        Policy p = allowingPolicy();
        BridgeClient.Authorisation cfg = authorised(
                "scope.include", "https://app.example.test/*",
                "scope.exclude", "https://app.example.test/admin*");

        check("the reading set really is missing lower(raw): "
              + Policy.readings("/ADMIN/../x"),
              !Policy.readings("/ADMIN/../x").contains("/admin/../x")
              && Policy.readings("/ADMIN/../x").contains("/ADMIN/../x")
              && Policy.readings("/ADMIN/../x").contains("/x"));
        denies("an uppercase path with a dot segment does not walk past "
               + "exclude=/admin*", p,
               req("GET", "https://app.example.test/ADMIN/../x",
                   "app.example.test", "/ADMIN/../x", ""),
               cfg, "scope_denied");
        // Same shape one level down, under an exclude anchored deeper, so the
        // check is not resting on the one spelling: here the collapsed reading
        // is a real resource rather than the root, and it is still not what the
        // exclusion names.
        BridgeClient.Authorisation deeper = authorised(
                "scope.include", "https://app.example.test/*",
                "scope.exclude", "https://app.example.test/a/admin*");
        check("and again: " + Policy.readings("/A/ADMIN/../x"),
              !Policy.readings("/A/ADMIN/../x").contains("/a/admin/../x")
              && Policy.readings("/A/ADMIN/../x").contains("/a/x"));
        denies("nor does /A/ADMIN/../x walk past exclude=/a/admin*", p,
               req("GET", "https://app.example.test/A/ADMIN/../x",
                   "app.example.test", "/A/ADMIN/../x", ""),
               deeper, "scope_denied");
        // The control: the same exclude, a path whose lowercase form it does
        // NOT name, is allowed -- so the two above are the case fold rather
        // than the exclude matching everything.
        allows("while a path the exclude does not name is still allowed", p,
               req("GET", "https://app.example.test/PUBLIC/../x",
                   "app.example.test", "/PUBLIC/../x", ""),
               cfg);
    }

    /**
     * Round 7, green sabotage. Nothing pinned that `lower()` folds the WHOLE
     * string.
     *
     * The check beside the U+0130 closure block pins lower()'s COST -- it goes
     * red if lower() is "simplified" back to String.toLowerCase -- and nothing
     * pinned its extent. Capping the fold at the first 4096 characters is 0 red
     * against 596 checks and flips a `LOGOUT` past that point from
     * dangerous_denied to ALLOW. Both loops in lower() are covered here: the
     * scan that looks for the first character needing a fold, and the copy that
     * folds the rest.
     */
    static void lowerFoldsTheWholeStringAndNotAPrefixOfIt() {
        Policy p = allowingPolicy();

        String tail = "x".repeat(6000) + "ABC";
        check("lower() folds a character 6000 in, not just a prefix",
              Policy.lower(tail).endsWith("abc")
              && Policy.lower(tail).length() == tail.length());
        String both = "A" + "x".repeat(6000) + "B";
        check("...and one at each end, so the copy loop is covered as well as "
              + "the scan that finds the first character needing a fold",
              Policy.lower(both).equals("a" + "x".repeat(6000) + "b"));

        // End to end, which is what a cap actually costs: the denylist matches
        // on lower(target), so a dangerous word past the cap stops being one.
        String path = "/x/" + "a".repeat(6000) + "/LOGOUT";
        check("the fixture puts LOGOUT " + (path.length() - "/LOGOUT".length())
              + " characters in, well past any prefix a cap would fold, and "
              + "stays under MAX_TARGET_CHARS",
              path.length() < Policy.MAX_TARGET_CHARS && path.length() > 4096);
        denies("a LOGOUT past 4096 characters is still a logout", p,
               req("GET", "https://app.example.test" + path,
                   "app.example.test", path, ""),
               APP, "dangerous_denied");
        // The same in the query half, which folds through the same method.
        String query = "a=" + "b".repeat(6000) + "&action=LOGOUT";
        denies("and so is one past 4096 characters of query", p,
               req("GET", "https://app.example.test/i.php?" + query,
                   "app.example.test", "/i.php", query),
               APP, "dangerous_denied");
        // The control: the same length with nothing dangerous in it is allowed,
        // so the denials above are the word and not the length.
        allows("while a target that long with nothing dangerous in it is allowed", p,
               req("GET", "https://app.example.test/x/" + "a".repeat(6000) + "/orders",
                   "app.example.test", "/x/" + "a".repeat(6000) + "/orders", ""),
               APP);
    }

    /**
     * Round 7. Three of the four spellings an ALLOW pattern is read by had no
     * input that could falsify them.
     *
     * `addSpellings` adds the verbatim pattern, its case fold, its decoded
     * form, its UTF-8 fold and its separators-inert form. Deleting any of the
     * last three left every check green, which is the position round 6 recorded
     * for two guards in `denies()` and refused to dress up. Here an input
     * exists for each, so each gets one rather than a claim.
     */
    static void everySpellingAnIncludeIsReadByHasAnInputThatNeedsIt() {
        Policy p = allowingPolicy();

        // The case fold. The allows() comment claims an operator who wrote
        // /API/* does not have every request under it refused; readings()
        // lowercases the derived member, so /API/orders reads as /api/orders
        // and only the folded SPELLING of the pattern covers it.
        allows("include=/API/* authorises /API/orders (the case fold)", p,
               req("GET", "https://app.example.test/API/orders",
                   "app.example.test", "/API/orders", ""),
               authorised("scope.include", "https://app.example.test/API/*"));
        check("...and the reading that needs it really is there: "
              + Policy.readings("/API/orders"),
              Policy.readings("/API/orders").contains("/api/orders")
              && Policy.spellingReadings("/API/*").contains("/api/*"));

        // The separators-inert spelling. An include carrying an encoded
        // separator AND an ordinary escape has a reading in which the first is
        // still escaped and the second is not -- which is exactly the reading
        // the REQUEST has, on every server that decodes after it has cut the
        // path into segments. Without it that reading of the path is uncovered
        // and allow-AND refuses the request.
        String inertPattern = "https://app.example.test/files/a%2fb%20c/*";
        String inertPath = "/files/a%2fb%20c/x.pdf";
        check("the path has a reading that only the inert spelling covers: "
              + Policy.readings(inertPath),
              Policy.readings(inertPath).contains("/files/a%2fb c/x.pdf")
              && Policy.spellingReadings("/files/a%2fb%20c/*")
                       .contains("/files/a%2fb c/*"));
        allows("include=/files/a%2fb%20c/* authorises its own request "
               + "(the separators-inert spelling)", p,
               req("GET", "https://app.example.test" + inertPath,
                   "app.example.test", inertPath, ""),
               authorised("scope.include", inertPattern));

        // The UTF-8 fold. An operator who wrote the accented directory as
        // percent-escapes has a pattern whose DECODED form is two Latin-1
        // characters and whose UTF-8 reading is the one character the request
        // actually names.
        String utf8Path = "/files/café/a.pdf";
        check("the pattern's decoded form is not the character the request "
              + "carries, and only its UTF-8 fold is",
              Policy.spellingReadings("/files/caf%c3%a9/*")
                    .contains("/files/café/*")
              && !Policy.spellingReadings("/files/caf%c3%a9/*")
                        .contains("/files/cafÃ©/*"));
        allows("include=/files/caf%c3%a9/* authorises /files/café/a.pdf "
               + "(the UTF-8 fold)", p,
               req("GET", "https://app.example.test" + utf8Path,
                   "app.example.test", utf8Path, ""),
               authorised("scope.include", "https://app.example.test/files/caf%c3%a9/*"));
    }
}
