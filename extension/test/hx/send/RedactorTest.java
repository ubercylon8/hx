// extension/test/hx/send/RedactorTest.java
package hx.send;

import hx.TestSupport;
import hx.policy.HxRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class RedactorTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(RedactorTest::check, name, body);
    }

    static void expectThrows(String what, Class<?> type, Runnable body) {
        try {
            body.run();
            check(what + " (expected " + type.getSimpleName() + ")", false);
        } catch (Throwable t) {
            check(what, type.isInstance(t));
        }
    }

    public static void main(String[] args) {
        t("anEmptyRegistryLeavesTheRequestVerbatim", RedactorTest::anEmptyRegistryLeavesTheRequestVerbatim);
        t("aRegisteredRangeBecomesTheIdentityPlaceholder", RedactorTest::aRegisteredRangeBecomesTheIdentityPlaceholder);
        t("theBytesOnTheWireAreNeverTouched", RedactorTest::theBytesOnTheWireAreNeverTouched);
        t("twoRangesAreBothReplacedWhateverOrderTheyWereRegisteredIn", RedactorTest::twoRangesAreBothReplacedWhateverOrderTheyWereRegisteredIn);
        t("overlappingRangesAreRefusedAndAbuttingOnesAreNot", RedactorTest::overlappingRangesAreRefusedAndAbuttingOnesAreNot);
        t("aRangePastTheEndIsRefusedNotTruncated", RedactorTest::aRangePastTheEndIsRefusedNotTruncated);
        t("degenerateRangesAreRefused", RedactorTest::degenerateRangesAreRefused);
        t("oneRequestsRangesCannotReachTheNext", RedactorTest::oneRequestsRangesCannotReachTheNext);
        t("twoRangeSetsAliveAtOnceDoNotShareOneList", RedactorTest::twoRangeSetsAliveAtOnceDoNotShareOneList);
        t("oneInjectedIsRefusedAgainstASecondRequest", RedactorTest::oneInjectedIsRefusedAgainstASecondRequest);
        t("theRangesTravelWithTheRequestNotTheThread", RedactorTest::theRangesTravelWithTheRequestNotTheThread);

        t("anUnmanagedAuthorizationIsNamed", RedactorTest::anUnmanagedAuthorizationIsNamed);
        t("credentialHeaderMatchingIsCaseInsensitive", RedactorTest::credentialHeaderMatchingIsCaseInsensitive);
        t("credentialDetectionSurvivesATurkishLocale", RedactorTest::credentialDetectionSurvivesATurkishLocale);
        t("theNamedHeaderDoesNotDependOnMapOrder", RedactorTest::theNamedHeaderDoesNotDependOnMapOrder);
        t("aWholeNameMustMatchNotAPrefix", RedactorTest::aWholeNameMustMatchNotAPrefix);
        t("aCredentialNameIsMatchedThroughSurroundingWhitespace", RedactorTest::aCredentialNameIsMatchedThroughSurroundingWhitespace);
        t("aRequestWithoutACredentialHeaderIsNull", RedactorTest::aRequestWithoutACredentialHeaderIsNull);

        t("setCookieValuesAreReplacedAndAttributesKept", RedactorTest::setCookieValuesAreReplacedAndAttributesKept);
        t("everySetCookieHeaderIsRedacted", RedactorTest::everySetCookieHeaderIsRedacted);
        t("setCookieMatchingIsCaseInsensitive", RedactorTest::setCookieMatchingIsCaseInsensitive);
        t("aDeletionCookieKeepsItsEmptyValue", RedactorTest::aDeletionCookieKeepsItsEmptyValue);
        t("aCookiePairWithNoEqualsIsRedactedWhole", RedactorTest::aCookiePairWithNoEqualsIsRedactedWhole);
        t("aFoldedContinuationOfASetCookieIsRedacted", RedactorTest::aFoldedContinuationOfASetCookieIsRedacted);
        t("aSecondFoldedContinuationIsRedactedToo", RedactorTest::aSecondFoldedContinuationIsRedactedToo);
        t("whitespaceBeforeTheColonDoesNotHideACookie", RedactorTest::whitespaceBeforeTheColonDoesNotHideACookie);
        t("aBlankLineBeforeTheStatusLineDoesNotEndTheHead", RedactorTest::aBlankLineBeforeTheStatusLineDoesNotEndTheHead);
        t("anInterimHeadDoesNotEndTheResponse", RedactorTest::anInterimHeadDoesNotEndTheResponse);
        t("aHeadWhoseFirstLineIsAFieldIsStillRedacted", RedactorTest::aHeadWhoseFirstLineIsAFieldIsStillRedacted);
        t("theResponseBodyIsNeverRewritten", RedactorTest::theResponseBodyIsNeverRewritten);

        t("anObservedCookieIsReplacedAndItsNameKept",
          RedactorTest::anObservedCookieIsReplacedAndItsNameKept);
        t("anObservedAuthorizationIsReplaced",
          RedactorTest::anObservedAuthorizationIsReplaced);
        t("anObservedProxyAuthorizationIsReplaced",
          RedactorTest::anObservedProxyAuthorizationIsReplaced);
        t("twoBrowsesDifferingOnlyInTheCredentialProduceOneBlob",
          RedactorTest::twoBrowsesDifferingOnlyInTheCredentialProduceOneBlob);
        t("anObservedCredentialNameIsMatchedWhateverItsCase",
          RedactorTest::anObservedCredentialNameIsMatchedWhateverItsCase);
        t("aCookieInTheREQUESTBodyIsNeverRewritten",
          RedactorTest::aCookieInTheRequestBodyIsNeverRewritten);
        t("aRequestWithNoCredentialRoundTripsVerbatimAndNeverAliases",
          RedactorTest::aRequestWithNoCredentialRoundTripsVerbatimAndNeverAliases);
        t("aFoldedContinuationOfAnObservedCredentialIsRedacted",
          RedactorTest::aFoldedContinuationOfAnObservedCredentialIsRedacted);
        t("whitespaceBeforeTheColonDoesNotHideAnObservedCredential",
          RedactorTest::whitespaceBeforeTheColonDoesNotHideAnObservedCredential);
        t("aBlankLineBeforeTheRequestLineDoesNotEndTheHead",
          RedactorTest::aBlankLineBeforeTheRequestLineDoesNotEndTheHead);
        t("anAbsoluteFormRequestLineIsNotMatchedAsAField",
          RedactorTest::anAbsoluteFormRequestLineIsNotMatchedAsAField);
        t("redactObservedRequestRefusesNullBytes",
          RedactorTest::redactObservedRequestRefusesNullBytes);
        t("theEmptyInjectedPathIsWhyJobFourExists",
          RedactorTest::theEmptyInjectedPathIsWhyJobFourExists);

        t("redactionHappensBeforeHashing", RedactorTest::redactionHappensBeforeHashing);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- the injected-range registry ------------------------------------

    static final String TOKEN = "eyJhbGciOiJIUzI1NiJ9.cHJvZC1zZXNzaW9u.9f2c";

    static byte[] authRequest() {
        return bytes("GET /orders?status=open HTTP/1.1\r\n"
                   + "Host: app.example.test\r\n"
                   + "Accept: application/json\r\n"
                   + "Authorization: Bearer " + TOKEN + "\r\n"
                   + "\r\n");
    }

    /** The range the extension would register for the request above: the
     *  credential value only, so the header name and the structure around it
     *  stay verbatim in the evidence. */
    static int tokenStart(byte[] raw) { return find(raw, "Bearer " + TOKEN); }
    static int tokenEnd(byte[] raw)   { return tokenStart(raw) + ("Bearer " + TOKEN).length(); }

    static void anEmptyRegistryLeavesTheRequestVerbatim() {
        // Nothing registers a range until identity injection ships. Until then
        // this is the only path that runs, and it must be a no-op.
        Redactor r = new Redactor();
        byte[] raw = authRequest();
        byte[] out = r.redactRequest(raw, new Redactor.Injected(raw));
        check("an empty registry returns the same bytes", Arrays.equals(out, raw));
        check("an empty registry still returns a copy, not the wire array", out != raw);
    }

    static void aRegisteredRangeBecomesTheIdentityPlaceholder() {
        Redactor r = new Redactor();
        byte[] raw = authRequest();
        Redactor.Injected injected = new Redactor.Injected(raw);
        injected.register("ident-admin", tokenStart(raw), tokenEnd(raw));
        String out = text(r.redactRequest(raw, injected));
        check("the injected range is replaced by the identity placeholder",
              out.contains("Authorization: {{identity:ident-admin:authz}}\r\n"));
        check("the credential is gone from the copy that crosses the bridge",
              !out.contains(TOKEN));
        check("everything around it is verbatim",
              out.startsWith("GET /orders?status=open HTTP/1.1\r\nHost: app.example.test\r\n")
              && out.endsWith("\r\n\r\n"));
    }

    static void theBytesOnTheWireAreNeverTouched() {
        // §4: the request Burp issues is verbatim; only the copy crossing the
        // bridge is substituted. An in-place edit would corrupt the exchange
        // it exists to evidence -- and would do it AFTER the decision.
        Redactor r = new Redactor();
        byte[] raw = authRequest();
        byte[] wire = raw.clone();
        Redactor.Injected injected = new Redactor.Injected(raw);
        injected.register("ident-admin", tokenStart(raw), tokenEnd(raw));
        r.redactRequest(raw, injected);
        check("redactRequest does not modify its argument", Arrays.equals(raw, wire));
    }

    static void twoRangesAreBothReplacedWhateverOrderTheyWereRegisteredIn() {
        Redactor r = new Redactor();
        byte[] raw = bytes("POST /account HTTP/1.1\r\n"
                         + "Host: app.example.test\r\n"
                         + "Cookie: JSESSIONID=9C4A1F0E27B84D5FA3\r\n"
                         + "Authorization: Bearer " + TOKEN + "\r\n"
                         + "\r\nname=x");
        // Registered LAST-first on purpose: the registry sorts, the caller
        // does not have to.
        Redactor.Injected injected = new Redactor.Injected(raw);
        int aStart = find(raw, "Bearer " + TOKEN);
        injected.register("ident-admin", aStart, aStart + ("Bearer " + TOKEN).length());
        int cStart = find(raw, "JSESSIONID=9C4A1F0E27B84D5FA3");
        injected.register("ident-admin", cStart, cStart + "JSESSIONID=9C4A1F0E27B84D5FA3".length());
        String out = text(r.redactRequest(raw, injected));
        check("both ranges are replaced",
              out.contains("Cookie: {{identity:ident-admin:authz}}\r\n")
              && out.contains("Authorization: {{identity:ident-admin:authz}}\r\n"));
        check("the body after the last range survives", out.endsWith("\r\n\r\nname=x"));
    }

    static void overlappingRangesAreRefusedAndAbuttingOnesAreNot() {
        // Overlap means the two ranges disagree about what those bytes are.
        // Truncating or double-substituting either one produces bytes that
        // were never sent, so the answer is a refusal.
        // These offsets are the whole fixture, so the bytes they are measured
        // from need only be long enough to hold them.
        Redactor.Injected injected = new Redactor.Injected(new byte[64]);
        injected.register("ident-admin", 10, 20);
        expectThrows("a range overlapping an earlier one is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-admin", 15, 25));
        expectThrows("a range containing an earlier one is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-b", 5, 30));
        // [10,20) and [20,30) are two adjacent injected headers, not an overlap.
        injected.register("ident-b", 20, 30);
        check("abutting ranges are accepted", true);
    }

    static void aRangePastTheEndIsRefusedNotTruncated() {
        // Silently clamping would hand the bridge a request shorter than the
        // one that was sent, and the evidence would be of a request nobody
        // made.
        Redactor r = new Redactor();
        byte[] raw = authRequest();
        Redactor.Injected injected = new Redactor.Injected(raw);
        injected.register("ident-admin", raw.length - 4, raw.length + 40);
        expectThrows("a range running past the end of the request is refused",
                     Redactor.RangeError.class, () -> r.redactRequest(raw, injected));
    }

    static void degenerateRangesAreRefused() {
        Redactor.Injected injected = new Redactor.Injected(new byte[16]);
        expectThrows("a negative start is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-admin", -1, 5));
        expectThrows("an empty range is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-admin", 7, 7));
        expectThrows("a reversed range is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-admin", 9, 4));
        expectThrows("a range with no identity is refused",
                     Redactor.RangeError.class, () -> injected.register("", 0, 5));
        // The degenerate ARGUMENTS, and the same answer for all of them. A
        // caller that has not said what it injected has not said "nothing";
        // RangeError is what the Sender turns into bad_frame, where an NPE
        // would reach BridgeClient's catch-all and close the connection
        // instead. That rationale was written here while three of these four
        // still threw NPE, which made it a claim about code that did not exist.
        expectThrows("redacting without naming any ranges at all is refused",
                     Redactor.RangeError.class,
                     () -> new Redactor().redactRequest(new byte[4], null));
        expectThrows("redacting null request bytes is refused",
                     Redactor.RangeError.class,
                     () -> new Redactor().redactRequest(null, new Redactor.Injected(new byte[4])));
        expectThrows("redacting a null response is refused",
                     Redactor.RangeError.class, () -> new Redactor().redactResponse(null));
        expectThrows("an Injected that names no bytes at all is refused",
                     Redactor.RangeError.class, () -> new Redactor.Injected(null));
    }

    static void oneRequestsRangesCannotReachTheNext() {
        // What clear() used to be for, now structural. One request's offsets
        // applied to the next request's bytes do not merely leak, they blank
        // out a span of somebody else's body -- so the ranges belong to the
        // request, and the next request's Injected is a different object with
        // nothing in it. There is no finally to forget and no registry to
        // clear on the wrong thread.
        Redactor r = new Redactor();
        byte[] first = authRequest();
        Redactor.Injected forFirst = new Redactor.Injected(first);
        forFirst.register("ident-admin", tokenStart(first), tokenEnd(first));
        r.redactRequest(first, forFirst);

        // Deliberately LONGER than the first request's last offset: were the
        // ranges to survive, this asks for silent corruption of an unrelated
        // body rather than the RangeError a short fixture would provoke.
        String body = "amount=100&to=acct-99&memo=ALONG-ENOUGH-MEMO-FIELD-THAT-SPANS-THE-WHOLE-RANGE";
        byte[] next = bytes("POST /transfer HTTP/1.1\r\n"
                          + "Host: app.example.test\r\n"
                          + "Content-Length: " + body.length() + "\r\n"
                          + "\r\n" + body);
        check("the next request, redacted with its own Injected, is verbatim",
              Arrays.equals(r.redactRequest(next, new Redactor.Injected(next)), next));
    }

    static void twoRangeSetsAliveAtOnceDoNotShareOneList() {
        // BOTH requests are built and BOTH range sets registered before either
        // is redacted. That is the shape the sequential fixture above cannot
        // reach: there, the second Injected is constructed after the first has
        // already been redacted, so a registry shared between instances is
        // reset at the one moment when there is nothing left to break. Here
        // the credential sits at a DIFFERENT offset in each fixture, so a set
        // applied to the wrong request lands on other bytes and leaves the
        // credential raw -- with no exception and nothing else to notice it by.
        Redactor r = new Redactor();
        String credA = "Bearer " + TOKEN + "-admin-session.aaaa";
        String credB = "Bearer " + TOKEN + "-teller-session.bbbb";
        byte[] b = bytes("GET /b HTTP/1.1\r\n"
                       + "Authorization: " + credB + "\r\n"
                       + "Host: app.example.test\r\nAccept: */*\r\n\r\n");
        byte[] a = bytes("GET /a HTTP/1.1\r\nHost: app.example.test\r\n"
                       + "X-Trace: 1234567890123456789012345678901234567890\r\n"
                       + "Authorization: " + credA + "\r\n\r\n");
        // Measured, not assumed: B's range has to fall entirely before A's
        // credential, or applying it to A would clip the credential and the
        // leak would show up as corruption rather than as a live token.
        check("the fixtures put the credential at different offsets, B's range clear of A's",
              find(b, credB) + credB.length() < find(a, credA));

        Redactor.Injected forA = new Redactor.Injected(a);
        forA.register("ident-admin", find(a, credA), find(a, credA) + credA.length());
        Redactor.Injected forB = new Redactor.Injected(b);
        forB.register("ident-teller", find(b, credB), find(b, credB) + credB.length());

        String outA = text(r.redactRequest(a, forA));
        String outB = text(r.redactRequest(b, forB));
        check("each request carries its own identity's placeholder",
              outA.contains("Authorization: {{identity:ident-admin:authz}}\r\n")
              && outB.contains("Authorization: {{identity:ident-teller:authz}}\r\n"));
        check("neither credential survives into the copy that crosses the bridge",
              !outA.contains(credA) && !outB.contains(credB));
        check("neither request carries the other's placeholder",
              !outA.contains("ident-teller") && !outB.contains("ident-admin"));
    }

    static void oneInjectedIsRefusedAgainstASecondRequest() {
        // Reuse used to fail closed only where the offsets happened to
        // collide. Four shapes, all measured before this pin existed: shorter
        // second request -> RangeError; longer with nothing newly registered
        // -> silently rewritten at the stale offsets, the second request's OWN
        // credential left verbatim; longer with an overlapping registration ->
        // RangeError; longer with a non-overlapping one -> silently rewritten
        // again. Two of four. An Injected now holds the array it was measured
        // from, so every shape is the same loud refusal.
        Redactor r = new Redactor();
        byte[] one = authRequest();
        Redactor.Injected reused = new Redactor.Injected(one);
        reused.register("ident-admin", tokenStart(one), tokenEnd(one));
        r.redactRequest(one, reused);

        // The binding is by IDENTITY, not by content or length: a second
        // array holding the exact same bytes as `one` is still refused,
        // because it is not the array these ranges were measured from. A
        // length-only check would let this through -- the two are the same
        // length by construction, being the same content -- which is exactly
        // why an equal-length reuse with the credential at a different offset
        // would otherwise be silently rewritten rather than refused.
        expectThrows("a second request with the SAME length -- indeed identical "
                    + "content, a different array object holding the same bytes -- is refused",
                     Redactor.RangeError.class, () -> r.redactRequest(one.clone(), reused));

        byte[] shorter = bytes("GET /x HTTP/1.1\r\nHost: app.example.test\r\n\r\n");
        expectThrows("a second request SHORTER than the stale range is refused",
                     Redactor.RangeError.class, () -> r.redactRequest(shorter, reused));

        // Padded so the stale range lands on this request's Content-Length and
        // clear of its own credential: the shape that rewrote the second
        // request silently while the credential it carried survived verbatim.
        String body = "amount=100&to=acct-99&memo=A-MEMO-FIELD-LONG-ENOUGH-TO-SPAN-THE-RANGE";
        byte[] longer = bytes("POST /transfer HTTP/1.1\r\nHost: app.example.test\r\n"
                            + "Content-Length: " + body.length() + "\r\n"
                            + "X-Filler: ........................................................................\r\n"
                            + "Authorization: Bearer " + TOKEN + "-second\r\n"
                            + "\r\n" + body);
        String own = "Bearer " + TOKEN + "-second";
        check("the second fixture is longer than the stale range and its own "
              + "credential sits clear of it",
              longer.length > tokenEnd(one) && find(longer, own) >= tokenEnd(one));

        expectThrows("a second request LONGER, with nothing newly registered, is refused",
                     Redactor.RangeError.class, () -> r.redactRequest(longer, reused));
        expectThrows("a second request LONGER, with a range OVERLAPPING the stale one, is refused",
                     Redactor.RangeError.class, () -> {
                         reused.register("ident-admin", tokenStart(one) + 2, tokenStart(one) + 12);
                         r.redactRequest(longer, reused);
                     });
        expectThrows("a second request LONGER, with a range that does NOT overlap, is refused",
                     Redactor.RangeError.class, () -> {
                         reused.register("ident-admin", find(longer, own), find(longer, own) + own.length());
                         r.redactRequest(longer, reused);
                     });
    }

    static void theRangesTravelWithTheRequestNotTheThread() throws Exception {
        // The read loop registers what it injected and a pooled worker
        // redacts -- the limit.concurrency shape §6 already has a config key
        // for. With the registry held on the Redactor (a field or a
        // ThreadLocal) the worker's is empty, so redactRequest hands back a
        // verbatim copy WITH the credential in it: no exception, no signal,
        // and those are the bytes that get content-addressed. The assertion
        // this replaced said the other thread's copy equalled `raw` -- it
        // passed if and only if the credential survived.
        Redactor r = new Redactor();
        byte[] raw = authRequest();
        Redactor.Injected injected = new Redactor.Injected(raw);
        injected.register("ident-admin", tokenStart(raw), tokenEnd(raw));
        String[] fromWorker = new String[1];
        Thread worker = new Thread(() -> fromWorker[0] = text(r.redactRequest(raw, injected)));
        // Daemon and bounded, for the reason on TestSupport.t: an unbounded
        // `worker.join()` here turns any `redactRequest` that ever takes a
        // lock into a class that prints NO summary line and no FAIL line, and
        // a non-daemon worker holds the JVM open past ALL PASS. Ten seconds
        // against a single in-memory byte-copy.
        worker.setDaemon(true);
        worker.start();
        TestSupport.join(worker, 10_000L, "the worker thread doing the redaction");
        check("a range registered on the read loop is applied by the worker that redacts",
              fromWorker[0].contains("Authorization: {{identity:ident-admin:authz}}\r\n")
              && !fromWorker[0].contains(TOKEN));
    }

    // ---- fail closed on what we did not inject --------------------------

    static HxRequest req(Map<String, List<String>> headers) {
        return new HxRequest("GET", "https://app.example.test/orders", "app.example.test",
                             "/orders", "status=open", headers, new byte[0]);
    }

    static void anUnmanagedAuthorizationIsNamed() {
        Redactor r = new Redactor();
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Accept", List.of("application/json"));
        h.put("Authorization", List.of("Bearer " + TOKEN));
        check("an Authorization the extension did not inject is named",
              "Authorization".equals(r.unmanagedCredential(req(h))));
    }

    static void credentialHeaderMatchingIsCaseInsensitive() {
        Redactor r = new Redactor();
        check("lower-case authorization is caught",
              "authorization".equals(r.unmanagedCredential(
                  req(Map.of("authorization", List.of("Bearer " + TOKEN))))));
        check("mixed-case Cookie is caught",
              "cOoKiE".equals(r.unmanagedCredential(
                  req(Map.of("cOoKiE", List.of("JSESSIONID=9C4A1F0E27B84D5FA3"))))));
        check("upper-case PROXY-AUTHORIZATION is caught",
              "PROXY-AUTHORIZATION".equals(r.unmanagedCredential(
                  req(Map.of("PROXY-AUTHORIZATION", List.of("Basic YWRtaW46aHVudGVyMg=="))))));
    }

    static void credentialDetectionSurvivesATurkishLocale() {
        Redactor r = new Redactor();
        Locale saved = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            // Measured, not assumed: this is the fold that would break a
            // toLowerCase()-based match, and it is why the matcher is ASCII.
            check("tr_TR really does fold 'I' away from 'i'",
                  !"AUTHORIZATION".toLowerCase().equals("authorization"));
            check("credential detection survives a Turkish locale",
                  "AUTHORIZATION".equals(r.unmanagedCredential(
                      req(Map.of("AUTHORIZATION", List.of("Bearer " + TOKEN))))));
        } finally {
            Locale.setDefault(saved);
        }
    }

    static void theNamedHeaderDoesNotDependOnMapOrder() {
        // Same request, two iteration orders, one answer: the refusal detail
        // is evidence and must read the same twice.
        Redactor r = new Redactor();
        Map<String, List<String>> cookieFirst = new LinkedHashMap<>();
        cookieFirst.put("Cookie", List.of("JSESSIONID=9C4A1F0E27B84D5FA3"));
        cookieFirst.put("Authorization", List.of("Bearer " + TOKEN));
        Map<String, List<String>> authFirst = new LinkedHashMap<>();
        authFirst.put("Authorization", List.of("Bearer " + TOKEN));
        authFirst.put("Cookie", List.of("JSESSIONID=9C4A1F0E27B84D5FA3"));
        check("Authorization wins whichever way the map iterates",
              "Authorization".equals(r.unmanagedCredential(req(cookieFirst)))
              && "Authorization".equals(r.unmanagedCredential(req(authFirst))));
    }

    static void aWholeNameMustMatchNotAPrefix() {
        Redactor r = new Redactor();
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("X-Cookie-Consent", List.of("all"));
        h.put("Authorization-Info", List.of("nextnonce=42"));
        check("a header merely containing a credential name is not one",
              r.unmanagedCredential(req(h)) == null);
    }

    static void aCredentialNameIsMatchedThroughSurroundingWhitespace() {
        // unmanagedCredential is a FAIL-CLOSED gate, so the cost of a name it
        // cannot match is not a missed match: it is the answer "no credential",
        // on which the Sender issues the request and persists it. RFC 9110
        // forbids whitespace around a field name and Sender.parse refuses one,
        // but this matcher is the last thing between a live production
        // credential and a content-addressed store, and it should not depend
        // on a caller two classes away having normalised its input.
        Redactor r = new Redactor();
        String[] spellings = { "Authorization ", " Authorization",
                               "Authorization\t", "Authorization\r",
                               "Authorization\n" };
        String[] labels = { "a trailing space", "a leading space",
                            "a trailing tab", "a trailing CR",
                            "a trailing LF" };
        for (int i = 0; i < spellings.length; i++)
            // Equality with the UNTRIMMED spelling, because the refusal quotes
            // what was actually sent rather than what we matched on.
            check("an Authorization with " + labels[i] + " is still a credential header",
                  spellings[i].equals(r.unmanagedCredential(
                      req(Map.of(spellings[i], List.of("Bearer " + TOKEN))))));
    }

    static void aRequestWithoutACredentialHeaderIsNull() {
        Redactor r = new Redactor();
        check("an ordinary request is not refused",
              r.unmanagedCredential(req(Map.of("Accept", List.of("*/*")))) == null);
        check("a request with no headers at all is not refused",
              r.unmanagedCredential(req(Map.of())) == null);
    }

    // ---- response Set-Cookie --------------------------------------------

    static final String SESSION = "9C4A1F0E27B84D5FA3";

    static byte[] loginResponse() {
        // A body whose second line is EXACTLY a Set-Cookie field, because that
        // is what a page documenting cookies looks like -- and because a body
        // that could never be mistaken for a header would not guard anything.
        String body = "Cookies this app sets:\r\nSet-Cookie: sid=not-a-real-header\r\n";
        return bytes("HTTP/1.1 302 Found\r\n"
                   + "Date: Sat, 22 Aug 2026 09:14:03 GMT\r\n"
                   + "Content-Type: text/html; charset=utf-8\r\n"
                   + "Set-Cookie: JSESSIONID=" + SESSION
                   + "; Path=/; HttpOnly; Secure; SameSite=Lax\r\n"
                   + "Set-Cookie: csrf=8f14e45fceea167a5a36dedd4bea2543; Path=/; Secure\r\n"
                   + "Location: https://app.example.test/dashboard\r\n"
                   + "Content-Length: " + body.length() + "\r\n"
                   + "\r\n" + body);
    }

    static void setCookieValuesAreReplacedAndAttributesKept() {
        Redactor r = new Redactor();
        byte[] raw = loginResponse();
        byte[] wire = raw.clone();
        String out = text(r.redactResponse(raw));
        check("the cookie value is replaced",
              out.contains("Set-Cookie: JSESSIONID={{observed:set-cookie}}; "
                           + "Path=/; HttpOnly; Secure; SameSite=Lax\r\n"));
        check("the live session cookie is gone", !out.contains(SESSION));
        check("attributes survive, so cookie-flag checks still read",
              out.contains("HttpOnly") && out.contains("Secure") && out.contains("SameSite=Lax"));
        check("other headers are verbatim",
              out.contains("Location: https://app.example.test/dashboard\r\n")
              && out.contains("Content-Type: text/html; charset=utf-8\r\n"));
        check("redactResponse does not modify its argument", Arrays.equals(raw, wire));
    }

    static void everySetCookieHeaderIsRedacted() {
        // A response sets several cookies at once, and the second one is as
        // live as the first.
        Redactor r = new Redactor();
        String out = text(r.redactResponse(loginResponse()));
        check("the second Set-Cookie is redacted too",
              out.contains("Set-Cookie: csrf={{observed:set-cookie}}; Path=/; Secure\r\n"));
        check("no cookie value survives anywhere in the head",
              !out.contains("8f14e45fceea167a5a36dedd4bea2543"));
    }

    static void setCookieMatchingIsCaseInsensitive() {
        Redactor r = new Redactor();
        String out = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "set-cookie: sid=" + SESSION + "; Path=/\r\n"
            + "SET-COOKIE: pref=dark\r\n"
            + "\r\n")));
        check("a lower-case set-cookie is redacted",
              out.contains("set-cookie: sid={{observed:set-cookie}}; Path=/\r\n"));
        check("an upper-case SET-COOKIE is redacted",
              out.contains("SET-COOKIE: pref={{observed:set-cookie}}\r\n"));
    }

    static void aDeletionCookieKeepsItsEmptyValue() {
        // A logout clears the cookie, and that is how a logout is DETECTED.
        // An empty value cannot be a credential, and a placeholder here would
        // read as an issuance.
        Redactor r = new Redactor();
        String out = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie: JSESSIONID=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/\r\n"
            + "\r\n")));
        check("a deletion cookie is left alone",
              out.contains("Set-Cookie: JSESSIONID=; "
                           + "Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/\r\n"));
    }

    static void aCookiePairWithNoEqualsIsRedactedWhole() {
        // No name=value split to make, so every byte of the pair could be the
        // value. Unknown means redact.
        Redactor r = new Redactor();
        String out = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie: " + SESSION + "; Path=/\r\n"
            + "\r\n")));
        check("a malformed cookie pair is redacted whole",
              out.contains("Set-Cookie: {{observed:set-cookie}}; Path=/\r\n"));
        check("its bytes do not survive", !out.contains(SESSION));
    }

    static void aFoldedContinuationOfASetCookieIsRedacted() {
        // obs-fold is dead in RFC 9110 and no real server emits it, but if one
        // does, the value can sit entirely on the folded line -- where a
        // per-line matcher never looks, because the continuation has no name.
        Redactor r = new Redactor();
        String out = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie: sid=\r\n"
            + "\t" + SESSION + "; Path=/\r\n"
            + "Content-Length: 0\r\n"
            + "\r\n")));
        check("a value hidden on a folded continuation line does not survive",
              !out.contains(SESSION));
        check("the fold itself is preserved so the head still parses",
              out.contains("\r\n\t{{observed:set-cookie}}\r\n"));
        check("the header after the fold is untouched",
              out.contains("Content-Length: 0\r\n"));
    }

    static void aSecondFoldedContinuationIsRedactedToo() {
        // The fold branch does not re-derive inSetCookie, so it stays armed
        // for as many continuation lines as arrive. Without this fixture,
        // clearing the flag after the FIRST fold leaves the whole suite green
        // and the second fold's cookie bytes on disk -- an unfalsified guard,
        // which on this branch is how seven of them got there.
        Redactor r = new Redactor();
        String out = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie: sid=\r\n"
            + "\t" + SESSION + "\r\n"
            + " csrf=8f14e45fceea167a5a36dedd4bea2543\r\n"
            + "Content-Length: 0\r\n"
            + "\r\n")));
        check("a value on a SECOND folded continuation does not survive either",
              !out.contains(SESSION) && !out.contains("8f14e45fceea167a5a36dedd4bea2543"));
        check("both folds are preserved so the head still parses",
              out.contains("\r\n\t{{observed:set-cookie}}\r\n {{observed:set-cookie}}\r\n"));
    }

    static void whitespaceBeforeTheColonDoesNotHideACookie() {
        // Name matching is ALL job 3 has, so a name it fails to match is a
        // live cookie copied through verbatim -- and it also leaves
        // inSetCookie false, which switches off the fold branch for that
        // header's continuations. RFC 9110 requires a recipient to reject
        // whitespace before the colon; a redactor that trusts every recipient
        // to have done so is one that fails open when one has not.
        Redactor r = new Redactor();
        String spaced = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie : JSESSIONID=" + SESSION + "; Path=/\r\n"
            + "\r\n")));
        check("a space before the colon does not pass the cookie through",
              !spaced.contains(SESSION)
              && spaced.contains("Set-Cookie : JSESSIONID={{observed:set-cookie}}; Path=/\r\n"));

        String tabbed = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie\t: sid=" + SESSION + "\r\n"
            + "\r\n")));
        check("a tab before the colon does not pass the cookie through",
              !tabbed.contains(SESSION));

        String cr = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie\r: sid=" + SESSION + "\r\n"
            + "\r\n")));
        // The byte side trims what the String side trims, through the same
        // predicate. A name it fails to match is a live cookie stored raw.
        check("a bare CR before the colon does not pass the cookie through",
              !cr.contains(SESSION));

        String folded = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie : sid=\r\n"
            + "\t" + SESSION + "; Path=/\r\n"
            + "\r\n")));
        check("the fold branch stays armed for such a header's continuation",
              !folded.contains(SESSION));
    }

    static void aBlankLineBeforeTheStatusLineDoesNotEndTheHead() {
        // RFC 9112 §2.2 explicitly contemplates a stray empty line ahead of
        // the status line. Ending the head there copies the ENTIRE response
        // through as "body" -- every Set-Cookie raw, into a content-addressed
        // store, with nothing in the evidence to say it happened.
        Redactor r = new Redactor();
        String body = "Set-Cookie: sid=not-a-real-header\r\n";
        String out = text(r.redactResponse(bytes(
              "\r\n"
            + "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie: JSESSIONID=" + SESSION + "; Path=/\r\n"
            + "Content-Length: " + body.length() + "\r\n"
            + "\r\n" + body)));
        check("a leading blank line does not disable redaction for the response",
              !out.contains(SESSION)
              && out.contains("Set-Cookie: JSESSIONID={{observed:set-cookie}}; Path=/\r\n"));
        check("the stray line is preserved, so the response reads as it arrived",
              out.startsWith("\r\nHTTP/1.1 200 OK\r\n"));
        // The other direction, and the one a fix could break: the blank line
        // that really does end the head still ends it.
        check("the head still ends at its own blank line", out.endsWith("\r\n\r\n" + body));

        // TWO of them, because offset zero is not what makes that line
        // special. Pinned at one line only, `if (first)` narrowed to
        // `if (first && i == 0)` leaves the whole suite green and drops the
        // second stray line's response into the store raw.
        String twice = text(r.redactResponse(bytes(
              "\r\n\r\n"
            + "HTTP/1.1 200 OK\r\n"
            + "Set-Cookie: JSESSIONID=" + SESSION + "; Path=/\r\n"
            + "\r\n")));
        check("a SECOND stray blank line does not disable redaction either",
              !twice.contains(SESSION)
              && twice.startsWith("\r\n\r\nHTTP/1.1 200 OK\r\n"));
    }

    static void anInterimHeadDoesNotEndTheResponse() {
        // RFC 9110 15.2: a 1xx is an interim response and never the final one,
        // so the blank line after it ends a head with the real response still
        // to come. Stopping there copies that whole response through as "body"
        // -- every Set-Cookie raw, into a content-addressed store, with
        // nothing in the evidence to say it happened. The branch cannot fire
        // on a final response, so it is safe whether or not Burp ever hands us
        // an interim head: that is Task 6's measurement, not this class's.
        Redactor r = new Redactor();
        String realHead = "HTTP/1.1 200 OK\r\n"
                        + "Set-Cookie: JSESSIONID=" + SESSION + "; Path=/; HttpOnly\r\n"
                        + "Content-Length: 0\r\n\r\n";
        String cont = text(r.redactResponse(bytes("HTTP/1.1 100 Continue\r\n\r\n" + realHead)));
        check("a 100 Continue ahead of the response does not disable redaction",
              !cont.contains(SESSION)
              && cont.contains("Set-Cookie: JSESSIONID={{observed:set-cookie}}; Path=/; HttpOnly\r\n"));
        check("the interim head itself is preserved, so the exchange reads as it arrived",
              cont.startsWith("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));

        String hints = text(r.redactResponse(bytes(
              "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n" + realHead)));
        check("a 103 Early Hints with fields of its own does not disable redaction either",
              !hints.contains(SESSION)
              && hints.contains("Link: </s.css>; rel=preload\r\n"));

        // RFC 9110 15.2 requires a client to parse ONE OR MORE 1xx responses
        // before the final one, and RFC 8297 permits more than one 103 --
        // Expect: 100-continue against an Early-Hints server produces
        // 100-then-103 directly. `first` is what re-arms the scan for each
        // interim head's OWN status line; a SINGLE interim head cannot show
        // that this matters, because `first` is already true when its status
        // line is read. Drop the reset and the SECOND interim head's status
        // line is read as an ordinary field instead (no colon, so it also
        // fails the Set-Cookie match), `interim` is never re-armed for it,
        // and the blank line that follows is then taken for the end of the
        // whole head -- so the real response, Set-Cookie and all, is
        // returned as "body".
        String twoHints = text(r.redactResponse(bytes(
              "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
            + "HTTP/1.1 103 Early Hints\r\nLink: </b>\r\n\r\n"
            + "HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=" + SESSION + "; Path=/\r\n\r\n")));
        check("two 1xx responses in a row do not disable redaction of the final one",
              !twoHints.contains(SESSION)
              && twoHints.contains("Set-Cookie: JSESSIONID={{observed:set-cookie}}; Path=/\r\n"));

        // The direction the branch could break, and the reason it is keyed on
        // the CODE rather than on "another head might follow": a final
        // response still ends its head at its own blank line.
        String body = "Set-Cookie: sid=not-a-real-header\r\n";
        String fin = text(r.redactResponse(bytes("HTTP/1.1 200 OK\r\n"
                        + "Set-Cookie: sid=" + SESSION + "\r\n"
                        + "Content-Length: " + body.length() + "\r\n\r\n" + body)));
        check("a final response still ends its head at its own blank line",
              fin.endsWith("\r\n\r\n" + body) && !fin.contains(SESSION));

        // A status code is exactly three digits (RFC 9112 4). "1000" is not a
        // 1xx, and reading it as one would scan a real body as a head -- but
        // that is invisible unless the "head" it scans has something in it a
        // matcher could mistake for Set-Cookie. A body opening with prose
        // that merely MENTIONS "Set-Cookie:" fails the name-length check for
        // the same reason a real header passes it, so such a fixture yields
        // the identical bytes whether or not 1000 is read as interim. The
        // first line has to be an actual field.
        String plain = "Set-Cookie: sid=" + SESSION + "; Path=/\r\n";
        String odd = text(r.redactResponse(bytes("HTTP/1.1 1000 Nonsense\r\n\r\n" + plain)));
        check("a code that is not three digits is not an interim head",
              odd.endsWith("\r\n\r\n" + plain));

        // interim=false at the reset above is unfalsified without this: an
        // interim head followed by a HEADLESS one -- no line of its own
        // starts with HTTP/ -- never re-enters the branch that would
        // re-derive `interim`, because that only happens from inside the
        // "first && startsWithHttpName" check. `interim` is left stuck at
        // whatever the interim head's OWN status line set it to, so the
        // headless head's own blank line -- which should end the scan -- is
        // misread as ending ANOTHER interim head, and the body that follows
        // is scanned as a third head instead of being returned untouched.
        String bodyLine = "Set-Cookie: not a real header, just body text\r\n";
        String headless = text(r.redactResponse(bytes(
              "HTTP/1.1 103 Early Hints\r\n\r\n"
            + "X-Odd: this head has no status line of its own\r\n"
            + "\r\n" + bodyLine)));
        check("an interim head followed by a headless one still lets the body through untouched",
              headless.endsWith("\r\n\r\n" + bodyLine));
    }

    static void aHeadWhoseFirstLineIsAFieldIsStillRedacted() {
        // The first non-empty line used to be taken for the status line
        // whatever it said, so a head beginning with Set-Cookie had that
        // cookie consumed as a status line and copied through raw.
        Redactor r = new Redactor();
        String out = text(r.redactResponse(bytes(
              "Set-Cookie: JSESSIONID=" + SESSION + "; Path=/\r\n"
            + "Content-Length: 0\r\n\r\n")));
        check("a Set-Cookie on the first line is not mistaken for a status line",
              !out.contains(SESSION)
              && out.contains("Set-Cookie: JSESSIONID={{observed:set-cookie}}; Path=/\r\n"));
        check("a head with no status line still ends at its blank line",
              out.endsWith("Content-Length: 0\r\n\r\n"));

        // The other direction: a real status line is still not matched as a
        // field, and still arms the scan for the fields after it.
        String normal = text(r.redactResponse(bytes(
              "HTTP/1.1 200 OK\r\nSet-Cookie: sid=" + SESSION + "\r\n\r\n")));
        check("a real status line is copied through verbatim and the head still reads",
              normal.startsWith("HTTP/1.1 200 OK\r\n") && !normal.contains(SESSION));
    }

    static void theResponseBodyIsNeverRewritten() {
        // A body may legitimately contain the text "Set-Cookie:" -- API error
        // dumps and documentation pages do -- and rewriting it corrupts the
        // evidence a check reads.
        Redactor r = new Redactor();
        String out = text(r.redactResponse(loginResponse()));
        check("a Set-Cookie inside the body is left verbatim",
              out.endsWith("\r\n\r\nCookies this app sets:\r\n"
                           + "Set-Cookie: sid=not-a-real-header\r\n"));
    }

    // ---- the ordering the blob store depends on -------------------------

    /**
     * The blob store is content-addressed: put() hashes the bytes it is given
     * and stores them under that digest. So the bytes handed to it are the
     * bytes kept, and redaction has to have happened already. Hash first and
     * the digest names the raw bytes -- which is what a content-addressed
     * store then keeps, in every backup taken since.
     */
    static void redactionHappensBeforeHashing() throws Exception {
        Redactor r = new Redactor();
        byte[] raw = authRequest();
        Redactor.Injected injected = new Redactor.Injected(raw);
        injected.register("ident-admin", tokenStart(raw), tokenEnd(raw));
        byte[] crossingTheBridge = r.redactRequest(raw, injected);

        // A content-addressed store, in three lines, standing in for
        // hx.store.blobs.BlobStore.put() -- same sha256 hex digest.
        Map<String, byte[]> store = new HashMap<>();
        store.put(sha256(crossingTheBridge), crossingTheBridge);

        check("the raw bytes are not addressable in the store at all",
              store.get(sha256(raw)) == null);
        check("nothing under the digest a caller computes can be turned back "
              + "into the credential",
              !text(store.get(sha256(crossingTheBridge))).contains(TOKEN));
        check("redacting changes the digest, so the raw bytes are not addressable",
              !sha256(crossingTheBridge).equals(sha256(raw)));

        // The other order, demonstrated rather than left as a claim: this is
        // what the store holds if the send path hashes what it was given and
        // redacts afterwards.
        Map<String, byte[]> hashedFirst = new HashMap<>();
        hashedFirst.put(sha256(raw), raw);
        check("hashing first leaves the credential recoverable from the store",
              text(hashedFirst.get(sha256(raw))).contains(TOKEN));
    }

    // ---- job 4: a request hx OBSERVED, not one it composed -----------------
    //
    // Every method below drives redactObservedRequest, which is the ONLY
    // mechanism between an operator's live session cookie and a
    // content-addressed blob store. Deleting the header-name match from that
    // method has to redden here or the finding it was written for is back.

    static final String COOKIE_SECRET = "3f9a1c77e5b24d0e8a1b6c4d2f7e9013";
    static final String BEARER_SECRET = "eyJhbGciOiJIUzI1NiJ9.b3BlcmF0b3I.7d1a";

    /** What the operator's browser sends through the proxy: a credential this
     *  extension did not compose, cannot refuse, and must not store. */
    static byte[] browsedRequest(String cookieValue) {
        return bytes("GET /account/settings HTTP/1.1\r\n"
                   + "Host: app.example.test\r\n"
                   + "User-Agent: Mozilla/5.0\r\n"
                   + "Cookie: JSESSIONID=" + cookieValue + "; theme=dark\r\n"
                   + "Accept: text/html\r\n"
                   + "\r\n");
    }

    static void anObservedCookieIsReplacedAndItsNameKept() {
        Redactor r = new Redactor();
        byte[] raw = browsedRequest(COOKIE_SECRET);
        byte[] wire = raw.clone();
        String out = text(r.redactObservedRequest(raw));
        // THE CHECK WHOSE ABSENCE WAS THE WHOLE FINDING. With redactRequest
        // and an empty Injected -- the shipped state for one commit -- this
        // line is the operator's live session cookie, verbatim, on its way
        // into a content-addressed store.
        check("the live session cookie is GONE (" + out.replace("\r\n", " | ") + ")",
              !out.contains(COOKIE_SECRET));
        check("the header name and colon survive, so the evidence still shows "
              + "a credential was sent",
              out.contains("Cookie: {{observed:cookie}}\r\n"));
        // THE WHOLE VALUE, not a parsed part of it. `theme=dark` is inside the
        // Cookie header and goes with it: a per-pair rule here would have to
        // decide which cookie names are secrets, and the browser's own
        // `JSESSIONID=` tells a check nothing the response's Set-Cookie did
        // not already say.
        check("and the whole value went, not just the pair that looked secret",
              !out.contains("theme=dark"));
        check("every other header is verbatim",
              out.contains("GET /account/settings HTTP/1.1\r\n")
              && out.contains("Host: app.example.test\r\n")
              && out.contains("User-Agent: Mozilla/5.0\r\n")
              && out.contains("Accept: text/html\r\n"));
        check("and the argument is not modified", Arrays.equals(raw, wire));
    }

    static void anObservedAuthorizationIsReplaced() {
        Redactor r = new Redactor();
        byte[] raw = bytes("GET /api/me HTTP/1.1\r\n"
                         + "Host: app.example.test\r\n"
                         + "Authorization: Bearer " + BEARER_SECRET + "\r\n"
                         + "\r\n");
        String out = text(r.redactObservedRequest(raw));
        check("the bearer token is gone", !out.contains(BEARER_SECRET));
        check("...and so is the scheme that carried it, because the whole "
              + "value is the secret",
              out.contains("Authorization: {{observed:authorization}}\r\n"));
    }

    static void anObservedProxyAuthorizationIsReplaced() {
        // The third of §6's three names, and the one a reader is likeliest to
        // assume is covered because the other two are.
        Redactor r = new Redactor();
        byte[] raw = bytes("GET /x HTTP/1.1\r\n"
                         + "Host: app.example.test\r\n"
                         + "Proxy-Authorization: Basic b3A6cDRzc3cwcmQ=\r\n"
                         + "\r\n");
        String out = text(r.redactObservedRequest(raw));
        check("the proxy credential is gone", !out.contains("b3A6cDRzc3cwcmQ="));
        check("and its name is kept",
              out.contains("Proxy-Authorization: {{observed:proxy-authorization}}\r\n"));
    }

    static void twoBrowsesDifferingOnlyInTheCredentialProduceOneBlob() throws Exception {
        // THE DETERMINISM CONSTRAINT, and it is not a style point. The plan's
        // Global Constraints require redaction to be deterministic -- "two
        // requests differing only in credential bytes must produce the same
        // blob" -- and the store is CONTENT-ADDRESSED, so a hash, a length or
        // any other function of the secret would give one page browsed under
        // two sessions two digests and two stored copies. Before job 4 existed
        // the proxy path broke this as well as leaking, because the raw
        // credential bytes WERE the difference between the two blobs.
        Redactor r = new Redactor();
        byte[] a = r.redactObservedRequest(browsedRequest(COOKIE_SECRET));
        byte[] b = r.redactObservedRequest(
                browsedRequest("00000000000000000000000000000000"));
        check("two sessions, one blob (" + text(a).replace("\r\n", " | ") + ")",
              Arrays.equals(a, b));
        check("...and therefore one digest", sha256(a).equals(sha256(b)));
        // And the control: the raw bytes really did differ, so the equality
        // above is the redaction's doing and not the fixture's.
        check("the inputs genuinely differed",
              !Arrays.equals(browsedRequest(COOKIE_SECRET),
                             browsedRequest("00000000000000000000000000000000")));
    }

    static void anObservedCredentialNameIsMatchedWhateverItsCase() {
        // A browser may send any case it likes; HTTP field names are
        // case-insensitive. A match that folded only one way would store the
        // credential of every client that spells it differently.
        Redactor r = new Redactor();
        String out = text(r.redactObservedRequest(
                bytes("GET /x HTTP/1.1\r\n"
                    + "COOKIE: sid=" + COOKIE_SECRET + "\r\n"
                    + "authorization: Bearer " + BEARER_SECRET + "\r\n"
                    + "\r\n")));
        check("an upper-case Cookie is matched", !out.contains(COOKIE_SECRET));
        check("a lower-case Authorization is matched", !out.contains(BEARER_SECRET));
        check("and the names are echoed as the client wrote them",
              out.contains("COOKIE: {{observed:cookie}}\r\n")
              && out.contains("authorization: {{observed:authorization}}\r\n"));
    }

    static void aCookieInTheRequestBodyIsNeverRewritten() {
        // Only the head is scanned, for job 3's reason exactly: a body may
        // legitimately carry the text. A form that posts a captured request,
        // a bug report, an API doc -- rewriting those corrupts the evidence a
        // check reads, and the body is not where a live credential is sent.
        Redactor r = new Redactor();
        String body = "report=Cookie: JSESSIONID=abc123; and it did not work";
        String out = text(r.redactObservedRequest(
                bytes("POST /support HTTP/1.1\r\n"
                    + "Host: app.example.test\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\n"
                    + "\r\n"
                    + body)));
        check("the body is byte-identical (" + out.substring(out.indexOf("\r\n\r\n") + 4) + ")",
              out.endsWith(body));
        check("and no placeholder was written into it",
              !out.substring(out.indexOf("\r\n\r\n")).contains("{{observed:"));
    }

    static void aRequestWithNoCredentialRoundTripsVerbatimAndNeverAliases() {
        Redactor r = new Redactor();
        byte[] raw = bytes("GET /public/index.html HTTP/1.1\r\n"
                         + "Host: app.example.test\r\n"
                         + "Accept: text/html\r\n"
                         + "\r\n");
        byte[] out = r.redactObservedRequest(raw);
        check("a request with nothing to redact comes back byte-identical",
              Arrays.equals(raw, out));
        // The same rule redactRequest's `raw.clone()` comment insists on: the
        // returned array must never alias the array that goes on the wire, or
        // a later in-place fix-up to one silently edits the other.
        check("...and is a DIFFERENT array, not the one that goes on the wire",
              raw != out);
    }

    static void aFoldedContinuationOfAnObservedCredentialIsRedacted() {
        // obs-fold. RFC 9110 says a recipient must reject it and no real
        // client emits it -- but if one does, the folded remainder of a
        // credential is credential bytes. Same trade as job 3's fold branch:
        // lose the continuation rather than store it.
        Redactor r = new Redactor();
        String out = text(r.redactObservedRequest(
                bytes("GET /x HTTP/1.1\r\n"
                    + "Cookie: JSESSIONID=" + COOKIE_SECRET + "\r\n"
                    + "\tcontinued=" + BEARER_SECRET + "\r\n"
                    + "Accept: text/html\r\n"
                    + "\r\n")));
        check("the first line's value is gone", !out.contains(COOKIE_SECRET));
        check("and so is the folded continuation", !out.contains(BEARER_SECRET));
        check("the fold's leading whitespace is kept, so the message still "
              + "parses the way it arrived",
              out.contains("\r\n\t{{observed:cookie}}\r\n"));
        check("and the header after the fold is untouched",
              out.contains("Accept: text/html\r\n"));
    }

    static void whitespaceBeforeTheColonDoesNotHideAnObservedCredential() {
        // RFC 9110 requires a recipient to reject `Cookie : v`, but name
        // matching is all job 4 has, and a name we fail to match passes a live
        // credential through verbatim. The same trim job 3 does.
        Redactor r = new Redactor();
        String out = text(r.redactObservedRequest(
                bytes("GET /x HTTP/1.1\r\n"
                    + "Cookie : JSESSIONID=" + COOKIE_SECRET + "\r\n"
                    + "\r\n")));
        check("the credential is still gone (" + out.replace("\r\n", " | ") + ")",
              !out.contains(COOKIE_SECRET));
    }

    static void aBlankLineBeforeTheRequestLineDoesNotEndTheHead() {
        // RFC 9112 2.2: a recipient MAY ignore an empty line before the
        // request line, so one can reach us. Stopping there would end the head
        // before a single field was read and copy the WHOLE request through as
        // "body" -- every credential raw. Same guard, same reason, as job 3's.
        Redactor r = new Redactor();
        String out = text(r.redactObservedRequest(
                bytes("\r\n"
                    + "GET /x HTTP/1.1\r\n"
                    + "Cookie: JSESSIONID=" + COOKIE_SECRET + "\r\n"
                    + "\r\n")));
        check("the leading blank line did not end the head",
              !out.contains(COOKIE_SECRET));
        check("and it is still there, verbatim", out.startsWith("\r\nGET /x"));
    }

    static void anAbsoluteFormRequestLineIsNotMatchedAsAField() {
        // No line is privileged here -- every head line is matched as a field
        // -- so the one line that is NOT a field has to survive that match. An
        // absolute-form target carries a colon, which is the only way a
        // request line can look like `name: value` at all.
        Redactor r = new Redactor();
        String line = "GET http://app.example.test:8080/x HTTP/1.1\r\n";
        String out = text(r.redactObservedRequest(
                bytes(line + "Cookie: JSESSIONID=" + COOKIE_SECRET + "\r\n\r\n")));
        check("the request line is verbatim (" + out.replace("\r\n", " | ") + ")",
              out.startsWith(line));
        check("and the credential after it is still redacted",
              !out.contains(COOKIE_SECRET));
    }

    static void redactObservedRequestRefusesNullBytes() {
        Redactor r = new Redactor();
        // A RangeError, not the NPE it would otherwise be, for the reason the
        // other two entry points give: an NPE out of here reaches a Burp proxy
        // thread and the send path's catch-all alike.
        expectThrows("null bytes are a RangeError", Redactor.RangeError.class,
                     () -> r.redactObservedRequest(null));
    }

    static void theEmptyInjectedPathIsWhyJobFourExists() {
        // THE FINDING, kept as a test so it cannot come back quietly. This is
        // not a complaint about redactRequest -- an empty Injected returning
        // the bytes unchanged is CORRECT for the send path, where job 2
        // refuses any credential job 1 did not inject. It is only wrong as the
        // whole of a path's redaction, and this pins the difference so that
        // routing the proxy path back through redactRequest is visibly a leak
        // rather than a plausible simplification.
        Redactor r = new Redactor();
        byte[] raw = browsedRequest(COOKIE_SECRET);
        String viaInjected = text(r.redactRequest(raw, new Redactor.Injected(raw)));
        check("redactRequest with an empty Injected returns the credential "
              + "VERBATIM -- it is not a redaction of observed traffic",
              viaInjected.contains(COOKIE_SECRET));
        check("...while job 4 removes it",
              !text(r.redactObservedRequest(raw)).contains(COOKIE_SECRET));
    }

    // ---- helpers ---------------------------------------------------------

    static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static String text(byte[] b)  { return new String(b, StandardCharsets.UTF_8); }

    /** Char offset == byte offset only because every fixture above is ASCII;
     *  a non-ASCII fixture would need a byte search instead. */
    static int find(byte[] hay, String needle) {
        int i = text(hay).indexOf(needle);
        if (i < 0) throw new IllegalArgumentException("test data has no " + needle);
        return i;
    }

    static String sha256(byte[] b) throws Exception {
        StringBuilder s = new StringBuilder();
        for (byte x : MessageDigest.getInstance("SHA-256").digest(b))
            s.append(String.format("%02x", x));
        return s.toString();
    }
}
