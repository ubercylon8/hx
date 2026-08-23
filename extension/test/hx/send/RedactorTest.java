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
        t("theRangesTravelWithTheRequestNotTheThread", RedactorTest::theRangesTravelWithTheRequestNotTheThread);

        t("anUnmanagedAuthorizationIsNamed", RedactorTest::anUnmanagedAuthorizationIsNamed);
        t("credentialHeaderMatchingIsCaseInsensitive", RedactorTest::credentialHeaderMatchingIsCaseInsensitive);
        t("credentialDetectionSurvivesATurkishLocale", RedactorTest::credentialDetectionSurvivesATurkishLocale);
        t("theNamedHeaderDoesNotDependOnMapOrder", RedactorTest::theNamedHeaderDoesNotDependOnMapOrder);
        t("aWholeNameMustMatchNotAPrefix", RedactorTest::aWholeNameMustMatchNotAPrefix);
        t("aRequestWithoutACredentialHeaderIsNull", RedactorTest::aRequestWithoutACredentialHeaderIsNull);

        t("setCookieValuesAreReplacedAndAttributesKept", RedactorTest::setCookieValuesAreReplacedAndAttributesKept);
        t("everySetCookieHeaderIsRedacted", RedactorTest::everySetCookieHeaderIsRedacted);
        t("setCookieMatchingIsCaseInsensitive", RedactorTest::setCookieMatchingIsCaseInsensitive);
        t("aDeletionCookieKeepsItsEmptyValue", RedactorTest::aDeletionCookieKeepsItsEmptyValue);
        t("aCookiePairWithNoEqualsIsRedactedWhole", RedactorTest::aCookiePairWithNoEqualsIsRedactedWhole);
        t("aFoldedContinuationOfASetCookieIsRedacted", RedactorTest::aFoldedContinuationOfASetCookieIsRedacted);
        t("theResponseBodyIsNeverRewritten", RedactorTest::theResponseBodyIsNeverRewritten);

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
        byte[] out = r.redactRequest(raw, new Redactor.Injected());
        check("an empty registry returns the same bytes", Arrays.equals(out, raw));
        check("an empty registry still returns a copy, not the wire array", out != raw);
    }

    static void aRegisteredRangeBecomesTheIdentityPlaceholder() {
        Redactor r = new Redactor();
        byte[] raw = authRequest();
        Redactor.Injected injected = new Redactor.Injected();
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
        Redactor.Injected injected = new Redactor.Injected();
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
        Redactor.Injected injected = new Redactor.Injected();
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
        Redactor.Injected injected = new Redactor.Injected();
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
        Redactor.Injected injected = new Redactor.Injected();
        injected.register("ident-admin", raw.length - 4, raw.length + 40);
        expectThrows("a range running past the end of the request is refused",
                     Redactor.RangeError.class, () -> r.redactRequest(raw, injected));
    }

    static void degenerateRangesAreRefused() {
        Redactor.Injected injected = new Redactor.Injected();
        expectThrows("a negative start is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-admin", -1, 5));
        expectThrows("an empty range is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-admin", 7, 7));
        expectThrows("a reversed range is refused",
                     Redactor.RangeError.class, () -> injected.register("ident-admin", 9, 4));
        expectThrows("a range with no identity is refused",
                     Redactor.RangeError.class, () -> injected.register("", 0, 5));
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
        Redactor.Injected forFirst = new Redactor.Injected();
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
              Arrays.equals(r.redactRequest(next, new Redactor.Injected()), next));
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
        Redactor.Injected injected = new Redactor.Injected();
        injected.register("ident-admin", tokenStart(raw), tokenEnd(raw));
        String[] fromWorker = new String[1];
        Thread worker = new Thread(() -> fromWorker[0] = text(r.redactRequest(raw, injected)));
        worker.start();
        worker.join();
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
        Redactor.Injected injected = new Redactor.Injected();
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
