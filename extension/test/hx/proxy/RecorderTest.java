// extension/test/hx/proxy/RecorderTest.java
package hx.proxy;

import hx.TestSupport;
import hx.send.Redactor;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The pairing of each redactor to its own message, DRIVEN.
 *
 * This class exists because the same defect was found three times in the four
 * lines it replaces, and each time the structural check written for the
 * previous one could not see it:
 *
 *   1. the request half redacted with `redactRequest` and an empty
 *      `Injected`, which returns the bytes verbatim;
 *   2. both redaction calls left in place and the RAW locals queued;
 *   3. the two redactors SWAPPED -- each function correct, each pointed at
 *      the wrong message, both halves leaking.
 *
 * Every one of those checks read the TEXT of `HxExtension`, which needs Burp
 * to construct a single argument and so cannot be executed here at all. THE
 * WHOLE POINT OF THIS CLASS IS THAT IT EXECUTES. A helper that discards its
 * argument, a function pointed at the wrong message, an identity function --
 * none of them can pass the checks below, because the checks look at BYTES
 * rather than at names.
 *
 * The real {@link Redactor} is used, not a fake. A fake would move the
 * question -- "is the right function applied to the right message" -- into the
 * fake, which is exactly the class of thing that has been wrong three times.
 *
 * Hand-rolled runner, like the other twelve classes: JUnit would be a
 * dependency, and this jar has none.
 */
public class RecorderTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** The shared per-method guard: a throw becomes a NAMED FAIL against this
     *  class's counter instead of ending main() with the rest unrun and no
     *  summary line printed. See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(RecorderTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("each half is redacted by the redactor that belongs to it",
          RecorderTest::eachHalfIsRedactedByItsOwnRedactor);
        t("the header names survive on both halves",
          RecorderTest::theHeaderNamesSurviveOnBothHalves);
        t("everything that is not a credential is byte-identical",
          RecorderTest::everythingElseIsUnchanged);
        t("the record carries the fields it was given",
          RecorderTest::theRecordCarriesTheFieldsItWasGiven);
        t("neither raw array is modified, and neither is aliased",
          RecorderTest::neitherRawArrayIsTouchedOrAliased);
        t("a record with no credential on either half round-trips",
          RecorderTest::nothingToRedactRoundTrips);
        t("a RangeError is not swallowed into an unredacted record",
          RecorderTest::aRangeErrorIsNotSwallowed);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures -------------------------------------------------------

    // THREE DISTINCT SECRETS, one per credential, so a check can say WHICH
    // half leaked rather than only that something did. Under the swap
    // mutation all three survive and all three assertions fire.
    static final String REQ_COOKIE = "d41d8cd98f00b204e9800998ecf8427e";
    static final String REQ_BEARER = "eyJhbGciOiJIUzI1NiJ9.b3BlcmF0b3I.7d1a";
    static final String RESP_COOKIE = "9e107d9d372bb6826bd81d3542a419d6";

    static byte[] rawRequest() {
        return bytes("GET /account/settings HTTP/1.1\r\n"
                   + "Host: app.example.test\r\n"
                   + "Cookie: JSESSIONID=" + REQ_COOKIE + "\r\n"
                   + "Authorization: Bearer " + REQ_BEARER + "\r\n"
                   + "Accept: text/html\r\n"
                   + "\r\n");
    }

    static byte[] rawResponse() {
        return bytes("HTTP/1.1 200 OK\r\n"
                   + "Content-Type: text/html; charset=utf-8\r\n"
                   + "Set-Cookie: JSESSIONID=" + RESP_COOKIE + "; Path=/; HttpOnly\r\n"
                   + "Content-Length: 13\r\n"
                   + "\r\n"
                   + "<html></html>");
    }

    static Observed record() {
        return new Recorder(new Redactor())
                .record("GET", "http://app.example.test/account/settings",
                        200, 42L, rawRequest(), rawResponse(), Source.OPERATOR);
    }

    static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static String text(byte[] b)  { return new String(b, StandardCharsets.UTF_8); }

    // ---- the tests ------------------------------------------------------

    static void eachHalfIsRedactedByItsOwnRedactor() {
        // THE CHECK THAT CLOSES ALL THREE TURNS OF THIS SCREW. Swap the two
        // calls inside Recorder and every one of these fires: redactResponse
        // matches only Set-Cookie, so a REQUEST handed to it comes back
        // verbatim, and redactObservedRequest matches only the three request
        // names, so a RESPONSE handed to it does too. Both functions stay
        // correct under that mutation. Only their bytes can tell.
        Observed o = record();
        String req = text(o.request());
        String resp = text(o.response());
        check("the request's session cookie is gone (" + firstLineWith(req, "Cookie") + ")",
              !req.contains(REQ_COOKIE));
        check("the request's bearer token is gone ("
              + firstLineWith(req, "Authorization") + ")",
              !req.contains(REQ_BEARER));
        check("the response's Set-Cookie value is gone ("
              + firstLineWith(resp, "Set-Cookie") + ")",
              !resp.contains(RESP_COOKIE));
        // And the placeholders prove the RIGHT function ran, not merely that
        // the secret is absent: `{{observed:cookie}}` is job 4's spelling and
        // `{{observed:set-cookie}}` is job 3's. A request that came back
        // carrying the response's placeholder would mean the functions were
        // swapped AND the fixture happened not to leak.
        check("and the request half carries the request placeholder",
              req.contains("{{observed:cookie}}")
              && req.contains("{{observed:authorization}}"));
        check("and the response half carries the response placeholder",
              resp.contains("{{observed:set-cookie}}"));
    }

    static void theHeaderNamesSurviveOnBothHalves() {
        // The evidence still has to show that a credential was PRESENT and
        // which kind -- that is what an auth-boundary check reads. Only the
        // bytes that would still authenticate are gone.
        Observed o = record();
        String req = text(o.request());
        String resp = text(o.response());
        check("Cookie: survives on the request",
              req.contains("Cookie: {{observed:cookie}}\r\n"));
        check("Authorization: survives on the request",
              req.contains("Authorization: {{observed:authorization}}\r\n"));
        check("Set-Cookie: survives on the response, attributes and all",
              resp.contains("Set-Cookie: JSESSIONID={{observed:set-cookie}}; "
                            + "Path=/; HttpOnly\r\n"));
    }

    static void everythingElseIsUnchanged() {
        Observed o = record();
        String req = text(o.request());
        String resp = text(o.response());
        check("the request line and its other headers are verbatim",
              req.startsWith("GET /account/settings HTTP/1.1\r\n")
              && req.contains("Host: app.example.test\r\n")
              && req.contains("Accept: text/html\r\n"));
        check("the status line and the other response headers are verbatim",
              resp.startsWith("HTTP/1.1 200 OK\r\n")
              && resp.contains("Content-Type: text/html; charset=utf-8\r\n")
              && resp.contains("Content-Length: 13\r\n"));
        check("and the response body is untouched", resp.endsWith("<html></html>"));
    }

    static void theRecordCarriesTheFieldsItWasGiven() {
        // The other five fields go through unexamined, and a Recorder that
        // shuffled them would put one exchange's status on another's row.
        Observed o = record();
        check("method (" + o.method() + ")", "GET".equals(o.method()));
        check("url (" + o.url() + ")",
              "http://app.example.test/account/settings".equals(o.url()));
        check("status (" + o.status() + ")", o.status() == 200);
        check("ms (" + o.ms() + ")", o.ms() == 42L);
        check("source (" + o.source() + ")", o.source() == Source.OPERATOR);
    }

    static void neitherRawArrayIsTouchedOrAliased() {
        // The bytes Burp is about to put on the wire must be verbatim: only
        // the copy crossing the bridge carries placeholders. An in-place edit
        // would corrupt the very exchange the record is evidence of.
        byte[] req = rawRequest(), resp = rawResponse();
        byte[] reqBefore = req.clone(), respBefore = resp.clone();
        Observed o = new Recorder(new Redactor())
                .record("GET", "http://app.example.test/x", 200, 1L,
                        req, resp, Source.CRAWLER);
        check("the raw request is unmodified", Arrays.equals(req, reqBefore));
        check("the raw response is unmodified", Arrays.equals(resp, respBefore));
        check("and the record aliases neither",
              o.request() != req && o.response() != resp);
    }

    static void nothingToRedactRoundTrips() {
        // A Recorder that rewrote a message with no credential in it would be
        // corrupting evidence, and the two entry points differ here: one
        // returns a copy of an untouched message, the other has a head to
        // walk. Both must come back byte-identical.
        byte[] req = bytes("GET /public/x HTTP/1.1\r\nHost: app.test\r\n\r\n");
        byte[] resp = bytes("HTTP/1.1 204 No Content\r\nServer: nginx\r\n\r\n");
        Observed o = new Recorder(new Redactor())
                .record("GET", "http://app.test/public/x", 204, 3L,
                        req, resp, Source.OPERATOR);
        check("the request came back byte-identical", Arrays.equals(req, o.request()));
        check("and the response too", Arrays.equals(resp, o.response()));
    }

    static void aRangeErrorIsNotSwallowed() {
        // Recorder has no counter, so it must not invent a fallback: a
        // fallback here is an UNREDACTED record. The caller counts the loss.
        boolean threw = false;
        try {
            new Recorder(new Redactor())
                    .record("GET", "http://app.test/x", 200, 1L,
                            null, rawResponse(), Source.OPERATOR);
        } catch (Redactor.RangeError expected) {
            threw = true;
        }
        check("a null half is a RangeError out of record(), not a record",
              threw);
    }

    /** The first line naming `needle`, for a check's own message: a FAIL that
     *  prints the leaked line is worth more than one that prints `false`. */
    static String firstLineWith(String message, String needle) {
        for (String line : message.split("\r\n"))
            if (line.startsWith(needle)) return line;
        return "<no " + needle + " line>";
    }
}
