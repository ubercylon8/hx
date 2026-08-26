// extension/test/hx/proxy/RecorderTest.java
package hx.proxy;

import hx.TestSupport;
import hx.send.Redactor;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
 * AND THE FOURTH TURN WAS A CONDITION, not a wiring mistake at all: with one
 * fixture per half, `rawResponse.length > 4096 ? rawResponse : redact(...)`
 * read 13 summary lines / 1900 ok / 0 FAIL / rc=0 and leaked every real
 * response. {@link #everyShapeOfMessageIsRedacted} answers that with six
 * shapes varying size, body presence, framing and encoding -- AND ITS JAVADOC
 * STATES WHAT NO FIXTURE SET CAN DO. A predicate over a property none of these
 * vary still passes. This class is not a proof that no bypass exists; it is a
 * set of inputs that makes the plausible ones fire. That is item 1 of the
 * canonical open list in {@link Recorder}'s javadoc, which is the one place
 * this path's residuals are enumerated.
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
        t("a RangeError is not swallowed into an unredacted record, on EITHER half",
          RecorderTest::aRangeErrorIsNotSwallowed);
        t("every shape of message is redacted, not just the small one",
          RecorderTest::everyShapeOfMessageIsRedacted);
        t("the COMPILER is what bounds construction, not a needle",
          RecorderTest::theCompilerBoundsConstruction);

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

    /** The cast is the point, not a wart: `record` is declared {@link Captured}
     *  because {@link Observed} is package-private and the entry point may not
     *  name it. This class SITS in that package, so it can look inside -- which
     *  is exactly the asymmetry that lets the compiler bound construction while
     *  a test still reads the bytes. */
    static Observed record() {
        return (Observed) new Recorder(new Redactor())
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
        Observed o = (Observed) new Recorder(new Redactor())
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
        Observed o = (Observed) new Recorder(new Redactor())
                .record("GET", "http://app.test/public/x", 204, 3L,
                        req, resp, Source.OPERATOR);
        check("the request came back byte-identical", Arrays.equals(req, o.request()));
        check("and the response too", Arrays.equals(resp, o.response()));
    }

    static void aRangeErrorIsNotSwallowed() {
        // Recorder has no counter, so it must not invent a fallback: a
        // fallback here is an UNREDACTED record. The caller counts the loss.
        //
        // BOTH HALVES, and the second case is the one that was missing. This
        // method drove the REQUEST half only, so `redactObservedRequest` threw
        // before `redactResponse` was ever reached -- and adding exactly the
        // fallback Recorder's javadoc forswears, on the response half,
        // measured 13 summary lines / 1900 ok / 0 FAIL / rc=0. A swallowed
        // RangeError there is a silent S7 leak: the head could not be walked,
        // so the Set-Cookie goes to the content-addressed store verbatim.
        check("a null REQUEST half is a RangeError out of record(), not a record",
              throwsRangeError(null, rawResponse()));
        check("and a null RESPONSE half is too, which is the half a fallback "
              + "would silently keep raw",
              throwsRangeError(rawRequest(), null));
    }

    static boolean throwsRangeError(byte[] req, byte[] resp) {
        try {
            new Recorder(new Redactor())
                    .record("GET", "http://app.test/x", 200, 1L,
                            req, resp, Source.OPERATOR);
            return false;
        } catch (Redactor.RangeError expected) {
            return true;
        }
    }

    /**
     * ONE FIXTURE PINS BEHAVIOUR ON ONE INPUT, and that is where the hole went
     * next. Measured, with everything else in this class green:
     *
     *     byte[] response = rawResponse.length > 4096
     *             ? rawResponse
     *             : redactor.redactResponse(rawResponse);
     *
     *     13 summary lines / 1900 ok / 0 FAIL / rc=0
     *
     * Every real HTML or JSON response -- i.e. essentially all of them -- then
     * goes into the content-addressed store with its `Set-Cookie` intact,
     * while the ~150-byte fixture above never fires the predicate. Nothing
     * structural sees it either: the call is present, its result is used, and
     * the right function meets the right message.
     *
     * The progression this task has walked is ORDER, then DATAFLOW, then
     * APPLICATION, now CONDITION -- and condition is the one example-based
     * testing is structurally weak against. So the fixtures vary in the
     * dimensions a plausible predicate would branch on: SIZE (one body well
     * over any threshold anyone would type), PRESENCE of a body at all, a
     * CHUNKED framing, a HEAD-style response with no body, and a BINARY body
     * whose bytes are not valid ASCII.
     *
     * WHAT THIS DOES NOT CLOSE, and it cannot be closed by adding fixtures: a
     * predicate over a property NONE of these vary -- a header count, a
     * content-type test, a `startsWith`, the day of the week -- still passes.
     * There is no fixture set that makes a conditional bypass impossible; what
     * there is, is a fixture set that makes the plausible ones fire. Do not
     * read this method as "no bypass is possible".
     */
    static void everyShapeOfMessageIsRedacted() {
        // 64 KB, comfortably past any threshold a bypass would be written with
        // -- 4096 and 8192 are the numbers people reach for.
        byte[] big = filler(64 * 1024);
        byte[] binary = new byte[512];
        for (int i = 0; i < binary.length; i++) binary[i] = (byte) i;   // 0x00-0xFF, not UTF-8

        List<Object[]> shapes = new ArrayList<>();
        shapes.add(new Object[]{"a small body both ways",
                message(requestHead("POST", "13"), bytes("name=value&x=1")),
                message(responseHead("200 OK", "Content-Length: 13\r\n"),
                        bytes("<html></html>"))});
        shapes.add(new Object[]{"a 64 KB body both ways",
                message(requestHead("POST", String.valueOf(big.length)), big),
                message(responseHead("200 OK", "Content-Length: " + big.length + "\r\n"), big)});
        shapes.add(new Object[]{"no body on either side",
                message(requestHead("GET", null), new byte[0]),
                message(responseHead("204 No Content", ""), new byte[0])});
        shapes.add(new Object[]{"a HEAD-style response, headers promising a body that is absent",
                message(requestHead("HEAD", null), new byte[0]),
                message(responseHead("200 OK", "Content-Length: 4096\r\n"), new byte[0])});
        shapes.add(new Object[]{"chunked framing on both halves",
                message(requestHead("POST", null) , bytes("5\r\nhello\r\n0\r\n\r\n")),
                message(responseHead("200 OK", "Transfer-Encoding: chunked\r\n"),
                        bytes("4\r\nbody\r\n0\r\n\r\n"))});
        shapes.add(new Object[]{"a binary body that is not valid ASCII",
                message(requestHead("POST", String.valueOf(binary.length)), binary),
                message(responseHead("200 OK", "Content-Type: application/octet-stream\r\n"),
                        binary)});

        // EVERY SOURCE, not just the operator's. `source == Source.CRAWLER
        // ? raw.clone() : redact(...)` inside `record` was measured at 13
        // summary lines / 2067 ok / 0 FAIL / rc=0 -- every crawler exchange
        // stored with Cookie, Authorization and Set-Cookie intact. It was NOT
        // an instance of "a predicate over a property no fixture varies":
        // `Source` is varied two methods down, in
        // neitherRawArrayIsTouchedOrAliased -- just never inside the redaction
        // assertions, which is the only place varying it would have caught
        // anything. Filing a closable finding under an unclosable residual is
        // what made the open list dishonest, twice.
        for (Source source : Source.values())
        for (Object[] shape : shapes) {
            String name = shape[0] + " / " + source;
            byte[] req = (byte[]) shape[1], resp = (byte[]) shape[2];
            Observed o = (Observed) new Recorder(new Redactor())
                    .record("POST", "http://app.example.test/x", 200, 7L,
                            req, resp, source);
            // Searched over BYTES, not over a String: a binary body is not
            // valid UTF-8, and decoding it would replace the very bytes a
            // leak might hide in.
            check(name + ": the request's cookie is gone",
                  !holds(o.request(), REQ_COOKIE));
            check(name + ": the request's bearer token is gone",
                  !holds(o.request(), REQ_BEARER));
            check(name + ": the response's Set-Cookie value is gone",
                  !holds(o.response(), RESP_COOKIE));
            check(name + ": and the redaction really ran, both halves",
                  holds(o.request(), "{{observed:cookie}}")
                  && holds(o.response(), "{{observed:set-cookie}}"));
            // ...and the evidence survives. A "redactor" that emptied the
            // message would pass every check above.
            check(name + ": the body is byte-identical",
                  Arrays.equals(body(req), body(o.request()))
                  && Arrays.equals(body(resp), body(o.response())));
        }
    }

    /**
     * The bound that a needle could not give: {@link Observed} and
     * {@link Denied} are PACKAGE-PRIVATE, so no code outside {@code hx.proxy}
     * can name either type by ANY spelling -- `new Observed(`,
     * `new hx.proxy.Observed(`, `Observed::new`, a factory, a lambda.
     *
     * READ OFF THE COMPILED CLASS, deliberately. Three text needles in
     * ChokepointTest were each defeated by a spelling they did not anticipate;
     * this reads the modifiers `javac` actually emitted and cannot be fooled by
     * how a construction is written. Restoring `public` to either record is
     * the separating mutation, and the bound was confirmed independently by
     * compiling a probe class in package `hx` that names each record: `javac`
     * answers "Observed is not public in hx.proxy; cannot be accessed from
     * outside package". A language rule, not a test that can rot.
     *
     * THIS BOUNDS OTHER PACKAGES AND NOT THIS ONE. Inside `hx.proxy` the bound
     * is `ChokepointTest`'s per-file count, which since round 4 counts BOTH
     * spellings a constructor has -- so the within-package half is closed too,
     * and it is no longer on {@link Recorder}'s open list.
     *
     * {@link Captured} STAYS PUBLIC, and that is load-bearing rather than
     * incidental: {@code Capture.offer(Captured)} is called from
     * {@code hx.HxExtension}, so the interface must be nameable there while
     * its two implementations are not. A public sealed interface permitting
     * package-private records is legal, and this asserts the arrangement
     * rather than assuming it.
     */
    static void theCompilerBoundsConstruction() {
        check("Observed is not public (" + Modifier.toString(
                      Observed.class.getModifiers()) + ")",
              !Modifier.isPublic(Observed.class.getModifiers()));
        check("Denied is not public (" + Modifier.toString(
                      Denied.class.getModifiers()) + ")",
              !Modifier.isPublic(Denied.class.getModifiers()));
        check("...while Captured IS public, so the entry point can still name "
              + "what it hands to Capture.offer",
              Modifier.isPublic(Captured.class.getModifiers()));
        check("and Captured is sealed, so a third kind of record is a compile "
              + "error rather than an arm nothing reaches",
              Captured.class.isSealed());
    }

    // ---- shape helpers ---------------------------------------------------

    static byte[] filler(int n) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) 'x');
        return b;
    }

    /** A request head carrying both credentials, plus an optional
     *  Content-Length. `method` and the length are what the shapes vary. */
    static String requestHead(String method, String contentLength) {
        return method + " /account/settings HTTP/1.1\r\n"
             + "Host: app.example.test\r\n"
             + "Cookie: JSESSIONID=" + REQ_COOKIE + "\r\n"
             + "Authorization: Bearer " + REQ_BEARER + "\r\n"
             + (contentLength == null ? "" : "Content-Length: " + contentLength + "\r\n");
    }

    /** A response head carrying the third credential. */
    static String responseHead(String status, String extra) {
        return "HTTP/1.1 " + status + "\r\n"
             + "Set-Cookie: JSESSIONID=" + RESP_COOKIE + "; Path=/; HttpOnly\r\n"
             + extra;
    }

    static byte[] message(String head, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(bytes(head + "\r\n"));
        out.writeBytes(body);
        return out.toByteArray();
    }

    /** Everything after the first blank line, as bytes. */
    static byte[] body(byte[] message) {
        for (int i = 0; i + 3 < message.length; i++)
            if (message[i] == '\r' && message[i + 1] == '\n'
                    && message[i + 2] == '\r' && message[i + 3] == '\n')
                return Arrays.copyOfRange(message, i + 4, message.length);
        return new byte[0];
    }

    /** Byte-wise substring search, so a binary body is searched as bytes
     *  rather than decoded into a String that would replace the bytes a leak
     *  could hide in. */
    static boolean holds(byte[] hay, String needle) {
        byte[] n = bytes(needle);
        outer:
        for (int i = 0; i + n.length <= hay.length; i++) {
            for (int k = 0; k < n.length; k++)
                if (hay[i + k] != n[k]) continue outer;
            return true;
        }
        return false;
    }

    /** The first line naming `needle`, for a check's own message: a FAIL that
     *  prints the leaked line is worth more than one that prints `false`. */
    static String firstLineWith(String message, String needle) {
        for (String line : message.split("\r\n"))
            if (line.startsWith(needle)) return line;
        return "<no " + needle + " line>";
    }
}
