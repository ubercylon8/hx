// extension/test/hx/send/SenderTest.java
package hx.send;

import hx.TestSupport;
import hx.bridge.BridgeClient;
import hx.bridge.Json;
import hx.policy.Decision;
import hx.policy.Distress;
import hx.policy.Gate;
import hx.policy.HxRequest;
import hx.policy.Policy;
import hx.policy.TickClock;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class SenderTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *
     *  Not decoration. Every sabotage count in this task was read off the FAIL
     *  lines of a full run, and a mutation that makes a method THROW rather
     *  than return the wrong value prints no FAIL lines at all: under
     *  `./test.sh | grep -c FAIL` a truncation and a green run are the same
     *  number. The other seven classes in this suite already run under it.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(SenderTest::check, name, body);
    }

    /** A fixed wall-clock instant in microseconds. Real value, not a round
     *  number: deadline arithmetic that only works on round numbers is a bug
     *  waiting for a Tuesday. */
    static final long NOW = 1_787_355_131_378_277L;
    static final long THIRTY_SECONDS = 30_000_000L;

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("hxsend");
        Path sentinel = dir.resolve("halt");          // deliberately absent
        try {
            t("anAllowedRequestIsIssuedOnceAndFramedAsAResult",
              () -> anAllowedRequestIsIssuedOnceAndFramedAsAResult(sentinel));
            t("everyDenialClassLeavesTheWireUntouched",
              () -> everyDenialClassLeavesTheWireUntouched(sentinel));
            t("theRefusalOrderIsPinned", () -> theRefusalOrderIsPinned(sentinel));
            t("rateLimitedCarriesRetryAfterUs", () -> rateLimitedCarriesRetryAfterUs(sentinel));
            t("anExpiredDeadlineIsRefusedWithoutIssuingOrSpendingBudget",
              () -> anExpiredDeadlineIsRefusedWithoutIssuingOrSpendingBudget(sentinel));
            t("aDeadlineThatExpiresMidFlightIsReportedAsTimeout",
              () -> aDeadlineThatExpiresMidFlightIsReportedAsTimeout(sentinel));
            t("aTransportFailureFeedsDistressAndHaltsTheNextSend",
              () -> aTransportFailureFeedsDistressAndHaltsTheNextSend(sentinel));
            t("distressPushesOneUnsolicitedHaltedFrame",
              () -> distressPushesOneUnsolicitedHaltedFrame(sentinel));
            t("aRedactionFailureIsRefusedRatherThanFramed",
              () -> aRedactionFailureIsRefusedRatherThanFramed(sentinel));
            t("anInterimHeadIsNotTheStatusAndDoesNotHideA5xx",
              () -> anInterimHeadIsNotTheStatusAndDoesNotHideA5xx(sentinel));
            t("twoSendsTrippingTogetherStillAnnounceOnce",
              () -> twoSendsTrippingTogetherStillAnnounceOnce(sentinel));
            t("theResultIsStampedWithTheEpochThatAuthorisedIt",
              () -> theResultIsStampedWithTheEpochThatAuthorisedIt(sentinel));
            t("theResponseBodyRidesUnderAKeyJsonRefusesToWrite",
              () -> theResponseBodyRidesUnderAKeyJsonRefusesToWrite(sentinel));
            t("theWireMappingRoundTripsWhatItParsed", SenderTest::theWireMappingRoundTripsWhatItParsed);
            t("theConfiguredLimitsArmTheGateOnceFromTheAuthorisation",
              SenderTest::theConfiguredLimitsArmTheGateOnceFromTheAuthorisation);
        } finally {
            Files.deleteIfExists(sentinel);
            Files.deleteIfExists(dir);
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- doubles -------------------------------------------------------

    // The clock is hx.policy.TickClock, the one Task 2 put in the test tree
    // for exactly this: every guard in this plan that owns time takes an
    // injected Clock so its boundaries can be hit AT the microsecond instead
    // of approached with a sleep, and one such clock for the whole suite means
    // one set of semantics for `advance`.

    /** The point of the whole task: it counts. */
    static final class FakeHttp implements Http {
        int calls = 0;
        HxRequest last;
        HttpReply reply = new HttpReply(200, RESPONSE, 12L, false);
        IOException boom = null;
        long advanceUsPerCall = 0;
        TickClock clock;
        /** Holds every caller here until as many have arrived as it was built
         *  for. The only way to have two sends genuinely IN FLIGHT at once,
         *  which is the one input that separates the announce-once flag from
         *  its absence -- see twoSendsTrippingTogetherStillAnnounceOnce. */
        CyclicBarrier bothInFlight = null;
        volatile String barrierError = null;

        public HttpReply send(HxRequest req, long deadlineUs) throws IOException {
            calls++;
            last = req;
            if (clock != null) clock.advance(advanceUsPerCall);
            if (bothInFlight != null) {
                // Recorded rather than thrown: a barrier that timed out means
                // the sends were NOT concurrent, and an IOException here is
                // indistinguishable from the transport failure the test wants.
                // A test that silently stopped testing its own premise is the
                // failure this field exists to make visible.
                try { bothInFlight.await(5, TimeUnit.SECONDS); }
                catch (Exception e) { barrierError = String.valueOf(e); }
            }
            if (boom != null) throw boom;
            return reply;
        }
    }

    /** Records the unsolicited `halted` frames Sender pushes. Auto-halt has no
     *  outstanding id to answer, so this is the only evidence that it told
     *  anyone -- and how many times it told them. */
    static final class RecordingNotifier implements BridgeClient.HaltNotifier {
        final List<String[]> frames = new ArrayList<>();
        // synchronized: twoSendsTrippingTogetherStillAnnounceOnce pushes from
        // two threads on purpose, and an unsynchronised ArrayList.add can lose
        // one -- which would report ONE frame from a Sender that sent two.
        public synchronized void halted(String reason, String host, String window) {
            frames.add(new String[] { reason, host, window });
        }
    }

    /** Counts too. A request refused before the Gate must cost no rate token
     *  and no budget slot -- the Limiter's check() has a side effect. */
    static final class CountingGate implements Gate {
        int calls = 0;
        Decision verdict = Decision.allow();
        public Decision check(HxRequest req) { calls++; return verdict; }
    }

    /** One Sender and every double it was built from. */
    static final class Rig {
        final TickClock clock = new TickClock(NOW);
        final CountingGate gate = new CountingGate();
        final FakeHttp http = new FakeHttp();
        final Redactor redactor = new Redactor();
        final RecordingNotifier notifier = new RecordingNotifier();
        final HaltSwitch halt;
        final Distress distress;
        final Sender sender;

        Rig(Path sentinel, int maxConsecutiveErrors) {
            http.clock = clock;
            // start() is deliberately NOT called: the sentinel poller is
            // HaltSwitch's own test's business, and a background thread in
            // here would make these assertions time-dependent.
            halt = new HaltSwitch(clock, sentinel, HaltSwitch.DEFAULT_POLL_MS);
            // The spec s4 production defaults: 20% 5xx, 5x baseline latency.
            distress = new Distress(clock, 0.20, 5.0, maxConsecutiveErrors);
            sender = new Sender(new Policy(gate), redactor, halt, distress, http, clock);
            sender.setHaltNotifier(notifier);
        }

        Rig(Path sentinel) { this(sentinel, 5); }
    }

    // ---- fixtures ------------------------------------------------------

    static final byte[] RESPONSE = ("HTTP/1.1 200 OK\r\n"
            + "Content-Type: application/json\r\n"
            + "Set-Cookie: session=9f1c4a2e7b; Path=/; HttpOnly; Secure\r\n"
            + "Content-Length: 15\r\n"
            + "\r\n"
            + "{\"orders\":[42]}").getBytes(StandardCharsets.ISO_8859_1);

    /**
     * What Burp actually hands back for an exchange with an interim head, byte
     * for byte in the shape MEASURED against Burp Suite Community Edition
     * 2026.7.3-52685: both heads in one array, the interim one first.
     *
     * The 5xx here is not decoration. It is the difference between a run that
     * auto-halts against a failing origin and one that records fifty 103s and
     * never stops.
     */
    static final byte[] INTERIM_THEN_500 = ("HTTP/1.1 103 Early Hints\r\n"
            + "Link: </style.css>; rel=preload; as=style\r\n"
            + "Set-Cookie: interim=EARLY_HINTS_COOKIE_9f1c; Path=/\r\n"
            + "\r\n"
            + "HTTP/1.1 500 Internal Server Error\r\n"
            + "Content-Type: application/json\r\n"
            + "Set-Cookie: session=FINAL_COOKIE_7b3d; Path=/; HttpOnly; Secure\r\n"
            + "Content-Length: 13\r\n"
            + "\r\n"
            + "{\"error\":42}\r\n").getBytes(StandardCharsets.ISO_8859_1);

    static Map<String, Object> sendHeader(long deadlineUs) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("v", 1L);
        h.put("t", "send");
        h.put("id", 41L);
        h.put("deadline_us", deadlineUs);
        h.put("engagement_id", "e-1");
        h.put("identity_id", null);
        h.put("target_host", "app.example.test");
        h.put("target_port", 443L);
        h.put("tls", true);
        return h;
    }

    static byte[] request(String method, String target, String... nameThenValue) {
        StringBuilder s = new StringBuilder();
        s.append(method).append(' ').append(target).append(" HTTP/1.1\r\n");
        s.append("Host: app.example.test\r\n");
        s.append("User-Agent: hx/0.1\r\n");
        for (int i = 0; i < nameThenValue.length; i += 2)
            s.append(nameThenValue[i]).append(": ").append(nameThenValue[i + 1]).append("\r\n");
        s.append("\r\n");
        return s.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    /** A request nobody would write by hand, byte for byte. `request(...)`
     *  above can only build well-formed ones, and a guard is only tested by
     *  the input that separates it from its absence. */
    static byte[] raw(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** A decided request, for the Gate cases that never go near a Sender.
     *  Limiter reads nothing off it -- a token is a token -- so the smallest
     *  well-formed value is the honest one to pass. */
    static final HxRequest REQ = new HxRequest("GET",
            "https://app.example.test/api/orders", "app.example.test",
            "/api/orders", "", Map.of(), new byte[0]);

    /** The scope an operator actually configured, at a real epoch. */
    static BridgeClient.Authorisation authorised() {
        Map<String, List<String>> scope = new LinkedHashMap<>();
        scope.put("scope.include", List.of("https://app.example.test/*"));
        scope.put("method.allow", List.of("GET", "HEAD", "OPTIONS"));
        scope.put("dangerous.path", List.of("*/logout*", "*/password*"));
        scope.put("limit.rate_rps", List.of("5"));
        return new BridgeClient.Authorisation(7L, Collections.unmodifiableMap(scope));
    }

    /** The DENY-ALL snapshot BridgeClient publishes before any configure and
     *  after every disconnect. Epoch 0 is what "not configured" IS. */
    static BridgeClient.Authorisation denyAll() {
        return new BridgeClient.Authorisation(0L, Map.of());
    }

    // ---- the assertion this task exists for ----------------------------

    static void denied(String label, Rig rig, Map<String, Object> header, byte[] body,
                       BridgeClient.Authorisation auth, String expectedClass) {
        Map<String, Object> reply = rig.sender.issue(header, body, auth);
        check(label + " -> t=error (got " + reply.get("t") + ")",
              "error".equals(reply.get("t")));
        check(label + " -> class=" + expectedClass + " (got " + reply.get("class") + ")",
              expectedClass.equals(reply.get("class")));
        // Not "an error was returned". Nothing was sent.
        check(label + " NEVER REACHED THE WIRE (fake Http saw " + rig.http.calls + " call(s))",
              rig.http.calls == 0);
        check(label + " carries no response body",
              !reply.containsKey(BridgeClient.BODY_KEY));
        check(label + " echoes the frame id", Long.valueOf(41L).equals(reply.get("id")));
    }

    // ---- tests ---------------------------------------------------------

    static void anAllowedRequestIsIssuedOnceAndFramedAsAResult(Path sentinel) {
        Rig r = new Rig(sentinel);
        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders?page=2"),
                authorised());

        check("an allowed request is framed as a result", "result".equals(reply.get("t")));
        check("issued exactly once (" + r.http.calls + ")", r.http.calls == 1);
        check("status is carried", Long.valueOf(200L).equals(reply.get("status")));
        check("outcome is ok", "ok".equals(reply.get("outcome")));
        check("elapsed ms is carried", Long.valueOf(12L).equals(reply.get("ms")));
        check("the url Policy saw is the one we asked for",
              "https://app.example.test/api/orders?page=2".equals(r.http.last.url()));
        check("path and query are split for Policy",
              "/api/orders".equals(r.http.last.path()) && "page=2".equals(r.http.last.query()));
        check("the destination comes from the frame header, not the Host line",
              "app.example.test".equals(r.http.last.host()));
        byte[] body = (byte[]) reply.get(BridgeClient.BODY_KEY);
        check("the response body rides under the reserved key", body != null);
        check("`bytes` counts the REDACTED body, which is what crosses the bridge",
              Long.valueOf((long) body.length).equals(reply.get("bytes")));
        // s7: a response Set-Cookie is a live production session cookie the
        // extension never injected, so the injected-range mechanism cannot key
        // it. The value goes; the name and attributes stay, so cookie-flag and
        // session-fixation checks still work.
        String text = new String(body, StandardCharsets.ISO_8859_1);
        check("the response session cookie value is gone", !text.contains("9f1c4a2e7b"));
        check("its name and attributes survive redaction",
              text.contains("Set-Cookie: session=") && text.contains("HttpOnly"));
        check("the payload is untouched", text.contains("{\"orders\":[42]}"));
    }

    static void everyDenialClassLeavesTheWireUntouched(Path sentinel) {
        Map<String, Object> header = sendHeader(NOW + THIRTY_SECONDS);

        denied("not_configured", new Rig(sentinel), header,
               request("GET", "/api/orders"), denyAll(), "not_configured");

        Rig halted = new Rig(sentinel);
        halted.halt.haltedByFrame("operator pressed stop");
        denied("halted", halted, header, request("GET", "/api/orders"),
               authorised(), "halted");

        denied("scope_denied", new Rig(sentinel), header,
               request("GET", "/api/orders"),
               new BridgeClient.Authorisation(7L, Map.of(
                       "scope.include", List.of("https://other.example.test/*"),
                       "method.allow", List.of("GET"))),
               "scope_denied");

        denied("method_denied", new Rig(sentinel), header,
               request("POST", "/api/orders"), authorised(), "method_denied");

        denied("dangerous_denied", new Rig(sentinel), header,
               request("GET", "/account/logout"), authorised(), "dangerous_denied");

        Rig limited = new Rig(sentinel);
        limited.gate.verdict = Decision.rateLimited(200_000L, "5 rps, 5 issued this second");
        denied("rate_limited", limited, header, request("GET", "/api/orders"),
               authorised(), "rate_limited");

        Rig spent = new Rig(sentinel);
        spent.gate.verdict = Decision.deny("budget_exhausted", "2000 of 2000 requests issued");
        denied("budget_exhausted", spent, header, request("GET", "/api/orders"),
               authorised(), "budget_exhausted");

        // s7: refused and NEVER PERSISTED. Until identity injection exists,
        // this is the only thing keeping a live client session cookie out of a
        // content-addressed blob store, where it would be in every backup.
        Rig cred = new Rig(sentinel);
        denied("unmanaged_credential", cred, header,
               request("GET", "/api/orders", "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"),
               authorised(), "unmanaged_credential");

        denied("bad_frame (no request line)", new Rig(sentinel), header,
               new byte[0], authorised(), "bad_frame");

        // The whitespace-before-the-colon refusal, and why it is load-bearing
        // rather than pedantry. RFC 9112 s5.1 requires a recipient to reject
        // `Name : value`, and recipients disagree about that in practice. Here
        // the field name parses as "Authorization " WITH the trailing space,
        // which unmanagedCredential -- a fail-closed gate answered BY NAME --
        // cannot match: delete the refusal and this exact request is ISSUED,
        // carrying a live bearer token, and its bytes are persisted. It is the
        // same hole as unmanaged_credential, reached through the parser.
        denied("bad_frame (whitespace before the colon)", new Rig(sentinel), header,
               raw("GET /api/orders HTTP/1.1\r\nHost: app.example.test\r\n"
                   + "Authorization : Bearer eyJhbGciOiJIUzI1NiJ9.e30.x\r\n\r\n"),
               authorised(), "bad_frame");

        // Absolute-form: two answers to "where is this going", and only one of
        // them was authorised.
        denied("bad_frame (target is not origin-form)", new Rig(sentinel), header,
               raw("GET http://other.example.test/api/orders HTTP/1.1\r\n"
                   + "Host: app.example.test\r\n\r\n"),
               authorised(), "bad_frame");

        // A header line with no colon at all: a field we would have to guess
        // the name of is one we refuse to reason about.
        denied("bad_frame (header line with no colon)", new Rig(sentinel), header,
               raw("GET /api/orders HTTP/1.1\r\nHost: app.example.test\r\n"
                   + "X-Not-A-Header\r\n\r\n"),
               authorised(), "bad_frame");

        Map<String, Object> noDeadline = sendHeader(NOW + THIRTY_SECONDS);
        noDeadline.remove("deadline_us");
        denied("bad_frame (no deadline_us)", new Rig(sentinel), noDeadline,
               request("GET", "/api/orders"), authorised(), "bad_frame");
    }

    /**
     * The pinned order: not_configured -> halted -> scope_denied ->
     * method_denied -> dangerous_denied -> rate_limited -> budget_exhausted.
     * Each case violates its rule AND every rule after it; the earliest must
     * win, or an operator reading a denial row is told the wrong reason for a
     * stop they need to understand.
     */
    static void theRefusalOrderIsPinned(Path sentinel) {
        Map<String, Object> header = sendHeader(NOW + THIRTY_SECONDS);
        byte[] worst = request("POST", "/account/logout");   // wrong method AND dangerous

        Rig a = new Rig(sentinel);
        a.halt.haltedByFrame("operator pressed stop");
        a.gate.verdict = Decision.deny("budget_exhausted", "spent");
        denied("epoch 0 beats halted, scope, method, dangerous and budget",
               a, header, worst, denyAll(), "not_configured");

        Rig b = new Rig(sentinel);
        b.halt.haltedByFrame("operator pressed stop");
        b.gate.verdict = Decision.deny("budget_exhausted", "spent");
        denied("halted beats scope, method, dangerous and budget",
               b, header, worst,
               new BridgeClient.Authorisation(7L, Map.of(
                       "scope.include", List.of("https://other.example.test/*"))),
               "halted");

        Rig c = new Rig(sentinel);
        c.gate.verdict = Decision.deny("budget_exhausted", "spent");
        denied("scope beats method, dangerous and budget", c, header, worst,
               new BridgeClient.Authorisation(7L, Map.of(
                       "scope.include", List.of("https://other.example.test/*"),
                       "method.allow", List.of("GET"),
                       "dangerous.path", List.of("*/logout*"))),
               "scope_denied");

        Rig d = new Rig(sentinel);
        d.gate.verdict = Decision.deny("budget_exhausted", "spent");
        denied("method beats dangerous and budget", d, header, worst,
               authorised(), "method_denied");
    }

    static void rateLimitedCarriesRetryAfterUs(Path sentinel) {
        Rig r = new Rig(sentinel);
        r.gate.verdict = Decision.rateLimited(200_000L, "5 rps, 5 issued this second");
        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        // s6: this is the one class that carries a retry hint, and the
        // distinction is load-bearing for the agent. rate_limited means slow
        // down; the three *_denied classes mean the answer will not change.
        check("rate_limited carries retry_after_us",
              Long.valueOf(200_000L).equals(reply.get("retry_after_us")));
        check("a *_denied class carries no retry hint",
              !new Rig(sentinel).sender.issue(
                      sendHeader(NOW + THIRTY_SECONDS), request("POST", "/api/orders"),
                      authorised()).containsKey("retry_after_us"));
    }

    /**
     * Plan 2 carried deadline_us on every request frame and validated its
     * presence without ever comparing it to a clock. This is where it starts
     * meaning something.
     */
    static void anExpiredDeadlineIsRefusedWithoutIssuingOrSpendingBudget(Path sentinel) {
        Rig r = new Rig(sentinel);
        // The caller gave up 1.5 s ago: its _request() has already popped this
        // id and a reply would be dropped by _deliver() on the far side.
        Map<String, Object> header = sendHeader(NOW - 1_500_000L);
        Map<String, Object> reply = r.sender.issue(header, request("GET", "/api/orders"),
                                                   authorised());
        check("an expired deadline -> t=error (got " + reply.get("t") + ")",
              "error".equals(reply.get("t")));
        check("an expired deadline -> class=timeout (got " + reply.get("class") + ")",
              "timeout".equals(reply.get("class")));
        check("an expired deadline NEVER REACHED THE WIRE (fake Http saw "
              + r.http.calls + " call(s))", r.http.calls == 0);
        // Why the deadline is checked FIRST. Limiter.check() has a side
        // effect; spending a rate token and a budget slot on a request nothing
        // is waiting for makes a run shorter for no evidence at all.
        check("an expired deadline costs no rate token or budget slot (gate consulted "
              + r.gate.calls + " time(s))", r.gate.calls == 0);
    }

    static void aDeadlineThatExpiresMidFlightIsReportedAsTimeout(Path sentinel) {
        Rig r = new Rig(sentinel);
        r.http.advanceUsPerCall = 31_000_000L;      // 31 s against a 30 s budget
        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("a response after the deadline is reported as timeout",
              "error".equals(reply.get("t")) && "timeout".equals(reply.get("class")));
        // It DID go out. This is not a refusal, and the difference matters:
        // the request exists on the client's estate whatever we report.
        check("the request was in fact issued", r.http.calls == 1);
        check("but no evidence is framed for a caller that stopped waiting",
              !reply.containsKey(BridgeClient.BODY_KEY));
    }

    static void aTransportFailureFeedsDistressAndHaltsTheNextSend(Path sentinel) {
        // maxConsecutiveErrors = 1 so ONE failure trips the stop condition and
        // the test needs no loop. The threshold is a constructor argument for
        // exactly this reason; spec s14 flags 5 as needing tuning anyway.
        Rig r = new Rig(sentinel, 1);
        r.http.boom = new IOException("Connection refused");

        Map<String, Object> first = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("a transport failure is reported as transport_error",
              "error".equals(first.get("t")) && "transport_error".equals(first.get("class")));
        check("the failure reached Distress", r.distress.stopReason() != null);
        check("and Distress names the host", "app.example.test".equals(r.distress.stopHost()));

        // Auto-halt is extension-initiated: nothing sent a halt frame, and the
        // sentinel file does not exist. Issuance still has to stop.
        Rig unused = null;
        Map<String, Object> second = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("the next send is halted by target distress",
              "error".equals(second.get("t")) && "halted".equals(second.get("class")));
        check("and it names the reason", String.valueOf(second.get("detail")).contains("distress"));
        check("the wire saw only the first request (" + r.http.calls + ")", r.http.calls == 1);
        check("unused stays null so javac keeps this honest", unused == null);
    }

    /**
     * A Redactor.RangeError is a DENIAL, never an implicit allow (s4).
     *
     * Plan 5's identity injection lands on issue(), between the credential
     * refusal and the issue, and a range that will not fit the bytes in hand
     * says the frame describes a request other than this one. Nothing
     * registers a range yet, so the one input that reaches the catch today is
     * a reply whose bytes the redactor cannot reason about at all -- the same
     * shape of failure, and the same answer: bytes that were not redacted are
     * not framed as evidence.
     *
     * Without the catch the RangeError leaves issue() as an unhandled
     * RuntimeException, reaches BridgeClient's send arm, and takes the control
     * channel down with it -- a stop the operator reads as `bridge_lost`
     * rather than as a refusal with a class.
     */
    static void aRedactionFailureIsRefusedRatherThanFramed(Path sentinel) {
        Rig r = new Rig(sentinel);
        r.http.reply = new HttpReply(200, null, 12L, false);
        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("a redaction failure is answered as bad_frame (got " + reply.get("class") + ")",
              "error".equals(reply.get("t")) && "bad_frame".equals(reply.get("class")));
        check("and nothing unredacted is framed",
              !reply.containsKey(BridgeClient.BODY_KEY));
        check("it echoes the frame id", Long.valueOf(41L).equals(reply.get("id")));
    }

    /**
     * s6: auto-halt is extension-initiated, so there is no outstanding id to
     * answer. Without an unsolicited `halted` frame the stop is invisible
     * until the next send fails, and `run.status = 'aborted'` has no
     * stop_reason to record -- the harness cannot invent one it was never
     * told.
     *
     * ONCE. Distress has no reset, so every send after the first would push an
     * identical frame, and the second one would be a second abort attempt
     * against a run that is already aborted for the same reason.
     */
    static void distressPushesOneUnsolicitedHaltedFrame(Path sentinel) {
        Rig r = new Rig(sentinel, 1);
        r.http.boom = new IOException("Connection refused");
        check("nothing is announced before anything goes wrong", r.notifier.frames.isEmpty());

        r.sender.issue(sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"),
                       authorised());
        check("the trip is announced (" + r.notifier.frames.size() + " frame(s))",
              r.notifier.frames.size() == 1);
        String[] frame = r.notifier.frames.get(0);
        check("the frame carries the reason Distress gave",
              frame[0] != null && frame[0].equals(r.distress.stopReason()));
        check("and the host it gave", "app.example.test".equals(frame[1]));
        // The third field is why the operator is being told: "5xx rate 0.40"
        // means nothing without the window it was measured over.
        check("and the window it measured", frame[2] != null && !frame[2].isEmpty());

        r.sender.issue(sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"),
                       authorised());
        check("a second refused send announces nothing further ("
              + r.notifier.frames.size() + ")", r.notifier.frames.size() == 1);
    }

    /**
     * ONCE, and the single-threaded path cannot show it.
     *
     * Deleting `announced.compareAndSet(false, true)` leaves all nine classes
     * green: after the first trip every later send is refused `halted` at the
     * top of issue(), before it can reach announceDistress, so the notifier is
     * called exactly once whether or not the flag is there. Measured -- 0 FAIL
     * lines, 9 x ALL PASS -- which makes the test above a test of the control
     * flow, not of the flag.
     *
     * The input that separates them is two sends ALREADY IN FLIGHT when the
     * host trips: both read stopReason() as null on the way in, both record a
     * failure on the way out, and both then have a stop to announce. A barrier
     * inside the fake Http holds each one there until the other has arrived,
     * so the interleaving is forced rather than hoped for.
     *
     * Not hypothetical: `limit.concurrency` is already a key ConfigBody
     * accepts, and the day it is honoured this is the ordinary case. A second
     * frame is a second abort attempt against a run already aborted for the
     * same reason.
     */
    static void twoSendsTrippingTogetherStillAnnounceOnce(Path sentinel) throws Exception {
        Rig r = new Rig(sentinel, 1);
        r.http.bothInFlight = new CyclicBarrier(2);
        r.http.boom = new IOException("Connection refused");
        // advanceUsPerCall stays 0: TickClock.advance is a read-modify-write
        // its own javadoc says only the driving thread may make.

        Runnable send = () -> r.sender.issue(sendHeader(NOW + THIRTY_SECONDS),
                                             request("GET", "/api/orders"), authorised());
        Thread a = new Thread(send, "hx-send-a");
        Thread b = new Thread(send, "hx-send-b");
        a.start(); b.start();
        a.join(10_000); b.join(10_000);

        check("both sends really were in flight together (" + r.http.barrierError + ")",
              r.http.barrierError == null);
        check("neither send is still running", !a.isAlive() && !b.isAlive());
        check("the host tripped", r.distress.stopReason() != null);
        check("and the stop was announced exactly once ("
              + r.notifier.frames.size() + ")", r.notifier.frames.size() == 1);
    }

    /**
     * An interim head is not the response, and this is a MEASUREMENT rather
     * than a reading of the RFC.
     *
     * Burp Suite Community Edition 2026.7.3-52685, driven headless against a
     * server that writes `103 Early Hints` and then `200 OK` on one
     * connection, answered `rr.response().statusCode()` == 103 and
     * `rr.response().toByteArray()` == 275 bytes carrying BOTH heads. So the
     * transport's status is the interim one and the real status is in the
     * bytes.
     *
     * Two things turn on it. The evidence line's `status` would say 103 for a
     * response that was a 500. And Distress counts 5xx off the same number: a
     * CDN sending early hints in front of a failing origin would record
     * nothing but 103s, hold a 0% 5xx rate, and never trip spec s4's auto-halt
     * -- the failure mode where the run keeps hammering a client's broken
     * production system because every sample looked fine.
     *
     * The third assertion is the one Task 4's second fix round bought:
     * Redactor.redactResponse's 1xx branch is LIVE CODE on this path, not the
     * dead branch it was thought to be. Without it the final head's
     * Set-Cookie is copied through raw into a content-addressed blob store.
     */
    static void anInterimHeadIsNotTheStatusAndDoesNotHideA5xx(Path sentinel) {
        Rig r = new Rig(sentinel);
        // 103 is what Montoya reported; the bytes are what came off the wire.
        r.http.reply = new HttpReply(103, INTERIM_THEN_500, 12L, false);

        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("the evidence line carries the FINAL status, not the interim head's ("
              + reply.get("status") + ")", Long.valueOf(500L).equals(reply.get("status")));

        String text = new String((byte[]) reply.get(BridgeClient.BODY_KEY),
                                 StandardCharsets.ISO_8859_1);
        check("the final response's session cookie value is still redacted",
              !text.contains("FINAL_COOKIE_7b3d"));
        check("and so is the interim head's", !text.contains("EARLY_HINTS_COOKIE_9f1c"));
        check("while both heads and the payload survive",
              text.contains("HTTP/1.1 103 Early Hints")
              && text.contains("HTTP/1.1 500 Internal Server Error")
              && text.contains("{\"error\":42}"));

        // Distress needs its baseline before the 5xx rate has an opinion: §4
        // takes it from the host's first ten requests. Ten identical answers
        // is a 100% 5xx rate, and a Sender that fed it 103s would sit at 0%.
        for (int i = 1; i < 10; i++)
            r.sender.issue(sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"),
                           authorised());
        check("and Distress saw ten 5xx, not ten 103s (" + r.distress.stopReason() + ")",
              r.distress.stopReason() != null
              && r.distress.stopReason().startsWith("5xx rate 100.0%"));
    }

    /**
     * The Plan 2 debt, paid. Epoch and scope arrive as ONE record and the
     * result is stamped with the epoch that authorised the scope it was
     * decided under -- not with whatever configEpoch() would answer now.
     */
    static void theResultIsStampedWithTheEpochThatAuthorisedIt(Path sentinel) {
        Rig r = new Rig(sentinel);
        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("the result carries the epoch from the snapshot it decided under",
              Long.valueOf(7L).equals(reply.get("config_epoch")));

        // The same Sender, the same everything, a different snapshot. Nothing
        // else can change the answer, because nothing else is read.
        Rig fresh = new Rig(sentinel);
        Map<String, Object> denied = fresh.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), denyAll());
        check("the snapshot is the only input: epoch 0 is not_configured",
              "not_configured".equals(denied.get("class")));
        check("and nothing was issued under it", fresh.http.calls == 0);
    }

    /**
     * The response body cannot travel in a flat JSON header, so it rides in
     * the result map under a reserved key that BridgeClient removes and hands
     * to Frame.encode as the frame body.
     *
     * Json.write refuses a byte[] value. That is the failsafe: a framer that
     * forgets to strip the key throws JsonError instead of quietly writing a
     * result frame with the evidence missing.
     */
    static void theResponseBodyRidesUnderAKeyJsonRefusesToWrite(Path sentinel) {
        Rig r = new Rig(sentinel);
        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        boolean threw = false;
        try { Json.write(reply); } catch (Json.JsonError e) { threw = true; }
        check("Json.write refuses a result that still carries the body key", threw);

        reply.remove(BridgeClient.BODY_KEY);
        String header = Json.write(reply);
        check("once stripped, the header writes", header.startsWith("{\"v\":1,\"t\":\"result\""));
        check("and the body key is not on the wire", !header.contains(BridgeClient.BODY_KEY));
    }

    /**
     * HxRequest is what Policy decides about; Sender.wireBytes is what Burp
     * issues. They have to agree, or the request that was authorised and the
     * request that goes out are two different requests.
     */
    static void theWireMappingRoundTripsWhatItParsed() {
        byte[] raw = ("POST /api/orders?page=2 HTTP/1.1\r\n"
                + "Host: app.example.test\r\n"
                + "User-Agent: hx/0.1\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: 13\r\n"
                + "\r\n"
                + "{\"qty\":7}\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);

        Map<String, Object> header = sendHeader(NOW + THIRTY_SECONDS);
        header.put("target_port", 8443L);
        Rig r = new Rig(Path.of("/nonexistent/hx-halt"));
        r.gate.verdict = Decision.allow();
        r.sender.issue(header, raw, new BridgeClient.Authorisation(7L, Map.of(
                "scope.include", List.of("https://app.example.test:8443/*"),
                "method.allow", List.of("POST"))));
        HxRequest req = r.http.last;
        check("the request reached Http", req != null);
        check("a non-default port is in the url",
              "https://app.example.test:8443/api/orders?page=2".equals(req.url()));
        check("Sender.secureOf reads the scheme back", Sender.secureOf(req));
        check("Sender.portOf reads the port back (" + Sender.portOf(req) + ")",
              Sender.portOf(req) == 8443);
        check("the body after the header block is preserved verbatim, CRLFs and all",
              "{\"qty\":7}\r\n\r\n".equals(new String(req.body(), StandardCharsets.ISO_8859_1)));
        check("wireBytes reproduces the request it parsed",
              new String(Sender.wireBytes(req), StandardCharsets.ISO_8859_1)
                      .equals(new String(raw, StandardCharsets.ISO_8859_1)));
    }

    /**
     * s4 calls the rate and the budget engagement-config defaults, not
     * constants, and `limit.rate_rps` and `limit.max_requests` are two of the
     * keys ConfigBody already accepts. An operator who configures 1 rps must
     * get 1 rps rather than the number this jar was built with.
     *
     * They arrive inside the same Authorisation snapshot the decision is made
     * under, which is the only place they can be read from coherently -- and
     * they are read ONCE, because Limiter's budget deliberately has no refill.
     */
    static void theConfiguredLimitsArmTheGateOnceFromTheAuthorisation() {
        TickClock clock = new TickClock(NOW);
        Limits limits = new Limits(clock, 5L, 2000L);

        limits.arm(denyAll());
        check("a DENY-ALL snapshot arms nothing: epoch 0 carries no config at all",
              limits.ratePerSecond() == 0L);

        // authorised() configures limit.rate_rps=5 and says nothing about
        // limit.max_requests.
        limits.arm(authorised());
        check("the configured rate is what the gate uses (" + limits.ratePerSecond() + ")",
              limits.ratePerSecond() == 5L);
        check("an absent key leaves the built-in default (" + limits.maxRequests() + ")",
              limits.maxRequests() == 2000L);

        check("the armed gate answers", limits.check(REQ).allowed());
        check("and spending is counted (" + limits.issued() + ")", limits.issued() == 1L);

        // A configure re-authorises SCOPE, not issuance. Rebuilding the
        // Limiter here would hand a spent run a fresh budget -- exactly what
        // Limiter's missing refill exists to prevent.
        limits.arm(new BridgeClient.Authorisation(8L, Map.of(
                "limit.rate_rps", List.of("99"),
                "limit.max_requests", List.of("1000000"))));
        check("a later configure does not re-arm the limits (" + limits.ratePerSecond() + ")",
              limits.ratePerSecond() == 5L);
        check("and does not refill the budget (" + limits.issued() + ")",
              limits.issued() == 1L);

        // Unreadable is not "use the default". An operator who asked for a
        // limit we cannot parse has not been given the limit they asked for,
        // and BridgeClient's send arm turns this throw into an error frame and
        // DENY-ALL.
        boolean threw = false;
        try {
            new Limits(clock, 5L, 2000L).arm(new BridgeClient.Authorisation(2L,
                    Map.of("limit.rate_rps", List.of("as fast as possible"))));
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check("a limit that is not a positive integer is refused, not defaulted", threw);

        check("an unarmed gate denies rather than allowing",
              !new Limits(clock, 5L, 2000L).check(REQ).allowed());
    }
}
