// extension/test/hx/send/SenderTest.java
package hx.send;

import hx.TestSupport;
import hx.bridge.BridgeClient;
import hx.bridge.Json;
import hx.policy.Clock;
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
            t("theSendPathRefusesEpochZeroBeforeItsOwnLaterChecks",
              () -> theSendPathRefusesEpochZeroBeforeItsOwnLaterChecks(sentinel));
            t("theRefusalOrderIsPinned", () -> theRefusalOrderIsPinned(sentinel));
            t("rateLimitedCarriesRetryAfterUs", () -> rateLimitedCarriesRetryAfterUs(sentinel));
            t("theDestinationPortAndSchemeAreReadFromTheFrameAndBounded",
              () -> theDestinationPortAndSchemeAreReadFromTheFrameAndBounded(sentinel));
            t("ipv6IsRefusedByScopeAndThatIsTheOnlyThingHoldingTheLine",
              () -> ipv6IsRefusedByScopeAndThatIsTheOnlyThingHoldingTheLine(sentinel));
            t("theDeadlineIsRefusedAtTheMicrosecondItPasses",
              () -> theDeadlineIsRefusedAtTheMicrosecondItPasses(sentinel));
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
            t("aResponselessReplyIsATransportErrorAndFeedsDistress",
              () -> aResponselessReplyIsATransportErrorAndFeedsDistress(sentinel));
            t("theDestinationIsTheFrameHeaderEvenWhenTheHostLineDisagrees",
              () -> theDestinationIsTheFrameHeaderEvenWhenTheHostLineDisagrees(sentinel));
            t("anInternalFailureIsNotSwallowedIntoAnErrorFrame",
              () -> anInternalFailureIsNotSwallowedIntoAnErrorFrame(sentinel));
            t("aHaltWithNoReasonNeverDeliversTheWordNull",
              () -> aHaltWithNoReasonNeverDeliversTheWordNull(dir));
            t("theInterimHeadScanIsBoundedAndFailsToward5xx",
              SenderTest::theInterimHeadScanIsBoundedAndFailsToward5xx);
            t("theEvidenceLineSaysWhichKindOf599ThisIs",
              () -> theEvidenceLineSaysWhichKindOf599ThisIs(sentinel));
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
        /** An UNCHECKED failure from inside issue(), which is a different
         *  thing from `boom` and must be answered differently: see
         *  anInternalFailureIsNotSwallowedIntoAnErrorFrame. */
        RuntimeException crash = null;
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
            if (crash != null) throw crash;
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

    /**
     * A clock that answers a SCRIPTED sequence and counts its reads.
     *
     * TickClock cannot do this job: it holds one value that only the driving
     * thread may move, and the input here is a value that CHANGES BETWEEN two
     * reads made inside one call to issue() -- a wall clock corrected backwards
     * under a running JVM, which is what HxExtension injects and says so.
     * Past the end of the script it holds the last value rather than throwing:
     * HaltSwitch.stale() catches Throwable from an injected clock and answers
     * "halted", so a clock that threw would make the test pass for the wrong
     * reason.
     */
    static final class SteppingClock implements Clock {
        private final long[] script;
        private int read = 0;
        SteppingClock(long... script) { this.script = script; }
        public long nowUs() {
            long v = script[Math.min(read, script.length - 1)];
            read++;
            return v;
        }
        int reads() { return read; }
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
            this(null, sentinel, maxConsecutiveErrors);
        }

        /** The same rig around a HaltSwitch the caller built. One test needs
         *  one wired to its OWN clock -- see
         *  aHaltWithNoReasonNeverDeliversTheWordNull -- and HaltSwitch is
         *  final, so there is nothing to subclass and no other way in. */
        Rig(HaltSwitch injected, int maxConsecutiveErrors) {
            this(injected, null, maxConsecutiveErrors);
        }

        private Rig(HaltSwitch injected, Path sentinel, int maxConsecutiveErrors) {
            http.clock = clock;
            // start() is deliberately NOT called on the one built here: the
            // sentinel poller is HaltSwitch's own test's business, and a
            // background thread in here would make these assertions
            // time-dependent.
            halt = injected != null ? injected
                 : new HaltSwitch(clock, sentinel, HaltSwitch.DEFAULT_POLL_MS);
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

    /**
     * denied(), plus the half of the ORDER OF REFUSAL comment that had no test
     * at all.
     *
     * Steps 0-4 of that comment -- bad_frame, timeout, not_configured, halted,
     * unmanaged_credential -- are placed BEFORE the Gate, and the comment gives
     * the reason: Policy's Gate is Limits, whose check() SPENDS a rate token
     * and a budget slot, and spending either on a request that is about to be
     * refused shortens the run for no evidence. denied() asserts what reached
     * the wire and never what the decision cost, so moving unmanaged_credential
     * below the Gate was invisible to all 1304 checks. A refused request that
     * spends budget is a spec s7 problem, not a matter of style.
     */
    static void deniedBeforeTheGate(String label, Rig rig, Map<String, Object> header,
                                    byte[] body, BridgeClient.Authorisation auth,
                                    String expectedClass) {
        denied(label, rig, header, body, auth, expectedClass);
        check(label + " COSTS NO RATE TOKEN OR BUDGET SLOT (gate consulted "
              + rig.gate.calls + " time(s))", rig.gate.calls == 0);
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

        deniedBeforeTheGate("not_configured", new Rig(sentinel), header,
               request("GET", "/api/orders"), denyAll(), "not_configured");

        Rig halted = new Rig(sentinel);
        halted.halt.haltedByFrame("operator pressed stop");
        deniedBeforeTheGate("halted", halted, header, request("GET", "/api/orders"),
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
        deniedBeforeTheGate("unmanaged_credential", cred, header,
               request("GET", "/api/orders", "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"),
               authorised(), "unmanaged_credential");

        deniedBeforeTheGate("bad_frame (no request line)", new Rig(sentinel), header,
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
     * Sender's OWN epoch-0 check, separated from Policy's.
     *
     * There are two epoch-0 guards on this path and they answer with the same
     * class AND the same detail string: Sender.decideAndIssue's
     * `auth.epoch() == 0` and Policy.decide's `auth == null ||
     * auth.epoch() == 0`. MEASURED on this branch: delete Sender's and the
     * dedicated site in everyDenialClassLeavesTheWireUntouched stays green in
     * ALL SIX of the assertions deniedBeforeTheGate makes, because Policy
     * answers in its place -- including "COSTS NO RATE TOKEN OR BUDGET SLOT",
     * since Policy also refuses before it consults the Gate.
     *
     * So no input separates the two by what comes BACK. The only thing
     * Sender's guard does that Policy's cannot is refuse EARLIER: before the
     * halt check, before the distress check and before the credential check,
     * none of which Policy can see. That is what this pins, and it is the
     * whole of the guard's observable contract.
     *
     * theRefusalOrderIsPinned's first case covers the halt half of that
     * (delete Sender's guard and it answers `halted`). This covers the
     * credential half, so the pin does not rest on a single rig having its
     * sentinel armed.
     */
    static void theSendPathRefusesEpochZeroBeforeItsOwnLaterChecks(Path sentinel) {
        Map<String, Object> header = sendHeader(NOW + THIRTY_SECONDS);
        byte[] withCredential = request("GET", "/api/orders",
                "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x");

        // The sentinel is the suite's, and it is deliberately ABSENT, so
        // nothing here is halted and no distress has been recorded: the only
        // two candidates are not_configured and unmanaged_credential, and
        // which one comes back says which guard ran.
        deniedBeforeTheGate("epoch 0 is refused before the credential check",
               new Rig(sentinel), header, withCredential, denyAll(), "not_configured");

        // The same frame at a real epoch IS the credential refusal, so the
        // case above is not vacuous: the credential guard is armed and would
        // have answered if Sender's epoch check had not run first.
        deniedBeforeTheGate("and the same frame at a real epoch is the credential refusal",
               new Rig(sentinel), header, withCredential, authorised(),
               "unmanaged_credential");
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
    /** An HxRequest at a url whose authority this test chose, for the two
     *  helpers that read a url and nothing else. */
    static HxRequest at(String url, String host) {
        return new HxRequest("GET", url, host, "/api/orders", "", Map.of(), new byte[0]);
    }

    /**
     * The destination fields of the frame header, and the port the url
     * encodes, each separated from its absence.
     *
     * MEASURED before this test existed, whole Java suite at 9 x ALL PASS /
     * 1407 ok / 0 FAIL for every one of these:
     *
     *   the target_port range check deleted outright     0 FAIL
     *   its low bound  1     -> 0                        0 FAIL
     *   its high bound 65535 -> 65536                    0 FAIL
     *   tls defaulting false -> defaulting true          0 FAIL
     *   portOf's IPv6 bracket rule deleted               0 FAIL
     *
     * Every one of them decides where Burp opens a connection, which is the
     * one thing on this path that is not recoverable by a later refusal.
     */
    static void theDestinationPortAndSchemeAreReadFromTheFrameAndBounded(Path sentinel) {
        Map<String, Object> header = sendHeader(NOW + THIRTY_SECONDS);

        // ---- target_port, outside the range ----------------------------
        // A frame this side cannot read a port from is a bad_frame, refused
        // before the Gate: it is step 0 of the ORDER OF REFUSAL, and a port
        // of 0 or 65536 is not a port on any stack that would carry it.
        for (long bad : new long[] {0L, -1L, 65536L, 70000L}) {
            Map<String, Object> h = sendHeader(NOW + THIRTY_SECONDS);
            h.put("target_port", bad);
            deniedBeforeTheGate("target_port " + bad + " is not a port",
                   new Rig(sentinel), h, request("GET", "/api/orders"),
                   authorised(), "bad_frame");
        }

        // ---- target_port, ON the range ---------------------------------
        // The other direction, so a bound cannot be narrowed either: 1 and
        // 65535 are ports, and the url has to carry them.
        Map<String, Object> lo = sendHeader(NOW + THIRTY_SECONDS);
        lo.put("target_port", 1L);
        HxRequest atOne = Sender.parse(lo, request("GET", "/api/orders"));
        check("port 1 is a port and the url carries it (" + atOne.url() + ")",
              "https://app.example.test:1/api/orders".equals(atOne.url()));
        Map<String, Object> hi = sendHeader(NOW + THIRTY_SECONDS);
        hi.put("target_port", 65535L);
        HxRequest atMax = Sender.parse(hi, request("GET", "/api/orders"));
        check("and 65535 is one too (" + atMax.url() + ")",
              "https://app.example.test:65535/api/orders".equals(atMax.url()));

        // ---- tls, and why FALSE is the fail-closed default -------------
        Map<String, Object> noTls = sendHeader(NOW + THIRTY_SECONDS);
        noTls.remove("tls");
        noTls.remove("target_port");
        HxRequest plain = Sender.parse(noTls, request("GET", "/api/orders"));
        check("a frame with no tls key is http, not https (" + plain.url() + ")",
              "http://app.example.test/api/orders".equals(plain.url()));
        check("secureOf agrees with the url it built", !Sender.secureOf(plain));
        check("and the scheme default it gets is 80 (" + Sender.portOf(plain) + ")",
              Sender.portOf(plain) == 80);

        // `Boolean.TRUE.equals`, not a truthiness test. A JSON string is not a
        // boolean, and a field this side cannot read must not be read as the
        // permissive answer.
        Map<String, Object> stringTls = sendHeader(NOW + THIRTY_SECONDS);
        stringTls.put("tls", "true");
        stringTls.remove("target_port");
        HxRequest notABoolean = Sender.parse(stringTls, request("GET", "/api/orders"));
        check("tls: \"true\" is a string, not a boolean, and does not build an https url ("
              + notABoolean.url() + ")",
              "http://app.example.test/api/orders".equals(notABoolean.url()));

        // Defaulting to false is fail-CLOSED and this is why, end to end
        // rather than by argument: scope patterns are scheme-exact, so the
        // http url an omitted tls produces is refused by an https-only
        // scope.include. Defaulting the other way would manufacture an https
        // url from a frame that never said https.
        Map<String, Object> noTlsAgain = sendHeader(NOW + THIRTY_SECONDS);
        noTlsAgain.remove("tls");
        noTlsAgain.remove("target_port");
        denied("a frame that omits tls is refused by an https-only scope",
               new Rig(sentinel), noTlsAgain, request("GET", "/api/orders"),
               authorised(), "scope_denied");

        // ---- portOf's bracket rule -------------------------------------
        // An IPv6 authority is full of colons and only ONE of them is a port
        // separator: the one after the closing bracket. Delete the rule and
        // the last colon INSIDE the literal is read as the separator, so
        // parseInt("1]") throws and a url with no port at all becomes an
        // exception instead of the scheme default.
        HxRequest bracketed = at("https://[2001:db8::1]/api/orders", "[2001:db8::1]");
        int port = -1;
        String threw = null;
        try { port = Sender.portOf(bracketed); }
        catch (Throwable t) { threw = String.valueOf(t); }
        check("a bracketed IPv6 authority with no port answers the scheme default ("
              + (threw == null ? String.valueOf(port) : threw) + ")",
              threw == null && port == 443);
        check("and a bracketed IPv6 authority WITH a port answers that port ("
              + Sender.portOf(at("https://[2001:db8::1]:8443/api/orders", "[2001:db8::1]")) + ")",
              Sender.portOf(at("https://[2001:db8::1]:8443/api/orders", "[2001:db8::1]")) == 8443);
    }

    /**
     * F9, as a tripwire rather than a note in a report.
     *
     * IPv6 TARGETS ARE UNUSABLE and the failure is in portOf, not in the scope
     * rules. MEASURED: a send frame with target_host "2001:db8::1" and
     * target_port 443 builds the url https://2001:db8::1/api/orders -- parse()
     * omits a default port, so the authority is a bare literal with no
     * brackets -- and portOf takes the text after its LAST colon and answers
     * 1. Burp would open a connection to port 1 of an address the operator
     * asked for on 443.
     *
     * The reason that is not a live defect today is the first check below:
     * Policy refuses the IPv6 url before portOf is ever consulted, EVEN WHEN
     * THE OPERATOR NAMED THAT EXACT ADDRESS in scope.include, because
     * Target.parse cannot read the authority. MEASURED on all three spellings
     * -- bare, bracketed, and bracketed with an explicit port -- each answered
     * scope_denied with the detail "url port is not a number". Both halves are
     * asserted
     * here so neither can move alone. IF THE FIRST CHECK EVER GOES RED BECAUSE
     * SOMEBODY TAUGHT Target.parse ABOUT IPv6, THE SECOND ONE IS THE LIVE BUG
     * THEY JUST EXPOSED: bracket the literal in parse() -- and then portOf's
     * lastIndexOf(']') guard starts doing the job it was written for -- or
     * refuse an unbracketed literal outright. Do not close half of it.
     */
    static void ipv6IsRefusedByScopeAndThatIsTheOnlyThingHoldingTheLine(Path sentinel) {
        Map<String, Object> header = sendHeader(NOW + THIRTY_SECONDS);
        header.put("target_host", "2001:db8::1");

        // The operator explicitly authorised this address, so this is not
        // "an address nobody asked for": it is the configured one, refused.
        BridgeClient.Authorisation named = new BridgeClient.Authorisation(7L, Map.of(
                "scope.include", List.of("https://2001:db8::1/*"),
                "method.allow", List.of("GET")));
        denied("an IPv6 target its own scope.include names is STILL scope_denied",
               new Rig(sentinel), header, request("GET", "/api/orders"), named,
               "scope_denied");

        // The hazard the check above is holding back, stated so it cannot rot
        // in silence. This assertion is deliberately on the WRONG answer.
        HxRequest bare = at("https://2001:db8::1/api/orders", "2001:db8::1");
        check("an unbracketed IPv6 authority answers port " + Sender.portOf(bare)
              + " for a frame that asked for 443 -- see this method's javadoc "
              + "before changing either half", Sender.portOf(bare) == 1);
    }

    /**
     * Both deadline comparisons, AT the microsecond.
     *
     * MEASURED before this test existed: relaxing either `>=` to `>` left the
     * whole Java suite at 9 x ALL PASS / 1407 ok / 0 FAIL. The existing two
     * deadline tests approach the boundary from 1.5 s and 31 s away, which
     * every off-by-one survives.
     *
     * `>=` is the correct side of both. A deadline is the instant the caller
     * stops waiting, not the last instant it waits: the harness's _request()
     * has popped the id by then and _deliver() drops a reply nobody holds.
     * Issuing AT it spends a rate token and a budget slot on evidence that
     * cannot be delivered.
     *
     * THE TWO GUARDS MASK EACH OTHER ON THE CLASS, which is why the first case
     * asserts the WIRE and not just the answer. Relax the pre-flight `>=` and
     * a deadline equal to now still comes back `timeout` -- the request goes
     * out, the clock has not moved, and the POST-flight check answers with the
     * same class. What changed is that a request nothing was waiting for was
     * issued to the client's estate and a budget slot was spent on it.
     */
    static void theDeadlineIsRefusedAtTheMicrosecondItPasses(Path sentinel) {
        // ---- before the flight -----------------------------------------
        Rig at = new Rig(sentinel);
        Map<String, Object> exactly = sendHeader(NOW);           // deadline == now
        Map<String, Object> reply = at.sender.issue(
                exactly, request("GET", "/api/orders"), authorised());
        check("a deadline equal to now is already gone (" + reply.get("class") + ")",
              "error".equals(reply.get("t")) && "timeout".equals(reply.get("class")));
        check("and it never reached the wire (" + at.http.calls + ")", at.http.calls == 0);
        check("nor cost a rate token (" + at.gate.calls + ")", at.gate.calls == 0);

        // One microsecond of budget left is still budget.
        Rig justInside = new Rig(sentinel);
        Map<String, Object> ok = justInside.sender.issue(
                sendHeader(NOW + 1L), request("GET", "/api/orders"), authorised());
        check("one microsecond before it is not (" + ok.get("t") + ")",
              "result".equals(ok.get("t")));

        // ---- after the flight ------------------------------------------
        // The send itself consumes exactly the whole budget, so the response
        // lands ON the deadline rather than past it.
        Rig landsOnIt = new Rig(sentinel);
        landsOnIt.http.advanceUsPerCall = THIRTY_SECONDS;
        Map<String, Object> late = landsOnIt.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("a response that lands ON the deadline is a timeout (" + late.get("class") + ")",
              "error".equals(late.get("t")) && "timeout".equals(late.get("class")));
        check("the request did go out, and this is not a refusal (" + landsOnIt.http.calls + ")",
              landsOnIt.http.calls == 1);
        check("no evidence is framed for a caller that stopped waiting",
              !late.containsKey(BridgeClient.BODY_KEY));

        // And one microsecond inside it is a result, so the check above is a
        // boundary rather than a blanket refusal of a slow response.
        Rig justMade = new Rig(sentinel);
        justMade.http.advanceUsPerCall = THIRTY_SECONDS - 1L;
        Map<String, Object> made = justMade.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("a response one microsecond inside it is framed (" + made.get("t") + ")",
              "result".equals(made.get("t")));
    }

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
     * A reply that never got a response, which is a DIFFERENT input from an
     * IOException and had none of its own.
     *
     * `new HttpReply(..., connectionError=true)` is constructed in exactly one
     * place in the extension -- HxExtension's `!rr.hasResponse()` branch, where
     * a refused connection, a DNS failure and a TLS failure all arrive, because
     * Montoya answers those with a response-less HttpRequestResponse rather
     * than by throwing. Until this test, no fixture in the suite set the flag:
     * every connection-error case went through the IOException catch, which
     * passes a hard-coded literal `true` and therefore proves nothing about the
     * field.
     *
     * Two one-line mutations were invisible to all 1304 checks because of it:
     *
     *   - delete the `if (reply.connectionError())` refusal, and a request that
     *     never got a response is framed as `{"t":"result","status":0,
     *     "bytes":0,"outcome":"ok"}` with a zero-length body. A fabricated
     *     evidence line claiming a successful exchange.
     *   - pass `false` instead of `reply.connectionError()` to Distress, and
     *     spec s4's five-consecutive-connection-errors auto-halt never fires on
     *     this path at all -- status 0 is not a 5xx, so nothing counts it.
     *
     * Both have the same failure scenario: a host whose firewall silently drops
     * the port. Today the run halts after five. After either, it spends its
     * whole 2000-request budget against a dead host and records 2000 exchanges
     * as `outcome: ok`.
     */
    static void aResponselessReplyIsATransportErrorAndFeedsDistress(Path sentinel) {
        // maxConsecutiveErrors = 1: one response-less reply is the whole input.
        Rig r = new Rig(sentinel, 1);
        r.http.reply = new HttpReply(0, new byte[0], 7L, true);

        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());

        check("a response-less reply is an error, not a result (got " + reply.get("t") + ")",
              "error".equals(reply.get("t")));
        check("and its class is transport_error (got " + reply.get("class") + ")",
              "transport_error".equals(reply.get("class")));
        check("nothing is framed as evidence for an exchange that never happened",
              !reply.containsKey(BridgeClient.BODY_KEY));
        check("it echoes the frame id", Long.valueOf(41L).equals(reply.get("id")));
        // The request DID leave: this is not a refusal, and the difference is
        // the whole reason Distress has to see it.
        check("the request was issued (" + r.http.calls + ")", r.http.calls == 1);
        check("the connection error reached Distress (" + r.distress.stopReason() + ")",
              r.distress.stopReason() != null);
        check("and Distress counted it as a CONNECTION error, not a status-0 reply",
              String.valueOf(r.distress.stopReason()).contains("consecutive connection errors"));
        check("and Distress names the host", "app.example.test".equals(r.distress.stopHost()));
        check("the stop was announced exactly once (" + r.notifier.frames.size() + ")",
              r.notifier.frames.size() == 1);
    }

    /**
     * The destination is the FRAME HEADER's, and this is the fixture that can
     * tell the two apart.
     *
     * Every other fixture in this class sets `target_host` and the `Host:` line
     * to the same string, so the check named "the destination comes from the
     * frame header, not the Host line" was a tautology under its own inputs:
     * making parse() prefer the Host header when present left all nine classes
     * green. One divergent fixture is the whole fix.
     *
     * The behaviour under test is also the one we want for its own sake, not
     * merely for the scope decision. Burp connects to the service we NAME, and
     * the spoofed `Host` goes out on the wire verbatim -- that is the standard
     * host-header-injection probe, and it only works if the two are separate.
     * Deciding scope on the Host line would let a request authorised for
     * app.example.test open a connection somewhere else entirely.
     */
    static void theDestinationIsTheFrameHeaderEvenWhenTheHostLineDisagrees(Path sentinel) {
        Rig r = new Rig(sentinel);
        Map<String, Object> reply = r.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS),
                raw("GET /api/orders HTTP/1.1\r\n"
                    + "Host: evil.example.com\r\n"
                    + "User-Agent: hx/0.1\r\n\r\n"),
                authorised());

        check("a divergent Host line does not stop the request (got "
              + reply.get("t") + "/" + reply.get("class") + ")", "result".equals(reply.get("t")));
        check("the request reached Http", r.http.last != null);
        check("the DESTINATION is the frame header's target_host (" + r.http.last.host() + ")",
              "app.example.test".equals(r.http.last.host()));
        check("so is the url Policy decided about (" + r.http.last.url() + ")",
              "https://app.example.test/api/orders".equals(r.http.last.url()));
        // And the injected header is still on the wire, untouched: this is a
        // host-header-injection probe, and rewriting it would delete the check.
        check("while the spoofed Host header goes out verbatim",
              new String(Sender.wireBytes(r.http.last), StandardCharsets.ISO_8859_1)
                      .contains("Host: evil.example.com"));
    }

    /**
     * issue() catches Redactor.RangeError -- and nothing else.
     *
     * Widening that catch to RuntimeException is invisible to every other
     * check in this suite, and it would silently delete the behaviour
     * BridgeClientTest's aSendHandlerThatThrowsDropsToDenyAll exists to
     * guarantee: an unchecked failure inside the send path is not a refusal
     * with a class, it is a send path we no longer understand, and spec s4's
     * terminal state is DENY-ALL with the channel closed. Swallowed into an
     * error frame, the run carries on issuing requests through code that just
     * threw.
     *
     * The narrow catch is therefore a claim about the ONE failure that is a
     * decision (a range that does not fit the bytes it is an offset into, which
     * says the frame describes some other request) as against every failure
     * that is a bug.
     */
    static void anInternalFailureIsNotSwallowedIntoAnErrorFrame(Path sentinel) {
        Rig r = new Rig(sentinel);
        r.http.crash = new IllegalStateException("Burp unloaded mid-request");

        RuntimeException escaped = null;
        Map<String, Object> reply = null;
        try {
            reply = r.sender.issue(sendHeader(NOW + THIRTY_SECONDS),
                                   request("GET", "/api/orders"), authorised());
        } catch (RuntimeException e) {
            escaped = e;
        }
        check("an unchecked failure inside issue() is NOT answered as a frame (got "
              + (reply == null ? "a throw" : reply.get("class")) + ")", reply == null);
        check("it reaches the send arm, which is what drops to DENY-ALL and closes ("
              + escaped + ")",
              escaped instanceof IllegalStateException
              && "Burp unloaded mid-request".equals(escaped.getMessage()));

        // The other half of the same claim: the ONE unchecked failure that IS
        // a decision still gets its class. aRedactionFailureIsRefusedRather-
        // ThanFramed asserts the whole shape; this line is here so the two
        // directions are read together and neither can be "simplified" into
        // the other.
        Rig ranged = new Rig(sentinel);
        ranged.http.reply = new HttpReply(200, null, 12L, false);
        check("while a RangeError is still a bad_frame",
              "bad_frame".equals(ranged.sender.issue(sendHeader(NOW + THIRTY_SECONDS),
                      request("GET", "/api/orders"), authorised()).get("class")));
    }

    /**
     * halted() true and reason() null is a real straddle, and the fallback
     * string is what stands between it and an operator reading `detail: null`.
     *
     * HaltSwitch publishes both inputs through one reference, so each ANSWER is
     * coherent -- but halted() and reason() are two calls, and its own javadoc
     * names the one gap left: "halted()==true followed by reason()==null".
     * Sender answers it with an explicit fallback rather than believing it was
     * never halted, and 07340ab fixed the same shape one layer up a week ago,
     * on the same operator-facing surface: a halt frame with no reason
     * delivered the four-character word "null".
     *
     * REACHED HERE THROUGH THE STALENESS RULE, on a clock that steps backwards
     * between the two reads -- which is not a contrivance: HxExtension injects
     * `Instant.now()` deliberately (deadline_us is absolute wall-clock
     * microseconds set by the peer, so a monotonic clock answers a different
     * question), and a wall clock is exactly the kind that an NTP correction
     * moves backwards under a running JVM.
     *
     *   read 1  the first poll, on start()'s own thread: lastPollUs = T0
     *   read 2  halted()  -> T0 + 400 s, past the 300 s staleness bound -> TRUE
     *   read 3  reason()  -> T0 again, the clock has been corrected -> not
     *           stale, no frame halt, no sentinel halt -> NULL
     */
    static void aHaltWithNoReasonNeverDeliversTheWordNull(Path dir) throws Exception {
        // 60 s poll interval: start()'s first poll runs on THIS thread and the
        // background poller then sleeps for a minute, so the only clock reads
        // in this test are the three scripted below.
        long pollMs = 60_000L;
        long staleUs = pollMs * 1000L * HaltSwitch.STALE_INTERVALS;
        SteppingClock clock = new SteppingClock(NOW, NOW + staleUs + 1L, NOW);
        HaltSwitch halt = new HaltSwitch(clock, dir.resolve("absent-halt"), pollMs);
        halt.start();
        try {
            Rig r = new Rig(halt, 5);
            Map<String, Object> reply = r.sender.issue(
                    sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"),
                    authorised());

            // The premise, asserted rather than assumed: exactly the three
            // reads above happened, so the straddle really was the input.
            check("the straddle was exercised: three clock reads (" + clock.reads() + ")",
                  clock.reads() == 3);
            check("a stalled poller halts issuance", "error".equals(reply.get("t"))
                  && "halted".equals(reply.get("class")));
            check("nothing was issued (" + r.http.calls + ")", r.http.calls == 0);
            Object detail = reply.get("detail");
            check("the detail is not null (" + detail + ")", detail != null);
            check("nor the four-character word null (" + detail + ")",
                  !"null".equals(detail));
            check("it says a halt was in force with no reason recorded (" + detail + ")",
                  "halted, no reason recorded".equals(detail));
        } finally {
            halt.stop();
        }
    }

    /**
     * The interim-head scan is BOUNDED, the bound is exactly 8 heads, and
     * running out of budget does not report the interim status.
     *
     * MEASURED against the compiled method before this test existed: 7 interim
     * heads then a 500 answered 500, 8 then a 500 answered 100, and 9 answered
     * 100. Past the bound it returned the interim 1xx, so Distress recorded a
     * healthy sample -- the same 0%-5xx blindness finalStatus was written to
     * prevent, reachable by any peer that chooses its own head count. A bound
     * whose overflow behaviour is "fail open in exactly the direction this
     * function exists to close" is a bypass with a parameter.
     *
     * The bound is pinned in BOTH directions here. It was pinned in neither:
     * MAX_INTERIM_HEADS 8 -> 2 was invisible to the whole suite, and only 8 ->
     * 1 reddened anything, so all that was asserted was ">= 2".
     */
    static void theInterimHeadScanIsBoundedAndFailsToward5xx() {
        check("the bound is 8 heads (" + Sender.MAX_INTERIM_HEADS + ")",
              Sender.MAX_INTERIM_HEADS == 8);
        // The VALUE, not merely "somewhere in 5xx". 599 -> 500 left all nine
        // classes green before this line existed, and 500 is a status real
        // origins send constantly: a sentinel that collides with a common
        // answer is exactly the ambiguity `outcome` had to be added to
        // resolve. Pinned here for the same reason MAX_INTERIM_HEADS is.
        check("and the unreadable-status sentinel is 599 ("
              + Sender.STATUS_UNREADABLE + ")", Sender.STATUS_UNREADABLE == 599);

        // 7 interim heads is the most that can precede a final one, because
        // the eighth iteration is the one that reads the final head.
        check("7 interim heads then a 500 still reads the 500 ("
              + Sender.finalStatus(interimHeads(7, "HTTP/1.1 500 Internal Server Error"), 103)
              + ")",
              Sender.finalStatus(interimHeads(7, "HTTP/1.1 500 Internal Server Error"), 103)
              == 500);
        check("and 7 interim heads then a 200 reads the 200 ("
              + Sender.finalStatus(interimHeads(7, "HTTP/1.1 200 OK"), 103) + ")",
              Sender.finalStatus(interimHeads(7, "HTTP/1.1 200 OK"), 103) == 200);

        // 8 is one too many. The answer is NOT the interim status.
        int exhausted = Sender.finalStatus(
                interimHeads(8, "HTTP/1.1 500 Internal Server Error"), 103);
        check("8 interim heads exhaust the scan (" + exhausted + ")",
              exhausted == Sender.STATUS_UNREADABLE);
        check("and an exhausted scan does not report the interim head (" + exhausted + ")",
              exhausted != 103);
        check("what it reports is inside the 5xx range Distress counts as an error ("
              + exhausted + ")", exhausted >= 500 && exhausted <= 599);
        check("40 heads of it are answered the same way",
              Sender.finalStatus(interimHeads(40, "HTTP/1.1 200 OK"), 103)
              == Sender.STATUS_UNREADABLE);

        // Running out of BYTES is a different ending and keeps the old answer:
        // there is nothing there for a peer to have hidden a status behind.
        check("truncation after a blank line still reports what the transport said",
              Sender.finalStatus(interimHeads(1, ""), 103) == 103);
        check("and a reply that is not 1xx is never touched at all",
              Sender.finalStatus(interimHeads(8, "HTTP/1.1 500 Internal Server Error"), 204)
              == 204);

        // ---- the two guards on the way IN to the scan ------------------
        //
        // MEASURED before these lines existed: dropping the `raw == null`
        // term, moving the low bound 100 -> 101, and moving the high bound
        // 199 -> 200 each left the whole Java suite at 9 x ALL PASS / 1407 ok
        // / 0 FAIL. The bounds are the RFC 9110 s15.2 definition of "1xx", and
        // 1xx-is-never-final is the entire licence this function has to
        // improve on what the transport reported.

        // A null `raw` is a real reply shape -- HttpReply carries whatever
        // Montoya gave us -- and it reaches redactResponse, which answers it
        // with a RangeError and a bad_frame. It must not become an NPE HERE
        // first, three frames earlier, where nothing would say which field
        // was missing.
        int nullRaw = -1;
        String nullThrew = null;
        try { nullRaw = Sender.finalStatus(null, 103); }
        catch (Throwable t) { nullThrew = String.valueOf(t); }
        check("a null response body reports the transport's status, not an NPE ("
              + (nullThrew == null ? String.valueOf(nullRaw) : nullThrew) + ")",
              nullThrew == null && nullRaw == 103);

        // BOTH ends of the 1xx range are inside it. 100 Continue is the one a
        // real client meets most often; 199 is the top of the range.
        check("a reported 100 is scanned like any other 1xx ("
              + Sender.finalStatus(interimHeads(1, "HTTP/1.1 200 OK"), 100) + ")",
              Sender.finalStatus(interimHeads(1, "HTTP/1.1 200 OK"), 100) == 200);
        check("and so is a reported 199 ("
              + Sender.finalStatus(interimHeads(1, "HTTP/1.1 200 OK"), 199) + ")",
              Sender.finalStatus(interimHeads(1, "HTTP/1.1 200 OK"), 199) == 200);

        // And both ends of what is NOT 1xx stay untouched. 200 is the case
        // that matters: a final response is final, and re-reading the bytes
        // behind one would let a peer's leading head overrule the status the
        // transport actually produced.
        byte[] fiveHundredFirst = interimHeads(0, "HTTP/1.1 500 Internal Server Error");
        check("a reported 200 is never re-read from the bytes ("
              + Sender.finalStatus(fiveHundredFirst, 200) + ")",
              Sender.finalStatus(fiveHundredFirst, 200) == 200);
        check("and a reported 99 is not a 1xx either ("
              + Sender.finalStatus(fiveHundredFirst, 99) + ")",
              Sender.finalStatus(fiveHundredFirst, 99) == 99);
    }

    /**
     * `status: 599` is two different statements, and the frame has to say
     * which.
     *
     * STATUS_UNREADABLE is 599, and 599 is not a reserved code -- it is in
     * unofficial use for connect timeouts, which is precisely the class of
     * peer (a proxy fronting an origin) that also emits early hints. So the
     * two frames below were, before `outcome` carried the difference,
     * identical in every field an operator can act on:
     *
     *   8 interim heads then a real 200: {status=599, bytes=360, ms=12, outcome=ok}
     *   the peer itself answers 599:      {status=599, bytes=101, ms=12, outcome=ok}
     *
     * The first is the sharp one. That exchange SUCCEEDED -- the redacted
     * bytes attached to that very frame contain `HTTP/1.1 200 OK` -- and the
     * indexed status says 599, so an operator grepping for 5xx finds an
     * exchange whose own evidence contradicts the index. Reading 599 as
     * "unknown" instead mislabels the real proxy 599 in the other direction,
     * so NEITHER reading of the number alone is correct and the distinction
     * cannot live on `status`.
     *
     * What must NOT move to fix it: `status` stays 599 and Distress still
     * counts it, because an unreadable status has to keep reading as an error
     * to the auto-halt rather than as a healthy sample. The last check here
     * asserts exactly that -- the conservative property survived the fix.
     */
    static void theEvidenceLineSaysWhichKindOf599ThisIs(Path sentinel) {
        // (a) the scan ran out of budget. The status we report is ours.
        Rig unreadable = new Rig(sentinel);
        unreadable.http.reply =
                new HttpReply(103, interimHeads(8, "HTTP/1.1 200 OK"), 12L, false);
        Map<String, Object> u = unreadable.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());

        check("an unreadable status is still framed as a result (" + u.get("t") + ")",
              "result".equals(u.get("t")));
        check("and `status` is still the conservative 599 (" + u.get("status") + ")",
              Long.valueOf(599L).equals(u.get("status")));
        check("but `outcome` says the status could not be read (" + u.get("outcome") + ")",
              "status_unreadable".equals(u.get("outcome")));
        // The contradiction that made this a finding: the frame's own body.
        String evidence = new String((byte[]) u.get(BridgeClient.BODY_KEY),
                                     StandardCharsets.ISO_8859_1);
        check("the redacted bytes on that very frame carry the 200 the peer sent",
              evidence.contains("HTTP/1.1 200 OK"));

        // (b) the peer answered 599 itself. Same number, different statement.
        Rig peer = new Rig(sentinel);
        peer.http.reply = new HttpReply(
                599, interimHeads(0, "HTTP/1.1 599 Network Connect Timeout"), 12L, false);
        Map<String, Object> s = peer.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());

        check("a peer's own 599 is carried through unchanged (" + s.get("status") + ")",
              Long.valueOf(599L).equals(s.get("status")));
        check("and is NOT labelled unreadable (" + s.get("outcome") + ")",
              "ok".equals(s.get("outcome")));

        // The finding itself: without this field the two frames are the same.
        check("`outcome` is the ONLY field telling the two 599s apart",
              s.get("status").equals(u.get("status"))
              && !String.valueOf(s.get("outcome")).equals(String.valueOf(u.get("outcome"))));

        // A 599 read out of the BYTES behind interim heads is still the
        // peer's. Only the exhausted-budget ending is ours -- a predicate
        // written as `status == 599 && reported was 1xx` would get this wrong.
        Rig behind = new Rig(sentinel);
        behind.http.reply = new HttpReply(
                103, interimHeads(3, "HTTP/1.1 599 Network Connect Timeout"), 12L, false);
        Map<String, Object> b = behind.sender.issue(
                sendHeader(NOW + THIRTY_SECONDS), request("GET", "/api/orders"), authorised());
        check("a 599 read from the bytes behind interim heads is the peer's too ("
              + b.get("outcome") + ")",
              Long.valueOf(599L).equals(b.get("status")) && "ok".equals(b.get("outcome")));

        // AND THE PART THAT MUST NOT HAVE MOVED. Distress is fed the same 599
        // it was fed before `outcome` existed: ten identical answers is a 100%
        // 5xx rate and trips spec s4's auto-halt. If carrying the distinction
        // had softened the status into something Distress does not count, an
        // origin behind eight interim heads would hold a 0% 5xx rate forever
        // -- the exact blindness finalStatus was written to close.
        for (int i = 1; i < 10; i++)
            unreadable.sender.issue(sendHeader(NOW + THIRTY_SECONDS),
                                    request("GET", "/api/orders"), authorised());
        check("an unreadable status still counts as a 5xx to the auto-halt ("
              + unreadable.distress.stopReason() + ")",
              unreadable.distress.stopReason() != null
              && unreadable.distress.stopReason().startsWith("5xx rate 100.0%"));
    }

    /** {@code n} interim heads, then {@code last} -- which may be empty, for
     *  the response that never arrived. */
    static byte[] interimHeads(int n, String last) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n; i++)
            s.append("HTTP/1.1 103 Early Hints\r\nLink: </").append(i)
             .append(".css>; rel=preload\r\n\r\n");
        s.append(last.isEmpty() ? "" : last + "\r\nContent-Length: 0\r\n\r\n");
        return s.toString().getBytes(StandardCharsets.ISO_8859_1);
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

        // "integer, ONCE". ConfigBody accumulates repeated keys in order and
        // an Authorisation can be built without ever crossing it, so the rule
        // is enforced where the value is USED as well as where it arrives.
        // Without this, a doubly-set limit.rate_rps silently takes the first
        // and the operator's second answer is discarded unread -- and the two
        // orders differ, so which number the run gets depends on which line
        // they typed first.
        boolean twiceRefused = false;
        try {
            new Limits(clock, 5L, 2000L).arm(new BridgeClient.Authorisation(2L,
                    Map.of("limit.rate_rps", List.of("5", "99"))));
        } catch (IllegalArgumentException e) {
            twiceRefused = String.valueOf(e.getMessage()).contains("integer, once");
        }
        check("two answers to \"how fast\" is not a limit: a repeated key is refused",
              twiceRefused);

        boolean zeroRefused = false;
        try {
            new Limits(clock, 5L, 2000L).arm(new BridgeClient.Authorisation(2L,
                    Map.of("limit.max_requests", List.of("0"))));
        } catch (IllegalArgumentException e) {
            zeroRefused = true;
        }
        check("and a budget of zero is refused rather than defaulted to 2000", zeroRefused);

        // The CLASS is asserted, not just "not allowed". MEASURED on this
        // branch: change this branch's class from not_configured to
        // scope_denied and the whole Java suite stays at 9 x ALL PASS / 1375
        // ok / 0 FAIL. The class is what the agent switches on (s6) -- a
        // *_denied means "the answer will not change", which is the wrong
        // thing to tell a caller whose only problem is that no configure has
        // been acknowledged yet.
        Decision unarmed = new Limits(clock, 5L, 2000L).check(REQ);
        check("an unarmed gate denies rather than allowing", !unarmed.allowed());
        check("and it denies as not_configured (got " + unarmed.errorClass() + ")",
              "not_configured".equals(unarmed.errorClass()));
        check("naming the reason (got \"" + unarmed.detail() + "\")",
              "the rate and budget are not armed".equals(unarmed.detail()));
    }
}
