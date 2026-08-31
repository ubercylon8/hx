// extension/test/hx/send/IdentityInjectionTest.java
package hx.send;

import hx.TestSupport;
import hx.bridge.BridgeClient;
import hx.policy.Decision;
import hx.policy.Distress;
import hx.policy.Gate;
import hx.policy.HxRequest;
import hx.policy.Policy;
import hx.policy.TickClock;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Identity injection on the send path: WHERE it happens, WHAT it writes, and
 * what it tells the Redactor about the bytes it wrote.
 *
 * THE ORDER IS THE WHOLE TASK. Injection composes a request carrying a live
 * credential, so it happens AFTER every gate -- scope, method, dangerous,
 * unmanaged credential, rate, budget. A refused request must never have had a
 * credential written into it, because the only thing standing between such a
 * request and the wire would be the refusal returning in time.
 * {@link #aRequestTheGateREFUSEDNeverHasACredentialWrittenIntoIt} is the test
 * that fails when that order is reversed, and it is written to fail on the
 * REVERSAL rather than on a symptom of it: see its own comment for the
 * measurement.
 *
 * NO BARE `assert` ANYWHERE IN THIS FILE. `extension/test.sh` passes no `-ea`,
 * so a Java assertion is a no-op and a suite written with them prints ALL PASS
 * whether or not the code works -- which is exactly what this plan's Task 4
 * sketch would have produced, `assert r.get("user").origins().size() == 1;`
 * and eleven more like it. Every claim below goes through {@link #check}.
 */
public class IdentityInjectionTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard, so a throw is a
     *  named FAIL rather than a truncated run with no summary line.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(IdentityInjectionTest::check, name, body);
    }

    static final long NOW = 1_787_355_131_378_277L;
    static final long THIRTY_SECONDS = 30_000_000L;

    /** The credential. Distinctive on purpose: every "did this leak" and "was
     *  this written" check below looks for THESE bytes. */
    static final String SECRET = "session=INJECTED_9f1c4a2e7b; Path=/";

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("hxinject");
        Path sentinel = dir.resolve("halt");          // deliberately absent
        try {
            t("anAbsentIdentityIdIssuesAnonymouslyAsBefore",
              () -> anAbsentIdentityIdIssuesAnonymouslyAsBefore(sentinel));
            t("aKnownIdentityHasItsHeaderInjectedIntoTheWireBytes",
              () -> aKnownIdentityHasItsHeaderInjectedIntoTheWireBytes(sentinel));
            t("anUnknownIdentityIdIsRefusedRatherThanIssuedAnonymously",
              () -> anUnknownIdentityIdIsRefusedRatherThanIssuedAnonymously(sentinel));
            t("aHostOutsideTheIdentitysOriginsIsRefused",
              () -> aHostOutsideTheIdentitysOriginsIsRefused(sentinel));
            t("theInjectedRangeIsRegisteredSoTheStoredCopyIsRedacted",
              IdentityInjectionTest::theInjectedRangeIsRegisteredSoTheStoredCopyIsRedacted);
            t("aRequestTheGateREFUSEDNeverHasACredentialWrittenIntoIt",
              () -> aRequestTheGateREFUSEDNeverHasACredentialWrittenIntoIt(sentinel));
            t("unmanagedCredentialStillFiresForAHeaderTheCallerSupplied",
              () -> unmanagedCredentialStillFiresForAHeaderTheCallerSupplied(sentinel));
            t("theIdentityHeaderReplacesOneTheCallerSentUnderTheSameName",
              () -> theIdentityHeaderReplacesOneTheCallerSentUnderTheSameName(sentinel));
            t("httpIsHandedThePostInjectionRequestAndItsExactBytes",
              () -> httpIsHandedThePostInjectionRequestAndItsExactBytes(sentinel));
            t("originsAreMatchedByHostAndNeverBySuffix",
              IdentityInjectionTest::originsAreMatchedByHostAndNeverBySuffix);
            t("aDegenerateIdentityIsRefusedRatherThanIssuedWithABogusRange",
              () -> aDegenerateIdentityIsRefusedRatherThanIssuedWithABogusRange(sentinel));
        } finally {
            Files.deleteIfExists(sentinel);
            Files.deleteIfExists(dir);
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- doubles -------------------------------------------------------

    /**
     * Counts, records the bytes, and records the request.
     *
     * `wire` is a PARAMETER of Http.send rather than something the fake builds
     * from `req`, which is what makes "the exact bytes that would have gone to
     * Burp" assertable here at all.
     */
    static final class FakeHttp implements Http {
        int calls = 0;
        HxRequest last;
        byte[] lastWire;
        HttpReply reply = new HttpReply(200, RESPONSE, 12L, false);
        public HttpReply send(HxRequest req, byte[] wire, long deadlineUs) {
            calls++;
            last = req;
            lastWire = wire;
            return reply;
        }
    }

    /**
     * A Gate that answers what it is told to AND records the request it was
     * asked about.
     *
     * The recording half is not decoration. Policy is asked in two calls and
     * the Gate is the SECOND, so the request this saw is the request as it
     * stood at the last moment anything could still refuse it -- which is
     * precisely the moment a credential must not yet have been written into.
     */
    static final class WatchingGate implements Gate {
        int calls = 0;
        HxRequest seen;
        Decision verdict = Decision.allow();
        public Decision check(HxRequest req) { calls++; seen = req; return verdict; }
    }

    /** One Sender and every double it was built from. */
    static final class Rig {
        final TickClock clock = new TickClock(NOW);
        final WatchingGate gate = new WatchingGate();
        final FakeHttp http = new FakeHttp();
        final Redactor redactor = new Redactor();
        final IdentityRegistry identities = new IdentityRegistry();
        final HaltSwitch halt;
        final Distress distress;
        final Sender sender;

        Rig(Path sentinel) {
            // start() is deliberately NOT called: a background poller would
            // make these assertions time-dependent, and the sentinel is absent.
            halt = new HaltSwitch(clock, sentinel, HaltSwitch.DEFAULT_POLL_MS);
            distress = new Distress(clock, 0.20, 5.0, 5);
            sender = new Sender(new Policy(gate), redactor, halt, distress, http, clock,
                                identities);
        }

        /** The identity every test here injects, unless it says otherwise. */
        void registerUser() {
            identities.register("user", 3, "Cookie", SECRET,
                                List.of("https://app.example.test"));
        }
    }

    // ---- fixtures ------------------------------------------------------

    static final byte[] RESPONSE = ("HTTP/1.1 200 OK\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: 15\r\n"
            + "\r\n"
            + "{\"orders\":[42]}").getBytes(StandardCharsets.ISO_8859_1);

    /**
     * TWO hosts in scope, and that is what makes `identity_origin` testable at
     * all: an identity's origins have to be checkable against a host the SCOPE
     * allows, or the request is refused `scope_denied` long before anything
     * looks at an identity, and the test would pass without the rule existing.
     */
    static BridgeClient.Authorisation authorised() {
        Map<String, List<String>> scope = new LinkedHashMap<>();
        scope.put("scope.include", List.of("https://app.example.test/*",
                                           "https://third-party.example.test/*"));
        scope.put("method.allow", List.of("GET", "HEAD", "OPTIONS"));
        scope.put("dangerous.path", List.of("*/logout*"));
        return new BridgeClient.Authorisation(7L, Collections.unmodifiableMap(scope));
    }

    static Map<String, Object> sendHeader(String host, String identityId) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("v", 1L);
        h.put("t", "send");
        h.put("id", 41L);
        h.put("deadline_us", NOW + THIRTY_SECONDS);
        h.put("engagement_id", "e-1");
        h.put("identity_id", identityId);
        h.put("target_host", host);
        h.put("target_port", 443L);
        h.put("tls", true);
        return h;
    }

    static byte[] request(String host, String... nameThenValue) {
        StringBuilder s = new StringBuilder();
        s.append("GET /api/orders HTTP/1.1\r\n");
        s.append("Host: ").append(host).append("\r\n");
        s.append("User-Agent: hx/0.1\r\n");
        for (int i = 0; i < nameThenValue.length; i += 2)
            s.append(nameThenValue[i]).append(": ").append(nameThenValue[i + 1]).append("\r\n");
        s.append("\r\n");
        return s.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    static String text(byte[] b) { return new String(b, StandardCharsets.ISO_8859_1); }

    // ---- the cases -----------------------------------------------------

    static void anAbsentIdentityIdIssuesAnonymouslyAsBefore(Path sentinel) {
        Rig rig = new Rig(sentinel);
        rig.registerUser();
        // The identity is REGISTERED and the frame does not name it. Absent
        // means anonymous, and a registry with something in it must not change
        // that -- an identity applied because it happened to exist is a
        // credential nobody asked to send.
        Map<String, Object> reply = rig.sender.issue(
                sendHeader("app.example.test", null),
                request("app.example.test"), authorised());
        check("an anonymous send is still a result (got " + reply.get("t") + ")",
              "result".equals(reply.get("t")));
        check("and it reached the wire", rig.http.calls == 1);
        check("and the bytes carry no credential", !text(rig.http.lastWire).contains(SECRET));
        check("and no Cookie header at all",
              !text(rig.http.lastWire).contains("Cookie"));

        // A blank id is absent too: an empty string is what an unset field
        // arrives as often enough that it must not mean "look up the identity
        // called nothing".
        Rig blank = new Rig(sentinel);
        blank.registerUser();
        check("a blank identity_id is anonymous, not unknown_identity",
              "result".equals(blank.sender.issue(
                      sendHeader("app.example.test", "   "),
                      request("app.example.test"), authorised()).get("t")));
    }

    static void aKnownIdentityHasItsHeaderInjectedIntoTheWireBytes(Path sentinel) {
        Rig rig = new Rig(sentinel);
        rig.registerUser();
        Map<String, Object> reply = rig.sender.issue(
                sendHeader("app.example.test", "user"),
                request("app.example.test"), authorised());
        check("the send is issued (got " + reply.get("t") + ")",
              "result".equals(reply.get("t")));
        check("exactly once", rig.http.calls == 1);

        String wire = text(rig.http.lastWire);
        check("the credential is on the wire", wire.contains("Cookie: " + SECRET + "\r\n"));
        // IMMEDIATELY AFTER THE REQUEST LINE, which is not a style choice:
        // compose() measures the credential's byte offset from the length of
        // the request line, so anywhere else would need the lengths of every
        // header in front of it.
        check("immediately after the request line",
              wire.startsWith("GET /api/orders HTTP/1.1\r\nCookie: " + SECRET + "\r\n"));
        check("and the caller's own headers are still there, in order",
              wire.contains("\r\nHost: app.example.test\r\nUser-Agent: hx/0.1\r\n"));
        check("and the request still ends with a blank line", wire.endsWith("\r\n\r\n"));
    }

    static void anUnknownIdentityIdIsRefusedRatherThanIssuedAnonymously(Path sentinel) {
        Rig rig = new Rig(sentinel);
        rig.registerUser();                       // "user" exists; "ghost" does not
        Map<String, Object> reply = rig.sender.issue(
                sendHeader("app.example.test", "ghost"),
                request("app.example.test"), authorised());
        // FAIL CLOSED. Issuing anonymously here is the single outcome the
        // whole feature exists to prevent: a `clean` answer about a view no
        // user is in.
        check("an unknown identity is an error (got " + reply.get("t") + ")",
              "error".equals(reply.get("t")));
        check("with class unknown_identity (got " + reply.get("class") + ")",
              "unknown_identity".equals(reply.get("class")));
        check("the detail names the id that was asked for",
              String.valueOf(reply.get("detail")).contains("ghost"));
        check("IT NEVER REACHED THE WIRE (fake Http saw " + rig.http.calls + " call(s))",
              rig.http.calls == 0);
        check("and no bytes were handed to it at all", rig.http.lastWire == null);
        check("the reply carries no response body",
              !reply.containsKey(BridgeClient.BODY_KEY));
    }

    static void aHostOutsideTheIdentitysOriginsIsRefused(Path sentinel) {
        Rig rig = new Rig(sentinel);
        rig.registerUser();                 // origins: https://app.example.test only
        Map<String, Object> reply = rig.sender.issue(
                sendHeader("third-party.example.test", "user"),
                request("third-party.example.test"), authorised());
        // The host is IN SCOPE -- authorised() includes it -- so this refusal
        // is the origins rule and nothing else. Scope and origins answer
        // different questions and both have to say yes.
        //
        // AND THIS REGISTRATION IS WHAT PRODUCTION NOW SENDS. F1 of the
        // whole-branch review measured that it was not: `origins` was the
        // engagement's whole `scope.include`, so a registration naming one
        // host while another was in scope could not arise, and this test
        // proved a rule against a configuration the Python side could never
        // build. Since the 2026-08-30 amendment to spec s5,
        // `hx.scan._identity_bracket` registers the single host its liveness
        // canary is addressed to, which is exactly the shape rig.registerUser()
        // builds -- so what this refuses is the ordinary multi-host scan.
        check("the gate allowed the host", rig.gate.calls == 1);
        check("a host outside the identity's origins is an error (got "
              + reply.get("t") + ")", "error".equals(reply.get("t")));
        check("with class identity_origin (got " + reply.get("class") + ")",
              "identity_origin".equals(reply.get("class")));
        check("the detail names the identity and the host it was refused for",
              String.valueOf(reply.get("detail")).contains("user")
              && String.valueOf(reply.get("detail")).contains("third-party.example.test"));
        check("THE CREDENTIAL NEVER LEFT (fake Http saw " + rig.http.calls + " call(s))",
              rig.http.calls == 0);
        check("and the refusal itself does not quote it",
              !String.valueOf(reply.get("detail")).contains(SECRET));

        // ...and the same identity against a host it IS registered for goes.
        Rig ok = new Rig(sentinel);
        ok.registerUser();
        check("the same identity is applied to a host it IS registered for",
              "result".equals(ok.sender.issue(
                      sendHeader("app.example.test", "user"),
                      request("app.example.test"), authorised()).get("t")));
    }

    /**
     * The stored copy is what reaches the blob store, and the blob store is
     * content-addressed -- so an unredacted credential is not merely stored,
     * it becomes an address that exists in every backup. Spec s7 calls this
     * the one item that cannot be retrofitted.
     *
     * compose() is driven directly, because the registration's whole purpose
     * is to be usable by whatever redacts these bytes, and redactRequest is
     * how that is checked: it refuses any array other than the one the ranges
     * were measured from, so this passing at all is also the proof that the
     * Injected names the array compose() returned.
     */
    static void theInjectedRangeIsRegisteredSoTheStoredCopyIsRedacted() {
        HxRequest req = Sender.parse(sendHeader("app.example.test", "user"),
                                     request("app.example.test"));
        IdentityRegistry.Entry ident = new IdentityRegistry.Entry(
                "user", 3, "Cookie", SECRET, List.of("https://app.example.test"));
        Sender.Composed composed = Sender.compose(req, ident);

        check("the composed bytes carry the credential",
              text(composed.wire()).contains(SECRET));
        String redacted = text(new Redactor().redactRequest(composed.wire(),
                                                            composed.injected()));
        check("the redacted copy does NOT (" + redacted.replace("\r\n", " | ") + ")",
              !redacted.contains(SECRET));
        check("and carries the placeholder in its place",
              redacted.contains("Cookie: {{identity:user:authz}}\r\n"));
        check("and is otherwise the same request",
              redacted.startsWith("GET /api/orders HTTP/1.1\r\n")
              && redacted.contains("Host: app.example.test\r\n")
              && redacted.contains("User-Agent: hx/0.1\r\n"));

        // The ANONYMOUS composition registers nothing, so redaction is a copy
        // -- which is what every send has been doing in spirit since Redactor
        // shipped, and is the shape that would leak if a range were missing.
        Sender.Composed anon = Sender.compose(req, null);
        check("an anonymous composition has nothing to redact",
              text(new Redactor().redactRequest(anon.wire(), anon.injected()))
                      .equals(text(anon.wire())));
    }

    /**
     * THE SAFETY PROPERTY OF THIS TASK.
     *
     * A request the gate refused must never have had a credential written into
     * it. If injection ran first, an out-of-scope or budget-exhausted send
     * would compose a request carrying a live session cookie, and the only
     * thing standing between that and the wire would be the refusal returning
     * in time.
     *
     * WHAT MAKES THIS FAIL WHEN THE ORDER IS REVERSED, rather than merely pass
     * when it is right: the request below names an identity the registry does
     * NOT hold AND is refused by the gate. Both refusals are available and
     * only one can be answered, so the CLASS names which step ran first.
     * Under the shipped order the answer is the gate's; move the identity
     * block above `policy.checkGate` and the same input answers
     * `unknown_identity`. MEASURED with exactly that edit -- the block cut and
     * pasted above the `policy.checkGate` call, nothing else touched -- this
     * class exits 1 with 2 FAIL: `the GATE answers first, not the identity
     * step (got unknown_identity)` here, and `the gate allowed the host` in
     * aHostOutsideTheIdentitysOriginsIsRefused, which sees the same move from
     * the other side.
     *
     * The checks after it are the same statement about the KNOWN identity,
     * where the Http fake takes the wire bytes as a parameter so
     * `lastWire == null` is "no request was ever handed on", and the Gate
     * records the request it was asked about so a credential written into
     * `req` before the gate would show up there.
     *
     * WHAT THIS CANNOT SEE, said plainly. If `compose` alone were moved above
     * the gate -- the bytes built, the credential written into them, and the
     * gate then refusing -- nothing here would go red, because a composition
     * that is discarded leaves no trace an outside test can read. The
     * discriminator above is the REFUSAL ORDER, which is what the published
     * decision order is about and what a reviewer can check by reading; the
     * composition's position is held by the comment in decideAndIssue and by
     * that comment sitting between the gate and the issue.
     */
    static void aRequestTheGateREFUSEDNeverHasACredentialWrittenIntoIt(Path sentinel) {
        Rig rig = new Rig(sentinel);
        rig.gate.verdict = Decision.deny("budget_exhausted", "run budget of 100 spent");
        Map<String, Object> reply = rig.sender.issue(
                sendHeader("app.example.test", "ghost"),
                request("app.example.test"), authorised());
        check("the GATE answers first, not the identity step (got "
              + reply.get("class") + ")", "budget_exhausted".equals(reply.get("class")));
        check("and nothing was issued", rig.http.calls == 0);

        // The same refusal with an identity that IS held: the case where an
        // injection running early would have written a live credential.
        Rig known = new Rig(sentinel);
        known.registerUser();
        known.gate.verdict = Decision.deny("rate_limited", "rate limit 5/s");
        Map<String, Object> refused = known.sender.issue(
                sendHeader("app.example.test", "user"),
                request("app.example.test"), authorised());
        check("a rate-limited send naming a HELD identity is still the gate's refusal",
              "rate_limited".equals(refused.get("class")));
        check("NO REQUEST WAS EVER COMPOSED FOR IT (wire bytes handed on: "
              + (known.http.lastWire == null ? "none" : "some") + ")",
              known.http.lastWire == null && known.http.calls == 0);
        check("and the request the gate was asked about carried no credential",
              known.gate.seen != null && !known.gate.seen.headers().containsKey("Cookie"));
        check("and the refusal does not quote the credential either",
              !String.valueOf(refused.get("detail")).contains(SECRET));

        // The FIRST half of Policy refuses even earlier, and the identity step
        // is behind that too: an out-of-scope host with an unknown identity is
        // a scope violation, which is the evidence an operator needs.
        Rig outOfScope = new Rig(sentinel);
        Map<String, Object> scope = outOfScope.sender.issue(
                sendHeader("elsewhere.example.test", "ghost"),
                request("elsewhere.example.test"), authorised());
        check("an out-of-scope send is scope_denied, not unknown_identity (got "
              + scope.get("class") + ")", "scope_denied".equals(scope.get("class")));
        check("and its gate was never even reached, so nothing was spent",
              outOfScope.gate.calls == 0 && outOfScope.http.calls == 0);
    }

    static void unmanagedCredentialStillFiresForAHeaderTheCallerSupplied(Path sentinel) {
        Rig rig = new Rig(sentinel);
        rig.registerUser();
        // s7 point 5: injection does not weaken this refusal, it is what
        // finally gives it an alternative. The frame names a REGISTERED
        // identity and ALSO carries a Cookie of its own -- the request is
        // still refused, because the extension did not put that one there.
        Map<String, Object> reply = rig.sender.issue(
                sendHeader("app.example.test", "user"),
                request("app.example.test", "Cookie", "session=THE_CALLERS_OWN"),
                authorised());
        check("a caller-supplied credential is still refused (got "
              + reply.get("class") + ")",
              "unmanaged_credential".equals(reply.get("class")));
        check("and nothing was issued", rig.http.calls == 0);
        // BEFORE the Gate, which is where that refusal has always been: a
        // request about to be refused must not spend a rate token or a budget
        // slot.
        check("and the Gate was never asked, so nothing was spent", rig.gate.calls == 0);
    }

    /**
     * DEFENCE IN DEPTH ON A STATE THE CONFIGURATION FORBIDS, and it is kept
     * because it is that, not because the state is reachable.
     *
     * The collision this pins -- the caller sending a header under the
     * identity's own name -- cannot happen in production, and the reason has
     * two independent halves. `hx.config` refuses any `inject.header` outside
     * `Cookie`, `Authorization` and `Proxy-Authorization` at load
     * (src/hx/config.py:130-134), so no fourth name can be configured; and
     * those three, sent by the caller, are refused `unmanaged_credential`
     * before injection is reached at all. Since the Task 5 fix round
     * `IdentityRegistry.register` refuses the fourth name too, on the
     * extension's own account -- which is why this method now builds the Entry
     * DIRECTLY and drives `compose()`, exactly as
     * {@link #aDegenerateIdentityIsRefusedRatherThanIssuedWithABogusRange}
     * does and for the same reason: there is no frame that reaches the send
     * path with one, and the last arm below is what says so.
     *
     * What is still worth pinning is `withHeaderFirst`'s SEMANTICS: two values
     * for one field name would leave the server to choose which, and a check
     * could then read an answer given to the caller's own credential and file
     * it as the identity's.
     */
    static void theIdentityHeaderReplacesOneTheCallerSentUnderTheSameName(Path sentinel) {
        IdentityRegistry.Entry ident = new IdentityRegistry.Entry(
                "api", 1, "X-Api-Key", "KEY_FROM_THE_IDENTITY",
                List.of("https://app.example.test"));
        String wire = text(Sender.compose(
                Sender.parse(sendHeader("app.example.test", "api"),
                             request("app.example.test", "X-Api-Key",
                                     "KEY_THE_CALLER_CHOSE")),
                ident).wire());
        check("the identity's value is what goes out",
              wire.contains("X-Api-Key: KEY_FROM_THE_IDENTITY\r\n"));
        check("and the caller's value is gone rather than sent alongside it",
              !wire.contains("KEY_THE_CALLER_CHOSE"));
        check("exactly one X-Api-Key header goes out",
              wire.split("X-Api-Key", -1).length - 1 == 1);

        // Field names are case-insensitive (RFC 9110 s5.1), so the collision is
        // matched that way too -- otherwise `x-api-key` from the caller would
        // ride out beside the identity's `X-Api-Key`.
        String cased = text(Sender.compose(
                Sender.parse(sendHeader("app.example.test", "api"),
                             request("app.example.test", "x-api-key",
                                     "KEY_THE_CALLER_CHOSE")),
                ident).wire());
        check("a differently-cased duplicate is replaced too",
              !cased.contains("KEY_THE_CALLER_CHOSE"));

        // ...and the Entry above could not have come off the wire. This is the
        // arm that keeps the javadoc honest: if registration ever stopped
        // refusing the name, this method would be testing a live path while
        // claiming to test a foreclosed one.
        check("and the registry refuses to hold a fourth header name anyway",
              registerRefused(new Rig(sentinel), "KEY_FROM_THE_IDENTITY",
                              "X-Api-Key"));
    }

    /**
     * Http gets the POST-injection request and the POST-injection bytes, and
     * they describe each other.
     *
     * Http takes the composed bytes as a parameter precisely so that the array
     * the Injected was measured from is the array that goes to Burp;
     * re-serialising the HxRequest downstream would produce a third array that
     * no range set names, and Redactor.Injected compares by IDENTITY rather
     * than by content, so that mistake would not be visible by reading the
     * bytes. WHAT THIS CHECKS is the half that IS visible from out here: both
     * arguments have had the identity applied, so an implementation reading
     * either one sees the same request. The array-identity half is held by
     * compose() returning both from one local.
     */
    static void httpIsHandedThePostInjectionRequestAndItsExactBytes(Path sentinel) {
        Rig rig = new Rig(sentinel);
        rig.registerUser();
        rig.sender.issue(sendHeader("app.example.test", "user"),
                         request("app.example.test"), authorised());
        check("Http was handed both a request and its bytes",
              rig.http.lastWire != null && rig.http.last != null);
        check("and they are the ones carrying the credential",
              text(rig.http.lastWire).contains(SECRET));
        check("and the HxRequest handed alongside them carries the header too, "
              + "first", rig.http.last.headers().keySet().iterator().next()
                      .equals("Cookie"));
        check("...while the destination it names is unchanged",
              "app.example.test".equals(rig.http.last.host())
              && "https://app.example.test/api/orders".equals(rig.http.last.url()));
    }

    static void originsAreMatchedByHostAndNeverBySuffix() {
        HxRequest at = Sender.parse(sendHeader("app.example.test", "user"),
                                    request("app.example.test"));
        // An origin written as a URL contributes its authority's host; one
        // written as a bare host contributes itself. Both spellings reach this
        // rule: spec s5's example is a URL, and `scope.include` hosts are what
        // the default is built from.
        check("a URL origin matches its host",
              Sender.appliesTo(entry("https://app.example.test"), at));
        check("a URL origin with a path matches too",
              Sender.appliesTo(entry("https://app.example.test/portal"), at));
        check("a port in the origin does not stop it matching",
              Sender.appliesTo(entry("https://app.example.test:8443"), at));
        check("a bare host matches", Sender.appliesTo(entry("app.example.test"), at));
        check("and case does not matter, because host names are case-insensitive",
              Sender.appliesTo(entry("HTTPS://APP.EXAMPLE.TEST"), at));

        // EXACT, and never a suffix. This is the whole value of the rule: a
        // credential must not follow a name that merely ends the same way.
        check("a different host does not match",
              !Sender.appliesTo(entry("https://other.example.test"), at));
        check("a SUBDOMAIN of the origin does not match",
              !Sender.appliesTo(entry("https://example.test"), at));
        check("and a host that merely ends with the origin does not match",
              !Sender.appliesTo(entry("https://evil-app.example.test"), at));
        check("nor does the origin as a bare suffix",
              !Sender.appliesTo(entry("example.test"), at));
        check("one matching origin among several is enough",
              Sender.appliesTo(new IdentityRegistry.Entry("user", 1, "Cookie", SECRET,
                      List.of("https://other.test", "https://app.example.test")), at));
    }

    static IdentityRegistry.Entry entry(String origin) {
        return new IdentityRegistry.Entry("user", 1, "Cookie", SECRET, List.of(origin));
    }

    /**
     * A range that names no bytes refuses the SEND rather than issuing one
     * whose redaction cannot be trusted.
     *
     * `IdentityRegistry.register` refuses a blank value, so this Entry cannot
     * come off the wire -- it is built here directly, which is also why the
     * case is driven at compose() rather than through issue(): there is no
     * frame that reaches the send path with one. That is the point of the
     * guard, which is defence in depth for the day something else can
     * construct an Entry. Where the RangeError GOES is issue()'s existing
     * catch, which answers `bad_frame` before anything is issued; that catch is
     * pinned by SenderTest.aRedactionFailureIsRefusedRatherThanFramed, which
     * reaches it through the other input -- a response the redactor cannot
     * read -- and not by this method.
     */
    static void aDegenerateIdentityIsRefusedRatherThanIssuedWithABogusRange(Path sentinel) {
        Rig rig = new Rig(sentinel);
        boolean refused = false;
        try {
            Sender.compose(Sender.parse(sendHeader("app.example.test", "user"),
                                        request("app.example.test")),
                           new IdentityRegistry.Entry("user", 1, "Cookie", "",
                                   List.of("https://app.example.test")));
        } catch (Redactor.RangeError e) {
            refused = true;
        }
        check("a zero-length credential is a RangeError rather than a range "
              + "naming nothing", refused);
        check("and the registry would never have produced one anyway",
              registerRefused(rig, "", "Cookie"));
    }

    static boolean registerRefused(Rig rig, String value, String header) {
        try {
            rig.identities.register("blank", 1, header, value,
                                    List.of("https://app.example.test"));
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }
}
