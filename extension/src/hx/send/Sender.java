// extension/src/hx/send/Sender.java
package hx.send;

import hx.bridge.BridgeClient;
import hx.policy.Clock;
import hx.policy.Decision;
import hx.policy.Distress;
import hx.policy.HxRequest;
import hx.policy.Policy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The chokepoint. Every request hx issues passes through issue(), and issue()
 * is the only thing in the extension that reaches anything capable of touching
 * a network -- through the injected Http, whose one implementation is built in
 * HxExtension. ChokepointTest asserts that structurally. Spec s4: "never add a
 * third egress path."
 *
 * Nothing in this file imports burp.*, and that is not tidiness. It is what
 * lets every refusal below be tested against a fake Http that counts its
 * calls, so the assertion can be "the request never left the JVM" rather than
 * the much weaker "an error came back".
 *
 * ORDER OF REFUSAL, and why it is this one:
 *
 *   0. bad_frame             you cannot decide about a request you cannot read.
 *   1. timeout               the caller has already given up. FIRST, because it
 *                            is the only check that costs nothing: Policy's
 *                            Gate is Limits, whose check() spends a rate token
 *                            and a budget slot, and spending either on a
 *                            request nothing is waiting for shortens the run
 *                            for no evidence.
 *   2. not_configured        DENY-ALL, read from the Authorisation snapshot.
 *   3. halted                halt frame, sentinel file, or auto-halt on target
 *                            distress.
 *   4. unmanaged_credential  before the Gate, for the same reason as 1.
 *   5. Policy                scope -> method -> dangerous -> rate -> budget.
 *
 * Steps 2-5 hold the pinned order -- not_configured, halted, scope_denied,
 * method_denied, dangerous_denied, rate_limited, budget_exhausted. Policy
 * checks not_configured too, and the duplication is deliberate: it is the
 * single most important check in the system, and repeating it here is what
 * lets the two halt checks run BEFORE the budget-consuming Gate without moving
 * any verdict out of its pinned position.
 */
public final class Sender {

    private final Policy policy;
    private final Redactor redactor;
    private final HaltSwitch halt;
    private final Distress distress;
    private final Http http;
    private final Clock clock;

    // Installed by HxExtension after construction, because it comes from the
    // BridgeClient and the Sender is what the BridgeClient is given. Volatile
    // for that cross-thread edge: written on Burp's initialize thread, read on
    // the read loop's.
    private volatile BridgeClient.HaltNotifier haltNotifier;

    // Auto-halt is announced once. Distress has no reset -- one distressed
    // host aborts the whole run and a human decides when it restarts -- so
    // every later send would push an identical frame at a run that is already
    // aborted for that same reason.
    private final AtomicBoolean announced = new AtomicBoolean(false);

    public Sender(Policy policy, Redactor redactor, HaltSwitch halt,
                  Distress distress, Http http, Clock clock) {
        this.policy = policy;
        this.redactor = redactor;
        this.halt = halt;
        this.distress = distress;
        this.http = http;
        this.clock = clock;
    }

    /**
     * Where the unsolicited `halted` frame goes.
     *
     * Spec s6: auto-halt is extension-initiated, so there is no outstanding id
     * to answer. Without this the stop is invisible until the next send fails,
     * and `run.status = 'aborted'` has no stop_reason to record -- the harness
     * cannot write down a reason nobody told it.
     */
    public void setHaltNotifier(BridgeClient.HaltNotifier n) { this.haltNotifier = n; }

    /**
     * Decide, issue, time, redact, answer.
     *
     * The Authorisation is a PARAMETER, not something read in here. It is read
     * exactly once per send, by BridgeClient's send arm, and carried down --
     * epoch and scope from one reference, so the scope a request was decided
     * under and the epoch stamped on its evidence line are the same commit.
     * configEpoch() and scopeConfig() are two reads of that one record and a
     * commit lands between them (393/400 trials, in the unsafe direction);
     * ChokepointTest asserts neither is called anywhere in extension/src.
     *
     * Returns a map ready to be framed as `result` or `error`. A result also
     * carries the redacted response bytes under BridgeClient.BODY_KEY, which
     * the framer removes and passes to Frame.encode as the body -- a flat JSON
     * header cannot carry them.
     *
     * There is nothing to clear. The ranges this extension injects are a
     * Redactor.Injected built per request FROM the bytes they are offsets
     * into and handed back to redactRequest with them; any other array is a
     * RangeError, so they cannot outlive the call --
     * which is the point: a registry kept on the Redactor is one a finally
     * here would clear on whichever thread happened to run issue(), while a
     * worker's copy leaked into its next request.
     *
     * A RangeError is a denial, never an allow (s4): nothing registers a
     * range until identity injection ships in Plan 5, so it cannot be raised
     * today -- but injection lands ON THIS METHOD, between the credential
     * refusal and the issue, and a range that will not fit the bytes in hand
     * says the frame describes a request other than this one.
     */
    public Map<String, Object> issue(Map<String, Object> header, byte[] body,
                                     BridgeClient.Authorisation auth) {
        try {
            return decideAndIssue(header, body, auth);
        } catch (Redactor.RangeError e) {
            return error(header.get("id"), "bad_frame",
                         "redaction range does not fit these bytes: " + e.getMessage());
        }
    }

    private Map<String, Object> decideAndIssue(Map<String, Object> header, byte[] body,
                                               BridgeClient.Authorisation auth) {
        Object id = header.get("id");

        // JSON numbers arrive as Long on this side; the pattern is the null
        // check as well as the type check.
        if (!(header.get("deadline_us") instanceof Long deadlineUs))
            return error(id, "bad_frame", "send frame has no deadline_us");

        HxRequest req;
        try {
            req = parse(header, body);
        } catch (IllegalArgumentException e) {
            return error(id, "bad_frame", e.getMessage());
        }

        long before = clock.nowUs();
        if (before >= deadlineUs)
            return error(id, "timeout", "deadline passed " + (before - deadlineUs)
                         + "us before this frame was decided; not issued");

        // Epoch 0 is the DENY-ALL Authorisation BridgeClient publishes before
        // any configure and after every disconnect. There is no other way to
        // get one: epochCounter is pre-incremented, so a real commit is >= 1.
        if (auth.epoch() == 0)
            return error(id, "not_configured", "no configure frame acknowledged yet");

        if (halt.halted()) {
            String why = halt.reason();
            return error(id, "halted", why == null ? "halted, no reason recorded" : why);
        }

        // Auto-halt. Distress is extension-initiated and has no reset: one
        // distressed host aborts the whole run (spec s4), and a human decides
        // when it restarts.
        String stop = distress.stopReason();
        if (stop != null)
            return error(id, "halted",
                         "target distress: " + stop + " on " + distress.stopHost());

        // s7: refused AND NEVER PERSISTED. Until identity injection registers
        // byte ranges, this is the only thing keeping a live client session
        // cookie out of a content-addressed blob store -- where, once written,
        // it is in every backup. This is the one item that cannot be
        // retrofitted.
        String credential = redactor.unmanagedCredential(req);
        if (credential != null)
            return error(id, "unmanaged_credential", "request carries a " + credential
                         + " header this extension did not inject");

        Decision d = policy.decide(req, auth);
        if (!d.allowed()) return error(id, d);

        HttpReply reply;
        try {
            reply = http.send(req, deadlineUs);
        } catch (IOException e) {
            // It tried. Distress has to see it: five consecutive connection
            // errors are one of the three auto-halt conditions in spec s4, and
            // a failure that never reaches the window is a failure that never
            // counts.
            distress.record(req.host(), 0, (clock.nowUs() - before) / 1000L, true);
            announceDistress();
            return error(id, "transport_error",
                         e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // MEASURED, not assumed: see finalStatus. The status Distress counts
        // has to be the FINAL response's, or a host that sends early hints
        // ahead of its 500s never trips the 20% rule -- one of the three
        // auto-halt conditions in spec s4 -- because every sample it recorded
        // was a 103.
        int status = finalStatus(reply.raw(), reply.status());
        distress.record(req.host(), status, reply.ms(), reply.connectionError());
        announceDistress();

        if (reply.connectionError())
            return error(id, "transport_error", "no response from " + req.host());

        long after = clock.nowUs();
        if (after >= deadlineUs)
            // The bytes exist, but the harness's _request() has already popped
            // this id and _deliver() drops a reply nobody is waiting for. Say
            // timeout rather than frame evidence the far side will discard.
            // Distress was fed above regardless: a host that answers slowly is
            // precisely what auto-halt watches for.
            return error(id, "timeout",
                         "response arrived " + (after - deadlineUs) + "us after the deadline");

        // Redaction runs BEFORE the bytes cross the bridge, because the blob
        // store on the far side is content-addressed: hashing raw bytes and
        // redacting afterwards means the raw bytes are already on disk.
        byte[] redacted = redactor.redactResponse(reply.raw());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("v", BridgeClient.PROTOCOL_VERSION);
        result.put("t", "result");
        result.put("id", id);
        result.put("status", (long) status);
        result.put("bytes", (long) redacted.length);
        result.put("ms", reply.ms());
        result.put("outcome", "ok");
        // The epoch that authorised the scope this was decided under, from the
        // same reference. An evidence line claiming authorisation from an
        // epoch that never granted it is worse than no evidence line.
        result.put("config_epoch", auth.epoch());
        result.put(BridgeClient.BODY_KEY, redacted);
        return result;
    }

    /**
     * Push the stop frame, the first time Distress has one to push.
     *
     * Called immediately after each record(), which is the only thing that can
     * turn stopReason() non-null, so "the first time" and "once" are the same
     * statement. The notifier is checked before the flag is spent: an
     * announcement nobody was listening for is not an announcement, and
     * burning the flag on it would lose the frame for good.
     */
    private void announceDistress() {
        String reason = distress.stopReason();
        if (reason == null) return;
        BridgeClient.HaltNotifier n = haltNotifier;
        if (n == null) return;
        if (!announced.compareAndSet(false, true)) return;
        n.halted(reason, distress.stopHost(), distress.window());
    }

    // ---- frame <-> wire ------------------------------------------------

    /**
     * Frame header plus raw request bytes -> the value Policy decides about.
     *
     * The destination is taken from the FRAME HEADER (target_host,
     * target_port, tls) and never from the request's own Host line. Burp
     * connects to the service we name, so the scope decision has to be about
     * that service; deciding on a Host header would let a request authorised
     * for app.example.test open a connection somewhere else entirely.
     *
     * Bytes are read as ISO-8859-1. Two reasons, both load-bearing: HTTP field
     * values are opaque octets rather than text, so UTF-8 would mangle a
     * Latin-1 cookie value and strict UTF-8 would refuse a request that is
     * perfectly legal on the wire; and ISO-8859-1 maps one octet to exactly
     * one char, so the string offsets below are byte offsets and the body
     * slice needs no re-encoding.
     */
    static HxRequest parse(Map<String, Object> header, byte[] body) {
        if (!(header.get("target_host") instanceof String host) || host.isEmpty())
            throw new IllegalArgumentException("send frame has no target_host");
        boolean tls = Boolean.TRUE.equals(header.get("tls"));
        long port = header.get("target_port") instanceof Long p ? p : (tls ? 443L : 80L);
        if (port < 1 || port > 65535)
            throw new IllegalArgumentException("target_port " + port + " is not a port");

        String text = new String(body, StandardCharsets.ISO_8859_1);
        int crlf = text.indexOf("\r\n\r\n");
        int lf = text.indexOf("\n\n");
        int headEnd, bodyStart;
        if (crlf >= 0 && (lf < 0 || crlf <= lf)) { headEnd = crlf; bodyStart = crlf + 4; }
        else if (lf >= 0) { headEnd = lf; bodyStart = lf + 2; }
        else { headEnd = text.length(); bodyStart = text.length(); }

        String[] lines = text.substring(0, headEnd).split("\r\n|\n", -1);
        if (lines.length == 0 || lines[0].isEmpty())
            throw new IllegalArgumentException("send body has no request line");
        String[] parts = lines[0].split(" ");
        if (parts.length < 2)
            throw new IllegalArgumentException("malformed request line: " + lines[0]);

        // NOT uppercased. HTTP methods are case-sensitive (RFC 9110 s9.1), and
        // `get` is what would go on the wire; normalising it here would let it
        // satisfy a method.allow of GET while the server sees something else.
        // Verbatim is the fail-closed direction.
        String method = parts[0];
        String target = parts[1];
        if (!target.startsWith("/"))
            // Absolute-form and authority-form both make the destination
            // ambiguous -- two answers to "where is this going" and only one of
            // them was authorised. OPTIONS * is not supported either; when it
            // is needed it needs its own scope answer, not this one.
            throw new IllegalArgumentException("request target must be origin-form: " + target);

        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue;
            int colon = line.indexOf(':');
            if (colon <= 0)
                throw new IllegalArgumentException("malformed header line: " + line);
            String name = line.substring(0, colon);
            if (!name.equals(name.strip()))
                // Whitespace between a field name and its colon is a request-
                // smuggling primitive: RFC 9112 s5.1 requires a recipient to
                // reject it, and recipients disagree about that in practice.
                // We refuse to reason about a header whose name we would have
                // to guess.
                throw new IllegalArgumentException("whitespace in header name: " + name);
            headers.computeIfAbsent(name, k -> new ArrayList<>()).add(line.substring(colon + 1).strip());
        }

        String path = target;
        String query = "";
        int q = target.indexOf('?');
        if (q >= 0) { path = target.substring(0, q); query = target.substring(q + 1); }

        boolean defaultPort = (tls && port == 443) || (!tls && port == 80);
        String url = (tls ? "https://" : "http://") + host
                   + (defaultPort ? "" : ":" + port) + target;

        // Frozen at both levels, like ConfigBody.parse, and here the ORDER is
        // load-bearing rather than a courtesy: wireBytes() emits headers in
        // iteration order, so an unordered copy would issue a different
        // request from the one Policy decided about.
        Map<String, List<String>> frozen = new LinkedHashMap<>();
        headers.forEach((k, v) -> frozen.put(k, List.copyOf(v)));
        return new HxRequest(method, url, host, path, query,
                             Collections.unmodifiableMap(frozen),
                             Arrays.copyOfRange(body, bodyStart, body.length));
    }

    /**
     * The request bytes to put on the wire.
     *
     * Public and static so HxExtension's Montoya adapter is three lines and
     * this mapping is testable without Burp. It reproduces exactly what
     * parse() accepted; what it does NOT reproduce is anything parse() refuses
     * (whitespace before a colon, absolute-form targets), the exact run of
     * spaces after a colon, an empty `?` with no query, and the interleaving of
     * headers with DIFFERENT names -- HxRequest groups by name, so
     * `A / B / A` is re-emitted as `A / A / B`. RFC 9110 s5.3 makes that
     * semantically identical, but a smuggling check that cares about field
     * order will not see the request it wrote. The fix is to hand Http the raw
     * frame body rather than reconstructing it; see the note in the plan.
     */
    public static byte[] wireBytes(HxRequest req) {
        StringBuilder s = new StringBuilder();
        s.append(req.method()).append(' ').append(req.path());
        if (!req.query().isEmpty()) s.append('?').append(req.query());
        s.append(" HTTP/1.1\r\n");
        req.headers().forEach((name, values) -> {
            for (String v : values) s.append(name).append(": ").append(v).append("\r\n");
        });
        s.append("\r\n");
        byte[] head = s.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[head.length + req.body().length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(req.body(), 0, out, head.length, req.body().length);
        return out;
    }

    /**
     * How many heads this will read before it gives up, counting the final one.
     * RFC 9110 s15.2 puts no ceiling on interim responses, and an unbounded
     * scan of a hostile response is a scan of whatever length that peer chose.
     *
     * So the tolerated number of INTERIM heads is one less than this: seven,
     * because the eighth iteration is the one that has to read the final head.
     * An earlier version of this javadoc said "how many heads a peer may put in
     * front of the final one", which reads as eight and was wrong -- measured,
     * 7 interim heads then a 500 answers 500 and 8 then a 500 does not.
     * SenderTest pins both sides, so this number cannot be changed silently in
     * either direction.
     */
    static final int MAX_INTERIM_HEADS = 8;

    /**
     * What an exhausted scan reports: a status Distress counts as an error.
     *
     * 599 is not a status any peer sent, and that is the point -- the
     * alternative is worse in the one direction this whole function exists to
     * close. When the scan runs out of budget the reported status is still the
     * INTERIM 1xx, and returning it would hand Distress a healthy sample for a
     * response whose real status we could not read: a peer that chooses how
     * many heads to send would then choose whether spec s4's 20% rule can ever
     * fire. A bound whose overflow behaviour is "fail open" is not a bound.
     *
     * It is inside 500..599, which is the range {@code Distress.tripOn5xxRate}
     * counts, so an origin hiding behind eight interim heads reads as broken
     * rather than as fine. On the evidence line it says the same thing to the
     * operator: this exchange did not produce a status we could stand behind.
     */
    public static final int STATUS_UNREADABLE = 599;

    /**
     * The status of the FINAL response in {@code raw}, which is NOT always the
     * one the transport reported.
     *
     * MEASURED, against Burp Suite Community Edition 2026.7.3-52685 on a
     * 103-then-200 exchange: {@code rr.response().statusCode()} answered
     * {@code 103}, and {@code rr.response().toByteArray()} carried BOTH heads
     * -- 275 bytes, interim head first, the real 200 and its body after it. So
     * Montoya parses the interim head as the response and hands the rest back
     * as bytes.
     *
     * That is fine for redaction, which reads the bytes and which
     * Redactor.redactResponse already scans head by head. It is not fine for
     * the status, which is read twice and matters both times: it is the
     * `status` on the evidence line, and it is what Distress counts 5xx from.
     * A host that sends `103 Early Hints` ahead of its 500s -- which is
     * exactly what a CDN in front of a failing origin does -- would otherwise
     * record fifty 103s, a 0% 5xx rate, and never trip spec s4's auto-halt.
     *
     * A 1xx is never the final response (RFC 9110 s15.2), so a reported 1xx is
     * the one case where the transport's answer can be improved on; anything
     * else is returned untouched. Nothing here guesses: if the bytes RUN OUT
     * before a later status line -- truncated mid-status-line, truncated after
     * a blank line, a line this cannot read at all -- the reported value
     * stands, because there is nothing there to have hidden anything behind.
     *
     * The one case that is NOT "the bytes ran out" is the scan running out of
     * BUDGET, and that one answers {@link #STATUS_UNREADABLE}: see there for
     * why the two endings must not give the same answer.
     */
    public static int finalStatus(byte[] raw, int reported) {
        // A null `raw` reaches redactResponse below, which answers it with a
        // RangeError and a bad_frame. It must not become an NPE here first.
        if (raw == null || reported < 100 || reported > 199) return reported;
        String text = new String(raw, StandardCharsets.ISO_8859_1);
        int i = 0;
        int head = 0;
        for (; head < MAX_INTERIM_HEADS && i < text.length(); head++) {
            int eol = text.indexOf('\n', i);
            if (eol < 0) return reported;
            int code = statusCodeOf(text.substring(i, eol));
            if (code < 100) return reported;        // not a status line: stop guessing
            if (code >= 200) return code;           // the final response
            // A 1xx head carries no body (RFC 9110 s15.2), so the next head
            // starts immediately after this one's blank line.
            int crlf = text.indexOf("\r\n\r\n", i);
            int lf = text.indexOf("\n\n", i);
            if (crlf >= 0 && (lf < 0 || crlf <= lf)) i = crlf + 4;
            else if (lf >= 0) i = lf + 2;
            else return reported;
        }
        // The scan gave up rather than ran out. Every head it read was a 1xx,
        // so the response IS still ahead of it somewhere and `reported` is
        // certainly not it -- the peer chose the head count, and it must not
        // get to choose the sample Distress records with it.
        if (head == MAX_INTERIM_HEADS) return STATUS_UNREADABLE;
        return reported;
    }

    /** The three-digit code of a status line, or -1 for a line that is not
     *  one. Deliberately strict: a line this cannot read is a line this must
     *  not report a status from. */
    private static int statusCodeOf(String line) {
        String s = line.strip();
        if (!s.startsWith("HTTP/")) return -1;
        int sp = s.indexOf(' ');
        if (sp < 0 || s.length() < sp + 4) return -1;
        int code = 0;
        for (int k = sp + 1; k < sp + 4; k++) {
            char c = s.charAt(k);
            if (c < '0' || c > '9') return -1;
            code = code * 10 + (c - '0');
        }
        return code;
    }

    /** True when the url this request was authorised under is https. */
    public static boolean secureOf(HxRequest req) {
        return req.url().startsWith("https://");
    }

    /**
     * The port the url encodes, or the scheme default.
     *
     * IPv6 TARGETS ARE NOT USABLE TODAY, and the failure is here rather than in
     * the scope rules. MEASURED: a send frame with {@code target_host:
     * "2001:db8::1"} and {@code target_port: 443} builds the url
     * {@code https://2001:db8::1/x} -- parse() omits a default port, so the
     * authority is a bare IPv6 literal with no brackets -- and this method
     * takes the text after its LAST colon and answers {@code 1}. The BRACKETED
     * form ({@code [2001:db8::1]}) answers 443 correctly.
     *
     * It fails CLOSED right now only because Policy scope-denies every IPv6 url
     * tried against it, so nothing reaches this method. That is one accident
     * away from being a connection to port 1 of an address the operator asked
     * for on 443. WHOEVER FIXES THE SCOPE SIDE MUST FIX THIS SIDE IN THE SAME
     * CHANGE: bracket the literal in parse() (and then the lastIndexOf(']')
     * guard below starts doing the job it was written for), or refuse an
     * unbracketed literal outright. Parked in the ledger as F9; do not close
     * half of it.
     */
    public static int portOf(HxRequest req) {
        boolean tls = secureOf(req);
        String rest = req.url().substring(tls ? 8 : 7);
        int slash = rest.indexOf('/');
        String authority = slash < 0 ? rest : rest.substring(0, slash);
        // An IPv6 literal is full of colons; only one after the closing
        // bracket is a port.
        int colon = authority.lastIndexOf(':');
        if (colon < 0 || colon < authority.lastIndexOf(']')) return tls ? 443 : 80;
        try {
            return Integer.parseInt(authority.substring(colon + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("no port in " + req.url(), e);
        }
    }

    // ---- replies -------------------------------------------------------

    private static Map<String, Object> error(Object id, String cls, String detail) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("v", BridgeClient.PROTOCOL_VERSION);
        e.put("t", "error");
        e.put("id", id);
        e.put("class", cls);
        e.put("detail", detail);
        return e;
    }

    private static Map<String, Object> error(Object id, Decision d) {
        Map<String, Object> e = error(id, d.errorClass(), d.detail());
        if ("rate_limited".equals(d.errorClass()))
            // s6: the one class that carries a retry hint. rate_limited means
            // slow down and try again; the three *_denied classes mean the
            // answer will not change however long you wait.
            e.put("retry_after_us", d.retryAfterUs());
        return e;
    }
}
