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
import java.util.Locale;
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
 *   4. Policy, first half    scope -> method -> dangerous. None of them spends
 *                            anything, so they cost nothing to run early.
 *   5. unmanaged_credential  BETWEEN the two halves. Before the Gate for the
 *                            same reason as 1; after 4 because running it
 *                            first made an out-of-scope request carrying a
 *                            Cookie into a credential error, naming the
 *                            credential rather than the boundary crossed.
 *                            (The class had no `denial` row at all until
 *                            SCHEMA_VERSION 6 gave it `kind='credential'`, so
 *                            the scope violation was then recorded nowhere;
 *                            the ordering stands on the first reason alone.)
 *   6. Policy, second half   the Gate: rate -> budget.
 *   7. unknown_identity      LAST, with identity_origin beside it, and the
 *   8. identity_origin       position is spec s7's: injection composes a
 *                            request carrying a live credential, so it happens
 *                            after every gate -- a refused request must never
 *                            have had one written into it. These two are the
 *                            only refusals that need an identity in hand, and
 *                            they are the last things on this path that can
 *                            refuse at all.
 *
 * Steps 2-6 hold the pinned order -- not_configured, halted, scope_denied,
 * method_denied, dangerous_denied, rate_limited, budget_exhausted. Policy
 * checks not_configured too, and the duplication is deliberate: it is the
 * single most important check in the system, and repeating it here is what
 * lets the two halt checks run BEFORE the budget-consuming Gate without moving
 * any verdict out of its pinned position.
 *
 * Policy is asked in TWO calls rather than one because step 5 sits between
 * them and cannot be made from inside Policy -- that class is decided by its
 * arguments alone and must not reach into hx.send for a Redactor. The Gate
 * half is owed after every allowed first half; ChokepointTest counts both
 * call sites, because an issue path that called only the first would issue
 * past the rate limit and past the run's budget.
 */
public final class Sender {

    private final Policy policy;
    private final Redactor redactor;
    private final HaltSwitch halt;
    private final Distress distress;
    private final Http http;
    private final Clock clock;
    /** The identities this run may issue under. Read AFTER the gate and
     *  nowhere else -- see decideAndIssue, where the position is the point. */
    private final IdentityRegistry identities;

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
                  Distress distress, Http http, Clock clock,
                  IdentityRegistry identities) {
        this.policy = policy;
        this.redactor = redactor;
        this.halt = halt;
        this.distress = distress;
        this.http = http;
        this.clock = clock;
        this.identities = identities;
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
     * Why issuance is held right now, or null while nothing is holding it.
     *
     * The REQUEST-INDEPENDENT half of decideAndIssue's refusals: the two that
     * can be answered without a request in hand, which is what makes them the
     * only two anything outside this class can usefully ask about. Everything
     * else below -- scope, method, dangerous path, unmanaged credential, rate,
     * budget, deadline -- is a question about ONE request and has no answer
     * without it. A caller who reads a null here has learned that the run is
     * not stopped, and NOT that any particular request may go out.
     *
     * It exists because it had to be asked from somewhere else. BridgeClient
     * keeps a `halted` flag of its own, written by the `halt` and `resume`
     * frame arms and by nothing else; spec s4 names three kill paths, and the
     * other two -- the sentinel file (including its stalled-poller rule) and
     * this auto-halt -- never touch it. Measured, with a sentinel file present
     * and HaltSwitch.halted() answering true, BridgeClient.maySend() answered
     * TRUE; likewise after Distress had tripped. So maySend() asks this, and
     * this is the same code decideAndIssue runs rather than a second opinion
     * about the same two objects: two implementations of "is the run stopped"
     * is how the consoles come to disagree with the wire.
     *
     * The ORDER is HaltSwitch first, then Distress, and it is pinned by
     * SenderTest.theHeldReasonIsTheSameAnswerTheSendPathActsOn rather than
     * left to this comment -- an operator halt and an auto-halt can both be in
     * force, and the reason a frame carries has to be stable when they are.
     * MEASURED: swapped, the whole Java suite was 9 x ALL PASS / 1484 ok / 0
     * FAIL, and an operator who pressed stop was told about a 5xx rate.
     * (theRefusalOrderIsPinned pins where `halted` sits among the other
     * CLASSES, which is a different question and does not see this swap.)
     *
     * HaltSwitch.halted() and .reason() are two calls and a change can land
     * between them -- see the note on HaltSwitch's own state record. The only
     * straddle that reaches here is halted()==true then reason()==null, which
     * is why there is a fallback string and not a null return.
     */
    public String issuanceHeldReason() {
        if (halt.halted()) {
            String why = halt.reason();
            return why == null ? "halted, no reason recorded" : why;
        }
        // Auto-halt. Distress is extension-initiated and has no reset: one
        // distressed host aborts the whole run (spec s4), and a human decides
        // when it restarts.
        String stop = distress.stopReason();
        if (stop != null) return "target distress: " + stop + " on " + distress.stopHost();
        return null;
    }

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
     * A RangeError is a denial, never an allow (s4), and identity injection
     * is what can now raise one: {@link #compose} refuses a range whose bytes
     * are not the credential it was measured for, BEFORE http.send, so a
     * request whose redaction range cannot be trusted is answered `bad_frame`
     * rather than issued.
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

        // Both halt checks, from the one method that owns them. This
        // POSITION -- after epoch 0, before scope -- is pinned by
        // theRefusalOrderIsPinned; the order of the two checks INSIDE
        // issuanceHeldReason is pinned there, and see its javadoc for why
        // that needed saying separately.
        String held = issuanceHeldReason();
        if (held != null) return error(id, "halted", held);

        // scope -> method -> dangerous. None of these spends anything, so
        // they are free to run before the credential check -- and they MUST,
        // because a credential refusal has no denial row and a scope
        // violation does.
        Decision boundary = policy.decideBeforeGate(req, auth);
        if (!boundary.allowed()) return error(id, boundary);

        // s7: refused AND NEVER PERSISTED. Until identity injection registers
        // byte ranges, this is the only thing keeping a live client session
        // cookie out of a content-addressed blob store -- where, once written,
        // it is in every backup. This is the one item that cannot be
        // retrofitted.
        //
        // BEFORE THE GATE and AFTER the boundary checks, and the two halves of
        // that placement have different reasons. Before the Gate, for the same
        // reason as guard 1: Limits.check() spends a rate token and a budget
        // slot on a request that is about to be refused. After scope, method
        // and dangerous, because running it first turned every out-of-scope
        // request CARRYING A COOKIE into a credential error naming the
        // credential rather than the boundary crossed -- and while the class
        // was in records.UNRECORDABLE, which it was until SCHEMA_VERSION 6,
        // with no row anywhere either. MEASURED before this moved:
        //
        //   out-of-scope AND unmanaged Cookie    -> unmanaged_credential
        //   out-of-scope, no cookie              -> scope_denied
        //   dangerous-path AND unmanaged Cookie  -> unmanaged_credential
        //
        // Until Plan 5 the natural agent action is replaying a request lifted
        // from Burp's history, which carries a Cookie -- so in that window
        // EVERY out-of-scope replay was filed as a credential error and the
        // scope-violation evidence was systematically absent. "Did the agent
        // ever try to leave scope?" was unanswerable from the store. s4: "Any
        // denial produces a `denial` row and a distinct error class. Denials
        // are never silent."
        //
        // Nothing about s7 is weakened by the move. The request is still
        // refused and still never persisted; what changed is which refusal an
        // operator is told about when there are two.
        String credential = redactor.unmanagedCredential(req);
        if (credential != null)
            return error(id, "unmanaged_credential", "request carries a " + credential
                         + " header this extension did not inject");

        // The Gate LAST: the only check on this path with a side effect.
        Decision d = policy.checkGate(req);
        if (!d.allowed()) return error(id, d);

        // ---- EVERY GATE HAS NOW ANSWERED --------------------------------
        //
        // AFTER THE GATE, DELIBERATELY. Injection composes a request carrying
        // a live credential, and doing it before the gate would mean an
        // out-of-scope or dangerous-path send had one composed for it -- with
        // only the refusal returning in time keeping it off the wire. Spec s7
        // pins the ordering.
        //
        // The two refusals below are the last things on this path that can
        // refuse, and they are HERE rather than above because they are the
        // only two that need an identity in hand: there is no identity to
        // resolve until the frame has been read, and no reason to resolve one
        // for a request the boundary checks are about to turn away.
        //
        // IdentityInjectionTest's aRequestTheGateREFUSEDNeverHasACredentialWrittenIntoIt
        // is what holds the order, and it holds it through the REFUSAL CLASS:
        // an input for which both a gate refusal and an identity refusal are
        // available can only be answered once, and the class names which step
        // ran. Moving this block above `policy.checkGate` turns that suite red.
        String identityId = header.get("identity_id") instanceof String s ? s : null;
        IdentityRegistry.Entry ident = null;
        if (identityId != null && !identityId.isBlank()) {
            ident = identities.get(identityId);
            if (ident == null)
                // FAIL CLOSED. Issuing anonymously because the identity is
                // unknown is the single outcome this whole feature exists to
                // prevent: a `clean` answer about a view no user is in.
                return error(id, "unknown_identity",
                             "no identity registered as " + identityId);
            if (!appliesTo(ident, req))
                // A credential is not sprayed at whatever host a check names.
                // The scope may well allow a third-party host; the operator's
                // session on the TARGET has no business being sent to it.
                return error(id, "identity_origin",
                             "identity " + identityId + " is not registered for "
                             + req.host());
        }

        // ---- AND NOTHING BELOW THIS LINE DECIDES ------------------------
        //
        // NOT "nothing below refuses", which is what this banner said until
        // the Task 5 review measured it false three ways over -- once in the
        // very next statement and twice more below it: compose() refuses a
        // range whose bytes are not the credential it was measured for
        // (Redactor.RangeError -> `bad_frame`, as issue()'s own javadoc says),
        // http.send failing is `transport_error`, and an overshot deadline is
        // `timeout` -- all three before anything is framed as a result. That is
        // the same defect cc886ac fixed one step higher -- a banner placed
        // above the lines that contradict it -- reintroduced at the line the
        // fix moved it to.
        //
        // WHAT IS TRUE HERE is the thing the ordering actually rests on: every
        // POLICY question has been answered -- scope, method, dangerous path,
        // the Gate, the unmanaged credential, the identity and its origin --
        // and none of them can be re-asked once a credential has been written
        // into the bytes. What can still fail below is mechanical: a range
        // that does not check out, a transport that will not carry it, a clock
        // that has run out. None of them is a decision this request could have
        // been spared by asking earlier, which is why moving the composition
        // above them would buy nothing and cost the ordering.
        //
        // The bytes that go on the wire, composed ONCE and here rather than in
        // the adapter: the Injected inside holds the array it was measured
        // from BY IDENTITY, so a second serialisation downstream would issue
        // an array no range set names. `ident` is null for an anonymous send,
        // and compose() then registers nothing -- an empty Injected, which
        // redactRequest answers with a verbatim copy.
        //
        // ChokepointTest.theCompositionHappensAfterTheGate is what holds this
        // line's position: the behavioural suite cannot see compose() moved
        // above policy.checkGate on its own, because the array it builds is
        // local and a refused request discards it.
        Composed composed = compose(req, ident);

        HttpReply reply;
        try {
            reply = http.send(composed.req(), composed.wire(), deadlineUs);
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
        // The scan is asked for its REASON as well as its answer: 599 is a
        // status a peer may also send for itself, so the number alone cannot
        // say which of the two this was. What Distress counts and what
        // `status` reports are unchanged either way -- the distinction goes on
        // `outcome`, below, and nowhere else.
        StatusScan scan = scanStatus(reply.raw(), reply.status());
        int status = scan.code();
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
        // What `status` cannot say on its own. 599 is not reserved -- it is
        // in unofficial use for connect timeouts, which is exactly the class
        // of peer that fronts an origin with early hints -- so `status: 599`
        // alone leaves an operator grepping for 5xx unable to tell a peer's
        // own 599 from an exchange whose own attached bytes say
        // `HTTP/1.1 200 OK`. See STATUS_UNREADABLE.
        result.put("outcome", scan.unreadable() ? "status_unreadable" : "ok");
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
        StringBuilder s = new StringBuilder(requestLine(req));
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
     * The request line and the CRLF that ends it, up to the first header.
     *
     * Extracted so that {@link #wireBytes} and {@link #compose} cannot
     * disagree about where the first header starts. compose measures the
     * injected credential's byte offset from exactly this length, and a second
     * spelling of the request line here would be a byte offset derived from
     * one grammar and applied to another -- which is a placeholder written
     * over the wrong bytes, with the credential left verbatim beside it.
     */
    private static String requestLine(HxRequest req) {
        StringBuilder s = new StringBuilder();
        s.append(req.method()).append(' ').append(req.path());
        if (!req.query().isEmpty()) s.append('?').append(req.query());
        return s.append(" HTTP/1.1\r\n").toString();
    }

    /**
     * The request to issue, the bytes it serialises to, and the ranges this
     * extension wrote into them.
     *
     * THE REQUEST IS IN HERE TOO, and not just the bytes, because the two must
     * not disagree: {@code Http} reads the destination off the request and the
     * payload off the bytes, so handing it the PRE-injection request beside
     * POST-injection bytes would leave an implementation two answers to "what
     * is this request", differing by exactly the credential. The one it read
     * would be the one it happened to reach for.
     *
     * The bytes and the ranges travel together because {@link Redactor.Injected} holds its
     * array BY IDENTITY and {@link Redactor#redactRequest} refuses any other:
     * a range set that arrives without the array it was measured from cannot
     * be used, and one that arrives beside a DIFFERENT array is a RangeError
     * rather than a silent rewrite at the wrong offsets.
     *
     * WHAT READS `injected` TODAY: nothing in production, and that is worth
     * saying plainly rather than leaving a reader to discover it. The send
     * path's `result` frame carries ONE body -- the redacted RESPONSE -- so no
     * copy of the request crosses the bridge from here at all; and nothing on
     * the Python side writes an `exchange` row for a send yet either, since
     * `records.record_exchange` has exactly one caller and it is
     * `hx.capture.Capture.on_exchange`, which serves the PROXY's `exchange`
     * frames. The registration happens anyway because spec s7
     * requires it to precede issuance and storage, and because the moment a
     * request half is added to this frame it must be redacted rather than
     * retrofitted: s7 calls the blob store the one item that cannot be
     * retrofitted, since a content-addressed credential is not merely stored,
     * it becomes an address that exists in every backup. The check inside
     * compose() is what stops the registration from being decorative in the
     * meantime -- an offset that does not name the credential fails the send.
     */
    record Composed(HxRequest req, byte[] wire, Redactor.Injected injected) { }

    /**
     * Serialise the request, writing {@code ident}'s header into it and
     * telling the Redactor precisely where the secret landed.
     *
     * BYTE RANGES, NOT A HEADER NAME: the range is known exactly because this
     * method wrote it, and Redactor's own javadoc says a name match is a
     * guess. The header goes FIRST, immediately after the request line, which
     * is what makes the offset computable from {@link #requestLine} alone.
     *
     * {@code ident} is null for an anonymous send and then this is
     * {@link #wireBytes} plus an empty {@link Redactor.Injected} -- required,
     * because redactRequest takes one, and empty because nothing was injected.
     *
     * THE OFFSETS ARE CHECKED AGAINST THE BYTES, not trusted. They are correct
     * by construction, and "by construction" is exactly the claim that stops
     * being true when someone changes how a header is emitted; the failure it
     * would cause is silent and unrecoverable -- a placeholder written over
     * innocent bytes while the credential stays verbatim in the copy that gets
     * content-addressed. A mismatch is a {@link Redactor.RangeError}, which
     * {@link #issue} answers `bad_frame` with, BEFORE http.send: the request
     * is refused rather than issued with a range nobody can trust.
     */
    static Composed compose(HxRequest req, IdentityRegistry.Entry ident) {
        if (ident == null) {
            byte[] wire = wireBytes(req);
            return new Composed(req, wire, new Redactor.Injected(wire));
        }
        HxRequest carrying = withHeaderFirst(req, ident.header(), ident.value());
        byte[] wire = wireBytes(carrying);
        byte[] value = ident.value().getBytes(StandardCharsets.ISO_8859_1);
        int start = requestLine(carrying).getBytes(StandardCharsets.ISO_8859_1).length
                  + (ident.header() + ": ").getBytes(StandardCharsets.ISO_8859_1).length;
        int end = start + value.length;
        if (end > wire.length
                || !Arrays.equals(wire, start, end, value, 0, value.length))
            throw new Redactor.RangeError(
                "the range computed for identity " + ident.id() + " is [" + start + ","
                + end + ") of " + wire.length + " bytes and those bytes are not the "
                + "credential; refusing to issue a request whose redaction range is wrong");
        Redactor.Injected injected = new Redactor.Injected(wire);
        injected.register(ident.id(), start, end);
        return new Composed(carrying, wire, injected);
    }

    /**
     * {@code req} with {@code name: value} as its FIRST header, replacing any
     * header the caller sent under that name.
     *
     * FIRST, because compose() measures the credential's offset from the end
     * of the request line, and a header emitted anywhere else would need the
     * lengths of everything in front of it.
     *
     * REPLACING, because the request is being issued AS this identity and two
     * values for one field name leave the server to choose which -- so a check
     * could read an answer given to the caller's own credential and file it as
     * the identity's. The three field names that matter most cannot reach this
     * point at all: Authorization, Cookie and Proxy-Authorization are
     * {@code Redactor.CREDENTIAL_HEADERS}, and a request carrying one this
     * extension did not inject was refused `unmanaged_credential` above.
     *
     * Field names are case-insensitive (RFC 9110 s5.1), so the match is too.
     * {@code equalsIgnoreCase} rather than Redactor's ASCII comparison because
     * nothing here is deciding whether a value is a credential -- this is
     * "which of the caller's headers is the one I am about to write", and the
     * name being replaced is one an operator put in the config.
     */
    private static HxRequest withHeaderFirst(HxRequest req, String name, String value) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put(name, List.of(value));
        req.headers().forEach((k, v) -> {
            if (!k.equalsIgnoreCase(name)) headers.put(k, v);
        });
        return new HxRequest(req.method(), req.url(), req.host(), req.path(),
                             req.query(), Collections.unmodifiableMap(headers),
                             req.body());
    }

    /**
     * Whether {@code ident} may be applied to the host {@code req} is going to.
     *
     * spec s5: origins bound WHERE a credential may be applied, so a probe
     * against a third-party host that is perfectly in scope never carries the
     * target's session. Scope and origins answer different questions and both
     * have to say yes.
     *
     * An origin is matched by its HOST, and the comparison is against
     * {@code req.host()} -- the name Burp will actually connect to, taken from
     * the send frame's `target_host` -- and never against the request's own
     * Host line, for the reason {@link #parse} gives: deciding on a Host header
     * would let a request authorised for one service open a connection
     * somewhere else. An origin written as a URL -- the shape spec s5's own
     * example uses, and the shape a `scope.include` pattern has, which is
     * where s5 says the default comes from --
     * contributes its authority's host; one written as a bare host
     * contributes itself. A PORT in the origin is ignored: this compares hosts,
     * and the port a send goes to is settled by the frame and by scope.
     *
     * Case-insensitive, because host names are (RFC 9110 s4.2.3), and exact
     * otherwise -- no suffix matching. `evil-app.test` must not satisfy an
     * origin of `app.test`, and neither must a subdomain nobody listed.
     */
    static boolean appliesTo(IdentityRegistry.Entry ident, HxRequest req) {
        String host = req.host().toLowerCase(Locale.ROOT);
        for (String origin : ident.origins())
            if (host.equals(hostOf(origin))) return true;
        return false;
    }

    /** The host part of an origin, lower-cased: everything after `://` and
     *  before the first `/`, `:` or `?`, or the whole string when there is no
     *  scheme. Deliberately not a URL parser -- an origin is a bound an
     *  operator wrote, and anything this cannot read simply matches no host,
     *  which is the fail-closed direction. */
    private static String hostOf(String origin) {
        String rest = origin.trim().toLowerCase(Locale.ROOT);
        int scheme = rest.indexOf("://");
        if (scheme >= 0) rest = rest.substring(scheme + 3);
        int cut = rest.length();
        for (String d : new String[] { "/", ":", "?" }) {
            int at = rest.indexOf(d);
            if (at >= 0 && at < cut) cut = at;
        }
        return rest.substring(0, cut);
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
     * The one 1xx that IS a final response.
     *
     * RFC 9110 s15.2.2: a `101 Switching Protocols` head ends HTTP on that
     * connection -- what follows the empty line is the negotiated protocol,
     * not another status line -- so 101 is the last HTTP status the exchange
     * will ever state. Every other 1xx promises a final head that is still to
     * come, which is the whole licence {@link #finalStatus} has to overrule
     * what the transport reported.
     *
     * Named rather than written twice: {@link #scanStatus} has to make this
     * exception at BOTH places a 101 can arrive -- reported by the transport,
     * and read out of the bytes behind an earlier interim head -- and two
     * bare 101s are two places for one of them to be changed alone. Pinned by
     * SenderTest, which drives both arrivals.
     */
    static final int SWITCHING_PROTOCOLS = 101;

    /**
     * What a scan that never found a final head reports: a status Distress
     * counts as an error.
     *
     * 599 is not a status any peer sent, and that is the point -- the
     * alternative is worse in the one direction this whole function exists to
     * close. When the scan does not reach a final status line the reported
     * status is still the INTERIM 1xx, and returning it would hand Distress a
     * healthy sample for a response whose real status we could not read: a
     * peer that chooses how many heads to send, or how far to truncate, would
     * then choose whether spec s4's 20% rule can ever fire. A bound whose
     * overflow behaviour is "fail open" is not a bound, and neither is a scan
     * whose truncation behaviour is.
     *
     * It is inside 500..599, which is the range {@code Distress.tripOn5xxRate}
     * counts, so an origin hiding behind eight interim heads -- or a dead
     * origin behind a CDN that already sent its `103 Early Hints` -- reads as
     * broken rather than as fine.
     *
     * THE EVIDENCE LINE NEEDS MORE THAN THAT, and gets it from `outcome`
     * rather than from here. 599 is NOT a reserved code -- it is in unofficial
     * use for connect timeouts, which is exactly the class of peer that fronts
     * an origin with early hints -- so a frame carrying `status: 599` alone is
     * indistinguishable from a peer that answered 599 itself, and the two
     * readings are wrong in opposite directions: read as unreadable, a real
     * proxy 599 stops being an error; read as real, an exchange that succeeded
     * with a 200 is indexed as a 5xx while the redacted bytes attached to that
     * very frame say `HTTP/1.1 200 OK`. So the result frame says
     * {@code outcome: "status_unreadable"} for this case and
     * {@code outcome: "ok"} for the peer's own 599, while `status` stays 599
     * in BOTH: the conservative-for-auto-halt property is the whole reason
     * this constant exists, and it must not come to depend on anyone reading a
     * second field.
     *
     * The VALUE is pinned by SenderTest, not merely its range. 500 would sit
     * on a status real origins send constantly, and a sentinel that collides
     * with a common answer is the ambiguity above, made worse.
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
     * A 1xx is never the final response (RFC 9110 s15.2) WITH ONE EXCEPTION,
     * so a reported 1xx is the one case where the transport's answer can be
     * improved on; anything else is returned untouched.
     *
     * THE EXCEPTION IS 101, and it is not a corner. RFC 9110 s15.2.2: after
     * the empty line that terminates a `101 Switching Protocols` head, the
     * connection changes protocol and NO FURTHER HTTP STATUS LINE EVER
     * FOLLOWS. So "a 1xx head with nothing parseable behind it" is not a
     * truncation for a 101 -- it is what a CORRECT, SUCCESSFUL 101 looks like,
     * and the bytes after it are the new protocol's frames, which statusCodeOf
     * reads as "not a status line". 100 and 102 head-only ARE genuine
     * truncations and stay unreadable; 101 head-only is the answer itself.
     *
     * Getting this wrong is the MIRROR of the bug the paragraph below
     * describes -- same rail, same severity, opposite direction -- so it is
     * measured to the same standard. Against the shipped method before this
     * exception existed, a WebSocket upgrade (`101` + `Upgrade: websocket`,
     * nothing after) answered {@code 599 / unreadable=true}. Driven 30 times
     * against a perfectly healthy host, the first TEN each recorded
     * {@code status=599, outcome=status_unreadable} -- ten 5xx samples, which
     * is exactly what spec s4's 20% rule needs -- the run auto-halted on the
     * tenth with `5xx rate 100.0%`, and the remaining twenty were refused
     * `halted` and never reached the wire. The host had answered every request
     * correctly. hx places no restriction on `Upgrade` requests, so that is
     * routine web-app work producing false evidence about a client production
     * system and stopping the assessment for a distress that never happened.
     *
     * THE SPLIT IS "a final head was read" vs "one was not", and NOT
     * "the scan ran out of budget" vs "everything else". An earlier version of
     * this javadoc drew it the second way -- if the bytes RUN OUT before a
     * later status line, "the reported value stands, because there is nothing
     * there to have hidden anything behind" -- and that premise is about the
     * BYTES while its conclusion is about the STATUS. It does not follow.
     * Nothing was hidden, and the 1xx is still not the final response: RFC
     * 9110 s15.2 does not stop applying because the connection died. Measured
     * against the shipped method before this was corrected, 30 sends against
     * a CDN answering `103 Early Hints` with a dead origin behind it recorded
     * thirty {@code status=103, outcome=ok} exchanges, a 0% 5xx rate and
     * {@code distress.stopReason() == null} -- the auto-halt disarmed by
     * exactly the failure it exists to catch.
     *
     * So every ending that falls out with {@code reported} still a NON-101 1xx
     * answers {@link #STATUS_UNREADABLE}: the scan running out of budget, the
     * bytes running out mid-line or after a blank line, a line this cannot
     * read at all, and a null {@code raw}. THREE things overrule it, not two:
     * a final status line READ OUT OF THE BYTES, a {@code reported} that was
     * never 1xx, and a {@link #SWITCHING_PROTOCOLS} -- reported or read out of
     * the bytes -- which is itself the final HTTP status of its exchange.
     */
    public static int finalStatus(byte[] raw, int reported) {
        return scanStatus(raw, reported).code();
    }

    /**
     * The status, and whether the exchange actually produced it.
     *
     * {@link #finalStatus} is this function with the provenance thrown away.
     * There is ONE scan and not two on purpose: a separate predicate answering
     * "was that 599 real?" would be a second copy of this loop, free to drift
     * from the answer it describes.
     *
     * {@code unreadable} is true for every ending that did NOT read a final
     * status line while {@code reported} was a 1xx OTHER THAN 101. The `ok`
     * endings are the THREE that produced a status the EXCHANGE actually
     * stated: a status line read out of the bytes, a reported status that was
     * never 1xx, and a {@link #SWITCHING_PROTOCOLS} from either place, which
     * is final where the rest of the 1xx range is not. Those three INCLUDE a
     * genuine 599, whether the transport reported it or it was read out of the
     * response bytes behind some interim heads -- the peer said 599 and we
     * believe it.
     *
     * A reported NON-101 1xx with no readable final head is NOT one of them,
     * however the bytes ended. See {@link #finalStatus} for why "the bytes ran
     * out" is not a licence to report the interim head, and for why 101 is the
     * one 1xx where there was never a later head to run out of.
     */
    public static StatusScan scanStatus(byte[] raw, int reported) {
        // Not an interim status: the transport's answer IS the final one, and
        // re-reading the bytes behind it would let a peer's leading head
        // overrule a status the exchange really produced.
        if (reported < 100 || reported > 199) return sent(reported);

        // 101 IS final (see SWITCHING_PROTOCOLS), so it is answered before
        // everything else here -- INCLUDING the null-`raw` guard below.
        // "Nothing parseable behind the head" is the NORMAL shape of a
        // successful upgrade, not a truncation, and it must not read as
        // distress in ANY of its forms: a null `raw` under a reported 101
        // answering 599 would put the auto-halt back exactly where a healthy
        // peer can trip it, which is the failure this exception exists to
        // close. The frame is still refused -- redactResponse answers a null
        // `raw` with a RangeError and a bad_frame -- so nothing is being
        // waved through here; only the sample Distress records is at stake,
        // and a completed upgrade is not a 5xx.
        if (reported == SWITCHING_PROTOCOLS) return sent(reported);

        // From here `reported` is a 1xx that is NOT final, so there are
        // exactly two answers left: a final status line read out of `raw`
        // (a 101 among them), or STATUS_UNREADABLE.
        //
        // A null `raw` is a real reply shape -- HttpReply carries whatever
        // Montoya gave us -- and it goes on to reach redactResponse, which
        // answers it with a RangeError and a bad_frame, so it must not become
        // an NPE here first. It must not answer `sent(103)` either: Distress
        // is fed BEFORE that RangeError is raised, so the interim head would
        // still land in the window as a healthy sample.
        if (raw == null) return unreadable();

        String text = new String(raw, StandardCharsets.ISO_8859_1);
        int i = 0;
        for (int head = 0; head < MAX_INTERIM_HEADS && i < text.length(); head++) {
            int eol = text.indexOf('\n', i);
            if (eol < 0) return unreadable();        // truncated mid-line
            int code = statusCodeOf(text.substring(i, eol));
            if (code < 100) return unreadable();     // not a status line: stop guessing
            // A 101 READ OUT OF THE BYTES ends the scan exactly as a reported
            // one does, and this arm is reachable: `103 Early Hints` in front
            // of an upgrade is one line of CDN config away, and Montoya then
            // reports the 103 and hands both heads back. Without this the loop
            // would step over the 101's blank line into the WebSocket frames
            // behind it, read them as "not a status line", and answer 599 for
            // an upgrade that succeeded. Tested before the `>= 200` arm
            // because 101 sorts below it, not as a special case of it.
            if (code == SWITCHING_PROTOCOLS) return sent(code);
            if (code >= 200) return sent(code);      // the final response
            // A 1xx head carries no body (RFC 9110 s15.2), so the next head
            // starts immediately after this one's blank line.
            int crlf = text.indexOf("\r\n\r\n", i);
            int lf = text.indexOf("\n\n", i);
            if (crlf >= 0 && (lf < 0 || crlf <= lf)) i = crlf + 4;
            else if (lf >= 0) i = lf + 2;
            else return unreadable();                // no blank line ends this 1xx head
        }
        // Out of budget, or out of bytes with every head read so far a 1xx.
        // Either way the final response is still ahead of this scan and
        // `reported` is certainly not it -- the peer chose the head count and
        // chose where to stop writing, and it must not get to choose the
        // sample Distress records either way.
        return unreadable();
    }

    /** A status the exchange itself produced. */
    private static StatusScan sent(int code) { return new StatusScan(code, false); }

    /** A reported 1xx and no final head to replace it with. */
    private static StatusScan unreadable() {
        return new StatusScan(STATUS_UNREADABLE, true);
    }

    /**
     * A status and where it came from.
     *
     * The accessor is {@code code()} rather than {@code status()} deliberately:
     * {@link HttpReply#status()} has exactly one reader in this tree -- the
     * scanStatus call in decideAndIssue -- and a second reader spelled the
     * same way anywhere in extension/src would make that invariant
     * unverifiable by the grep that checks it. Written with a `#` rather than
     * a dot for the same reason: see ChokepointTest's
     * theDeprecatedAccessorsAreUnusedEverywhere, which makes the rule
     * explicit -- fix the javadoc, do not widen the needle.
     *
     * PUBLIC, ALONG WITH {@link #scanStatus}, BECAUSE THERE IS ONE SCAN AND NOT
     * TWO. The PROXY path emits the same two wire values -- `status` and
     * `outcome` -- and shipped them as `r.statusCode()` raw and the literal
     * `"ok"`, with no scan behind either: a `103 Early Hints` in front of a
     * dead origin filed `status=103, outcome=ok`, which is the exact pair S5
     * measured thirty of and the pair that leaves S4's auto-halt a healthy
     * sample for every failing request. {@link #finalStatus} was already
     * public and is NOT enough for that caller: it throws the provenance away,
     * and deriving "was that unreadable" from the code alone gets a genuine
     * 599 read out of the bytes behind a 103 exactly backwards. So the caller
     * gets the whole answer rather than half of it and a second copy of this
     * loop. `hx.proxy` -> `hx.send` is the edge {@link Redactor} already
     * crosses in that direction; the reverse is the one to refuse.
     *
     * @param code       what goes on the evidence line and into Distress
     * @param unreadable true when {@code code} is {@link #STATUS_UNREADABLE}
     *                   BECAUSE no final status line could be read behind a
     *                   reported 1xx, rather than because anything in the
     *                   exchange said 599
     */
    public record StatusScan(int code, boolean unreadable) { }

    /**
     * The three-digit code of a status line, or -1 for a line that is not
     * one. Deliberately strict: a line this cannot read is a line this must
     * not report a status from.
     *
     * A STATUS-CODE IS EXACTLY THREE DIGITS, and the delimiter after the third
     * is part of the grammar: RFC 9112 s4 is `status-line = HTTP-version SP
     * status-code SP [ reason-phrase ]`. Until that was checked, a FOURTH
     * digit was simply dropped and the three-digit prefix reported as the
     * status. MEASURED against the shipped method, each line below behind a
     * `103 Early Hints` head and in front of a real `HTTP/1.1 500`:
     *
     *     HTTP/1.1 1010 Weird  ->  101 / ok
     *     HTTP/1.1 2000        ->  200 / ok
     *     HTTP/1.1 5000        ->  500 / ok
     *
     * `1010` is the sharp one and it is new: 101 is final (see
     * {@link #SWITCHING_PROTOCOLS}), so the scan STOPPED at a line no RFC
     * calls a status line and filed a HEALTHY sample for an exchange whose own
     * bytes say 500 -- the auto-halt disarmed by a peer writing one extra
     * digit. All three now answer -1, which scanStatus reads as `not a status
     * line: stop guessing` and answers {@link #STATUS_UNREADABLE}: a 5xx
     * sample rather than a healthy one, which is the direction this whole
     * function fails in.
     *
     * END OF LINE IS A DELIMITER TOO, and it has to be. `line` is stripped
     * before this reads it, so a status line with NO REASON PHRASE ends at the
     * third digit whichever way the peer wrote it: `HTTP/1.1 204` and
     * `HTTP/1.1 204 ` -- the grammar's SP with nothing after it -- are the same
     * string by then, and both are still read.
     *
     * THE DELIMITER SET IS {@link Redactor}'s, not a second opinion. Its
     * `isInterim` has read this same grammar off the same bytes since it was
     * written -- `c + 3 == to || raw[c + 3] == ' ' || raw[c + 3] == '\t'`, and
     * `"HTTP/1.1 1000 x" is not a 1xx` is its own comment -- so this method was
     * the one reader of a status CODE in this package that did not check it.
     * Two readers of one grammar that disagree is the drift this branch keeps
     * finding: SP, HTAB or end of line here means the redaction pass and the
     * status pass cannot classify the same head two ways.
     */
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
        // Exactly three digits (RFC 9112 s4), so what follows them is the
        // whitespace before the reason phrase -- or nothing at all.
        if (s.length() > sp + 4 && s.charAt(sp + 4) != ' ' && s.charAt(sp + 4) != '\t')
            return -1;
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
