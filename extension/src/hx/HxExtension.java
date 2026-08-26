package hx;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import hx.bridge.BridgeClient;
import hx.policy.Clock;
import hx.policy.Decision;
import hx.policy.Distress;
import hx.policy.HxRequest;
import hx.policy.Policy;
import hx.proxy.Capture;
import hx.proxy.Denied;
import hx.proxy.Observed;
import hx.proxy.Pending;
import hx.proxy.ProxyGate;
import hx.proxy.Source;
import hx.send.HaltSwitch;
import hx.send.Http;
import hx.send.HttpReply;
import hx.send.Limits;
import hx.send.Redactor;
import hx.send.Sender;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Burp entry point, and the only file in extension/src that names burp.* at
 * all. It reads its socket path, engagement id, instance id and halt sentinel
 * from system properties so the harness controls them at launch, builds the
 * send path AND the proxy path, then dials in on a background thread and stays
 * in DENY-ALL until configured.
 *
 * BOTH of S4's enforcement points are joined here and nowhere else: the send
 * path through {@link Sender}, and the proxy handlers through
 * {@link ProxyGate}. Neither can be driven without Burp, so what holds them in
 * place is ChokepointTest -- counts for the wires, positions for the two
 * orderings that make the second point mean anything (the gate decides before
 * anything is queued; the {@link Redactor} runs before anything is queued).
 */
public class HxExtension implements BurpExtension {

    // Written on Burp's initialize thread, read by the unloading handler on
    // another -- the same cross-thread edge the bridge's own fields were fixed
    // for. Read it ONCE into a local there too: `if (client != null)
    // client.close()` races itself, NPEs inside the handler, and skips the
    // close() that was the point of the handler.
    //
    // `capture` is SHADOWED by a local of the same name inside initialize, so
    // the unloading handler names it `this.capture` -- the field, published by
    // the volatile write, rather than the local the lambda would otherwise
    // close over.
    private volatile BridgeClient client;
    private volatile HaltSwitch halt;
    private volatile Capture capture;

    /** Single-digit req/s, per spec s4's production profile. Used only when a
     *  configure body omits limit.rate_rps. */
    static final long DEFAULT_RATE_RPS = 5L;

    /** The per-run budget when a configure body omits limit.max_requests. */
    static final long DEFAULT_MAX_REQUESTS = 2000L;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("hx bridge");

        String sock = System.getProperty("hx.socket");
        String engagement = System.getProperty("hx.engagement");
        String instance = System.getProperty("hx.instance", "unknown");
        String sentinel = System.getProperty("hx.halt_sentinel");

        if (sock == null || engagement == null || sentinel == null) {
            // The sentinel is required, not optional. It is the kill path that
            // works when the bridge does not -- an operator creating a file
            // from a shell while the socket is dead -- and an extension that
            // went live without one would have two of the three paths spec s4
            // promises, silently.
            api.logging().logToError("hx: -Dhx.socket, -Dhx.engagement and "
                + "-Dhx.halt_sentinel are required; extension idle");
            return;
        }
        System.setProperty("hx.burp.version", api.burpSuite().version().toString());

        // Wall clock, not System.nanoTime(). deadline_us is absolute
        // microseconds since epoch, set by the harness on the other side of
        // the socket; a monotonic clock answers a different question and
        // cannot be compared with the peer's deadline at all.
        Clock clock = () -> {
            Instant t = Instant.now();
            return t.getEpochSecond() * 1_000_000L + t.getNano() / 1_000L;
        };

        Redactor redactor = new Redactor();
        HaltSwitch haltSwitch = new HaltSwitch(clock, Path.of(sentinel),
                                               HaltSwitch.DEFAULT_POLL_MS);
        // Spec s4's auto-halt thresholds: stop above a 20% 5xx rate, above 5x
        // the baseline p50 latency, or after 5 consecutive connection errors.
        // s4 calls these engagement-config defaults and s14 flags them for
        // tuning, which is why Distress takes all three as constructor
        // arguments rather than owning them -- but the configure body cannot
        // carry them yet: ConfigBody.KEYS has no distress key and an
        // unrecognised key is a hard error, so routing them through the wire
        // is a protocol change (the parser, the protocol document, and the
        // harness that writes the body) rather than a wiring change here.
        Distress distress = new Distress(clock, 0.20, 5.0, 5);
        // The rate and the budget DO arrive in the configure body, so these
        // two numbers are only what an omitted key falls back to. Limits reads
        // them out of the Authorisation snapshot -- see below, and see why it
        // reads them exactly once.
        Limits limits = new Limits(clock, DEFAULT_RATE_RPS, DEFAULT_MAX_REQUESTS);

        BridgeClient c = new BridgeClient(Path.of(sock), engagement, instance,
                new BridgeClient.Log() {
                    public void info(String s)  { api.logging().logToOutput(s); }
                    public void error(String s) { api.logging().logToError(s); }
                });

        // ONE Policy for the whole extension, given a name so the second
        // enforcement point can be handed THIS one. Policy owns the Gate, and
        // the Gate is where the rate limit and the per-run budget live: a
        // proxy path that built its own `new Policy(new Limits(...))` would be
        // a SECOND per-run budget for one run, and no behavioural test can see
        // that -- each half of it is internally consistent, and the pair
        // counter in ChokepointTest counts `.decideBeforeGate(` and
        // `.checkGate(`, not constructions. Measured: adding that second
        // Policy here was 10 x ALL PASS before ChokepointTest.oneRunHasOnePolicy
        // existed, and is 1 FAIL naming this file now. Sharing this reference
        // is the wiring Task 7 needs; the inline construction this replaces is
        // the shape that makes a second one the natural thing to write.
        Policy policy = new Policy(limits);
        Sender sender = new Sender(policy, redactor, haltSwitch,
                                   distress, montoyaHttp(api, clock), clock);
        // Auto-halt is extension-initiated: there is no outstanding id to
        // answer, so this frame is the only way the harness hears about a stop
        // before the next send fails -- and run.status = 'aborted' needs a
        // stop_reason that exists nowhere else.
        sender.setHaltNotifier(c.haltNotifier());

        // Handler, halt sink and sentinel poller all installed BEFORE the
        // dial: a window in which the client is live with one of the three
        // kill paths missing is a window in which spec s4's promise is not
        // true.
        c.setSendHandler((header, body, auth) -> {
            // The limits the operator configured, taken from the same snapshot
            // this request is about to be decided under. Armed once; a later
            // configure re-authorises scope, not issuance.
            limits.arm(auth);
            return sender.issue(header, body, auth);
        });
        // Without this, a halt frame reaches BridgeClient's own flag and
        // stops nothing: that flag governs maySend(), and the send path asks
        // HaltSwitch.
        c.setHaltSink(new BridgeClient.HaltSink() {
            public void halted(String reason) { haltSwitch.haltedByFrame(reason); }
            public void resumed()             { haltSwitch.resumedByFrame(); }
        });
        // ...and the way back. Without this, maySend() and checkMaySend() see
        // the `halt` FRAME and nothing else: a sentinel-file halt, a stalled
        // poller and an auto-halt all leave them answering true, measured.
        // A method reference and not a lambda body, so there is one answer to
        // "is the run stopped" and the send path runs it too.
        c.setHaltSource(sender::issuanceHeldReason);
        // s4: the rate and budget are armed once and held for the run, so a
        // later configure naming a different one must be REFUSED rather than
        // silently ignored -- an operator who believes they slowed the run
        // down and did not is the failure this exists to prevent.
        c.setConfigGuard(limits::refuseIfLimitsMoved);

        // ---- S4's SECOND enforcement point -------------------------------
        //
        // Wired here: after the send path, and BEFORE the dial -- the same
        // rule the kill paths follow and for the same reason. A window in
        // which the proxy is live and the gate is not is a window in which
        // S4's promise ("every byte that leaves this machine crosses exactly
        // one of two enforcement points") is false.
        //
        // Nothing in this block can be DRIVEN without Burp -- the handlers
        // take Montoya types that only Burp constructs -- so ChokepointTest
        // counts and positions it instead: the registrations, the gate call
        // inside the handler, the scope re-check before the bytes leave, and
        // the two ORDERINGS this join exists to protect (enforcement before
        // recording, redaction before queueing). The ONE piece of it that is
        // ordinary code is `listenerPort` below, which takes a String; it is
        // public and ProxyGateTest drives it.
        //
        // AN ASSUMPTION THIS WIRING RESTS ON AND CANNOT CHECK, written down
        // for Task 9 to measure rather than left implicit: that a request
        // issued by the SEND path -- `api.http().sendRequest` in the adapter
        // below -- does NOT also traverse these proxy handlers. If it did,
        // every send would be decided twice and, worse, attributed by a
        // listener port it does not have: UNATTRIBUTED, refused, and the send
        // path dead. Montoya issues those from Burp's own HTTP stack rather
        // than through a proxy listener, and nothing here has measured it.
        //
        // 0 is "no crawler configured", which Source.forListenerPort reads as
        // "attribute every request whose own listener port parses to
        // OPERATOR". A deployment that never sets -Dhx.crawler_port therefore
        // applies the human's rules to humans rather than the agent's rules to
        // a human by accident.
        int crawlerPort = Integer.getInteger("hx.crawler_port", 0);
        ProxyGate gate = new ProxyGate(policy);   // THE SAME Policy -- see above
        Capture capture = new Capture(Capture.DEFAULT_CAPACITY, c.exchangeSink());
        // ONE number for both bounds, so there is one figure to reason about
        // rather than two. It is NOT a claim that the two overflow together:
        // they count different things -- the queue holds records waiting for
        // the drain, this map holds requests waiting for a response -- and an
        // empty queue is perfectly compatible with 600 requests in flight and
        // this map evicting. What the map's bound says is only this: it
        // overflows once more than DEFAULT_CAPACITY requests are unanswered at
        // one moment, and every eviction past that is a `take` that will miss
        // and a record counted lost.
        Pending pending = new Pending(Capture.DEFAULT_CAPACITY);

        api.proxy().registerRequestHandler(new ProxyRequestHandler() {

            /**
             * The request arriving from the browser: attribute it, decide
             * about it, and either drop it or start its clock.
             */
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest r) {
                // UNATTRIBUTED until proved otherwise, so a throw out of any
                // of the reads below leaves the source at the answer ProxyGate
                // refuses rather than at the permissive one. `method` and
                // `url` are read into locals inside the try for the same
                // reason the adapter builds its request inside one: they are
                // Montoya's code handed a hostile page's bytes, and a throw
                // out of them while building the Denied would escape this
                // handler entirely.
                Source source = Source.UNATTRIBUTED;
                String method = "";
                String url = "";
                ProxyGate.Verdict verdict;
                try {
                    source = Source.forListenerPort(
                            listenerPort(r.listenerInterface()), crawlerPort);
                    method = r.method();
                    url = r.url();
                    // ONE read, passed in. configEpoch() and scopeConfig() are
                    // two reads of one record and can straddle a commit; a
                    // decision made from two halves of two authorisations is a
                    // decision about a request nobody authorised.
                    BridgeClient.Authorisation auth = c.authorisation();
                    verdict = gate.decide(proxyRequest(r), auth, source);
                } catch (RuntimeException e) {
                    // A gate that threw has decided NOTHING, and the only safe
                    // reading of nothing is no. `not_configured` with the
                    // EXTENSION_FAULT prefix, per S6's documented overload: a
                    // broken jar and an unconfigured run land under one
                    // denial.kind and the prefix is what separates them.
                    verdict = new ProxyGate.Verdict(false, "not_configured",
                            BridgeClient.EXTENSION_FAULT
                            + "the proxy request handler threw: " + e);
                }
                if (!verdict.allow()) {
                    capture.offer(new Denied(method, url, verdict.errorClass(),
                                             verdict.detail(), source));
                    return ProxyRequestReceivedAction.drop();
                }
                // nanoTime, not the wall clock: this is the origin of a
                // DURATION, and Instant.now() would measure an NTP step as
                // latency. Same distinction the send adapter makes below.
                pending.put(r.messageId(), System.nanoTime(), source);
                return ProxyRequestReceivedAction.continueWith(r);
            }

            /**
             * The last point before the bytes leave, and the reason this
             * handler has two halves.
             *
             * Burp's Intercept tab sits BETWEEN the two callbacks, and an
             * operator there can rewrite the request -- including its host. A
             * gate that ran only at the first point would let an EDITED
             * request leave with no decision about it at all, and S4 is
             * unambiguous about what that costs: scope is the client's
             * boundary and the one thing no caller may spend.
             *
             * SCOPE AND NOTHING ELSE, for every source. `decideScopeOnly`
             * spends no rate token and no budget slot, so this re-check is
             * free; `decide` would charge a crawler twice for one request, and
             * ChokepointTest's pair counter could not see it because that one
             * counts Policy's internal halves on the send path.
             *
             * TWO HONEST LIMITS. `drop()` from THIS callback is unmeasured --
             * Task 1 measured the drop from handleRequestReceived only, where
             * it sends zero bytes to the target and answers the client 200 OK
             * with Burp's own HTML. The claim here is "Montoya documents both
             * actions identically", not "we saw zero bytes"; Task 9 measures
             * it. And this is a second scope DECISION, not a second
             * enforcement point: S4 counts egress paths, not callbacks, and
             * both callbacks belong to this one handler.
             */
            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest r) {
                String method = "";
                String url = "";
                boolean allow;
                String errorClass = null;
                String detail = null;
                try {
                    method = r.method();
                    url = r.url();
                    BridgeClient.Authorisation auth = c.authorisation();
                    Decision d = policy.decideScopeOnly(proxyRequest(r), auth);
                    allow = d.allowed();
                    errorClass = d.errorClass();
                    detail = d.detail();
                } catch (RuntimeException e) {
                    Decision d = Decision.deny("not_configured",
                            BridgeClient.EXTENSION_FAULT
                            + "the pre-send scope re-check threw: " + e);
                    allow = false;
                    errorClass = d.errorClass();
                    detail = d.detail();
                }
                if (!allow) {
                    // The entry will never be answered: this request is not
                    // going to the target, so no response can arrive for it.
                    // Taken rather than left to age out, so the map's bound is
                    // spent on requests that are actually in flight -- and the
                    // source it carries is the attribution the FIRST callback
                    // made, which is the only one either callback ever makes.
                    Pending.Entry e = pending.take(r.messageId());
                    capture.offer(new Denied(method, url, errorClass, detail,
                                             e == null ? Source.UNATTRIBUTED : e.source()));
                    return ProxyRequestToBeSentAction.drop();
                }
                return ProxyRequestToBeSentAction.continueWith(r);
            }
        });

        api.proxy().registerResponseHandler(new ProxyResponseHandler() {

            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse r) {
                Pending.Entry e = pending.take(r.messageId());
                if (e == null) {
                    // NO START TIME AND NO SOURCE, so there is no exchange to
                    // record: a row with a guessed duration on it is
                    // fabricated evidence, and this project has refused that
                    // twice already. Charged to UNATTRIBUTED because this is
                    // the one place the source is genuinely unknown -- a drop
                    // with no run attached beats a drop filed against a run
                    // that was picked.
                    capture.countLost(Source.UNATTRIBUTED);
                    return ProxyResponseReceivedAction.continueWith(r);
                }
                try {
                    // REDACTION FIRST, and before anything is queued. S7 makes
                    // the blob store content-addressed, so a credential that
                    // reaches the hashing step on the Python side is already
                    // unrecoverable -- and Observed's own javadoc says its byte
                    // arrays are post-redaction, which makes an Observed
                    // holding raw bytes a live credential sitting in a queue.
                    byte[] reqBytes = r.initiatingRequest().toByteArray().getBytes();
                    // Empty, because the proxy path injects no identity of its
                    // own -- but still REQUIRED, and constructed over the same
                    // array the ranges would have been measured from: Injected
                    // compares by identity and refuses a different array.
                    byte[] redactedReq = redactor.redactRequest(
                            reqBytes, new Redactor.Injected(reqBytes));
                    byte[] redactedResp = redactor.redactResponse(
                            r.toByteArray().getBytes());
                    long ms = (System.nanoTime() - e.startNanos()) / 1_000_000L;
                    capture.offer(new Observed(r.initiatingRequest().method(),
                                               r.initiatingRequest().url(),
                                               r.statusCode(), ms,
                                               redactedReq, redactedResp,
                                               e.source()));
                } catch (RuntimeException ex) {
                    // Redaction that could not finish, or bytes Montoya would
                    // not hand over. The record is lost either way and says so
                    // -- offering it unredacted is the one answer that is
                    // worse than losing it.
                    capture.countLost(e.source());
                }
                return ProxyResponseReceivedAction.continueWith(r);
            }

            /** A bare pass-through. The response was already captured at
             *  handleResponseReceived; capturing it again here would double
             *  every row in the store. */
            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse r) {
                return ProxyResponseToBeSentAction.continueWith(r);
            }
        });

        haltSwitch.start();
        capture.start();
        this.halt = haltSwitch;
        this.capture = capture;
        this.client = c;

        Thread t = new Thread(() -> {
            try {
                c.connect();
            } catch (Exception e) {
                api.logging().logToError("hx: bridge connect failed: " + e);
            }
        }, "hx-bridge");
        t.setDaemon(true);
        t.start();

        api.extension().registerUnloadingHandler(() -> {
            BridgeClient live = client;
            if (live != null) live.close();
            HaltSwitch h = halt;
            if (h != null) h.stop();
            // ONE stop(), here, and there is no second. A record offered
            // DURING stop() counts itself (Capture's path 5) and has nothing
            // left to report through; a second call would race the first
            // identically while the JVM is being torn down. `this.capture`
            // and not `capture`: the local of that name inside initialize
            // shadows the field, and it is the FIELD this handler -- on
            // another thread -- must read.
            Capture cap = this.capture;
            if (cap != null) cap.stop();
        });
        api.logging().logToOutput("hx: bridge dialling " + sock);
    }

    /**
     * The port off Burp's `listenerInterface()`, or {@link Source#NO_PORT}
     * when there is not one to be had.
     *
     * MEASURED: `listenerInterface()` answers `"127.0.0.1:<port>"` and names a
     * different port per listener, over plain HTTP and through a CONNECT
     * tunnel -- docs/burp-proxy-measurements.md, Q1. There is no
     * `listenerPort()` on an intercepted message (the HISTORY type has one and
     * is not reachable from a handler), so the port is parsed after the LAST
     * colon: an IPv6 interface is `[::1]:8080` and the first colon is inside
     * the address.
     *
     * EVERY FAILURE OF THE PARSE ANSWERS NO_PORT, and none of them invents a
     * number: a null interface, no colon at all, an empty tail, a tail that is
     * not all digits, and a digit run too long for {@code Integer.parseInt} to
     * take. `Source.forListenerPort` turns NO_PORT into UNATTRIBUTED and
     * ProxyGate REFUSES it -- "we could not work out who is driving" is a code
     * failure or a change in Burp, and the operator branch is the one that
     * drops the method allowlist, the dangerous-path denylist, the rate limit
     * and the budget. The refusal is not caught and retried as OPERATOR.
     *
     * WHAT THIS METHOD DOES NOT DO IS RANGE-CHECK, and that is deliberate
     * rather than an omission. `70000` parses fine and is handed over as
     * itself; {@link Source#forListenerPort} answers UNATTRIBUTED for anything
     * outside 1..65535, and duplicating that test here would add a branch no
     * input could separate from its absence -- the same finding Source's own
     * comment records about a `crawlerPort > 0` clause it removed. The
     * five-digit bound below is NOT that test wearing a disguise: it exists
     * only because {@code Integer.parseInt} THROWS on a longer run of digits,
     * and a throw out of here reaches a Burp proxy thread with no answer for
     * it. `ProxyGateTest.theListenerInterfaceIsParsedOrRefused` pins the
     * boundary from both sides.
     *
     * NOT the same thing as an unrecognised port. A port that PARSES and is
     * not the crawler's is the operator, deliberately -- see Source, which
     * pins both sides of that line.
     *
     * PUBLIC and static so it can be DRIVEN. It is the one piece of the second
     * enforcement point that needs no Burp to run, and it decides which of two
     * rule sets a request gets -- leaving it untestable alongside everything
     * else in this file would leave the attribution parse itself resting on
     * nothing. `ProxyGateTest.theListenerInterfaceIsParsedOrRefused` is where
     * it is pinned, next to the attribution rule it feeds.
     */
    public static int listenerPort(String listenerInterface) {
        if (listenerInterface == null) return Source.NO_PORT;
        int colon = listenerInterface.lastIndexOf(':');
        if (colon < 0) return Source.NO_PORT;
        String tail = listenerInterface.substring(colon + 1);
        if (tail.isEmpty()) return Source.NO_PORT;
        for (int i = 0; i < tail.length(); i++)
            if (tail.charAt(i) < '0' || tail.charAt(i) > '9') return Source.NO_PORT;
        // Bounded before parsing: `Integer.parseInt` on a 30-digit run of
        // digits throws, and a throw here would be a decision this method
        // cannot make reaching a caller that has no answer for it either.
        if (tail.length() > 5) return Source.NO_PORT;
        return Integer.parseInt(tail);
    }

    /**
     * One intercepted request, as the rules ask about it.
     *
     * `path()` carries the query and Policy wants the two apart, so it is
     * split at the FIRST `?` -- `pathWithoutQuery()` exists and would be a
     * second accessor to trust where one already answers. Policy checks that
     * the url's authority and path agree with `host` and `path` before it
     * matches anything (Policy.checkScope), so a Burp that disagreed with
     * itself is a scope_denied rather than a decision about the wrong
     * destination.
     *
     * Every field is read from Montoya inside the CALLER'S try. A null out of
     * any of them is an IllegalArgumentException from HxRequest's own
     * constructor, which is a RuntimeException, which is a DENY.
     */
    private static HxRequest proxyRequest(InterceptedRequest r) {
        String pathAndQuery = r.path();
        int q = pathAndQuery.indexOf('?');
        String path = q < 0 ? pathAndQuery : pathAndQuery.substring(0, q);
        String query = q < 0 ? "" : pathAndQuery.substring(q + 1);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (HttpHeader h : r.headers())
            headers.computeIfAbsent(h.name(), k -> new ArrayList<>()).add(h.value());
        return new HxRequest(r.method(), r.url(), r.httpService().host(),
                             path, query, headers, r.body().getBytes());
    }

    /**
     * The extension's only route to the network.
     *
     * Everything above this line is testable without Burp; nothing below it
     * is. Keeping it to one lambda is what makes ChokepointTest's count mean
     * something.
     */
    private static Http montoyaHttp(MontoyaApi api, Clock clock) {
        return (req, deadlineUs) -> {
            // Monotonic, because this one IS a duration. Instant.now() would
            // measure an NTP step as latency and feed it to Distress, whose
            // latency rule stops the whole run at 5x baseline. Taken before the
            // try, so a build that throws still has a t0 to have failed after.
            long t0 = System.nanoTime();
            HttpRequestResponse rr;
            // EVERYTHING the adapter does is inside this try, not just the
            // egress call. Sender.portOf throws IllegalArgumentException on an
            // authority whose post-colon text is not an integer, and
            // HttpService.httpService / HttpRequest.httpRequest are Montoya's
            // code handed attacker-influenced strings -- all three used to sit
            // ABOVE the try doing exactly what the catch below says must not
            // happen. ChokepointTest pins their position, because nothing can
            // test this file behaviourally.
            try {
                HttpService service = HttpService.httpService(
                        req.host(), Sender.portOf(req), Sender.secureOf(req));
                HttpRequest request = HttpRequest.httpRequest(
                        service, ByteArray.byteArray(Sender.wireBytes(req)));

                // Burp's own timeout is an optimisation; ours is the
                // enforcement. Sender re-reads the clock after this returns
                // and answers `timeout` on its own account, so an overshoot
                // here -- or a unit that is not what we think it is -- cannot
                // turn into a result frame for a caller that stopped waiting.
                long remainingMs = Math.max(1L, (deadlineUs - clock.nowUs()) / 1000L);
                RequestOptions options = RequestOptions.requestOptions()
                        // Spec s4: redirects are not auto-followed. Each hop is
                        // a distinct issuance with its own scope decision. Burp
                        // does not follow them on sendRequest today; saying so
                        // explicitly means a future default cannot create an
                        // egress path that never crossed Policy.
                        .withRedirectionMode(RedirectionMode.NEVER)
                        .withResponseTimeout(remainingMs);

                rr = api.http().sendRequest(request, options);
            } catch (RuntimeException e) {
                // Montoya answers most transport failures with a response-less
                // HttpRequestResponse rather than throwing, but "most" is not
                // "all", and a RuntimeException escaping here would reach
                // BridgeClient's catch-all and close the connection. Sender
                // handles IOException and feeds it to Distress; give it one.
                throw new IOException("could not issue " + req.url(), e);
            }
            long ms = (System.nanoTime() - t0) / 1_000_000L;

            if (!rr.hasResponse())
                // A refused connection, a DNS failure and a TLS failure all
                // arrive here rather than as an exception. The flag is what
                // lets Distress count them toward its consecutive-error stop;
                // a status of 0 would count as an ordinary non-5xx reply.
                return new HttpReply(0, new byte[0], ms, true);

            return new HttpReply(rr.response().statusCode(),
                                 rr.response().toByteArray().getBytes(), ms, false);
        };
    }
}
