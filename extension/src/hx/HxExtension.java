package hx;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import hx.bridge.BridgeClient;
import hx.policy.Clock;
import hx.policy.Distress;
import hx.policy.Policy;
import hx.send.HaltSwitch;
import hx.send.Http;
import hx.send.HttpReply;
import hx.send.Limits;
import hx.send.Redactor;
import hx.send.Sender;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;

/**
 * Burp entry point, and the only file in extension/src that names burp.* at
 * all. It reads its socket path, engagement id, instance id and halt sentinel
 * from system properties so the harness controls them at launch, builds the
 * send path, then dials in on a background thread and stays in DENY-ALL until
 * configured.
 */
public class HxExtension implements BurpExtension {

    // Written on Burp's initialize thread, read by the unloading handler on
    // another -- the same cross-thread edge the bridge's own fields were fixed
    // for. Read it ONCE into a local there too: `if (client != null)
    // client.close()` races itself, NPEs inside the handler, and skips the
    // close() that was the point of the handler.
    private volatile BridgeClient client;
    private volatile HaltSwitch halt;

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
        haltSwitch.start();
        this.halt = haltSwitch;
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
        });
        api.logging().logToOutput("hx: bridge dialling " + sock);
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
