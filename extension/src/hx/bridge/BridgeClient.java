package hx.bridge;

import java.io.*;
import java.net.*;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The Burp end of the bridge. Dials the harness, announces itself, and refuses
 * to send anything until it has been configured.
 *
 * DENY-ALL is the initial and terminal state. Burp's extensionData does not
 * survive a restart, so a reconnected extension knows nothing -- it must be
 * told the scope again before it may issue a single request.
 */
public final class BridgeClient {

    public static final long PROTOCOL_VERSION = 1L;

    /**
     * What a `not_configured` detail says when the extension is at fault
     * rather than the operator.
     *
     * `not_configured` is OVERLOADED: it is the class for "no configure has
     * been acknowledged" AND for a send path that threw or was never
     * installed. docs/bridge-protocol.md's class list records that;
     * spec s6's does not -- it names the class and nothing more, and widening
     * s6's own enumeration was not this round's licence.
     * The two readings are opposite instructions. The first says an operator
     * has not authorised the run yet and the second says this jar is broken,
     * and only the second is a reason to look at a stack trace.
     *
     * That matters at the store, not just at the console. `records.DENIAL_KIND`
     * maps this class to `kind='not_configured'`, so both file the same row
     * and `SELECT kind, COUNT(*) FROM denial GROUP BY kind` reads a crash as
     * an unauthorised run. The class cannot be split without amending s6's
     * enumeration, which is a protocol change; the DETAIL can carry it today,
     * and a prefix carries it in a form a consumer can test for rather than
     * one it has to parse prose out of. `records.EXTENSION_FAULT` is the same
     * string on the Python side.
     */
    public static final String EXTENSION_FAULT = "extension fault: ";

    public static class NotConfigured extends RuntimeException {
        public NotConfigured(String m) { super(m); }
    }

    /**
     * The two logging calls the bridge makes. Montoya's Logging satisfies it
     * through an adapter and the test fake implements it directly. Declaring
     * it here is what keeps BridgeClient free of a compile-time Montoya
     * dependency -- and unlike the `Object log` it replaces, it can actually
     * be called.
     */
    public interface Log {
        void info(String s);
        void error(String s);
    }

    /** The reserved key a SendHandler puts the redacted response body under.
     *  It cannot travel in a flat JSON header, and Json.write refuses a byte[]
     *  -- so a framer that forgets the remove() below throws JsonError rather
     *  than quietly writing a result frame with the evidence missing. */
    public static final String BODY_KEY = "@body";

    /**
     * What answers a `send` frame. Sender.issue has this shape; it is a
     * functional interface so HxExtension can install it as a lambda, which
     * keeps hx.send.Sender free of any declared dependency on this class
     * beyond the Authorisation record it is handed.
     */
    @FunctionalInterface
    public interface SendHandler {
        Map<String, Object> handle(Map<String, Object> header, byte[] body, Authorisation auth);
    }

    // Written on Burp's initialize thread before connect(), read on the read
    // loop's thread. Volatile for the same reason every other field here is.
    private volatile SendHandler sendHandler;

    /** Install the send path. Called before connect(): a client that is live
     *  with no handler answers every send `not_configured`, which is correct
     *  but useless. */
    public void setSendHandler(SendHandler h) { this.sendHandler = h; }

    /**
     * The unsolicited stop frame, burp -> py.
     *
     * Spec s6: auto-halt is extension-initiated, so there is no outstanding id
     * to answer. This is a push, not a reply, and it is the only way the
     * harness learns of a stop before the next send fails -- which matters
     * because `run.status = 'aborted'` needs a stop_reason, and the only place
     * that reason exists is the extension that decided to stop.
     */
    public interface HaltNotifier {
        void halted(String reason, String host, String window);
    }

    /**
     * A notifier that frames {v, t:"halted", reason, host, window} and writes
     * it down the socket.
     *
     * The three fields are what the harness needs to write one row: the
     * reason, the host that produced it, and the window it was measured over
     * -- "5xx rate 0.40" is not an explanation without the last of those.
     */
    public HaltNotifier haltNotifier() {
        return (reason, host, window) -> {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("v", PROTOCOL_VERSION);
            f.put("t", "halted");
            f.put("reason", reason);
            f.put("host", host);
            f.put("window", window);
            try {
                send(f, new byte[0]);
            } catch (IOException e) {
                // The stop could not be delivered, so nothing on the far side
                // will record it. A peer that cannot be told we stopped is a
                // peer we have no authorisation from either: DENY-ALL is where
                // an undelivered stop lands.
                log.error("hx: halted frame undeliverable, deny-all: " + e);
                denyAll();
            }
        };
    }

    /**
     * Where `halt` and `resume` frames land: the switch the SEND PATH asks.
     *
     * HaltSwitch has the matching pair of methods but does not implement this
     * interface -- hx.send must not take a compile-time dependency on the
     * bridge for a two-method callback -- so HxExtension installs a delegating
     * instance, in one place, before it dials.
     */
    public interface HaltSink {
        void halted(String reason);
        void resumed();
    }

    // Written on Burp's initialize thread before connect(), read on the read
    // loop's thread. Volatile for the same reason every other field here is.
    private volatile HaltSink haltSink;

    /** Install the halt switch. Called before connect(): a client that goes
     *  live with no sink routes halt frames to its own flag alone, and that
     *  flag is not what Sender asks. */
    public void setHaltSink(HaltSink s) { this.haltSink = s; }

    /**
     * The other direction: what the SEND PATH would refuse for, asked.
     *
     * {@link HaltSink} is one-way, and that asymmetry was a fail-open hole.
     * This client keeps a {@code halted} flag written by the `halt` and
     * `resume` frame arms and by nothing else -- there are exactly TWO writes
     * to it in this file, one in each arm -- while spec s4 names THREE kill
     * paths. The sentinel file (with its stalled-poller rule) and the
     * auto-halt on target distress never reach that flag; the send path asks
     * {@code Sender.issuanceHeldReason()} instead.
     *
     * MEASURED against this client before this interface existed, with the
     * client configured and live:
     *
     *   sentinel file present   HaltSwitch.halted()=true   maySend()=true
     *   poller stalled          HaltSwitch.halted()=true   maySend()=true
     *   auto-halt tripped       stopReason() non-null      maySend()=true
     *
     * and {@link #checkMaySend()} threw nothing in all three. So a second
     * enforcement point written against the obvious gate on the class the
     * bridge already routes through -- {@code if (client.maySend())} -- would
     * keep issuing through an operator halt raised by hand.
     *
     * ONE method, and it returns the REASON rather than a boolean, so the
     * implementation HxExtension installs is {@code sender::issuanceHeldReason}
     * -- the same code the send path runs, not a second opinion assembled here
     * from the same two objects.
     */
    public interface HaltSource {
        /** Why issuance is held, or null while nothing is holding it. */
        String heldReason();
    }

    // Written on Burp's initialize thread before connect(), read wherever
    // maySend() is. Volatile for the same reason haltSink is.
    private volatile HaltSource haltSource;

    /** Install the send path's halt authority. Called before connect(), for
     *  the same reason setHaltSink is: until it is installed, maySend()
     *  answers false -- a client that cannot ask whether the run is stopped
     *  does not get to say it is not. */
    public void setHaltSource(HaltSource s) { this.haltSource = s; }

    /**
     * Whether a `configure` can be acted on, asked before it is committed.
     *
     * There is exactly one thing this answers today and spec s4 names it:
     * `Limits` takes the rate and budget from the FIRST authorisation with an
     * epoch and holds them for the run, because the budget must be monotonic
     * -- a scope push must not resupply a run that has spent its requests. So
     * an operator pushing `limit.rate_rps: 1` mid-run got a fresh
     * `config_epoch`, no error, no log line, and the OLD RATE. Lowering a rate
     * is the one change that is always safe, and believing you have slowed a
     * run down when you have not is the failure to avoid.
     *
     * A refusal here is `bad_config`: DENY-ALL first, channel kept, so a
     * corrected configure can follow. Same answer as an unparseable configure
     * and for the same reason -- carrying on under the PREVIOUS intent is
     * exactly the harm when the new intent was tighter.
     *
     * This is NOT re-arming, which is a later plan's work. It is the refusal
     * that makes the absence of re-arming visible.
     */
    public interface ConfigGuard {
        /** Why this configure cannot be acted on, or null when it can. */
        String refuse(Map<String, List<String>> scope);
    }

    private volatile ConfigGuard configGuard;

    /**
     * Install it. Called before connect(), with the others.
     *
     * An UNINSTALLED guard accepts, unlike {@link #setHaltSource}, and the
     * asymmetry is deliberate: a halt source that is missing leaves a question
     * about stopping unanswered, where a config guard that is missing leaves
     * the pre-existing silent-ignore. Failing closed here would mean an
     * extension that cannot be configured at all, which is worse than the
     * thing being fixed. ChokepointTest counts the wire instead.
     *
     * A guard that THROWS is a refusal. It is asked about an operator's
     * intent, and an answer it could not produce is not permission.
     */
    public void setConfigGuard(ConfigGuard g) { this.configGuard = g; }

    private final Path socketPath;
    private final String engagementId;
    private final String instanceId;
    private final Log log;

    private volatile SocketChannel channel;
    private volatile InputStream in;
    private volatile OutputStream out;

    // F1: close() must be STICKY. Without it a client that was closed before
    // its dial completed goes on to hello, configure and live sending -- an
    // unloaded extension holding a control channel on a daemon thread.
    private volatile boolean closed = false;

    // close() and the read loop's configure commit both mutate the permission
    // state from different threads. Re-checking `closed` after the commit only
    // makes the window narrow (~ns); this monitor makes it not exist. In a
    // component whose whole job is refusing to send, "too small to observe" is
    // not the same as "cannot happen".
    //
    // Package-private, not private: BridgeClientTest.theCommitIsExclusiveWith-
    // Close() takes this monitor itself to park a commit inside handle()'s
    // `synchronized (commitLock)` deterministically. See the note on handle()
    // below -- this field's visibility is load-bearing for that test.
    final Object commitLock = new Object();

    private final AtomicBoolean configured = new AtomicBoolean(false);
    private final AtomicBoolean halted = new AtomicBoolean(false);

    /**
     * The epoch and the scope it authorises, published together.
     *
     * They were two volatile fields, and a caller holding no lock cannot read
     * two volatiles coherently no matter where the writes sit: the review
     * measured maySend() answering true with configEpoch()==1 while
     * scopeConfig() already returned the epoch-2 scope. A request only epoch 2
     * permits then goes out stamped epoch 1 -- an evidence line claiming
     * authorisation from an epoch that never granted it. Moving the writes
     * inside commitLock did not fix it (still 9/200); one reference does,
     * because there is only one write to observe.
     */
    public record Authorisation(long epoch, Map<String, List<String>> scope) { }
    private static final Authorisation DENIED = new Authorisation(0, Map.of());
    private volatile Authorisation committed = DENIED;

    private volatile String haltReason = null;
    private long epochCounter = 0;

    public BridgeClient(Path socketPath, String engagementId, String instanceId, Log log) {
        this.socketPath = socketPath;
        this.engagementId = engagementId;
        this.instanceId = instanceId;
        this.log = log;
    }

    public boolean isConfigured() { return configured.get(); }

    /**
     * @deprecated Two reads of {@link #committed}: a commit can land between
     * this call and a following {@link #scopeConfig()} (or vice versa), so
     * the pair straddles the commit and a decision can be made under one
     * epoch's scope while stamped with the other's epoch -- the natural read
     * order, {@code scopeConfig()} then {@code configEpoch()}, is the
     * dangerous one, since it yields the new epoch with the old, superseded
     * scope. Any decision that must send with an epoch and the scope that
     * epoch actually authorises has to read both in the one call
     * {@link #authorisation()} makes. Retained for callers that read only
     * this field.
     * @see BridgeClient#authorisation()
     */
    @Deprecated
    public long configEpoch() { return committed.epoch(); }

    /**
     * @deprecated See {@link #configEpoch()}: this is the other half of the
     * same straddle. Retained for callers that read only this field.
     * @see BridgeClient#authorisation()
     */
    @Deprecated
    public Map<String, List<String>> scopeConfig() { return committed.scope(); }

    /**
     * Epoch and scope in ONE read. Publishing them through a single reference
     * makes the STATE coherent, but configEpoch() then scopeConfig() is still
     * two reads of it and a commit can land between them: a busy poll measured
     * 11/400 there, against 32/400 for the two-field version this replaced.
     * Narrower is not closed. Anything that decides under a scope and then
     * stamps the epoch that granted it -- Plan 3's send path, and the evidence
     * line behind it -- must take the pair from here, once.
     */
    public Authorisation authorisation() { return committed; }

    /**
     * Is anything stopping issuance right now?
     *
     * THREE authorities, not one: this client's own two flags, plus the
     * {@link HaltSource} the send path enforces. It used to be the two flags
     * alone -- see HaltSource for the measurement -- and the flag it calls
     * `halted` is the `halt` FRAME and nothing else.
     *
     * WHAT A TRUE ANSWER DOES NOT MEAN. Every refusal that needs a request in
     * hand is still ahead: scope, method, dangerous path, unmanaged
     * credential, rate, budget, deadline. This answers "is the run stopped",
     * which is a necessary condition for issuing and not a sufficient one.
     * The only thing that decides a REQUEST is {@code Sender.issue}.
     *
     * Keeping the local `halted` flag as well as asking the source is not
     * redundancy for its own sake. The `halt` arm tells the switch FIRST and
     * sets this flag second, and `resume` clears this flag first and tells the
     * switch last; the AND is what leaves no window on either transition in
     * which this answers true while one of the two authorities is holding.
     */
    public boolean maySend() {
        return configured.get() && !halted.get() && heldReason() == null;
    }

    /**
     * The send path's halt authority, asked safely.
     *
     * FAIL CLOSED on an uninstalled source, and on one that throws. A client
     * that cannot find out whether the run is stopped has not found out that
     * it is running, and DENY-ALL is what this branch is. HxExtension installs
     * it before the dial, alongside the sink, so the null case is a wiring
     * failure rather than a state -- and a wiring failure that denies is one
     * somebody notices.
     */
    private String heldReason() {
        HaltSource s = haltSource;
        if (s == null) return "no halt source installed";
        try {
            return s.heldReason();
        } catch (Throwable t) {
            return "halt source threw: " + t;
        }
    }

    /** Drop to DENY-ALL. Returns whether the client had been configured.
     *  `configured` is cleared FIRST: maySend() reads only that and `halted`,
     *  so no observer sees permission outlive the scope behind it. */
    private boolean denyAll() {
        boolean was = configured.getAndSet(false);
        committed = DENIED;
        return was;
    }

    /** Throws unless {@link #maySend()} would answer true, and says which of
     *  the three authorities refused. Same caveat as maySend(): not throwing
     *  means the RUN is not stopped, not that a given request may go out. */
    public void checkMaySend() {
        if (!configured.get())
            throw new NotConfigured("not_configured: no configure frame acknowledged yet");
        if (halted.get())
            throw new NotConfigured("halted: " + (haltReason == null ? "no reason given" : haltReason));
        String held = heldReason();
        if (held != null)
            throw new NotConfigured("halted: " + held);
    }

    public void connect() throws IOException {
        if (closed) throw new IOException("this client is closed; make a new one");
        channel = SocketChannel.open(UnixDomainSocketAddress.of(socketPath));
        in = Channels.newInputStream(channel);
        out = Channels.newOutputStream(channel);

        Map<String, Object> hello = new LinkedHashMap<>();
        hello.put("v", PROTOCOL_VERSION);
        hello.put("t", "hello");
        hello.put("ext_version", "0.1.0");
        hello.put("pid", ProcessHandle.current().pid());
        hello.put("burp_version", System.getProperty("hx.burp.version", "unknown"));
        hello.put("instance_id", instanceId);
        hello.put("engagement_id", engagementId);
        try {
            send(hello, new byte[0]);
        } catch (IOException | RuntimeException e) {
            closeChannel();          // F6: a dialled channel must not outlive a failed hello
            throw e;
        }
        // close() may have run while we were dialling: it had no channel to
        // shut and nothing configured to clear, so it left no trace here.
        if (closed) { closeChannel(); return; }

        readLoop();
    }

    private void readLoop() {
        // The Reader is created once, outside the loop, and owns its buffer
        // across iterations. Constructing one per iteration would lose every
        // frame that arrived in the same delivery as its predecessor.
        Frame.Reader reader = new Frame.Reader(in);
        try {
            while (true) {
                Frame.Decoded f = reader.read();
                if (!handle(f)) return;
            }
        } catch (Frame.PeerClosed | Frame.FrameError | IOException e) {
            // The expected ways a connection ends. Nothing to do here: the
            // finally block is what enforces the terminal state.
        } finally {
            // DENY-ALL on EVERY exit path, not just the ones named above. The
            // `return` out of the loop -- a protocol mismatch -- skips the
            // catch blocks entirely, and used to leave maySend() true with a
            // dead read loop and no control channel: the extension would keep
            // issuing requests that nothing could halt. This is the same shape
            // as the Python side's _reset() in _serve()'s finally, and for the
            // same reason.
            boolean wasConfigured = denyAll();
            closeChannel();
            if (wasConfigured) log.info("hx: control channel gone, deny-all");
        }
    }

    /** Test seam: is the dialled channel still open? Package-private and
     *  BridgeClient is final, so it cannot escape hx.bridge. F6 -- a channel
     *  outliving a failed hello -- has no other observable. */
    boolean channelIsOpen() {
        SocketChannel c = channel;
        return c != null && c.isOpen();
    }

    private void closeChannel() {
        try { if (channel != null) channel.close(); } catch (IOException ignored) { }
    }

    /** Package-private, not private: BridgeClientTest calls this directly to
     *  check that a closed client refuses a frame without needing to win a
     *  race first. BridgeClient is final, so nothing escapes hx.bridge.
     *
     *  Both this method's visibility and commitLock's are load-bearing for
     *  theCommitIsExclusiveWithClose(): that test holds commitLock on its own
     *  thread, calls handle() directly from a second thread so it parks on
     *  `synchronized (commitLock)` below, then calls close() -- which takes
     *  the same monitor -- reentrantly from the first thread. Make either
     *  member private again and that test cannot compile, let alone run; a
     *  later "tidy-up" that does so would silently delete the only
     *  deterministic coverage of the commit-lock guard, leaving only the
     *  scheduler-dependent race detector, which passes clean at 1-2 vCPU on
     *  broken code. */
    boolean handle(Frame.Decoded f) throws IOException {
        if (closed) return false;
        Object v = f.header.get("v");
        if (!Long.valueOf(PROTOCOL_VERSION).equals(v)) {
            error(f, "protocol_mismatch", "expected v=" + PROTOCOL_VERSION + " got " + v);
            return false;
        }
        String t = String.valueOf(f.header.get("t"));

        switch (t) {
            case "configure" -> {
                if (!(f.header.get("deadline_us") instanceof Long)) {
                    // Required on every request frame. Missing it means the
                    // sender is not speaking this protocol version properly.
                    error(f, "bad_frame", "request frame has no deadline_us");
                    return true;
                }
                if (!engagementId.equals(f.header.get("engagement_id"))) {
                    error(f, "engagement_mismatch",
                          "configure names engagement " + f.header.get("engagement_id")
                          + " but this extension serves " + engagementId);
                    return true;
                }
                Map<String, List<String>> scope;
                try {
                    scope = ConfigBody.parse(f.body);
                } catch (Frame.FrameError e) {
                    // Unknown intent means DENY, not "carry on under the last
                    // intent". The likeliest trigger is an operator NARROWING
                    // scope with a key this jar predates: keeping the old,
                    // wider scope would then send exactly where they just said
                    // not to. Unlike engagement_mismatch and bad_frame above --
                    // neither of which is our peer trying to configure us --
                    // this one is, and it failed.
                    denyAll();
                    error(f, "bad_config", e.getMessage());
                    return true;
                }
                // BEFORE the commit, so a refused configure leaves no epoch
                // behind. An operator who was told `bad_config` must not find
                // a fresh config_epoch on the next result frame.
                String unusable = refuseConfigure(scope);
                if (unusable != null) {
                    denyAll();
                    error(f, "bad_config", unusable);
                    return true;
                }

                long epoch;
                synchronized (commitLock) {
                    // Either close() got here first -- and we must not undo it
                    // -- or it cannot arrive until this commit is complete and
                    // will then clear it. No ordering in between exists.
                    if (closed) return false;
                    epoch = ++epochCounter;
                    // One write publishes the epoch and the scope it
                    // authorises. Both are visible, or neither is.
                    committed = new Authorisation(epoch, scope);
                    configured.set(true);
                    // NOT halted.set(false). A configure re-authorises SCOPE,
                    // not ISSUANCE. An operator halts BECAUSE the scope went
                    // wrong and then pushes the corrected scope -- the most
                    // likely next action of all -- and clearing the halt here
                    // re-armed issuance with no `resume` on the wire, no log
                    // line, and both consoles reading "configured". Only a
                    // `resume` frame lifts a halt.
                }

                Map<String, Object> ack = new LinkedHashMap<>();
                ack.put("v", PROTOCOL_VERSION);
                ack.put("t", "configured");
                ack.put("id", f.header.get("id"));
                // The epoch WE committed, not whatever configEpoch() says now:
                // a close() between the commit and here zeroes it, and the ack
                // would then claim config_epoch 0 for a configure that was in
                // fact acknowledged under epoch N.
                ack.put("config_epoch", epoch);
                send(ack, new byte[0]);
            }
            case "send" -> {
                if (!engagementId.equals(f.header.get("engagement_id"))) {
                    // s6: every send carries it and the extension refuses a
                    // mismatch. Client A's bytes must never reach client B's
                    // report, and this is the cheapest place to say so.
                    error(f, "engagement_mismatch",
                          "send names engagement " + f.header.get("engagement_id")
                          + " but this extension serves " + engagementId);
                    return true;
                }
                SendHandler h = sendHandler;
                if (h == null) {
                    // "Nothing is wired up yet" is a state, not an exemption.
                    // EXTENSION_FAULT: this is not the operator failing to
                    // configure -- see the constant.
                    error(f, "not_configured",
                          EXTENSION_FAULT + "no send handler is installed");
                    return true;
                }
                Map<String, Object> reply;
                try {
                    // ONE read of the snapshot per decision, carried down as a
                    // parameter. The explicit receiver below is load-bearing:
                    // ChokepointTest counts the snapshot read across
                    // extension/src and expects exactly one, and it counts the
                    // dotted form -- a bare call here reads as zero. Write it
                    // with `this.` and leave it that way.
                    reply = h.handle(f.header, f.body, this.authorisation());
                } catch (Throwable ex) {
                    // An exception is never an implicit allow. Answer the
                    // caller so it gets an error class instead of a silent
                    // bridge_lost, then drop to DENY-ALL and close: a send path
                    // that threw is a send path we no longer understand, and
                    // the terminal state is the only honest place to be.
                    //
                    // `ex`, not `t`: handle() already has a String t, the
                    // frame type it switched on.
                    log.error("hx: send handler threw, deny-all: " + ex);
                    error(f, "not_configured",
                          EXTENSION_FAULT + "the send path threw: " + ex);
                    denyAll();
                    return false;
                }
                Object raw = reply.remove(BODY_KEY);
                send(reply, raw instanceof byte[] b ? b : new byte[0]);
            }
            case "halt" -> {
                // NOT String.valueOf(): for an absent key that answers the
                // four-character string "null", which is neither null nor
                // blank, so HaltSwitch's "no reason given" fallback could
                // never fire for the only production caller and both
                // consoles showed the operator the word null.
                String why = f.header.get("reason") instanceof String r ? r : null;
                // The switch FIRST, this flag second. `halted` here governs
                // maySend()/checkMaySend(); the send path asks HaltSwitch, and
                // on the way DOWN the stricter authority is told first.
                if (!notifyHalt(true, why)) return false;
                halted.set(true);
                haltReason = why;
            }
            case "resume" -> {
                halted.set(false);
                // ...and on the way back UP it is told last, so no window
                // exists in which issuance is armed and the flag behind it is
                // not. Only a `resume` frame reaches here: a `configure` does
                // not lift a halt.
                if (!notifyHalt(false, null)) return false;
            }
            default -> {
                error(f, "unknown_frame", "unrecognised frame type " + t);
            }
        }
        return true;
    }

    /** Ask the {@link ConfigGuard}, safely. A guard that throws refuses: it
     *  is asked about an operator's intent, and an answer it could not
     *  produce is not permission. */
    private String refuseConfigure(Map<String, List<String>> scope) {
        ConfigGuard g = configGuard;
        if (g == null) return null;
        try {
            return g.refuse(scope);
        } catch (Throwable t) {
            return "the configure guard could not decide about this body: " + t;
        }
    }

    /**
     * Hand a halt or a resume to the switch. Returns false when the read loop
     * must drop to DENY-ALL and close.
     *
     * A sink that throws is the one case that cannot be shrugged off: the
     * frame that was supposed to stop issuance did not arrive anywhere, and an
     * exception is never an implicit allow. With no sink installed at all --
     * the state before HxExtension wires one up -- the local flag is the whole
     * answer, and nothing can be issued through a client that has no
     * SendHandler either.
     */
    private boolean notifyHalt(boolean halt, String reason) {
        HaltSink s = haltSink;
        if (s == null) return true;
        try {
            if (halt) s.halted(reason); else s.resumed();
            return true;
        } catch (Throwable t) {
            log.error("hx: halt sink threw, deny-all: " + t);
            denyAll();
            return false;
        }
    }

    private void error(Frame.Decoded f, String cls, String detail) throws IOException {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("v", PROTOCOL_VERSION);
        e.put("t", "error");
        e.put("id", f.header.get("id"));
        e.put("class", cls);
        e.put("detail", detail);
        send(e, new byte[0]);
    }

    private synchronized void send(Map<String, Object> header, byte[] body) throws IOException {
        out.write(Frame.encode(header, body));
        out.flush();
    }

    public void close() {
        synchronized (commitLock) {
            closed = true;           // sticky: checked by connect() and handle()
            denyAll();
        }
        closeChannel();              // I/O outside the monitor
    }
}
