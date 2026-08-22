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

    public boolean maySend() { return configured.get() && !halted.get(); }

    /** Drop to DENY-ALL. Returns whether the client had been configured.
     *  `configured` is cleared FIRST: maySend() reads only that and `halted`,
     *  so no observer sees permission outlive the scope behind it. */
    private boolean denyAll() {
        boolean was = configured.getAndSet(false);
        committed = DENIED;
        return was;
    }

    /** Throws unless the extension is configured and not halted. */
    public void checkMaySend() {
        if (!configured.get())
            throw new NotConfigured("not_configured: no configure frame acknowledged yet");
        if (halted.get())
            throw new NotConfigured("halted: " + haltReason);
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
            case "halt" -> {
                halted.set(true);
                haltReason = String.valueOf(f.header.get("reason"));
            }
            case "resume" -> halted.set(false);
            default -> {
                error(f, "unknown_frame", "unrecognised frame type " + t);
            }
        }
        return true;
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
