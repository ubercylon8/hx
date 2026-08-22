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

    private final Path socketPath;
    private final String engagementId;
    private final String instanceId;
    private final Object log;

    private SocketChannel channel;
    private InputStream in;
    private OutputStream out;

    private final AtomicBoolean configured = new AtomicBoolean(false);
    private final AtomicBoolean halted = new AtomicBoolean(false);
    private volatile long configEpoch = 0;
    private volatile Map<String, List<String>> scopeConfig = Map.of();
    private volatile String haltReason = null;
    private long epochCounter = 0;

    public BridgeClient(Path socketPath, String engagementId, String instanceId, Object log) {
        this.socketPath = socketPath;
        this.engagementId = engagementId;
        this.instanceId = instanceId;
        this.log = log;
    }

    public boolean isConfigured() { return configured.get(); }
    public long configEpoch() { return configEpoch; }
    public Map<String, List<String>> scopeConfig() { return scopeConfig; }
    public boolean maySend() { return configured.get() && !halted.get(); }

    /** Throws unless the extension is configured and not halted. */
    public void checkMaySend() {
        if (!configured.get())
            throw new NotConfigured("not_configured: no configure frame acknowledged yet");
        if (halted.get())
            throw new NotConfigured("halted: " + haltReason);
    }

    public void connect() throws IOException {
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
        send(hello, new byte[0]);

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
        } catch (Frame.PeerClosed | IOException e) {
            // Peer closed. DENY-ALL is also the terminal state.
            configured.set(false);
            configEpoch = 0;
        } catch (Frame.FrameError e) {
            configured.set(false);
        }
    }

    private boolean handle(Frame.Decoded f) throws IOException {
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
                try {
                    scopeConfig = ConfigBody.parse(f.body);
                } catch (Frame.FrameError e) {
                    error(f, "bad_config", e.getMessage());
                    return true;
                }
                configEpoch = ++epochCounter;
                configured.set(true);
                halted.set(false);

                Map<String, Object> ack = new LinkedHashMap<>();
                ack.put("v", PROTOCOL_VERSION);
                ack.put("t", "configured");
                ack.put("id", f.header.get("id"));
                ack.put("config_epoch", configEpoch);
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
        configured.set(false);
        try { if (channel != null) channel.close(); } catch (IOException ignored) { }
    }
}
