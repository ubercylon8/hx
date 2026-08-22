package hx.bridge;

import java.io.*;
import java.net.*;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Drives BridgeClient against a fake Python server on a real unix socket. */
public class BridgeClientTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("hxbridge");
        Path sock = dir.resolve("t.sock");

        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));

            FakeMontoya.Logger log = new FakeMontoya.Logger();
            BridgeClient client = new BridgeClient(sock, "e-1", "i-1", log);

            Thread t = new Thread(() -> { try { client.connect(); } catch (Exception ignored) { } });
            t.start();

            try (SocketChannel peer = server.accept()) {
                InputStream in = java.nio.channels.Channels.newInputStream(peer);
                OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
                // One Reader for the whole connection: frames coalesce, and a
                // fresh reader per call would drop whatever followed the one
                // it returned.
                Frame.Reader reader = new Frame.Reader(in);

                // 1. hello arrives with the right identity
                Frame.Decoded hello = reader.read();
                check("sends hello", "hello".equals(hello.header.get("t")));
                check("hello carries engagement_id", "e-1".equals(hello.header.get("engagement_id")));
                check("hello carries instance_id", "i-1".equals(hello.header.get("instance_id")));
                check("hello carries protocol version", Long.valueOf(1L).equals(hello.header.get("v")));

                // 2. DENY-ALL before configure
                check("unconfigured after hello", !client.isConfigured());
                boolean threw = false;
                try { client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { threw = true; }
                check("checkMaySend throws NotConfigured before configure", threw);

                // 3. configure -> configured, with an epoch
                Map<String, Object> cfg = new LinkedHashMap<>();
                cfg.put("v", 1L); cfg.put("t", "configure"); cfg.put("id", 1L);
                cfg.put("engagement_id", "e-1"); cfg.put("scope_sha256", "abc");
                cfg.put("profile", "production");
                // configure is the one request frame, and BridgeServer._request
                // stamps id and deadline_us onto every one of them. A fake that
                // omits it is not the peer: the client answers bad_frame.
                cfg.put("deadline_us", System.currentTimeMillis() * 1000L + 10_000_000L);
                out.write(Frame.encode(cfg, "scope.include\thttps://a/*\nlimit.rate_rps\t5\n"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                out.flush();

                Frame.Decoded ack = reader.read();
                check("acks with configured", "configured".equals(ack.header.get("t")));
                check("ack echoes the request id", Long.valueOf(1L).equals(ack.header.get("id")));
                check("ack carries a non-zero epoch",
                      ((Long) ack.header.get("config_epoch")) > 0);

                waitUntil(() -> client.isConfigured());
                check("configured after ack", client.isConfigured());
                check("scope config parsed",
                      client.scopeConfig().get("scope.include").equals(List.of("https://a/*")));
                // The coherent read. configEpoch() then scopeConfig() is two
                // volatile reads and a commit can land between them; this is
                // the one an evidence line has to use.
                BridgeClient.Authorisation au = client.authorisation();
                check("authorisation() carries the epoch and the scope together",
                      au.epoch() == client.configEpoch()
                      && au.scope().equals(client.scopeConfig()));
                client.checkMaySend();   // must not throw now

                // 4. halt / resume
                Map<String, Object> halt = Map.of("v", 1L, "t", "halt", "reason", "operator");
                out.write(Frame.encode(halt, new byte[0])); out.flush();
                waitUntil(() -> !client.maySend());
                boolean haltedThrew = false;
                try { client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { haltedThrew = true; }
                check("halt blocks sending", haltedThrew);

                out.write(Frame.encode(Map.of("v", 1L, "t", "resume"), new byte[0])); out.flush();
                waitUntil(() -> client.maySend());
                boolean resumed = client.maySend();
                try { client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { resumed = false; }
                check("resume unblocks sending", resumed);

                // 5. an engagement_id mismatch on configure is refused
                Map<String, Object> wrong = new LinkedHashMap<>(cfg);
                wrong.put("id", 2L); wrong.put("engagement_id", "SOMEONE-ELSE");
                out.write(Frame.encode(wrong, new byte[0])); out.flush();
                Frame.Decoded err = reader.read();
                check("engagement mismatch answered with error",
                      "error".equals(err.header.get("t")));
                check("error class names the mismatch",
                      String.valueOf(err.header.get("class")).contains("engagement"));

                // 6. a protocol-mismatch frame while configured must trip
                // DENY-ALL through readLoop's OTHER exit path. handle()
                // returns false here, and the bare `return` that used to
                // follow skipped both catch blocks entirely: configured
                // stayed true, configEpoch kept its value, and maySend()
                // would answer true forever with a dead read loop and no
                // control channel behind it. This is the exact leak the
                // finally block in readLoop() exists to close.
                check("configured before the protocol-mismatch frame", client.maySend());
                Map<String, Object> badVersion = new LinkedHashMap<>();
                badVersion.put("v", 2L); badVersion.put("t", "halt"); badVersion.put("reason", "operator");
                out.write(Frame.encode(badVersion, new byte[0])); out.flush();
                Frame.Decoded mismatch = reader.read();
                check("protocol mismatch answered with error",
                      "error".equals(mismatch.header.get("t")));
                check("error class names the protocol mismatch",
                      "protocol_mismatch".equals(mismatch.header.get("class")));
                waitUntil(() -> !client.maySend());
                check("protocol mismatch trips DENY-ALL via readLoop's return path",
                      !client.maySend());
                boolean deniedAfterMismatch = false;
                try { client.checkMaySend(); }
                catch (BridgeClient.NotConfigured e) { deniedAfterMismatch = true; }
                check("checkMaySend throws after the protocol-mismatch DENY-ALL",
                      deniedAfterMismatch);
            }
            client.close();

            closedIsSticky();
            aClosedClientDoesNotGoLive();
            aRefusedConfigureDropsToDenyAll();
            closeIsTerminalAgainstTheReadLoop();
            losingThePeerDropsToDenyAll();
            aFailedHelloLeavesNoChannelBehind();
            theCommitIsExclusiveWithClose();
            aConfigureDoesNotLiftAHalt();
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(dir);
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    /** Drive a fresh client to "configured" and hand back the pieces. */
    static final class Live implements AutoCloseable {
        final BridgeClient client; final SocketChannel peer;
        final OutputStream out; final Frame.Reader reader; final FakeMontoya.Logger log;
        final ServerSocketChannel server;
        Live(ServerSocketChannel server, BridgeClient c, SocketChannel p,
             OutputStream o, Frame.Reader r, FakeMontoya.Logger l) {
            this.server = server; this.client = c; this.peer = p;
            this.out = o; this.reader = r; this.log = l;
        }
        public void close() throws Exception {
            client.close(); peer.close(); server.close();
        }
    }

    static Map<String, Object> configureFrame(String engagement, long id) {
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("v", 1L); cfg.put("t", "configure"); cfg.put("id", id);
        cfg.put("engagement_id", engagement); cfg.put("scope_sha256", "abc");
        cfg.put("profile", "production");
        cfg.put("deadline_us", System.currentTimeMillis() * 1000L + 10_000_000L);
        return cfg;
    }

    static Live live(Path dir, String name) throws Exception {
        Path sock = dir.resolve(name);
        ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(sock));
        FakeMontoya.Logger log = new FakeMontoya.Logger();
        BridgeClient client = new BridgeClient(sock, "e-1", "i-1", log);
        // Daemon: a read loop that leaks past the end of a test must fail the
        // suite by way of its assertions, not outlive main() and hang the JVM.
        Thread dial = new Thread(() -> { try { client.connect(); } catch (Exception ignored) { } });
        dial.setDaemon(true);
        dial.start();
        SocketChannel peer = server.accept();
        OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
        Frame.Reader reader = new Frame.Reader(java.nio.channels.Channels.newInputStream(peer));
        reader.read();                                   // the hello
        out.write(Frame.encode(configureFrame("e-1", 1L),
                  "scope.include\thttps://WIDE/*\n".getBytes(StandardCharsets.UTF_8)));
        out.flush();
        reader.read();                                   // the ack
        waitUntil(client::isConfigured);
        return new Live(server, client, peer, out, reader, log);
    }

    /** close() must be sticky: a client closed before its dial completes must
     *  never go on to hello, configure and live sending. Reproduced by the
     *  review as an UNLOADED extension holding a control channel. */
    static void closedIsSticky() throws Exception {
        Path dir = Files.createTempDirectory("hxsticky");
        Path sock = dir.resolve("s.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            BridgeClient client = new BridgeClient(sock, "e-1", "i-1", new FakeMontoya.Logger());
            client.close();

            // On a thread with a join timeout: an unfixed client's connect()
            // dials, sends hello and blocks in readLoop forever, so a direct
            // call would hang the suite instead of failing it.
            final boolean[] refused = {false};
            Thread dial = new Thread(() -> {
                try { client.connect(); }
                catch (IOException e) { refused[0] = true; }
                catch (Exception ignored) { }
            });
            dial.setDaemon(true);
            dial.start();
            dial.join(3000);

            check("connect() on a closed client returns instead of dialling", !dial.isAlive());
            check("connect() on a closed client is refused", refused[0]);
            check("a closed client never reports maySend", !client.maySend());
        } finally {
            Files.deleteIfExists(sock); Files.deleteIfExists(dir);
        }
    }

    /** A configure arriving after close() must not resurrect the client. */
    static void aClosedClientDoesNotGoLive() throws Exception {
        Path dir = Files.createTempDirectory("hxresurrect");
        try (Live l = live(dir, "r.sock")) {
            check("live before close", l.client.maySend());
            l.client.close();
            check("closed client denies immediately", !l.client.maySend());

            // A second configure lands after close(): the read loop must not
            // act on it.
            try {
                l.out.write(Frame.encode(configureFrame("e-1", 2L),
                        "scope.include\thttps://SNEAKY/*\n".getBytes(StandardCharsets.UTF_8)));
                l.out.flush();
            } catch (IOException ignored) { /* channel already shut: also fine */ }
            Thread.sleep(150);
            check("a configure after close() does not resurrect the client", !l.client.maySend());
            check("and leaves no epoch behind", l.client.configEpoch() == 0);
            check("and leaves no scope behind", l.client.scopeConfig().isEmpty());

            // The same property without a race in it. closeIsTerminalAgainst-
            // TheReadLoop() below can only catch the defect when the scheduler
            // cooperates -- measured 0/20 on ONE core against 11-14/20 on 24 --
            // and CI runners are commonly 2 vCPU, so on its own that guard can
            // go quietly vacuous. This one cannot: it hands handle() a frame
            // directly on this thread, on a client that was configured before
            // close(), and it must be refused.
            boolean refused;
            try {
                refused = !l.client.handle(
                        Frame.decode(Frame.encode(configureFrame("e-1", 9L), CFG)));
            } catch (IOException e) {
                // It got as far as writing an ack down a channel close() shut,
                // which means it did not refuse the frame. Caught so this
                // reports as a failed check rather than killing the runner
                // part-way through the suite.
                refused = false;
            }
            check("handle() refuses a frame on a closed client", refused);
            check("and did not re-enable sending", !l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("r.sock")); Files.deleteIfExists(dir);
        }
    }

    /** A configure we cannot parse means the operator's intent is unknown.
     *  Keeping the PREVIOUS, wider scope would send exactly where a narrowing
     *  operator just said not to. */
    static void aRefusedConfigureDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxbadcfg");
        try (Live l = live(dir, "b.sock")) {
            check("wide scope is in force first",
                  l.client.scopeConfig().toString().contains("WIDE"));

            l.out.write(Frame.encode(configureFrame("e-1", 3L),
                    "this-is-not-a-config-body\n".getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded err = l.reader.read();
            check("unparseable configure is answered with an error",
                  "error".equals(err.header.get("t")));
            check("error class names the config",
                  String.valueOf(err.header.get("class")).contains("config"));

            waitUntil(() -> !l.client.maySend());
            check("a refused configure drops to DENY-ALL", !l.client.maySend());
            check("the superseded wider scope is dropped", l.client.scopeConfig().isEmpty());
            check("and its epoch with it", l.client.configEpoch() == 0);
        } finally {
            Files.deleteIfExists(dir.resolve("b.sock")); Files.deleteIfExists(dir);
        }
    }

    /** The most common terminal path of all, and previously untested. */
    static void losingThePeerDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxpeergone");
        try (Live l = live(dir, "p.sock")) {
            check("configured while the peer is up", l.client.maySend());
            l.peer.close();

            waitUntil(() -> !l.client.maySend());
            check("losing the peer drops to DENY-ALL", !l.client.maySend());
            check("epoch zeroed on peer loss", l.client.configEpoch() == 0);
            check("scope dropped on peer loss", l.client.scopeConfig().isEmpty());
            // maySend() flipping is not a happens-before edge for the log line:
            // denyAll() lands two statements before log.info(). Wait on the
            // thing being asserted.
            waitUntil(() -> l.log.sawInfo("deny-all"));
            check("and the transition is logged",
                  l.log.sawInfo("deny-all"));
        } finally {
            Files.deleteIfExists(dir.resolve("p.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * close() must be terminal the instant it returns. The read loop runs on
     * its own thread and may be part-way through a `configure` that was
     * already sitting in the Reader's buffer when close() ran; if the commit
     * is not exclusive with close(), the loop sets configured back to true
     * behind close()'s back and maySend() answers true for as long as it takes
     * to write the ack -- microseconds in which Plan 3 will send.
     *
     * Two details are load-bearing, both learned the hard way. A COALESCED
     * BACKLOG of configure frames, because with one there is nothing for
     * close() to race. And a BUSY POLL, because the window opens a few us
     * AFTER close() returns: a sample at t=0 lands before it, a sample at
     * t=2ms lands after it, and both report all-clear. Point samples measured
     * 0/40 on code that a poll catches 39/40.
     *
     * This is a DETECTOR, not the guard. It is scheduler-dependent: against
     * the defective client the review measured 11-14/20 on 24 cores, 1-3/20 on
     * two, and 0/20 pinned to one -- so on a 2-vCPU CI runner it can pass
     * clean on broken code. The guard is the deterministic handle()-after-
     * close() check in aClosedClientDoesNotGoLive(). A 64-frame backlog and
     * an ack read before close() (which proves the loop is already chewing
     * through the backlog rather than parked on the socket) took the detector
     * to 18-20/20 on multi-core without losing the 2-core signal.
     */
    static void closeIsTerminalAgainstTheReadLoop() throws Exception {
        Path dir = Files.createTempDirectory("hxclose");
        int resurrections = 0, attempts = 20;
        try {
            for (int i = 0; i < attempts; i++) {
                Path sock = dir.resolve("c" + i + ".sock");
                try (ServerSocketChannel server =
                             ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
                    server.bind(UnixDomainSocketAddress.of(sock));
                    BridgeClient client =
                            new BridgeClient(sock, "e-1", "i-1", new FakeMontoya.Logger());
                    Thread t = new Thread(() -> {
                        try { client.connect(); } catch (Exception ignored) { } });
                    t.setDaemon(true);
                    t.start();
                    try (SocketChannel peer = server.accept()) {
                        OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
                        Frame.Reader reader =
                                new Frame.Reader(java.nio.channels.Channels.newInputStream(peer));
                        reader.read();                                   // hello

                        out.write(Frame.encode(configureFrame("e-1", 0L), CFG));
                        out.flush();
                        reader.read();                                   // the ack
                        waitUntil(client::isConfigured);

                        ByteArrayOutputStream backlog = new ByteArrayOutputStream();
                        for (int j = 1; j <= BACKLOG; j++)
                            backlog.write(Frame.encode(configureFrame("e-1", j), CFG));
                        out.write(backlog.toByteArray()); out.flush();

                        // Gate on the first ack: it says the read loop has the
                        // whole backlog in its Reader and is committing frames
                        // out of it, so close() lands mid-backlog rather than
                        // before the bytes have even arrived.
                        reader.read();

                        client.close();

                        long end = System.nanoTime() + 5_000_000L;       // 5 ms
                        while (System.nanoTime() < end)
                            if (client.maySend()) { resurrections++; break; }
                    }
                }
                Files.deleteIfExists(sock);
            }
        } finally {
            Files.deleteIfExists(dir);
        }
        check("close() is terminal: the read loop cannot re-enable sending behind it ("
              + resurrections + "/" + attempts + " resurrections)", resurrections == 0);
    }

    /** Frames left buffered in the client's Reader when close() lands. Two was
     *  enough to see the defect on a busy machine and nowhere near enough on a
     *  quiet one. */
    static final int BACKLOG = 64;

    /**
     * F6: a dialled channel must not outlive a failed hello. Reverting the
     * closeChannel() in connect()'s catch failed nothing before this existed --
     * an unloadable extension would hold an open control channel with no
     * reader on it, and connect()'s caller would have no way to shut it.
     *
     * Deterministic, not a race, and the instance_id is what makes it so. At
     * 8 MB the hello cannot fit in the socket buffer (212992 bytes here), so
     * the write BLOCKS. Whether the peer's close lands before the write starts
     * or while it is parked, the write fails; there is no interleaving in
     * which it quietly succeeds and the client sails on into readLoop().
     */
    static void aFailedHelloLeavesNoChannelBehind() throws Exception {
        Path dir = Files.createTempDirectory("hxhello");
        Path sock = dir.resolve("h.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            BridgeClient client = new BridgeClient(
                    sock, "e-1", "i-".repeat(4 << 20), new FakeMontoya.Logger());

            Thread killer = new Thread(() -> {
                try (SocketChannel peer = server.accept()) {
                    // Accepted and dropped on the floor: nothing will ever
                    // drain this hello.
                } catch (IOException ignored) { }
            });
            killer.setDaemon(true);
            killer.start();

            boolean threw = false;
            try { client.connect(); } catch (Exception e) { threw = true; }
            killer.join(5000);

            check("a hello that cannot be written propagates out of connect()", threw);
            check("and the dialled channel does not outlive the failed hello",
                  !client.channelIsOpen());
            check("and the client is still denying", !client.maySend());
        } finally {
            Files.deleteIfExists(sock); Files.deleteIfExists(dir);
        }
    }

    /**
     * The commit-lock guard, deterministically. The top-of-handle() guard
     * cannot satisfy this one: the frame is already past it and parked on the
     * monitor when close() runs.
     *
     * Monitor reentrancy is what makes it deterministic. This thread holds
     * commitLock, so the helper cannot get past `synchronized (commitLock)` in
     * handle(); close() takes the SAME monitor and this thread already owns it,
     * so it proceeds. When this block exits, the helper acquires the monitor
     * and must observe `closed`.
     *
     * The park is verified by LOCK IDENTITY, not by Thread.State alone: a
     * thread stuck on a class-initialisation monitor is also BLOCKED, and
     * accepting that would let the helper still be BEFORE the top-of-handle()
     * guard when close() lands -- which passes for the wrong reason and stops
     * covering the commit-lock guard at all.
     */
    static void theCommitIsExclusiveWithClose() throws Exception {
        Path dir = Files.createTempDirectory("hxexcl");
        try (Live l = live(dir, "x.sock")) {
            final boolean[] refused = {false};
            Thread t;
            synchronized (l.client.commitLock) {
                t = new Thread(() -> {
                    try { refused[0] = !l.client.handle(
                            Frame.decode(Frame.encode(configureFrame("e-1", 7L), CFG))); }
                    catch (IOException e) { refused[0] = false; }
                });
                t.setDaemon(true);
                t.start();
                check("the configure is parked on commitLock itself",
                      waitUntilBlockedOn(t, l.client.commitLock));
                l.client.close();          // reentrant: this thread holds the monitor
            }
            t.join(5000);
            check("a commit parked on commitLock is refused once close() has run", refused[0]);
            check("and close() stays terminal", !l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("x.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A configure frame must NOT lift an operator halt. The commit used to end
     * with `halted.set(false)`, so the most likely next action after halting --
     * halt because the scope went wrong, push the corrected scope -- re-armed
     * issuance with no resume() on the wire, no log line, and both consoles
     * reading "configured".
     *
     * The other half of the assertion matters just as much: the epoch and the
     * scope must still commit. Narrowing scope during an emergency stop is
     * exactly what an operator should be able to do, so "configure is refused
     * while halted" would be the wrong fix. A configure re-authorises SCOPE,
     * not ISSUANCE.
     */
    static void aConfigureDoesNotLiftAHalt() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltcfg");
        try (Live l = live(dir, "h.sock")) {              // configured, epoch 1, WIDE
            check("configured before the halt", l.client.maySend());

            l.out.write(Frame.encode(
                    Map.of("v", 1L, "t", "halt", "reason", "scope was wrong"), new byte[0]));
            l.out.flush();
            waitUntil(() -> !l.client.maySend());
            check("halt blocks sending", !l.client.maySend());

            // The corrected, NARROWER scope, pushed while halted.
            l.out.write(Frame.encode(configureFrame("e-1", 4L),
                    "scope.include\thttps://NARROW/*\n".getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded ack = l.reader.read();
            // Reading the ack is the happens-before edge: the commit completes
            // before the ack is written, so nothing below has to poll.
            check("the configure while halted is acknowledged",
                  "configured".equals(ack.header.get("t")));

            boolean stillHalted = false;
            String message = "";
            try { l.client.checkMaySend(); }
            catch (BridgeClient.NotConfigured e) { stillHalted = true; message = e.getMessage(); }
            check("a configure does not lift an operator halt", stillHalted);
            check("and the refusal still names the halt, not a missing configure ("
                  + message + ")", message.startsWith("halted:"));
            check("and maySend() agrees", !l.client.maySend());

            // ...while the scope and epoch it carried DID commit.
            BridgeClient.Authorisation au = l.client.authorisation();
            check("the configure still advanced the epoch (" + au.epoch() + ")",
                  au.epoch() == 2L);
            check("ack reports the advanced epoch",
                  Long.valueOf(2L).equals(ack.header.get("config_epoch")));
            check("the narrowed scope is in force",
                  au.scope().get("scope.include").equals(List.of("https://NARROW/*")));

            // And a resume -- the frame that IS allowed to re-arm issuance --
            // does so, under the epoch-2 scope.
            l.out.write(Frame.encode(Map.of("v", 1L, "t", "resume"), new byte[0]));
            l.out.flush();
            waitUntil(l.client::maySend);
            check("resume is what re-arms issuance", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("h.sock")); Files.deleteIfExists(dir);
        }
    }

    /** True once `t` is BLOCKED on `monitor` specifically. */
    static boolean waitUntilBlockedOn(Thread t, Object monitor) throws Exception {
        java.lang.management.ThreadMXBean mx = java.lang.management.ManagementFactory.getThreadMXBean();
        int want = System.identityHashCode(monitor);
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            java.lang.management.ThreadInfo info = mx.getThreadInfo(t.threadId());
            if (info != null && t.getState() == Thread.State.BLOCKED) {
                java.lang.management.LockInfo li = info.getLockInfo();
                if (li != null && li.getIdentityHashCode() == want) return true;
            }
            Thread.sleep(1);
        }
        return false;
    }

    static final byte[] CFG =
            "scope.include\thttps://RACE/*\n".getBytes(StandardCharsets.UTF_8);

    interface Cond { boolean ok(); }

    static void waitUntil(Cond c) throws Exception {
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            if (c.ok()) return;
            Thread.sleep(10);
        }
    }
}
