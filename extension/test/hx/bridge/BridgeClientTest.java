package hx.bridge;

import static hx.TestSupport.waitUntilBlockedOn;

import hx.TestSupport;
import hx.send.HaltSwitch;

import java.io.*;
import java.net.*;
import java.nio.channels.Channel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Drives BridgeClient against a fake Python server on a real unix socket. */
public class BridgeClientTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(BridgeClientTest::check, name, body);
    }

    /**
     * Every blocking socket operation in this file carries a deadline.
     *
     * This is the third way a hand-rolled runner truncates, and the worst of
     * them. A sabotage that stops BridgeClient sending its hello used to park
     * the first {@code reader.read()} on the socket FOREVER: zero lines of
     * output, no summary line, and no exit code at all -- a result that under
     * {@code ./test.sh | grep -c FAIL} reads as zero failures, and a runner
     * that has to be killed from outside. `timeout` in test.sh bounds the
     * damage; it does not make the test report anything. A guard that can only
     * be stopped by an outside stopwatch is not guarding.
     *
     * Ten seconds is twenty-five times the whole class's measured runtime
     * (381 ms), and twice the 5 s bound {@link #waitUntil} already carries, so
     * it can only fire on a genuine wedge. It also has to leave room for the
     * WORST case rather than the typical one: every method wedging in turn
     * costs one deadline each, and that total must stay inside test.sh's 300 s
     * backstop -- 10 s buys thirty methods, against nine today.
     */
    static final long READ_DEADLINE_MS = 10_000L;

    /**
     * A unix-domain {@link SocketChannel} has no SO_TIMEOUT, so the deadline is
     * a watchdog that CLOSES the channel out from under the parked call. The
     * blocked read or accept then throws, which the per-method guard turns into
     * a named FAIL. Whether the watchdog fired is recorded rather than inferred
     * from the exception type: an ordinary IOException from a test that is
     * doing its job must keep its own message.
     */
    static final class Deadline implements AutoCloseable {
        private final AtomicBoolean expired = new AtomicBoolean(false);
        private final Thread watchdog;

        Deadline(Channel ch) {
            watchdog = new Thread(() -> {
                try { Thread.sleep(READ_DEADLINE_MS); }
                catch (InterruptedException arrivedInTime) { return; }
                expired.set(true);
                try { ch.close(); } catch (IOException ignored) { }
            });
            watchdog.setDaemon(true);
            watchdog.start();
        }

        boolean expired() { return expired.get(); }

        public void close() { watchdog.interrupt(); }
    }

    /** {@code reader.read()} with a deadline on it. */
    static Frame.Decoded read(Frame.Reader reader, Channel ch, String what) throws Exception {
        try (Deadline d = new Deadline(ch)) {
            try {
                return reader.read();
            } catch (IOException e) {
                if (d.expired())
                    throw new IOException(what + " did not arrive within "
                                          + READ_DEADLINE_MS + " ms", e);
                throw e;
            }
        }
    }

    /** {@code server.accept()} with a deadline on it: a client that never
     *  dials wedges here exactly as a frame that never arrives wedges above. */
    static SocketChannel accept(ServerSocketChannel server) throws Exception {
        try (Deadline d = new Deadline(server)) {
            try {
                return server.accept();
            } catch (IOException e) {
                if (d.expired())
                    throw new IOException("the client did not dial within "
                                          + READ_DEADLINE_MS + " ms", e);
                throw e;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("hxbridge");
        Path sock = dir.resolve("t.sock");

        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));

            FakeMontoya.Logger log = new FakeMontoya.Logger();
            BridgeClient client = new BridgeClient(sock, "e-1", "i-1", log);

            // Daemon, for the same reason live()'s dial thread is one: a read
            // loop that outlives its assertions must not keep the JVM up after
            // main() has printed its summary.
            Thread dial = new Thread(() -> { try { client.connect(); } catch (Exception ignored) { } });
            dial.setDaemon(true);
            dial.start();

            t("theControlChannelHandshake", () -> theControlChannelHandshake(server, client));
            client.close();

            t("closedIsSticky", BridgeClientTest::closedIsSticky);
            t("aClosedClientDoesNotGoLive", BridgeClientTest::aClosedClientDoesNotGoLive);
            t("aRefusedConfigureDropsToDenyAll", BridgeClientTest::aRefusedConfigureDropsToDenyAll);
            t("closeIsTerminalAgainstTheReadLoop", BridgeClientTest::closeIsTerminalAgainstTheReadLoop);
            t("losingThePeerDropsToDenyAll", BridgeClientTest::losingThePeerDropsToDenyAll);
            t("aFailedHelloLeavesNoChannelBehind", BridgeClientTest::aFailedHelloLeavesNoChannelBehind);
            t("theCommitIsExclusiveWithClose", BridgeClientTest::theCommitIsExclusiveWithClose);
            t("aConfigureDoesNotLiftAHalt", BridgeClientTest::aConfigureDoesNotLiftAHalt);
            t("haltFramesReachTheSwitchTheSendPathAsks", BridgeClientTest::haltFramesReachTheSwitchTheSendPathAsks);
            t("aHaltFrameWithNoReasonDoesNotDeliverTheWordNull", BridgeClientTest::aHaltFrameWithNoReasonDoesNotDeliverTheWordNull);
            t("aHaltSinkThatThrowsDropsToDenyAll", BridgeClientTest::aHaltSinkThatThrowsDropsToDenyAll);
            t("theSendArmHandsTheHandlerOneCoherentAuthorisation", BridgeClientTest::theSendArmHandsTheHandlerOneCoherentAuthorisation);
            t("aSendForAnotherEngagementNeverReachesTheHandler", BridgeClientTest::aSendForAnotherEngagementNeverReachesTheHandler);
            t("aSendHandlerThatThrowsDropsToDenyAll", BridgeClientTest::aSendHandlerThatThrowsDropsToDenyAll);
            t("aSendWithNoHandlerInstalledIsRefused", BridgeClientTest::aSendWithNoHandlerInstalledIsRefused);
            t("aThrowingSendArmBothDeniesAndStopsTheLoop",
              BridgeClientTest::aThrowingSendArmBothDeniesAndStopsTheLoop);
            t("anUnusableLimitIsRefusedAtConfigureTimeAndTheChannelSurvives",
              BridgeClientTest::anUnusableLimitIsRefusedAtConfigureTimeAndTheChannelSurvives);
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(dir);
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    /**
     * The first connection, end to end: hello, the DENY-ALL that precedes any
     * configure, the configure itself, halt/resume, and the two frames that
     * must be refused. A method rather than an inline block in main() so that
     * the per-method guard covers it -- inline, a single throw in here (an
     * unanswered read, a null header) took the other eight methods with it.
     */
    static void theControlChannelHandshake(ServerSocketChannel server, BridgeClient client)
            throws Exception {
        try (SocketChannel peer = accept(server)) {
            InputStream in = java.nio.channels.Channels.newInputStream(peer);
            OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
            // One Reader for the whole connection: frames coalesce, and a
            // fresh reader per call would drop whatever followed the one
            // it returned.
            Frame.Reader reader = new Frame.Reader(in);

            // 1. hello arrives with the right identity
            Frame.Decoded hello = read(reader, peer, "the hello");
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

            Frame.Decoded ack = read(reader, peer, "the configured ack");
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
            Frame.Decoded err = read(reader, peer, "the engagement-mismatch error");
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
            Frame.Decoded mismatch = read(reader, peer, "the protocol-mismatch error");
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
        SocketChannel peer = accept(server);
        OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
        Frame.Reader reader = new Frame.Reader(java.nio.channels.Channels.newInputStream(peer));
        read(reader, peer, "the hello");
        out.write(Frame.encode(configureFrame("e-1", 1L),
                  "scope.include\thttps://WIDE/*\n".getBytes(StandardCharsets.UTF_8)));
        out.flush();
        read(reader, peer, "the configured ack");
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
            Frame.Decoded err = read(l.reader, l.peer, "the config error");
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
                    try (SocketChannel peer = accept(server)) {
                        OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
                        Frame.Reader reader =
                                new Frame.Reader(java.nio.channels.Channels.newInputStream(peer));
                        read(reader, peer, "the hello");

                        out.write(Frame.encode(configureFrame("e-1", 0L), CFG));
                        out.flush();
                        read(reader, peer, "the configured ack");
                        waitUntil(client::isConfigured);

                        ByteArrayOutputStream backlog = new ByteArrayOutputStream();
                        for (int j = 1; j <= BACKLOG; j++)
                            backlog.write(Frame.encode(configureFrame("e-1", j), CFG));
                        out.write(backlog.toByteArray()); out.flush();

                        // Gate on the first ack: it says the read loop has the
                        // whole backlog in its Reader and is committing frames
                        // out of it, so close() lands mid-backlog rather than
                        // before the bytes have even arrived.
                        read(reader, peer, "the first backlog ack");

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
            Frame.Decoded ack = read(l.reader, l.peer,
                                     "the ack for the configure sent while halted");
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

    /**
     * A `halt` frame has to reach the switch the SEND PATH asks.
     *
     * BridgeClient's own `halted` flag guards maySend() and checkMaySend(),
     * and Sender calls neither: it asks HaltSwitch. Wired up wrongly -- or not
     * at all -- a halt frame would flip a flag nothing on the send path reads,
     * both consoles would say "halted", and requests would keep going out. The
     * failure has no other observable: maySend() answers false either way.
     */
    static void haltFramesReachTheSwitchTheSendPathAsks() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltsink");
        // Unstarted, so this test runs no poller thread: the sentinel half is
        // HaltSwitchTest's business, and the frame half needs no clock -- an
        // unarmed switch never reads one.
        HaltSwitch hs = new HaltSwitch(() -> 0L, dir.resolve("halt"), 500L);
        try (Live l = live(dir, "hs.sock")) {
            l.client.setHaltSink(new BridgeClient.HaltSink() {
                public void halted(String reason) { hs.haltedByFrame(reason); }
                public void resumed()             { hs.resumedByFrame(); }
            });
            check("the send path is not halted before the frame", !hs.halted());

            l.out.write(Frame.encode(
                    Map.of("v", 1L, "t", "halt", "reason", "operator pressed stop"), new byte[0]));
            l.out.flush();
            waitUntil(hs::halted);
            check("a halt frame halts the switch the send path asks", hs.halted());
            check("and the operator's words arrive with it",
                  "operator pressed stop".equals(hs.reason()));
            check("and the client's own flag agrees", !l.client.maySend());

            l.out.write(Frame.encode(Map.of("v", 1L, "t", "resume"), new byte[0]));
            l.out.flush();
            waitUntil(() -> !hs.halted());
            check("a resume frame lifts it on the send path too", !hs.halted());
            check("and the client is sending again", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("hs.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A `halt` frame carrying no `reason` key must not deliver the WORD
     * "null".
     *
     * `String.valueOf(f.header.get("reason"))` answers the four-character
     * string "null" for an absent key, and "null" is neither null nor blank,
     * so HaltSwitch's "halted by frame, no reason given" fallback could never
     * fire for a bridge-delivered halt -- the only production caller. Measured
     * end to end, through a real socket: reason() was the literal "null" and
     * checkMaySend() threw `NotConfigured: halted: null`. Both places an
     * operator reads showed them the word null where the reason belongs.
     */
    static void aHaltFrameWithNoReasonDoesNotDeliverTheWordNull() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltnoreasonframe");
        HaltSwitch hs = new HaltSwitch(() -> 0L, dir.resolve("halt"), 500L);
        try (Live l = live(dir, "hn.sock")) {
            l.client.setHaltSink(new BridgeClient.HaltSink() {
                public void halted(String reason) { hs.haltedByFrame(reason); }
                public void resumed()             { hs.resumedByFrame(); }
            });

            l.out.write(Frame.encode(Map.of("v", 1L, "t", "halt"), new byte[0]));
            l.out.flush();
            waitUntil(hs::halted);
            check("a halt frame with no reason still halts the send path", hs.halted());
            check("and the switch's own fallback is what the send path reports ("
                  + hs.reason() + ")",
                  "halted by frame, no reason given".equals(hs.reason()));

            String message = "";
            try { l.client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { message = e.getMessage(); }
            check("and the client's refusal does not read `halted: null` (" + message + ")",
                  message.startsWith("halted:") && !message.contains("null"));
        } finally {
            Files.deleteIfExists(dir.resolve("hn.sock")); Files.deleteIfExists(dir);
        }
    }

    /** A halt that could not be delivered is an unknown state, and unknown is
     *  stop. Not "log it and carry on": the frame that was meant to stop
     *  issuance went nowhere. */
    static void aHaltSinkThatThrowsDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltsinkthrows");
        try (Live l = live(dir, "ht.sock")) {
            l.client.setHaltSink(new BridgeClient.HaltSink() {
                public void halted(String reason) { throw new IllegalStateException("switch is gone"); }
                public void resumed()             { }
            });
            check("configured before the undeliverable halt", l.client.maySend());

            l.out.write(Frame.encode(
                    Map.of("v", 1L, "t", "halt", "reason", "operator pressed stop"), new byte[0]));
            l.out.flush();
            waitUntil(() -> !l.client.isConfigured());
            // isConfigured(), not maySend(): the local halt flag would answer
            // maySend() false on its own, so a client that had merely logged
            // the failure and carried on under the standing scope would pass a
            // maySend() check. DENY-ALL means the scope went too.
            check("a halt that could not be delivered drops to DENY-ALL",
                  !l.client.isConfigured());
            check("and the transition is logged", l.log.sawError("halt sink threw, deny-all"));
        } finally {
            Files.deleteIfExists(dir.resolve("ht.sock")); Files.deleteIfExists(dir);
        }
    }

    static Map<String, Object> sendFrame(String engagement, long id) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("v", 1L); s.put("t", "send"); s.put("id", id);
        s.put("deadline_us", System.currentTimeMillis() * 1000L + 30_000_000L);
        s.put("engagement_id", engagement);
        s.put("identity_id", null);
        s.put("target_host", "app.example.test");
        s.put("target_port", 443L);
        s.put("tls", true);
        return s;
    }

    static final byte[] GET = ("GET /api/orders HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8);

    /** The send arm reads the Authorisation ONCE and hands the whole snapshot
     *  down. This is the only place in the extension that reads it at all. */
    static void theSendArmHandsTheHandlerOneCoherentAuthorisation() throws Exception {
        Path dir = Files.createTempDirectory("hxsendarm");
        try (Live l = live(dir, "s.sock")) {
            final List<BridgeClient.Authorisation> seen = new ArrayList<>();
            l.client.setSendHandler((h, b, auth) -> {
                seen.add(auth);
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("v", 1L); r.put("t", "result"); r.put("id", h.get("id"));
                r.put("status", 200L); r.put("outcome", "ok");
                r.put(BridgeClient.BODY_KEY,
                      "HTTP/1.1 200 OK\r\n\r\nhi".getBytes(StandardCharsets.UTF_8));
                return r;
            });

            l.out.write(Frame.encode(sendFrame("e-1", 11L), GET));
            l.out.flush();
            // Through this class's deadline wrapper, not a bare reader.read():
            // a send arm that answers nothing parks here forever, and a class
            // that prints no summary line reads as zero failures.
            Frame.Decoded result = read(l.reader, l.peer, "the result frame");

            check("the send arm answers with the handler's frame",
                  "result".equals(result.header.get("t")));
            check("the handler saw the request body",
                  Long.valueOf(11L).equals(result.header.get("id")));
            check("the reserved body key never reaches the wire",
                  !result.header.containsKey(BridgeClient.BODY_KEY));
            check("and its bytes became the frame body",
                  "HTTP/1.1 200 OK\r\n\r\nhi".equals(
                          new String(result.body, StandardCharsets.UTF_8)));
            check("the handler was given exactly one Authorisation", seen.size() == 1);
            check("with the acked epoch", seen.get(0).epoch() == 1L);
            check("and the scope that epoch authorised",
                  seen.get(0).scope().toString().contains("WIDE"));
        } finally {
            Files.deleteIfExists(dir.resolve("s.sock")); Files.deleteIfExists(dir);
        }
    }

    /** s6: every send carries engagement_id and the extension refuses a
     *  mismatch -- before the handler, which would otherwise decide about a
     *  request belonging to somebody else's engagement. */
    static void aSendForAnotherEngagementNeverReachesTheHandler() throws Exception {
        Path dir = Files.createTempDirectory("hxsendmismatch");
        try (Live l = live(dir, "m.sock")) {
            final int[] calls = {0};
            l.client.setSendHandler((h, b, auth) -> { calls[0]++; return new LinkedHashMap<>(); });

            l.out.write(Frame.encode(sendFrame("SOMEONE-ELSE", 12L), GET));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the engagement-mismatch error");

            check("a send for another engagement is answered with an error",
                  "error".equals(err.header.get("t")));
            check("the class names the mismatch",
                  "engagement_mismatch".equals(err.header.get("class")));
            check("and the handler was never called (" + calls[0] + ")", calls[0] == 0);
            check("the connection survives a mismatched send", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("m.sock")); Files.deleteIfExists(dir);
        }
    }

    /** An exception is never an implicit allow. A handler that throws is
     *  answered, then the client drops to DENY-ALL and closes. */
    static void aSendHandlerThatThrowsDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxsendthrow");
        try (Live l = live(dir, "t.sock")) {
            check("live before the throw", l.client.maySend());
            l.client.setSendHandler((h, b, auth) -> {
                throw new IllegalStateException("policy table was null");
            });

            l.out.write(Frame.encode(sendFrame("e-1", 13L), GET));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the internal-failure error");

            check("a throwing handler still answers the caller",
                  "error".equals(err.header.get("t")));
            check("with a class rather than a silent bridge_lost",
                  "not_configured".equals(err.header.get("class")));
            check("and the detail names the failure",
                  String.valueOf(err.header.get("detail")).contains("policy table was null"));

            waitUntil(() -> !l.client.maySend());
            check("a send path that threw drops to DENY-ALL", !l.client.maySend());
            check("and the transition is logged",
                  l.log.sawError("send handler threw"));
        } finally {
            Files.deleteIfExists(dir.resolve("t.sock")); Files.deleteIfExists(dir);
        }
    }

    /** No handler is a state, not an exemption. */
    static void aSendWithNoHandlerInstalledIsRefused() throws Exception {
        Path dir = Files.createTempDirectory("hxnohandler");
        try (Live l = live(dir, "n.sock")) {
            l.out.write(Frame.encode(sendFrame("e-1", 14L), GET));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the no-handler error");
            check("a send with no handler is refused",
                  "error".equals(err.header.get("t"))
                  && "not_configured".equals(err.header.get("class")));

            // The input that separates the guard from its absence, and the
            // class alone is not it: delete the null check and h.handle()
            // NPEs, the send arm's catch answers the SAME not_configured
            // class, and the two are indistinguishable from the error frame --
            // measured green across all nine classes. What differs is what
            // happens next. The catch drops to DENY-ALL and closes; the guard
            // refuses one send and leaves a live client that a handler can
            // still be installed on, which is what "a state, not an exemption"
            // means.
            l.client.setSendHandler((h, b, auth) -> {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("v", 1L); r.put("t", "result"); r.put("id", h.get("id"));
                r.put("status", 200L); r.put("outcome", "ok");
                return r;
            });
            l.out.write(Frame.encode(sendFrame("e-1", 15L), GET));
            l.out.flush();
            Frame.Decoded then = read(l.reader, l.peer, "the result once a handler is installed");
            check("a missing handler is not a bridge failure: the client is still live",
                  l.client.maySend());
            check("and the handler installed afterwards answers",
                  "result".equals(then.header.get("t"))
                  && Long.valueOf(15L).equals(then.header.get("id")));
        } finally {
            Files.deleteIfExists(dir.resolve("n.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * The send arm's catch does TWO things -- `denyAll()` and `return false` --
     * and each was masking the other.
     *
     * Delete `denyAll()` and the read loop's own finally still lands in
     * DENY-ALL on the way out, so `maySend()` reads false either way. Delete
     * `return false` and `denyAll()` has already cleared `configured`, so
     * `maySend()` reads false again. Both mutations were measured at 9 x ALL
     * PASS, and the pair is not redundant at all: the finally only runs
     * because the arm asked the loop to leave, and the loop only leaves a
     * client that is already denying because the arm denied first.
     *
     * handle() is called DIRECTLY here, which is what separates them. Nothing
     * unwinds the read loop, so denyAll()'s absence is visible in maySend(),
     * and the return value is visible on its own -- the answer to "does the
     * control channel go on serving a send path that just threw", which spec
     * s4 answers no.
     */
    static void aThrowingSendArmBothDeniesAndStopsTheLoop() throws Exception {
        Path dir = Files.createTempDirectory("hxsendarmthrow");
        try (Live l = live(dir, "at.sock")) {
            check("live before the throw", l.client.maySend());
            l.client.setSendHandler((h, b, auth) -> {
                throw new IllegalStateException("the redactor is gone");
            });

            boolean keepReading = l.client.handle(
                    Frame.decode(Frame.encode(sendFrame("e-1", 21L), GET)));
            Frame.Decoded err = read(l.reader, l.peer, "the internal-failure error");
            check("the caller is answered with a class, not a silent bridge_lost",
                  "error".equals(err.header.get("t"))
                  && "not_configured".equals(err.header.get("class")));
            // Each of the two, separately.
            check("the arm itself drops to DENY-ALL rather than leaving it to the "
                  + "read loop's finally", !l.client.maySend());
            check("and it tells the read loop to stop (" + keepReading + ")", !keepReading);
        } finally {
            Files.deleteIfExists(dir.resolve("at.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A limit the extension cannot use is refused WHEN IT ARRIVES, and the
     * control channel survives the refusal.
     *
     * REPRODUCED end to end before this existed, over a real unix socket:
     *
     *     configure ack: t=configured  epoch=1     <- the operator is told OK
     *     first send:    t=error class=not_configured
     *                    detail=... limit.rate_rps is not an integer: as fast
     *                    as possible
     *     after it:      maySend()=false, http calls=0
     *     a corrected configure: IMPOSSIBLE -- java.io.IOException: Broken pipe
     *
     * Fail-closed, and the detail even named the cause -- but the answer came
     * one frame too late and on the wrong side of a channel close. HxExtension
     * dials once, on a daemon thread, and has no reconnect, so recovery meant
     * reloading the extension inside Burp.
     *
     * bad_config is the answer that already existed for exactly this shape: an
     * operator's configure that we could not act on. It drops to DENY-ALL --
     * identical safety, nothing is issued either way -- and keeps the channel,
     * so the corrected configure below is heard. The asymmetry with an equally
     * malformed value arriving one frame later was the whole argument.
     */
    static void anUnusableLimitIsRefusedAtConfigureTimeAndTheChannelSurvives()
            throws Exception {
        Path dir = Files.createTempDirectory("hxbadlimit");
        try (Live l = live(dir, "bl.sock")) {
            check("wide scope is in force first",
                  l.client.authorisation().scope().toString().contains("WIDE"));

            l.out.write(Frame.encode(configureFrame("e-1", 31L),
                    ("scope.include\thttps://a/*\n"
                     + "limit.rate_rps\tas fast as possible\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the bad-limit error");
            check("an unusable limit is answered at CONFIGURE time (got "
                  + err.header.get("t") + ")", "error".equals(err.header.get("t")));
            check("with class bad_config (got " + err.header.get("class") + "), not an "
                  + "ack the first send has to take back",
                  "bad_config".equals(err.header.get("class")));
            check("and the detail names the key and the value it could not read",
                  String.valueOf(err.header.get("detail")).contains("limit.rate_rps")
                  && String.valueOf(err.header.get("detail")).contains("as fast as possible"));

            waitUntil(() -> !l.client.maySend());
            check("a configure it could not act on drops to DENY-ALL", !l.client.maySend());
            check("the superseded wider scope is dropped",
                  l.client.authorisation().scope().isEmpty());

            // The half that the send-time refusal could not deliver.
            l.out.write(Frame.encode(configureFrame("e-1", 32L),
                    ("scope.include\thttps://NARROW/*\nlimit.rate_rps\t3\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded ack = read(l.reader, l.peer, "the corrected configured ack");
            check("the channel survives, so a corrected configure is heard (got "
                  + ack.header.get("t") + ")", "configured".equals(ack.header.get("t")));
            waitUntil(l.client::maySend);
            check("and the run is live again under the corrected config",
                  l.client.maySend());
            check("with the corrected scope",
                  l.client.authorisation().scope().toString().contains("NARROW"));

            // Two answers to "how fast" is not a limit either, and it lands in
            // the same place rather than at the first send.
            l.out.write(Frame.encode(configureFrame("e-1", 33L),
                    ("scope.include\thttps://a/*\nlimit.max_requests\t10\n"
                     + "limit.max_requests\t2000\n").getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded twice = read(l.reader, l.peer, "the repeated-limit error");
            check("a repeated limit key is bad_config too (got "
                  + twice.header.get("class") + ")",
                  "bad_config".equals(twice.header.get("class")));

            // ZERO is the third branch, and the only one of the three that was
            // unpinned: `limit.rate_rps 0` is a perfectly good integer set
            // exactly once, so neither refusal above sees it. Deleting
            // `if (n <= 0) throw ...` from ConfigBody.positiveInteger left
            // 9 x ALL PASS / 1364 ok / 0 FAIL -- and positiveInteger's own
            // javadoc invites the deletion by noting that Limits.positive
            // still makes the same three checks, from which a reader concludes
            // the line is redundant.
            //
            // What it restores is not a tidiness regression. 0 parses, is
            // acked `configured`, and then throws out of Limits.arm at the
            // FIRST send -- which answers not_configured, drops to DENY-ALL
            // and CLOSES the channel, with no reconnect in HxExtension. That
            // is precisely the unrecoverable failure the rest of this method
            // was written to close, restored invisibly.
            l.out.write(Frame.encode(configureFrame("e-1", 34L),
                    ("scope.include\thttps://a/*\nlimit.rate_rps\t0\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded zero = read(l.reader, l.peer, "the zero-limit error");
            check("a limit of ZERO is refused at configure time, not at the first "
                  + "send (got " + zero.header.get("t") + "/"
                  + zero.header.get("class") + ")",
                  "bad_config".equals(zero.header.get("class")));
        } finally {
            Files.deleteIfExists(dir.resolve("bl.sock")); Files.deleteIfExists(dir);
        }
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
