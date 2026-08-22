package hx.bridge;

import java.io.*;
import java.net.*;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
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
                client.checkMaySend();
                check("resume unblocks sending", true);

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
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(dir);
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    interface Cond { boolean ok(); }

    static void waitUntil(Cond c) throws Exception {
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            if (c.ok()) return;
            Thread.sleep(10);
        }
    }
}
