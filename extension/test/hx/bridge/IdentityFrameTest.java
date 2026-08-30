package hx.bridge;

import hx.TestSupport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The `identity` frame: its body's grammar, its schema, and the arm of
 * BridgeClient.handle that acts on it.
 *
 * Driven against the same fake Python server BridgeClientTest uses -- its
 * {@code live()} builds a real unix socket, dials a real client and gets it to
 * `configured`, and reusing it is what keeps ONE harness for this package
 * rather than a second one that could drift about what "configured" means.
 *
 * NO BARE `assert` ANYWHERE IN THIS FILE. `extension/test.sh` passes no `-ea`,
 * so a Java assertion is a no-op and a suite written with them prints ALL PASS
 * whether or not the code works. Every claim below goes through
 * {@link #check}, which is the same idiom every other class here uses.
 */
public class IdentityFrameTest {

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
        TestSupport.t(IdentityFrameTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("theBodyParserReadsWhatThePythonWriterEmits",
          IdentityFrameTest::theBodyParserReadsWhatThePythonWriterEmits);
        t("aBodyThatCannotBeActedOnIsRefusedFieldByField",
          IdentityFrameTest::aBodyThatCannotBeActedOnIsRefusedFieldByField);
        t("aParsedBodyNeverPrintsItsOwnValue",
          IdentityFrameTest::aParsedBodyNeverPrintsItsOwnValue);
        t("aHeaderIsStillFlatAndABodyIsBounded",
          IdentityFrameTest::aHeaderIsStillFlatAndABodyIsBounded);
        t("anIdentityFrameIsAckedWithIdentityRegistered",
          IdentityFrameTest::anIdentityFrameIsAckedWithIdentityRegistered);
        t("aStaleGenerationIsRefusedAndTheChannelSurvives",
          IdentityFrameTest::aStaleGenerationIsRefusedAndTheChannelSurvives);
        t("aMalformedFrameIsBadIdentityAndReachesNoSink",
          IdentityFrameTest::aMalformedFrameIsBadIdentityAndReachesNoSink);
        t("theValueNeverReachesTheLog", IdentityFrameTest::theValueNeverReachesTheLog);
        t("anotherEngagementsIdentityIsRefusedBeforeTheSinkIsAsked",
          IdentityFrameTest::anotherEngagementsIdentityIsRefusedBeforeTheSinkIsAsked);
        t("anIdentityIsRefusedWhileTheRunIsStopped",
          IdentityFrameTest::anIdentityIsRefusedWhileTheRunIsStopped);
        t("anIdentityWithNoSinkInstalledIsAnExtensionFault",
          IdentityFrameTest::anIdentityWithNoSinkInstalledIsAnExtensionFault);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures ------------------------------------------------------

    /** The credential. Distinctive on purpose: every "did this leak" check
     *  below looks for THESE bytes and nothing that merely resembles them. */
    static final String SECRET = "session=IDENTITY_FRAME_SECRET_4f2a";

    /**
     * Byte for byte what `hx.bridge.codec.identity_body` emits -- the same key
     * order, the same `separators=(",", ":")` with no spaces, the same nesting.
     *
     * Written out rather than built by a helper, because the thing being
     * tested is that THIS side reads what THAT side writes, and a helper that
     * assembled it here would be testing this file against itself.
     */
    static byte[] body(String id, int generation, String header, String value,
                       String... origins) {
        StringBuilder s = new StringBuilder();
        s.append("{\"identity_id\":\"").append(id).append("\",\"generation\":")
         .append(generation).append(",\"inject\":{\"header\":\"").append(header)
         .append("\",\"value\":\"").append(value).append("\"},\"origins\":[");
        for (int i = 0; i < origins.length; i++) {
            if (i > 0) s.append(',');
            s.append('"').append(origins[i]).append('"');
        }
        return s.append("]}").toString().getBytes(StandardCharsets.UTF_8);
    }

    static Map<String, Object> identityFrame(String engagement, long id) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("v", 1L);
        f.put("t", "identity");
        f.put("id", id);
        f.put("engagement_id", engagement);
        f.put("deadline_us", System.currentTimeMillis() * 1000L + 10_000_000L);
        return f;
    }

    /** Records what the arm handed it, and can refuse either way on demand. */
    static final class RecordingSink implements BridgeClient.IdentitySink {
        final List<String> registered = new ArrayList<>();
        RuntimeException refuseWith = null;
        public synchronized void register(String identityId, int generation, String header,
                                          String value, List<String> origins) {
            if (refuseWith != null) throw refuseWith;
            registered.add(identityId + "@" + generation + " " + header + "=" + value
                           + " " + origins);
        }
        synchronized int count() { return registered.size(); }
        synchronized String last() {
            return registered.isEmpty() ? "" : registered.get(registered.size() - 1);
        }
    }

    // ---- the body ------------------------------------------------------

    static void theBodyParserReadsWhatThePythonWriterEmits() {
        IdentityBody.Parsed p = IdentityBody.parse(
                body("user", 3, "Cookie", SECRET, "https://app.test", "https://api.app.test"));
        check("the identity id survives the round trip", "user".equals(p.identityId()));
        check("and the generation, as an int rather than a Long", p.generation() == 3);
        check("and the header out of the nested inject object", "Cookie".equals(p.header()));
        check("and the value out of the same object", SECRET.equals(p.value()));
        check("and every origin, in order",
              p.origins().equals(List.of("https://app.test", "https://api.app.test")));

        // The list is frozen, so a caller cannot widen a bound after the frame
        // it came from has been acted on.
        boolean frozen = false;
        try { p.origins().add("https://evil.test"); }
        catch (UnsupportedOperationException e) { frozen = true; }
        check("the origins a frame carried cannot be widened afterwards", frozen);
    }

    static void aBodyThatCannotBeActedOnIsRefusedFieldByField() {
        // Each of these is a body the PYTHON writer refuses too. They are
        // checked here because the writer being in this repository is not a
        // guarantee about what arrived on the wire.
        String[][] refusals = {
            {"not JSON at all", "this is not json"},
            {"a JSON array rather than an object", "[1,2,3]"},
            {"no identity_id", "{\"generation\":1,\"inject\":{\"header\":\"C\",\"value\":\"v\"},"
                               + "\"origins\":[\"https://a\"]}"},
            {"a blank identity_id", "{\"identity_id\":\"  \",\"generation\":1,"
                                    + "\"inject\":{\"header\":\"C\",\"value\":\"v\"},"
                                    + "\"origins\":[\"https://a\"]}"},
            {"generation 0, which could never advance anything",
             "{\"identity_id\":\"user\",\"generation\":0,"
             + "\"inject\":{\"header\":\"C\",\"value\":\"v\"},\"origins\":[\"https://a\"]}"},
            {"a generation past what an int holds",
             "{\"identity_id\":\"user\",\"generation\":4294967297,"
             + "\"inject\":{\"header\":\"C\",\"value\":\"v\"},\"origins\":[\"https://a\"]}"},
            {"no inject object", "{\"identity_id\":\"user\",\"generation\":1,"
                                 + "\"origins\":[\"https://a\"]}"},
            {"an empty value, which registers nothing",
             "{\"identity_id\":\"user\",\"generation\":1,"
             + "\"inject\":{\"header\":\"C\",\"value\":\"\"},\"origins\":[\"https://a\"]}"},
            {"no origins, so the credential could go to any host scope allows",
             "{\"identity_id\":\"user\",\"generation\":1,"
             + "\"inject\":{\"header\":\"C\",\"value\":\"v\"},\"origins\":[]}"},
            {"a blank origin, which is a silently dead bound",
             "{\"identity_id\":\"user\",\"generation\":1,"
             + "\"inject\":{\"header\":\"C\",\"value\":\"v\"},\"origins\":[\" \"]}"},
        };
        for (String[] one : refusals) {
            boolean refused = false;
            try {
                IdentityBody.parse(one[1].getBytes(StandardCharsets.UTF_8));
            } catch (Frame.FrameError e) {
                refused = true;
            }
            check("refused: " + one[0], refused);
        }

        // 2^31 - 1 is the largest generation an int holds, and it is ACCEPTED:
        // the bound above is a bound and not an off-by-one.
        check("the largest generation an int holds is still accepted",
              IdentityBody.parse(body("user", Integer.MAX_VALUE, "C", "v", "https://a"))
                      .generation() == Integer.MAX_VALUE);
    }

    static void aParsedBodyNeverPrintsItsOwnValue() {
        // Spec s5: this is the only frame in the protocol whose payload is a
        // secret. A record's generated toString would put it into every
        // exception message and debug line that happened to hold one -- and
        // the arm below builds an error detail out of exactly such a message.
        String printed = IdentityBody.parse(
                body("user", 1, "Cookie", SECRET, "https://app.test")).toString();
        check("toString names the identity", printed.contains("user"));
        check("and the generation", printed.contains("1"));
        check("and says the value is redacted", printed.contains("<redacted>"));
        check("and does NOT contain the credential (" + printed + ")",
              !printed.contains(SECRET));
    }

    static void aHeaderIsStillFlatAndABodyIsBounded() {
        // The header path is UNCHANGED by the body parser sharing its grammar.
        boolean flat = false;
        try { Json.parse("{\"a\":{\"b\":1}}"); }
        catch (Json.JsonError e) { flat = e.getMessage().contains("header must be flat"); }
        check("a nested value in a HEADER is still refused", flat);
        boolean noArray = false;
        try { Json.parse("{\"a\":[1]}"); }
        catch (Json.JsonError e) { noArray = true; }
        check("and an array in a header likewise", noArray);

        // ...while a BODY may nest, one level or several.
        Map<String, Object> nested = Json.parseBody("{\"a\":{\"b\":[1,\"x\",true,null]}}");
        check("a body reads a nested object", nested.get("a") instanceof Map);
        Object inner = ((Map<?, ?>) nested.get("a")).get("b");
        check("and an array inside it, with its element types intact",
              inner instanceof List<?> l && l.size() == 4 && Long.valueOf(1L).equals(l.get(0))
              && "x".equals(l.get(1)) && Boolean.TRUE.equals(l.get(2)) && l.get(3) == null);
        check("an empty object and an empty array are both bodies",
              Json.parseBody("{\"a\":{},\"b\":[]}").size() == 2);

        // THE BOUND. A frame body is capped only by Frame.MAX_FRAME -- 64 MB --
        // so unbounded recursion here is a StackOverflowError, which is an
        // Error and not a JsonError any arm answers with a refusal.
        StringBuilder deep = new StringBuilder("{\"a\":");
        for (int i = 0; i < 64; i++) deep.append('[');
        boolean bounded = false;
        try { Json.parseBody(deep.toString()); }
        catch (Json.JsonError e) { bounded = e.getMessage().contains("nests deeper than"); }
        check("a body deeper than the bound is a JsonError, not a StackOverflowError",
              bounded);
        // ...and the bound is not so tight that the identity body cannot be
        // read, which is the input it exists for.
        check("the depth the identity body actually needs is inside it",
              IdentityBody.parse(body("user", 1, "C", "v", "https://a")).generation() == 1);
    }

    // ---- the arm -------------------------------------------------------

    static void anIdentityFrameIsAckedWithIdentityRegistered() throws Exception {
        Path dir = Files.createTempDirectory("hxident");
        try (BridgeClientTest.Live l = BridgeClientTest.live(dir, "ia.sock")) {
            RecordingSink sink = new RecordingSink();
            l.client.setIdentitySink(sink);
            l.out.write(Frame.encode(identityFrame("e-1", 7L),
                                     body("user", 3, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            Frame.Decoded ack = BridgeClientTest.read(l.reader, l.peer, "the identity ack");

            // The wire contract Task 3 pinned from the Python side:
            // `BridgeServer.register_identity` returns only on this frame type
            // and raises on every other, so an ack of the wrong shape fails the
            // run rather than reading as success.
            check("the ack is identity_registered (got " + ack.header.get("t") + ")",
                  "identity_registered".equals(ack.header.get("t")));
            check("and answers the frame's own id",
                  Long.valueOf(7L).equals(ack.header.get("id")));
            check("and names the identity and generation now in force",
                  "user".equals(ack.header.get("identity_id"))
                  && Long.valueOf(3L).equals(ack.header.get("generation")));
            check("and carries no body", ack.body.length == 0);
            check("the sink was handed every field, once",
                  sink.count() == 1
                  && sink.last().equals("user@3 Cookie=" + SECRET + " [https://app.test]"));
        } finally {
            Files.deleteIfExists(dir.resolve("ia.sock")); Files.deleteIfExists(dir);
        }
    }

    static void aStaleGenerationIsRefusedAndTheChannelSurvives() throws Exception {
        Path dir = Files.createTempDirectory("hxidentstale");
        try (BridgeClientTest.Live l = BridgeClientTest.live(dir, "is.sock")) {
            RecordingSink sink = new RecordingSink();
            sink.refuseWith = new BridgeClient.StaleIdentity(
                    "identity user is at generation 5; refusing to go back to 2");
            l.client.setIdentitySink(sink);
            l.out.write(Frame.encode(identityFrame("e-1", 8L),
                                     body("user", 2, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            Frame.Decoded err = BridgeClientTest.read(l.reader, l.peer, "the stale refusal");
            check("a generation that goes backwards is an error frame",
                  "error".equals(err.header.get("t")));
            check("with class stale_generation (got " + err.header.get("class") + ")",
                  "stale_generation".equals(err.header.get("class")));
            check("and the detail the registry gave, which names both generations",
                  String.valueOf(err.header.get("detail")).contains("refusing to go back to 2"));
            check("and no credential in it",
                  !String.valueOf(err.header.get("detail")).contains(SECRET));

            // A REFUSAL, NOT A FAULT: a replayed frame is exactly what the
            // monotonic rule exists to refuse, so the run goes on.
            check("the channel survives a stale identity", l.client.maySend());
            sink.refuseWith = null;
            l.out.write(Frame.encode(identityFrame("e-1", 9L),
                                     body("user", 6, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            Frame.Decoded ok = BridgeClientTest.read(l.reader, l.peer, "the refresh ack");
            check("and the refresh after it is registered",
                  "identity_registered".equals(ok.header.get("t"))
                  && Long.valueOf(6L).equals(ok.header.get("generation")));
        } finally {
            Files.deleteIfExists(dir.resolve("is.sock")); Files.deleteIfExists(dir);
        }
    }

    static void aMalformedFrameIsBadIdentityAndReachesNoSink() throws Exception {
        Path dir = Files.createTempDirectory("hxidentbad");
        try (BridgeClientTest.Live l = BridgeClientTest.live(dir, "ib.sock")) {
            RecordingSink sink = new RecordingSink();
            l.client.setIdentitySink(sink);

            // A body this side cannot read.
            l.out.write(Frame.encode(identityFrame("e-1", 10L),
                                     "{\"identity_id\":\"user\"}".getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded err = BridgeClientTest.read(l.reader, l.peer, "the bad-body error");
            check("an unreadable body is an error frame", "error".equals(err.header.get("t")));
            check("with class bad_identity (got " + err.header.get("class") + ")",
                  "bad_identity".equals(err.header.get("class")));
            check("and it never reached the sink", sink.count() == 0);

            // A body this side reads and the REGISTRY refuses: the sink's other
            // documented signal, which is a different class from the one above.
            sink.refuseWith = new IllegalArgumentException("identity user has no header");
            l.out.write(Frame.encode(identityFrame("e-1", 11L),
                                     body("user", 1, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            Frame.Decoded reg = BridgeClientTest.read(l.reader, l.peer, "the registry refusal");
            check("a registry refusal is bad_identity too (got " + reg.header.get("class") + ")",
                  "error".equals(reg.header.get("t"))
                  && "bad_identity".equals(reg.header.get("class")));
            check("and the channel survives both", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("ib.sock")); Files.deleteIfExists(dir);
        }
    }

    static void theValueNeverReachesTheLog() throws Exception {
        Path dir = Files.createTempDirectory("hxidentlog");
        try (BridgeClientTest.Live l = BridgeClientTest.live(dir, "il.sock")) {
            l.client.setIdentitySink(new RecordingSink());
            l.out.write(Frame.encode(identityFrame("e-1", 12L),
                                     body("user", 4, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            BridgeClientTest.read(l.reader, l.peer, "the identity ack");

            // Spec s5: the bridge's diagnostics print frame kinds and
            // correlation ids, never bodies, and an `identity` frame must not
            // become the exception. The id and the generation ARE printed --
            // they are what an operator needs to see and neither is a secret.
            String out = l.log.out.toString(), err = l.log.err.toString();
            check("the log says the identity was registered",
                  l.log.sawInfo("identity user") && l.log.sawInfo("generation 4"));
            check("and neither stream contains the credential",
                  !out.contains(SECRET) && !err.contains(SECRET));
        } finally {
            Files.deleteIfExists(dir.resolve("il.sock")); Files.deleteIfExists(dir);
        }
    }

    static void anotherEngagementsIdentityIsRefusedBeforeTheSinkIsAsked() throws Exception {
        Path dir = Files.createTempDirectory("hxidenteng");
        try (BridgeClientTest.Live l = BridgeClientTest.live(dir, "ie.sock")) {
            RecordingSink sink = new RecordingSink();
            l.client.setIdentitySink(sink);
            l.out.write(Frame.encode(identityFrame("e-OTHER", 13L),
                                     body("user", 1, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            Frame.Decoded err = BridgeClientTest.read(l.reader, l.peer, "the mismatch error");
            check("a frame for another engagement is engagement_mismatch (got "
                  + err.header.get("class") + ")",
                  "engagement_mismatch".equals(err.header.get("class")));
            // One client's credential must never be held for another client's
            // run, which is the whole point of the id being on the frame.
            check("and no credential was registered", sink.count() == 0);
        } finally {
            Files.deleteIfExists(dir.resolve("ie.sock")); Files.deleteIfExists(dir);
        }
    }

    static void anIdentityIsRefusedWhileTheRunIsStopped() throws Exception {
        Path dir = Files.createTempDirectory("hxidenthalt");
        try (BridgeClientTest.Live l = BridgeClientTest.live(dir, "ih.sock")) {
            RecordingSink sink = new RecordingSink();
            l.client.setIdentitySink(sink);
            // s5: refused unless configured and not halted, exactly as `send`
            // is. Registering a credential into a stopped run leaves a live
            // secret held for issuance that may never be authorised.
            boolean handled = l.client.handle(Frame.decode(Frame.encode(
                    haltFrame(), new byte[0])));
            check("the halt frame was handled", handled);
            l.out.write(Frame.encode(identityFrame("e-1", 14L),
                                     body("user", 1, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            Frame.Decoded err = BridgeClientTest.read(l.reader, l.peer, "the halted refusal");
            check("an identity frame under a halt is refused (got "
                  + err.header.get("class") + ")", "halted".equals(err.header.get("class")));
            check("and the reason the operator gave is carried",
                  String.valueOf(err.header.get("detail")).contains("scope looked wrong"));
            check("and nothing was registered", sink.count() == 0);
        } finally {
            Files.deleteIfExists(dir.resolve("ih.sock")); Files.deleteIfExists(dir);
        }
    }

    static Map<String, Object> haltFrame() {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("v", 1L);
        f.put("t", "halt");
        f.put("reason", "scope looked wrong");
        return f;
    }

    static void anIdentityWithNoSinkInstalledIsAnExtensionFault() throws Exception {
        Path dir = Files.createTempDirectory("hxidentnosink");
        try (BridgeClientTest.Live l = BridgeClientTest.live(dir, "in.sock")) {
            // No setIdentitySink at all. A credential the send path could not
            // have been given must not be acknowledged as registered -- and
            // "this jar is broken" is a different instruction from "the
            // operator has not authorised this run", which is what the prefix
            // separates.
            l.out.write(Frame.encode(identityFrame("e-1", 15L),
                                     body("user", 1, "Cookie", SECRET, "https://app.test")));
            l.out.flush();
            Frame.Decoded err = BridgeClientTest.read(l.reader, l.peer, "the no-sink error");
            check("an identity frame with nothing to register into is refused",
                  "error".equals(err.header.get("t"))
                  && "not_configured".equals(err.header.get("class")));
            check("and the detail says the extension is at fault, not the operator",
                  String.valueOf(err.header.get("detail"))
                          .startsWith(BridgeClient.EXTENSION_FAULT));
            check("the client is still live: a missing sink is a state, not a fault "
                  + "that ends the channel", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("in.sock")); Files.deleteIfExists(dir);
        }
    }
}
