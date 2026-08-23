package hx.bridge;

import hx.TestSupport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.*;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class CodecTest {

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
        TestSupport.t(CodecTest::check, name, body);
    }

    static void expectThrows(String what, Class<?> type, Runnable body) {
        try {
            body.run();
            check(what + " (expected " + type.getSimpleName() + ")", false);
        } catch (Throwable t) {
            check(what, type.isInstance(t));
        }
    }

    public static void main(String[] args) throws Exception {
        t("headerRoundTrip", CodecTest::headerRoundTrip);
        t("bodyIsVerbatim", CodecTest::bodyIsVerbatim);
        t("bodyNewlinesDoNotConfuseTheHeaderSplit", CodecTest::bodyNewlinesDoNotConfuseTheHeaderSplit);
        t("incompleteIsDistinctFromCorrupt", CodecTest::incompleteIsDistinctFromCorrupt);
        t("oversizedLengthIsRefused", CodecTest::oversizedLengthIsRefused);
        t("readReassemblesAcrossChunks", CodecTest::readReassemblesAcrossChunks);
        t("readerKeepsCoalescedFrames", CodecTest::readerKeepsCoalescedFrames);
        t("readerSurvivesArbitraryChunkBoundaries", CodecTest::readerSurvivesArbitraryChunkBoundaries);
        t("readerDistinguishesCleanCloseFromTruncation", CodecTest::readerDistinguishesCleanCloseFromTruncation);
        t("readerRejectsAnOversizedPrefixBeforeAllocating", CodecTest::readerRejectsAnOversizedPrefixBeforeAllocating);
        t("configBody", CodecTest::configBody);
        t("configBodyResultIsFrozen", CodecTest::configBodyResultIsFrozen);
        t("goldenVectors", CodecTest::goldenVectors);
        t("malformedInputsAreRejected", CodecTest::malformedInputsAreRejected);
        t("invalidUtf8HeaderIsRejected", CodecTest::invalidUtf8HeaderIsRejected);
        t("pairedSurrogateEqualsRawSupplementaryCharacter", CodecTest::pairedSurrogateEqualsRawSupplementaryCharacter);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    static void headerRoundTrip() {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("v", 1L); h.put("t", "hello"); h.put("pid", 4171L);
        Frame.Decoded d = Frame.decode(Frame.encode(h, new byte[0]));
        check("header round trip", d.header.equals(h) && d.body.length == 0);
    }

    static void bodyIsVerbatim() {
        byte[] payload = "GET / HTTP/1.1\r\nHost: a\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> h = Map.of("v", 1L, "t", "send", "id", 1L);
        Frame.Decoded d = Frame.decode(Frame.encode(h, payload));
        check("body survives verbatim", Arrays.equals(d.body, payload));
    }

    static void bodyNewlinesDoNotConfuseTheHeaderSplit() {
        byte[] payload = "\n\n{\"not\":\"a header\"}\n".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> h = Map.of("v", 1L, "t", "send", "id", 2L);
        Frame.Decoded d = Frame.decode(Frame.encode(h, payload));
        check("header ends at the FIRST newline",
              "send".equals(d.header.get("t")) && Arrays.equals(d.body, payload));
    }

    static void incompleteIsDistinctFromCorrupt() {
        byte[] raw = Frame.encode(Map.of("v", 1L, "t", "hello"), "abcdef".getBytes());
        for (int cut : new int[]{0, 1, 3, 4, raw.length - 1}) {
            byte[] part = Arrays.copyOf(raw, cut);
            expectThrows("partial buffer of " + cut + " raises Incomplete",
                         Frame.Incomplete.class, () -> Frame.decode(part));
        }
    }

    static void oversizedLengthIsRefused() {
        byte[] evil = new byte[6];
        long tooBig = Frame.MAX_FRAME + 1L;
        evil[0] = (byte) (tooBig >>> 24); evil[1] = (byte) (tooBig >>> 16);
        evil[2] = (byte) (tooBig >>> 8);  evil[3] = (byte) tooBig;
        expectThrows("oversized length prefix refused before allocating",
                     Frame.FrameError.class, () -> Frame.decode(evil));
    }

    static void readReassemblesAcrossChunks() throws Exception {
        byte[] payload = new byte[100_000];
        new Random(42).nextBytes(payload);
        byte[] raw = Frame.encode(Map.of("v", 1L, "t", "result", "id", 5L), payload);
        Frame.Decoded d = new Frame.Reader(new ByteArrayInputStream(raw)).read();
        check("read() reassembles a large frame", Arrays.equals(d.body, payload));
    }

    static void readerKeepsCoalescedFrames() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);
        byte[] f2 = Frame.encode(Map.of("v", 1L, "t", "halt"), "body".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream both = new ByteArrayOutputStream();
        both.write(f1); both.write(f2);

        Frame.Reader r = new Frame.Reader(new ByteArrayInputStream(both.toByteArray()));
        check("coalesced frame 1", "configure".equals(r.read().header.get("t")));
        Frame.Decoded second = r.read();
        // The whole point: a call-local buffer loses this one.
        check("coalesced frame 2 survives", "halt".equals(second.header.get("t")));
        check("coalesced frame 2 body intact",
              "body".equals(new String(second.body, StandardCharsets.UTF_8)));
    }

    static void readerSurvivesArbitraryChunkBoundaries() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);
        byte[] f2 = Frame.encode(Map.of("v", 1L, "t", "halt"), "body".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream three = new ByteArrayOutputStream();
        three.write(f1); three.write(f2); three.write(f1);
        final byte[] all = three.toByteArray();

        InputStream sevenAtATime = new InputStream() {
            int i = 0;
            public int read() { return i < all.length ? (all[i++] & 0xff) : -1; }
            public int read(byte[] b, int off, int l) {
                if (i >= all.length) return -1;
                int n = Math.min(7, Math.min(l, all.length - i));
                System.arraycopy(all, i, b, off, n); i += n; return n;
            }
        };
        Frame.Reader r = new Frame.Reader(sevenAtATime);
        check("7-byte chunks: frame 1", "configure".equals(r.read().header.get("t")));
        check("7-byte chunks: frame 2", "halt".equals(r.read().header.get("t")));
        check("7-byte chunks: frame 3", "configure".equals(r.read().header.get("t")));
    }

    static void readerDistinguishesCleanCloseFromTruncation() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);

        Frame.Reader clean = new Frame.Reader(new ByteArrayInputStream(f1));
        clean.read();
        boolean ok = false;
        try { clean.read(); } catch (Frame.PeerClosed e) { ok = "peer closed".equals(e.getMessage()); }
        check("clean close at a frame boundary is not an error condition", ok);

        byte[] truncated = Arrays.copyOfRange(f1, 0, f1.length - 3);
        ok = false;
        try { new Frame.Reader(new ByteArrayInputStream(truncated)).read(); }
        catch (Frame.PeerClosed e) { ok = "peer closed mid-frame".equals(e.getMessage()); }
        check("a truncated frame is reported as mid-frame", ok);
    }

    static void readerRejectsAnOversizedPrefixBeforeAllocating() throws Exception {
        byte[] huge = new byte[] {(byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, 'x'};
        boolean ok = false;
        try { new Frame.Reader(new ByteArrayInputStream(huge)).read(); }
        catch (Frame.FrameError e) { ok = e.getMessage().contains("exceeds MAX_FRAME"); }
        check("oversized length prefix rejected before allocation", ok);
    }

    static void configBody() {
        byte[] body = ("scope.include\thttps://a/*\nscope.include\thttps://b/*\n"
                     + "limit.rate_rps\t5\n").getBytes(StandardCharsets.UTF_8);
        Map<String, List<String>> got = ConfigBody.parse(body);
        check("config repeated keys accumulate in order",
              got.get("scope.include").equals(List.of("https://a/*", "https://b/*")));
        check("config single value", got.get("limit.rate_rps").equals(List.of("5")));
        expectThrows("unrecognised config key is an error", Frame.FrameError.class,
                     () -> ConfigBody.parse("scope.includ\tx\n".getBytes(StandardCharsets.UTF_8)));
        expectThrows("config line without a tab is an error", Frame.FrameError.class,
                     () -> ConfigBody.parse("scope.include x\n".getBytes(StandardCharsets.UTF_8)));
    }

    /** ConfigBody.parse() is the only producer of the map BridgeClient hands
     *  out via authorisation()/scopeConfig(). A holder that could widen it in
     *  place would be authorising itself for a scope no configure frame ever
     *  set -- no epoch bump, no log line. Both levels must be frozen: the
     *  outer map AND every inner list. */
    static void configBodyResultIsFrozen() {
        byte[] body = "scope.include\thttps://a/*\n".getBytes(StandardCharsets.UTF_8);
        // A fresh parse per assertion. Sharing one map lets the first
        // assertion corrupt the second: if the outer map is NOT frozen, the
        // put() succeeds and replaces the value with an immutable List.of(),
        // so the inner-list assertion then passes for entirely the wrong
        // reason and the failure output points at one level when both are
        // broken.
        Map<String, List<String>> outer = ConfigBody.parse(body);
        expectThrows("the map itself rejects mutation", UnsupportedOperationException.class,
                     () -> outer.put("scope.include", List.of("https://evil/*")));

        Map<String, List<String>> inner = ConfigBody.parse(body);
        expectThrows("an inner list rejects mutation", UnsupportedOperationException.class,
                     () -> inner.get("scope.include").add("https://evil/*"));
    }

    /** The vectors Python recorded. If these disagree, the two codecs have drifted. */
    static void goldenVectors() throws Exception {
        Path p = Path.of("..", "tests", "vectors", "frames.json");
        String text = Files.readString(p, StandardCharsets.UTF_8);
        List<Map<String, Object>> frames = MiniVectorReader.frames(text);
        check("vectors file has frames", !frames.isEmpty());
        for (Map<String, Object> v : frames) {
            String name = (String) v.get("name");
            @SuppressWarnings("unchecked")
            Map<String, Object> header = (Map<String, Object>) v.get("header");
            byte[] body = ((String) v.get("body_utf8")).getBytes(StandardCharsets.UTF_8);
            String wantHex = (String) v.get("hex");

            String gotHex = hex(Frame.encode(header, body));
            check("vector " + name + " encodes to the recorded bytes", gotHex.equals(wantHex));

            Frame.Decoded d = Frame.decode(unhex(wantHex));
            check("vector " + name + " decodes to the recorded header", d.header.equals(header));
            check("vector " + name + " decodes to the recorded body", Arrays.equals(d.body, body));
        }
    }

    /**
     * Well-formed vectors can only pin agreement on what is VALID. They say
     * nothing about whether both sides reject the same hostile input the same
     * way -- which is exactly how a NumberFormatException escaped Frame.decode
     * in the first place. This pins rejection too, on both Json.parse directly
     * and on Frame.decode once the same text is wrapped in a real frame.
     */
    static void malformedInputsAreRejected() throws Exception {
        Path p = Path.of("..", "tests", "vectors", "malformed.json");
        String text = Files.readString(p, StandardCharsets.UTF_8);
        List<Map<String, Object>> cases = MalformedVectorReader.cases(text);
        check("malformed vectors file has cases", !cases.isEmpty());
        for (Map<String, Object> c : cases) {
            String name = (String) c.get("name");
            String headerText = (String) c.get("header_text");

            expectThrows("malformed " + name + ": Json.parse rejects it",
                         Json.JsonError.class, () -> Json.parse(headerText));

            byte[] raw = rawFrame(headerText.getBytes(StandardCharsets.UTF_8));
            expectThrows("malformed " + name + ": Frame.decode rejects it wrapped in a frame",
                         Frame.FrameError.class, () -> Frame.decode(raw));
        }
    }

    /**
     * Java's default decoder REPLACES malformed bytes with U+FFFD instead of
     * raising, silently accepting a frame Python rejects outright. Frame.decode
     * therefore decodes the header STRICTLY, and this is the check that pins it.
     *
     * The bad byte has to sit INSIDE an otherwise well-formed header for the
     * check to be able to fail. This one guarded the strict decoder with
     * {0xC3, 0x28} alone, which is not JSON under EITHER decoding: Json.parse
     * threw regardless, so replacing the CharsetDecoder with a lenient
     * `new String(...)` still printed ok. Measured.
     *
     * Direction matters, which is why this is worth pinning at all. On
     * 000000147b2276223a312c2274223a2268656cff6f227d0a:
     *
     *   JAVA lenient : ACCEPTED   t = "hel\uFFFDo"
     *   JAVA strict  : REJECTED   header bytes are not valid UTF-8
     *   PYTHON       : REJECTED   'utf-8' codec can't decode byte 0xff
     *
     * Strict means FrameError, which trips readLoop()'s finally and denyAll().
     * Lenient means a mangled `t` falls through to
     * `default -> error(f, "unknown_frame"); return true` and the connection
     * CARRIES ON under the standing scope -- on a frame the harness would
     * never have accepted.
     */
    static void invalidUtf8HeaderIsRejected() {
        // {"v":1,"t":"hel<0xFF>o"} -- valid JSON with both required fields the
        // moment 0xFF is leniently replaced by U+FFFD, so a lenient decode is
        // ACCEPTED here rather than dying in the parser.
        byte[] inside = new byte[] {
            '{', '"', 'v', '"', ':', '1', ',', '"', 't', '"', ':', '"',
            'h', 'e', 'l', (byte) 0xFF, 'o', '"', '}'
        };
        byte[] rawInside = rawFrame(inside);
        expectThrows("invalid UTF-8 INSIDE an otherwise valid header raises FrameError, "
                     + "not a U+FFFD-mangled frame type",
                     Frame.FrameError.class, () -> Frame.decode(rawInside));

        // Kept as well: 0xC3 starts a 2-byte sequence that must be followed by
        // a continuation byte (0x80-0xBF), and 0x28 '(' is not one. This one
        // cannot distinguish strict from lenient on its own -- see above -- but
        // it costs nothing and pins the truncated-sequence shape too.
        byte[] bad = new byte[] { (byte) 0xC3, 0x28 };
        byte[] raw = rawFrame(bad);
        expectThrows("invalid UTF-8 header (0xC3 0x28) raises FrameError, not U+FFFD",
                     Frame.FrameError.class, () -> Frame.decode(raw));
    }

    /**
     * A supplementary character is legally encoded in JSON as a PAIR of \\u
     * escapes -- exactly what json.dumps emits by default (ensure_ascii=True)
     * -- and separately as a raw UTF-8 character, which is what our own
     * codec emits (ensure_ascii=False). Both must parse to the identical
     * Java string, or a peer that switches encoding style produces a frame
     * this side reads differently -- or not at all.
     */
    static void pairedSurrogateEqualsRawSupplementaryCharacter() {
        // Escaped form: a literal \\u83d\\ude00 pair IN THE JSON TEXT, for
        // Json.parse's own escape handling to combine at runtime. (Double
        // backslashes here so javac leaves the backslash in the string --
        // a single \\u escape would be consumed by the COMPILER instead.)
        Map<String, Object> escaped = Json.parse("{\"v\":1,\"t\":\"x\",\"a\":\"\\ud83d\\ude00\"}");
        // Unescaped form: javac's OWN \\u processing embeds the actual
        // surrogate pair directly into this Java string literal at compile
        // time -- equivalent to typing the raw emoji glyph in UTF-8 source.
        Map<String, Object> raw = Json.parse("{\"v\":1,\"t\":\"x\",\"a\":\"😀\"}");
        check("escaped surrogate pair equals the raw supplementary character",
              escaped.equals(raw) && "😀".equals(escaped.get("a")));
    }

    /** [4-byte BE length][headerBytes]\n -- built by hand so a header that is
     * not valid JSON (most of malformed.json isn't) can still be wrapped in a
     * real frame; Frame.encode itself would refuse to write such a header. */
    static byte[] rawFrame(byte[] headerBytes) {
        byte[] payload = new byte[headerBytes.length + 1];
        System.arraycopy(headerBytes, 0, payload, 0, headerBytes.length);
        payload[headerBytes.length] = '\n';
        int len = payload.length;
        byte[] raw = new byte[4 + len];
        raw[0] = (byte) (len >>> 24); raw[1] = (byte) (len >>> 16);
        raw[2] = (byte) (len >>> 8);  raw[3] = (byte) len;
        System.arraycopy(payload, 0, raw, 4, len);
        return raw;
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
