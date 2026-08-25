package hx.bridge;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/**
 * [4-byte BE length][header JSON]\n[body bytes]
 *
 * TWO BODIES, when a frame carries a request AND a response. Plan 4's
 * `exchange` frame has two halves and they cannot share one opaque body: the
 * far side content-addresses each independently. The two-body form declares
 * itself in the HEADER, under {@link #BODIES_KEY}, and packs the body slot as
 *
 *     [4-byte BE len(first)][first][4-byte BE len(second)][second]
 *
 * so the OUTER frame is unchanged: same length prefix, same header, same
 * newline, same opaque body slot. Every frame this jar wrote before -- hello,
 * configured, result, error, halted -- still goes through the one-body
 * {@link #encode(Map, byte[])} and is byte-identical to what it was.
 *
 * HOW TO FALSIFY THAT rather than take it on trust: `Frame.encode(` appears
 * exactly twice in extension/src, both inside BridgeClient's two `send`
 * overloads, and the three-argument one is reached only from
 * `BridgeClient.exchangeSink()`. A third call site, or a `send` that started
 * routing control frames through the two-body form, would make the sentence
 * false -- and would also redden CodecTest.goldenVectors and Python's
 * test_vectors_match_their_recorded_hex, which assert the same recorded bytes
 * from opposite sides of the bridge.
 */
public final class Frame {

    public static final int MAX_FRAME = 64 * 1024 * 1024;

    /**
     * The header key that says the body slot holds two length-prefixed bodies.
     *
     * In the HEADER rather than inferred from `t`, deliberately: the codec has
     * no business knowing the frame vocabulary, and a reader that guessed from
     * `t == "exchange"` would silently mis-parse the first frame type someone
     * adds with two bodies and forgets to teach it about. `codec.BODIES_KEY`
     * is the same string on the Python side.
     */
    public static final String BODIES_KEY = "bodies";

    /** The buffer holds less than one whole frame. Normal on a stream socket. */
    public static class Incomplete extends RuntimeException {
        public Incomplete(String m) { super(m); }
    }

    /** The bytes are not a valid frame. */
    public static class FrameError extends RuntimeException {
        public FrameError(String m) { super(m); }
    }

    public static final class Decoded {
        public final Map<String, Object> header;
        public final byte[] body;
        /** The SECOND body, or null when the frame carries one. Null and
         *  zero-length are different answers: a two-body frame whose response
         *  half is empty decodes to an empty array here, and reading that as
         *  "there was no second half" is how an exchange with no response
         *  would come to look like an ordinary one-body frame. */
        public final byte[] second;
        public final int consumed;
        Decoded(Map<String, Object> header, byte[] body, int consumed) {
            this(header, body, null, consumed);
        }
        Decoded(Map<String, Object> header, byte[] body, byte[] second, int consumed) {
            this.header = header; this.body = body;
            this.second = second; this.consumed = consumed;
        }
    }

    private Frame() { }

    public static byte[] encode(Map<String, Object> header, byte[] body) {
        byte[] head = Json.write(header).getBytes(StandardCharsets.UTF_8);
        int length = head.length + 1 + body.length;
        if (length > MAX_FRAME) throw new FrameError("frame of " + length + " exceeds MAX_FRAME");
        byte[] out = new byte[4 + length];
        out[0] = (byte) (length >>> 24); out[1] = (byte) (length >>> 16);
        out[2] = (byte) (length >>> 8);  out[3] = (byte) length;
        System.arraycopy(head, 0, out, 4, head.length);
        out[4 + head.length] = '\n';
        System.arraycopy(body, 0, out, 5 + head.length, body.length);
        return out;
    }

    /**
     * The two-body form: one frame carrying a request and a response.
     *
     * The header is COPIED and stamped with {@link #BODIES_KEY} here rather
     * than trusted from the caller, so the declaration on the wire and the
     * shape of the bytes cannot disagree -- a caller that forgot the key would
     * otherwise produce a frame whose second body is silently read as trailing
     * bytes of the first. The frame is then built by the one-body encoder
     * above, which is what keeps the outer form identical.
     */
    public static byte[] encode(Map<String, Object> header, byte[] first, byte[] second) {
        long total = 4L + first.length + 4L + second.length;
        // Checked before the arrays are joined, not after: MAX_FRAME exists so
        // one frame cannot make this JVM allocate arbitrarily, and a check that
        // runs after the allocation it is bounding has already lost.
        if (total > MAX_FRAME)
            throw new FrameError("two bodies of " + first.length + " + "
                                 + second.length + " exceed MAX_FRAME " + MAX_FRAME);
        byte[] payload = new byte[(int) total];
        putInt(payload, 0, first.length);
        System.arraycopy(first, 0, payload, 4, first.length);
        putInt(payload, 4 + first.length, second.length);
        System.arraycopy(second, 0, payload, 8 + first.length, second.length);
        Map<String, Object> stamped = new java.util.LinkedHashMap<>(header);
        stamped.put(BODIES_KEY, 2L);
        return encode(stamped, payload);
    }

    private static void putInt(byte[] out, int at, int v) {
        out[at] = (byte) (v >>> 24); out[at + 1] = (byte) (v >>> 16);
        out[at + 2] = (byte) (v >>> 8); out[at + 3] = (byte) v;
    }

    private static long getInt(byte[] b, int at) {
        return ((long) (b[at] & 0xff) << 24) | ((b[at + 1] & 0xff) << 16)
             | ((b[at + 2] & 0xff) << 8) | (b[at + 3] & 0xff);
    }

    /** Whether the header declares the two-body form. `2L` and nothing else:
     *  Json.parse yields Long for every integer, and a `bodies` this version
     *  does not know is a frame it cannot read, not one to guess at. */
    private static boolean declaresTwoBodies(Map<String, Object> header) {
        Object b = header.get(BODIES_KEY);
        if (b == null) return false;
        if (Long.valueOf(2L).equals(b)) return true;
        throw new FrameError("header declares " + BODIES_KEY + "=" + b
                             + "; this version reads 2 and no other value");
    }

    /**
     * Split a declared two-body payload. EXACT FIT is required: the two
     * declared lengths must consume the payload to its last byte. A payload
     * with bytes left over is a frame this side and the other side would read
     * differently, and the whole reason the lengths are on the wire at all is
     * so neither has to guess where the halves end.
     */
    private static byte[][] splitBodies(byte[] payload) {
        if (payload.length < 4)
            throw new FrameError("two-body frame has no length prefix for its first body");
        long n1 = getInt(payload, 0);
        if (payload.length < 4 + n1 + 4)
            throw new FrameError("two-body frame declares a first body of " + n1
                                 + " but holds " + payload.length + " bytes");
        long n2 = getInt(payload, (int) (4 + n1));
        if (payload.length != 8 + n1 + n2)
            throw new FrameError("two-body frame declares bodies of " + n1 + " + "
                                 + n2 + ", which do not fill its " + payload.length
                                 + " bytes");
        return new byte[][] {
            Arrays.copyOfRange(payload, 4, (int) (4 + n1)),
            Arrays.copyOfRange(payload, (int) (8 + n1), (int) (8 + n1 + n2)),
        };
    }

    public static Decoded decode(byte[] buf) {
        if (buf.length < 4) throw new Incomplete("need a length prefix");
        long length = ((long) (buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16)
                    | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
        // Checked BEFORE any allocation: the prefix is attacker-influenced.
        if (length > MAX_FRAME) throw new FrameError("declared frame of " + length + " exceeds MAX_FRAME");
        int end = (int) (4 + length);
        if (buf.length < end) throw new Incomplete("need " + end + " bytes, have " + buf.length);

        int nl = -1;
        for (int i = 4; i < end; i++) if (buf[i] == '\n') { nl = i; break; }
        if (nl < 0) throw new FrameError("header has no newline terminator");

        String headerText;
        try {
            // Java's default decoder REPLACES malformed bytes with U+FFFD, silently
            // accepting a frame Python rejects outright. Decode strictly instead.
            headerText = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(buf, 4, nl - 4))
                    .toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new FrameError("header bytes are not valid UTF-8: " + e.getMessage());
        }
        Map<String, Object> header;
        try {
            header = Json.parse(headerText);
        } catch (Json.JsonError e) {
            throw new FrameError("header is not valid JSON: " + e.getMessage());
        }
        byte[] payload = Arrays.copyOfRange(buf, nl + 1, end);
        if (declaresTwoBodies(header)) {
            byte[][] two = splitBodies(payload);
            return new Decoded(header, two[0], two[1], end);
        }
        return new Decoded(header, payload, end);
    }

    /** Peer closed the connection. Distinct from Incomplete, which means
     *  "call again with more bytes". */
    public static class PeerClosed extends RuntimeException {
        public PeerClosed(String m) { super(m); }
    }

    /**
     * Reads frames from a stream, owning the buffer across calls.
     *
     * A bare read(InputStream) cannot be correct in a loop. decode() reports
     * `consumed` precisely because one read may deliver more than one frame,
     * and a method that returns after the first frame has nowhere to put the
     * remainder -- so it drops it, and the loss surfaces later as a misleading
     * "peer closed mid-frame". Owning the buffer is that somewhere. This
     * mirrors codec.FrameReader on the Python side, including reading the
     * length prefix first so draining a large frame is linear rather than
     * re-parsing a growing buffer once per chunk.
     *
     * A Reader belongs to exactly one thread. It is not merely unsynchronised:
     * `buf` and the hoisted `chunk` are per-Reader staging, so two concurrent
     * read() calls scribble over each other's bytes.
     */
    public static final class Reader {
        private final InputStream in;
        private byte[] buf = new byte[0];
        private int len = 0;                       // bytes of buf actually in use

        public Reader(InputStream in) { this.in = in; }

        private final byte[] chunk = new byte[65536];   // one per Reader, not per call

        public Decoded read() throws IOException {
            while (true) {
                if (len >= 4) {
                    long length = ((long) (buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16)
                                | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
                    // Checked before allocation: the prefix is attacker-influenced.
                    if (length > MAX_FRAME)
                        throw new FrameError("declared frame of " + length
                                             + " exceeds MAX_FRAME " + MAX_FRAME);
                    int end = (int) (4 + length);
                    if (len >= end) {
                        Decoded d = decode(Arrays.copyOfRange(buf, 0, end));
                        System.arraycopy(buf, d.consumed, buf, 0, len - d.consumed);
                        len -= d.consumed;
                        // One 64 MB frame must not pin 64 MB for the life of
                        // the connection -- but shrinking to 64 KB after every
                        // ordinary frame is worse than the leak it prevents:
                        // Plan 3's `exchange` frames carry HTTP bodies, and 200
                        // x 2 MB measured 206 ms of drop-and-re-double against
                        // 122 ms with this hysteresis. Trigger well above the
                        // working set, and never shrink below 1 MB.
                        if (buf.length > (1 << 22) && len < (buf.length >>> 2))
                            buf = Arrays.copyOf(buf, Math.max(len, 1 << 20));
                        return d;
                    }
                }
                int n = in.read(chunk);
                if (n < 0) throw new PeerClosed(len > 0 ? "peer closed mid-frame" : "peer closed");
                if (len + n > buf.length)
                    buf = Arrays.copyOf(buf, Math.max(len + n, Math.max(1024, buf.length * 2)));
                System.arraycopy(chunk, 0, buf, len, n);
                len += n;
            }
        }
    }
}
