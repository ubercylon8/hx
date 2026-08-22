package hx.bridge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/** [4-byte BE length][header JSON]\n[body bytes] */
public final class Frame {

    public static final int MAX_FRAME = 64 * 1024 * 1024;

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
        public final int consumed;
        Decoded(Map<String, Object> header, byte[] body, int consumed) {
            this.header = header; this.body = body; this.consumed = consumed;
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
        return new Decoded(header, Arrays.copyOfRange(buf, nl + 1, end), end);
    }

    /** Read exactly one frame, reassembling across however many chunks arrive. */
    public static Decoded read(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[65536];
        while (true) {
            try {
                return decode(buf.toByteArray());
            } catch (Incomplete ignored) {
                // fall through and read more
            }
            int n = in.read(chunk);
            if (n < 0) throw new Incomplete("peer closed mid-frame");
            buf.write(chunk, 0, n);
        }
    }
}
