package hx.bridge;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A JSON reader and writer for FLAT objects only.
 *
 * Values may be string, integer, boolean or null -- no nested objects, no
 * arrays. That is not a shortcut, it is the contract: the bridge header schema
 * is flat precisely so this parser stays small enough to be obviously correct,
 * and structured payloads travel in the frame body instead. A nested value is
 * rejected loudly rather than half-parsed.
 */
public final class Json {

    public static class JsonError extends RuntimeException {
        public JsonError(String m) { super(m); }
    }

    private Json() { }

    // ---- writing ----------------------------------------------------

    public static String write(Map<String, Object> obj) {
        StringBuilder s = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : obj.entrySet()) {
            if (!first) s.append(',');
            first = false;
            writeString(s, e.getKey());
            s.append(':');
            writeValue(s, e.getValue());
        }
        return s.append('}').toString();
    }

    private static void writeValue(StringBuilder s, Object v) {
        if (v == null) { s.append("null"); return; }
        if (v instanceof String str) { writeString(s, str); return; }
        if (v instanceof Boolean b) { s.append(b ? "true" : "false"); return; }
        if (v instanceof Integer || v instanceof Long) { s.append(v); return; }
        throw new JsonError("header must be flat; cannot write " + v.getClass().getName());
    }

    private static void writeString(StringBuilder s, String v) {
        s.append('"');
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            switch (c) {
                case '"'  -> s.append("\\\"");
                case '\\' -> s.append("\\\\");
                case '\n' -> s.append("\\n");
                case '\r' -> s.append("\\r");
                case '\t' -> s.append("\\t");
                case '\b' -> s.append("\\b");
                case '\f' -> s.append("\\f");
                default -> {
                    if (c < 0x20) s.append(String.format("\\u%04x", (int) c));
                    else s.append(c);
                }
            }
        }
        s.append('"');
    }

    // ---- parsing ----------------------------------------------------

    public static Map<String, Object> parse(String text) {
        P p = new P(text);
        p.ws();
        p.expect('{');
        Map<String, Object> out = new LinkedHashMap<>();
        p.ws();
        if (p.peek() == '}') { p.next(); return out; }
        while (true) {
            p.ws();
            String key = p.string();
            p.ws();
            p.expect(':');
            p.ws();
            out.put(key, p.value());
            p.ws();
            char c = p.next();
            if (c == '}') return out;
            if (c != ',') throw new JsonError("expected ',' or '}' at " + p.i);
        }
    }

    private static final class P {
        final String s;
        int i = 0;
        P(String s) { this.s = s; }

        char peek() {
            if (i >= s.length()) throw new JsonError("unexpected end of input");
            return s.charAt(i);
        }

        char next() { char c = peek(); i++; return c; }

        void expect(char c) {
            char got = next();
            if (got != c) throw new JsonError("expected '" + c + "' but found '" + got + "' at " + (i - 1));
        }

        void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

        String string() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') return b.toString();
                if (c != '\\') { b.append(c); continue; }
                char esc = next();
                switch (esc) {
                    case '"'  -> b.append('"');
                    case '\\' -> b.append('\\');
                    case '/'  -> b.append('/');
                    case 'n'  -> b.append('\n');
                    case 'r'  -> b.append('\r');
                    case 't'  -> b.append('\t');
                    case 'b'  -> b.append('\b');
                    case 'f'  -> b.append('\f');
                    case 'u'  -> {
                        if (i + 4 > s.length()) throw new JsonError("truncated \\u escape");
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> throw new JsonError("bad escape \\" + esc);
                }
            }
        }

        Object value() {
            char c = peek();
            if (c == '"') return string();
            if (c == '{' || c == '[')
                throw new JsonError("header must be flat; nested values are not supported");
            if (s.startsWith("true", i))  { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i))  { i += 4; return null; }
            int start = i;
            if (c == '-') i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            if (i == start) throw new JsonError("unparseable value at " + i);
            if (i < s.length() && (s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E'))
                throw new JsonError("header numbers must be integers");
            return Long.parseLong(s.substring(start, i));
        }
    }
}
