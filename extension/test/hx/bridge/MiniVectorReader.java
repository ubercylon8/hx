package hx.bridge;

import java.util.*;

/**
 * Reads tests/vectors/frames.json. Json.parse handles only flat objects by
 * design, and each vector entry nests a "header" object one level deep, so
 * this reader carves the header substring out and parses it on its own (it
 * IS flat by itself), then parses the rest of the entry -- with a string
 * placeholder standing in for the header -- through the same flat parser.
 * Widening Json.parse to accept nesting, just to satisfy a test, is the
 * wrong trade.
 */
final class MiniVectorReader {

    static List<Map<String, Object>> frames(String text) {
        List<Map<String, Object>> out = new ArrayList<>();
        int i = text.indexOf("\"frames\"");
        if (i < 0) throw new IllegalArgumentException("no frames key");
        int depth = 0;
        int objStart = -1;
        for (int p = text.indexOf('[', i); p < text.length(); p++) {
            char c = text.charAt(p);
            if (c == '"') { p = skipString(text, p); continue; }
            if (c == '{') { if (depth == 0) objStart = p; depth++; }
            else if (c == '}') {
                depth--;
                if (depth == 0) out.add(parseEntry(text.substring(objStart, p + 1)));
            } else if (c == ']' && depth == 0) break;
        }
        return out;
    }

    /**
     * A frame entry is flat except for its one nested "header" object. Carve
     * the header out, parse it on its own, and parse the remainder -- with a
     * string placeholder standing in for header -- with the same flat parser.
     */
    private static Map<String, Object> parseEntry(String entry) {
        int hk = entry.indexOf("\"header\"");
        if (hk < 0) throw new IllegalArgumentException("frame entry has no header: " + entry);
        int hStart = entry.indexOf('{', hk);
        int hEnd = matchBrace(entry, hStart);
        Map<String, Object> header = Json.parse(entry.substring(hStart, hEnd + 1));

        String flattened = entry.substring(0, hStart) + "\"\"" + entry.substring(hEnd + 1);
        Map<String, Object> out = new LinkedHashMap<>(Json.parse(flattened));
        out.put("header", header);
        return out;
    }

    private static int matchBrace(String s, int open) {
        int depth = 0;
        for (int p = open; p < s.length(); p++) {
            char c = s.charAt(p);
            if (c == '"') { p = skipString(s, p); continue; }
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return p; }
        }
        throw new IllegalArgumentException("unterminated object");
    }

    private static int skipString(String s, int start) {
        for (int p = start + 1; p < s.length(); p++) {
            if (s.charAt(p) == '\\') { p++; continue; }
            if (s.charAt(p) == '"') return p;
        }
        throw new IllegalArgumentException("unterminated string");
    }
}
