package hx.bridge;

import java.util.*;

/**
 * Reads tests/vectors/malformed.json. Unlike frames.json, every case object
 * here is flat -- name, header_text and why are all plain strings -- so the
 * ordinary flat Json.parse can read each case directly; only the outer
 * "cases" array needs a hand-rolled boundary scan.
 */
final class MalformedVectorReader {

    static List<Map<String, Object>> cases(String text) {
        List<Map<String, Object>> out = new ArrayList<>();
        int i = text.indexOf("\"cases\"");
        if (i < 0) throw new IllegalArgumentException("no cases key");
        int depth = 0;
        int objStart = -1;
        for (int p = text.indexOf('[', i); p < text.length(); p++) {
            char c = text.charAt(p);
            if (c == '"') { p = skipString(text, p); continue; }
            if (c == '{') { if (depth == 0) objStart = p; depth++; }
            else if (c == '}') {
                depth--;
                if (depth == 0) out.add(Json.parse(text.substring(objStart, p + 1)));
            } else if (c == ']' && depth == 0) break;
        }
        return out;
    }

    private static int skipString(String s, int start) {
        for (int p = start + 1; p < s.length(); p++) {
            if (s.charAt(p) == '\\') { p++; continue; }
            if (s.charAt(p) == '"') return p;
        }
        throw new IllegalArgumentException("unterminated string");
    }
}
