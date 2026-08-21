package hx.bridge;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * The `configure` body: key<TAB>value lines, repeated keys accumulating in
 * order. Not JSON, because a flat JSON parser cannot express the nested scope
 * and limit configuration and widening the parser is the wrong trade.
 */
public final class ConfigBody {

    public static final Set<String> KEYS = Set.of(
        "scope.include", "scope.exclude", "dangerous.path", "method.allow",
        "limit.rate_rps", "limit.concurrency", "limit.max_requests", "render.allow"
    );

    private ConfigBody() { }

    public static Map<String, List<String>> parse(byte[] body) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (String line : new String(body, StandardCharsets.UTF_8).split("\n", -1)) {
            if (line.isEmpty()) continue;
            int tab = line.indexOf('\t');
            if (tab < 0) throw new Frame.FrameError("config line has no tab separator: " + line);
            String key = line.substring(0, tab);
            if (!KEYS.contains(key))
                // Silently ignoring a key the sender believed it set is how a
                // scope rule goes missing.
                throw new Frame.FrameError("unrecognised config key: " + key);
            out.computeIfAbsent(key, k -> new ArrayList<>()).add(line.substring(tab + 1));
        }
        return out;
    }
}
