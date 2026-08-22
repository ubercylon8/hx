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
        // parse() is the ONLY producer of a Map<String, List<String>> that
        // BridgeClient hands out (authorisation().scope() / scopeConfig()),
        // and nothing downstream mutates it after this call returns. Freeze
        // it here so that invariant holds by construction rather than by
        // convention: a holder that widened scope in place would authorise
        // requests under a scope no configure frame ever set, no epoch bump
        // and no log line to show for it.
        //
        // Both levels are needed: Map.copyOf alone would leave each inner
        // ArrayList mutable, and mutating a scope list in place authorises a
        // scope no configure frame ever set -- no epoch bump, no log line.
        //
        // The outer wrapper is unmodifiableMap over a LinkedHashMap rather
        // than Map.copyOf so that ITERATION order survives. Be clear about
        // what does and does not depend on that: CodecTest's "repeated keys
        // accumulate in order" asserts on the inner List, which List.copyOf
        // preserves either way -- swapping in Map.copyOf keeps the whole suite
        // green. Nothing tests map iteration order. It is preserved here
        // because a config's key order is the operator's, and an unordered
        // rendering of someone's scope in a report is a defect no test will
        // catch for you.
        Map<String, List<String>> frozen = new LinkedHashMap<>();
        out.forEach((k, v) -> frozen.put(k, List.copyOf(v)));
        return Collections.unmodifiableMap(frozen);
    }
}
