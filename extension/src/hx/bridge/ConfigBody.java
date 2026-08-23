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

    /**
     * The keys that are read as numbers, and are therefore checked HERE.
     *
     * REPRODUCED END TO END over a unix socket before this existed:
     * `limit.rate_rps = as fast as possible` parsed fine, the extension acked
     * `t=configured epoch=1`, and the operator's console said the run was
     * configured. The FIRST send then threw out of Limits.arm, the send arm
     * answered `not_configured`, dropped to DENY-ALL and CLOSED -- and
     * HxExtension has no reconnect (`c.connect()` runs once, on a daemon
     * thread), so the corrected configure could not be sent at all:
     * `java.io.IOException: Broken pipe`. Recovery needed an extension reload
     * inside Burp.
     *
     * Refusing it here answers `bad_config` instead: the same DENY-ALL, the
     * same nothing-issued, but the channel lives and the next configure is
     * heard. Safety is identical; recoverability is not. An equally malformed
     * value arriving one frame later already got the survivable answer, and
     * that asymmetry was the whole argument.
     *
     * `limit.concurrency` is deliberately NOT in this list. Nothing reads it
     * yet -- refusing a config for a value no code consults would be this
     * parser inventing a rule rather than enforcing one. It joins the list in
     * the change that honours it.
     */
    private static final Set<String> POSITIVE_INTEGER_KEYS =
        Set.of("limit.rate_rps", "limit.max_requests");

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
        // Checked after the whole body is read, so a repeated key is seen as
        // repeated. See POSITIVE_INTEGER_KEYS for why this is worth a frame
        // the caller can recover from.
        for (String key : POSITIVE_INTEGER_KEYS) positiveInteger(out.get(key), key);

        Map<String, List<String>> frozen = new LinkedHashMap<>();
        out.forEach((k, v) -> frozen.put(k, List.copyOf(v)));
        return Collections.unmodifiableMap(frozen);
    }

    /**
     * "integer, once" -- the protocol document's words for these keys -- read
     * as a refusal rather than as documentation.
     *
     * An absent key is fine: it means the operator expressed no opinion and
     * the jar's built-in default answers. A key that is PRESENT and unreadable
     * is not, and falling back to the default there is the one answer wrong in
     * both directions -- an operator who asked for 1 rps would silently get 5,
     * and one who asked for 500 would silently get 5 as well.
     *
     * Limits.positive still makes the same three checks on the value it
     * actually uses. That is not duplication to be tidied away: this one
     * guards the WIRE, and an Authorisation can be constructed without ever
     * crossing it.
     */
    private static void positiveInteger(List<String> values, String key) {
        if (values == null || values.isEmpty()) return;
        if (values.size() != 1)
            throw new Frame.FrameError(key + " was set " + values.size()
                + " times; it is an integer, once -- two answers to \"how fast\" "
                + "is not a limit");
        String raw = values.get(0).strip();
        long n;
        try {
            n = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw new Frame.FrameError(key + " is not an integer: " + raw);
        }
        if (n <= 0) throw new Frame.FrameError(key + " must be positive, not " + n);
    }
}
