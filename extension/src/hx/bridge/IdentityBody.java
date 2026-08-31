package hx.bridge;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The `identity` body: `{identity_id, generation, inject: {header, value},
 * origins: [...]}`, JSON, written by `hx.bridge.codec.identity_body`.
 *
 * JSON rather than {@link ConfigBody}'s key&lt;TAB&gt;value lines because the
 * payload nests, and because the writer on the Python side is already JSON --
 * this is the reader for what that function emits, not a second opinion about
 * what the frame should look like. It stands beside ConfigBody for the same
 * reason ConfigBody stands apart from {@link Json}: a frame BODY is a
 * structured payload with rules of its own, and the class that says what those
 * rules are is not the class that reads characters. The characters here are
 * {@link Json#parseBody}'s, because there is one JSON grammar in this tree and
 * a second reader of it would be free to disagree about a surrogate pair.
 *
 * EVERY FIELD IS RE-VALIDATED, and `hx.bridge.codec.parse_identity` states the
 * principle for both sides: a body is checked on the reading side because the
 * writing side being in this repository is not a guarantee about what actually
 * arrived on the wire. The checks below are that function's, field for field
 * -- a missing origin list, a generation below 1, an empty value -- and where
 * they differ THIS side is the stricter one: an all-whitespace `identity_id`,
 * `header` or `value` is truthy in Python and is refused here, which is the
 * fail-closed direction and is also what `IdentityRegistry.register` would say
 * about it one call later.
 *
 * WHAT THIS DOES NOT DO is decide whether the identity may be registered.
 * A generation that does not advance the one already held is a REFUSAL and not
 * a malformed frame, and the only thing that knows which is the registry; see
 * BridgeClient's `identity` arm, which maps the two apart onto
 * `bad_identity` and `stale_generation`.
 *
 * `Parsed.toString()` is overridden for the reason `IdentityRegistry.Entry`'s
 * is: this is the one frame in the protocol whose payload is a live credential
 * (spec s5), and a record's generated toString would put it into any exception
 * message or debug line that happened to hold one.
 */
public final class IdentityBody {

    public record Parsed(String identityId, int generation, String header,
                         String value, List<String> origins) {
        @Override
        public String toString() {
            return "IdentityBody[identity_id=" + identityId
                 + ", generation=" + generation + ", header=" + header
                 + ", origins=" + origins + ", value=<redacted>]";
        }
    }

    private IdentityBody() { }

    /** @throws Frame.FrameError for a body this cannot be acted on, which
     *  BridgeClient answers with `bad_identity`. A {@link Json.JsonError} from
     *  the grammar underneath is wrapped into one here, so a caller has a
     *  single type to catch and the two failures cannot drift apart. */
    public static Parsed parse(byte[] body) {
        Map<String, Object> payload;
        try {
            payload = Json.parseBody(new String(body, StandardCharsets.UTF_8));
        } catch (Json.JsonError e) {
            throw new Frame.FrameError("identity body is not valid JSON: " + e.getMessage());
        }

        String identityId = string(payload.get("identity_id"));
        if (identityId == null) throw new Frame.FrameError("an identity frame needs an identity_id");

        // A Long on this side, like every other JSON number. The int cast is
        // checked rather than truncated: IdentityRegistry counts generations
        // in an int, and a silently wrapped 2^32 + 1 would read as generation
        // 1 and be accepted as a rollback of everything above it.
        if (!(payload.get("generation") instanceof Long g))
            throw new Frame.FrameError("generation must be an integer >= 1, got "
                                       + payload.get("generation"));
        if (g < 1 || g > Integer.MAX_VALUE)
            throw new Frame.FrameError("generation must be an integer >= 1 and at most "
                                       + Integer.MAX_VALUE + ", got " + g);

        if (!(payload.get("inject") instanceof Map<?, ?> inject))
            throw new Frame.FrameError("an identity frame needs an inject object");
        String header = string(inject.get("header"));
        if (header == null) throw new Frame.FrameError("an identity frame needs a header to inject into");
        String value = string(inject.get("value"));
        if (value == null) throw new Frame.FrameError("an identity frame with no value registers nothing");

        // A BLANK origin is refused alongside a missing list, and the reason is
        // `parse_identity`'s: an entry that matches no host is not a narrower
        // bound, it is a silently dead rule, and the caller believes it
        // registered one the extension will never apply.
        if (!(payload.get("origins") instanceof List<?> raw) || raw.isEmpty())
            throw new Frame.FrameError(
                "an identity frame needs at least one origin; an identity with no "
                + "origin could be applied to any host the scope allows");
        List<String> origins = new ArrayList<>();
        for (Object o : raw) {
            String origin = string(o);
            if (origin == null)
                throw new Frame.FrameError(
                    "an identity frame needs at least one origin; an identity with no "
                    + "origin could be applied to any host the scope allows");
            origins.add(origin);
        }

        return new Parsed(identityId, (int) (long) g, header, value, List.copyOf(origins));
    }

    /** The value as a non-blank String, or null for anything else. Blank and
     *  absent are one answer here because they have one consequence: a field
     *  the frame did not actually supply. */
    private static String string(Object v) {
        return v instanceof String s && !s.isBlank() ? s : null;
    }
}
