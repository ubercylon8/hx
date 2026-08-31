package hx.send;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The identities this run may issue under, held in memory and written nowhere.
 *
 * GENERATION IS MONOTONIC, and the reason is Limiter's: a value that can go
 * backwards is a value a replayed frame can control. A refresh advances the
 * generation, so accepting a LOWER one would let a duplicated or reordered
 * frame restore a credential the operator has already replaced -- most likely
 * a dead one, which would produce a run of unauthenticated answers that every
 * check reads as "not vulnerable".
 *
 * The SAME generation is idempotent rather than an error: the bridge may retry
 * a frame, and a retry that threw would fail a run over a duplicate that
 * changed nothing.
 *
 * `Entry.toString()` is overridden because a record's generated one would put
 * a live session cookie into every exception message and debug line that
 * happens to hold an Entry.
 *
 * WHAT MAY BE WRITTEN ONTO THE WIRE IS DECIDED HERE, NOT BY THE CALLER. §4's
 * invariant is that "every byte that leaves this machine crosses exactly one
 * of two enforcement points, BOTH INSIDE THE JVM", and `Policy.checkGate`
 * decides about a REQUEST -- so bytes appended to that request after it
 * answered are bytes that crossed no such point. {@link Sender#compose} appends
 * `header + ": " + value` and its self-check cannot see the difference: it
 * verifies that the bytes at the registered range ARE the credential, and a
 * value containing CRLF satisfies that exactly while splitting into a second
 * header. So the character class and the header NAME are both refused HERE,
 * at the one door an entry can come through, rather than trusted to the
 * harness on the other side of a socket. The harness refuses them too --
 * `hx.config` restricts `inject.header` to the same three names at load, and
 * `hx.bridge.codec.identity_body` refuses the same character class when it
 * writes the frame -- and that is worth having for the earlier, better error.
 * It is not what makes the invariant hold. See {@link #register}.
 */
public final class IdentityRegistry {

    public static final class StaleGeneration extends RuntimeException {
        public StaleGeneration(String message) { super(message); }
    }

    public record Entry(String id, int generation, String header, String value,
                        List<String> origins) {
        @Override
        public String toString() {
            return "Entry[id=" + id + ", generation=" + generation
                 + ", header=" + header + ", origins=" + origins
                 + ", value=<redacted>]";
        }
    }

    private final Map<String, Entry> byId = new ConcurrentHashMap<>();

    /**
     * Hold {@code id} at {@code generation}, or refuse.
     *
     * Every refusal here is an {@link IllegalArgumentException} except the
     * rollback, which is a {@link StaleGeneration}: BridgeClient answers the
     * first `bad_identity` and the second `stale_generation`, and the two say
     * different things to an operator -- "this frame is malformed" and "this
     * frame arrived after a newer one".
     *
     * NO REFUSAL MESSAGE QUOTES THE VALUE, not even one character of it. §5
     * says the credential is logged on neither side, and these messages travel
     * as an `error` frame's detail and are logged by the harness that receives
     * them. The header name IS quoted, but only once it is known to be free of
     * CR, LF and NUL -- a name carrying a newline would otherwise forge a line
     * in the harness's own log.
     */
    public void register(String id, int generation, String header, String value,
                         List<String> origins) {
        if (id == null || id.isBlank())
            throw new IllegalArgumentException("an identity needs an id");
        // THE ID IS CHECKED FOR THE SAME CHARACTERS AS THE CREDENTIAL, and it
        // is not decoration. The id is interpolated into every refusal this
        // class and `Sender` produce, and `unknown_identity`/`identity_origin`
        // are RECORDED: `hx.store.records` writes the refusal text into
        // `denial.reason`. So an id carrying a line feed forges a line in a
        // STORED ROW, not merely in a log -- the same defect as a credential
        // carrying one, one layer out. The Task 5 re-review traced how far it
        // reached rather than stopping at the log.
        //
        // Checked BEFORE the id is used in any message below, so a refusal
        // about a hostile id cannot itself carry that id into the row that
        // records it.
        checkWritable(id, "id", id);
        if (generation < 1)
            throw new IllegalArgumentException(
                "generation must be at least 1, got " + generation);
        if (header == null || header.isBlank())
            throw new IllegalArgumentException("identity " + id + " has no header");
        if (value == null || value.isBlank())
            throw new IllegalArgumentException(
                "identity " + id + " has a blank value; that is not a credential");
        if (origins == null || origins.isEmpty())
            throw new IllegalArgumentException(
                "identity " + id + " has no origins; an identity with no origin "
                + "could be applied to any host the scope allows");

        // THE CHARACTER CLASS FIRST, so that everything below it -- including
        // the name match, which compares against ASCII spellings -- is looking
        // at text the wire can carry verbatim.
        checkWritable(id, "header name", header);
        checkWritable(id, "value", value);

        // ...AND THE NAME SET, which until the Task 5 review only `hx.config`
        // enforced. A name is not a free string here: `Sender.withHeaderFirst`
        // writes it as the FIRST header of the composed request, so whatever
        // is registered is what goes out. `Redactor.isCredentialHeader` is
        // asked rather than a list being kept here, for the reason
        // `OBSERVED_CREDENTIAL` is derived rather than typed out: the three
        // names are one vocabulary, and a copy of it here would be a second
        // place to edit and a silent drift when only one of them was.
        if (!Redactor.isCredentialHeader(header))
            throw new IllegalArgumentException(
                "identity " + id + " asks to inject into '" + header + "', which is "
                + "not one of the three credential headers this extension will "
                + "write (Cookie, Authorization, Proxy-Authorization)");

        // COPIED, not referenced: the caller keeps its own list, and a list
        // this class held a reference to could be widened after registration.
        List<String> frozen = List.copyOf(origins);

        byId.compute(id, (k, held) -> {
            if (held != null && generation < held.generation())
                throw new StaleGeneration(
                    "identity " + id + " is at generation " + held.generation()
                    + "; refusing to go back to " + generation);
            // EQUAL GENERATION KEEPS THE HELD ENTRY, and that is not a
            // shortcut for the retry case -- it is the monotonic rule meaning
            // what it says. This used to build a new Entry from whatever the
            // call passed, so a second frame at the SAME generation carrying a
            // DIFFERENT credential swapped it silently: a content change that
            // never advanced the counter whose whole job is to gate content
            // changes. Identical content, which is all a bridge retry ever
            // sends, is unaffected either way. A real rotation advances the
            // generation -- `hx.identity.refresh` returns `generation + 1`
            // unconditionally -- so nothing legitimate needs this door.
            //
            // A STATIC identity does not advance it: `hx.identity.resolve`
            // hard-codes generation 1, so a rotated static credential
            // arriving here at 1 would be dropped in favour of the held one.
            // That is unreachable while every scan gets a fresh JVM and an
            // empty registry, and the full argument -- what makes it
            // unreachable, what would make it reachable, and what the fix
            // would be -- is written on `resolve` rather than duplicated
            // here. Read it before making this registry outlive a run.
            if (held != null && generation == held.generation())
                return held;
            return new Entry(id, generation, header, value, frozen);
        });
    }

    /**
     * Refuse text that {@link Sender#compose} could not write onto the wire as
     * itself.
     *
     * THREE CLASSES, EACH FOR A DIFFERENT REASON:
     *
     *   - CR and LF END A HEADER. `compose` writes `name + ": " + value` and
     *     `Sender.wireBytes` ends each field with CRLF, so a value of
     *     {@code "sess=1\r\nX-Smuggled: yes"} issues a SECOND header that no
     *     gate saw -- and `compose`'s own self-check passes, because the bytes
     *     at the registered range genuinely are the value it was handed. A
     *     value containing a blank line ends the head early and turns the
     *     caller's remaining fields, `Host` included, into a body;
     *     {@code "\r\nContent-Length: 0"} is a request-smuggling primitive
     *     written by the enforcement point itself.
     *   - NUL IS NOT LEGAL FIELD CONTENT. It cannot split a header, and it is
     *     refused anyway: RFC 9110 §5.5's field-content admits VCHAR, SP, HTAB
     *     and obs-text and nothing else, so a credential carrying one is a
     *     credential whose treatment is left to whatever parses it. Everything
     *     between here and the socket is Java, so this is NOT a claim that it
     *     would be truncated somewhere -- it is a refusal to write a field the
     *     grammar does not admit and then reason about what came back.
     *   - ABOVE LATIN-1 IS SILENTLY MANGLED. `wireBytes` encodes ISO-8859-1
     *     and `String.getBytes` replaces an unmappable character with '?', so
     *     {@code "sess=€123"} goes out as {@code "sess=?123"}: a
     *     credential the server rejects, an answer given to nobody, and a
     *     check that reads it as "not vulnerable" -- the single outcome this
     *     whole feature exists to prevent. The offsets stay correct and the
     *     redaction stays correct, which is exactly why nothing downstream can
     *     notice. Refusing at registration is where an operator can act on it.
     *
     * WHAT IS NOT REFUSED, deliberately: the other C0 controls, DEL, and the
     * 0x80..0xFF half of Latin-1. None of them can end a header or change the
     * byte length, obs-text (RFC 9110 §5.5) makes the high half legal field
     * content, and 8-bit cookie values do occur. The bound is drawn at what
     * changes the SHAPE of the request or the CONTENT of the credential, not
     * at what looks unusual.
     */
    private static void checkWritable(String id, String what, String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // The character itself is never named -- see register()'s javadoc.
            // The class is what an operator needs, and it is what a refresh
            // script printing two lines, or a pasted variable, will hit.
            if (c == '\r' || c == '\n')
                throw new IllegalArgumentException(
                    "identity " + id + "'s " + what + " contains a carriage return "
                    + "or line feed; injecting it would write a header this "
                    + "extension never decided about");
            if (c == '\0')
                throw new IllegalArgumentException(
                    "identity " + id + "'s " + what + " contains a NUL");
            if (c > 0xFF)
                throw new IllegalArgumentException(
                    "identity " + id + "'s " + what + " contains a character "
                    + "outside Latin-1; the wire encoding would replace it with "
                    + "'?', and a mangled credential answers as an unauthenticated "
                    + "one");
        }
    }

    /** The identity, or null when nothing is registered under that id. */
    public Entry get(String id) { return id == null ? null : byId.get(id); }
}
