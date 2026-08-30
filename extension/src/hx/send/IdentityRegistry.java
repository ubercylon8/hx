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

    public void register(String id, int generation, String header, String value,
                         List<String> origins) {
        if (id == null || id.isBlank())
            throw new IllegalArgumentException("an identity needs an id");
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
            if (held != null && generation == held.generation())
                return held;
            return new Entry(id, generation, header, value, frozen);
        });
    }

    /** The identity, or null when nothing is registered under that id. */
    public Entry get(String id) { return id == null ? null : byId.get(id); }
}
