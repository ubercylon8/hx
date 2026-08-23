// extension/src/hx/send/Redactor.java
package hx.send;

import hx.policy.HxRequest;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Credential redaction for the copy of an exchange that crosses the bridge.
 *
 * Three jobs, and they are three because a credential reaches disk by three
 * different routes (§7):
 *
 *  1. What WE injected. The extension knows the exact byte range it wrote, so
 *     it replaces that range with {@code {{identity:<id>:authz}}}. Byte ranges,
 *     not header names: the range is known exactly, and a name match is a
 *     guess. The ranges are handed in as an {@link Injected} alongside the
 *     bytes they were measured from -- see that class for why they are not
 *     kept on the Redactor. Nothing registers a range until identity injection
 *     ships; until then an empty {@code Injected} passes every request through
 *     unchanged. It is built now anyway because §7 calls this the one item
 *     that cannot be retrofitted -- once raw credentials are content-addressed
 *     into the blob store they are in every backup taken since.
 *
 *  2. What we did NOT inject. {@link #unmanagedCredential} names an
 *     Authorization, Cookie or Proxy-Authorization header the harness supplied
 *     itself. The Sender refuses such a request with {@code
 *     unmanaged_credential} and never persists it, which is what closes the
 *     window before job 1 has anything to redact.
 *
 *  3. What the application handed BACK. A response Set-Cookie is a live
 *     production session cookie the extension never injected, so job 1 cannot
 *     key on it and job 2 cannot refuse it -- the request already went out.
 *     Header-name matching is all there is, so cookie VALUES are replaced with
 *     {@code {{observed:set-cookie}}} and the cookie name and its attributes
 *     are kept, so session-fixation and cookie-flag checks still read.
 *
 * Redaction runs BEFORE hashing. The blob store is content-addressed: the
 * digest names the bytes it was computed over, so hashing raw bytes and
 * redacting afterwards stores the raw ones under their own digest.
 *
 * The bytes on the wire are never touched. redactRequest() and redactResponse()
 * return a new array and leave their argument byte-for-byte as it was: the
 * request Burp issues is verbatim, only the copy crossing the bridge carries
 * placeholders. An in-place edit would corrupt the very exchange it is meant to
 * evidence.
 *
 * No burp.* import, no I/O, no clock: this class is decided by its arguments
 * alone and its tests need nothing running.
 */
public final class Redactor {

    /**
     * A registered range that cannot be applied to these bytes. Refusing is
     * the only safe answer: a range that runs off the end, or over another,
     * describes a request other than the one in hand, and applying it anyway
     * would either truncate the request or blank out a span of somebody
     * else's body.
     *
     * The send path catches this and answers with the error class
     * {@code bad_frame} -- nothing has been issued at that point, and §4 says
     * an exception is never an implicit allow.
     */
    public static final class RangeError extends RuntimeException {
        public RangeError(String m) { super(m); }
    }

    /**
     * The three credential headers §6 names, lower-cased for the ASCII match
     * below, in the FIXED precedence order the refusal reports. A request may
     * carry more than one; which one is named must not depend on the harness's
     * map iteration order, or the same refusal reads differently twice.
     */
    private static final String[] CREDENTIAL_HEADERS = {
        "authorization", "cookie", "proxy-authorization"
    };

    private static final byte[] OBSERVED_COOKIE =
        "{{observed:set-cookie}}".getBytes(StandardCharsets.US_ASCII);

    /** RFC 9112 2.3: the HTTP-name is case-SENSITIVE, so this is a byte match. */
    private static final byte[] HTTP_NAME = "HTTP/".getBytes(StandardCharsets.US_ASCII);

    private record Range(String identityId, int start, int end) { }

    /**
     * The byte ranges this extension injected into ONE serialised request.
     *
     * The ranges live here, next to the bytes they were measured from, rather
     * than on the Redactor -- and that is the whole of the design. A range is
     * a byte offset into ONE request; applied to another it does not merely
     * leak, it substitutes a placeholder over whatever happens to sit at those
     * offsets in the other request's body. Making the caller pass this object
     * to {@link Redactor#redactRequest} means a caller physically cannot
     * redact without naming a range set. There is nothing to clear, because
     * nothing survives the request.
     *
     * Naming A range set is not naming the RIGHT one, and the difference was
     * measured rather than argued: with the ranges merely passed in, reusing
     * one {@code Injected} for a second request threw only when the stale
     * offsets happened to collide with the new ones. Of the four shapes --
     * second request shorter, longer with no new registration, longer with an
     * overlapping registration, longer with a non-overlapping one -- two threw
     * and two silently rewrote the second request at the first one's offsets,
     * leaving the second request's own credential verbatim. Fail-closed was
     * incidental to offset collision.
     *
     * So the object is constructed FROM the array and holds it by IDENTITY,
     * and {@link Redactor#redactRequest} refuses any other array. Identity,
     * not content: two requests can serialise to equal bytes and still be two
     * requests. A range set therefore cannot precede the array it was measured
     * from -- there is no way to build one without it -- and cannot outlive
     * it, because any other array is a {@link RangeError}.
     *
     * What identity CANNOT see is in-place mutation of the same array after
     * binding. Moving the credential to a different offset within THIS array
     * after construction -- or after a range has already been registered for
     * its old position -- leaves it unprotected with no exception and no
     * signal, because the identity check still passes: it is still the same
     * array, just rewritten. That is inherent to checking identity rather
     * than content, not a gap this class can close. Plan 5, which is the
     * first caller: do not touch the array after handing it to an Injected.
     *
     * The list is per INSTANCE, and that is load-bearing separately: two
     * requests can be built, and both range sets registered, before either is
     * redacted, so one list shared between instances leaks whichever request
     * is redacted with the loser's offsets -- silently, since the bytes are
     * the right length. RedactorTest's twoRangeSetsAliveAtOnceDoNotShareOneList
     * is the pin; the sequential fixture next to it cannot reach that shape.
     *
     * Every registry kept on the REDACTOR -- a plain field or a ThreadLocal --
     * leaves a silent path to redacting against the WRONG registry, and it
     * fails OPEN. With a ThreadLocal: register on the read loop, redact on a
     * pooled worker (the `limit.concurrency` case §6 already has a config key
     * for) and the worker's registry is empty, so redactRequest hands back a
     * verbatim copy INCLUDING the credential, with no exception and no signal
     * of any kind -- and that is what gets content-addressed. §7 calls this
     * the one item that cannot be retrofitted, so the shape has to be the one
     * that cannot desync rather than the one that usually does not.
     *
     * synchronized because this object legitimately crosses threads -- the
     * read loop may build it and a worker redact with it. Read that as memory
     * safety and nothing more, because that is all it was measured to be. It
     * makes the list safe to touch from two threads; it does NOT order
     * registration before redaction. A range registered after redactRequest
     * has taken its snapshot is simply not in it, and the copy that crosses
     * the bridge carries the credential with no exception and no signal.
     * This is a genuine race, not a hypothetical one -- but no leak rate is
     * recorded here, because none was reproducible: an unsynchronized race
     * between register() and redactRequest(), and the same two actions
     * released together from a barrier, have each now been measured at three
     * sharply different rates by three separate attempts, in both
     * directions. Every number was a property of a harness and a scheduler,
     * never of this class. What holds regardless of the number is that the
     * lock decides nothing about which of the two happens first. The
     * contract the caller has to keep, and which nothing here can check, is
     * REGISTER EVERYTHING, THEN REDACT.
     *
     * Deliberately NOT pinned by a test, because the only shape such a test
     * could take is asserting that a late registration is absent from an
     * earlier output -- a check that passes if and only if the credential
     * survives. This suite has already had one of those.
     *
     * Two further honesty notes, in the spirit of the matcher paragraph at the
     * foot of this file: no test here distinguishes {@code snapshot()}'s copy
     * from the live list (the sort that would race happens in the caller), and
     * none distinguishes either {@code synchronized} keyword from its absence.
     * Both are measured green when removed. They are here because this object
     * crosses threads by design, not because something is watching them.
     */
    public static final class Injected {

        /** The array these offsets were measured from, by identity. */
        private final byte[] forThese;

        private final List<Range> ranges = new ArrayList<>();

        /**
         * @param forThese the serialised request whose bytes the ranges
         *                 registered here are offsets into. Held, not copied:
         *                 the point is to recognise THAT array again.
         */
        public Injected(byte[] forThese) {
            if (forThese == null)
                throw new RangeError("an Injected must name the bytes its ranges are measured from");
            this.forThese = forThese;
        }

        /**
         * Record a half-open byte range [start, end) that this extension
         * injected into the request bytes on behalf of {@code identityId}.
         *
         * Overlaps are rejected here, where the caller that made the mistake
         * is still on the stack. Abutting ranges -- [10,20) and [20,30) -- are
         * two adjacent injected headers and are fine.
         */
        public synchronized void register(String identityId, int start, int end) {
            if (identityId == null || identityId.isEmpty())
                throw new RangeError("a registered range must name an identity");
            if (start < 0 || end <= start)
                throw new RangeError("not a range: [" + start + "," + end + ")");
            for (Range r : ranges)
                if (start < r.end() && r.start() < end)
                    throw new RangeError("range [" + start + "," + end + ") overlaps ["
                        + r.start() + "," + r.end() + ") registered for " + r.identityId());
            ranges.add(new Range(identityId, start, end));
        }

        /** A copy, so redactRequest sorts and walks a list nothing else holds. */
        private synchronized List<Range> snapshot() {
            return new ArrayList<>(ranges);
        }
    }

    /**
     * The name of a credential header this extension did not inject, or null.
     *
     * It answers about the request the HARNESS sent us, which is why no
     * registered range is consulted: {@link HxRequest} is the frozen content
     * of a `send` frame, injection happens downstream on the serialised bytes,
     * and that is precisely why registered ranges are byte offsets rather than
     * header names. So a credential header present HERE is by construction one
     * we did not put there. The Sender's order is fixed by that: refuse on
     * this answer first, then inject, then register, then redact.
     *
     * The value is not inspected. A header we did not inject is unmanaged
     * whether or not this particular value looks like a credential, and a
     * value-sniffing rule is the kind that gets fooled.
     */
    public String unmanagedCredential(HxRequest req) {
        Map<String, List<String>> headers = req.headers();
        if (headers == null) return null;
        for (String wanted : CREDENTIAL_HEADERS)
            for (Map.Entry<String, List<String>> e : headers.entrySet())
                // The name as the harness wrote it, not the one we matched on:
                // the refusal should quote what was actually sent.
                if (asciiEqualsIgnoreCase(wanted, e.getKey())) return e.getKey();
        return null;
    }

    /**
     * The request bytes with every range in {@code injected} replaced by that
     * identity's placeholder. Neither argument is modified.
     *
     * {@code injected} must be the ranges measured from THESE bytes, and it
     * is CHECKED rather than assumed: an {@code Injected} built for another
     * array is refused whatever its offsets are. It is a parameter rather than
     * state on this object so that there is no other kind of call to make: no
     * registry to desync, none to forget to clear.
     *
     * A null {@code raw} is a {@link RangeError} too, not the
     * {@code NullPointerException} it would otherwise be. The send path turns
     * a RangeError into {@code bad_frame}; an NPE reaches BridgeClient's
     * catch-all and closes the connection.
     */
    public byte[] redactRequest(byte[] raw, Injected injected) {
        if (raw == null)
            throw new RangeError("redactRequest needs the request bytes");
        if (injected == null)
            throw new RangeError("redactRequest needs the ranges injected into these bytes");
        if (injected.forThese != raw)
            // Not the array these offsets were measured from. Two requests can
            // serialise to equal bytes, so this is an identity test: reusing
            // one range set for a second request is the shape that silently
            // rewrote the second request wherever the offsets missed.
            throw new RangeError("these ranges were measured from another " + injected.forThese.length
                + "-byte array, not the " + raw.length + "-byte request being redacted");
        List<Range> mine = injected.snapshot();
        // A copy even when there is nothing to do: the returned array must
        // never alias the array that goes on the wire, or a later in-place
        // fix-up to one silently edits the other.
        if (mine.isEmpty()) return raw.clone();

        mine.sort(Comparator.comparingInt(Range::start));
        for (Range r : mine)
            if (r.end() > raw.length)
                throw new RangeError("range [" + r.start() + "," + r.end() + ") registered for "
                    + r.identityId() + " runs past the " + raw.length + "-byte request");

        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length);
        int at = 0;
        for (Range r : mine) {
            out.write(raw, at, r.start() - at);
            out.writeBytes(("{{identity:" + r.identityId() + ":authz}}")
                           .getBytes(StandardCharsets.UTF_8));
            at = r.end();
        }
        out.write(raw, at, raw.length - at);
        return out.toByteArray();
    }

    /**
     * The response bytes with every Set-Cookie VALUE replaced, name and
     * attributes kept. The argument is not modified.
     *
     * Only the head is scanned. A body may legitimately contain the text
     * "Set-Cookie: sid=..." -- documentation pages and API error dumps do --
     * and rewriting it would corrupt the evidence a check reads.
     *
     * "The head" is every head. A 1xx is an INTERIM response: RFC 9110 15.2
     * says it is never the final one, so its blank line ends a head with the
     * real response still to come. Treating that blank line as the end of the
     * scan copies the whole final response through as "body" -- every
     * Set-Cookie raw, into a content-addressed store. Whether interim heads
     * reach this class at all is Task 6's measurement of what Montoya's
     * toByteArray() carries; the branch is safe either way, because it cannot
     * fire on a final response.
     */
    public byte[] redactResponse(byte[] raw) {
        if (raw == null)
            throw new RangeError("redactResponse needs the response bytes");
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length);
        int i = 0;
        boolean first = true;       // no line of THIS head has been read yet
        boolean interim = false;    // ...and what has been read is a 1xx head
        boolean inSetCookie = false;
        while (i < raw.length) {
            int next = lineStartAfter(raw, i);      // start of the following line
            int content = contentEnd(raw, i, next); // this line without its CR/LF

            if (content == i) {                     // an empty line
                if (first) {
                    // ...but not the one that ends the head, because the head
                    // has not started. RFC 9112 2.2 says a recipient MAY
                    // ignore an empty line before the status line, so one can
                    // reach us -- and stopping here stops before a single
                    // field has been read, copying the WHOLE response through
                    // as "body" with every Set-Cookie raw. Keep it verbatim
                    // and keep looking for the status line.
                    out.write(raw, i, next - i);
                    i = next;
                    continue;
                }
                if (interim) {
                    // ...and not this one either: it ends an INTERIM head, and
                    // an interim head is by definition not the final response.
                    // The real one follows, Set-Cookie and all. Keep the blank
                    // line verbatim and start the next head.
                    out.write(raw, i, next - i);
                    i = next;
                    first = true;
                    interim = false;
                    inSetCookie = false;
                    continue;
                }
                out.write(raw, i, raw.length - i);  // the head really is over
                return out.toByteArray();
            }
            if (first && startsWithHttpName(raw, i, content)) {
                // A status line, and it has to LOOK like one. Taking the first
                // non-empty line for a status line whatever it says means a
                // head whose first field is Set-Cookie has that cookie
                // consumed as the status line and copied through raw. The
                // `first` FLAG is load-bearing three ways: it tells an empty
                // line before the status line from the empty line that ends
                // the head, it is what a 1xx head resets, and it is what stops
                // a body line reading "HTTP/1.1 200 OK" from re-arming the
                // scan -- that line is past the return above.
                interim = isInterim(raw, i, content);
                first = false;
                inSetCookie = false;
                out.write(raw, i, next - i);
                i = next;
                continue;
            }
            // A field, so the head has started even if no status line ever
            // arrived. Fall through and match it like any other.
            first = false;
            if (raw[i] == ' ' || raw[i] == '\t') {
                // obs-fold. RFC 9110 says a recipient must reject it and no
                // real server emits it, but if one does, the folded remainder
                // of a Set-Cookie is cookie bytes we cannot parse -- so the
                // whole continuation goes, attributes included. Losing a
                // folded attribute beats storing a folded session cookie.
                if (inSetCookie) {
                    int ws = i;
                    while (ws < content && (raw[ws] == ' ' || raw[ws] == '\t')) ws++;
                    out.write(raw, i, ws - i);
                    out.writeBytes(OBSERVED_COOKIE);
                    out.write(raw, content, next - content);
                } else {
                    out.write(raw, i, next - i);
                }
                i = next;
                continue;
            }
            int colon = indexOf(raw, i, content, (byte) ':');
            // Whitespace comes off the NAME before matching. RFC 9110 requires
            // a recipient to reject `Set-Cookie : v`, but name matching is all
            // job 3 has, and a name we fail to match does two things at once:
            // it passes a live cookie through verbatim, and it leaves
            // inSetCookie false, which switches the fold branch off for that
            // header's continuations as well. (Leading whitespace never
            // arrives here -- a line that starts with it is a fold.)
            // The SAME whitespace the String-side matcher trims, through the
            // same predicate, so the two cannot drift: a name this side let
            // through is a live cookie stored verbatim. A bare LF cannot occur
            // inside a line here -- lineStartAfter splits on it -- so that arm
            // is unreachable from these bytes and is shared for the drift, not
            // for the case.
            int nameEnd = colon;
            while (nameEnd > i && isOws((char) (raw[nameEnd - 1] & 0xff))) nameEnd--;
            inSetCookie = colon > i && asciiEqualsIgnoreCase("set-cookie", raw, i, nameEnd);
            if (!inSetCookie) {
                out.write(raw, i, next - i);
                i = next;
                continue;
            }
            out.write(raw, i, colon + 1 - i);       // "Set-Cookie:" as written
            int v = colon + 1;
            while (v < content && (raw[v] == ' ' || raw[v] == '\t')) v++;
            out.write(raw, colon + 1, v - (colon + 1));   // the OWS, verbatim

            int semi = indexOf(raw, v, content, (byte) ';');
            int pairEnd = semi < 0 ? content : semi;
            int eq = indexOf(raw, v, pairEnd, (byte) '=');
            if (eq < 0) {
                // No name=value split to make, so every byte of the pair is a
                // candidate value. Unknown means redact.
                out.writeBytes(OBSERVED_COOKIE);
            } else if (eq + 1 == pairEnd) {
                // "sid=" with nothing after it is a DELETION, and that is how
                // a logout is detected. An empty value cannot be a credential,
                // and a placeholder here would read as an issuance.
                out.write(raw, v, pairEnd - v);
            } else {
                out.write(raw, v, eq + 1 - v);      // the cookie name and '='
                out.writeBytes(OBSERVED_COOKIE);
            }
            out.write(raw, pairEnd, next - pairEnd); // attributes and the CRLF
            i = next;
        }
        return out.toByteArray();
    }

    // ---- bytes ----------------------------------------------------------

    /** Index just past this line's terminator, or raw.length. */
    private static int lineStartAfter(byte[] raw, int from) {
        for (int i = from; i < raw.length; i++) if (raw[i] == '\n') return i + 1;
        return raw.length;
    }

    /** Index of the line's last content byte + 1: the terminator stripped,
     *  whether it is CRLF or a bare LF, and neither is rewritten as the other. */
    private static int contentEnd(byte[] raw, int from, int next) {
        int e = next;
        if (e > from && raw[e - 1] == '\n') e--;
        if (e > from && raw[e - 1] == '\r') e--;
        return e;
    }

    /**
     * Does this line start a status line? RFC 9112 2.3 defines the HTTP-name
     * case-sensitively as %s"HTTP", so this match is deliberately not folded.
     *
     * The cost of answering NO to a real status line is that it is matched as
     * a field, finds no colon before a name that matches, and is copied
     * verbatim -- the same bytes out. The cost of answering YES to a field is
     * that field skipping the Set-Cookie match entirely.
     */
    private static boolean startsWithHttpName(byte[] raw, int from, int to) {
        if (to - from < HTTP_NAME.length) return false;
        for (int k = 0; k < HTTP_NAME.length; k++)
            if (raw[from + k] != HTTP_NAME[k]) return false;
        return true;
    }

    /**
     * Does this status line carry a 1xx code -- an interim response?
     *
     * Exactly three digits after the first space, per RFC 9112 4: "HTTP/1.1
     * 1000 x" is not a 1xx and neither is "HTTP/1.1 1". Being strict here is
     * the cautious direction in the one way that matters: a final response
     * wrongly read as interim would have its BODY scanned as a head, which
     * rewrites evidence, while an interim head wrongly read as final loses the
     * whole real response to the store raw.
     */
    private static boolean isInterim(byte[] raw, int from, int to) {
        int sp = indexOf(raw, from, to, (byte) ' ');
        if (sp < 0) return false;
        int c = sp + 1;
        if (c + 3 > to || raw[c] != '1') return false;
        for (int k = c; k < c + 3; k++)
            if (raw[k] < '0' || raw[k] > '9') return false;
        return c + 3 == to || raw[c + 3] == ' ' || raw[c + 3] == '\t';
    }

    private static int indexOf(byte[] raw, int from, int to, byte b) {
        for (int i = from; i < to; i++) if (raw[i] == b) return i;
        return -1;
    }

    /**
     * ASCII case folding, deliberately hand-rolled.
     *
     * Not {@code toLowerCase()}: that folds per the DEFAULT locale, and in
     * tr_TR 'I' folds to 'ı' (U+0131), so "AUTHORIZATION" stops matching
     * "authorization" -- a credential header missed because of the operator's
     * locale. Burp runs in that locale, and RedactorTest pins the case.
     *
     * Not {@code equalsIgnoreCase} either -- and that half is a preference
     * rather than a guarded behaviour, which is worth saying plainly, because
     * a reader takes a comment as a premise. What is demonstrable is the
     * difference: {@code "COOKIE"} spelled with U+212A KELVIN SIGN
     * {@code equalsIgnoreCase} {@code "cookie"} -- measured true on JDK 26 --
     * and does not match here. What is NOT demonstrable from this suite is
     * that the difference matters, because nothing in it distinguishes the two
     * matchers: RFC 9110 field names are ASCII, so on every name either is ever
     * asked about they agree, and swapping this for equalsIgnoreCase leaves
     * every check green. The tr_TR case above is the one that IS pinned, and
     * it is red under toLowerCase(). Read this paragraph as the reason to
     * prefer a matcher that answers only about bytes the wire can carry, not
     * as a claim that a test is watching.
     */
    private static boolean asciiEqualsIgnoreCase(String lower, String actual) {
        if (actual == null) return false;
        // Whitespace around the name comes off first. unmanagedCredential is a
        // FAIL-CLOSED gate, so "Authorization " failing to match is not a
        // missed match: it is the answer "no credential", on which the Sender
        // issues the request and persists it. Widening the match can only
        // produce extra refusals, which is the safe direction, and it is why
        // this trims rather than refusing the odd name outright.
        int from = 0, to = actual.length();
        while (from < to && isOws(actual.charAt(from))) from++;
        while (to > from && isOws(actual.charAt(to - 1))) to--;
        if (to - from != lower.length()) return false;
        for (int i = 0; i < lower.length(); i++)
            if (asciiLower(actual.charAt(from + i)) != lower.charAt(i)) return false;
        return true;
    }

    /** Space, tab, CR and LF: what can still be wrapped around a field name
     *  that reached us through a parser which did not reject it. ASCII only,
     *  and only these four, for the same reason asciiLower is hand-rolled. */
    private static boolean isOws(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    private static boolean asciiEqualsIgnoreCase(String lower, byte[] raw, int from, int to) {
        if (to - from != lower.length()) return false;
        for (int i = 0; i < lower.length(); i++)
            if (asciiLower((char) (raw[from + i] & 0xff)) != lower.charAt(i)) return false;
        return true;
    }

    private static char asciiLower(char c) {
        return (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
    }
}
