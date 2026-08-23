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

    private record Range(String identityId, int start, int end) { }

    /**
     * The byte ranges this extension injected into ONE serialised request.
     *
     * The ranges live here, next to the bytes they were measured from, rather
     * than on the Redactor -- and that is the whole of the design. A range is
     * a byte offset into ONE request; applied to another it does not merely
     * leak, it substitutes a placeholder over whatever happens to sit at those
     * offsets in the other request's body. Making the caller pass this object
     * to {@link Redactor#redactRequest} MAKES THE COMPILER CARRY THE CONTRACT:
     * a caller physically cannot redact without naming the ranges for those
     * bytes, and a range set cannot precede or outlive the array it was
     * measured from. There is nothing to clear, because nothing survives the
     * request.
     *
     * Every registry kept on the instance -- a plain field or a ThreadLocal --
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
     * read loop may build it and a worker redact with it. It costs nothing
     * uncontended and it removes any need to reason about safe publication.
     */
    public static final class Injected {

        private final List<Range> ranges = new ArrayList<>();

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
     * {@code injected} must be the ranges measured from THESE bytes. It is a
     * parameter rather than state on this object so that there is no other
     * kind of call to make: no registry to desync, none to forget to clear.
     */
    public byte[] redactRequest(byte[] raw, Injected injected) {
        if (injected == null)
            throw new RangeError("redactRequest needs the ranges injected into these bytes");
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
     */
    public byte[] redactResponse(byte[] raw) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length);
        int i = 0;
        boolean first = true;
        boolean inSetCookie = false;
        while (i < raw.length) {
            int next = lineStartAfter(raw, i);      // start of the following line
            int content = contentEnd(raw, i, next); // this line without its CR/LF

            if (content == i) {                     // the blank line: head is over
                out.write(raw, i, raw.length - i);
                return out.toByteArray();
            }
            if (first) {                            // the status line is not a field
                first = false;
                inSetCookie = false;
                out.write(raw, i, next - i);
                i = next;
                continue;
            }
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
            inSetCookie = colon > i && asciiEqualsIgnoreCase("set-cookie", raw, i, colon);
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
     * Not {@code equalsIgnoreCase} either, though that one IS locale-
     * independent and would pass every test here: it folds the whole of
     * Unicode, so "COOKIE" spelled with U+212A KELVIN SIGN equals "cookie"
     * -- measured true on JDK 26. Inventing matches errs safe, but RFC 9110
     * field names are ASCII, and a matcher that answers about bytes the wire
     * cannot carry is one nobody can reason about.
     */
    private static boolean asciiEqualsIgnoreCase(String lower, String actual) {
        if (actual == null || actual.length() != lower.length()) return false;
        for (int i = 0; i < lower.length(); i++)
            if (asciiLower(actual.charAt(i)) != lower.charAt(i)) return false;
        return true;
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
