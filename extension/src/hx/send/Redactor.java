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
 * FOUR jobs, and they are four because a credential reaches disk by four
 * different routes (§7). WHICH JOB COVERS WHICH PATH is the thing to read
 * first, because getting that wrong is how a path ends up with no mechanism at
 * all -- which is exactly what happened to the proxy path's request half
 * between Task 7 and its first fix round, and it stored the operator's live
 * session cookies verbatim in a content-addressed store:
 *
 *   SEND path, request   -- jobs 1 and 2, which cover each other. A credential
 *                           this extension injected has a known byte range
 *                           (job 1); one the harness supplied is REFUSED
 *                           before issuance (job 2), so it never reaches the
 *                           store at all.
 *   SEND path, response  -- job 3.
 *   PROXY path, request  -- job 4, and ONLY job 4. Job 1 has nothing
 *                           registered, because this extension composed
 *                           nothing; job 2 cannot apply, because §4
 *                           deliberately does not rule-check the operator's
 *                           own browsing and refusing it is not on the table.
 *   PROXY path, response -- job 3, the same call the send path makes.
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
 *  4. What we merely WATCHED GO PAST. {@link #redactObservedRequest} is job 3
 *     pointed at a request instead of a response: the operator's browser sends
 *     its own {@code Cookie} and {@code Authorization} headers through the
 *     proxy, this extension composed none of them, and it may not refuse them
 *     either. Header-name matching is again all there is, so the three
 *     {@link #CREDENTIAL_HEADERS} values are replaced with
 *     {@code {{observed:<name>}}} and the names are kept.
 *
 *     THE PLACEHOLDER IS FIXED, and that is a second requirement rather than a
 *     stylistic choice. The plan's Global Constraints require redaction to be
 *     DETERMINISTIC -- "two requests differing only in credential bytes must
 *     produce the same blob" -- and the blob store is content-addressed, so a
 *     hash or a length here would give one page browsed under two sessions two
 *     different digests and two stored copies. Before job 4 existed the proxy
 *     path violated that constraint as well as leaking, because the raw
 *     credential bytes WERE the difference between the two blobs.
 *
 *  5. WHAT THE TARGET CARRIES. A credential does not have to be in a header.
 *     {@code GET http://user:pass@app.test/ HTTP/1.1} puts one in the request
 *     LINE, which jobs 1-4 do not touch: job 1 has no range, job 2 looks only
 *     at header names, and jobs 3 and 4 match a field name before a colon.
 *     Measured surviving verbatim into a content-addressed blob store, which
 *     is the one place S7 says a credential can never be taken back out of.
 *
 *     ONLY THE USERINFO, and only because RFC 3986 3.2.1 says exactly where
 *     it lives: {@code authority = [ userinfo "@" ] host [ ":" port ]}, and
 *     {@code @} is a gen-delim that no host and no port may contain. So an
 *     {@code @} inside an authority IS the userinfo delimiter -- a structural
 *     fact, not a guess about what a string looks like. The userinfo is
 *     replaced whole with {@link #OBSERVED_USERINFO} and the {@code @} kept,
 *     by {@link #redactTarget}.
 *
 *     AND THE VALUES OF WELL-KNOWN CREDENTIAL PARAMETERS. A token does not
 *     have to be in the authority either: {@code /cb?access_token=...} is
 *     the commonest shape of all. {@link #CREDENTIAL_PARAMS} is matched by
 *     NAME, whole and case-insensitively, exactly as the header names are;
 *     the name and the {@code =} are kept and only the value becomes
 *     {@link #OBSERVED_PARAM}. Names and not SHAPES: a rule that redacted
 *     what looks opaque would rewrite {@code ?id=1001} and corrupt the
 *     evidence an access-control check reads, and redacting every value is
 *     the same corruption with no judgement in it.
 *
 *     THAT LIST IS INCOMPLETE BY CONSTRUCTION -- it catches well-known names
 *     and NOT a client's own name for a token -- and
 *     {@link #redactObservedRequest}'s "WHAT THIS EXCLUDES" says so in the
 *     detail it deserves, with the test that pins the limit.
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

    /**
     * True when {@code name} is one of those three, so that
     * {@link IdentityRegistry#register} can refuse to hold an identity that
     * would inject anything else without keeping a second copy of the list.
     *
     * IT DOES NOT TRIM, and that is the one way it deliberately differs from
     * {@link #asciiEqualsIgnoreCase(String, String)} beside it. That matcher
     * trims OWS because it is a FAIL-CLOSED gate on a name the harness sent:
     * widening it can only produce extra refusals. This one is the opposite
     * direction -- it decides what may be WRITTEN -- so a trim would be
     * fail-OPEN: `"Cookie "` would match, and `withHeaderFirst` would then
     * emit `Cookie : v`, a field name with a space before its colon that
     * RFC 9112 §5.1 requires a server to reject and that parsers disagree
     * about, which is the shape a smuggling pair is built from.
     *
     * Case-insensitive because RFC 9110 §5.1 field names are, and matched on
     * ASCII alone for {@link #asciiLower}'s locale reason. The
     * `equalsIgnoreCase` half of that reasoning -- which the matcher below
     * calls a preference, because nothing there rests on it -- does carry
     * weight here: "COOKIE" spelled with a U+212A KELVIN SIGN is
     * `equalsIgnoreCase` "cookie", and the answer this method gives is an
     * ACCEPTANCE. Registration refuses that spelling before it can reach this
     * method, because U+212A is outside Latin-1 and
     * `IdentityRegistry.checkWritable` runs first -- so today the ordering is
     * what makes it moot, and a matcher that is right on its own does not
     * depend on the ordering staying that way.
     */
    static boolean isCredentialHeader(String name) {
        if (name == null) return false;
        for (String wanted : CREDENTIAL_HEADERS) {
            if (name.length() != wanted.length()) continue;
            boolean same = true;
            for (int i = 0; i < wanted.length(); i++)
                if (asciiLower(name.charAt(i)) != wanted.charAt(i)) { same = false; break; }
            if (same) return true;
        }
        return false;
    }

    private static final byte[] OBSERVED_COOKIE =
        "{{observed:set-cookie}}".getBytes(StandardCharsets.US_ASCII);

    /**
     * Job 4's placeholders, one per {@link #CREDENTIAL_HEADERS} entry and in
     * the same order.
     *
     * DERIVED from that array rather than written out beside it. A fourth
     * credential header added there gets a placeholder here for free; a second
     * hand-kept list would be a vocabulary in two places, and the drift that
     * matters is silent -- a name matched with no placeholder to write is an
     * {@code ArrayIndexOutOfBoundsException} on a Burp proxy thread, and a
     * placeholder with no name is dead bytes nobody notices.
     */
    private static final byte[][] OBSERVED_CREDENTIAL = observedPlaceholders();

    private static byte[][] observedPlaceholders() {
        byte[][] out = new byte[CREDENTIAL_HEADERS.length][];
        for (int i = 0; i < out.length; i++)
            out[i] = ("{{observed:" + CREDENTIAL_HEADERS[i] + "}}")
                     .getBytes(StandardCharsets.US_ASCII);
        return out;
    }

    /**
     * Job 5's placeholder, replacing a request target's userinfo whole.
     *
     * FIXED, for job 4's reason exactly: the blob store is content-addressed,
     * so two browses of one page under two basic-auth users must hash to one
     * blob. What that costs is stated rather than hidden -- WHICH user is
     * lost, because it is a fixed string and not `{{observed:userinfo:<user>}}`.
     * The username half of a userinfo is not reliably a name: RFC 3986 3.2.1
     * deprecates the `user:password` form and says nothing requires a colon at
     * all, and `https://ghp_livetoken@host/` is the commonest real shape --
     * keeping "the part before the colon" would store that token verbatim.
     * So the whole subcomponent goes, and the identity of the user is a thing
     * this placeholder does not carry.
     *
     * NOT DERIVED from {@link #CREDENTIAL_HEADERS} like {@link #OBSERVED_CREDENTIAL}
     * is: this one names a URI subcomponent, not a header, so there is no
     * entry there it could be paired with.
     */
    private static final byte[] OBSERVED_USERINFO =
        "{{observed:userinfo}}".getBytes(StandardCharsets.US_ASCII);

    /**
     * Query-parameter names whose VALUE is a credential, lower-cased for the
     * ASCII match, in no significant order.
     *
     * A FIXED LIST OF NAMES, AND THAT IS THE WHOLE DESIGN. The two rejected
     * alternatives are worth keeping written down, because both look like
     * improvements:
     *
     *   BY SHAPE -- "a long opaque-looking value is a secret" -- rewrites
     *   {@code ?id=1001} and {@code ?order=8f3c...} and corrupts the exact
     *   evidence an access-control check reads. A redaction that eats the
     *   identifier makes the finding it was protecting unprovable.
     *
     *   EVERY VALUE -- redact the lot -- is the same corruption with no
     *   judgement in it at all.
     *
     * So it is names, matched whole and case-insensitively, exactly the way
     * {@link #CREDENTIAL_HEADERS} is matched. It is INCOMPLETE BY
     * CONSTRUCTION and says so in {@link #redactObservedRequest}'s exclusion
     * list: a client's own spelling for a token is not here and cannot be.
     * Incomplete is not the same as worthless -- catching {@code access_token}
     * today is strictly better than a known leak -- but the two are told apart
     * only by saying plainly which one this is.
     *
     * WHAT THE LIST COSTS, said once here rather than left to be discovered:
     * a few of these names are genuinely ambiguous. {@code key} is a Google
     * API key and also a sort key; {@code sid} is a session id and also a
     * store id; {@code auth} and {@code sig} are used for both. Those
     * parameters lose their values in the evidence. That is the trade the
     * ambiguity forces, and it runs the safe way: a redacted non-secret is a
     * gap in a report, a stored secret is in every backup.
     *
     * WHAT IS DELIBERATELY ABSENT, with the reason, because an omission
     * nobody wrote down reads as an oversight:
     *
     *   {@code code}   -- an OAuth authorization code IS a credential, and
     *                     {@code ?code=} is also a country code, an error
     *                     code, a discount code and a status code. The
     *                     false-positive rate is the highest on the list by
     *                     an order of magnitude and it would blank values
     *                     that are the whole point of the request.
     *   {@code state}  -- OAuth {@code state} is a CSRF token, not an
     *                     authenticator: possessing it grants nothing, and a
     *                     CSRF check needs to read it.
     *   {@code nonce}, {@code csrf}, {@code _token} -- same argument as
     *                     {@code state}.
     *
     * THE OPERATOR-DECLARED EXTENSION IS THE NEXT STEP AND IT IS NOT A FIX
     * TO THIS FILE. A per-engagement list -- the client naming
     * {@code acme_session} themselves -- is reviewable, belongs to the
     * engagement rather than to this repository's guesswork, and fails in the
     * direction of the operator knowing what was redacted. It needs a config
     * schema change AND a `configure` wire key to carry it, and an
     * unrecognised `configure` key is a hard {@code bad_config} today (see
     * ConfigBody and S4's note on limit re-arming) -- so there is no wire for
     * it either. Both halves have to land together or an operator's list is
     * silently ignored, which is the failure mode S4 spends a paragraph on.
     */
    private static final String[] CREDENTIAL_PARAMS = {
        "access_token", "refresh_token", "id_token", "auth_token", "token",
        "jwt",
        "api_key", "apikey", "api-key", "key",
        "secret", "client_secret",
        "password", "passwd", "pwd",
        "auth", "authorization",
        "sig", "signature",
        "session", "sessionid", "sid",
        // AWS SigV4 query authentication. A presigned S3 URL carries a live
        // credential in exactly these three parameters, it is a shape any web
        // application test runs into, and none of the generic names above
        // matches them -- the match is on the WHOLE name.
        "x-amz-signature", "x-amz-credential", "x-amz-security-token",
    };

    /**
     * Job 5's placeholder for a credential parameter's VALUE. The name and the
     * {@code =} are kept.
     *
     * ONE FIXED STRING, not {@code {{observed:<name>}}}, for two reasons.
     * Determinism is the first: two requests differing only in the credential
     * must hash to one blob, and while the NAME is not the secret, a
     * per-name placeholder buys nothing -- the name is still right there in
     * front of the {@code =}. The second is that the key set is what
     * {@code surface.query_key_set} reads, and it reads the KEY; the
     * placeholder never enters that computation at all.
     */
    private static final byte[] OBSERVED_PARAM =
        "{{observed:param}}".getBytes(StandardCharsets.US_ASCII);

    /** RFC 9112 2.3: the HTTP-name is case-SENSITIVE, so this is a byte match. */
    private static final byte[] HTTP_NAME = "HTTP/".getBytes(StandardCharsets.US_ASCII);

    private record Range(String identityId, int start, int end) { }

    /**
     * One half-open span of a head line to replace, and what to put there.
     *
     * Job 5 makes up to two independent decisions about one line -- the
     * userinfo and each credential parameter's value -- and they are collected
     * rather than applied in sequence because they can NEST. Emitting as they
     * are found writes the same bytes twice for
     * `?access_token=http://u:p@h/`.
     */
    private record Cut(int start, int end, byte[] with) { }

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
     * The bytes of a request hx merely OBSERVED, with every credential header
     * VALUE replaced. The argument is not modified.
     *
     * JOB 4. See the class javadoc for which job covers which path; the short
     * version is that this is the ONLY mechanism standing between an
     * operator's live session cookie and a content-addressed blob store, and
     * {@link #redactRequest} is not a substitute for it. Handed an empty
     * {@link Injected} -- which is what the proxy path has, because it
     * composed nothing -- {@code redactRequest} returns {@code raw.clone()},
     * i.e. the credential verbatim. That was the shipped state of the proxy
     * path for one commit and it is the reason this method exists.
     *
     * NAME KEPT, VALUE REPLACED, exactly as job 3 does it: the evidence still
     * shows that a credential WAS sent and which kind, which is what an
     * auth-boundary check reads, while the bytes that would still authenticate
     * are gone. The placeholder is FIXED -- see {@link #OBSERVED_CREDENTIAL}
     * -- so two browses of one page under two sessions produce one blob.
     *
     * ONLY THE HEAD IS SCANNED, for job 3's reason exactly: a body may
     * legitimately carry the text {@code Cookie: sid=...} -- a documentation
     * page, an API error dump, a captured request pasted into a form -- and
     * rewriting it would corrupt the evidence a check reads. The head ends at
     * the first empty line.
     *
     * "EVERY HEAD LINE IS MATCHED AS A FIELD" IS TRUE OF LF-TERMINATED LINES
     * AND OF NOTHING ELSE. {@link #lineStartAfter} scans for {@code \n}, so a
     * message using BARE CR as its terminator is one line to this scan, has no
     * name before its first colon that matches, and is copied through
     * verbatim. That is a passthrough of a credential, and it is left as one
     * deliberately: RFC 9112 2.2 requires CRLF and permits a bare LF, and
     * nothing permits a bare CR -- a server would not parse such a message as
     * HTTP either, so nothing on the wire reaches this shape. It is named here
     * because the sentence above would otherwise be a claim wider than the
     * code, not because a bare-CR parser is wanted. The other four verbatim
     * passthroughs a review found are the same kind and are named where they
     * arise: a NUL inside a field name, a fold following a NON-credential
     * header (per RFC that text is the other header's value), a field name
     * split across a fold, and a pipelined second request.
     *
     * NO REQUEST LINE IS RECOGNISED AS A LINE, and that is deliberate rather
     * than an omission -- job 5 below privileges no line either, it only
     * rewrites a URI's userinfo wherever one appears in the FIRST head line.
     * {@link #redactResponse} has to know its status line, because
     * taking the first non-empty line for one whatever it says would let a
     * head whose first field is Set-Cookie have that cookie consumed as the
     * status line and copied through raw. Here no line is privileged: every
     * head line is matched as a field, and a request line survives that match
     * because the name before its first colon always begins with the method
     * token and a space -- {@code GET /x HTTP/1.1} has no colon at all, and
     * {@code GET http://h:8080/x HTTP/1.1} gives the name {@code GET http},
     * neither of which is one of the three. That holds for a SYNTACTICALLY
     * VALID request line and is not claimed beyond one: ':' is not a tchar, so
     * no method token can carry one, and the trim below takes whitespace off
     * the ENDS only. A malformed first line that genuinely reads
     * {@code Cookie: x} is redacted, which is the safe direction and the same
     * answer this method gives that line anywhere else in the head.
     *
     * THE FIRST HEAD LINE ALSO GOES THROUGH {@link #redactTarget}, which is
     * job 5. It rewrites the userinfo of a URI appearing in that line and
     * NOTHING else -- no name is matched, no line is consumed as anything, and
     * a line with no {@code ://} in it is written through byte for byte. It
     * runs on the first head line whatever that line turns out to be, so a
     * malformed message whose first line is a credential FIELD is redacted as
     * a field (above) and never reaches job 5; the flag is set for it all the
     * same, because the line after the first is not a request line either.
     *
     * WHAT THIS EXCLUDES, named rather than left to be discovered:
     *
     *   - A CREDENTIAL IN A QUERY PARAMETER THIS LIST DOES NOT NAME.
     *     THIS CATCHES A FIXED LIST OF WELL-KNOWN NAMES AND DOES NOT CATCH A
     *     CLIENT'S OWN NAME FOR A TOKEN. {@code ?access_token=} is redacted;
     *     {@code ?acme_session=} is not, and neither is any other spelling an
     *     application invented for itself. {@link #CREDENTIAL_PARAMS} is the
     *     whole of what is matched, and the space of names an application may
     *     choose is unbounded, so no list closes it. Incomplete is not
     *     worthless -- catching {@code access_token} is strictly better than
     *     a known leak -- but the two are told apart only by saying which
     *     this is, and {@code aClientsOwnNameForATokenIsNotCaught} pins it
     *     with a made-up parameter name so the limit is a MEASURED FACT
     *     rather than a caveat someone can quietly widen.
     *
     *     THE ROUTE OUT is an operator-declared list in the engagement
     *     config -- reviewable, owned by the engagement rather than by this
     *     repository's guesswork, and failing in the direction of the
     *     operator knowing what was redacted. It is NOT a change to this
     *     file: it needs a config schema change AND a `configure` wire key to
     *     carry it, and an unrecognised `configure` key is a hard
     *     {@code bad_config} today, so there is no wire for it either. Both
     *     halves have to land together or an operator's list is silently
     *     ignored -- the failure mode S4 spends a paragraph on for limits.
     *
     *     Three smaller edges of the same mechanism: a name that is
     *     PERCENT-ENCODED ({@code %61ccess_token}) is not matched, because
     *     decoding would mean deciding what a name that decodes two ways IS;
     *     a pair separated by {@code ;} rather than {@code &} is one pair to
     *     this scan; and a credential inside another parameter's value
     *     ({@code ?next=/a%3Ftoken%3Dx}) is inside one opaque value and is
     *     not reached.
     *   - A CREDENTIAL IN THE BODY. A login POST's password is in the body
     *     and stays there, verbatim. S7 keeps payload and request structure
     *     verbatim on purpose -- "evidence remains defensible" -- and nothing
     *     here distinguishes a form field from a form field.
     *   - USERINFO IN A HEADER VALUE: {@code Referer: http://u:p@host/},
     *     {@code Origin}, a URI inside a custom header. Job 5 runs on the
     *     first head line only. Running it over every field value would
     *     rewrite arbitrary text that merely contains {@code ://} and an
     *     {@code @}, which is the shape rule this class refuses everywhere
     *     else.
     *   - a credential in a header this list does not name: {@code X-Api-Key},
     *     {@code X-Auth-Token}, a bearer token in a custom header. §6 names
     *     three and {@link #CREDENTIAL_HEADERS} is those three. A fourth name
     *     added there is covered here automatically, which is why the
     *     placeholders are derived from it;
     *   - a 1xx-style interim head. There is no such thing in a request, so
     *     unlike {@link #redactResponse} this scan does not look for one --
     *     and if a pipelined SECOND request followed the first in one array,
     *     its head would be treated as body and go through raw. This class is
     *     handed one message at a time by contract (Montoya's
     *     {@code initiatingRequest().toByteArray()}), and that contract is
     *     UNMEASURED here, like everything else this file's proxy caller
     *     assumes about Burp -- see HxExtension's assumption block.
     *
     * A null {@code raw} is a {@link RangeError}, the same as the other two
     * entry points, and for the same reason: an NPE out of here reaches a Burp
     * proxy thread and the send path's catch-all alike.
     */
    public byte[] redactObservedRequest(byte[] raw) {
        if (raw == null)
            throw new RangeError("redactObservedRequest needs the request bytes");
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length);
        int i = 0;
        boolean first = true;        // no line of the head has been read yet
        // Whether the first line of the head has been WRITTEN. `first` cannot
        // do this job: it is cleared for the fold and credential branches too,
        // and it is read before those decide anything, so the one line job 5
        // may touch has to be tracked on its own.
        boolean targetDone = false;
        int credential = -1;         // index into CREDENTIAL_HEADERS, or -1
        while (i < raw.length) {
            int next = lineStartAfter(raw, i);      // start of the following line
            int content = contentEnd(raw, i, next); // this line without its CR/LF

            if (content == i) {                     // an empty line
                if (first) {
                    // RFC 9112 2.2: a recipient MAY ignore an empty line
                    // before the request line, so one can reach us. Stopping
                    // here would end the head before a single field was read
                    // and copy the WHOLE request through as "body", every
                    // credential raw. Keep it verbatim and keep looking.
                    out.write(raw, i, next - i);
                    i = next;
                    continue;
                }
                out.write(raw, i, raw.length - i);  // the head really is over
                return out.toByteArray();
            }
            first = false;
            // Taken and cleared HERE, above every branch, so that exactly one
            // line of the head can be job 5's however that line is handled --
            // a fold, a credential field or a request line all consume it.
            boolean isFirstLine = !targetDone;
            targetDone = true;
            if (raw[i] == ' ' || raw[i] == '\t') {
                // obs-fold. RFC 9110 says a recipient must reject it and no
                // real client emits it, but if one does, the folded remainder
                // of a credential is credential bytes -- so the whole
                // continuation goes. Same trade as job 3's fold branch.
                if (credential >= 0) {
                    int ws = i;
                    while (ws < content && (raw[ws] == ' ' || raw[ws] == '\t')) ws++;
                    out.write(raw, i, ws - i);
                    out.writeBytes(OBSERVED_CREDENTIAL[credential]);
                    out.write(raw, content, next - content);
                } else {
                    out.write(raw, i, next - i);
                }
                i = next;
                continue;
            }
            int colon = indexOf(raw, i, content, (byte) ':');
            // Whitespace off the NAME before matching, through the same
            // predicate job 3 uses, so the two cannot drift: a name this side
            // lets through is a live credential stored verbatim.
            int nameEnd = colon;
            while (nameEnd > i && isOws((char) (raw[nameEnd - 1] & 0xff))) nameEnd--;
            credential = -1;
            if (colon > i)
                for (int k = 0; k < CREDENTIAL_HEADERS.length; k++)
                    if (asciiEqualsIgnoreCase(CREDENTIAL_HEADERS[k], raw, i, nameEnd)) {
                        credential = k;
                        break;
                    }
            if (credential < 0) {
                // JOB 5, and only on the first line of the head. Everything
                // else is written through byte for byte, exactly as before.
                if (isFirstLine) redactTarget(raw, i, next, out);
                else out.write(raw, i, next - i);
                i = next;
                continue;
            }
            out.write(raw, i, colon + 1 - i);             // the name and colon
            int v = colon + 1;
            while (v < content && (raw[v] == ' ' || raw[v] == '\t')) v++;
            out.write(raw, colon + 1, v - (colon + 1));   // the OWS, verbatim
            // THE WHOLE VALUE, not a parsed part of it. Job 3 keeps a cookie's
            // NAME because `sid=` is what a session-fixation check reads and
            // it is not a secret. Here the whole value is the secret --
            // `Bearer eyJ...`, `sid=...; other=...` -- and a cookie NAME sent
            // by the browser tells a check nothing the response's Set-Cookie
            // did not already say.
            out.writeBytes(OBSERVED_CREDENTIAL[credential]);
            out.write(raw, content, next - content);      // the CRLF
            i = next;
        }
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

    /**
     * JOB 5. Write {@code raw[from, to)} through, with the userinfo of a URI
     * appearing in it replaced by {@link #OBSERVED_USERINFO}.
     *
     * STRUCTURAL, not a guess, and this is the whole argument for it being
     * here at all when a parameter-name list is not:
     *
     *   RFC 3986 3.2:   authority is what follows {@code "//"} and runs to the
     *                   next {@code / ? #} or the end of the URI.
     *   RFC 3986 3.2.1: {@code authority = [ userinfo "@" ] host [ ":" port ]}.
     *   RFC 3986 2.2:   {@code @} is a gen-delim. Neither {@code host}
     *                   (reg-name / IP-literal / IPv4address) nor {@code port}
     *                   (DIGIT) admits one.
     *
     * So an {@code @} inside an authority can only be the userinfo delimiter.
     * There is no shape being recognised and no name being matched: the
     * question "is there a credential here" is not asked, because RFC 3986
     * already answers "this subcomponent is where one goes".
     *
     * THE LAST {@code @} IN THE AUTHORITY, not the first. {@code @} is not
     * legal INSIDE a userinfo either (it is pct-encoded as {@code %40}), so a
     * conforming authority has exactly one and the two rules agree. They part
     * only on a malformed authority carrying two, where the last is what
     * {@code urlsplit} and the WHATWG URL parser both take as the delimiter --
     * and taking the FIRST there would leave the bytes between the two
     * verbatim. The Python side is the same rule for the same reason; see
     * tests/vectors/userinfo.txt, which is the one place the two are compared.
     *
     * THE {@code @} IS KEPT. `{{observed:userinfo}}@host` still reads as an
     * authority, so a reader can see that a credential was carried there --
     * which is the same trade job 3 makes when it keeps a cookie's name.
     *
     * THE FIRST {@code ://} IN THE LINE, and no attempt to find a second. A
     * request line has one target; the target may itself carry an absolute URI
     * in a query (`/redirect?to=http://u:p@evil/`) and that is the one this
     * finds, which is correct -- it is a credential in the target either way.
     * A line with a userinfo in a SECOND URI and none in the first is not
     * covered, and no request line has that shape.
     *
     * Nothing is written when there is no {@code ://} and no {@code @}: the
     * line goes through byte for byte, so a message with no userinfo in it is
     * unchanged by this method and hashes as it did before job 5 existed.
     */
    private static void redactTarget(byte[] raw, int from, int to,
                                     ByteArrayOutputStream out) {
        List<Cut> cuts = new ArrayList<>();
        addUserinfoCut(raw, from, to, cuts);
        addCredentialParamCuts(raw, from, to, cuts);
        if (cuts.isEmpty()) {
            // The overwhelmingly common line, and it must come through byte
            // for byte: a request with nothing to redact has to hash exactly
            // as it did before job 5 existed.
            out.write(raw, from, to - from);
            return;
        }
        cuts.sort(Comparator.comparingInt(Cut::start));
        int at = from;
        for (Cut c : cuts) {
            // OVERLAP IS DROPPED, NOT MERGED, and one input really produces
            // it: `?access_token=http://u:p@h/` has a userinfo cut sitting
            // INSIDE a parameter-value cut. Sorted by start, the parameter
            // value comes first and swallows the userinfo, so the inner cut
            // is already gone -- skipping it is correct rather than merely
            // safe. Without the guard the second write() would be handed a
            // negative length and throw on a Burp proxy thread.
            if (c.start() < at) continue;
            out.write(raw, at, c.start() - at);
            out.writeBytes(c.with());
            at = c.end();
        }
        out.write(raw, at, to - at);
    }

    /**
     * The userinfo of the first URI in {@code raw[from, to)}, as a cut.
     *
     * See {@link #redactTarget}'s javadoc for the RFC 3986 argument. The cut
     * ENDS at the {@code @} rather than past it, so the {@code @} survives and
     * the result still reads as an authority.
     */
    private static void addUserinfoCut(byte[] raw, int from, int to,
                                       List<Cut> cuts) {
        int scheme = -1;
        for (int p = from; p + 2 < to; p++)
            if (raw[p] == ':' && raw[p + 1] == '/' && raw[p + 2] == '/') {
                scheme = p;
                break;
            }
        if (scheme < 0) return;
        int authStart = scheme + 3;
        int authEnd = authStart;
        while (authEnd < to) {
            byte b = raw[authEnd];
            // The authority's terminators, plus the ones that end the TARGET
            // inside a request line: SP separates it from the HTTP-version,
            // and CR/LF/HTAB end the line. Without those a line with no path
            // at all -- `GET http://u:p@h HTTP/1.1` -- would run the
            // authority on into ` HTTP/1.1` and find no `@` after it either
            // way, but a SECOND `@` anywhere later in the line would then be
            // taken for the delimiter and blank out the version too.
            if (b == '/' || b == '?' || b == '#' || b == ' ' || b == '\t'
                    || b == '\r' || b == '\n') break;
            authEnd++;
        }
        int at = -1;
        for (int p = authStart; p < authEnd; p++) if (raw[p] == '@') at = p;
        if (at < 0) return;
        cuts.add(new Cut(authStart, at, OBSERVED_USERINFO));
    }

    /**
     * The VALUES of {@link #CREDENTIAL_PARAMS} in the target's query, as cuts.
     *
     * WHERE THE QUERY IS, structurally: RFC 3986 3.4 says the query begins at
     * the FIRST {@code ?} and runs to the next {@code #} or the end of the
     * URI. {@code ?} is a gen-delim and is not a {@code pchar}, so it cannot
     * appear unencoded in a path -- the first one really is the delimiter --
     * and inside a request LINE the target also ends at the SP before the
     * HTTP-version, so SP/HTAB/CR/LF end the scan too.
     *
     * PAIRS ARE SPLIT ON {@code &} AND NAME FROM VALUE ON THE FIRST
     * {@code =}. `&` is the form-urlencoded separator every client emits;
     * `;` was an old alternative, is not accepted here, and is named in
     * {@link #redactObservedRequest}'s exclusions rather than guessed at --
     * treating it as a separator would split values that legitimately contain
     * one.
     *
     * A PAIR WITH NO {@code =} IS LEFT ALONE. `?access_token` on its own
     * carries no value to redact, and a placeholder there would invent one.
     * An EMPTY value -- `?access_token=&next=/` -- is left alone for the same
     * reason job 3 leaves a deletion cookie's empty value: an empty value
     * cannot be a credential, and writing a placeholder over it would read as
     * an issuance.
     *
     * THE NAME IS MATCHED RAW, NOT PERCENT-DECODED. `%61ccess_token` is not
     * matched, and that is a real bypass rather than an oversight worth
     * hiding: decoding here would mean deciding what a name that decodes two
     * different ways IS, and this class's whole discipline is that it does
     * not guess. It is named in the exclusion list with everything else this
     * does not catch.
     */
    private static void addCredentialParamCuts(byte[] raw, int from, int to,
                                               List<Cut> cuts) {
        int q = indexOf(raw, from, to, (byte) '?');
        if (q < 0) return;
        int qEnd = q + 1;
        while (qEnd < to) {
            byte b = raw[qEnd];
            if (b == '#' || b == ' ' || b == '\t' || b == '\r' || b == '\n')
                break;
            qEnd++;
        }
        int p = q + 1;
        while (p < qEnd) {
            int amp = p;
            while (amp < qEnd && raw[amp] != '&') amp++;
            int eq = p;
            while (eq < amp && raw[eq] != '=') eq++;
            // eq == amp means no '='; eq + 1 == amp means an empty value.
            if (eq + 1 < amp && isCredentialParam(raw, p, eq))
                cuts.add(new Cut(eq + 1, amp, OBSERVED_PARAM));
            p = amp + 1;
        }
    }

    /** Whether {@code raw[from, to)} is one of {@link #CREDENTIAL_PARAMS},
     *  matched WHOLE and case-insensitively through the same predicate the
     *  header names use, so the two cannot drift in how they fold case. */
    private static boolean isCredentialParam(byte[] raw, int from, int to) {
        for (String name : CREDENTIAL_PARAMS)
            if (asciiEqualsIgnoreCase(name, raw, from, to)) return true;
        return false;
    }

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
