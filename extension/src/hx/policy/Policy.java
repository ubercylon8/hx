// extension/src/hx/policy/Policy.java
package hx.policy;

import hx.bridge.BridgeClient;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The decision, as a pure function of a request and one Authorisation
 * snapshot. No sockets, no clock, no filesystem, and nothing from Burp's
 * Montoya API -- PolicyTest scans every source file in this package and fails
 * if one names a Montoya type, because a ruleset that needs Burp running to be
 * exercised is a ruleset that will be exercised by hand, once, and then
 * trusted.
 *
 * THE ORDER IS THE CONTRACT: not_configured -> [halted] -> scope_denied ->
 * method_denied -> dangerous_denied -> rate_limited -> budget_exhausted. When
 * a request violates several rules the earliest wins, because the denial an
 * operator reads is the reason they will act on. "Rate limited" for a request
 * that was never in scope sends them to tune a limit instead of fixing their
 * scope file.
 *
 * `halted` is in brackets because it is not decidable here: a halt is a piece
 * of live state (a halt frame, the sentinel file, or auto-halt on target
 * distress), not a property of the request and the authorisation. Sender
 * checks it, in that position, between not_configured and this method.
 *
 * WHAT THE RULES MATCH AGAINST: the request that goes on the wire is
 * unchanged -- readings() decides, it never rewrites. But "the path" is not
 * one string. It is the bytes we send AND every resource a target server might
 * resolve them to, and those differ by more than encoding:
 *
 *   /account/log%6fut  is a real logout on every server that has shipped
 *   /app/..;/other     is /other on every servlet container, so every Spring app
 *   /app/..\other      is /other on IIS and .NET, which read a backslash
 *                      as a path separator
 *   /admin./users      is /admin/users on Windows, which trims trailing dots
 *   /.../admin/users   is /admin/users on Windows too: `...` is a name, and a
 *                      name of nothing but trailing dots trims to nothing
 *   /x/..%ef%bc%8flogout  is /x/../logout wherever a wide string reaches an
 *                      ANSI API, because U+FF0F best-fits to `/`
 *   /foo%2fbar/../admin/users  is /admin/users in python's urljoin, node's
 *                      new URL() and java's URI.normalize alike: none of them
 *                      decodes %2f before resolving the `..`, so the `..`
 *                      pops one whole segment called `foo%2fbar`
 *   /a%2fb/%2e%2e/admin/users  is /admin/users on anything that decodes AFTER
 *                      it has cut the path into segments -- Apache with
 *                      AllowEncodedSlashes off, nginx, Tomcat -- which reads
 *                      the `%2e%2e` as a `..` while `a%2fb` stays one segment
 *
 * Worse, mainstream libraries disagree about the SAME path with no attacker
 * involved. For `/a//../admin/users`:
 *
 *   python  urljoin()             -> /a/admin/users
 *   node    new URL().pathname    -> /a/admin/users
 *   java    URI.normalize()       -> /admin/users
 *
 * An earlier round of this class picked ONE reading (merge empty segments,
 * then resolve dot segments) and matched against it. Picking one is picking
 * which half of the internet to be wrong about, and it opened a live bypass:
 * with exclude=/a/admin/*, `/a//../admin/users` was ALLOWED, because merging
 * first does not shorten the path, it RELOCATES it -- out from under a glob
 * anchored at the prefix the merge had just deleted.
 *
 * So readings() returns a SET: the raw path plus every normalisation a
 * mainstream server or library plausibly applies, deduplicated. Both kinds of
 * rule read the WHOLE set, each in its fail-closed direction:
 *
 *   - a DENY rule (scope.exclude, dangerous.path) refuses if ANY reading of
 *     the path matches ANY reading of the pattern, case folded. A denylist has
 *     to see every reading of the request, not a favourite one.
 *   - an ALLOW rule (scope.include) authorises only if EVERY reading of the
 *     path is matched by some reading of the pattern.
 *
 * The second half is not decoration, and it is not symmetric with the first.
 * With include=/app/* a request for `/app/%2e%2e/other` matches the include as
 * bytes while the server serves `/other`, which no include names. Requiring
 * every reading to be included is what closes that.
 *
 * Cost of the set model when it is wrong, on the PATH side: a deny rule
 * matches a path some exotic server would route elsewhere, or an include
 * refuses one. Both are denials, which is the direction a tool aimed at
 * production has to err in.
 *
 * That used to be written here as a property of the WHOLE model, and it was
 * false. A reading of a PATTERN widens the rule it belongs to, and a wider
 * scope.include -- the one rule that authorises anything -- is an ALLOW, not
 * a denial. Three characters in an include were enough:
 *
 *   include=/app;v=1/*  authorised  /app/secret
 *   include=/a(backslash)b/*  authorised  /a/b/secret
 *   include=/admin./*   authorised  /admin/users
 *   include=/../*       authorised  the entire host
 *
 * What makes the sentence above true is the split in Rule: an ALLOW pattern is
 * read only along the ENCODING axis -- different SPELLINGS of one resource --
 * while the SEGMENT axis (;params, backslashes, dot resolution, tail
 * trimming), every one of which names a DIFFERENT resource, belongs to deny
 * patterns alone. See Rule.forInclude and spellingReadings.
 *
 * Matching a decoded COPY while sending raw bytes -- the obvious fix -- would
 * reintroduce exactly the decision-versus-wire mismatch the authority checks
 * below exist to prevent. Deciding about the bytes we send is right; it only
 * works if the matcher's idea of "the same path" also covers the target
 * server's, which is what the reading set adds.
 *
 * DENY PATTERNS ARE READ THE SAME WAY, AND ONE WAY MORE. An operator's
 * pattern is a string a human typed and it has the same several readings a
 * path does, so Rule.forExclude builds the same set from it. Matching raw
 * patterns against readings of the path alone fails SILENTLY in both
 * directions:
 * `scope.exclude .../%61dmin/*` is a DEAD RULE that stops nothing while reading
 * as if it named /admin/*, and `scope.include .../files/my%20docs/*` authorises
 * NOTHING -- neither `/files/my%20docs/a.pdf` nor `/files/my docs/a.pdf` --
 * while the operator is told only that their request "matches no scope.include
 * pattern", which sends them to rewrite a pattern that was right.
 *
 * ALLOW PATTERNS GET THE ENCODING HALF OF THAT AND NOTHING ELSE, because the
 * two halves push in opposite directions on a rule that authorises. A
 * different SPELLING of a pattern names the same resource, so an include has
 * to cover all of them or it authorises nothing. A segment transform names a
 * DIFFERENT resource, so an include that gained one would authorise something
 * the operator never wrote. spellingReadings is that half on its own.
 *
 * The one way more is ENCODING, and it exists because readings() never
 * encodes. A pattern naming a directory with a non-ASCII character in it --
 * an accent, a CJK name -- is typed as characters and arrives as
 * percent-escapes, and no decoding of the pattern reaches the escaped spelling
 * the request's raw reading carries. patternReadings() adds it. It is a
 * pattern-only reading, and its comment says why it cannot be a path's.
 *
 * decide() IS TOTAL: every input returns a Decision. A null Authorisation, one
 * carrying a null scope map, a null list under a key, a null element inside a
 * list, a path of nothing but slashes, a 4 KB path of nested escapes -- all
 * answered, none thrown. That is a guarantee this class owes its caller rather
 * than a tidiness: Sender treats a Decision as the whole answer, so anything
 * thrown out of here is an implicit allow the moment a caller mishandles it.
 * The malformed shapes are unreachable from the wire today because
 * ConfigBody.parse builds every list with List.copyOf, which rejects nulls --
 * but that is a property of a DIFFERENT class, and a guarantee stated here has
 * to be enforced here.
 *
 * The Authorisation is a PARAMETER. It is read once per send, by
 * BridgeClient's send arm, and carried down -- epoch and scope from the one
 * reference, so the scope a request was decided under and the epoch stamped on
 * its evidence line are the same commit. configEpoch() and scopeConfig() are
 * two reads of that one record and a commit lands between them: measured wrong
 * in 393/400 trials, in the unsafe direction.
 */
public final class Policy {

    /**
     * Spec s4: "Defaults on a production profile are single-digit req/s and
     * GET/HEAD/OPTIONS only."
     *
     * This applies whenever `method.allow` is ABSENT, whatever profile the
     * configure frame named -- Authorisation carries the config body, and the
     * profile is a header field that never reaches this class. That is
     * deliberate: the body is what was hashed and committed at this epoch, and
     * the strictest profile's allowlist is the only safe reading of "the
     * operator did not say".
     */
    static final List<String> DEFAULT_METHODS = List.of("GET", "HEAD", "OPTIONS");

    // Spec s4: the denylist "ships with sensible defaults (logout, password
    // change, delete, purge) and is separate from scope -- 'in scope' and
    // 'safe to touch automatically' are different questions."
    //
    // Same glob syntax as an operator's own `dangerous.path` lines, matched
    // case-insensitively against the request target -- path AND query, because
    // on a legacy application a logout is `/index.php?action=logout` at least
    // as often as it is `/logout`. Each verb therefore appears twice, once
    // after a `/` and once after a `=`: those are the two separators it can
    // follow, and requiring one is what keeps `/api/blogouts` out of the
    // denylist. The two spellings of sign-out are both here because real
    // applications use both, and password covers change-password,
    // password/change and reset-password without guessing which shape a given
    // app chose.
    //
    // The false-positive direction is accepted deliberately: `?sort=deleted_at`
    // matches and will be refused. A visible dangerous_denied on a listing
    // endpoint costs an operator one config line; an automated logout costs
    // them the session, and possibly the evidence of everything issued under
    // it.
    //
    // These are ADDED to whatever the operator configured, never replaced by
    // it: ConfigBody.KEYS has no key meaning "drop a default", so a
    // `dangerous.path` line can only be read as one more thing to refuse. The
    // cost is real and accepted -- there is no way to authorise hx to issue a
    // logout, and an operator who needs one issues it by hand in Repeater,
    // which is where s1 says manual manipulation belongs.
    //
    // (Line comments, not javadoc: a pattern beginning `*/` ends a block
    // comment.)
    static final List<String> DEFAULT_DANGEROUS = List.of(
            "*/logout*",   "*=logout*",
            "*/signout*",  "*=signout*",
            "*/sign-out*", "*=sign-out*",
            "*/password*", "*=password*",
            "*/delete*",   "*=delete*",
            "*/purge*",    "*=purge*");

    private final Gate gate;

    public Policy(Gate gate) {
        this.gate = gate;
    }

    public Decision decide(HxRequest req, BridgeClient.Authorisation auth) {
        // Epoch 0 is the DENY-ALL Authorisation BridgeClient publishes before
        // any configure and after every disconnect; epochCounter is
        // pre-incremented, so a real commit is >= 1 and there is no other way
        // to observe a 0. A null snapshot is a caller bug, and the fail-closed
        // reading of a caller bug is the same one.
        if (auth == null || auth.epoch() == 0)
            return Decision.deny("not_configured", "no configure frame acknowledged yet");

        Map<String, List<String>> scope = auth.scope();
        // An Authorisation that cannot be read is answered the same way as one
        // that was never committed. See malformation().
        String malformed = malformation(scope);
        if (malformed != null)
            return Decision.deny("not_configured", malformed);

        Decision scoped = checkScope(req, scope);
        if (!scoped.allowed()) return scoped;

        // NOT uppercased on either side. HTTP methods are case-sensitive (RFC
        // 9110 s9.1) and Sender.parse keeps whatever the frame said, so `get`
        // is what would go on the wire; folding case here would let it satisfy
        // a method.allow of GET while the server sees something else.
        List<String> allowed = scope.getOrDefault("method.allow", DEFAULT_METHODS);
        if (!allowed.contains(req.method()))
            return Decision.deny("method_denied",
                    req.method() + " is not in method.allow " + allowed);

        // Every reading of the target against every reading of the pattern,
        // and any one match refuses. The RAW reading is not a formality: it is
        // the only one that catches `/account/logout/../profile`, whose other
        // readings resolve to `/account/profile` with the logout popped off --
        // a request that reaches a logout URL on any server that does not
        // normalise before routing. The encoded readings catch
        // `/account/log%6fut`, `/account/%2570assword` (decoded twice),
        // `/x/..%5clogout` (IIS reads the backslash as a separator) and
        // `/ADMIN/purge`. The detail line quotes the RAW target, because that
        // is what the operator's frame said and what they will search for.
        Set<String> targets = targetReadings(req);
        for (String pattern : dangerousPatterns(scope))
            for (String p : patternReadings(pattern))
                for (String target : targets)
                    if (glob(lower(p), lower(target)))
                        return Decision.deny("dangerous_denied",
                                req.target() + " matches dangerous.path " + pattern);

        // The Gate LAST, because it is the only check with a side effect:
        // Limiter.check() spends a rate token and a budget slot, and spending
        // either on a request three earlier rules would have refused shortens
        // the run for no evidence.
        Decision gated;
        try {
            gated = gate.check(req);
        } catch (RuntimeException e) {
            // s4: an exception is never an implicit allow. budget_exhausted is
            // the honest class -- it is the one that means "this run is over",
            // and a gate that cannot say what is left of the budget has ended
            // the run whether or not it meant to.
            return Decision.deny("budget_exhausted",
                    "gate failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        if (gated == null)
            return Decision.deny("budget_exhausted", "gate returned no decision");
        return gated;
    }

    /**
     * Why an Authorisation cannot be decided under, or null when it can.
     *
     * decide() is documented as total, and totality is not something a caller
     * can be trusted to supply: `new Authorisation(7, null)`, a null list under
     * `scope.include`, or a null element inside one all reached a
     * NullPointerException three frames down, and an exception unwinding out of
     * decide() is an implicit allow the moment any caller mishandles it.
     *
     * The class is `not_configured`, not `scope_denied`: a snapshot this
     * malformed did not come from ConfigBody.parse -- which freezes every list
     * with List.copyOf, and List.copyOf rejects nulls -- so it is a caller bug,
     * and "no usable configuration" is the honest thing to tell an operator
     * about one. The detail names the key so the bug is findable.
     */
    private static String malformation(Map<String, List<String>> scope) {
        if (scope == null) return "the authorisation carries no scope";
        for (Map.Entry<String, List<String>> e : scope.entrySet()) {
            if (e.getValue() == null)
                return "the authorisation's " + e.getKey() + " is null";
            for (String v : e.getValue())
                if (v == null)
                    return "the authorisation's " + e.getKey() + " carries a null value";
        }
        return null;
    }

    // ---- scope ---------------------------------------------------------

    /**
     * Scope is decided about the URL, and every pattern is parsed BEFORE any
     * of them is matched. Parsing lazily would make the verdict depend on the
     * order of the include list: a garbage pattern after a matching one would
     * never be reached, and the same config would authorise or refuse the same
     * request depending on which line the operator typed first.
     */
    private static Decision checkScope(HxRequest req, Map<String, List<String>> scope) {
        Decision undecidable = undecidable(req);
        if (undecidable != null) return undecidable;

        Target t;
        try {
            t = Target.parse(req.url());
        } catch (IllegalArgumentException e) {
            return Decision.deny("scope_denied", e.getMessage());
        }

        // Policy decides about req.url(); Burp connects to req.host() on the
        // port in that url. If the url's authority is not exactly that host,
        // the decision and the connection are about different destinations --
        // which is precisely what a `target_host` of
        // "app.example.test@evil.example.test" (userinfo: everything before
        // the @ is discarded by a URL parser, and by nobody else) or
        // "app.example.test:8443" (a port smuggled into the host field) buys
        // an attacker who can influence a send frame. Neither can be matched
        // safely, so neither is matched at all.
        if (!t.host().equals(lower(req.host())))
            return Decision.deny("scope_denied", "url authority host " + t.host()
                    + " is not the connection host " + req.host());
        // Same argument one field down: the url's path is what the patterns
        // are matched against and req.path() is what the wire gets. The query
        // is deliberately NOT compared -- HxRequest cannot tell "/x" from
        // "/x?", both of which parse to an empty query -- and no scope pattern
        // matches against it.
        if (!t.path().equals(req.path()))
            return Decision.deny("scope_denied", "url path " + t.path()
                    + " is not the request path " + req.path());

        List<String> include = scope.getOrDefault("scope.include", List.of());
        if (include.isEmpty())
            // An engagement with no scope.include authorises nothing. This is
            // reachable with a non-zero epoch: a configure frame carrying only
            // limits commits fine.
            return Decision.deny("scope_denied", "no scope.include pattern is configured");

        List<Rule> excludes = new ArrayList<>();
        List<Rule> includes = new ArrayList<>();
        try {
            for (String p : scope.getOrDefault("scope.exclude", List.of()))
                excludes.add(Rule.forExclude(p));
            for (String p : include)
                includes.add(Rule.forInclude(p));
        } catch (IllegalArgumentException e) {
            return Decision.deny("scope_denied", "unusable scope pattern: " + e.getMessage());
        }

        // Computed once, and handed to both kinds of rule: they read the set
        // differently, but neither should pay for building it per pattern. The
        // host half needs nothing of the sort -- checkHostChars refuses '%'
        // outright, so an encoded authority never reaches a comparison.
        //
        // The bound is passed INTO the construction rather than checked after
        // it. For one round it was checked after, which bounded the matching
        // and left the building unbounded -- see readings(String,int). What
        // comes back is at most budget + 1 members, and it is budget + 1
        // exactly when the real set is bigger.
        int budget = readingBudget(t.path());
        Set<String> pathReadings = readings(t.path(), budget);

        // Refuse rather than pay to match every rule, and every dangerous.path
        // pattern still to come, against a reading set that has exploded. See
        // MAX_READINGS for the measurements the bound is picked from. Checked
        // the moment the count is known and before either rule loop below or
        // the dangerous.path loop later in decide() runs a single glob.
        if (pathReadings.size() > budget)
            return Decision.deny("scope_denied", "request path has at least "
                    + pathReadings.size() + " readings, over the " + budget
                    + " this can decide about");

        // Exclude first: an exclusion is the operator naming something they
        // know they must not touch, and it beats every include it overlaps.
        for (Rule r : excludes)
            if (r.denies(t, pathReadings))
                return Decision.deny("scope_denied",
                        req.url() + " matches scope.exclude " + r.source());

        for (Rule r : includes)
            if (r.allows(t, pathReadings)) return Decision.allow();

        return Decision.deny("scope_denied", req.url() + " matches no scope.include pattern");
    }

    /**
     * The longest request target this can decide about, and the deepest nesting
     * of percent-escapes it will unwrap.
     *
     * Both are bounds on work done on the ENFORCEMENT thread, per request.
     * decodeToFixedPoint is quadratic in the length of its input WITHOUT the
     * round bound -- each round is a full pass and a deeply nested escape needs
     * one round per layer -- and Frame.MAX_FRAME is 64 MB, so nothing upstream
     * stops a send frame from carrying a path that long. Measured before either
     * bound existed: a 20 KB nested path took decide() 370 ms, 100 KB took
     * 8.9 s, 400 KB took 143 s, and every one of them ended in ALLOW. That is a
     * denial-of-service on our own ruleset, from a frame we accepted.
     *
     * 8192 characters is the number every mainstream server picked for the same
     * question. Apache's default LimitRequestLine is 8190, nginx's
     * large_client_header_buffers line is 8k, Tomcat's maxHttpRequestHeaderSize
     * is 8192. A target over that is one no target server was going to answer,
     * so refusing it costs an operator nothing they had.
     *
     * It was 4096 for one round, and 4096 refuses traffic that is ordinary
     * rather than exotic: a SAML HTTP-Redirect binding puts a deflated,
     * base64'd, signed SAMLRequest in the query; an OIDC `request` parameter is
     * a whole JWT; a Kibana or Grafana share link is a rison blob; an
     * Elasticsearch `?source={...}` GET is the query body. Every one of those
     * is a legitimate request an engagement might need, and every one can pass
     * 4096. A bound below what the target itself accepts is not a safety
     * margin, it is a tool that cannot reach part of the application.
     *
     * The cost argument that justified the lower number no longer holds. It was
     * written when decode was unbounded and quadratic; with the round bound in
     * place decode is linear. Measured at this bound, on the current code:
     * decide() costs 414 us on 8192 benign characters, 3.6 ms on 8192
     * characters of `/a;b(backslash)c. ` -- every transform firing in every
     * segment -- and 26 ms on the worst input my own hill climb could find.
     * The ordinary path stays at ~2 us. (The same rows when the bound was
     * raised, before the reading set grew a decoding axis and before the
     * bounds below were on the construction: 200 us, 3.4 ms, and 406 ms
     * reported-but-unbounded.)
     *
     * That number was, for one round, the honest ceiling rather than an
     * enforced one -- reported in this comment and left unbounded, on the
     * argument that it degrades hx rather than bypassing it and that
     * truncating the reading set would be a worse fix than the cost. Both
     * halves of that argument still hold; what changed is that "reported but
     * not enforced" is itself a choice, and the honest one is a denial on the
     * count, not a shrug at 406 ms. See MAX_READINGS, just below, for the
     * bound and the reasoning for it.
     *
     * Hardcoded, not a config key: a key means a ConfigBody.KEYS change, which
     * is a change to the wire protocol between the agent and the extension --
     * the same reason the distress thresholds are not keys either.
     *
     * 16 rounds is eight more than any real double-encoding: legitimate traffic
     * needs one, an attack needs two, and nothing benign needs sixteen.
     *
     * Hitting either bound is a DENIAL, never a shrug. "I could not finish
     * reasoning about this request" and "this request is fine" are different
     * answers, and only one of them may be given to a request aimed at a
     * production estate.
     */
    static final int MAX_TARGET_CHARS = 8192;
    static final int MAX_DECODE_ROUNDS = 16;

    /**
     * The most readings a path may have before checkScope refuses it outright,
     * rather than pay to match every rule against every one of them.
     *
     * MEASURED, not guessed, in both directions. Real traffic -- the
     * before/after fixtures this task's fix rounds accumulated, every escape,
     * separator, dot-segment and trim trigger this class knows about, several
     * to a path -- tops out at 12 to 16 readings; `/a;b\c. /d`, one segment
     * carrying every transform at once, is 7. The pathological end: a
     * 600,000-sample search over an alphabet that includes the best-fit
     * homoglyphs found a 128-character shape whose reading set is 425
     * members, and an independent 300,000-sample search run for this bound
     * found a 121-character shape reaching 261 on its own. 64 is roughly 4x
     * the real ceiling and comfortably under a sixth of the smaller of the two
     * pathological figures -- headroom in both directions, not a number
     * squeezed between them.
     *
     * It is a DENIAL, and it has to be: the alternative anyone reaches for
     * first is truncating the set at N members, and truncating fails OPEN
     * both ways a denial cannot. A deny rule that stops looking early may
     * never reach the one truncated member that would have matched, so an
     * exclusion silently stops covering a path it used to. An allow rule that
     * stops early may never reach the one member that would have failed
     * coverage, so an include silently authorises a request one of its
     * readings does not actually name. Refusing the target outright has
     * neither failure: nothing is allowed on a reading nobody checked, and
     * nothing is denied on one either -- the request is simply refused, which
     * is the one answer that is safe regardless of which unchecked reading
     * would have mattered. A target whose readings explode past what real
     * traffic needs is not a legitimate caller's request in the first place.
     *
     * WHERE IT IS ENFORCED, and the correction to what this comment used to
     * claim. It said this "STOPS THE COST rather than merely bounding it",
     * because the dangerous.path loop -- every pattern against every reading
     * -- is never reached for an oversized set. That half is true. The half it
     * left out is that `checkScope` BUILT THE WHOLE SET and only then compared
     * its size, so the bound never touched construction at all, which is the
     * larger of the two costs for a set that has exploded. The review that
     * found it measured a 240-character unit whose set is 1,315 members: tiled
     * to MAX_TARGET_CHARS, one `decide()` cost 165 ms and roughly 75 MB of
     * transient heap, against the 19 ms quoted here. Fourth claim on this task
     * that was plausible, load-bearing and never run.
     *
     * The limit is now carried into readings() and every loop in the
     * construction stops on it, so at most budget + 1 members are ever built
     * and the matching loops are still never reached. That alone was not
     * enough, and my own search said so: with the count bounded at 64 an
     * 8192-character target still cost `decide()` 144 ms, because 64 readings
     * of an 8192-character path is a different amount of work from 64 readings
     * of a short one. See MAX_READING_CHARS, which bounds the product, and the
     * round report for the measurement at both bounds.
     *
     * Hardcoded for the same reason MAX_TARGET_CHARS is: a config key is a
     * wire-protocol change, and this number is a property of the matching
     * algorithm, not of an engagement.
     */
    static final int MAX_READINGS = 64;

    /**
     * The other half of the same bound: the total SIZE of the reading set, in
     * characters, that this will build before it refuses the request.
     *
     * MAX_READINGS on its own bounds the COUNT, and the count is not the cost.
     * Building a reading is a pass over a string, and 64 readings of an
     * 8192-character path is 64 passes over 8192 characters for every one of
     * the transform combinations -- half a megabyte of live strings and
     * hundreds of millions of character copies for ONE decision. The cost is
     * the PRODUCT, and a bound on one factor is not a bound on a product.
     * Measured, by running the same hill climb against a build of this class
     * with this bound removed and nothing else changed: it finds targets
     * costing decide() over 100 ms, against 26 ms for the worst it can find
     * with the bound in. Both runs had every other bound in place and doing
     * exactly what it says.
     *
     * So the budget is 128 K reading-characters, and the number of readings a
     * path may have is MAX_READINGS or that budget divided by the path's
     * length, whichever is smaller. It is one bound expressed in the currency
     * the cost is actually charged in:
     *
     *   path length     readings affordable
     *   up to 2048      64  (MAX_READINGS -- the count bound is what bites)
     *   4096            32
     *   8192            16  (MAX_TARGET_CHARS -- the size bound is what bites)
     *
     * 16 at the longest path this will look at is not a squeeze: it is the top
     * of the range real traffic occupies (12 to 16, and those are SHORT paths
     * carrying several triggers each), and a long request target in real
     * traffic is a SAML assertion, an OIDC request JWT or a rison blob -- one
     * or two readings, never sixteen. The shapes that need more than sixteen
     * readings of an eight-kilobyte path are constructed, and constructing one
     * is what this refuses.
     *
     * Same class, same reasoning, same failure direction as MAX_READINGS: a
     * DENIAL naming the count, never a truncation. Hardcoded for the same
     * reason -- a config key is a change to the wire protocol, and this is a
     * property of the matching algorithm rather than of an engagement.
     */
    static final int MAX_READING_CHARS = 128 * 1024;

    /**
     * How many readings this path may have before checkScope refuses it: the
     * count bound and the size bound, whichever is tighter. At least 1, so a
     * path is never refused for having the one reading every path has.
     */
    static int readingBudget(String path) {
        return Math.max(1, Math.min(MAX_READINGS,
                                    MAX_READING_CHARS / Math.max(1, path.length())));
    }

    /**
     * The denial for a request too long or too deeply encoded to decide about,
     * or null when there is none.
     *
     * `scope_denied` because scope is the first rule about the request itself,
     * so this keeps the pinned order intact, and because it is true: a request
     * whose readings cannot be computed has not been shown to be in scope.
     *
     * This is the bound on the INPUT; MAX_READINGS and MAX_READING_CHARS,
     * carried into the construction, bound what that input turns into. The
     * two kinds catch different things -- a merely long path does not
     * necessarily read many ways, and the short shapes that reach hundreds of
     * readings are nowhere near MAX_TARGET_CHARS.
     *
     * Both arms here are load-bearing and only one of them used to have a
     * check. Deleting `|| !decodesFully(req.query())` left all 490 checks in
     * PolicyTest green while a query still percent-encoded after
     * MAX_DECODE_ROUNDS went through: the dangerous.path denylist reads the
     * QUERY as well as the path, so a query nobody could finish decoding is a
     * denylist reading nobody checked.
     */
    private static Decision undecidable(HxRequest req) {
        int size = req.path().length() + req.query().length();
        if (size > MAX_TARGET_CHARS)
            return Decision.deny("scope_denied", "request target is " + size
                    + " characters, over the " + MAX_TARGET_CHARS
                    + " this can decide about");
        if (!decodesFully(req.path()) || !decodesFully(req.query()))
            return Decision.deny("scope_denied",
                    "request target is still percent-encoded after "
                    + MAX_DECODE_ROUNDS + " rounds of decoding");
        return null;
    }

    /** scheme, host, port and path of a request URL, with no ambiguity left in
     *  any of them. */
    private record Target(String scheme, String host, int port, String path) {

        static Target parse(String url) {
            int sep = url.indexOf("://");
            if (sep <= 0) throw new IllegalArgumentException("url has no scheme: " + url);
            String scheme = lower(url.substring(0, sep));
            if (!scheme.equals("http") && !scheme.equals("https"))
                throw new IllegalArgumentException("url scheme is not http(s): " + url);

            String rest = url.substring(sep + 3);
            int slash = rest.indexOf('/');
            if (slash < 0)
                // Sender only ever builds a url from an origin-form target, so
                // this is a caller that built one some other way.
                throw new IllegalArgumentException("url has no path: " + url);

            String authority = rest.substring(0, slash);
            String pathAndQuery = rest.substring(slash);
            int q = pathAndQuery.indexOf('?');
            String path = q < 0 ? pathAndQuery : pathAndQuery.substring(0, q);

            if (authority.indexOf('@') >= 0)
                throw new IllegalArgumentException("url authority carries userinfo: " + url);

            int port = scheme.equals("https") ? 443 : 80;
            String host = authority;
            int colon = authority.indexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon);
                String portText = authority.substring(colon + 1);
                if (portText.isEmpty())
                    throw new IllegalArgumentException("url authority has an empty port: " + url);
                for (int i = 0; i < portText.length(); i++)
                    if (portText.charAt(i) < '0' || portText.charAt(i) > '9')
                        // Catches the second colon of an unbracketed IPv6
                        // literal as well as junk. An IPv6 target needs
                        // brackets before it can be reasoned about, and
                        // nothing produces one yet.
                        throw new IllegalArgumentException("url port is not a number: " + url);
                if (portText.length() > 5)
                    throw new IllegalArgumentException("url port is out of range: " + url);
                port = Integer.parseInt(portText);
                if (port < 1 || port > 65535)
                    throw new IllegalArgumentException("url port is out of range: " + url);
            }
            host = lower(host);
            checkHostChars(host, url);
            return new Target(scheme, host, port, path);
        }
    }

    /**
     * A hostname we are willing to match against a pattern.
     *
     * The refused characters are the ones that create a SECOND reading of
     * where a request is going: '@' (userinfo), ':' (port), '/' and '\'
     * (authority ends), whitespace, and anything non-ASCII (a Cyrillic 'a' in
     * a hostname is a different host that renders identically). '_' is allowed
     * although RFC 1123 does not: internal names use it, and it cannot make an
     * authority ambiguous.
     */
    private static void checkHostChars(String host, String url) {
        if (host.isEmpty())
            throw new IllegalArgumentException("url has an empty host: " + url);
        if (host.startsWith(".") || host.endsWith(".") || host.contains(".."))
            throw new IllegalArgumentException("url host has an empty label: " + url);
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                      || c == '-' || c == '.' || c == '_';
            if (!ok) throw new IllegalArgumentException(
                    "url host has a character that cannot appear in a hostname: " + url);
        }
    }

    /**
     * One scope.include / scope.exclude pattern, pre-parsed -- including its
     * path half read every way its KIND of rule may read it.
     *
     * A deny pattern gets the same treatment as the request, for the reason
     * given in the class comment: an operator's pattern is a typed string with
     * the same several readings, and reading it only one way fails silently in
     * both directions -- a dead exclude that stops nothing, an include that
     * authorises nothing.
     *
     * An allow pattern gets the ENCODING half of that and nothing else, and
     * the asymmetry is the whole point. Round 3 gave patterns decoding
     * readings to fix "an include with an escape authorises nothing"; that is
     * the encoding axis, different spellings of the SAME resource, and it is
     * right for both kinds. The segment axis names a DIFFERENT resource, and
     * on the one rule that authorises anything a different resource is a live
     * bypass -- `include=/../*` read as `/*` authorised the whole host. So
     * forExclude() takes patternReadings() and forInclude() takes
     * spellingReadings(), and the two are different sets on purpose.
     */
    private record Rule(String source, String scheme, String hostPattern,
                        boolean hostSuffix, int port, String pathGlob,
                        Set<String> globReadings) {

        /** A scope.exclude pattern: read every way a path is read. */
        static Rule forExclude(String pattern) { return parse(pattern, false); }

        /** A scope.include pattern: read only the ways that SPELL the same
         *  resource. */
        static Rule forInclude(String pattern) { return parse(pattern, true); }

        private static Rule parse(String pattern, boolean allowRule) {
            int sep = pattern.indexOf("://");
            if (sep <= 0) throw new IllegalArgumentException(pattern + " has no scheme");
            String scheme = lower(pattern.substring(0, sep));
            if (!scheme.equals("http") && !scheme.equals("https"))
                throw new IllegalArgumentException(pattern + " has a scheme that is not http(s)");

            String rest = pattern.substring(sep + 3);
            int slash = rest.indexOf('/');
            if (slash < 0)
                // "https://app.example.test" has two readings -- the root
                // only, or everything under it -- and they differ by the whole
                // application. Make the operator write which one.
                throw new IllegalArgumentException(pattern + " has no path; write /* if you mean everything");

            String authority = rest.substring(0, slash);
            String pathGlob = rest.substring(slash);
            if (authority.indexOf('@') >= 0)
                throw new IllegalArgumentException(pattern + " carries userinfo");

            int port = scheme.equals("https") ? 443 : 80;
            String host = authority;
            int colon = authority.indexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon);
                String portText = authority.substring(colon + 1);
                if (portText.isEmpty() || portText.length() > 5)
                    throw new IllegalArgumentException(pattern + " has a bad port");
                for (int i = 0; i < portText.length(); i++)
                    if (portText.charAt(i) < '0' || portText.charAt(i) > '9')
                        throw new IllegalArgumentException(pattern + " has a bad port");
                port = Integer.parseInt(portText);
                if (port < 1 || port > 65535)
                    throw new IllegalArgumentException(pattern + " has a bad port");
            }
            host = lower(host);

            // The host half accepts exactly one wildcard shape: a leading
            // "*." matching one or more labels underneath a suffix. A general
            // glob here would let "*.example.test" be written as
            // "*example.test", which also matches "notexample.test", and would
            // let a bare "*" authorise the entire internet from one typo.
            boolean suffix = false;
            if (host.startsWith("*.")) {
                suffix = true;
                host = host.substring(1);           // ".example.test"
                checkHostChars(host.substring(1), pattern);
            } else {
                checkHostChars(host, pattern);
            }
            return new Rule(pattern, scheme, host, suffix, port, pathGlob,
                            allowRule ? spellingReadings(pathGlob)
                                      : patternReadings(pathGlob));
        }

        /** Everything but the path. Shared, because scheme, port and host
         *  have exactly one reading each -- it is the path that has two. */
        private boolean authorityMatches(Target t) {
            if (!scheme.equals(t.scheme())) return false;
            if (port != t.port()) return false;
            if (hostSuffix)
                // ".example.test" matches api.example.test but NOT
                // example.test: an operator scoping the subdomains has not
                // scoped the apex, which is frequently a different service run
                // by a different team.
                return t.host().endsWith(hostPattern);
            return hostPattern.equals(t.host());
        }

        /**
         * scope.exclude: ANY reading of the path against ANY reading of the
         * pattern, and case is folded doing it.
         *
         * Case-folded because `dangerous.path` already was and scope.exclude
         * was not, and the difference was live: an operator excluding
         * `/admin/*` was not excluding `/ADMIN/users` on a target with
         * case-insensitive routing, which is most of them. Two denylists in
         * one file disagreeing about what "the same path" means is the finding,
         * not the typo.
         *
         * lower() on an already-lowered reading returns the same instance, so
         * the derived readings -- which readings() lowercases by construction
         * -- cost nothing to fold again.
         *
         * BOTH FOLDS ARE NOW SUBSUMED, and saying so is the point of this
         * paragraph. Round 5 recorded one of them as falsifiable and the other
         * as defence in depth; round 6 made the un-decoded member a BASE, so
         * addReadings now contributes lower(raw) on both sides -- the path's
         * raw reading and the pattern's -- and the two shapes that used to
         * need this method's lower() arrive folded before it is reached.
         * Sabotaging either fold is 0 red, where the path side was 1 red and
         * the pattern side 0 the round before.
         *
         * The calls stay, and the reason is not sentiment: `lower(reading)` is
         * NOT always a member, because readings() lowercases the COLLAPSED
         * form and collapse is not the identity on a path with a dot segment.
         * A pattern that matched only the folded uncollapsed raw reading would
         * need this. I could not build one -- every pattern I tried had its own
         * dot segments resolved the same way and matched the collapsed member
         * instead -- and "no realistic input can falsify this" is a claim, not
         * an argument, so it is written here as a claim rather than turned into
         * a test I do not believe in. This is the second guard on this task to
         * end up in that position, and both are recorded rather than deleted.
         */
        boolean denies(Target t, Set<String> pathReadings) {
            if (!authorityMatches(t)) return false;
            for (String pattern : globReadings)
                for (String reading : pathReadings)
                    if (glob(lower(pattern), lower(reading))) return true;
            return false;
        }

        /**
         * scope.include: EVERY reading of the path must be matched by SOME
         * reading of the pattern, or the request is out of scope.
         *
         * Note which side quantifies which way. "Every reading of the path" is
         * what closes the escapes -- `/app/%2e%2e/other` and `/app/..;/other`
         * each have a reading that lands on `/other`, which the include does
         * not name. "Some reading of the pattern" is what keeps an operator's
         * own escapes usable: `/files/my%20docs/*` has to authorise the request
         * whether it arrives encoded or not, and only the pattern's decoded
         * reading matches the decoded arrival.
         *
         * The raw reading of the path stays case-SENSITIVE, because readings()
         * lowercases only the derived readings and glob() folds nothing.
         * Folding case on an allow rule WIDENS it, which is the wrong direction
         * for the one rule that authorises anything, and `/Admin` has never
         * been authorised by a pattern naming `/admin`. The derived readings
         * are lowercased on both sides, so an operator who wrote `/API/*` does
         * not have every request under it refused -- which would be fail-closed
         * but would also be just broken.
         *
         * That principle was stated here while the code did the opposite one
         * field along. `globReadings` held the SEGMENT readings of the pattern
         * too, and coverage by any one of them was coverage, so a single
         * trigger character in an include widened it to a resource the
         * operator never named:
         *
         *   include=/app;v=1/*  ->  /app/secret        ALLOW
         *   include=/admin./*   ->  /admin/users       ALLOW
         *   include=/../*       ->  /anything/at/all   ALLOW, the whole host
         *
         * An include's readings are now its SPELLINGS only. Every reading of
         * the path still has to be covered -- that half is unchanged, and it
         * is the half that closes the escapes.
         */
        boolean allows(Target t, Set<String> pathReadings) {
            if (!authorityMatches(t)) return false;
            for (String reading : pathReadings) {
                boolean covered = false;
                for (String pattern : globReadings)
                    if (glob(pattern, reading)) { covered = true; break; }
                if (!covered) return false;
            }
            return true;
        }
    }

    // ---- dangerous paths ------------------------------------------------

    private static List<String> dangerousPatterns(Map<String, List<String>> scope) {
        List<String> configured = scope.getOrDefault("dangerous.path", List.of());
        if (configured.isEmpty()) return DEFAULT_DANGEROUS;
        List<String> all = new ArrayList<>(DEFAULT_DANGEROUS);
        all.addAll(configured);
        return all;
    }

    // ---- helpers --------------------------------------------------------

    /**
     * `*` matches any run of characters, including none. There is no other
     * metacharacter: a scope pattern is read by an operator under time
     * pressure, and a regex is a language in which it is easy to write
     * something wider than you meant -- and in which a pattern from a config
     * file is a denial-of-service on our own JVM.
     *
     * Iterative with one backtrack point, so a pattern of many stars against a
     * long path cannot go exponential.
     */
    static boolean glob(String pattern, String text) {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.length()) {
            if (p < pattern.length() && pattern.charAt(p) == '*') {
                star = p++;
                mark = t;
            } else if (p < pattern.length() && pattern.charAt(p) == text.charAt(t)) {
                p++;
                t++;
            } else if (star >= 0) {
                p = star + 1;
                t = ++mark;
            } else {
                return false;
            }
        }
        while (p < pattern.length() && pattern.charAt(p) == '*') p++;
        return p == pattern.length();
    }

    // ---- readings --------------------------------------------------------

    /**
     * Every reading of a path this tool is willing to be wrong about, as a set.
     *
     * This replaced a canonical() that returned ONE string, because there is no
     * one string to return -- see the class comment for the three mainstream
     * libraries that disagree about `/a//../admin/users`, and for the bypass
     * that picking one of them opened. A set removes the guess: a deny rule
     * refuses if any member matches, an allow rule authorises only if every
     * member is covered, and neither has to know which normaliser the target
     * server runs.
     *
     * WHAT IS IN THE SET.
     *
     *   - the RAW path, verbatim and unfolded. It is the only reading that is
     *     certainly real -- it is what goes on the wire -- and it is the only
     *     one that catches a pattern written against the bytes
     *     (`/reports/q1%20final*`) or a dangerous URL that other readings
     *     normalise away (`/account/logout/../profile`).
     *   - the path with dot segments resolved, in BOTH orders relative to
     *     merging empty segments, because that is exactly where the mainstream
     *     libraries part company. Merge-then-resolve is what a slash-merging
     *     server does (`/a//../admin` is `/admin`); resolve-then-merge is RFC
     *     3986's remove_dot_segments, which treats the doubled slash as a real
     *     empty segment for `..` to pop (`/a/admin`). Both ship. Both are here.
     *   - the same over EACH of three answers to "what did the server decode
     *     before it routed": nothing, everything, or everything except the
     *     separators. Decoding is a reading like the rest and not a step that
     *     happens first -- see derive() for the five exclusions that were
     *     walked past while it was mandatory.
     *   - the same, with `;params` stripped from each segment. Every servlet
     *     container -- Tomcat, Jetty, Undertow, WebSphere, so every Spring Boot
     *     application -- strips them BEFORE normalising, which turns the
     *     segment `..;` into `..`. `/app/..;/other` is served as `/other`, and
     *     `..;/` is the most weaponised URL-normalisation trick in the field.
     *   - the same, with `\` folded to `/`. IIS and .NET read a backslash as a
     *     path separator, so a backslash before `users` reaches `/admin/users`
     *     and `/x/..%5clogout` is a real logout. (Spelt out rather than shown:
     *     a backslash followed by a `u` is a unicode escape in Java source and
     *     the compiler reads it even inside a comment.)
     *   - the same, with trailing dots, spaces and NULs trimmed from each
     *     segment. Windows trims trailing dots and spaces from a name before
     *     opening it, so `/admin./users` and `/admin%20/users` reach `/admin`.
     *     A trailing NUL is trimmed the same way.
     *   - the same, with everything from the first NUL onwards cut off,
     *     because a NUL is where a C string ends: `/admin%00foo` and
     *     `/admin%00.html` are both requests for `/admin` on anything that
     *     hands the path to a C API. That is a SEPARATE transform from the
     *     tail trim, which only ever reached a NUL sitting at the end of a
     *     segment. See truncateAtNul for the exclusion `/admin%00.html`
     *     walked past while two comments said it could not.
     *   - all combinations of those four, because servers implement different
     *     SUBSETS of them: Tomcat strips parameters and rejects backslashes,
     *     IIS folds backslashes and trims dots but keeps parameters. A
     *     combination nobody implements only adds a reading, and an extra
     *     reading of a PATH can only deny more. (A reading of an allow
     *     PATTERN is the opposite, which is why patterns are split; see
     *     spellingReadings.)
     *   - when the decoded bytes are not all ASCII, the same again over the
     *     UTF-8 reading of those bytes, which is what folds the overlong
     *     `%c0%ae%c0%ae` -- the classic IIS traversal -- back to `..`.
     *   - and the same again with the Windows ANSI best-fit mapping applied,
     *     which turns U+FF0F into `/`, U+FF0E into `.` and U+FF3C into a
     *     backslash. See foldBestFit.
     *
     * Identical readings collapse, so an ordinary path like `/api/orders`
     * produces exactly ONE member and costs one glob per rule. The set only
     * grows for a path that carries the characters the transforms act on,
     * which is to say for an attack.
     *
     * THE SET IS CLOSED, and it is closed by CONSTRUCTION rather than by
     * argument. Every member is fed back through derive() until a pass adds
     * nothing, so readings(m) is a subset of readings(p) for every member m --
     * which is the property the idempotence check in PolicyTest asserts and,
     * for two rounds, was never given an input that could falsify. It could
     * not be had for free: `applicable` is computed on a base, the transforms
     * COMPOSE, and a composition creates trigger characters the base did not
     * carry. See addReadings for the two-character path that walked past an
     * exclusion because of it.
     *
     * The loop terminates because every transform in it either shortens its
     * input or preserves its length -- decoding replaces three characters with
     * one, truncating and stripping and trimming and collapsing delete, the
     * byte folds and the case fold substitute -- so the members are drawn from
     * a shrinking pool. Encoding, which lengthens, is deliberately NOT in the
     * loop; see patternReadings.
     *
     * That was written here while it was FALSE, and the false clause was the
     * case fold. `"\u0130".toLowerCase(Locale.ROOT)` is TWO characters, an `i`
     * and a combining dot above: String.toLowerCase implements Unicode's full
     * mapping and the full mapping lengthens. The loop still terminated, on an
     * argument nobody had made -- the expansion is idempotent -- which is a
     * true conclusion resting on a false reason, and this task has now shipped
     * four of those. It was not only an argument, either: a cost search found
     * that a path of 8190 U+0130 characters cost decide() 99 ms and was
     * ALLOWED, with a reading set of TWO members that no bound on the set
     * could ever have caught. lower() folds one code point to one code point
     * now, so the sentence above is true because the CODE changed. See lower(),
     * and the checks in PolicyTest that pin both halves.
     *
     * ORDER WITHIN ONE PASS is load-bearing, though the fixed point covers the
     * other orders too, as later passes over the members one pass produced.
     * Decoding, WHERE IT IS APPLIED AT ALL, comes first, so `%2e%2e` is
     * already `..` when dot segments are resolved and `%2f` is already a
     * separator when the path is split into them -- and the base where it is
     * NOT applied is what gives the RFC reading, in which neither is true.
     * The NUL truncation comes next, because a C string ends before anything
     * else gets to look at it. Backslash folding comes
     * before parameter stripping, because folding decides where the SEGMENTS
     * are and stripping is per segment: `/a;b\c` folds to `/a;b/c` and then
     * strips to `/a/c`, whereas stripping first would reach `/a` and the
     * reading `/a/c` would never be built. Lowercasing comes LAST, on decoded
     * text, so `%4C` and `%6c` both arrive at `l`.
     *
     * Re-decoding on every pass is not wasted work but it is nearly free, and
     * it is what lets foldBestFit produce a `%`: the loop finds the escape that
     * character creates. It is also the only way a transform could ever produce
     * a new escape, and none of them can -- every deletion these transforms
     * make runs to the end of a segment, so the character after a deleted run
     * is a `/` or nothing, and a `%` can never acquire two hex digits it did
     * not already have. The brute-force closure check in PolicyTest is what
     * says so empirically.
     *
     * KNOWN LIMIT, stated rather than left to be discovered: `%uXXXX`, the
     * non-standard UTF-16 escape old IIS accepted (`%u002e%u002e/` for `../`),
     * is NOT decoded. It is not in the set because it is not percent-encoding
     * -- decodeOnce reads two hex digits after a `%`, and `%u0` is not two hex
     * digits -- and because IIS has not accepted it by default for many years.
     * If it ever needs to be, it belongs in decodeOnce, not here. (The
     * character it names in the traversal that made it famous, U+FF0E, IS
     * folded now -- by foldBestFit, from its percent-encoded UTF-8 spelling.)
     */
    static Set<String> readings(String path) {
        return readings(path, Integer.MAX_VALUE);
    }

    /**
     * The same set, built no further than `limit` members.
     *
     * MAX_READINGS used to be a bound on MATCHING and not on CONSTRUCTION:
     * checkScope built the whole set and only then compared its size, so a
     * target whose readings explode still paid to have every one of them
     * built. The review that found this measured a 240-character unit whose
     * set is 1,315 members, costing one decide() 165 ms and about 75 MB of
     * transient heap before the count was even looked at. The bound was on the
     * wrong side of the work.
     *
     * So the limit is carried into the construction and every loop stops on
     * it. The set that comes back has at most limit + 1 members, and it has
     * exactly limit + 1 if and only if the real set is larger -- which is all
     * a caller needs to refuse it, and one member more than it needs. Nothing
     * is TRUNCATED and handed to a matcher: a set built to the cap is only
     * ever used to produce the denial. See MAX_READINGS for why truncation is
     * the one answer that is unsafe in both directions.
     *
     * The unbounded arm above is what patterns and the tests use. A pattern
     * comes from the operator's own config rather than from the wire, and the
     * dangerous.path pass over the target runs only after checkScope has
     * already refused an oversized path -- so no attacker-controlled string
     * reaches the unbounded arm.
     */
    static Set<String> readings(String path, int limit) {
        Set<String> out = new LinkedHashSet<>();
        out.add(path);
        Deque<String> pending = new ArrayDeque<>();
        pending.add(path);
        while (!pending.isEmpty() && out.size() <= limit)
            derive(out, pending, pending.poll(), limit);
        return out;
    }

    /**
     * Every reading of one member, added to the set and queued if it is new.
     *
     * DECODING IS A READING, NOT A PREPROCESSING STEP, and for four rounds it
     * was the one mandatory transform in this class. Every other transform was
     * offered both on and off, through the `applicable` subsets in
     * addReadings; the un-decoded member was in the set only VERBATIM and
     * UNRESOLVED. So collapseDotSegments(raw) was never a member -- and that
     * is exactly what RFC 3986 s6.2.2 specifies, and what all three of the
     * libraries the class comment cites as its authority actually produce:
     *
     *   /foo%2fbar/../admin/users
     *     python urljoin()       -> /admin/users
     *     node   new URL()       -> /admin/users
     *     java   URI.normalize() -> /admin/users
     *     readings()             -> { raw, /foo/admin/users }
     *
     * The `..` popped `foo/bar` on our reading and `foo%2fbar` on theirs, and
     * the two land in different places. exclude=/admin/* was walked past by
     * spelling one separator as %2f -- and so were exclude=/api/payments/* and
     * a wildcard-host exclude of /wp-admin/*.
     *
     * So the member goes through the pipeline three ways, and each one is a
     * real answer to "what did the target server route on":
     *
     *   - the member ITSELF, undecoded. The server routed on the bytes it was
     *     sent and unescaped afterwards, if at all. This is the RFC reading,
     *     and the one urljoin, new URL() and URI.normalize() give.
     *   - the member DECODED to a fixed point, with the decoded characters
     *     read as syntax. The server unescaped before it routed, so a %2f is a
     *     separator and a %2e%2e is a dot segment. This was the only base.
     *   - the member decoded WITH THE SEPARATORS LEFT INERT: every escape
     *     unwrapped except the ones that would produce a `/` or a backslash,
     *     which stay escaped. That is a server which decodes AFTER it has cut
     *     the path into segments -- Apache with AllowEncodedSlashes off,
     *     nginx, Tomcat, and every framework that routes on the raw target and
     *     unescapes only the segment values it hands to a handler. It is the
     *     one reading that gets `/a%2fb/%2e%2e/admin/users` right: the
     *     `%2e%2e` becomes a `..` while `a%2fb` stays ONE segment for it to
     *     pop, which is `/admin/users`. Neither of the other two reaches it.
     *
     * Each of the three then gets the byte-level re-readings and the whole
     * segment pipeline, so the un-decoded member is derived exactly the way
     * its decoded form is instead of sitting outside the machinery as a
     * special case. Two of the three collapse into the first whenever the
     * member carries no escape, and the third into the second whenever it
     * carries no separator escape -- which is what keeps `/api/orders` at one
     * base, one member and one glob per rule.
     */
    private static void derive(Set<String> out, Deque<String> pending, String member, int limit) {
        addBases(out, pending, member, limit);
        String decoded = decodeToFixedPoint(member);
        if (!decoded.equals(member)) addBases(out, pending, decoded, limit);
        String inert = decodeSeparatorsInert(member);
        if (!inert.equals(member) && !inert.equals(decoded))
            addBases(out, pending, inert, limit);
    }

    /**
     * One base and its two byte-level re-readings, each run through the
     * segment transforms.
     *
     * foldOverlongUtf8 reads the decoded bytes as UTF-8, which is what folds
     * the overlong %c0%ae traversal back to `..`; foldBestFit reads what a
     * Windows ANSI API substitutes for a character its code page cannot spell.
     * Each is skipped when it is the identity, which is every ASCII path and
     * so the whole of the hot path.
     */
    private static void addBases(Set<String> out, Deque<String> pending, String base, int limit) {
        addReadings(out, pending, base, limit);
        String utf8 = foldOverlongUtf8(base);
        if (!utf8.equals(base)) addReadings(out, pending, utf8, limit);
        String bestFit = foldBestFit(utf8);
        if (!bestFit.equals(utf8)) addReadings(out, pending, bestFit, limit);
    }

    /**
     * Every reading of a PATTERN: readings(), plus the pattern spelt as the
     * percent-encoded UTF-8 a request carries it in.
     *
     * readings() only ever DECODES, which is right for a path -- the wire
     * carries the escaped form and the server unescapes it. A pattern is the
     * other way round. An operator who writes `scope.include
     * .../files/cafe-with-an-acute/*` has typed the characters; the request
     * arrives as `/files/caf%c3%a9/a.pdf`, whose RAW reading is percent-encoded
     * and which no decoding of the pattern can ever produce. Under allow-AND
     * one uncovered reading refuses the request, so that include authorised
     * NOTHING and told the operator only that their request "matches no
     * scope.include pattern" -- which sends them to rewrite a pattern that was
     * right.
     *
     * BOTH hex cases, because the raw reading of a path is verbatim and
     * unfolded (see Rule.allows) and the encoding a request arrives in is not
     * the operator's choice: `%c3%a9` and `%C3%A9` are the same two bytes and
     * only one of them is a string match.
     *
     * This is NOT done inside readings(), and the reason is termination.
     * Encoding LENGTHENS -- one character becomes six -- so a set closed under
     * both encoding and decoding has no fixed point to reach: the encoded form
     * decodes to bytes, which encode to a longer form, forever. Every
     * transform readings() iterates shortens or preserves length, which is what
     * bounds that loop. Encoding is applied ONCE, to the pattern as the
     * operator typed it, and the result is fed through readings() like any
     * other string.
     */
    static Set<String> patternReadings(String pattern) {
        Set<String> out = readings(pattern);
        String encoded = percentEncodeUtf8(pattern, false);
        if (!encoded.equals(pattern)) {
            out.addAll(readings(encoded));
            out.addAll(readings(percentEncodeUtf8(pattern, true)));
        }
        return out;
    }

    /**
     * Every way a pattern SPELLS one resource, and no way it could name a
     * different one. This is what a scope.include is read by.
     *
     * The encoding axis only: percent-decoding (to a fixed point, with the
     * separators-inert reading beside it), the UTF-8 fold, the encoded
     * spelling in both hex cases, and the case fold. Every one of those is the
     * SAME path written differently, which is what an allow rule has to cover
     * or it authorises nothing -- `include=.../files/my%20docs/*` has to
     * authorise the request whether it arrives encoded or not, and
     * `include=.../files/cafe-with-an-acute/*` has to authorise the
     * percent-encoded UTF-8 a request actually carries.
     *
     * What is NOT here is the segment axis: ;params stripped, backslashes
     * folded, dot segments resolved, empty segments merged, segment tails
     * trimmed, best-fit homoglyphs substituted. Each of those answers "which
     * resource does this name on some server", and widening a DENY rule that
     * way denies more while widening an ALLOW rule authorises more. The
     * measured cost of not making the distinction: `include=/../*` resolved to
     * `/*` and authorised every path on the host.
     *
     * The best-fit fold is on the excluded side for the same reason even
     * though it looks like an encoding: it MANUFACTURES separators. U+FF0F
     * becomes a `/` and U+FF05 becomes a `%`, so an include carrying one would
     * gain a reading that cuts the path somewhere the operator did not.
     *
     * Flat rather than a fixed point, because none of these transforms creates
     * a trigger for another: decoding already runs to a fixed point, and the
     * rest substitute characters one for one.
     *
     * THE COST, stated rather than left to be found. An include that carries a
     * segment trigger now authorises nothing at all -- not even the path it
     * literally spells. `include=/app;v=1/*` refuses `/app;v=1/secret`,
     * because that request still has the reading `/app/secret`, which a
     * servlet container serves and the pattern does not name, and allow-AND
     * refuses on any uncovered reading. It is the fail-closed answer, it is
     * visible (the operator is told the request matches no scope.include
     * pattern rather than being quietly allowed), and the remedy is one
     * pattern wide enough to cover both readings -- `/app*` here -- because
     * allows() asks a SINGLE rule to cover the whole set and two half-scopes
     * deliberately do not add up. The alternative was measured:
     * `include=/../*` authorising every path on the host.
     */
    static Set<String> spellingReadings(String pattern) {
        Set<String> out = new LinkedHashSet<>();
        addSpellings(out, pattern);
        String encoded = percentEncodeUtf8(pattern, false);
        if (!encoded.equals(pattern)) {
            addSpellings(out, encoded);
            addSpellings(out, percentEncodeUtf8(pattern, true));
        }
        return out;
    }

    /** One spelling and the readings of it that are still the same resource.
     *  Verbatim AND case-folded, because the path's raw reading is verbatim
     *  and its derived readings are lowercased, and an include has to cover
     *  both. */
    private static void addSpellings(Set<String> out, String s) {
        out.add(s);
        out.add(lower(s));
        String decoded = decodeToFixedPoint(s);
        if (decoded.equals(s)) return;
        out.add(lower(decoded));
        String utf8 = foldOverlongUtf8(decoded);
        if (!utf8.equals(decoded)) out.add(lower(utf8));
        String inert = decodeSeparatorsInert(s);
        if (!inert.equals(decoded)) out.add(lower(inert));
    }

    private static final int STRIP_PARAMS = 1, FOLD_BACKSLASH = 2, TRIM_TAILS = 4,
                             TRUNCATE_NUL = 8;

    /**
     * The transform combinations over one base, in both dot-segment orders,
     * with every new member queued for re-derivation.
     *
     * Only combinations of the transforms this base can actually be CHANGED by
     * are built. Each of the four is the identity on a string without its
     * trigger character -- a `;`, a backslash, a trimmable segment tail, a NUL
     * -- so the skipped combinations produce nothing this base has not already
     * produced. That is an early-out about ONE PASS over ONE base, and it is
     * only that: the claim that the SET is therefore closed does not follow
     * from it, and used to be made here. See below.
     *
     * It is also where the closure defect lived, and the reason readings()
     * iterates. `applicable` is computed on the BASE, and an earlier version
     * stopped there under a comment claiming the set was closed because "a
     * skipped combination would have produced a member the set already holds".
     * The first clause is true of the base; the conclusion does not follow,
     * because THE TRANSFORMS COMPOSE. Stripping a `;param` or folding a
     * backslash CREATES a segment tail the base did not have:
     * `/admin%20;x/users` decodes to `/admin ;x/users`, whose only trimmable
     * character is hidden behind the parameter, so TRIM_TAILS never switched on
     * and the reading `/admin /users` -- which Windows trims to `/admin/users`
     * -- was never built. `exclude=/admin/*` was walked past by appending two
     * characters to a path it already caught. Feeding every member back through
     * derive() until nothing new appears is what makes the closure claim true
     * rather than plausible. It also widens the claim: one pass applies the
     * three transforms in one fixed order, and re-deriving every member makes
     * the set closed under any SEQUENCE of them, which is what "every reading a
     * server might resolve this to" actually asks for.
     */
    private static void addReadings(Set<String> out, Deque<String> pending, String base, int limit) {
        int applicable = 0;
        if (base.indexOf(';') >= 0) applicable |= STRIP_PARAMS;
        if (base.indexOf('\\') >= 0) applicable |= FOLD_BACKSLASH;
        if (hasTrimmableTail(base)) applicable |= TRIM_TAILS;
        if (base.indexOf('\0') >= 0) applicable |= TRUNCATE_NUL;
        for (int flags = 0; flags <= applicable; flags++) {
            if ((flags & ~applicable) != 0) continue;
            if (out.size() > limit) return;
            String s = base;
            if ((flags & TRUNCATE_NUL) != 0) s = truncateAtNul(s);
            if ((flags & FOLD_BACKSLASH) != 0) s = foldBackslashes(s);
            if ((flags & STRIP_PARAMS) != 0) s = stripPathParameters(s);
            if ((flags & TRIM_TAILS) != 0) s = trimSegmentTails(s);
            add(out, pending, lower(collapseDotSegments(collapseEmptySegments(s))));
            if (out.size() > limit) return;
            add(out, pending, lower(collapseEmptySegments(collapseDotSegments(s))));
        }
    }

    private static void add(Set<String> out, Deque<String> pending, String reading) {
        if (out.add(reading)) pending.add(reading);
    }

    /** Whether trimSegmentTails() would change this path -- exactly the
     *  condition under which it is not the identity, including the dot
     *  segments it deliberately leaves alone. */
    private static boolean hasTrimmableTail(String path) {
        int start = 0;
        for (int i = 0; i <= path.length(); i++)
            if (i == path.length() || path.charAt(i) == '/') {
                if (i > start) {
                    char last = path.charAt(i - 1);
                    if (last == ' ' || last == '\0'
                            || (last == '.' && !isDotSegment(path, start, i)))
                        return true;
                }
                start = i + 1;
            }
        return false;
    }

    /** `\` read as the separator IIS and .NET read it as. */
    static String foldBackslashes(String path) {
        return path.indexOf('\\') < 0 ? path : path.replace('\\', '/');
    }

    /**
     * Everything from the first `;` of a segment to the end of that segment,
     * removed -- what a servlet container does to `/app/orders;jsessionid=X`
     * before it looks at the path at all.
     *
     * The `;` and what follows are dropped, the `/` that ends the segment is
     * kept. That is what makes `/app/..;/other` read as `/app/../other` and
     * then as `/other`.
     */
    static String stripPathParameters(String path) {
        if (path.indexOf(';') < 0) return path;
        StringBuilder out = new StringBuilder(path.length());
        boolean dropping = false;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '/') { dropping = false; out.append(c); continue; }
            if (c == ';') dropping = true;
            if (!dropping) out.append(c);
        }
        return out.toString();
    }

    /**
     * Everything from the first NUL to the end of the path, cut off.
     *
     * A NUL is where a C string ENDS. Anything that hands the path to a C API
     * -- a filesystem call, a legacy module, an ANSI Windows API -- sees the
     * path stop there, so `/admin%00.html` is a request for `/admin` and
     * `/admin%00/users` is one too.
     *
     * Two comments in this file asserted exactly that for four rounds and no
     * transform built it. trimSegmentTails trims a NUL only where it is the
     * LAST character of a segment, which catches `/admin%00/users` for a
     * different reason and misses `/admin%00.html` entirely: with an exclusion
     * on `.../admin`, appending `%00.html` to a path it caught was an ALLOW.
     * The claim was true of real servers and false of this class, which is the
     * failure mode this task has now shipped four times.
     *
     * Both readings are kept, because they are different servers. The trim is
     * a NAME that ends in a NUL and a path that carries on past it; the
     * truncation is a STRING that ends at the NUL and takes the rest of the
     * path with it.
     */
    static String truncateAtNul(String path) {
        int nul = path.indexOf('\0');
        return nul < 0 ? path : path.substring(0, nul);
    }

    /**
     * Trailing dots, spaces and NULs trimmed from each segment.
     *
     * Windows trims trailing dots and spaces from a filename before opening
     * it, and IIS serves what Windows opens, so `/admin./users` and
     * `/admin%20/users` reach the same resource `/admin/users` does. A NUL at
     * the end of a name is trimmed with them.
     *
     * A NUL in the MIDDLE of a name is a different reading and not this one:
     * this method only ever trims a tail, so `/admin%00.html` came out
     * unchanged. truncateAtNul is where the C-string reading lives.
     *
     * `.` and `..` are left ALONE, and NOTHING ELSE IS. They are dot SEGMENTS,
     * resolved a step later; trimming their dots would delete the step rather
     * than normalise a name, and `/app/.. /other` -- whose whole point is that
     * the trimmed segment must still be a `..` -- would come out as
     * `/app//other` instead of `/other`.
     *
     * The exemption used to be "a segment of nothing but dots", which is wider
     * than the argument for it. `...` and `....` are not dot segments, they are
     * ordinary names, and Windows trims them to NOTHING -- so `/.../admin/users`
     * is `//admin/users` is `/admin/users` on the server, while the exemption
     * left it as a segment called `...` that `exclude=/admin/*` never matched.
     * Three characters bought a walk past an exclusion.
     */
    static String trimSegmentTails(String path) {
        StringBuilder out = new StringBuilder(path.length());
        int start = 0;
        for (int i = 0; i <= path.length(); i++)
            if (i == path.length() || path.charAt(i) == '/') {
                out.append(trimSegmentTail(path, start, i));
                if (i < path.length()) out.append('/');
                start = i + 1;
            }
        return out.toString();
    }

    private static String trimSegmentTail(String path, int start, int end) {
        int cut = end;
        while (cut > start) {
            char c = path.charAt(cut - 1);
            if (c != ' ' && c != '\0') break;
            cut--;
        }
        if (!isDotSegment(path, start, cut))
            while (cut > start) {
                char c = path.charAt(cut - 1);
                if (c != '.' && c != ' ' && c != '\0') break;
                cut--;
            }
        return path.substring(start, cut);
    }

    /** Whether this segment is `.` or `..` -- the two dot SEGMENTS, and not
     *  the longer runs of dots, which are names. */
    private static boolean isDotSegment(String path, int start, int end) {
        int length = end - start;
        if (length != 1 && length != 2) return false;
        for (int i = start; i < end; i++) if (path.charAt(i) != '.') return false;
        return true;
    }

    /**
     * The decoded bytes read as UTF-8, when they are not already ASCII.
     *
     * decodeOnce maps a percent-escape to one char with no transcoding, so
     * after decoding a string of `%c0%ae` is the two chars 0xC0 0xAE. Read as
     * UTF-8 that is an OVERLONG encoding of `.`, and `%c0%ae%c0%ae%c0%af` is
     * the `../` that walked past IIS for years. Nothing else in this class
     * would ever see it: a dot-segment resolver looking for the two-character
     * string ".." does not find it there.
     *
     * Overlong forms are folded on purpose -- they are the attack, and a
     * decoder that rejects them (as a correct UTF-8 decoder must) is exactly
     * the decoder that would not produce this reading. Well-formed sequences
     * are folded too, which is just correct: `%c3%a9` becomes the one char
     * `e-acute` rather than two bytes, so an operator's pattern and the request
     * agree about a filename with an accent in it.
     *
     * A sequence that is not well formed at all -- a lead byte with no
     * continuation after it -- is copied through and reading carries on, for
     * the same reason decodeOnce does not abandon a string on one bad escape:
     * a single stray byte must not be a switch that turns this reading off.
     */
    static String foldOverlongUtf8(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) < 0x80) i++;
        if (i == s.length()) return s;
        StringBuilder out = new StringBuilder(s.length());
        out.append(s, 0, i);
        while (i < s.length()) {
            char c = s.charAt(i);
            int extra = c >= 0xf0 && c <= 0xf7 ? 3
                      : c >= 0xe0 && c <= 0xef ? 2
                      : c >= 0xc0 && c <= 0xdf ? 1 : 0;
            if (extra == 0 || i + extra >= s.length()) { out.append(c); i++; continue; }
            int cp = c & (0x3f >> extra);
            boolean wellFormed = true;
            for (int k = 1; k <= extra && wellFormed; k++) {
                char b = s.charAt(i + k);
                if (b < 0x80 || b > 0xbf) wellFormed = false;
                else cp = (cp << 6) | (b & 0x3f);
            }
            if (!wellFormed || cp > 0xffff) { out.append(c); i++; continue; }
            out.append((char) cp);
            i += extra + 1;
        }
        return out.toString();
    }

    /**
     * The Windows ANSI best-fit mapping, over the characters that can become a
     * path separator.
     *
     * When a Windows program hands a wide string to an ANSI ("A") API --
     * which the whole compatibility layer under a great deal of shipped
     * software still does -- WideCharToMultiByte does not fail on a character
     * the code page cannot represent. It substitutes a VISUALLY SIMILAR one
     * from a per-code-page "best fit" table. U+FF0F FULLWIDTH SOLIDUS becomes
     * an ordinary `/`. U+FF0E becomes `.`, U+FF3C becomes a backslash, U+FF1B
     * becomes `;`. The path that reaches the filesystem is not the path that
     * was routed.
     *
     * So `/x/..` followed by U+FF0F followed by `logout` -- three
     * percent-escapes on the wire, `%ef%bc%8f` -- is served as `/x/../logout`,
     * which is a real logout, and every reading this class had before this
     * method saw a segment called `..(something)logout` that no glob names.
     * Named "WorstFit" at Black Hat EU 2024; the same mapping is what made the
     * historic `%uff0e%uff0e/` IIS traversal work.
     *
     * CLOSED rather than documented, on the reviewer's argument: the payload is
     * in every modern traversal wordlist, and the party generating targets for
     * this tool is an agent working a pentest, which is exactly the party that
     * pastes a wordlist entry.
     *
     * The map is the separator-producing entries only. The real tables map
     * hundreds of characters -- quotes, dashes, currency signs -- and none of
     * the rest changes how a path is READ. U+FF05 (fullwidth percent) is here
     * because it can create an escape, and readings() re-derives every member,
     * so the escape it creates is decoded on the next pass.
     */
    static String foldBestFit(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) < 0x80) i++;
        if (i == s.length()) return s;                  // pure ASCII: nothing to fit
        StringBuilder out = null;
        for (; i < s.length(); i++) {
            char c = s.charAt(i);
            char fit = bestFit(c);
            if (fit == c) continue;
            if (out == null) out = new StringBuilder(s);
            out.setCharAt(i, fit);
        }
        return out == null ? s : out.toString();
    }

    /** Hex rather than character literals on purpose: these code points are
     *  homoglyphs of the separators, and a reader has no way to tell them apart
     *  in a source file. */
    private static char bestFit(char c) {
        switch (c) {
            case 0xff0f:            // FULLWIDTH SOLIDUS
            case 0x2215:            // DIVISION SLASH
            case 0x2044:            // FRACTION SLASH
            case 0x29f8: return '/';// BIG SOLIDUS
            case 0xff3c:            // FULLWIDTH REVERSE SOLIDUS
            case 0xfe68: return '\\';// SMALL REVERSE SOLIDUS
            case 0xff0e:            // FULLWIDTH FULL STOP
            case 0xfe52:            // SMALL FULL STOP
            case 0xff61:            // HALFWIDTH IDEOGRAPHIC FULL STOP
            case 0x2024: return '.';// ONE DOT LEADER
            case 0xff1b:            // FULLWIDTH SEMICOLON
            case 0xfe54: return ';';// SMALL SEMICOLON
            case 0xff05: return '%';// FULLWIDTH PERCENT SIGN
            default:     return c;
        }
    }

    /**
     * The string spelt as the percent-encoded UTF-8 a request would carry it
     * in. Only patternReadings() calls this; see its comment for why it is not
     * a reading of a path.
     *
     * Surrogate pairs are encoded as the one code point they are, not as two
     * unpaired halves, which is what String.getBytes does for a substring that
     * holds the whole pair.
     */
    static String percentEncodeUtf8(String s, boolean upperHex) {
        int i = 0;
        while (i < s.length() && s.charAt(i) < 0x80) i++;
        if (i == s.length()) return s;                  // pure ASCII: already encoded
        StringBuilder out = new StringBuilder(s.length() + 16);
        out.append(s, 0, i);
        String digits = upperHex ? "0123456789ABCDEF" : "0123456789abcdef";
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c < 0x80) { out.append(c); i++; continue; }
            int end = i + (Character.isHighSurrogate(c) && i + 1 < s.length()
                           && Character.isLowSurrogate(s.charAt(i + 1)) ? 2 : 1);
            for (byte b : s.substring(i, end).getBytes(StandardCharsets.UTF_8))
                out.append('%').append(digits.charAt((b >> 4) & 0xf))
                   .append(digits.charAt(b & 0xf));
            i = end;
        }
        return out.toString();
    }

    /**
     * Runs of two or more `/` collapsed to one; a lone `/` is left alone.
     * Never throws: a path of nothing but slashes collapses to `/` like any
     * other run, which is what the "path that is only slashes" check in
     * PolicyTest pins -- decide() must answer that with a Decision, not an
     * exception a careless caller could read as an allow.
     */
    static String collapseEmptySegments(String path) {
        if (path.indexOf("//") < 0) return path;    // nothing to collapse
        StringBuilder out = new StringBuilder(path.length());
        boolean prevSlash = false;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            boolean slash = c == '/';
            if (slash && prevSlash) continue;
            out.append(c);
            prevSlash = slash;
        }
        return out.toString();
    }

    /**
     * Percent-decoding repeated until a round changes nothing, or until
     * MAX_DECODE_ROUNDS rounds have run.
     *
     * Decoding runs to a FIXED POINT, not once. `%2570assword` decodes to
     * `%70assword` and only then to `password`, and a denylist that stopped
     * after one round would be reading the middle spelling while the server,
     * or any proxy in front of it, reads the last.
     *
     * The cap is not about termination -- a round that changes anything
     * replaces three characters with one, so the string strictly shortens and
     * the loop was already bounded by its length. It is about COST: each round
     * is a full pass, so a path of one escape nested n deep costs O(n^2), and
     * that ran on the enforcement thread with nothing capping the path length.
     * See MAX_TARGET_CHARS. A string still changing after 16 rounds is not a
     * request anyone is legitimately making, and decodesFully() is what turns
     * it into a denial rather than a partially-decoded reading nobody checked.
     */
    static String decodeToFixedPoint(String s) {
        for (int round = 0; round < MAX_DECODE_ROUNDS; round++) {
            String next = decodeOnce(s);
            if (next.equals(s)) return s;
            s = next;
        }
        return s;
    }

    /**
     * The same, except that an escape which would produce a path separator is
     * left alone: `%2f` stays `%2f` and `%5c` stays `%5c`, in any hex case and
     * however deeply they were nested (`%252f` unwraps once, to `%2f`, and
     * stops there).
     *
     * This is the reading of a server that decodes AFTER it has cut the path
     * into segments, which is most of them: Apache with the default
     * AllowEncodedSlashes off, nginx, Tomcat, and every framework that routes
     * on the raw target and unescapes only the segment values it passes on. An
     * encoded slash is DATA to such a server, not syntax -- which is the whole
     * reason `%2f` has its own family of bypasses.
     *
     * It is the only base that reads `/a%2fb/%2e%2e/admin/users` the way those
     * servers do. Decoding nothing leaves `%2e%2e`, which is not a dot
     * segment, so nothing pops. Decoding everything makes `a%2fb` into two
     * segments, so `..` pops only `b`. Decoding the dots but not the slash
     * leaves one segment for `..` to pop, and the answer is `/admin/users`.
     */
    static String decodeSeparatorsInert(String s) {
        for (int round = 0; round < MAX_DECODE_ROUNDS; round++) {
            String next = decodeOnce(s, true);
            if (next.equals(s)) return s;
            s = next;
        }
        return s;
    }

    /**
     * Whether decodeToFixedPoint actually reached a fixed point rather than
     * running out of rounds. One extra decodeOnce, so it costs one pass.
     *
     * Kept separate from decodeToFixedPoint rather than folded into it because
     * the answer belongs to decide(), which owes the caller a Decision:
     * "still encoded after 16 rounds" has to become a denial, and a decoder
     * that threw or returned null to say so would be a decoder that could take
     * decide() down with it.
     */
    static boolean decodesFully(String s) {
        String decoded = decodeToFixedPoint(s);
        return decodeOnce(decoded).equals(decoded);
    }

    /**
     * One round of percent-decoding. It NEVER throws and never rejects: a
     * malformed escape -- a bare `%`, `%z`, a truncated `%4` at the end of the
     * string -- is copied through verbatim and decoding carries on past it.
     *
     * Abandoning the whole string on one bad escape, the other reading of
     * "return the input unchanged", would hand an attacker a switch: append a
     * single `%` to `/account/log%6fut` and canonicalisation turns itself off
     * for the entire path. Per-escape leniency keeps the rest decoded, so the
     * denylist still sees `logout%`, and a test pins exactly that request.
     * Throwing would be worse again -- anything thrown out of decide() is an
     * implicit allow the moment a caller mishandles it, which is the failure
     * this whole class exists to make impossible.
     *
     * Bytes become chars one for one, with no transcoding. Every pattern these
     * strings are matched against is ASCII, and choosing a charset here would
     * add a second reading of the path rather than remove one.
     */
    static String decodeOnce(String s) {
        return decodeOnce(s, false);
    }

    /**
     * One round, with the option of leaving the separator-producing escapes
     * alone. `separatorsInert` is what decodeSeparatorsInert passes; see there
     * for the servers that reading belongs to. An escape it declines to
     * decode is copied through exactly the way a malformed one is, so the rest
     * of the string still decodes.
     */
    static String decodeOnce(String s, boolean separatorsInert) {
        int first = s.indexOf('%');
        if (first < 0) return s;
        StringBuilder out = new StringBuilder(s.length());
        out.append(s, 0, first);
        for (int i = first; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '%' || i + 2 >= s.length()) { out.append(c); continue; }
            int hi = hexDigit(s.charAt(i + 1));
            int lo = hexDigit(s.charAt(i + 2));
            if (hi < 0 || lo < 0) { out.append(c); continue; }
            char decoded = (char) (hi * 16 + lo);
            if (separatorsInert && (decoded == '/' || decoded == '\\')) {
                out.append(c);
                continue;
            }
            out.append(decoded);
            i += 2;
        }
        return out.toString();
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /**
     * RFC 3986 remove_dot_segments, over the '/'-separated segments of a path.
     * A `..` at the root is discarded rather than escaping it, and a trailing
     * `.` or `..` leaves the trailing slash it implies, so `/a/b/..` is `/a/`
     * and not `/a`.
     */
    static String collapseDotSegments(String path) {
        // With no '.' anywhere there is no dot segment, and the split-and-
        // rejoin below reproduces its input character for character. Returning
        // early is the same answer without the ArrayList: this runs per
        // request per pattern, and almost every pattern is dot-free.
        if (path.indexOf('.') < 0) return path;
        boolean absolute = path.startsWith("/");
        List<String> segments = new ArrayList<>();
        int start = 0;
        for (int i = 0; i <= path.length(); i++)
            if (i == path.length() || path.charAt(i) == '/') {
                segments.add(path.substring(start, i));
                start = i + 1;
            }

        List<String> kept = new ArrayList<>();
        boolean trailingSlash = false;
        for (int i = absolute ? 1 : 0; i < segments.size(); i++) {
            String seg = segments.get(i);
            boolean last = i == segments.size() - 1;
            if (seg.equals(".")) {
                if (last) trailingSlash = true;
            } else if (seg.equals("..")) {
                if (!kept.isEmpty()) kept.remove(kept.size() - 1);
                if (last) trailingSlash = true;
            } else {
                kept.add(seg);
            }
        }

        StringBuilder out = new StringBuilder();
        if (absolute) out.append('/');
        for (int i = 0; i < kept.size(); i++) {
            if (i > 0) out.append('/');
            out.append(kept.get(i));
        }
        if (trailingSlash && (out.length() == 0 || out.charAt(out.length() - 1) != '/'))
            out.append('/');
        return out.toString();
    }

    /**
     * Every reading of the origin-form target, for the dangerous-path denylist,
     * which reads path AND query: every reading of the path against every
     * reading of the query.
     *
     * The query has TWO readings, raw and decoded, and both earn their place.
     * The decoded one is the obvious half -- on a legacy application the logout
     * is `?action=log%6fut` at least as often as it is a path. The raw one is
     * the half that is easy to drop and hard to miss the loss of: a
     * dangerous.path an operator wrote against the bytes, `*=log%6*`, matches
     * `action=log%6fut` and matches nothing at all once the query is decoded,
     * because `%6f` is gone by then and `%6` was never a whole escape.
     *
     * The two halves are read separately, and the path transforms are applied
     * to the path ONLY: a `..` in a query value is a value, a `;` in one is a
     * separator some frameworks still use, and a `%2f` in one is not a path
     * separator the server will ever see.
     *
     * With no query the target IS the path, so the path's readings are the
     * target's -- built once rather than copied.
     */
    private static Set<String> targetReadings(HxRequest req) {
        Set<String> paths = readings(req.path());
        if (req.query().isEmpty()) return paths;
        Set<String> queries = new LinkedHashSet<>();
        queries.add(req.query());
        queries.add(lower(decodeToFixedPoint(req.query())));
        Set<String> out = new LinkedHashSet<>();
        for (String path : paths)
            for (String query : queries)
                out.add(path + "?" + query);
        return out;
    }

    /**
     * Case folded ONE CODE POINT AT A TIME, which is not what
     * String.toLowerCase does and is deliberate in both directions.
     *
     * Locale is the first reason, and it was the original one: in a Turkish
     * locale `"I".toLowerCase()` is a DOTLESS i, so an operator who wrote a
     * dangerous.path in capitals would have it stop matching `/delete` on
     * their laptop and nowhere else. Character.toLowerCase(int) is Unicode's
     * SIMPLE mapping and has no locale at all, so there is no default to get
     * wrong.
     *
     * COST is the second, and it is why this is a loop rather than
     * `s.toLowerCase(Locale.ROOT)`. String.toLowerCase implements Unicode's
     * FULL mapping, including the conditional and multi-character cases, and
     * the JDK's implementation of that path is orders of magnitude slower per
     * character than the simple one. Measured, on this machine, by a cost
     * search that went looking for the most expensive decide() it could build:
     * a path of 8190 U+0130 characters (LATIN CAPITAL LETTER I WITH DOT ABOVE,
     * whose full lowercase is TWO characters, an `i` and a combining dot) cost
     * `decide()` 99 ms and was ALLOWED -- with a reading set of TWO members,
     * so neither MAX_READINGS nor MAX_READING_CHARS came anywhere near it and
     * MAX_TARGET_CHARS was satisfied. It is not a reading-set explosion at all;
     * it is one string operation being slow. Per code point it is 0.5 ms.
     *
     * LENGTH is the third, and it repairs an argument rather than the cost.
     * readings() terminates because its transforms shorten or preserve length,
     * and that claim was made in this file while String.toLowerCase quietly
     * broke it -- `"\u0130"` lowercases to two characters. The simple mapping
     * is one code point to one code point, and Unicode has no simple case
     * mapping that crosses out of the plane it starts in, so this cannot
     * lengthen a string at all. The invariant is true again because the code
     * changed, not because the comment did.
     *
     * WHAT IT COSTS: the conditional mappings, which are the Greek final sigma
     * and the U+0130 dot. `lower("\u0130")` is `i` here and `i` plus a
     * combining dot in String.toLowerCase, and a capital sigma folds to the
     * medial form in every position. Both sides of every comparison in this
     * class go through this method, so the only shape that could notice is an
     * operator's pattern spelt with one of those two characters against a
     * request spelt with the other. PolicyTest pins the U+0130 behaviour so
     * the difference is a decision on the record rather than a surprise.
     */
    static String lower(String s) {
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            if (cp != Character.toLowerCase(cp)) break;
            i += Character.charCount(cp);
        }
        if (i == s.length()) return s;                  // already folded: no copy
        StringBuilder out = new StringBuilder(s.length());
        out.append(s, 0, i);
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            out.appendCodePoint(Character.toLowerCase(cp));
            i += Character.charCount(cp);
        }
        return out.toString();
    }
}
