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
        //
        // BOTH SIDES ARE CASE FOLDED HERE, and this is a second copy of the
        // fold Rule.denies documents rather than a belt-and-braces one.
        // readings() lowercases the COLLAPSED members only, so the verbatim raw
        // reading arrives unfolded -- and on a path carrying a `/../` it is the
        // one member that still holds the dangerous segment, because every
        // other reading pops it. Drop this lower() and
        // `/account/LOGOUT/../profile` becomes an ALLOW that issues a real
        // logout, with every other check in PolicyTest green. Round 7 pinned
        // the call in Rule.denies and left this one unnamed;
        // theDangerousPassFoldsTheCaseOfAnUncollapsedRawReading pins it now.
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
        int budget = readingBudget(t.path().length());
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

        // The same bound over the TARGET, which is what the dangerous.path pass
        // reads: every reading of the path against every reading of the query,
        // so the cost that pass pays is the PRODUCT and a bound on one factor is
        // not a bound on a product -- the argument MAX_READING_CHARS already
        // makes about length. It is taken HERE, in scope, because no rule may
        // run a glob against a set nobody could finish building, and because
        // scope is the first rule about the request itself: putting the denial
        // anywhere later would break the pinned order.
        //
        // The query half is bounded and not merely counted, for the reason the
        // path half is: this was measured, not assumed. A hill climb over the
        // alphabet an evasion is built from reaches 70 query readings from a
        // 162-character query -- past MAX_READINGS on its own, before it is
        // multiplied by anything.
        if (!req.query().isEmpty()) {
            int targetBudget = readingBudget(req.path().length() + req.query().length() + 1);
            Set<String> queries = queryReadings(req.query(), targetBudget);
            long product = (long) pathReadings.size() * queries.size();
            if (product > targetBudget)
                return Decision.deny("scope_denied", "request target has at least "
                        + product + " readings, over the " + targetBudget
                        + " this can decide about");
        }

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
     * RE-MEASURED after the best-fit table grew from thirteen entries to the
     * whole fullwidth block, because a bound justified by a measurement is only
     * as good as the build it was measured on. Real traffic is unchanged: an
     * ordinary path is 1 reading, `/app/orders;jsessionid=1` is 2, and
     * `/a;b(backslash)c. /d` -- every transform firing in one segment -- is
     * still 7. The pathological end moved a long way: a hill climb over the
     * trigger alphabet now reaches 2,229 readings from a THIRTY-TWO character
     * path, against the 261 and 425 above. The bound is what stands between
     * that and the enforcement thread, and the gap between 7 and 64 is what
     * says the bound is not standing in front of anything real.
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
     * How many readings a string this long may have before checkScope refuses
     * it: the count bound and the size bound, whichever is tighter. At least 1,
     * so a path is never refused for having the one reading every path has.
     *
     * Taken over a LENGTH rather than a string because it is asked twice: once
     * about the path, whose readings the scope rules match, and once about the
     * whole target, whose readings the dangerous.path pass matches. The second
     * has no string to be handed -- the target's readings are a product of two
     * sets and are never built as one string until they are matched.
     */
    static int readingBudget(int length) {
        return Math.max(1, Math.min(MAX_READINGS,
                                    MAX_READING_CHARS / Math.max(1, length)));
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
     *   - and the same again with the Windows ANSI best-fit mapping applied.
     *     That is not the separator homoglyphs, and it is not the fullwidth
     *     block either: it is every entry of Microsoft's bestfit1252.txt that
     *     lands on printable ASCII, 392 of them, generated from the file. A
     *     fullwidth spelling of `logout` is `logout` to an ANSI API, and so is
     *     `logout` with a Polish `l`. See foldBestFit.
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
     * The encoding axis: percent-decoding (to a fixed point, with the
     * separators-inert reading beside it), the UTF-8 fold, the encoded
     * spelling in both hex cases, and the case fold. Every one of those is the
     * SAME path written differently, which is what an allow rule has to cover
     * or it authorises nothing -- `include=.../files/my%20docs/*` has to
     * authorise the request whether it arrives encoded or not, and
     * `include=.../files/cafe-with-an-acute/*` has to authorise the
     * percent-encoded UTF-8 a request actually carries. PLUS, since Round 9,
     * the LETTER half of the best-fit fold -- foldBestFitLetters, called from
     * addSpellings -- because `include=.../p(U+0142)atno(U+015B)ci/*` has to
     * authorise the ASCII best-fit reading a Windows target routes that
     * request as, the same way the encoding axis already covered an escape.
     *
     * What is NOT here is the segment axis: ;params stripped, backslashes
     * folded, dot segments resolved, empty segments merged, segment tails
     * trimmed. Each of those answers "which resource does this name on some
     * server", and widening a DENY rule that way denies more while widening an
     * ALLOW rule authorises more. The measured cost of not making the
     * distinction: `include=/../*` resolved to `/*` and authorised every path
     * on the host.
     *
     * THE BEST-FIT FOLD IS SPLIT ACROSS THE TWO KINDS OF RULE, by what a
     * fit's TARGET is rather than by a second list of code points -- see
     * foldBestFitLetters. The separator half -- 122 of the table's 398 --
     * stays excluded, for the same reason the segment axis is: it MANUFACTURES
     * structure. U+FF0F becomes a `/`, U+FF05 becomes a `%`, U+FF0A becomes a
     * `*` -- a GLOB METACHARACTER the moment it sits in a pattern's own
     * spelling -- so an include carrying one would gain a reading that cuts
     * the path, escapes it, or globs it, somewhere the operator did not write.
     * foldBestFit still folds that half for a PATH and for a DENY pattern; it
     * always has. The LETTER half -- 276 of 398 -- is different in kind, not
     * degree: it substitutes one letter or digit for another, one code point
     * for one code point, so it cannot split a segment, cannot merge two, and
     * cannot manufacture a `/`, a `\`, a `.`, a `;`, a `%` or a `*`. The
     * structural argument above never reached it, which is what made it a
     * ruling to take rather than a bypass to close.
     *
     * THE COST OF NOT RULING IT IN WAS MEASURED FIRST, and is worth keeping:
     * before Round 9, an include whose own text carried a letter-half code
     * point authorised nothing at all --
     *
     *   include=.../p(U+0142)atno(U+015B)ci/*   Polish     authorised NOTHING
     *   include=.../kullan(U+0131)c(U+0131)/*   Turkish    authorised NOTHING
     *   include=.../pl(U+0103)(U+0163)i/*       Romanian   authorised NOTHING
     *   include=.../lietot(U+0101)js/*          Latvian    authorised NOTHING
     *   include=.../(a Greek word with an alpha)/*  Greek   authorised NOTHING
     *
     * -- and all five authorise their own request now; PolicyTest carries the
     * table and its controls. What is still NOT affected is anything code page
     * 1252 can already spell -- so Spanish, French, German, Portuguese and
     * Italian scopes, and Cyrillic and CJK ones, are untouched -- nor an
     * include anchored at an ASCII prefix, because the fold changes a NAME and
     * not the prefix, and that was true either way.
     *
     * THE ACCEPTED COST, taken knowingly rather than found later: an include
     * spelt with a letter homoglyph now authorises the plain spelling too.
     * `include=/(U+FF41)dmin/*` folded reads as `/admin/*` and authorises the
     * real admin area, which is the `include=/../*` failure with a homoglyph
     * in place of a dot segment -- a real widening, but of one NAME to one
     * name, never of one directory to the whole host, because the fold cannot
     * add a `/` or a `*`. It is fail-closed and visible on the side that still
     * refuses: an uncovered reading still tells the operator the request
     * matches no scope.include pattern rather than being quietly allowed.
     *
     * Flat rather than a fixed point, because none of these transforms creates
     * a trigger for another: decoding already runs to a fixed point, and the
     * rest -- the case fold, the letter fold -- substitute characters one for
     * one and cannot manufacture an escape or a separator for a later pass to
     * find.
     *
     * THE SEGMENT-AXIS COST, stated rather than left to be found, and
     * unaffected by any of the above because best-fit is an encoding-axis
     * question. An include that carries a segment trigger authorises nothing
     * at all -- not even the path it literally spells. `include=/app;v=1/*`
     * refuses `/app;v=1/secret`, because that request still has the reading
     * `/app/secret`, which a servlet container serves and the pattern does not
     * name, and allow-AND refuses on any uncovered reading. It is the
     * fail-closed answer, it is visible (the operator is told the request
     * matches no scope.include pattern rather than being quietly allowed), and
     * the remedy is one pattern wide enough to cover both readings --
     * `/app*` here -- because allows() asks a SINGLE rule to cover the whole
     * set and two half-scopes deliberately do not add up. The alternative was
     * measured: `include=/../*` authorising every path on the host.
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
     *  both. Plus its letter-half best-fit fold (see addLetterFold), for the
     *  operator who typed the homoglyph as a literal character rather than as
     *  an escape -- decodeToFixedPoint below is the identity on `s` in that
     *  case, and this method would otherwise return before ever reaching
     *  addSpelling. */
    private static void addSpellings(Set<String> out, String s) {
        out.add(s);
        out.add(lower(s));
        addLetterFold(out, s);
        String decoded = decodeToFixedPoint(s);
        if (decoded.equals(s)) return;
        addSpelling(out, decoded);
        String utf8 = foldOverlongUtf8(decoded);
        if (!utf8.equals(decoded)) addSpelling(out, utf8);
        String inert = decodeSeparatorsInert(s);
        if (!inert.equals(decoded)) addSpelling(out, inert);
    }

    /**
     * One DERIVED spelling of an allow pattern: case-folded always, and
     * verbatim as well when it is ASCII.
     *
     * The pattern the operator typed is held verbatim by addSpellings above;
     * everything decoding produces from it was held ONLY case-folded, and that
     * was the exact failure patternReadings exists to prevent, one axis along:
     *
     *   include=.../files/A%2eB/*     refused  /files/A.B/x
     *   include=.../files/My%20Docs/* refused  /files/My Docs/x
     *
     * while the all-lowercase spellings of both were allowed. Rule.allows
     * compares the path's RAW reading without folding case -- deliberately,
     * because folding case on the one rule that authorises anything widens it
     * -- so `/files/A.B/x` has an uppercase reading that a set holding only
     * `/files/a.b/*` cannot cover, and allow-AND refuses on it. The operator is
     * told their request "matches no scope.include pattern", which sends them
     * to rewrite a pattern that was right.
     *
     * ASCII ONLY, and that is the whole of the condition. Adding every decoded
     * spelling verbatim would put MOJIBAKE in the set: decodeToFixedPoint of
     * `/files/caf%c3%a9/*` ends in the two Latin-1 characters U+00C3 U+00A9,
     * which is not a spelling of anything -- the character the request names
     * is the UTF-8 fold one line down. PolicyTest pins its absence, and that
     * pin is older than this method. An ASCII decoded form has no such second
     * reading: what it says is what a matcher will compare.
     *
     * It cannot widen the rule structurally either. Every string it adds is
     * the case-variant of one the set already held, so it matches a SUBSET of
     * what lower(s) matches once both sides are folded -- and the only side
     * that is not folded is the path's raw reading, which is the reading this
     * exists to cover.
     *
     * Since Round 9 it also adds the letter-half best-fit fold of `s` (see
     * addLetterFold), which is what covers an operator who typed the
     * homoglyph as a percent-escape -- `include=.../p%c5%82atnosci/*` --
     * rather than as a literal character: `s` here is decodeToFixedPoint's or
     * foldOverlongUtf8's output, so the fold reaches it exactly where
     * addSpellings' own call reaches the literal spelling.
     */
    private static void addSpelling(Set<String> out, String s) {
        out.add(lower(s));
        if (isAscii(s)) out.add(s);
        addLetterFold(out, s);
    }

    /**
     * The letter-half best-fit spelling of `s` (see foldBestFitLetters),
     * added case-folded always and verbatim when the fold left nothing but
     * ASCII behind -- the same two rules addSpelling applies to a decoded
     * spelling, because this is that same kind of derived spelling and not
     * the operator's own text.
     *
     * A no-op whenever `s` carries none of the 276 code points, which is
     * every ASCII pattern and every pattern in a script the table does not
     * cover -- so the whole of Cyrillic, CJK and Latin-1 costs this method one
     * scan and nothing more.
     */
    private static void addLetterFold(Set<String> out, String s) {
        String letters = foldBestFitLetters(s);
        if (letters.equals(s)) return;
        out.add(lower(letters));
        if (isAscii(letters)) out.add(letters);
    }

    /** Whether every character is ASCII -- asked about a DECODED string, where
     *  a non-ASCII character means the decode produced bytes rather than
     *  text. */
    private static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++)
            if (s.charAt(i) >= 0x80) return false;
        return true;
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

    /**
     * Whether trimSegmentTails() would change this path -- exactly the
     * condition under which it is not the identity, including the dot segments
     * it deliberately leaves alone.
     *
     * `i > start` is what keeps `charAt(i - 1)` off the character before an
     * EMPTY segment, and the only shape that needs it is a segment of exactly
     * one trimmable character. Weakened to `i > start + 1` it leaves every
     * check in PolicyTest green while `/a/%20/b/leaf` and `/a/%00/b/leaf` walk
     * past `exclude=/a/b/*` -- Windows trims the one-character name away and
     * serves `/a/b/leaf`, and the NUL truncation reading does not save it
     * because that reading is `/a`, which the exclusion does not name. Every
     * other trimmable path in the suite carries a NAME in front of the
     * trimmable character, which is why the weakening used to be free. See
     * aSegmentOfNothingButASpaceOrANulIsStillTrimmed.
     */
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
     * The Windows ANSI best-fit mapping, over the characters that change what
     * a path SAYS.
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
     * THE TABLE IS NOT DRAWN BY HAND ANY MORE, and the reason is a measurement
     * rather than a preference. It was drawn by hand twice. Each subset was
     * argued for in this comment, each argument was reasonable, and each left
     * a live bypass of the denylist this tool ships:
     *
     *   13 entries, "the separator-producing ones only":
     *       /account/l(U+FF0F)gout       ALLOW -- a real logout
     *   105 entries, the whole fullwidth block plus eleven homoglyphs:
     *       /account/(U+0142)ogout       ALLOW -- `l` with a stroke
     *       /account/l(U+014D)gout       ALLOW -- `o` with a macron
     *       /i.php?action=lo(U+0261)out  ALLOW -- a script `g`
     *       /(U+0101)dmin/users          ALLOW past exclude=/admin/*
     *       /adm(U+0131)n/users          ALLOW past exclude=/admin/*
     *       /(U+03B1)dmin/users          ALLOW past exclude=/admin/*
     *
     * Same file, same substitution, same threat model as the fullwidth block
     * the round before: 392 of bestfit1252.txt's 698 entries land on ASCII
     * 0x20..0x7E -- 384 of them on 0x21..0x7E and 8 more on the space -- and
     * the hand-drawn table held 99 of the 392. So the table is now EMITTED
     * from the vendor file -- see bestFit -- and the only judgement left in it
     * is a filter anyone can re-run.
     *
     * THE COST WAS REAL, measured before Round 9 ruled on it rather than
     * argued about after. A best-fit reading belonged to a PATH and to a DENY
     * pattern, never to an ALLOW pattern, so an include that CARRIED a folded
     * code point authorised nothing: the request kept the folded reading and
     * the pattern could not name it. With the fullwidth block that cost was
     * theoretical -- nobody's scope file is spelt in fullwidth. With the
     * whole table it was not, because 276 of 398 entries fold to a letter or a
     * digit:
     *
     *   include=.../p(U+0142)atno(U+015B)ci/*   authorised NOTHING
     *   include=.../kullan(U+0131)c(U+0131)/*   authorised NOTHING
     *   include=.../p(U+0159)istup/*            authorised NOTHING
     *
     * Polish, Turkish, Czech, Slovak, Hungarian, Romanian, Baltic and part of
     * Greek. RULED IN: those 276 entries -- foldBestFitLetters, just above --
     * are now part of spellingReadings, so all three authorise their own
     * request. The other 122, the ones that manufacture a `/`, a `\`, a `.`, a
     * `;`, a `%` or a `*`, stayed exactly where they were: foldBestFit still
     * folds them for a PATH and for a DENY pattern, and spellingReadings still
     * does not. See spellingReadings for the argument the split rests on.
     *
     * The rule is still exact rather than per-language: an include's own text
     * needed the fold when a code point in the LETTER half appeared in it, and
     * not otherwise. So Czech `/p(U+0159)istup/*` needed it and has it now,
     * while `/u(U+017E)ivatel/*` never needed one -- U+017E is a character
     * 1252 can already spell. The whole Latin-1 supplement is in that second
     * group, so Spanish, French, German, Portuguese and Italian scopes were
     * never touched, and neither were Cyrillic or CJK ones. Nor is a scope
     * anchored at an ASCII prefix affected -- `/files/*` authorises a folded
     * filename under it either way, because the fold changes a NAME and not
     * the prefix.
     *
     * THE ACCEPTED COST, taken knowingly rather than found later: an include
     * spelt with a letter homoglyph now authorises the plain spelling too --
     * `include=/(fullwidth a)dmin/*` also authorises `/admin/*`, which is the
     * `include=/../*` failure with a homoglyph standing in for a dot segment.
     * It widens one NAME to one name and never a directory to the whole host,
     * because a letter fold cannot add a `/` or a `*`. See the include-cost
     * table in PolicyTest, which pins every row of this paragraph in both
     * directions, and the round report, where the ruling is recorded.
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

    /**
     * Whether a best-fit TARGET character is a letter or a digit --
     * `[0-9A-Za-z]` -- rather than punctuation, a separator, or the space this
     * table also folds. Asked of what bestFit() RETURNS, not of a second list
     * of code points: that is what makes the split below DERIVED from the
     * table rather than drawn a third time by hand, which is the mistake this
     * whole file exists to stop making.
     */
    private static boolean isLetterOrDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /**
     * foldBestFit, restricted to the 276 of 398 entries whose TARGET is a
     * letter or a digit. This is the half Round 9 ruled an ALLOW pattern may
     * use -- see spellingReadings and addSpellings -- because it is 1:1 on
     * characters: it substitutes one letter for another and cannot split a
     * segment, cannot merge two, and cannot manufacture a `/`, a `\`, a `.`, a
     * `;`, a `%` or a `*`. U+FF0F still does not become a `/` here and U+FF0A
     * still does not become a `*`; foldBestFit is what folds those, and it
     * stays the only one of the two an ALLOW pattern is never read by.
     *
     * The filter is on bestFit()'s OUTPUT for each character in `s`, not on a
     * second table of code points, so this cannot drift from foldBestFit the
     * way a hand-copied subset could.
     */
    static String foldBestFitLetters(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) < 0x80) i++;
        if (i == s.length()) return s;                  // pure ASCII: nothing to fit
        StringBuilder out = null;
        for (; i < s.length(); i++) {
            char c = s.charAt(i);
            char fit = bestFit(c);
            if (fit == c || !isLetterOrDigit(fit)) continue;
            if (out == null) out = new StringBuilder(s);
            out.setCharAt(i, fit);
        }
        return out == null ? s : out.toString();
    }

    /**
     * One code point, as WideCharToMultiByte would spell it in code page 1252.
     *
     * GENERATED, not curated. Every WCTABLE entry of Microsoft's own
     * bestfit1252.txt whose source is non-ASCII and whose target is 0x20..0x7E
     * -- 392 of its 698 -- plus six homoglyphs of path syntax that file does
     * not cover. 398 cases, one line each, carrying the vendor's own name for
     * the code point, so an entry cannot be dropped silently and cannot be
     * added without saying where it came from:
     *
     *   python3 extension/tools/bestfit_table.py --emit    # the block below
     *   python3 extension/tools/bestfit_table.py --check   # verify this file
     *
     * That script holds the URL, the sha256 of the exact file the block was
     * generated from, the filter, and the six supplements with a reason each.
     * It is an author's tool: nothing imports it, the build does not run it,
     * and the shipped extension still has no dependency and no network.
     *
     * THE SIX SUPPLEMENTS are U+29F8, U+FE68, U+FE52, U+FF61, U+2024 and
     * U+FE54, and they are labelled in the block. The comment they replace
     * said they were "best fits in other code pages' tables". That was FALSE,
     * and it was checked rather than re-argued: none of the six best-fits to
     * printable ASCII in the WCTABLE of bestfit932, 936, 949, 950, 874,
     * 1250-1258 or 10000 either. They stay because a best-fit reading of a
     * PATH only ever denies more and they are homoglyphs of `/`, a backslash,
     * `.` and `;`. U+2024 is the sharpest: bestfit1252 DOES map it, to 0xB7
     * MIDDLE DOT, and folding it to `.` is this class's judgement rather than
     * the vendor's.
     *
     * SPACE IS IN THE FILTER, which is 8 entries -- the quad and em spaces and
     * U+3000 IDEOGRAPHIC SPACE. Windows trims a trailing space from a name, so
     * `/a/(U+3000)/b/leaf` reads as `/a/b/leaf` and an exclusion on `/a/b/*`
     * has to see it. (bestfit1252 maps them to 0x20, so this is the file's
     * judgement and not ours.)
     *
     * KNOWN LIMIT, stated rather than left to be found: 1252 is the ANSI code
     * page of a Windows host installed for a Western locale. A Japanese host
     * is 932 and a Chinese one 936, and their tables are larger -- the union
     * over the fifteen named above is 530 code points against this file's 392.
     * Folding that union would map much of CJK onto ASCII and refuse any CJK
     * scope outright, so it is not done, and against a CJK Windows estate this
     * fold is a SUBSET of what the target will do.
     *
     * Hex sources rather than character literals: these are homoglyphs, and a
     * reader has no way to tell them apart in a source file.
     *
     * The two bounds are the table's own first and last entry, so the entire
     * Latin-1 supplement -- every accented character a Western European path
     * actually carries -- leaves in two comparisons.
     */
    private static char bestFit(char c) {
        if (c < 0x0100 || c > 0xff61) return c;
        switch (c) {
            // ---- GENERATED from bestfit1252.txt; see bestfit_table.py ----
            case 0x0100: return 'A';  // LATIN CAPITAL LETTER A WITH MACRON
            case 0x0101: return 'a';  // LATIN SMALL LETTER A WITH MACRON
            case 0x0102: return 'A';  // LATIN CAPITAL LETTER A WITH BREVE
            case 0x0103: return 'a';  // LATIN SMALL LETTER A WITH BREVE
            case 0x0104: return 'A';  // LATIN CAPITAL LETTER A WITH OGONEK
            case 0x0105: return 'a';  // LATIN SMALL LETTER A WITH OGONEK
            case 0x0106: return 'C';  // LATIN CAPITAL LETTER C WITH ACUTE
            case 0x0107: return 'c';  // LATIN SMALL LETTER C WITH ACUTE
            case 0x0108: return 'C';  // LATIN CAPITAL LETTER C WITH CIRCUMFLEX
            case 0x0109: return 'c';  // LATIN SMALL LETTER C WITH CIRCUMFLEX
            case 0x010a: return 'C';  // LATIN CAPITAL LETTER C WITH DOT ABOVE
            case 0x010b: return 'c';  // LATIN SMALL LETTER C WITH DOT ABOVE
            case 0x010c: return 'C';  // LATIN CAPITAL LETTER C WITH CARON
            case 0x010d: return 'c';  // LATIN SMALL LETTER C WITH CARON
            case 0x010e: return 'D';  // LATIN CAPITAL LETTER D WITH CARON
            case 0x010f: return 'd';  // LATIN SMALL LETTER D WITH CARON
            case 0x0111: return 'd';  // LATIN SMALL LETTER D WITH STROKE
            case 0x0112: return 'E';  // LATIN CAPITAL LETTER E WITH MACRON
            case 0x0113: return 'e';  // LATIN SMALL LETTER E WITH MACRON
            case 0x0114: return 'E';  // LATIN CAPITAL LETTER E WITH BREVE
            case 0x0115: return 'e';  // LATIN SMALL LETTER E WITH BREVE
            case 0x0116: return 'E';  // LATIN CAPITAL LETTER E WITH DOT ABOVE
            case 0x0117: return 'e';  // LATIN SMALL LETTER E WITH DOT ABOVE
            case 0x0118: return 'E';  // LATIN CAPITAL LETTER E WITH OGONEK
            case 0x0119: return 'e';  // LATIN SMALL LETTER E WITH OGONEK
            case 0x011a: return 'E';  // LATIN CAPITAL LETTER E WITH CARON
            case 0x011b: return 'e';  // LATIN SMALL LETTER E WITH CARON
            case 0x011c: return 'G';  // LATIN CAPITAL LETTER G WITH CIRCUMFLEX
            case 0x011d: return 'g';  // LATIN SMALL LETTER G WITH CIRCUMFLEX
            case 0x011e: return 'G';  // LATIN CAPITAL LETTER G WITH BREVE
            case 0x011f: return 'g';  // LATIN SMALL LETTER G WITH BREVE
            case 0x0120: return 'G';  // LATIN CAPITAL LETTER G WITH DOT ABOVE
            case 0x0121: return 'g';  // LATIN SMALL LETTER G WITH DOT ABOVE
            case 0x0122: return 'G';  // LATIN CAPITAL LETTER G WITH CEDILLA
            case 0x0123: return 'g';  // LATIN SMALL LETTER G WITH CEDILLA
            case 0x0124: return 'H';  // LATIN CAPITAL LETTER H WITH CIRCUMFLEX
            case 0x0125: return 'h';  // LATIN SMALL LETTER H WITH CIRCUMFLEX
            case 0x0126: return 'H';  // LATIN CAPITAL LETTER H WITH STROKE
            case 0x0127: return 'h';  // LATIN SMALL LETTER H WITH STROKE
            case 0x0128: return 'I';  // LATIN CAPITAL LETTER I WITH TILDE
            case 0x0129: return 'i';  // LATIN SMALL LETTER I WITH TILDE
            case 0x012a: return 'I';  // LATIN CAPITAL LETTER I WITH MACRON
            case 0x012b: return 'i';  // LATIN SMALL LETTER I WITH MACRON
            case 0x012c: return 'I';  // LATIN CAPITAL LETTER I WITH BREVE
            case 0x012d: return 'i';  // LATIN SMALL LETTER I WITH BREVE
            case 0x012e: return 'I';  // LATIN CAPITAL LETTER I WITH OGONEK
            case 0x012f: return 'i';  // LATIN SMALL LETTER I WITH OGONEK
            case 0x0130: return 'I';  // LATIN CAPITAL LETTER I WITH DOT ABOVE
            case 0x0131: return 'i';  // LATIN SMALL LETTER DOTLESS I
            case 0x0134: return 'J';  // LATIN CAPITAL LETTER J WITH CIRCUMFLEX
            case 0x0135: return 'j';  // LATIN SMALL LETTER J WITH CIRCUMFLEX
            case 0x0136: return 'K';  // LATIN CAPITAL LETTER K WITH CEDILLA
            case 0x0137: return 'k';  // LATIN SMALL LETTER K WITH CEDILLA
            case 0x0139: return 'L';  // LATIN CAPITAL LETTER L WITH ACUTE
            case 0x013a: return 'l';  // LATIN SMALL LETTER L WITH ACUTE
            case 0x013b: return 'L';  // LATIN CAPITAL LETTER L WITH CEDILLA
            case 0x013c: return 'l';  // LATIN SMALL LETTER L WITH CEDILLA
            case 0x013d: return 'L';  // LATIN CAPITAL LETTER L WITH CARON
            case 0x013e: return 'l';  // LATIN SMALL LETTER L WITH CARON
            case 0x0141: return 'L';  // LATIN CAPITAL LETTER L WITH STROKE
            case 0x0142: return 'l';  // LATIN SMALL LETTER L WITH STROKE
            case 0x0143: return 'N';  // LATIN CAPITAL LETTER N WITH ACUTE
            case 0x0144: return 'n';  // LATIN SMALL LETTER N WITH ACUTE
            case 0x0145: return 'N';  // LATIN CAPITAL LETTER N WITH CEDILLA
            case 0x0146: return 'n';  // LATIN SMALL LETTER N WITH CEDILLA
            case 0x0147: return 'N';  // LATIN CAPITAL LETTER N WITH CARON
            case 0x0148: return 'n';  // LATIN SMALL LETTER N WITH CARON
            case 0x014c: return 'O';  // LATIN CAPITAL LETTER O WITH MACRON
            case 0x014d: return 'o';  // LATIN SMALL LETTER O WITH MACRON
            case 0x014e: return 'O';  // LATIN CAPITAL LETTER O WITH BREVE
            case 0x014f: return 'o';  // LATIN SMALL LETTER O WITH BREVE
            case 0x0150: return 'O';  // LATIN CAPITAL LETTER O WITH DOUBLE ACUTE
            case 0x0151: return 'o';  // LATIN SMALL LETTER O WITH DOUBLE ACUTE
            case 0x0154: return 'R';  // LATIN CAPITAL LETTER R WITH ACUTE
            case 0x0155: return 'r';  // LATIN SMALL LETTER R WITH ACUTE
            case 0x0156: return 'R';  // LATIN CAPITAL LETTER R WITH CEDILLA
            case 0x0157: return 'r';  // LATIN SMALL LETTER R WITH CEDILLA
            case 0x0158: return 'R';  // LATIN CAPITAL LETTER R WITH CARON
            case 0x0159: return 'r';  // LATIN SMALL LETTER R WITH CARON
            case 0x015a: return 'S';  // LATIN CAPITAL LETTER S WITH ACUTE
            case 0x015b: return 's';  // LATIN SMALL LETTER S WITH ACUTE
            case 0x015c: return 'S';  // LATIN CAPITAL LETTER S WITH CIRCUMFLEX
            case 0x015d: return 's';  // LATIN SMALL LETTER S WITH CIRCUMFLEX
            case 0x015e: return 'S';  // LATIN CAPITAL LETTER S WITH CEDILLA
            case 0x015f: return 's';  // LATIN SMALL LETTER S WITH CEDILLA
            case 0x0162: return 'T';  // LATIN CAPITAL LETTER T WITH CEDILLA
            case 0x0163: return 't';  // LATIN SMALL LETTER T WITH CEDILLA
            case 0x0164: return 'T';  // LATIN CAPITAL LETTER T WITH CARON
            case 0x0165: return 't';  // LATIN SMALL LETTER T WITH CARON
            case 0x0166: return 'T';  // LATIN CAPITAL LETTER T WITH STROKE
            case 0x0167: return 't';  // LATIN SMALL LETTER T WITH STROKE
            case 0x0168: return 'U';  // LATIN CAPITAL LETTER U WITH TILDE
            case 0x0169: return 'u';  // LATIN SMALL LETTER U WITH TILDE
            case 0x016a: return 'U';  // LATIN CAPITAL LETTER U WITH MACRON
            case 0x016b: return 'u';  // LATIN SMALL LETTER U WITH MACRON
            case 0x016c: return 'U';  // LATIN CAPITAL LETTER U WITH BREVE
            case 0x016d: return 'u';  // LATIN SMALL LETTER U WITH BREVE
            case 0x016e: return 'U';  // LATIN CAPITAL LETTER U WITH RING ABOVE
            case 0x016f: return 'u';  // LATIN SMALL LETTER U WITH RING ABOVE
            case 0x0170: return 'U';  // LATIN CAPITAL LETTER U WITH DOUBLE ACUTE
            case 0x0171: return 'u';  // LATIN SMALL LETTER U WITH DOUBLE ACUTE
            case 0x0172: return 'U';  // LATIN CAPITAL LETTER U WITH OGONEK
            case 0x0173: return 'u';  // LATIN SMALL LETTER U WITH OGONEK
            case 0x0174: return 'W';  // LATIN CAPITAL LETTER W WITH CIRCUMFLEX
            case 0x0175: return 'w';  // LATIN SMALL LETTER W WITH CIRCUMFLEX
            case 0x0176: return 'Y';  // LATIN CAPITAL LETTER Y WITH CIRCUMFLEX
            case 0x0177: return 'y';  // LATIN SMALL LETTER Y WITH CIRCUMFLEX
            case 0x0179: return 'Z';  // LATIN CAPITAL LETTER Z WITH ACUTE
            case 0x017a: return 'z';  // LATIN SMALL LETTER Z WITH ACUTE
            case 0x017b: return 'Z';  // LATIN CAPITAL LETTER Z WITH DOT ABOVE
            case 0x017c: return 'z';  // LATIN SMALL LETTER Z WITH DOT ABOVE
            case 0x0180: return 'b';  // LATIN SMALL LETTER B WITH STROKE
            case 0x0197: return 'I';  // LATIN CAPITAL LETTER I WITH STROKE
            case 0x019a: return 'l';  // LATIN SMALL LETTER L WITH BAR
            case 0x019f: return 'O';  // LATIN CAPITAL LETTER O WITH MIDDLE TILDE
            case 0x01a0: return 'O';  // LATIN CAPITAL LETTER O WITH HORN
            case 0x01a1: return 'o';  // LATIN SMALL LETTER O WITH HORN
            case 0x01ab: return 't';  // LATIN SMALL LETTER T WITH PALATAL HOOK
            case 0x01ae: return 'T';  // LATIN CAPITAL LETTER T WITH RETROFLEX HOOK
            case 0x01af: return 'U';  // LATIN CAPITAL LETTER U WITH HORN
            case 0x01b0: return 'u';  // LATIN SMALL LETTER U WITH HORN
            case 0x01b6: return 'z';  // LATIN SMALL LETTER Z WITH STROKE
            case 0x01c0: return '|';  // LATIN LETTER DENTAL CLICK
            case 0x01c3: return '!';  // LATIN LETTER RETROFLEX CLICK
            case 0x01cd: return 'A';  // LATIN CAPITAL LETTER A WITH CARON
            case 0x01ce: return 'a';  // LATIN SMALL LETTER A WITH CARON
            case 0x01cf: return 'I';  // LATIN CAPITAL LETTER I WITH CARON
            case 0x01d0: return 'i';  // LATIN SMALL LETTER I WITH CARON
            case 0x01d1: return 'O';  // LATIN CAPITAL LETTER O WITH CARON
            case 0x01d2: return 'o';  // LATIN SMALL LETTER O WITH CARON
            case 0x01d3: return 'U';  // LATIN CAPITAL LETTER U WITH CARON
            case 0x01d4: return 'u';  // LATIN SMALL LETTER U WITH CARON
            case 0x01d5: return 'U';  // LATIN CAPITAL LETTER U WITH DIAERESIS AND MACRON
            case 0x01d6: return 'u';  // LATIN SMALL LETTER U WITH DIAERESIS AND MACRON
            case 0x01d7: return 'U';  // LATIN CAPITAL LETTER U WITH DIAERESIS AND ACUTE
            case 0x01d8: return 'u';  // LATIN SMALL LETTER U WITH DIAERESIS AND ACUTE
            case 0x01d9: return 'U';  // LATIN CAPITAL LETTER U WITH DIAERESIS AND CARON
            case 0x01da: return 'u';  // LATIN SMALL LETTER U WITH DIAERESIS AND CARON
            case 0x01db: return 'U';  // LATIN CAPITAL LETTER U WITH DIAERESIS AND GRAVE
            case 0x01dc: return 'u';  // LATIN SMALL LETTER U WITH DIAERESIS AND GRAVE
            case 0x01de: return 'A';  // LATIN CAPITAL LETTER A WITH DIAERESIS AND MACRON
            case 0x01df: return 'a';  // LATIN SMALL LETTER A WITH DIAERESIS AND MACRON
            case 0x01e4: return 'G';  // LATIN CAPITAL LETTER G WITH STROKE
            case 0x01e5: return 'g';  // LATIN SMALL LETTER G WITH STROKE
            case 0x01e6: return 'G';  // LATIN CAPITAL LETTER G WITH CARON
            case 0x01e7: return 'g';  // LATIN SMALL LETTER G WITH CARON
            case 0x01e8: return 'K';  // LATIN CAPITAL LETTER K WITH CARON
            case 0x01e9: return 'k';  // LATIN SMALL LETTER K WITH CARON
            case 0x01ea: return 'O';  // LATIN CAPITAL LETTER O WITH OGONEK
            case 0x01eb: return 'o';  // LATIN SMALL LETTER O WITH OGONEK
            case 0x01ec: return 'O';  // LATIN CAPITAL LETTER O WITH OGONEK AND MACRON
            case 0x01ed: return 'o';  // LATIN SMALL LETTER O WITH OGONEK AND MACRON
            case 0x01f0: return 'j';  // LATIN SMALL LETTER J WITH CARON
            case 0x0261: return 'g';  // LATIN SMALL LETTER SCRIPT G
            case 0x02b9: return '\'';  // MODIFIER LETTER PRIME
            case 0x02ba: return '"';  // MODIFIER LETTER DOUBLE PRIME
            case 0x02bc: return '\'';  // MODIFIER LETTER APOSTROPHE
            case 0x02c4: return '^';  // MODIFIER LETTER UP ARROWHEAD
            case 0x02c8: return '\'';  // MODIFIER LETTER VERTICAL LINE
            case 0x02cb: return '`';  // MODIFIER LETTER GRAVE ACCENT
            case 0x02cd: return '_';  // MODIFIER LETTER LOW MACRON
            case 0x0300: return '`';  // COMBINING GRAVE ACCENT
            case 0x0302: return '^';  // COMBINING CIRCUMFLEX ACCENT
            case 0x0303: return '~';  // COMBINING TILDE
            case 0x030e: return '"';  // COMBINING DOUBLE VERTICAL LINE ABOVE
            case 0x0331: return '_';  // COMBINING MACRON BELOW
            case 0x0332: return '_';  // COMBINING LOW LINE
            case 0x037e: return ';';  // GREEK QUESTION MARK
            case 0x0393: return 'G';  // GREEK CAPITAL LETTER GAMMA
            case 0x0398: return 'T';  // GREEK CAPITAL LETTER THETA
            case 0x03a3: return 'S';  // GREEK CAPITAL LETTER SIGMA
            case 0x03a6: return 'F';  // GREEK CAPITAL LETTER PHI
            case 0x03a9: return 'O';  // GREEK CAPITAL LETTER OMEGA
            case 0x03b1: return 'a';  // GREEK SMALL LETTER ALPHA
            case 0x03b4: return 'd';  // GREEK SMALL LETTER DELTA
            case 0x03b5: return 'e';  // GREEK SMALL LETTER EPSILON
            case 0x03c0: return 'p';  // GREEK SMALL LETTER PI
            case 0x03c3: return 's';  // GREEK SMALL LETTER SIGMA
            case 0x03c4: return 't';  // GREEK SMALL LETTER TAU
            case 0x03c6: return 'f';  // GREEK SMALL LETTER PHI
            case 0x04bb: return 'h';  // CYRILLIC SMALL LETTER SHHA
            case 0x0589: return ':';  // ARMENIAN FULL STOP
            case 0x066a: return '%';  // ARABIC PERCENT SIGN
            case 0x2000: return ' ';  // EN QUAD
            case 0x2001: return ' ';  // EM QUAD
            case 0x2002: return ' ';  // EN SPACE
            case 0x2003: return ' ';  // EM SPACE
            case 0x2004: return ' ';  // THREE-PER-EM SPACE
            case 0x2005: return ' ';  // FOUR-PER-EM SPACE
            case 0x2006: return ' ';  // SIX-PER-EM SPACE
            case 0x2010: return '-';  // HYPHEN
            case 0x2011: return '-';  // NON-BREAKING HYPHEN
            case 0x2017: return '=';  // DOUBLE LOW LINE
            case 0x2024: return '.';  // ONE DOT LEADER (bestfit1252 says MIDDLE DOT)  [not in any Microsoft table]
            case 0x2032: return '\'';  // PRIME
            case 0x2035: return '`';  // REVERSED PRIME
            case 0x2044: return '/';  // FRACTION SLASH
            case 0x2074: return '4';  // SUPERSCRIPT FOUR
            case 0x2075: return '5';  // SUPERSCRIPT FIVE
            case 0x2076: return '6';  // SUPERSCRIPT SIX
            case 0x2077: return '7';  // SUPERSCRIPT SEVEN
            case 0x2078: return '8';  // SUPERSCRIPT EIGHT
            case 0x207f: return 'n';  // SUPERSCRIPT LATIN SMALL LETTER N
            case 0x2080: return '0';  // SUBSCRIPT ZERO
            case 0x2081: return '1';  // SUBSCRIPT ONE
            case 0x2082: return '2';  // SUBSCRIPT TWO
            case 0x2083: return '3';  // SUBSCRIPT THREE
            case 0x2084: return '4';  // SUBSCRIPT FOUR
            case 0x2085: return '5';  // SUBSCRIPT FIVE
            case 0x2086: return '6';  // SUBSCRIPT SIX
            case 0x2087: return '7';  // SUBSCRIPT SEVEN
            case 0x2088: return '8';  // SUBSCRIPT EIGHT
            case 0x2089: return '9';  // SUBSCRIPT NINE
            case 0x20a7: return 'P';  // PESETA SIGN
            case 0x2102: return 'C';  // DOUBLE-STRUCK CAPITAL C
            case 0x2107: return 'E';  // EULER CONSTANT
            case 0x210a: return 'g';  // SCRIPT SMALL G
            case 0x210b: return 'H';  // SCRIPT CAPITAL H
            case 0x210c: return 'H';  // BLACK-LETTER CAPITAL H
            case 0x210d: return 'H';  // DOUBLE-STRUCK CAPITAL H
            case 0x210e: return 'h';  // PLANCK CONSTANT
            case 0x2110: return 'I';  // SCRIPT CAPITAL I
            case 0x2111: return 'I';  // BLACK-LETTER CAPITAL I
            case 0x2112: return 'L';  // SCRIPT CAPITAL L
            case 0x2113: return 'l';  // SCRIPT SMALL L
            case 0x2115: return 'N';  // DOUBLE-STRUCK CAPITAL N
            case 0x2118: return 'P';  // SCRIPT CAPITAL P
            case 0x2119: return 'P';  // DOUBLE-STRUCK CAPITAL P
            case 0x211a: return 'Q';  // DOUBLE-STRUCK CAPITAL Q
            case 0x211b: return 'R';  // SCRIPT CAPITAL R
            case 0x211c: return 'R';  // BLACK-LETTER CAPITAL R
            case 0x211d: return 'R';  // DOUBLE-STRUCK CAPITAL R
            case 0x2124: return 'Z';  // DOUBLE-STRUCK CAPITAL Z
            case 0x2128: return 'Z';  // BLACK-LETTER CAPITAL Z
            case 0x212a: return 'K';  // KELVIN SIGN
            case 0x212c: return 'B';  // SCRIPT CAPITAL B
            case 0x212d: return 'C';  // BLACK-LETTER CAPITAL C
            case 0x212e: return 'e';  // ESTIMATED SYMBOL
            case 0x212f: return 'e';  // SCRIPT SMALL E
            case 0x2130: return 'E';  // SCRIPT CAPITAL E
            case 0x2131: return 'F';  // SCRIPT CAPITAL F
            case 0x2133: return 'M';  // SCRIPT CAPITAL M
            case 0x2134: return 'o';  // SCRIPT SMALL O
            case 0x2212: return '-';  // MINUS SIGN
            case 0x2215: return '/';  // DIVISION SLASH
            case 0x2216: return '\\';  // SET MINUS
            case 0x2217: return '*';  // ASTERISK OPERATOR
            case 0x221a: return 'v';  // SQUARE ROOT
            case 0x221e: return '8';  // INFINITY
            case 0x2223: return '|';  // DIVIDES
            case 0x2229: return 'n';  // INTERSECTION
            case 0x2236: return ':';  // RATIO
            case 0x223c: return '~';  // TILDE OPERATOR
            case 0x2261: return '=';  // IDENTICAL TO
            case 0x2264: return '=';  // LESS-THAN OR EQUAL TO
            case 0x2265: return '=';  // GREATER-THAN OR EQUAL TO
            case 0x2303: return '^';  // UP ARROWHEAD
            case 0x2320: return '(';  // TOP HALF INTEGRAL
            case 0x2321: return ')';  // BOTTOM HALF INTEGRAL
            case 0x2329: return '<';  // LEFT-POINTING ANGLE BRACKET
            case 0x232a: return '>';  // RIGHT-POINTING ANGLE BRACKET
            case 0x2500: return '-';  // BOX DRAWINGS LIGHT HORIZONTAL
            case 0x250c: return '+';  // BOX DRAWINGS LIGHT DOWN AND RIGHT
            case 0x2510: return '+';  // BOX DRAWINGS LIGHT DOWN AND LEFT
            case 0x2514: return '+';  // BOX DRAWINGS LIGHT UP AND RIGHT
            case 0x2518: return '+';  // BOX DRAWINGS LIGHT UP AND LEFT
            case 0x251c: return '+';  // BOX DRAWINGS LIGHT VERTICAL AND RIGHT
            case 0x252c: return '-';  // BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
            case 0x2534: return '-';  // BOX DRAWINGS LIGHT UP AND HORIZONTAL
            case 0x253c: return '+';  // BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
            case 0x2550: return '-';  // BOX DRAWINGS DOUBLE HORIZONTAL
            case 0x2552: return '+';  // BOX DRAWINGS DOWN SINGLE AND RIGHT DOUBLE
            case 0x2553: return '+';  // BOX DRAWINGS DOWN DOUBLE AND RIGHT SINGLE
            case 0x2554: return '+';  // BOX DRAWINGS DOUBLE DOWN AND RIGHT
            case 0x2555: return '+';  // BOX DRAWINGS DOWN SINGLE AND LEFT DOUBLE
            case 0x2556: return '+';  // BOX DRAWINGS DOWN DOUBLE AND LEFT SINGLE
            case 0x2557: return '+';  // BOX DRAWINGS DOUBLE DOWN AND LEFT
            case 0x2558: return '+';  // BOX DRAWINGS UP SINGLE AND RIGHT DOUBLE
            case 0x2559: return '+';  // BOX DRAWINGS UP DOUBLE AND RIGHT SINGLE
            case 0x255a: return '+';  // BOX DRAWINGS DOUBLE UP AND RIGHT
            case 0x255b: return '+';  // BOX DRAWINGS UP SINGLE AND LEFT DOUBLE
            case 0x255c: return '+';  // BOX DRAWINGS UP DOUBLE AND LEFT SINGLE
            case 0x255d: return '+';  // BOX DRAWINGS DOUBLE UP AND LEFT
            case 0x2564: return '-';  // BOX DRAWINGS DOWN SINGLE AND HORIZONTAL DOUBLE
            case 0x2565: return '-';  // BOX DRAWINGS DOWN DOUBLE AND HORIZONTAL SINGLE
            case 0x2566: return '-';  // BOX DRAWINGS DOUBLE DOWN AND HORIZONTAL
            case 0x2567: return '-';  // BOX DRAWINGS UP SINGLE AND HORIZONTAL DOUBLE
            case 0x2568: return '-';  // BOX DRAWINGS UP DOUBLE AND HORIZONTAL SINGLE
            case 0x2569: return '-';  // BOX DRAWINGS DOUBLE UP AND HORIZONTAL
            case 0x256a: return '+';  // BOX DRAWINGS VERTICAL SINGLE AND HORIZONTAL DOUBLE
            case 0x256b: return '+';  // BOX DRAWINGS VERTICAL DOUBLE AND HORIZONTAL SINGLE
            case 0x256c: return '+';  // BOX DRAWINGS DOUBLE VERTICAL AND HORIZONTAL
            case 0x2584: return '_';  // LOWER HALF BLOCK
            case 0x2758: return '|';  // LIGHT VERTICAL BAR
            case 0x29f8: return '/';  // BIG SOLIDUS  [not in any Microsoft table]
            case 0x3000: return ' ';  // IDEOGRAPHIC SPACE
            case 0x3008: return '<';  // LEFT ANGLE BRACKET
            case 0x3009: return '>';  // RIGHT ANGLE BRACKET
            case 0x301a: return '[';  // LEFT WHITE SQUARE BRACKET
            case 0x301b: return ']';  // RIGHT WHITE SQUARE BRACKET
            case 0xfe52: return '.';  // SMALL FULL STOP  [not in any Microsoft table]
            case 0xfe54: return ';';  // SMALL SEMICOLON  [not in any Microsoft table]
            case 0xfe68: return '\\';  // SMALL REVERSE SOLIDUS  [not in any Microsoft table]
            case 0xff01: return '!';  // FULLWIDTH EXCLAMATION MARK
            case 0xff02: return '"';  // FULLWIDTH QUOTATION MARK
            case 0xff03: return '#';  // FULLWIDTH NUMBER SIGN
            case 0xff04: return '$';  // FULLWIDTH DOLLAR SIGN
            case 0xff05: return '%';  // FULLWIDTH PERCENT SIGN
            case 0xff06: return '&';  // FULLWIDTH AMPERSAND
            case 0xff07: return '\'';  // FULLWIDTH APOSTROPHE
            case 0xff08: return '(';  // FULLWIDTH LEFT PARENTHESIS
            case 0xff09: return ')';  // FULLWIDTH RIGHT PARENTHESIS
            case 0xff0a: return '*';  // FULLWIDTH ASTERISK
            case 0xff0b: return '+';  // FULLWIDTH PLUS SIGN
            case 0xff0c: return ',';  // FULLWIDTH COMMA
            case 0xff0d: return '-';  // FULLWIDTH HYPHEN-MINUS
            case 0xff0e: return '.';  // FULLWIDTH FULL STOP
            case 0xff0f: return '/';  // FULLWIDTH SOLIDUS
            case 0xff10: return '0';  // FULLWIDTH DIGIT ZERO
            case 0xff11: return '1';  // FULLWIDTH DIGIT ONE
            case 0xff12: return '2';  // FULLWIDTH DIGIT TWO
            case 0xff13: return '3';  // FULLWIDTH DIGIT THREE
            case 0xff14: return '4';  // FULLWIDTH DIGIT FOUR
            case 0xff15: return '5';  // FULLWIDTH DIGIT FIVE
            case 0xff16: return '6';  // FULLWIDTH DIGIT SIX
            case 0xff17: return '7';  // FULLWIDTH DIGIT SEVEN
            case 0xff18: return '8';  // FULLWIDTH DIGIT EIGHT
            case 0xff19: return '9';  // FULLWIDTH DIGIT NINE
            case 0xff1a: return ':';  // FULLWIDTH COLON
            case 0xff1b: return ';';  // FULLWIDTH SEMICOLON
            case 0xff1c: return '<';  // FULLWIDTH LESS-THAN SIGN
            case 0xff1d: return '=';  // FULLWIDTH EQUALS SIGN
            case 0xff1e: return '>';  // FULLWIDTH GREATER-THAN SIGN
            case 0xff1f: return '?';  // FULLWIDTH QUESTION MARK
            case 0xff20: return '@';  // FULLWIDTH COMMERCIAL AT
            case 0xff21: return 'A';  // FULLWIDTH LATIN CAPITAL LETTER A
            case 0xff22: return 'B';  // FULLWIDTH LATIN CAPITAL LETTER B
            case 0xff23: return 'C';  // FULLWIDTH LATIN CAPITAL LETTER C
            case 0xff24: return 'D';  // FULLWIDTH LATIN CAPITAL LETTER D
            case 0xff25: return 'E';  // FULLWIDTH LATIN CAPITAL LETTER E
            case 0xff26: return 'F';  // FULLWIDTH LATIN CAPITAL LETTER F
            case 0xff27: return 'G';  // FULLWIDTH LATIN CAPITAL LETTER G
            case 0xff28: return 'H';  // FULLWIDTH LATIN CAPITAL LETTER H
            case 0xff29: return 'I';  // FULLWIDTH LATIN CAPITAL LETTER I
            case 0xff2a: return 'J';  // FULLWIDTH LATIN CAPITAL LETTER J
            case 0xff2b: return 'K';  // FULLWIDTH LATIN CAPITAL LETTER K
            case 0xff2c: return 'L';  // FULLWIDTH LATIN CAPITAL LETTER L
            case 0xff2d: return 'M';  // FULLWIDTH LATIN CAPITAL LETTER M
            case 0xff2e: return 'N';  // FULLWIDTH LATIN CAPITAL LETTER N
            case 0xff2f: return 'O';  // FULLWIDTH LATIN CAPITAL LETTER O
            case 0xff30: return 'P';  // FULLWIDTH LATIN CAPITAL LETTER P
            case 0xff31: return 'Q';  // FULLWIDTH LATIN CAPITAL LETTER Q
            case 0xff32: return 'R';  // FULLWIDTH LATIN CAPITAL LETTER R
            case 0xff33: return 'S';  // FULLWIDTH LATIN CAPITAL LETTER S
            case 0xff34: return 'T';  // FULLWIDTH LATIN CAPITAL LETTER T
            case 0xff35: return 'U';  // FULLWIDTH LATIN CAPITAL LETTER U
            case 0xff36: return 'V';  // FULLWIDTH LATIN CAPITAL LETTER V
            case 0xff37: return 'W';  // FULLWIDTH LATIN CAPITAL LETTER W
            case 0xff38: return 'X';  // FULLWIDTH LATIN CAPITAL LETTER X
            case 0xff39: return 'Y';  // FULLWIDTH LATIN CAPITAL LETTER Y
            case 0xff3a: return 'Z';  // FULLWIDTH LATIN CAPITAL LETTER Z
            case 0xff3b: return '[';  // FULLWIDTH LEFT SQUARE BRACKET
            case 0xff3c: return '\\';  // FULLWIDTH REVERSE SOLIDUS
            case 0xff3d: return ']';  // FULLWIDTH RIGHT SQUARE BRACKET
            case 0xff3e: return '^';  // FULLWIDTH CIRCUMFLEX ACCENT
            case 0xff3f: return '_';  // FULLWIDTH LOW LINE
            case 0xff40: return '`';  // FULLWIDTH GRAVE ACCENT
            case 0xff41: return 'a';  // FULLWIDTH LATIN SMALL LETTER A
            case 0xff42: return 'b';  // FULLWIDTH LATIN SMALL LETTER B
            case 0xff43: return 'c';  // FULLWIDTH LATIN SMALL LETTER C
            case 0xff44: return 'd';  // FULLWIDTH LATIN SMALL LETTER D
            case 0xff45: return 'e';  // FULLWIDTH LATIN SMALL LETTER E
            case 0xff46: return 'f';  // FULLWIDTH LATIN SMALL LETTER F
            case 0xff47: return 'g';  // FULLWIDTH LATIN SMALL LETTER G
            case 0xff48: return 'h';  // FULLWIDTH LATIN SMALL LETTER H
            case 0xff49: return 'i';  // FULLWIDTH LATIN SMALL LETTER I
            case 0xff4a: return 'j';  // FULLWIDTH LATIN SMALL LETTER J
            case 0xff4b: return 'k';  // FULLWIDTH LATIN SMALL LETTER K
            case 0xff4c: return 'l';  // FULLWIDTH LATIN SMALL LETTER L
            case 0xff4d: return 'm';  // FULLWIDTH LATIN SMALL LETTER M
            case 0xff4e: return 'n';  // FULLWIDTH LATIN SMALL LETTER N
            case 0xff4f: return 'o';  // FULLWIDTH LATIN SMALL LETTER O
            case 0xff50: return 'p';  // FULLWIDTH LATIN SMALL LETTER P
            case 0xff51: return 'q';  // FULLWIDTH LATIN SMALL LETTER Q
            case 0xff52: return 'r';  // FULLWIDTH LATIN SMALL LETTER R
            case 0xff53: return 's';  // FULLWIDTH LATIN SMALL LETTER S
            case 0xff54: return 't';  // FULLWIDTH LATIN SMALL LETTER T
            case 0xff55: return 'u';  // FULLWIDTH LATIN SMALL LETTER U
            case 0xff56: return 'v';  // FULLWIDTH LATIN SMALL LETTER V
            case 0xff57: return 'w';  // FULLWIDTH LATIN SMALL LETTER W
            case 0xff58: return 'x';  // FULLWIDTH LATIN SMALL LETTER X
            case 0xff59: return 'y';  // FULLWIDTH LATIN SMALL LETTER Y
            case 0xff5a: return 'z';  // FULLWIDTH LATIN SMALL LETTER Z
            case 0xff5b: return '{';  // FULLWIDTH LEFT CURLY BRACKET
            case 0xff5c: return '|';  // FULLWIDTH VERTICAL LINE
            case 0xff5d: return '}';  // FULLWIDTH RIGHT CURLY BRACKET
            case 0xff5e: return '~';  // FULLWIDTH TILDE
            case 0xff61: return '.';  // HALFWIDTH IDEOGRAPHIC FULL STOP  [not in any Microsoft table]
            // ---- END GENERATED ----
            default: return c;
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
     * The query is read by queryReadings, which gives it the BYTE folds the
     * path gets and none of the SEGMENT transforms. The two halves are read
     * separately, and that half of the split is right: a `..` in a query value
     * is a value, a `;` in one is a separator some frameworks still use, and a
     * `%2f` in one is not a path separator the server will ever see.
     *
     * With no query the target IS the path, so the path's readings are the
     * target's -- built once rather than copied.
     */
    private static Set<String> targetReadings(HxRequest req) {
        Set<String> paths = readings(req.path());
        if (req.query().isEmpty()) return paths;
        Set<String> queries = queryReadings(req.query());
        Set<String> out = new LinkedHashSet<>();
        for (String path : paths)
            for (String query : queries)
                out.add(path + "?" + query);
        return out;
    }

    /**
     * Every reading of a QUERY string: the byte folds, closed, and not one of
     * the path transforms.
     *
     * For four rounds this was `{raw, lower(decoded)}` -- two members and no
     * folds at all, while the path half had grown a decoding axis, an overlong
     * UTF-8 fold and a best-fit fold. The same bytes therefore got two
     * different answers from the same denylist, and the class comment's reason
     * for reading the halves separately does not cover it: that reason is about
     * `..`, `;` and `%2f`, which are PATH syntax. A byte fold is not path
     * syntax. It is what the target does to the characters before anything
     * looks at them, and it does it to a query string exactly as readily:
     *
     *   PATH   /account/logo%c1%b5t          dangerous_denied
     *   QUERY  /i.php?action=logo%c1%b5t     ALLOW   <- same overlong `u`
     *   PATH   /x/..(U+FF05)2flogout         dangerous_denied
     *   QUERY  /i.php?action=log(U+FF05)6fut ALLOW   <- same best-fit `%`
     *
     * and the second row of each pair is an automated logout on a legacy
     * application, which is where `?action=logout` lives in the first place.
     *
     * WHAT IS IN THE SET: the closure of the query under decoding to a fixed
     * point, the overlong UTF-8 fold, the best-fit fold and the case fold. The
     * UNDECODED member earns its place for the reason it always did -- a
     * dangerous.path an operator wrote against the bytes, `*=log%6*`, matches
     * `action=log%6fut` and matches nothing once the query is decoded, because
     * `%6f` is gone by then and `%6` was never a whole escape.
     *
     * Case folded, and the query is NOT also held verbatim beside its fold.
     * readings() holds the path verbatim because Rule.allows compares an
     * include against it WITHOUT folding case, and an allow rule must not be
     * widened by one. Nothing reads this set but the dangerous.path pass, which
     * folds both sides itself, so a verbatim member is a member no caller can
     * tell from its fold: I added one, sabotaged it, and it was 0 red because
     * it cannot be otherwise. It is not here rather than here-and-unfalsifiable.
     *
     * CLOSED for the same reason readings() is: the folds COMPOSE, and the
     * best-fit fold in particular MANUFACTURES escapes -- U+FF05 becomes a `%`
     * and the two hex digits after it were already there. One pass of
     * decode-then-fold reaches `log%6fut` and stops; the fixed point decodes it
     * again and reaches `logout`. A flat set would have closed the first row
     * above and left the third open, which is the shape of defect this task has
     * shipped four times.
     *
     * It terminates on the same argument, and the argument is the same shape:
     * decoding replaces three characters with one, the UTF-8 fold replaces two
     * or more with one, and the best-fit and case folds substitute one code
     * point for one -- so every member is drawn from a pool of strings no
     * longer than the query, and neither substitution can be undone by the
     * other (best-fit lands in ASCII, which it maps to itself; lower() is
     * Unicode's simple mapping, which is idempotent).
     *
     * BOUNDED, and the bound is a measurement rather than a precaution. My
     * first version of this comment said the set "stays in single digits"
     * because the folds are functions of the whole string rather than the
     * subset choice the path transforms are -- an argument that sounded right
     * and that a 600,000-sample search immediately falsified at 17 members. A
     * hill climb then reached 53 at 200 characters and 70 at 162, which is past
     * MAX_READINGS before it is multiplied by the path's set at all. Fifth
     * plausible, load-bearing, never-run claim on this task, caught this time
     * because the number went in the comment only after the search printed it.
     *
     * So checkScope bounds the PRODUCT of this set and the path's, and the
     * limit is carried into the construction here for the reason it is carried
     * into readings(): a bound checked after the building is a bound on the
     * wrong side of the work. At most limit + 1 members come back, and exactly
     * limit + 1 when the real set is larger, which is all a caller needs to
     * refuse it.
     */
    static Set<String> queryReadings(String query) {
        return queryReadings(query, Integer.MAX_VALUE);
    }

    static Set<String> queryReadings(String query, int limit) {
        Set<String> out = new LinkedHashSet<>();
        Deque<String> pending = new ArrayDeque<>();
        pending.add(query);
        while (!pending.isEmpty() && out.size() <= limit)
            deriveQuery(out, pending, pending.poll(), limit);
        return out;
    }

    /** One query member, decoded or not, with the byte folds over each. */
    private static void deriveQuery(Set<String> out, Deque<String> pending, String member, int limit) {
        addQueryFolds(out, pending, member, limit);
        String decoded = decodeToFixedPoint(member);
        if (!decoded.equals(member)) addQueryFolds(out, pending, decoded, limit);
    }

    /** The two byte folds and the case fold over one query base. Each is
     *  skipped when it is the identity, which is every ASCII query and so the
     *  whole of the hot path. */
    private static void addQueryFolds(Set<String> out, Deque<String> pending, String base, int limit) {
        if (out.size() > limit) return;
        add(out, pending, lower(base));
        String utf8 = foldOverlongUtf8(base);
        if (out.size() > limit) return;
        if (!utf8.equals(base)) add(out, pending, lower(utf8));
        String bestFit = foldBestFit(utf8);
        if (out.size() > limit) return;
        if (!bestFit.equals(utf8)) add(out, pending, lower(bestFit));
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
