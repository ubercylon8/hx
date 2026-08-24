// extension/test/hx/ChokepointTest.java
package hx;

import hx.TestSupport;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * The enforcement invariant, asserted structurally rather than behaviourally.
 *
 * Spec s4: "Every byte that leaves this machine crosses exactly one of two
 * enforcement points... State it, test it, and never add a third egress path."
 * A behavioural test can only show that the paths it knows about are enforced.
 * This one counts, over the whole of extension/src, so a path nobody thought
 * to test cannot exist quietly.
 *
 * It reads RAW TEXT, comments included, and that cuts BOTH ways. This javadoc
 * used to claim it was "the fail-safe direction"; it was measured, and it is
 * not.
 *
 *   - For a count that must be ZERO (the batch call, the deprecated
 *     accessors), a comment that spells the needle makes the count 1 and this
 *     test go RED. That direction is fail-safe: rewrite the comment, do not
 *     loosen the needle.
 *   - For a count that must be EXACTLY ONE, a comment ANYWHERE in the tree can
 *     supply that one. MEASURED: setting RedirectionMode.ALWAYS in the entry
 *     point and writing `RedirectionMode.NEVER` in a comment in Sender.java
 *     left all nine classes green -- redirects followed inside Burp, and a
 *     comment saying they were not. That direction is fail-OPEN.
 *
 * So a whole-tree count is used only where zero is the answer or where the
 * needle is a CALL nobody would write in prose. Where the count must be
 * exactly one and the text is a constant a comment could carry, take it in
 * {@link #ENTRY_POINT} alone -- see {@link #redirectsAreNotFollowed} -- and
 * assert the whole family appears once there, so a second setting cannot hide
 * behind the first.
 */
public class ChokepointTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** The shared per-method guard, as every other class in this suite runs
     *  its methods. Each check below reads a file: an IOException out of one
     *  of them would end main() with the rest unrun and NO summary line, and a
     *  structural test that silently stopped counting is the one failure this
     *  class could not survive -- it is the only thing asserting there is no
     *  second egress path. See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(ChokepointTest::check, name, body);
    }

    static final String ENTRY_POINT = Path.of("src", "hx", "HxExtension.java").toString();

    public static void main(String[] args) throws Exception {
        List<Path> sources = sources();
        // A walk that matched nothing would make every count below zero, and
        // "zero occurrences" is what most of these assertions want. The suite
        // has to prove it looked at something first.
        check("found the extension sources (" + sources.size() + " files)",
              sources.size() >= 8);

        t("oneEgressPath", () -> oneEgressPath(sources));
        t("noBatchEgressPath", () -> noBatchEgressPath(sources));
        t("redirectsAreNotFollowed", ChokepointTest::redirectsAreNotFollowed);
        t("montoyaIsConfinedToTheEntryPoint", () -> montoyaIsConfinedToTheEntryPoint(sources));
        t("theDeprecatedAccessorsAreUnusedEverywhere",
          () -> theDeprecatedAccessorsAreUnusedEverywhere(sources));
        t("theAuthorisationSnapshotIsReadInExactlyOnePlace",
          () -> theAuthorisationSnapshotIsReadInExactlyOnePlace(sources));
        t("everyKillPathIsWiredBeforeTheDial", ChokepointTest::everyKillPathIsWiredBeforeTheDial);
        t("bothHalvesOfTheDecisionAreAskedAndOnlyOnce",
          () -> bothHalvesOfTheDecisionAreAskedAndOnlyOnce(sources));
        t("noSecondEgressFamilyExists", () -> noSecondEgressFamilyExists(sources));
        t("theAdapterBuildsItsRequestInsideTheTry",
          ChokepointTest::theAdapterBuildsItsRequestInsideTheTry);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    /** test.sh runs from extension/, the same cwd CodecTest reads its golden
     *  vectors from. */
    static List<Path> sources() throws IOException {
        try (Stream<Path> s = Files.walk(Path.of("src"))) {
            return s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
    }

    /**
     * TWO needles, and the second is the one that matters.
     *
     * `http().sendRequest` is a SPELLING, and the review broke it without
     * touching a character of it: `var h2 = api.http(); h2.sendRequest(request,
     * options);` is a genuine second, ungated issuance that all four counters
     * here missed -- the batch counter looks for `sendRequests(`, `import burp.`
     * is unchanged because the sabotage lives in the one file allowed to import
     * it, and `.authorisation()` is unchanged. Duplicating the call outright is
     * the shape nobody writes; a local named `h2` is the shape a "convenience
     * retry" takes.
     *
     * So the HANDLE is counted too. Nothing in the extension may reach Montoya's
     * HTTP API at all except the one adapter in the entry point, whatever it
     * does with what it gets back -- which also catches the batch call, a
     * three-iteration loop, and anything else reachable from a second handle.
     *
     * WHAT IT DOES NOT SEE: `.http()` is still a SPELLING, so `var h2 = api .
     * http ();` slips past it. That is a shape nobody writes and the class
     * javadoc above already scopes these needles as spellings; noted so the
     * next reader does not have to rediscover it before deciding it is
     * acceptable.
     */
    static void oneEgressPath(List<Path> sources) throws IOException {
        int total = 0, handles = 0;
        List<String> hits = new ArrayList<>();
        List<String> handleHits = new ArrayList<>();
        for (Path p : sources) {
            String t = text(p);
            int n = count(t, "http().sendRequest");
            total += n;
            if (n > 0) hits.add(p + " x" + n);
            int h = count(t, ".http()");
            handles += h;
            if (h > 0) handleHits.add(p + " x" + h);
        }
        check("the egress call appears exactly once in extension/src, not " + total
              + " times " + hits, total == 1);
        check("and it is in " + ENTRY_POINT + ", not " + hits,
              hits.size() == 1 && hits.get(0).startsWith(ENTRY_POINT));
        check("Montoya's HTTP API is REACHED exactly once in extension/src, not "
              + handles + " times " + handleHits, handles == 1);
        check("and that one reach is in " + ENTRY_POINT + ", not " + handleHits,
              handleHits.size() == 1 && handleHits.get(0).startsWith(ENTRY_POINT));
    }

    static void noBatchEgressPath(List<Path> sources) throws IOException {
        int total = 0;
        for (Path p : sources) total += count(text(p), "sendRequests(");
        // Montoya's batch call is a second egress path wearing the first one's
        // name. It was measured working on Community (spec s2), which is
        // exactly why it needs saying no to in writing: one request per
        // decision, or Policy is deciding about a list.
        check("the batch egress call appears nowhere in extension/src (" + total + ")",
              total == 0);
    }

    /**
     * Spec s4: each hop is a distinct issuance with its own scope decision and
     * its own exchange row. A redirect followed inside Burp is a request that
     * never crossed Policy -- a third egress path that looks exactly like the
     * first.
     *
     * Counted in {@link #ENTRY_POINT} ONLY, and this is the one check on this
     * branch that was MEASURED FAIL-OPEN before it was. Taken over all of
     * extension/src, `.withRedirectionMode(RedirectionMode.ALWAYS)` in the
     * entry point plus `// see HxExtension: RedirectionMode.NEVER` in a comment
     * in Sender.java gave the count its 1 and left all nine classes green:
     * redirects followed inside Burp, and a comment two files away saying they
     * were not. A whole-tree count of a CONSTANT is a count of prose.
     *
     * The second assertion is what makes the first one hold. `NEVER` appearing
     * once is not "redirects are off" if `ALWAYS` is also there -- the last
     * call to .withRedirectionMode wins, and either order is one line. So the
     * whole family is counted: exactly one RedirectionMode is named in the
     * adapter, and it is NEVER.
     *
     * WHAT IT DOES NOT SEE: a DISCARDED BUILDER RETURN. Montoya's options
     * builder returns a new object rather than mutating, so
     * `options.withRedirectionMode(RedirectionMode.NEVER);` written as a bare
     * statement -- return value dropped, the built options never carrying it
     * -- still counts exactly one `RedirectionMode.` and one `NEVER`, and
     * passes. This is PRE-EXISTING rather than a regression introduced by
     * narrowing the count to the entry point: the whole-tree version was
     * equally blind to it. Only a test that can drive the adapter would catch
     * it, and HxExtension needs Burp to run at all.
     */
    static void redirectsAreNotFollowed() throws IOException {
        String entry = text(Path.of(ENTRY_POINT));
        int never = count(entry, "RedirectionMode.NEVER");
        int any = count(entry, "RedirectionMode.");
        check("the egress call disables redirect following (" + never + ")", never == 1);
        check("and it names exactly one redirection mode, so a second setting "
              + "cannot override it (" + any + ")", any == 1);
    }

    static void montoyaIsConfinedToTheEntryPoint(List<Path> sources) throws IOException {
        List<String> importers = new ArrayList<>();
        for (Path p : sources)
            if (count(text(p), "import burp.") > 0) importers.add(p.toString());
        // Stronger than the plan's global constraint, and deliberately so.
        // With Http as an interface, hx.send.Sender needs no burp.* type at
        // all -- which is what makes the refusal tests able to count calls.
        check("burp.* is imported only by " + ENTRY_POINT + ", not by " + importers,
              importers.equals(List.of(ENTRY_POINT)));
    }

    /**
     * Counted WITH the leading dot, so a declaration (`public long
     * configEpoch()`) and a javadoc cross-reference (`{@link #configEpoch()}`)
     * do not match. A javadoc that writes `BridgeClient.configEpoch()` with a
     * dot instead of a `#` will trip this, and that is the correct outcome:
     * fix the javadoc, do not widen the needle.
     */
    static void theDeprecatedAccessorsAreUnusedEverywhere(List<Path> sources) throws IOException {
        int epoch = 0, scope = 0;
        for (Path p : sources) {
            String t = text(p);
            epoch += count(t, ".configEpoch()");
            scope += count(t, ".scopeConfig()");
        }
        // Two reads of one record, with a commit landing between them:
        // measured wrong in 393/400 trials, and wrong in the unsafe direction
        // -- decide under the superseded wider scope, stamp it with the epoch
        // that narrowed it.
        check("nothing in extension/src calls the deprecated configEpoch() (" + epoch + ")",
              epoch == 0);
        check("nothing in extension/src calls the deprecated scopeConfig() (" + scope + ")",
              scope == 0);
    }

    /**
     * BridgeClient's send arm writes `this.authorisation()` with an explicit
     * receiver precisely so this count can be taken. A bare `authorisation()`
     * there reads as zero here and turns this check red -- which is the
     * correct failure, not a false alarm to be quietened by loosening the
     * needle.
     */
    static void theAuthorisationSnapshotIsReadInExactlyOnePlace(List<Path> sources)
            throws IOException {
        int total = 0;
        for (Path p : sources) total += count(text(p), ".authorisation()");
        check("the whole extension reads the Authorisation snapshot in exactly one "
              + "place, not " + total, total == 1);
    }

    /**
     * There is no SECOND EGRESS FAMILY, not merely one Montoya call.
     *
     * Everything else in this class counts `http().sendRequest` -- Montoya's
     * way out. Spec s4 says "never add a third egress path", and the JDK
     * itself is the second one nobody was counting: `new Socket(...)`,
     * `URL.openConnection()`, `java.net.http.HttpClient`, a `DatagramSocket`.
     * A request issued through any of those never crosses Sender at all, so
     * scope, method, dangerous-path, rate, budget and the credential refusal
     * do not run and nothing anywhere would say so.
     *
     * And it needs no import line to become possible: `BridgeClient` already
     * carries `import java.net.*` for its unix socket, so `new Socket(host,
     * port)` compiles in that file today. Grepping for a new import would
     * have found nothing.
     *
     * Clean at the time of writing -- every needle below is 0 -- so this is a
     * tripwire rather than a fix. The needles are chosen NOT to collide with
     * the bridge's legitimate unix-domain socket: that uses
     * `SocketChannel.open(UnixDomainSocketAddress)` and
     * `ServerSocketChannel`, neither of which contains `Socket(`. The one
     * that does the most work is `InetSocketAddress` -- a SocketChannel is
     * harmless until something gives it a network address to connect to.
     */
    static void noSecondEgressFamilyExists(List<Path> sources) throws IOException {
        String[] needles = {
            "new Socket(",        // a TCP client socket, straight from the JDK
            "InetSocketAddress",  // ...or the address that turns a channel into one
            "openConnection(",    // URL -> URLConnection / HttpURLConnection
            "openStream(",        // URL.openStream(), the one-liner version
            "HttpClient",         // java.net.http, the modern one
            "DatagramSocket",     // UDP is egress too
        };
        for (String needle : needles) {
            int total = 0;
            for (Path p : sources) total += count(text(p), needle);
            check("no `" + needle + "` anywhere in extension/src (" + total + ")",
                  total == 0);
        }
    }

    /**
     * Policy is asked in two halves, and both halves are asked exactly once.
     *
     * `decide()` was split so spec s7's credential refusal could sit BETWEEN
     * them: it must run before the Gate (which spends a rate token and a
     * budget slot) and after scope/method/dangerous (whose classes have
     * `denial` rows, where `unmanaged_credential` has none). Policy cannot
     * make that check itself -- it is decided by its arguments alone and must
     * not reach into hx.send for a Redactor -- so the interleaving lives in
     * Sender.
     *
     * The split is what this guards. `decideBeforeGate` answering `allowed()`
     * is NOT permission to issue: the Gate has not run. A second issue path
     * that called only the first half would issue past the rate limit and past
     * the run's budget, with every behavioural test green, because every one
     * of them drives the path that does call both.
     *
     * Counting is all this can do, and one of each is what the send path
     * needs. `decide(` is not counted: it remains correct for a caller with
     * nothing to interleave, and PolicyTest drives every rule through it.
     */
    static void bothHalvesOfTheDecisionAreAskedAndOnlyOnce(List<Path> sources)
            throws IOException {
        int before = 0, gate = 0;
        for (Path p : sources) {
            String t = text(p);
            before += count(t, ".decideBeforeGate(");
            gate += count(t, ".checkGate(");
        }
        check("the boundary half of the decision is asked exactly once (" + before + ")",
              before == 1);
        check("and the Gate half exactly once with it (" + gate + ")", gate == 1);
        // The pair, not the two counts separately: what makes an allowed
        // first half safe is that a second half follows it.
        check("so no path in extension/src takes one without the other",
              before == gate);
    }

    /**
     * The six wires that make the send path and its kill paths real, counted
     * where they are made.
     *
     * Nothing can test HxExtension behaviourally -- it needs Burp -- and every
     * one of these fails SILENTLY. Without setHaltSink a `halt` frame flips
     * BridgeClient's own flag and stops nothing, because the flag governs
     * maySend() while the send path asks HaltSwitch: requests keep going out
     * with both consoles reading "halted". Without setHaltSource the same gap
     * runs the other way: maySend() falls back to that local flag, which the
     * sentinel file, the stalled-poller rule and the auto-halt never touch --
     * measured, all three left it answering TRUE. It fails CLOSED rather than
     * silently now (an uninstalled source denies), which is why this check is
     * about the line existing at all. Without start() the sentinel file
     * is never read and spec s4's third kill path -- the one that works when
     * the bridge does not -- is missing. Without setHaltNotifier an auto-halt
     * is invisible until the next send fails, and run.stop_reason is written
     * from a frame nobody sent. Without setSendHandler every send is refused
     * `not_configured`, which is at least loud. Without setConfigGuard an
     * operator who lowers `limit.rate_rps` mid-run gets a fresh config_epoch,
     * no error and the OLD RATE -- s4 says that must be refused rather than
     * ignored, and an uninstalled guard ACCEPTS (see setConfigGuard for why
     * that asymmetry is deliberate), so this line is the whole of the check.
     *
     * Counting is all this can do, and it is worth more than nothing: the
     * failure being guarded against is the line being DELETED or never
     * written, not the line being wrong.
     */
    static void everyKillPathIsWiredBeforeTheDial() throws IOException {
        String entry = text(Path.of(ENTRY_POINT));
        check("a halt frame is routed to the switch the send path asks ("
              + count(entry, "setHaltSink(") + ")", count(entry, "setHaltSink(") == 1);
        check("and maySend() asks that same authority back ("
              + count(entry, "setHaltSource(") + ")", count(entry, "setHaltSource(") == 1);
        check("the sentinel poller is started (" + count(entry, "haltSwitch.start()") + ")",
              count(entry, "haltSwitch.start()") == 1);
        check("an auto-halt has somewhere to announce itself ("
              + count(entry, "setHaltNotifier(") + ")", count(entry, "setHaltNotifier(") == 1);
        check("and the send path is installed (" + count(entry, "setSendHandler(") + ")",
              count(entry, "setSendHandler(") == 1);
        check("and a configure that would move an armed limit is refused ("
              + count(entry, "setConfigGuard(") + ")",
              count(entry, "setConfigGuard(") == 1);
    }

    /**
     * Everything the adapter builds is inside the try that turns a
     * RuntimeException into an IOException.
     *
     * The comment on that catch says a RuntimeException escaping it "would
     * reach BridgeClient's catch-all and close the connection. Sender handles
     * IOException and feeds it to Distress; give it one." That was true of the
     * one line the try used to wrap and false of the three above it:
     * Sender.portOf throws IllegalArgumentException for an authority whose
     * post-colon text is not an integer, and HttpService.httpService and
     * HttpRequest.httpRequest are someone else's code called with attacker-
     * influenced strings. Any of them would have taken the control channel
     * down instead of costing one request a transport_error.
     *
     * A position check, not a behavioural one, and the honest reason is that
     * HxExtension needs Burp to run at all -- see the class comment on
     * everyKillPathIsWiredBeforeTheDial. It is anchored at the adapter's own
     * declaration rather than at the file, so an unrelated try elsewhere in
     * HxExtension cannot satisfy it.
     *
     * WHAT IT DOES NOT SEE. These are FIRST-OCCURRENCE OFFSETS, not brace
     * nesting. MEASURED: a decoy `try { ... } catch (RuntimeException e) {
     * throw new IOException(...); }` opened inside montoyaHttp BEFORE an
     * unprotected HttpService.httpService / HttpRequest.httpRequest pair
     * satisfies all four checks below and gives 9 x ALL PASS, with the very
     * calls this was written about sitting outside any guard. So the anchoring
     * claim above is true of the FILE and false of the ADAPTER'S OWN BODY: it
     * catches the lines moving back out of the try, which is the regression it
     * was written for, and it cannot catch a second try opened in front of
     * them. That was judged acceptable -- the finding was LOW and this is
     * strictly better than nothing -- and a brace parser is the fix on the day
     * it stops being.
     */
    static void theAdapterBuildsItsRequestInsideTheTry() throws IOException {
        String entry = text(Path.of(ENTRY_POINT));
        int adapter = entry.indexOf("private static Http montoyaHttp(");
        check("the adapter is where it is expected to be (" + adapter + ")", adapter >= 0);
        int guard = entry.indexOf("try {", adapter);
        int service = entry.indexOf("HttpService.httpService(", adapter);
        int request = entry.indexOf("HttpRequest.httpRequest(", adapter);
        int egress = entry.indexOf("http().sendRequest(", adapter);
        check("the adapter opens a try (" + guard + ")", guard > adapter);
        check("the HttpService is built inside it (" + service + " > " + guard + ")",
              service > guard);
        check("the HttpRequest is built inside it (" + request + " > " + guard + ")",
              request > guard);
        check("and the egress call is inside it too (" + egress + " > " + guard + ")",
              egress > guard);
    }

    static int count(String haystack, String needle) {
        int n = 0, i = 0;
        while ((i = haystack.indexOf(needle, i)) >= 0) { n++; i += needle.length(); }
        return n;
    }

    static String text(Path p) throws IOException {
        return Files.readString(p, StandardCharsets.UTF_8);
    }
}
