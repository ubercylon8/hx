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
 * WHETHER A NEEDLE READS PROSE IS PER-NEEDLE, AND EVERY ONE BELOW SAYS WHICH
 * KIND IT IS. PROSE HERE IS COMMENTS AND STRING LITERALS BOTH: a needle blind
 * to `// c.setHaltSource(x);` but satisfied by `"c.setHaltSource(x)"` is one
 * syntax character from being supplied by prose either way, and that is what
 * the six wire needles were for the few hours between the comment fix and the
 * literal one -- see {@link #stripCommentsAndLiterals} for the measurement.
 * There is no globally right answer, and both directions were measured on this
 * branch and both were wrong somewhere:
 *
 *   - For a count that must be ZERO (the batch call, the deprecated
 *     accessors), a comment that spells the needle makes the count 1 and this
 *     test go RED. That direction is fail-safe: rewrite the comment, do not
 *     loosen the needle. These read RAW TEXT, via {@link #text}.
 *   - For a count that must be EXACTLY ONE, a comment ANYWHERE in the tree can
 *     supply that one. MEASURED: setting RedirectionMode.ALWAYS in the entry
 *     point and writing `RedirectionMode.NEVER` in a comment in Sender.java
 *     left all nine classes green -- redirects followed inside Burp, and a
 *     comment saying they were not. That direction is fail-OPEN.
 *
 * So the rule is about what the needle is PROVING, and the two kinds pull
 * opposite ways:
 *
 *   - A needle proving A WIRE EXISTS -- a call, a handler installation, a
 *     seam being connected -- must IGNORE COMMENTS AND STRING LITERALS ALIKE,
 *     because prose cannot install anything and quoting it does not change
 *     that. MEASURED, on this branch and against these very
 *     checks: prefixing `//` to `c.setHaltSource(...)` and
 *     `c.setConfigGuard(...)` in HxExtension -- the commonest way a wire is
 *     lost -- left java at 9 x ALL PASS / 1592 ok / 0 FAIL (the count before
 *     this class gained the stripper's own test), integration at 13 passed and
 *     python at 376 passed, with F2 (maySend()/checkMaySend() fail-open
 *     against the sentinel file, the stalled poller and the auto-halt) and F8
 *     (a mid-run configure lowering the rate, silently ignored) both silently
 *     restored. `TODO(plan-6): re-enable c.setHaltSource(...)` with the line
 *     itself deleted was measured the same way, and was GREEN here.
 *
 *     ONE THING DID GO RED, and it is not a binding: `tests/
 *     test_plan_matches_repo.py` compares HxExtension.java to a byte-identical
 *     copy inside the plan, so it noticed the edited file -- until
 *     `scripts/sync_plan_block.py` was run, which is the documented workflow
 *     after editing any file, and then python was 376 passed too. A check that
 *     goes green the moment you follow the normal procedure is not what holds
 *     a wire in place. These read {@link #code}.
 *   - A needle proving AN OPTION IS SET -- a constant, an enum member, a
 *     flag -- must NOT be satisfiable by prose, so a comment or a literal
 *     naming it has to COUNT. Blinding {@link #redirectsAreNotFollowed} to
 *     comments would make
 *     `// RedirectionMode.ALWAYS` invisible to the "exactly one mode is
 *     named" arm, and that arm is the entire reason the first one holds.
 *     These read {@link #text}, and narrowing the file they read is the other
 *     half of their defence.
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
        t("theStripperIsNotVacuousAndDoesNotOverreach",
          ChokepointTest::theStripperIsNotVacuousAndDoesNotOverreach);
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
     * WIRE-EXISTS needles, both of them, so they read {@link #code}: a
     * comment cannot issue a request, and the failure being guarded against is
     * the real call being commented out while a commented one keeps the count
     * at 1. Counts are unchanged by the switch (measured: 9 x ALL PASS either
     * way), so this closes a hole rather than moving a number.
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
            String t = code(p);
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

    /** A MUST-BE-ZERO needle, so it reads {@link #text} and comments COUNT:
     *  a comment that spells the batch call turns this red, which is the
     *  fail-safe direction. Rewrite the comment, do not loosen the needle. */
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
     * AN OPTION-IS-SET needle, and the one that fixes the kind of every other
     * needle in this class by contrast. It reads {@link #text} and it MUST:
     * blinding it to comments would make `// RedirectionMode.ALWAYS` invisible
     * to the second assertion below, which is the whole of the first one's
     * defence. An option cannot be proved set by prose, so prose has to count
     * against it -- the opposite of a wire-exists needle, where prose must not
     * count for it. Narrowing the file it reads is what makes that affordable.
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

    /** A MUST-BE-ZERO-ELSEWHERE needle: it reads {@link #text}, so a comment
     *  spelling `import burp.` in another file turns this red rather than
     *  passing. Fail-safe, and deliberately so. */
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
     * MUST-BE-ZERO needles, so they read {@link #text} and a comment counts.
     *
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
     * A WIRE-EXISTS needle -- it proves a READ happens -- so it reads
     * {@link #code} and a commented-out `this.authorisation()` cannot supply
     * the one it is looking for.
     *
     * BridgeClient's send arm writes `this.authorisation()` with an explicit
     * receiver precisely so this count can be taken. A bare `authorisation()`
     * there reads as zero here and turns this check red -- which is the
     * correct failure, not a false alarm to be quietened by loosening the
     * needle.
     */
    static void theAuthorisationSnapshotIsReadInExactlyOnePlace(List<Path> sources)
            throws IOException {
        int total = 0;
        for (Path p : sources) total += count(code(p), ".authorisation()");
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
     * MUST-BE-ZERO needles, so they read {@link #text}: a comment naming
     * `new Socket(` turns this red, and that is the answer wanted -- a second
     * egress family being DISCUSSED in this tree is worth a human look.
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
     * budget slot) and after scope/method/dangerous, whose classes name the
     * boundary crossed rather than the credential carried. Policy cannot
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
     * WIRE-EXISTS needles, so they read {@link #code}: a commented-out
     * `.checkGate(` beside a live `.decideBeforeGate(` would otherwise keep
     * both counts at 1 and the pair assertion below satisfied, with the Gate
     * never asked.
     *
     * Counting is all this can do, and one of each is what the send path
     * needs. `decide(` is not counted: it remains correct for a caller with
     * nothing to interleave, and PolicyTest drives every rule through it.
     */
    static void bothHalvesOfTheDecisionAreAskedAndOnlyOnce(List<Path> sources)
            throws IOException {
        int before = 0, gate = 0;
        for (Path p : sources) {
            String t = code(p);
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
     *
     * ALL SIX ARE WIRE-EXISTS NEEDLES, so they read {@link #code} and NEITHER
     * A COMMENT NOR A STRING LITERAL can supply any of them. Until 2026-08-24
     * they read {@link #text}, and this test was the ONLY thing binding these
     * lines to production: prefixing `//` to `c.setHaltSource(...)` and
     * `c.setConfigGuard(...)` -- the commonest way a wire is lost -- left java
     * at 9 x ALL PASS / 1592 ok / 0 FAIL (the count before the stripper's own
     * test was added), integration at 13 passed and python at 376 passed once
     * the plan block was re-synced, which is the documented step after editing
     * any file. F2 and F8, the two defects the round before last was held to
     * fix, were both silently back. Deleting the line and leaving
     * `// TODO(plan-6): re-enable c.setHaltSource(...)` behind was measured
     * separately and was equally green. BLINDING THESE SIX TO COMMENTS ALONE
     * WAS NOT ENOUGH, and the gap outlived that fix by a few hours: the same
     * deletion with the TODO written as a STRING LITERAL -- `String todo =
     * "re-enable c.setHaltSource(sender::issuanceHeldReason); later";` -- was
     * still 9 x ALL PASS / 1602 ok / 0 FAIL here, this check printing (1). It
     * is the same deleted wire, so it is the same F2. That is why
     * {@link #code} blanks literal bodies as well.
     *
     * `setConfigGuard(` is the sharpest of the six because {@code ConfigGuard}
     * FAILS OPEN when uninstalled -- see BridgeClient.setConfigGuard for why
     * that asymmetry is deliberate -- so this line existing is the whole of
     * F8's binding. `HaltSource` at least denies when it is missing.
     */
    static void everyKillPathIsWiredBeforeTheDial() throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
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
     * The instrument, before anything is measured with it.
     *
     * {@link #stripCommentsAndLiterals} is the whole of the fix above, and a
     * stripper that quietly returned its input would leave every needle
     * exactly as fail-open as it was, with six green checks saying otherwise.
     * So it is driven directly, on a fixture that carries each needle shape
     * rather than on a real file -- a real file that happened to contain no
     * commented-out wire would satisfy a vacuous stripper too.
     *
     * BOTH failure directions are here, and UNDER-STRIPPING HAS TWO SHAPES:
     * a comment naming a wire, and a STRING LITERAL naming one. The literal
     * is the shape this test asserted the WRONG WAY round until 2026-08-24 --
     * it proved non-over-reach with `count(stripped, "setHaltSink(real)") ==
     * 1`, a wire needle read out of a string literal, so the suite positively
     * asserted that prose in quotes installs a wire. Every survivor that stands
     * for non-over-reach below is now deliberately NOT a needle. The one needle
     * still counted as a survivor -- `setHaltNotifier(` -- is REAL CODE, which
     * is the count that has to stay 1 whatever else changes.
     *
     * Over-running a literal is the opposite failure: `"//"` is a string, and
     * a stripper that read it as a comment would blank everything AFTER it --
     * turning the counts to zero and reddening this class for a reason with
     * nothing to do with the wires. That direction is now proved by the code
     * that FOLLOWS each literal surviving, since the literal's own body no
     * longer does.
     */
    static void theStripperIsNotVacuousAndDoesNotOverreach() {
        String src = String.join("\n",
            "class X {",
            "    // c.setHaltSource(gone);",
            "    /* c.setConfigGuard(gone); */",
            "    /**",
            "     * TODO(plan-6): re-enable c.setSendHandler(gone);",
            "     */",
            "    void f() {",
            "        String todo = \"re-enable c.setHaltSink(gone); later\";",
            "        String url = \"https://x/*y*/z\";",
            "        char slash = '/';",
            "        int afterTheLiterals = 42;",
            "        c.setHaltNotifier(real);   // and a trailing comment",
            "    }",
            "}");
        String stripped = stripCommentsAndLiterals(src);

        // Not vacuous: every commented needle is gone...
        check("a // comment cannot supply a wire (" + count(stripped, "setHaltSource(") + ")",
              count(stripped, "setHaltSource(") == 0);
        check("nor can a /* */ comment (" + count(stripped, "setConfigGuard(") + ")",
              count(stripped, "setConfigGuard(") == 0);
        check("nor can a TODO inside a javadoc (" + count(stripped, "setSendHandler(") + ")",
              count(stripped, "setSendHandler(") == 0);
        check("nor can a comment trailing real code ("
              + count(stripped, "and a trailing comment") + ")",
              count(stripped, "and a trailing comment") == 0);
        // ...and neither is a string literal, which is the half of "prose
        // cannot install anything" this class was missing.
        check("nor can a string literal naming a wire ("
              + count(stripped, "setHaltSink(") + ")",
              count(stripped, "setHaltSink(") == 0);
        check("and the rest of that literal's body is gone with it ("
              + count(stripped, "https://x") + ")", count(stripped, "https://x") == 0);

        // ...and not over-reaching: every line AFTER a literal is still there,
        // literals carrying `//`, `/*` and a lone `/` included, and so are the
        // delimiters that say where each literal was.
        // Each of these three is the line AFTER one of the literals above,
        // in order, so each says that literal was closed rather than run past.
        check("a literal naming a wire is closed, not run past ("
              + count(stripped, "String url = \"") + ")",
              count(stripped, "String url = \"") == 1);
        check("a `//` and a `/*` inside a string literal start no comment ("
              + count(stripped, "char slash = '") + ")",
              count(stripped, "char slash = '") == 1);
        check("and a '/' character literal is not a comment either ("
              + count(stripped, "int afterTheLiterals = 42;") + ")",
              count(stripped, "int afterTheLiterals = 42;") == 1);
        check("the call before that trailing comment survives ("
              + count(stripped, "setHaltNotifier(") + ")",
              count(stripped, "setHaltNotifier(") == 1);

        // Offsets are preserved, which is what lets a position check read
        // this string and still be talking about the file.
        check("the stripped text is the same length as the source ("
              + stripped.length() + " vs " + src.length() + ")",
              stripped.length() == src.length());
        check("and has the same line count (" + count(stripped, "\n") + ")",
              count(stripped, "\n") == count(src, "\n"));
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
     * Offsets are taken in {@link #code} rather than {@link #text}, and
     * {@link #stripCommentsAndLiterals} preserves length so they still point
     * at the same places in the file. That closes one shape this used to miss,
     * MEASURED with `// try { a decoy` inserted into montoyaHttp ahead of the
     * real one:
     *
     *     text()  the adapter opens a try (9214)   <- the COMMENT's
     *     code()  the adapter opens a try (9236)   <- the real one
     *
     * 22 characters earlier. There are FIVE checks below and the lower number
     * does not move them all one way: THREE of them -- the HttpService, the
     * HttpRequest and the egress call -- compare `> guard`, and a guard 22
     * characters earlier makes those three EASIER to satisfy, which is prose
     * deciding a position check and the same fail-open as prose supplying a
     * wire. The fourth, `guard > adapter`, gets HARDER, and the fifth,
     * `adapter >= 0`, does not involve the guard at all. Three EASIER is the
     * whole of the concern: they are the ones asserting the calls are inside
     * the try. Both runs were green here, because the real try is still where
     * it should be; the point is which `try {` the check was talking about.
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
        String entry = code(Path.of(ENTRY_POINT));
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

    /** The file, comments and all. For needles that must count PROSE -- see
     *  the class javadoc, and {@link #redirectsAreNotFollowed} for the one
     *  that was measured fail-open when it did not. */
    static String text(Path p) throws IOException {
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** The file's CODE: {@link #text} with every comment, and the BODY of
     *  every string and character literal, blanked out. For needles proving a
     *  WIRE EXISTS, which neither a comment nor a literal must be able to
     *  supply. */
    static String code(Path p) throws IOException {
        return stripCommentsAndLiterals(text(p));
    }

    /**
     * Java comments AND THE BODIES of string and character literals replaced
     * by spaces, CHARACTER FOR CHARACTER.
     *
     * Blanked rather than deleted so every offset in the file survives: an
     * index taken in this string is an index into the original, which keeps
     * {@link #theAdapterBuildsItsRequestInsideTheTry}'s position arithmetic
     * meaningful and stops "which string was this offset from" ever being a
     * question. Newlines are kept for the same reason.
     *
     * THE LITERAL BODIES GO FOR THE SAME REASON THE COMMENTS DO: prose cannot
     * install anything, and a string literal is prose. Blanking only comments
     * left that principle one syntax character short. MEASURED against this
     * class on 2026-08-24, with the real wire DELETED from HxExtension and a
     * diagnostic naming it left behind:
     *
     *     String todo = "re-enable c.setHaltSource(sender::issuanceHeldReason); later";
     *     api.logging().logToOutput(todo);
     *
     * ...java was 9 x ALL PASS / 1602 ok / 0 FAIL, with
     * {@link #everyKillPathIsWiredBeforeTheDial} printing `and maySend() asks
     * that same authority back (1)` -- the 1 supplied entirely by the literal.
     * It is the same wire deleted the same way as the `//` measurement in that
     * method, so it restores the same F2: maySend()/checkMaySend() fail-open
     * against the sentinel file, the stalled poller and the auto-halt. A
     * refactor that drops a wire and leaves a diagnostic naming it is not an
     * exotic shape.
     *
     * THE DELIMITERS STAY and only what is between them goes, so `"x"` becomes
     * `" "`. Nothing this class counts is spelled inside a literal in
     * extension/src: measured across all 18 sources, every needle's count --
     * whole-tree and entry-point -- is identical with the bodies blanked and
     * without, and so is every offset, because the length does not move.
     *
     * It is a lexer, not a parser: it knows nothing of the code between the
     * literals and does not need to. What it must never do is under-strip (the
     * fail-open this exists to close) or run PAST a literal's close, which
     * would blank the real code after it -- red, but red for a reason that has
     * nothing to do with the wires, which is its own kind of broken
     * instrument. {@link #theStripperIsNotVacuousAndDoesNotOverreach} drives
     * both directions.
     */
    static String stripCommentsAndLiterals(String src) {
        char[] out = src.toCharArray();
        int n = out.length, i = 0;
        while (i < n) {
            char c = out[i];
            if (c == '"' || c == '\'') {
                boolean block = c == '"' && i + 2 < n && out[i + 1] == '"' && out[i + 2] == '"';
                i += block ? 3 : 1;              // the opening delimiter is kept
                while (i < n) {
                    if (out[i] == '\\') {
                        // The escape and the character it escapes are ONE
                        // unit. Blanking the backslash alone would leave a
                        // bare `"` behind it that reads as the close, and
                        // everything after the literal would be scanned as
                        // if it were inside one.
                        i = blank(out, i, n);
                        i = blank(out, i, n);
                        continue;
                    }
                    if (block) {
                        if (out[i] == '"' && i + 2 < n && out[i + 1] == '"'
                                && out[i + 2] == '"') { i += 3; break; }
                    } else {
                        if (out[i] == c) { i++; break; }
                        // An unterminated literal is not this class's problem
                        // to diagnose -- javac has already refused the file --
                        // but running to EOF looking for its close would blank
                        // the rest of the file. Stop at the line end.
                        if (out[i] == '\n') break;
                    }
                    i = blank(out, i, n);
                }
                continue;
            }
            if (c == '/' && i + 1 < n && out[i + 1] == '/') {
                while (i < n && out[i] != '\n') out[i++] = ' ';
                continue;
            }
            if (c == '/' && i + 1 < n && out[i + 1] == '*') {
                out[i++] = ' ';
                out[i++] = ' ';
                while (i < n && !(out[i] == '*' && i + 1 < n && out[i + 1] == '/')) {
                    if (out[i] != '\n') out[i] = ' ';
                    i++;
                }
                if (i < n) out[i++] = ' ';
                if (i < n) out[i++] = ' ';
                continue;
            }
            i++;
        }
        return new String(out);
    }

    /** One character blanked, and the next index. A NEWLINE IS NEVER BLANKED:
     *  the line-count and length invariants this stripper is used under are
     *  what keep an offset taken in its output an offset into the file. */
    private static int blank(char[] out, int i, int n) {
        if (i < n && out[i] != '\n') out[i] = ' ';
        return i + 1;
    }
}
