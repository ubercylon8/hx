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
 *
 * WHAT EVERY CHECK IN THIS FILE IS, AND THEREFORE WHAT NONE OF THEM CAN DO.
 * They are TEXT SCANS. They see NAMES, not VALUES. That single sentence is a
 * better guide than any list of shapes, and the list is why: this class has
 * enumerated its own blind spot three times and been wrong about it twice.
 *
 *   - Round 1 said the checks pin that the calls happen in the right ORDER. A
 *     value computed and then not used defeated that: both redaction calls
 *     left exactly where they were and the queued record's two byte arguments
 *     changed to the RAW locals -- one identifier each -- measured at 12
 *     summary lines / 0 FAIL / rc=0 with raw bytes going into a
 *     content-addressed store, every offset still correct.
 *   - Round 2 pinned DATAFLOW: each local bound once, read once, the consuming
 *     expression delimited and searched for the names it must not contain. It
 *     declared its residual to be "an identity function". That was too narrow
 *     in the direction that flatters the check. The real residual is ANY CALL
 *     WRAPPING THE VALUE AT ITS USE SITE, whatever that call returns -- a
 *     helper that DISCARDS its redacted argument and re-fetches the raw bytes
 *     is not an identity function and reads 12 / 0 FAIL / rc=0, so a reader
 *     taking the old sentence as the boundary would judge it covered.
 *   - And dataflow is not APPLICATION. Swapping two same-typed functions
 *     between two same-typed arguments leaves every name, every count and
 *     every offset intact: measured at 12 / 1880 ok / 0 FAIL / rc=0 with both
 *     halves of an exchange leaking.
 *
 * So: A TEXT SCAN CANNOT SEE THROUGH A CALL, and it cannot tell which VALUE a
 * name holds. Do not write a check here whose property depends on either, and
 * when one is the only thing holding a property, say so and name the layer
 * that actually holds it. For the redaction that layer is now
 * `RecorderTest`, which asserts over BYTES -- see
 * {@link #theRecordIsBuiltByTheRecorderAndNeverInline} for what was moved out
 * of the text's reach and why.
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
        t("theBridgeNamesNothingInTheProxyPackage",
          () -> theBridgeNamesNothingInTheProxyPackage(sources));
        t("theDeprecatedAccessorsAreUnusedEverywhere",
          () -> theDeprecatedAccessorsAreUnusedEverywhere(sources));
        t("everyDecisionReadsOneAuthorisationSnapshot",
          () -> everyDecisionReadsOneAuthorisationSnapshot(sources));
        t("theStripperIsNotVacuousAndDoesNotOverreach",
          ChokepointTest::theStripperIsNotVacuousAndDoesNotOverreach);
        t("everyKillPathIsWiredBeforeTheDial", ChokepointTest::everyKillPathIsWiredBeforeTheDial);
        t("theGateIsSpentOnlyWhereTheHalvesArePaired",
          () -> theGateIsSpentOnlyWhereTheHalvesArePaired(sources));
        t("oneRunHasOnePolicy", () -> oneRunHasOnePolicy(sources));
        t("noSecondEgressFamilyExists", () -> noSecondEgressFamilyExists(sources));
        t("theAdapterBuildsItsRequestInsideTheTry",
          ChokepointTest::theAdapterBuildsItsRequestInsideTheTry);
        t("theSecondEnforcementPointIsRegisteredAndAsksTheGate",
          ChokepointTest::theSecondEnforcementPointIsRegisteredAndAsksTheGate);
        t("theRefusalIsHeldBeforeItIsRecorded",
          ChokepointTest::theRefusalIsHeldBeforeItIsRecorded);
        t("theClockAndTheAttributionAreWrittenDownAndTakenBack",
          ChokepointTest::theClockAndTheAttributionAreWrittenDownAndTakenBack);
        t("theRecordingStructuresHoldTheirMonitors",
          ChokepointTest::theRecordingStructuresHoldTheirMonitors);
        t("theGateDecidesBeforeAnythingIsQueued",
          ChokepointTest::theGateDecidesBeforeAnythingIsQueued);
        t("everyTypeNeedleSurvivesQualification",
          ChokepointTest::everyTypeNeedleSurvivesQualification);
        t("theRecordIsBuiltByTheRecorderAndNeverInline",
          () -> theRecordIsBuiltByTheRecorderAndNeverInline(sources));

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

    /**
     * A MUST-BE-ZERO-ELSEWHERE needle: it reads {@link #text}, so a comment
     * naming a Montoya type in another file turns this red rather than
     * passing. Fail-safe, and deliberately so.
     *
     * THE NEEDLE WAS `import burp.` AND THAT WAS NOT THE PROPERTY. Measured:
     * a fully-qualified `burp.api.montoya.core.ByteArray` in
     * `hx/proxy/Recorder.java`, with no import line, compiles (test.sh puts
     * the jar on the classpath) and read 13 summary lines / 1900 ok / 0 FAIL
     * / rc=0. The invariant held; the check did not. That matters more than
     * usual here, because "Recorder names no Montoya type" is what makes
     * Recorder drivable, and this check is one of the four layers
     * {@link #noSecondEgressFamilyExists} names as what closes ITS gap.
     *
     * `burp.api.` and not `burp.`, and the reason is measured rather than
     * aesthetic: the jar has exactly ONE package root, `burp/api/`, so every
     * reference to a Montoya type -- imported, statically imported or written
     * out in full -- contains this string, while `burp.` alone also matches
     * the legitimate system-property NAME `"hx.burp.version"` in
     * `BridgeClient`. A needle that forces a real property to be renamed is a
     * needle that will be loosened by the next person in a hurry.
     */
    static void montoyaIsConfinedToTheEntryPoint(List<Path> sources) throws IOException {
        List<String> namers = new ArrayList<>();
        for (Path p : sources)
            if (count(text(p), MONTOYA) > 0) namers.add(p.toString());
        // Stronger than the plan's global constraint, and deliberately so.
        // With Http as an interface, hx.send.Sender needs no Montoya type at
        // all -- which is what makes the refusal tests able to count calls.
        check("Montoya is named only by " + ENTRY_POINT + ", not by " + namers,
              namers.equals(List.of(ENTRY_POINT)));
    }

    /**
     * The dependency runs one way: hx.proxy -> hx.bridge, and never back.
     *
     * `HaltSink` and `SendHandler` are declared in BridgeClient precisely so
     * the packages that call the bridge need no compile-time dependency the
     * other way. `ExchangeSink` was declared in `Capture` instead, and
     * `exchangeSink()` returned it -- so the bridge imported the proxy package
     * while the proxy package already imported the bridge. javac does not mind
     * a cycle, because it sees every source at once; a reader trying to work
     * out which of two files is the authority on a drop's spelling does.
     *
     * MOVING THE INTERFACE ALONE WOULD NOT HAVE FIXED IT: its second method
     * was `dropped(long, Source)` and its body called `Capture.sourceName`,
     * both of which survive the move. Making the callback source-agnostic --
     * a String, null for "no spelling" -- is what actually cut it, and this
     * counts the needle rather than trusting that.
     *
     * A MUST-BE-ZERO needle, so a COMMENT counts too. That is the same rule
     * as the deprecated-accessor check below and it has the same answer: a
     * javadoc that needs to talk about the other package says "the proxy
     * package", not the dotted name. Fix the prose, do not widen the needle.
     */
    static void theBridgeNamesNothingInTheProxyPackage(List<Path> sources)
            throws IOException {
        List<String> naming = new ArrayList<>();
        for (Path p : sources) {
            if (!p.toString().contains("hx/bridge/")) continue;
            if (count(text(p), "hx.proxy") > 0) naming.add(p.toString());
        }
        check("no file in hx.bridge names hx.proxy (" + naming + ")",
              naming.isEmpty());
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

    static final String BRIDGE_CLIENT =
            Path.of("src", "hx", "bridge", "BridgeClient.java").toString();

    /** Every reference to a Montoya type contains this: the API jar has one
     *  package root, `burp/api/`, measured. */
    static final String MONTOYA = "burp.api.";

    /** Policy declares the constructor its count cannot help matching. */
    static final String POLICY =
            Path.of("src", "hx", "policy", "Policy.java").toString();

    /** The record itself, which declares the constructor the count below
     *  cannot help matching. */
    static final String OBSERVED =
            Path.of("src", "hx", "proxy", "Observed.java").toString();

    /** The one file that turns two raw halves into a redacted record. It has
     *  no burp.* type in it, which is what lets RecorderTest execute it. */
    static final String RECORDER =
            Path.of("src", "hx", "proxy", "Recorder.java").toString();

    /** The issuing path: the one file that interleaves S7's credential refusal
     *  between Policy's two halves. */
    static final String SENDER =
            Path.of("src", "hx", "send", "Sender.java").toString();

    /**
     * ONE READ PER DECIDING CALLBACK, AND NO READ THAT IS NOT ONE'S.
     *
     * This check counted ONE read in the whole of extension/src until Task 7,
     * and one was right while the send arm was the only thing deciding.
     * Wiring the second enforcement point makes it THREE: the send arm, the
     * proxy request handler, and the re-decision before the bytes leave.
     *
     * THE NUMBER IS NOT WHAT MATTERS AND WIDENING IT TO 3 WOULD PIN NOTHING.
     * `configEpoch()` and `scopeConfig()` are two reads of one record and can
     * straddle a commit -- measured wrong in 393/400 trials, and wrong in the
     * unsafe direction. What that costs is a decision assembled from two
     * halves of two authorisations, and the shape of that bug is A SECOND READ
     * INSIDE ONE DECISION, which a bare total of 3 cannot tell from one
     * decision moved to another file. So the reads are pinned to the things
     * that make them, DERIVED rather than restated:
     *
     *   - BridgeClient reads once, for the send arm;
     *   - the entry point reads exactly as many times as it has DECIDING
     *     CALLBACKS, which is the equality that turns a second read inside
     *     either handler red;
     *   - each read comes BEFORE the question it feeds, in order, so the
     *     equality cannot be satisfied by two reads in one callback and none
     *     in the other;
     *   - and nothing else in extension/src reads it at all.
     *
     * DERIVED FROM THE CALLBACK DECLARATIONS, not from the questions, and that
     * changed in fix round 1. It used to count `gate.decide(` +
     * `decideScopeOnly(` -- one question per callback, which was true until
     * the second callback gained a SECOND question (`decideBeforeGate` for the
     * crawler, `decideScopeOnly` for the operator -- two branches of one
     * decision, taken under one snapshot). Counting questions would then read
     * three decisions against two reads and go red on correct code. The
     * callbacks are the right unit: a callback decides once, whatever it asks.
     *
     * THE WITNESS FOR THE WIDENING, in the shape
     * `test_vocabularies_match_the_schema.py` uses for its own: the equality
     * is vacuous if both sides are zero -- a file with no reads and no
     * callbacks satisfies it -- so the callback count is asserted to be 2
     * outright. Deleting either callback is then red here as well as in the
     * registration counts.
     *
     * WIRE-EXISTS needles, so they read {@link #code}: a commented-out
     * `this.authorisation()` cannot supply one. BridgeClient's send arm writes
     * `this.authorisation()` with an explicit receiver precisely so the count
     * can be taken; a bare `authorisation()` there reads as zero and turns
     * this red, which is the correct failure rather than a reason to loosen
     * the needle.
     */
    static void everyDecisionReadsOneAuthorisationSnapshot(List<Path> sources)
            throws IOException {
        int total = 0;
        List<String> elsewhere = new ArrayList<>();
        for (Path p : sources) {
            int n = count(code(p), ".authorisation()");
            total += n;
            if (n > 0 && !p.toString().equals(BRIDGE_CLIENT)
                      && !p.toString().equals(ENTRY_POINT))
                elsewhere.add(p + " x" + n);
        }
        String bridge = code(Path.of(BRIDGE_CLIENT));
        String entry = code(Path.of(ENTRY_POINT));
        int inBridge = count(bridge, ".authorisation()");
        int inEntry = count(entry, ".authorisation()");
        // The two callbacks a request is decided about in, by their
        // declarations. A response handler decides nothing and must read
        // nothing, which is what the totals below enforce.
        int callbacks = count(entry, "handleRequestReceived(InterceptedRequest r)")
                      + count(entry, "handleRequestToBeSent(InterceptedRequest r)");

        check("the send arm reads the Authorisation snapshot once (" + inBridge + ")",
              inBridge == 1);
        check("the entry point has two deciding callbacks -- the proxy request "
              + "handler and the pre-send re-decision (" + callbacks + ")",
              callbacks == 2);
        check("and reads the snapshot exactly once per deciding callback ("
              + inEntry + " reads, " + callbacks + " callbacks)",
              inEntry == callbacks);
        check("nothing else in extension/src reads it at all " + elsewhere,
              elsewhere.isEmpty());
        check("so the whole extension reads it " + (1 + callbacks) + " times, "
              + "once per decision (" + total + ")", total == 1 + callbacks);

        // Each read AHEAD of the question it feeds. Without this, two reads in
        // one callback and none in the other satisfies the equality above --
        // and "none in the other" is a decision taken under an authorisation
        // fetched for a different request. The second callback asks one of two
        // questions and both are spelled `policy.decide...`, so the common
        // prefix is what is looked for; nothing before it in this file spells
        // that (the first callback asks `gate.decide(`).
        int read1 = entry.indexOf(".authorisation()");
        int gate = entry.indexOf("gate.decide(");
        int read2 = entry.indexOf(".authorisation()", read1 + 1);
        int reDecision = entry.indexOf("policy.decide", read2);
        check("the request handler reads before it asks the gate (" + read1
              + " < " + gate + ")", read1 >= 0 && read1 < gate);
        check("and the re-decision reads its own, after that gate call and "
              + "before its own question (" + gate + " < " + read2 + " < "
              + reDecision + ")",
              read2 > gate && reDecision > read2);
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
     *
     * THE FIRST NEEDLE WAS `new Socket(` AND IT WAS BLIND TO A QUALIFIED NAME,
     * measured on 2026-08-25 as Task 7's row G. This class's own javadoc above
     * says the family "needs no import line to become possible"; the needle
     * then required the one spelling that DOES need one. Three runs, each a
     * single edit to `Pending.size()`, against a clean 12 summary lines / 0
     * FAIL / rc=0:
     *
     *     new java.net.Socket()                       12 lines, 0 FAIL, rc=0
     *     new java.net.Socket("127.0.0.1", 1).close() 12 lines, 0 FAIL, rc=0
     *     new Socket("127.0.0.1", 1) + the import     12 lines, 1 FAIL, rc=1
     *
     * The middle one is a WORKING TCP egress -- the two-argument constructor
     * connects, so it needs no `InetSocketAddress` either -- sitting in
     * extension/src with every check green. The needle is `Socket(` now, which
     * catches the qualified and unqualified spellings alike and `new
     * ServerSocket(` with them. It cost nothing to tighten: `Socket(` appears
     * ZERO times in extension/src today, measured across all 25 sources, for
     * the reason the paragraph above gives -- the unix-domain path spells
     * `SocketChannel.open(` and `ServerSocketChannel`, and neither has the
     * paren against the word.
     *
     * QUALIFICATION WAS NOT THE ONLY HOLE, and the sentence that used to stand
     * here -- "the other five needles have no such blind spot" -- was FALSE.
     * Two reviewers found it independently, and each measured its probe as a
     * single added line in `extension/src` against a clean 12 / 0 FAIL / rc=0:
     *
     *     new java.net.URL("http://127.0.0.1:1/").getContent()  12 / 0 / rc=0
     *     new ProcessBuilder("curl", ...).start()               12 / 0 / rc=0
     *     java.net.InetAddress.getByName(...)                   12 / 0 / rc=0
     *     api.collaborator().createClient()...                  12 / 0 / rc=0
     *     new java.net.URL("http://127.0.0.1:1/").openStream()  12 / 1 / rc=1
     *
     * The last is the control: the needle works for the door it names. The
     * first is the lesson -- `getContent()` is a THIRD door on the very object
     * `openConnection(` and `openStream(` guard, so the list was enumerating
     * SPELLINGS where the capability was the thing to name. The needle is now
     * the object (`URL(`), which no method on it can get past.
     *
     * `URL(` WAS NOT FREE, and the four occurrences it collided with were
     * PROSE: comments in `Policy.java` discussing JavaScript's `new URL()` for
     * path normalisation. These needles read {@link #text}, so prose counts,
     * and this class's own rule for a must-be-zero needle applies -- rewrite
     * the comment, do not loosen the needle. The four were rewritten to say
     * `new URL` without the paren, which says the same thing, and `URL(` is 0.
     * The other four additions were 0 to begin with.
     *
     * WHAT THIS LIST EXCLUDES IS EVERY SPELLING NOT IN IT, and that is the
     * whole of it. The bullets that used to stand here read as a survey of the
     * gap and were not one -- the first named `uri.toURL().getContent()` as an
     * escape, and it is CAUGHT, because `toURL(` contains `URL(`. A list of
     * exclusions that under-states the check's reach in one bullet and
     * over-states it in the shape it misses is worse than no list, which is
     * this class's own Rule 4 turned on itself for the third time.
     *
     * The measured escape is not exotic and its type IS fully spelled:
     *
     *     new java.util.logging.SocketHandler("127.0.0.1", 9999);
     *
     * One line, one JDK TCP connection, and 12 summary lines / 1880 ok /
     * 0 FAIL / rc=0. `SocketHandler(` does not contain `Socket(` and no other
     * needle touches it. IT IS DELIBERATELY NOT ADDED: enumerating spellings
     * is the error F4 was raised about, one more name does not change what a
     * text scan can do, and the JDK has more classes that open a socket than
     * anyone will finish listing -- a logging handler is only the funniest.
     *
     * WHAT DOES CLOSE IT is not a longer list. It is the layers below and
     * above this one: {@link #montoyaIsConfinedToTheEntryPoint} keeps `burp.*`
     * to one file, {@link #oneEgressPath} keeps Montoya's HTTP API to one
     * reach inside it, `extension/build.sh` compiles `src` alone against the
     * Montoya API so there is no third party to hide in -- and, for anything
     * the JDK can still do, an end-to-end run that WATCHES THE WIRE. That is
     * Task 9's, and it is the only layer that can answer "did bytes leave"
     * rather than "is this spelling present".
     *
     * So this check is a TRIPWIRE on the shapes a second egress path has
     * actually taken in this repository -- twice now, both found by review
     * rather than by it -- and it is not a proof that none exists. Read it as
     * that and nothing more.
     */
    static void noSecondEgressFamilyExists(List<Path> sources) throws IOException {
        String[] needles = {
            "Socket(",            // a TCP client socket, straight from the JDK,
                                  // qualified or not -- see the javadoc above
            "InetSocketAddress",  // ...or the address that turns a channel into one
            "URL(",               // the OBJECT, not one of its doors: see above
            "openConnection(",    // URL -> URLConnection / HttpURLConnection
            "openStream(",        // URL.openStream(), the one-liner version
            "HttpClient",         // java.net.http, the modern one
            "DatagramSocket",     // UDP is egress too
            "InetAddress",        // a DNS lookup is bytes off this machine
            "ProcessBuilder",     // ...and so is `curl`
            "Runtime.getRuntime", // the older spelling of the same thing
            "collaborator()",     // Montoya's OTHER network facility
        };
        for (String needle : needles) {
            int total = 0;
            for (Path p : sources) total += count(text(p), needle);
            check("no `" + needle + "` anywhere in extension/src (" + total + ")",
                  total == 0);
        }
    }

    /**
     * WHEREVER THE PAID HALF IS SPENT, THE FREE HALF WENT BEFORE IT -- and the
     * paid half is spent in exactly one place.
     *
     * `Policy.decide()` was split so spec s7's credential refusal could sit
     * BETWEEN the halves: it must run before the Gate (which spends a rate
     * token and a budget slot) and after scope/method/dangerous, whose classes
     * name the boundary crossed rather than the credential carried. Policy
     * cannot make that check itself -- it is decided by its arguments alone
     * and must not reach into hx.send for a Redactor -- so the interleaving
     * lives in Sender.
     *
     * `decideBeforeGate` answering `allowed()` is NOT permission to issue: the
     * Gate has not run. A second ISSUE path that called only the first half
     * would issue past the rate limit and past the run's budget, with every
     * behavioural test green, because every one of them drives the path that
     * does call both.
     *
     * THIS USED TO BE `before == 1 && gate == 1 && before == gate`, WHOLE-TREE,
     * and fix round 1 made that false rather than wrong. The proxy path's
     * second callback re-decides an INTERCEPT-EDITED request: S4 says the
     * method allowlist and the dangerous-path denylist apply to crawler
     * traffic in full, and an edit after the first callback's decision is a
     * request nobody checked. So it asks `decideBeforeGate` -- and it must NOT
     * ask the Gate, because the Gate was already spent for this request at the
     * first callback, and asking again charges a crawler twice for one
     * request.
     *
     * Bumping the constant to 2 would have said nothing about that. What the
     * check says instead, DERIVED per file rather than restated as a total:
     *
     *   - the ISSUING path (Sender) asks both halves, the same number of
     *     times, and that number is one. This is the original pair assertion,
     *     narrowed to the file where the interleaving actually lives -- so a
     *     deleted `.checkGate(` there is still red;
     *   - the entry point asks the free half and NEVER the paid one. A
     *     must-be-zero, which is the strongest shape this class has, and it is
     *     the thing that would go wrong: `policy.decide(` or `.checkGate(` at
     *     the second callback is a double charge no behavioural test can see;
     *   - NO OTHER FILE asks either half. A third caller of `decideBeforeGate`
     *     is a path that might issue on a half-decision, and it has to be
     *     looked at by a human rather than absorbed into a total.
     *
     * WIRE-EXISTS needles, so they read {@link #code}: a commented-out
     * `.checkGate(` beside a live `.decideBeforeGate(` would otherwise keep
     * the counts satisfied with the Gate never asked.
     *
     * `decide(` is not counted: it remains correct for a caller with nothing
     * to interleave -- the proxy path's FIRST callback reaches it through
     * `ProxyGate` -- and PolicyTest drives every rule through it.
     */
    static void theGateIsSpentOnlyWhereTheHalvesArePaired(List<Path> sources)
            throws IOException {
        String sender = code(Path.of(SENDER));
        String entry = code(Path.of(ENTRY_POINT));
        int senderBefore = count(sender, ".decideBeforeGate(");
        int senderGate = count(sender, ".checkGate(");
        int entryBefore = count(entry, ".decideBeforeGate(");
        int entryGate = count(entry, ".checkGate(");

        check("the issuing path asks the boundary half exactly once ("
              + senderBefore + ")", senderBefore == 1);
        check("and the Gate half exactly once with it (" + senderGate + ")",
              senderGate == 1);
        // The pair, not the two counts separately: what makes an allowed first
        // half safe is that a second half follows it.
        check("so the issuing path never takes one without the other",
              senderBefore == senderGate);

        check("the proxy path re-decides with the free half (" + entryBefore + ")",
              entryBefore == 1);
        // THE ONE THAT WOULD GO WRONG. The Gate was spent for this request at
        // the first callback; spending it again charges a crawler twice for
        // one request, shortening the run for no evidence, and every
        // behavioural test stays green because each half of it is internally
        // consistent.
        check("and NEVER the paid one -- the Gate is not spent twice for one "
              + "request (" + entryGate + ")", entryGate == 0);
        // ...and not through the front door either. `policy.decide(` runs both
        // halves INSIDE Policy, so it reaches the Gate without ever spelling
        // `.checkGate(` here -- which is the shape a double charge would
        // actually be written in, and the count above cannot see it. The
        // needle takes the paren, so `policy.decideBeforeGate(` and
        // `policy.decideScopeOnly(` do not match it. ProxyGate's own
        // `policy.decide(` is a different file and is the FIRST callback's
        // paying decision, which is correct.
        int entryFull = count(entry, "policy.decide(");
        check("and not through policy.decide(), which reaches the Gate without "
              + "naming it (" + entryFull + ")", entryFull == 0);

        List<String> elsewhere = new ArrayList<>();
        for (Path p : sources) {
            if (p.toString().equals(SENDER) || p.toString().equals(ENTRY_POINT)) continue;
            String c = code(p);
            int n = count(c, ".decideBeforeGate(") + count(c, ".checkGate(");
            if (n > 0) elsewhere.add(p + " x" + n);
        }
        check("and no other file in extension/src asks either half " + elsewhere,
              elsewhere.isEmpty());
    }

    /**
     * The extension builds ONE Policy, and the second enforcement point is
     * handed that one.
     *
     * Policy owns the Gate, and the Gate is where the rate limit and the
     * per-run budget live. Two Policy objects sharing one Limits would be
     * harmless -- this is NOT a claim that a second Policy is wrong in
     * itself. It is a tripwire on the shape a second one arrives in: the
     * natural way to give the proxy path a Policy, when the send path's was
     * built inline at its call site, is to write another
     * `new Policy(new Limits(...))` -- and that is a SECOND per-run budget for
     * one run, which no behavioural test can see because each half of it is
     * internally consistent. {@link #theGateIsSpentOnlyWhereTheHalvesArePaired}
     * cannot see it either: it counts `.decideBeforeGate(` and `.checkGate(`,
     * not constructions.
     *
     * A WIRE-EXISTS needle, so it reads {@link #code}: prose cannot construct
     * anything. That is not theoretical here -- the entry point's own comment
     * spells `new Policy(new Limits(...))` to explain the hazard, and this
     * count is 1 with that comment in place, which is the measurement that
     * this needle is blind to prose. Whole-tree, because the answer is a fixed
     * count of a CALL nobody writes in prose -- the class javadoc's rule for
     * when that is safe.
     *
     * WHAT IT DOES NOT SEE, beyond a second Limits: a CONSTRUCTOR REFERENCE.
     * `Policy::new` contains no `Policy(` and would slip past, exactly as
     * `Observed::new` did before {@link hx.proxy.Observed} was made
     * package-private and the compiler took over that job. There is no
     * equivalent compiler bound available here -- `Policy` is public because
     * `hx.send` and `hx.proxy` both need it -- so this is a declared residual
     * and not a closed one.
     *
     * AND NOT A SECOND LIMITS EITHER. `new Limits(` is not counted,
     * because Limits is legitimately constructible for defaults and the
     * damage is done by the Policy that takes it. If this count ever needs to
     * be two, say which Limits the second one shares before changing the
     * number.
     */
    static void oneRunHasOnePolicy(List<Path> sources) throws IOException {
        int total = 0;
        List<String> hits = new ArrayList<>();
        for (Path p : sources) {
            // `Policy(` and not `new Policy(`: a QUALIFIED construction,
            // `new hx.policy.Policy(limits)`, slipped past the `new ` spelling
            // and read 13 summary lines / 1900 ok / 0 FAIL / rc=0 -- a second
            // per-run budget for one run, which is the exact failure this
            // check's javadoc says no behavioural test can see. The cost of
            // the wider needle is that Policy's own CONSTRUCTOR DECLARATION
            // matches, so the expected answer is two files.
            int n = count(code(p), "Policy(");
            total += n;
            if (n > 0) hits.add(p + " x" + n);
        }
        check("Policy is DECLARED in one file and CONSTRUCTED in one, and the "
              + "one that constructs it is " + ENTRY_POINT + " -- not " + hits,
              hits.equals(List.of(ENTRY_POINT + " x1", POLICY + " x1")));
        check("so extension/src builds exactly one Policy (" + (total - 1)
              + " constructions + 1 declaration = " + total + ")", total == 2);
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

    /**
     * S4's SECOND enforcement point exists, once, and the gate is inside it.
     *
     * A handler that forwards without asking is a third egress path wearing
     * the second one's name -- and unlike the send path there is nothing
     * behind it: the proxy is Burp's own socket, so a request the handler
     * passes through has crossed no rule of ours at all.
     *
     * The FOURTH count is the one that is easiest to argue away. Montoya's
     * ProxyRequestHandler has two callbacks, and Burp's INTERCEPT TAB sits
     * between them: an operator can rewrite the request there, host included.
     * A gate at the first callback only therefore lets an EDITED request leave
     * with no decision about it, which is the one hole in this system where
     * bytes could cross the engagement boundary. `decideScopeOnly(` and not
     * `decide(` is deliberate and is counted as itself: the full question
     * spends a rate token and a budget slot, so asking it twice would charge a
     * crawler twice for one request -- and
     * {@link #bothHalvesOfTheDecisionAreAskedAndOnlyOnce} could not see that,
     * because it counts Policy's internal halves on the send path.
     *
     * WIRE-EXISTS needles, all four, so they read {@link #code}: prose cannot
     * register a handler or ask a question. Taken in {@link #ENTRY_POINT},
     * which is the only file allowed to name burp.* at all -- see
     * {@link #montoyaIsConfinedToTheEntryPoint}, which is what makes that
     * narrowing safe rather than convenient.
     *
     * WHAT THESE DO NOT SEE: whether the handler HONOURS the verdict. MEASURED
     * by a reviewer, on the committed tree: `if (!verdict.allow() && false)`
     * forwards every refused request to the target and reads 12 summary lines
     * / 0 FAIL / rc=0. `gate.decide(` is still called once, the offer is still
     * textually after it, and every count here is satisfied. Only Task 9
     * driving real Burp can catch it, and the CONDITION IT MUST MEET is
     * written where its implementer will read it -- in HxExtension's
     * assumption block, item 2: assert a refused request reaches the target
     * ZERO times, measured AT THE TARGET, never by reading the client's
     * response, because `drop()` answers the client 200 OK with ~1529 bytes of
     * Burp's own HTML and is indistinguishable from a delivery by status code.
     *
     * The two position checks below cover the orderings; this one covers
     * existence.
     */
    static void theSecondEnforcementPointIsRegisteredAndAsksTheGate()
            throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int n1 = count(entry, "registerRequestHandler(");
        int n2 = count(entry, "registerResponseHandler(");
        int n3 = count(entry, "gate.decide(");
        int n4 = count(entry, "decideScopeOnly(");
        check("registerRequestHandler appears exactly once (" + n1 + ")", n1 == 1);
        check("registerResponseHandler appears exactly once (" + n2 + ")", n2 == 1);
        check("the proxy handler asks the gate (" + n3 + ")", n3 == 1);
        check("scope is re-decided before the request is sent (" + n4 + ")",
              n4 == 1);
    }

    /**
     * THE REFUSAL IS DECIDED AND HELD BEFORE ANYTHING IS RECORDED, AND IS
     * RETURNED WHATEVER THE RECORDING DID.
     *
     * "Capture never gates enforcement" was true at the two request callbacks
     * only because {@link hx.proxy.Capture#offer} documents that it never
     * throws. That is a contingent property of another class, not a structure,
     * and it is one field made nullable away from being false: a `Captured`
     * with a null `Source` NPEs at `dropped[o.source().ordinal()]`. A throw
     * out of that line escaped the handler with `drop()` never executed, and
     * what Burp does with a proxy handler that threw is measured nowhere in
     * this repository.
     *
     * So the action is bound to a local BEFORE the offer and returned AFTER
     * it, with the offer inside a `try`. The property is then the control
     * flow's rather than the callee's -- {@link hx.proxy.Capture}'s promise is
     * still worth keeping, and nothing depends on it any more.
     *
     * Counted, not positioned per callback, because there are exactly two of
     * these and a count of two is what a deleted one turns into. The response
     * handler is not counted here: it already wrapped its offer, and its
     * action carries no enforcement -- it forwards either way.
     */
    static void theRefusalIsHeldBeforeItIsRecorded() throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int bound = count(entry, "Action refuse =");
        int returned = count(entry, "return refuse;");
        int bind = entry.indexOf("Action refuse =");
        int offer = entry.indexOf("capture.offer(");
        int ret = entry.indexOf("return refuse;");
        check("both refusing callbacks bind their action first (" + bound + ")",
              bound == 2);
        check("and return that local rather than a fresh call (" + returned + ")",
              returned == 2);
        check("the action is decided before anything is recorded (" + bind
              + " < " + offer + ")", bind >= 0 && offer >= 0 && bind < offer);
        check("and returned after (" + ret + " > " + offer + ")",
              ret > offer);
    }

    /**
     * THE CLOCK AND THE ATTRIBUTION ARE WRITTEN DOWN, AND TAKEN BACK.
     *
     * `Pending` is well tested as a CLASS and was held by nothing as WIRING.
     * MEASURED by a reviewer on the committed tree: guard `pending.put(...)`
     * so it never runs -- one `if` -- and the suite reads 12 summary lines /
     * 0 FAIL / rc=0 while hx captures ZERO proxy exchanges. Every response
     * handler then takes a miss, counts `countLost(UNATTRIBUTED)` and records
     * nothing, so the only symptom is `run.dropped_total` climbing, which S5
     * presents as a coverage FLOOR -- i.e. the failure looks exactly like "the
     * harness is fine, this run just saw little traffic". A total outage that
     * reads as poor coverage is the worst shape a defect can have here.
     *
     * TWO takes, not one, and both are needed: the response handler takes the
     * entry to build the record, and the second request callback takes it when
     * it refuses, because that request will never be answered and the map's
     * bound should be spent on requests actually in flight.
     *
     * WIRE-EXISTS needles, so they read {@link #code}.
     *
     * WHAT THEY DO NOT SEE, and it is why the counts are not the whole check:
     * a `put` that is never REACHED still counts 1, and the measured mutation
     * is exactly that -- a guard, not a deletion. So the statement's own line
     * is asserted to carry nothing in front of it and to be indented like the
     * `continueWith` it precedes, which is what a same-line guard and an
     * enclosing block respectively disturb.
     *
     * MEASURED, three shapes, each 12 summary lines and rc=1: the put DELETED
     * (3 FAIL), the reviewer's same-line guard `if (source == null) ...`
     * (2 FAIL, the line prefix and the indent), and an ENCLOSING `if { }`
     * block (1 FAIL, the indent alone -- the block re-indents by four).
     *
     * WHAT REMAINS UNSEEN even so: a guard whose block happens to re-indent to
     * exactly this column, and any condition that is false at RUNTIME rather
     * than in the text. Closing that needs Burp driving real traffic, and it
     * is Task 9's -- see HxExtension's assumption block.
     */
    static void theClockAndTheAttributionAreWrittenDownAndTakenBack()
            throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int put = count(entry, "pending.put(");
        int take = count(entry, "pending.take(");
        check("the request handler writes the clock and the source down ("
              + put + ")", put == 1);
        check("and both the response handler and the refusing re-decision take "
              + "them back (" + take + ")", take == 2);

        // AND THE PUT IS UNCONDITIONAL. The measured mutation is not a
        // deletion -- it is `if (source == null) pending.put(...)`, which
        // leaves the count above at 1. So the statement's own line is checked:
        // nothing but whitespace in front of it, and the same indentation as
        // the `continueWith` that follows it in the same block.
        int put1 = entry.indexOf("pending.put(");
        int lineStart = entry.lastIndexOf('\n', put1) + 1;
        String prefix = put1 >= 0 ? entry.substring(lineStart, put1) : "x";
        check("the put is a statement of its own, with no guard in front of it "
              + "[" + prefix + "]", put1 >= 0 && prefix.isBlank());
        int cont = entry.indexOf("return ProxyRequestReceivedAction.continueWith(r);");
        int contStart = entry.lastIndexOf('\n', cont) + 1;
        check("and sits in the same block as the pass-through it precedes ("
              + prefix.length() + " vs " + (cont - contStart) + ")",
              cont > put1 && prefix.length() == cont - contStart);
    }

    /**
     * THE RECORDING STRUCTURES HOLD THEIR MONITORS.
     *
     * `Pending` is reached from Burp's proxy threads, so every read and every
     * write of its map and its counter is inside `synchronized (live)`. The
     * concurrency test in `PendingTest` separates that for `put` and `take` --
     * with all four monitors removed it goes red 3 runs of 3 -- but NOT for
     * `evicted()` and `size()`, which no test reads from a second thread.
     * MEASURED by a reviewer: de-synchronizing those two alone reads 12 / 0
     * FAIL / rc=0, so the claim in `Pending`'s javadoc was true and held by
     * nothing.
     *
     * A COUNT IS NOT A PLACEMENT CHECK and this one does not pretend to be:
     * four `synchronized (live) {` in that file could in principle be four
     * monitors around the wrong code. What it does catch is the shape that
     * actually happens -- an accessor written or edited without one -- and the
     * placement of the two that matter most is separated behaviourally next
     * door. The four are `put`, `take`, `evicted` and `size`; the number is
     * stated rather than derived because there is nothing in the file to
     * derive it from that is not the same count read twice.
     */
    static void theRecordingStructuresHoldTheirMonitors() throws IOException {
        String pending = code(Path.of("src", "hx", "proxy", "Pending.java"));
        int monitors = count(pending, "synchronized (live) {");
        check("Pending guards all four of its accessors -- put, take, evicted, "
              + "size (" + monitors + ")", monitors == 4);
    }

    /**
     * ENFORCEMENT NEVER WAITS ON RECORDING.
     *
     * The gate is asked before anything is offered to the capture queue. Put
     * the other way round -- offer first, decide after -- and every refused
     * request has already been queued as an exchange the harness will record,
     * and a full or wedged queue is suddenly in the path of a DECISION rather
     * than of a record. S4 is explicit that a wedged harness changes what hx
     * KNOWS, never what it ALLOWS; this is that sentence made structural.
     *
     * A position check, and the honest reason is the same one
     * {@link #theAdapterBuildsItsRequestInsideTheTry} gives: HxExtension needs
     * Burp to run at all. Offsets are taken in {@link #code}, whose stripper
     * preserves length, so an index into it is an index into the file and a
     * commented decoy cannot move either end.
     *
     * THE ANTI-VACUITY CHECKS ARE LOAD-BEARING, not decoration. `indexOf`
     * answers -1 for a needle that is not there, and -1 is less than every
     * real offset -- so DELETING the gate call would satisfy "the gate comes
     * first" perfectly. The presence checks are what make the mutation red.
     *
     * WHAT IT DOES NOT SEE: which handler each needle is in. These are
     * FIRST-OCCURRENCE offsets over the whole file, not brace nesting, so a
     * `gate.decide(` in one handler ahead of a `capture.offer(` in another
     * satisfies it. There is exactly one of the former, so today it cannot
     * drift; a second decision site would need this check rewritten around
     * the handler's own body, the way the adapter check anchors at its
     * declaration.
     */
    static void theGateDecidesBeforeAnythingIsQueued() throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int decide = entry.indexOf("gate.decide(");
        int offer = entry.indexOf("capture.offer(");
        check("the gate is asked in " + ENTRY_POINT + " (" + decide + ")",
              decide >= 0);
        check("and something is queued there (" + offer + ")", offer >= 0);
        check("and the decision comes first (" + decide + " < " + offer + ")",
              decide >= 0 && offer >= 0 && decide < offer);
    }

    /**
     * THE RECORD IS BUILT BY THE THING THAT REDACTS, AND NEVER HERE.
     *
     * THREE TURNS OF ONE SCREW, and this method is what is left of them. The
     * redaction wiring lived in {@link #ENTRY_POINT} and the same defect was
     * found three times, each smaller than the last and each GREEN against the
     * check written for the one before it:
     *
     *   1. the request half redacted with `redactRequest` and an empty
     *      `Injected` -- `return raw.clone()`, the operator's live cookie
     *      into a content-addressed store. Closed by an ORDER check;
     *   2. both redaction calls left in place and the RAW locals queued
     *      instead of their results -- one identifier each. Closed by a
     *      DATAFLOW check: each local bound once, read once, and the record
     *      construction delimited and searched for the names it must not
     *      contain;
     *   3. the two redactors SWAPPED. Both functions still correct, both
     *      pointed at the wrong message, BOTH HALVES leaking -- and every
     *      assertion of (2) still satisfied, because each function is still
     *      called and each result is still queued. MEASURED at 12 summary
     *      lines / 1880 ok / 0 FAIL / rc=0.
     *
     * ORDERING IS NOT DATAFLOW; DATAFLOW IS NOT APPLICATION. Every one of
     * those checks asks a question about the TEXT of a file that needs Burp to
     * construct a single argument and so cannot be executed by this suite at
     * all. The fourth hole would have been smaller again. So the redaction,
     * the pairing of each redactor to its own message, and the construction of
     * the {@link hx.proxy.Observed} were moved into {@link hx.proxy.Recorder},
     * which has no `burp.*` type in it, and `RecorderTest` DRIVES them: it
     * asserts over BYTES, so a swapped pair, a discarded argument and an
     * identity function all turn it red.
     *
     * WHAT IS LEFT FOR TEXT TO SAY, and it is the whole of what this method
     * now does:
     *
     *   - the record is built by the Recorder and NEVER inline. THE REAL BOUND
     *     HERE IS THE COMPILER, NOT THIS COUNT. `new Observed(` missed
     *     `new hx.proxy.Observed(`; the widened `Observed(` missed
     *     `Observed::new` -- measured at 13 / 1900 ok / 0 FAIL / rc=0 with
     *     both halves raw -- and a third widening would miss a fourth
     *     spelling. So {@link hx.proxy.Observed} and {@link hx.proxy.Denied}
     *     are PACKAGE-PRIVATE: nothing outside `hx.proxy` can name either type
     *     by any spelling, and `javac` says so rather than a needle. That is
     *     asserted where it can be asserted for real -- by REFLECTION, in
     *     `RecorderTest.theCompilerBoundsConstruction`, which reads the
     *     compiled modifiers and cannot be fooled by how a construction is
     *     written. The count below is what remains useful AFTER that bound:
     *     it narrows construction WITHIN the package to one file, and it is
     *     spelling-bound in the way the compiler is not;
     *   - the proxy path's redaction is on the drivable side of the line.
     *     `.redactObservedRequest(` appears exactly once in extension/src and
     *     it is in Recorder.java, and the entry point CALLS neither redaction
     *     method at all. Moving either call back into the entry point is red.
     *     Counted WITH the leading dot, the way the deprecated-accessor check
     *     is, so `Redactor`'s own declaration of the method is not a call;
     *   - THE FIRST call site's two raw arrays go to the two slots the right
     *     way round. Both are `byte[]`, so a swap compiles and puts the
     *     response in the request's slot. Each binding is delimited to its own
     *     `;` and checked for what it names, and their order inside the call
     *     is asserted;
     *   - and there is only one call site to check, because the Recorder is
     *     CONSTRUCTED once and CALLED once. Both halves of that are needed and
     *     only the first was obvious: every arm above is `indexOf`, the FIRST
     *     match, so a second `Recorder` built in another handler with the
     *     halves reversed was measured at 13 / 1900 ok / 0 FAIL / rc=0 with
     *     both halves leaking -- G1 restored through a door nothing was
     *     looking at. But ONE Recorder called TWICE is the same door, so the
     *     call is counted too. Constructions are counted the way `Policy` is.
     *
     * THE ORDERING AND CALL-SITE ARMS ARE A TEXT SCAN with the same limit as
     * every other in this file -- see the class javadoc: they see names, not
     * values, they cannot see through a call, and they read the FIRST call
     * site, which is only sufficient because the count above says there is one
     * Recorder to call. The layer that closes what they cannot is
     * `RecorderTest` for the transform and Task 9 for the wire.
     */
    static void theRecordIsBuiltByTheRecorderAndNeverInline(List<Path> sources)
            throws IOException {
        String entry = code(Path.of(ENTRY_POINT));

        // ---- the record is built where the redaction is ---------------------
        List<String> observed = new ArrayList<>();
        List<String> jobFour = new ArrayList<>();
        for (Path p : sources) {
            String c = code(p);
            // `Observed(` and not `new Observed(`, so a QUALIFIED
            // construction -- `new hx.proxy.Observed(...)` -- cannot slip
            // past. That shape was measured slipping past the `new ` spelling
            // during this round's own sabotage, which is the F4 lesson
            // arriving a third time: needle the name, not the phrase around
            // it. The cost is that the record's own DECLARATION matches, so
            // the expected answer is two files rather than one.
            int n = count(c, "Observed(");
            if (n > 0) observed.add(p + " x" + n);
            int j = count(c, ".redactObservedRequest(");
            if (j > 0) jobFour.add(p + " x" + j);
        }
        check("Observed is DECLARED in one file and CONSTRUCTED in one, and "
              + "the one that constructs it is " + RECORDER + " -- not " + observed,
              observed.equals(List.of(OBSERVED + " x1", RECORDER + " x1")));
        check("and redacts an observed request in exactly one place, the same "
              + "one -- not " + jobFour,
              jobFour.equals(List.of(RECORDER + " x1")));
        // The entry point names NEITHER redaction method. This is the
        // must-be-zero that says the wiring stayed on the drivable side of the
        // line: put either call back in here and it is red, whatever else the
        // line does.
        int entryRedacts = count(entry, ".redactObservedRequest(")
                         + count(entry, ".redactResponse(");
        check("and the entry point redacts nothing itself (" + entryRedacts + ")",
              entryRedacts == 0);

        // ONE Recorder, counted the way one Policy is -- and for a sharper
        // reason: every positional arm below reads the FIRST call site, so a
        // SECOND Recorder is a second call site nothing looks at. Measured:
        // one built in handleResponseToBeSent with the halves reversed read
        // 13 / 1900 ok / 0 FAIL / rc=0 with both halves leaking. `Recorder(`
        // and not `new Recorder(`, so a qualified construction cannot slip;
        // the cost is that Recorder's own constructor declaration matches.
        List<String> recorders = new ArrayList<>();
        for (Path p : sources) {
            int n = count(code(p), "Recorder(");
            if (n > 0) recorders.add(p + " x" + n);
        }
        check("Recorder is DECLARED in one file and CONSTRUCTED in one, and the "
              + "one that constructs it is " + ENTRY_POINT + " -- not " + recorders,
              recorders.equals(List.of(ENTRY_POINT + " x1", RECORDER + " x1")));
        // ...AND CALLED ONCE. One Recorder is not one call site: the same
        // object called twice is two sets of arguments and only the first is
        // read by the arms below. Counting constructions alone would have left
        // that, and the sentence "there is one call site" would have been a
        // claim about a count that does not say it.
        int calls = count(entry, "recorder.record(");
        check("and the entry point calls it exactly once, so the positional "
              + "arms below see every call there is (" + calls + ")", calls == 1);

        // ---- and it is handed the two halves the right way round ------------
        check("the entry point builds its record through the Recorder ("
              + entry.indexOf("recorder.record(") + ")",
              entry.indexOf("recorder.record(") >= 0);
        // Delimited through the same helper as the bindings, which answers ""
        // for a needle that is gone -- so a renamed call is a clean FAIL here
        // rather than a StringIndexOutOfBounds out of this method. Measured:
        // the unguarded version threw, TestSupport.t turned it into a named
        // FAIL, and every assertion after it went unrun.
        String args = statement(entry, "recorder.record(");
        int rawReq = args.indexOf("rawRequest");
        int rawResp = args.indexOf("rawResponse");
        check("the call names both raw halves (" + rawReq + ", " + rawResp + ")",
              rawReq >= 0 && rawResp >= 0);
        check("and passes the request half first (" + rawReq + " < " + rawResp + ")",
              rawReq >= 0 && rawResp >= 0 && rawReq < rawResp);
        // ADJACENT AND BARE. The ordering check above is satisfied by
        // `asSent(r, rawRequest), rawResponse` -- a call wrapping the value at
        // its use site, which is the residual this class's javadoc names and
        // the one shape a text scan cannot see through. It cannot see through
        // it here either; what it CAN say is that the two slots are the two
        // bare locals, side by side, with nothing between them. Measured red
        // on the wrapping shape and on the swap.
        check("and passes them bare and adjacent, with no call between the "
              + "locals and the slots", args.contains("rawRequest, rawResponse,"));

        // Each local bound once and passed once, so a third use is something
        // else being done with a raw array.
        check("the raw request local is bound once and passed once, not "
              + count(entry, "rawRequest") + " times",
              count(entry, "rawRequest") == 2);
        check("and the raw response local likewise, not " + count(entry, "rawResponse"),
              count(entry, "rawResponse") == 2);

        // ...and each holds what its name says. Delimited to its own binding
        // statement, because `toByteArray()` appears three times in this file
        // and `initiatingRequest()` five: an undelimited search would be
        // satisfied by the wrong site.
        String reqBind = statement(entry, "byte[] rawRequest =");
        String respBind = statement(entry, "byte[] rawResponse =");
        check("the request half is read from the INITIATING request ("
              + reqBind.trim() + ")", reqBind.contains("initiatingRequest("));
        check("and the response half from the response itself ("
              + respBind.trim() + ")",
              respBind.contains("toByteArray(") && !respBind.contains("initiatingRequest("));
    }

    /** One Java statement, from the start of {@code needle} to the `;` that
     *  ends it, or "" if the needle is absent. The empty string satisfies no
     *  `contains` check and fails every one, which is the fail-safe direction
     *  for a needle that has been renamed away. */
    static String statement(String haystack, String needle) {
        int at = haystack.indexOf(needle);
        if (at < 0) return "";
        int end = haystack.indexOf(";", at);
        return end < 0 ? "" : haystack.substring(at, end);
    }

    /**
     * EVERY NEEDLE THAT NAMES A TYPE MATCHES ITS OWN FULLY-QUALIFIED SPELLING.
     *
     * THIS EXISTS BECAUSE THE SAME DEFECT HAS APPEARED SIX TIMES ON ONE TASK,
     * always in the same shape and always found by a reviewer rather than by
     * this suite. Each was a needle that matched the spelling someone happened
     * to write and not the CONSTRUCT it was about:
     *
     *     `new Socket(`     blind to `new java.net.Socket(`
     *     `new Observed(`   blind to `new hx.proxy.Observed(`
     *     `Observed(`       blind to `Observed::new`
     *     `new Policy(`     blind to `new hx.policy.Policy(`   -- a second budget
     *     `import burp.`    blind to a fully-qualified Montoya type
     *     `openConnection(` blind to `URL.getContent()`        -- same family, API side
     *
     * Four of the six were WORKING defects, not hypotheticals: a live TCP
     * egress, two raw-credential leaks and a second per-run budget, each
     * measured at a fully green suite.
     *
     * So the property is asserted instead of re-derived by the next reviewer.
     * For each needle below, a fully-qualified spelling of the same construct
     * is written out and the needle must match it. No compilation and no
     * subprocess -- string work over this file's own text, finite, and
     * directly falsifiable: revert any needle to its `new `-prefixed or
     * `import `-prefixed form and its row goes red HERE, in the suite, rather
     * than in the next review. (It DOES read one file: its own source, for the
     * two anti-vacuity arms below.)
     *
     * ANTI-VACUITY RUNS BOTH WAYS FOR THE ONE FAMILY WHERE IT CAN. The needles
     * of {@link #noSecondEgressFamilyExists} live in one array literal, so
     * that array is parsed out of this file's own text and every entry is
     * required to have a row here -- adding a needle without a row is red. For
     * the needles scattered across other methods no rule can enumerate them,
     * so the reverse direction is all there is: every row's needle must appear
     * verbatim somewhere in this file, which catches a needle renamed out from
     * under its row but NOT a new needle added elsewhere without one. That
     * asymmetry is the honest limit of this check and is why the array family
     * -- the one with a history -- is the one held from both sides.
     *
     * WHAT THIS DOES NOT ASSERT, because qualification is not the only
     * dimension: a CONSTRUCTOR REFERENCE (`Socket::new`, `Policy::new`) has no
     * paren and matches no `X(` needle, and a METHOD REFERENCE
     * (`client::configEpoch`) matches no `.x()` needle. Those are named as
     * residuals where they arise. The one place that dimension IS closed is
     * {@link hx.proxy.Observed} and {@link hx.proxy.Denied}, where the answer
     * was not a better needle but a package-private record and a compiler.
     */
    static void everyTypeNeedleSurvivesQualification() throws IOException {
        // {needle, a fully-qualified spelling of the same construct}
        String[][] rows = {
            {"Socket(",           "new java.net.Socket(\"127.0.0.1\", 1)"},
            {"InetSocketAddress", "new java.net.InetSocketAddress(\"h\", 1)"},
            {"URL(",              "new java.net.URL(\"http://h/\")"},
            {"openConnection(",   "new java.net.URL(\"http://h/\").openConnection()"},
            {"openStream(",       "new java.net.URL(\"http://h/\").openStream()"},
            {"HttpClient",        "java.net.http.HttpClient.newHttpClient()"},
            {"DatagramSocket",    "new java.net.DatagramSocket()"},
            {"InetAddress",       "java.net.InetAddress.getByName(\"h\")"},
            {"ProcessBuilder",    "new java.lang.ProcessBuilder(\"curl\")"},
            {"Runtime.getRuntime", "java.lang.Runtime.getRuntime().exec(\"curl\")"},
            {"collaborator()",    "api.collaborator().createClient()"},
            {"Policy(",           "new hx.policy.Policy(limits)"},
            {"Recorder(",         "new hx.proxy.Recorder(redactor)"},
            {"Observed(",         "new hx.proxy.Observed(m, u, s, ms, q, r, src)"},
            {MONTOYA,             "burp.api.montoya.core.ByteArray b = null;"},
            {"RedirectionMode.",  "burp.api.montoya.http.RedirectionMode.NEVER"},
            {"HttpService.httpService(",
             "burp.api.montoya.http.HttpService.httpService(h, p, s)"},
            {"HttpRequest.httpRequest(",
             "burp.api.montoya.http.message.requests.HttpRequest.httpRequest(s, b)"},
            {"hx.proxy",          "hx.proxy.Observed o = null;"},
        };
        String self = text(Path.of("test", "hx", "ChokepointTest.java"));
        check("this class can read its own source (" + self.length() + " chars)",
              self.length() > 10_000);
        // The rows above are string literals in this same file, so a naive
        // "is this needle still used" search finds the ROW and passes on a
        // needle nothing else spells any more. The table is cut out first.
        int rowsAt = self.indexOf("String[][] rows = {");
        int rowsEnd = self.indexOf("        };", rowsAt);
        check("the row table was located and excluded (" + rowsAt + ".."
              + rowsEnd + ")", rowsAt >= 0 && rowsEnd > rowsAt);
        String elsewhere = rowsEnd > rowsAt
                ? self.substring(0, rowsAt) + self.substring(rowsEnd) : self;

        for (String[] row : rows) {
            check("`" + row[0] + "` matches its qualified spelling `" + row[1] + "`",
                  count(row[1], row[0]) >= 1);
            // ...and the needle is one this file actually uses, SOMEWHERE
            // OTHER THAN THE ROW. A row whose needle has been renamed away is
            // stale, and a stale row is a green check about nothing.
            check("...and `" + row[0] + "` is a needle this file still uses",
                  count(elsewhere, "\"" + row[0] + "\"") >= 1);
        }

        // The one family that can be enumerated: every needle in
        // noSecondEgressFamilyExists's array must have a row above.
        int from = self.indexOf("String[] needles = {");
        int to = self.indexOf("};", from);
        check("the egress needle array was found (" + from + ".." + to + ")",
              from >= 0 && to > from);
        List<String> missing = new ArrayList<>();
        String array = to > from ? self.substring(from, to) : "";
        int at = 0;
        int found = 0;
        while ((at = array.indexOf('"', at)) >= 0) {
            int end = array.indexOf('"', at + 1);
            if (end < 0) break;
            String needle = array.substring(at + 1, end);
            found++;
            boolean covered = false;
            for (String[] row : rows) if (row[0].equals(needle)) covered = true;
            if (!covered) missing.add(needle);
            at = end + 1;
        }
        check("every egress needle was read out of the array (" + found + ")",
              found >= 10);
        check("...and every one of them has a qualified-spelling row " + missing,
              missing.isEmpty());
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
