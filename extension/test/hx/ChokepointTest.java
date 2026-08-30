// extension/test/hx/ChokepointTest.java
package hx;

import hx.TestSupport;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
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
        t("theBuiltRequestOptionsAreTheOnesIssued",
          ChokepointTest::theBuiltRequestOptionsAreTheOnesIssued);
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
        t("theCaptureDrainIsStarted", ChokepointTest::theCaptureDrainIsStarted);
        t("everyPathThatSpendsTheGateArmsItFirst",
          ChokepointTest::everyPathThatSpendsTheGateArmsItFirst);
        t("theGateIsSpentOnlyWhereTheHalvesArePaired",
          () -> theGateIsSpentOnlyWhereTheHalvesArePaired(sources));
        t("theCompositionHappensAfterTheGate",
          ChokepointTest::theCompositionHappensAfterTheGate);
        t("oneRunHasOnePolicy", () -> oneRunHasOnePolicy(sources));
        t("noSecondEgressFamilyExists", () -> noSecondEgressFamilyExists(sources));
        t("theAdapterBuildsItsRequestInsideTheTry",
          ChokepointTest::theAdapterBuildsItsRequestInsideTheTry);
        t("theSecondEnforcementPointIsRegisteredAndAsksTheGate",
          ChokepointTest::theSecondEnforcementPointIsRegisteredAndAsksTheGate);
        t("theSecondCallbackObservesAndCannotRefuse",
          ChokepointTest::theSecondCallbackObservesAndCannotRefuse);
        t("theRefusalIsHeldBeforeItIsRecorded",
          ChokepointTest::theRefusalIsHeldBeforeItIsRecorded);
        t("theClockAndTheAttributionAreWrittenDownAndTakenBack",
          ChokepointTest::theClockAndTheAttributionAreWrittenDownAndTakenBack);
        t("theRecordingStructuresHoldTheirMonitors",
          ChokepointTest::theRecordingStructuresHoldTheirMonitors);
        t("theGateDecidesBeforeAnythingIsQueued",
          ChokepointTest::theGateDecidesBeforeAnythingIsQueued);
        t("theTypeNeedlesCoverEveryConstructionForm",
          ChokepointTest::theTypeNeedlesCoverEveryConstructionForm);
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
            int n = calls(t, "http().sendRequest", "::sendRequest");
            total += n;
            if (n > 0) hits.add(p + " x" + n);
            int h = calls(t, ".http()", "::http");
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
        for (Path p : sources)
            total += calls(text(p), "sendRequests(", "::sendRequests");
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
     * A DISCARDED BUILDER RETURN USED TO BE INVISIBLE HERE and is not any
     * more; the two checks that close it are below and the measurement is
     * beside them. The paragraph that follows is what the gap WAS, kept
     * because it is the clearest statement of the shape: Montoya's options
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
        // ...AND THE BUILDER RETURN IS KEPT. Montoya's options builder returns
        // a NEW object rather than mutating, so
        // `options.withRedirectionMode(RedirectionMode.NEVER);` as a bare
        // statement compiles, does nothing, and reads identically to the
        // correct code. MEASURED with exactly that edit: 13 summary lines /
        // 2067 ok / 0 FAIL / rc=0, with redirects FOLLOWED inside Burp -- each
        // hop then a request that never crossed Policy, which is S4's third
        // egress path wearing the first one's name. Presence is not
        // application, one level over into a fluent chain.
        //
        // Delimited to the statement that BINDS `options`, so a call whose
        // result is dropped on the floor sits outside the span. It is a text
        // scan and it pins WHERE the setting is written, not what the built
        // object holds; nothing here can run the builder.
        // Read with COMMENTS STRIPPED, deliberately: `statement` ends at the
        // first `;`, and the javadoc inside this very chain contains one
        // ("...on sendRequest today;"). With `text` the span stopped before the
        // builder call and this check failed against CORRECT code -- measured.
        // Literals are kept, because `RedirectionMode.NEVER` is what is being
        // looked for and is not one.
        String chain = codeKeepingLiterals(Path.of(ENTRY_POINT));
        String built = statement(chain, "RequestOptions options =");
        check("the mode is set inside the options the adapter KEEPS, not in a "
              + "statement whose return is discarded",
              built.contains("RedirectionMode.NEVER"));
        // BOTH GRAMMAR FORMS, through calls(). `options::withRedirectionMode`
        // is an invocation in every sense that matters and this needle counted
        // one spelling of it -- which is also why the needle now has a row in
        // theTypeNeedlesCoverEveryConstructionForm's `called` table, where
        // every COUNTED method needle belongs. The reference form cannot
        // legally appear inside the built statement, so the sums are the same
        // numbers on correct code; what changes is that a reference ADDED
        // elsewhere in the adapter now moves the right-hand count and reddens
        // this arm instead of sliding past it.
        check("and every withRedirectionMode call is in that same statement ("
              + calls(built, "withRedirectionMode(", "::withRedirectionMode")
              + " of "
              + calls(chain, "withRedirectionMode(", "::withRedirectionMode") + ")",
              calls(built, "withRedirectionMode(", "::withRedirectionMode")
                      == calls(entry, "withRedirectionMode(", "::withRedirectionMode")
              && calls(chain, "withRedirectionMode(", "::withRedirectionMode") == 1);
        check("and it names exactly one redirection mode, so a second setting "
              + "cannot override it (" + any + ")", any == 1);
    }

    /**
     * THE OPTIONS THE ADAPTER BUILDS ARE THE OPTIONS IT ISSUES UNDER.
     *
     * PRESENCE IS NOT APPLICATION, one level out from the hole
     * {@link #redirectsAreNotFollowed} closed. That check pins WHERE the
     * redirection mode is written and cannot see whether the object the chain
     * built ever reaches the call. {@code Http.sendRequest} has a
     * ONE-ARGUMENT OVERLOAD, so dropping the second argument COMPILES, and
     * both mutations below were measured green against a clean
     * 13 summary lines / 2200 ok / 0 FAIL / rc=0:
     *
     *     rr = api.http().sendRequest(request);
     *     rr = api.http().sendRequest(request,
     *              RequestOptions.requestOptions().withResponseTimeout(remainingMs));
     *
     * In BOTH, `RedirectionMode.NEVER` is computed and thrown away: `never`
     * is 1, `any` is 1, the built statement still contains the constant, and
     * both `withRedirectionMode(` counts are satisfied -- while the request
     * goes out under Burp's DEFAULT redirection mode. S4: "Not auto-followed.
     * Each hop is a distinct issuance with its own scope decision and its own
     * exchange row." Every hop after the first would never cross Policy, which
     * is S4's third egress path wearing the first one's name. The first
     * mutation drops `withResponseTimeout` with it, so the deadline stops
     * being enforced at the transport too -- Sender still answers `timeout` on
     * its own clock, so that half is a fail-safe loss rather than a hole.
     *
     * The SECOND mutation is the realistic one: it still passes AN options
     * object, so it reads in review as the correct code with the chain
     * refactored.
     *
     * WHAT THIS CHECKS, and it is a DATAFLOW shape rather than a spelling of
     * the call: the local the builder chain binds is used EXACTLY ONCE in the
     * whole entry point, and that one use is inside the egress statement. So
     * a call that takes no options (0 uses), a call handed a freshly built
     * object (the bound local unused, 1 use), and a rebuild between the two
     * (3 uses) are all red. Measured results for both of the above are in the
     * fix-wave report.
     *
     * WHAT IT DOES NOT COVER, stated because the family this belongs to is
     * six instances deep and every one of them was a check that overclaimed:
     *
     *   - A THIRD OVERLOAD. `sendRequest(request, options, somethingElse)`
     *     satisfies every arm here, and if that third argument could override
     *     the redirection mode this check would not see it. MEASURED rather
     *     than assumed, because the first draft of this sentence guessed and
     *     guessed wrong: `javap burp.api.montoya.http.Http` on the jar this
     *     tree builds against lists FOUR `sendRequest` overloads --
     *     `(HttpRequest)`, `(HttpRequest, HttpMode)`,
     *     `(HttpRequest, HttpMode, String)` and `(HttpRequest,
     *     RequestOptions)`. Only the last takes options at all, so no
     *     three-argument call can carry them and there is nothing today for
     *     this gap to be. The `(HttpRequest, HttpMode)` form is a TWO-argument
     *     call that drops the options entirely, and the arms below do catch
     *     it -- the bound local goes unread. Nothing here would notice a
     *     future overload arriving.
     *   - THE IDENTIFIER'S NAME. `options` is a spelling. Renaming the local
     *     turns the binding needle and the count red together, so it fails
     *     CLOSED and the next reader updates two literals -- but this method
     *     is pinned to a name, not to a type.
     *   - WHETHER MONTOYA HONOURS THE OBJECT. Nothing in this repository can
     *     run the builder; that is `docs/burp-proxy-measurements.md`'s job.
     *   - {@link #statement} ends at the FIRST `;`, so an argument list
     *     containing one would truncate the span. Today neither does.
     *
     * Read from {@link #codeKeepingLiterals} for the same reason
     * {@link #redirectsAreNotFollowed} is: `statement` stops at a `;` and the
     * javadoc inside the adapter's own chain contains one, so comments must be
     * stripped -- while literals are kept, because a literal is not what is
     * being counted here and blanking one cannot help.
     */
    static void theBuiltRequestOptionsAreTheOnesIssued() throws IOException {
        String chain = codeKeepingLiterals(Path.of(ENTRY_POINT));
        String built = statement(chain, "RequestOptions options =");
        String issue = statement(chain, "http().sendRequest(");
        // Anti-vacuity, both ends: statement() answers "" for a needle that
        // has been renamed away, and "" satisfies no arm below -- count 0 is
        // not 1 and "" contains nothing. -1-style vacuity has no equivalent
        // here, but the two presence checks are stated anyway so a rename
        // reads as a rename rather than as a dataflow failure.
        check("the adapter binds its RequestOptions (" + built.trim() + ")",
              !built.isEmpty());
        check("and the egress statement was located (" + issue.trim() + ")",
              !issue.isEmpty());
        // ONE BINDING, ONE READ, IN THE WHOLE ENTRY POINT. `RequestOptions`
        // and `requestOptions()` carry a CAPITAL O and do not match this
        // needle, so the two hits are the declaration and the argument.
        check("the built options are read exactly once in " + ENTRY_POINT
              + " (" + count(chain, "options") + ")",
              count(chain, "options") == 2);
        check("one of the two is the binding itself (" + count(built, "options") + ")",
              count(built, "options") == 1);
        // ...so the other one is here, and this is the arm the two measured
        // mutations fail.
        check("and the other is the argument the egress call issues under ("
              + issue.trim() + ")", issue.contains("options"));
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
            // BOTH CALL FORMS. A method reference is an invocation, and
            // `client::configEpoch` contains no `.configEpoch()` -- so the
            // paren form alone left a must-be-zero check that a two-line
            // detour walks past, which is the same grammar point the
            // constructor needles were fixed for. See
            // theTypeNeedlesCoverEveryConstructionForm.
            epoch += calls(t, ".configEpoch()", "::configEpoch");
            scope += calls(t, ".scopeConfig()", "::scopeConfig");
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

    /** ...and its sibling, counted for the same reason. */
    static final String DENIED =
            Path.of("src", "hx", "proxy", "Denied.java").toString();

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
     * proxy request handler, and the scope observation before the bytes
     * leave.
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
     * DERIVED FROM THE QUESTIONS -- `gate.decide(` + `decideScopeOnly(` -- and
     * that is a restoration. Fix round 1 moved it to counting CALLBACK
     * DECLARATIONS, because the second callback had gained a SECOND question
     * (`decideBeforeGate` for the crawler, `decideScopeOnly` for the operator)
     * and counting questions would have read three against two reads and gone
     * red on correct code. Task 9 measured that the second callback cannot
     * refuse anything -- `ProxyRequestToBeSentAction.drop()` does not prevent
     * egress on Burp 2026.7.3 -- so it no longer branches by source and no
     * longer decides: it asks ONE question, `decideScopeOnly`, and logs.
     *
     * Questions are the stronger unit whenever it is available, and this is
     * why it is taken back: a callback that grows a SECOND question without a
     * second snapshot read is exactly the two-halves-of-two-authorisations bug
     * this method exists for, and a count of DECLARATIONS cannot see it.
     *
     * The two questions are not the same kind of thing and the equality does
     * not claim they are: `gate.decide(` DECIDES and `decideScopeOnly(`
     * OBSERVES. What both need, and what is counted, is that each was answered
     * under an authorisation fetched for THIS request -- an observation
     * assembled from two halves of two authorisations is a log line an
     * operator acts on at 02:00 and it must not be a guess either.
     *
     * THE WITNESS FOR THE EQUALITY, in the shape
     * `test_vocabularies_match_the_schema.py` uses for its own: it is vacuous
     * if both sides are zero -- a file with no reads and no questions
     * satisfies it -- so the question count is asserted to be 2 outright.
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
            int n = calls(code(p), ".authorisation()", "::authorisation");
            total += n;
            if (n > 0 && !p.toString().equals(BRIDGE_CLIENT)
                      && !p.toString().equals(ENTRY_POINT))
                elsewhere.add(p + " x" + n);
        }
        String bridge = code(Path.of(BRIDGE_CLIENT));
        String entry = code(Path.of(ENTRY_POINT));
        int inBridge = calls(bridge, ".authorisation()", "::authorisation");
        int inEntry = calls(entry, ".authorisation()", "::authorisation");
        // The two questions the entry point asks of a request: the gate call
        // that DECIDES, and the pre-send scope call that only OBSERVES. A
        // response handler asks neither and must read nothing, which is what
        // the totals below enforce.
        int questions = calls(entry, "gate.decide(", "gate::decide")
                      + calls(entry, "decideScopeOnly(", "::decideScopeOnly");

        check("the send arm reads the Authorisation snapshot once (" + inBridge + ")",
              inBridge == 1);
        check("the entry point asks two questions -- the proxy gate and the "
              + "pre-send scope observation (" + questions + ")",
              questions == 2);
        check("and reads the snapshot exactly once per question ("
              + inEntry + " reads, " + questions + " questions)",
              inEntry == questions);
        check("nothing else in extension/src reads it at all " + elsewhere,
              elsewhere.isEmpty());
        check("so the whole extension reads it " + (1 + questions) + " times, "
              + "once per question (" + total + ")", total == 1 + questions);

        // Each read AHEAD of the question it feeds. Without this, two reads in
        // one callback and none in the other satisfies the equality above --
        // and "none in the other" is an answer taken under an authorisation
        // fetched for a different request.
        int read1 = entry.indexOf(".authorisation()");
        int gate = entry.indexOf("gate.decide(");
        int read2 = entry.indexOf(".authorisation()", read1 + 1);
        int observation = entry.indexOf("policy.decideScopeOnly(", read2);
        check("the request handler reads before it asks the gate (" + read1
              + " < " + gate + ")", read1 >= 0 && read1 < gate);
        check("and the pre-send observation reads its own, after that gate "
              + "call and before its own question (" + gate + " < " + read2
              + " < " + observation + ")",
              read2 > gate && observation > read2);
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
     * that and nothing more. It is item 2 of the canonical open list in
     * {@link hx.proxy.Recorder}'s javadoc, which is the one place this path's
     * residuals are enumerated.
     */
    static void noSecondEgressFamilyExists(List<Path> sources) throws IOException {
        String[] needles = {
            "Socket(",            // a TCP client socket, straight from the JDK,
                                  // qualified or not -- see the javadoc above
            "Socket::new",        // ...and the OTHER spelling a constructor has
            "InetSocketAddress",  // ...or the address that turns a channel into one
            "URL(",               // the OBJECT, not one of its doors: see above
            "URL::new",           // ...in both of its constructor spellings too
            "openConnection(",    // URL -> URLConnection / HttpURLConnection
            "::openConnection",   // ...and the reference form of the same call
            "openStream(",        // URL.openStream(), the one-liner version
            "::openStream",       // ...likewise
            "HttpClient",         // java.net.http, the modern one
            "DatagramSocket",     // UDP is egress too
            "InetAddress",        // a DNS lookup is bytes off this machine
            "ProcessBuilder",     // ...and so is `curl`
            "Runtime.getRuntime", // the older spelling of the same thing
            "collaborator()",     // Montoya's OTHER network facility
            "::collaborator",     // ...reached by reference
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
     * THE WHOLE-TREE PAIR `before == 1 && gate == 1 && before == gate` IS
     * BACK, and its round trip is worth recording. Task 7's fix round 1 gave
     * the proxy path's second callback a re-DECISION that asked
     * `decideBeforeGate`, which made the whole-tree count 2 and forced this
     * check into a per-file form. Task 9 measured that
     * `ProxyRequestToBeSentAction.drop()` does not prevent egress on Burp
     * 2026.7.3, so that callback cannot refuse anything and no longer tries:
     * it asks `decideScopeOnly` and LOGS. `decideBeforeGate` therefore has one
     * caller again -- the issuing path -- and the original assertion is the
     * true one.
     *
     * What the check says, DERIVED per file rather than restated as a total:
     *
     *   - the ISSUING path (Sender) asks both halves, the same number of
     *     times, and that number is one. This is the original pair assertion,
     *     narrowed to the file where the interleaving actually lives -- so a
     *     deleted `.checkGate(` there is still red;
     *   - NO OTHER FILE IN THE TREE ASKS EITHER HALF, the entry point
     *     included. A must-be-zero, which is the strongest shape this class
     *     has. A third caller of `decideBeforeGate` is a path that might issue
     *     on a half-decision, and it has to be looked at by a human rather
     *     than absorbed into a total;
     *   - and the entry point does not reach the Gate through the FRONT DOOR
     *     either. Kept from fix round 1 and it is not about the deleted
     *     decision: `policy.decide(` runs both halves inside Policy without
     *     ever spelling `.checkGate(` here, which is the shape a double charge
     *     would actually be written in, and the sweep above cannot see it.
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
        int senderBefore = calls(sender, ".decideBeforeGate(", "::decideBeforeGate");
        int senderGate = calls(sender, ".checkGate(", "::checkGate");

        check("the issuing path asks the boundary half exactly once ("
              + senderBefore + ")", senderBefore == 1);
        check("and the Gate half exactly once with it (" + senderGate + ")",
              senderGate == 1);
        // The pair, not the two counts separately: what makes an allowed first
        // half safe is that a second half follows it.
        check("so the issuing path never takes one without the other",
              senderBefore == senderGate);

        // ...and not through the front door either. `policy.decide(` runs both
        // halves INSIDE Policy, so it reaches the Gate without ever spelling
        // `.checkGate(` here -- which is the shape a double charge would
        // actually be written in, and the count above cannot see it. The
        // needle takes the paren, so `policy.decideBeforeGate(` and
        // `policy.decideScopeOnly(` do not match it. ProxyGate's own
        // `policy.decide(` is a different file and is the FIRST callback's
        // paying decision, which is correct.
        int entryFull = calls(entry, "policy.decide(", "policy::decide");
        check("and not through policy.decide(), which reaches the Gate without "
              + "naming it (" + entryFull + ")", entryFull == 0);

        // THE ENTRY POINT IS NO LONGER EXCLUDED. It was, while its second
        // callback asked `decideBeforeGate`; that call is gone, so the entry
        // point is swept like every other file and a re-added one is red here
        // rather than needing a count of its own.
        List<String> elsewhere = new ArrayList<>();
        for (Path p : sources) {
            if (p.toString().equals(SENDER)) continue;
            String c = code(p);
            // BOTH FORMS on BOTH halves. The round-4 report claimed every
            // must-be-zero method needle counted both; this arm did not, so a
            // `policy::checkGate` in ProxyGate's operator branch was invisible
            // to it and went red only through ProxyGateTest's budget check --
            // a different check catching it by luck of coverage.
            int n = calls(c, ".decideBeforeGate(", "::decideBeforeGate")
                  + calls(c, ".checkGate(", "::checkGate");
            if (n > 0) elsewhere.add(p + " x" + n);
        }
        check("and no other file in extension/src asks either half -- the "
              + "entry point included " + elsewhere, elsewhere.isEmpty());
    }

    /**
     * THE CREDENTIAL IS WRITTEN INTO THE BYTES AFTER THE GATE HAS ANSWERED.
     *
     * The refusal half of that ordering IS behavioural and is pinned:
     * `IdentityInjectionTest.aRequestTheGateREFUSEDNeverHasACredentialWrittenIntoIt`
     * hands the send path an input for which both a gate refusal and an
     * identity refusal are available, and discriminates on WHICH class comes
     * back. Moving the identity block above `policy.checkGate` turns that
     * suite red -- measured by the Task 5 reviewer at 15 ALL PASS, rc=1,
     * 2 FAIL, with exactly the two messages the report claimed.
     *
     * THE COMPOSITION HALF IS NOT, AND CANNOT BE. Moving `compose(` ALONE
     * above the gate -- bytes built and the credential written in for a
     * request the gate then refuses, both refusals left where they are --
     * left the whole suite at 16 ALL PASS / 0 FAIL / rc=0, also measured by
     * the reviewer. There is nothing for a behavioural test to see: the array
     * is a local, the `Injected` is a local, the request is refused, and both
     * are discarded with no trace outside `decideAndIssue` that any test can
     * read. So it was held by a comment, and this method is what makes it a
     * fact.
     *
     * WHAT IS ASSERTED IS THE ORDERING AND NOTHING MORE. Not that a
     * pre-gate composition would leak -- it would not, on today's code; the
     * consequence is bounded and the report said so. What it would break is
     * §4's invariant that every byte leaving this machine crossed a point
     * inside this JVM that decided about it: a credential written into a
     * request the Gate has not yet allowed is a request assembled on the
     * strength of no decision, and the only thing keeping it off the wire is
     * that the refusal happens to return in time.
     *
     * THE COUNT IS TWO AND BOTH ARE CHECKED. `compose(` occurs twice in
     * Sender.java's code -- the call in `decideAndIssue` and the declaration
     * of the method itself -- and this does not try to tell them apart. It
     * requires BOTH to sit after `.checkGate(`, which is sound whichever is
     * which: the call is one of the two. The cost is that moving the
     * DECLARATION above `decideAndIssue` would redden this for no behavioural
     * reason, and that is the trade taken rather than a fragile needle that
     * tries to name the call site alone. The count arm is what keeps "both"
     * exact: a third occurrence would leave a middle one unexamined, and the
     * count is what stops there being one.
     *
     * `.checkGate(` is read positionally here and its count is pinned at one
     * by {@link #theGateIsSpentOnlyWhereTheHalvesArePaired} in this same
     * class, so the offset taken below is the only occurrence rather than the
     * first of several.
     *
     * WHAT IT DOES NOT SEE, the limitation every offset in this file carries:
     * THESE ARE OFFSETS, NOT BRACE NESTING. A `compose(` moved into a branch
     * that runs before the gate but written lower in the file would pass. What
     * it catches is the mutation that was actually measured green -- the
     * statement cut and pasted above `policy.checkGate`.
     */
    static void theCompositionHappensAfterTheGate() throws IOException {
        String sender = code(Path.of(SENDER));
        int composes = calls(sender, "compose(", "::compose");
        check("compose( occurs twice in Sender.java -- one call, one "
              + "declaration (" + composes + ")", composes == 2);
        int gate = sender.indexOf(".checkGate(");
        int firstCompose = sender.indexOf("compose(");
        int lastCompose = sender.lastIndexOf("compose(");
        // Anti-vacuity: indexOf answers -1 for a needle that is absent and -1
        // is below every real offset, so a DELETED gate call would satisfy
        // "after the gate" perfectly.
        check("the Gate is asked in this file (" + gate + ")", gate >= 0);
        check("and the composition is in it (" + firstCompose + ".."
              + lastCompose + ")", firstCompose >= 0 && lastCompose > firstCompose);
        check("the first compose( is after the Gate (" + gate + " < "
              + firstCompose + ")", gate >= 0 && firstCompose > gate);
        check("and so is the second, so whichever is the call site is after "
              + "it (" + gate + " < " + lastCompose + ")",
              gate >= 0 && lastCompose > gate);
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
     * A NEEDLE AND NOT A COMPILER BOUND, and the difference is worth stating
     * because {@link hx.proxy.Observed} took the other road. That record is
     * package-private, so `javac` refuses every construction outside
     * `hx.proxy` whatever its spelling. `Policy` cannot be: `hx.send.Sender`
     * and `hx.proxy.ProxyGate` both hold one and `hx.HxExtension` builds it,
     * so it is public of necessity and a text needle is what there is. What
     * makes that acceptable is that the needle now covers the CLOSED set of
     * spellings a construction has -- see the two needles above and
     * {@link #theTypeNeedlesCoverEveryConstructionForm}.
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
            // BOTH CONSTRUCTOR SPELLINGS. `Policy(` alone was blind to
            // `Policy::new`, and a method reference is a construction: with
            // `Function<Limits, Policy> mk = Policy::new; mk.apply(limits)` in
            // the entry point this check read 13 summary lines / 1980 ok /
            // 0 FAIL / rc=0 -- a second Gate and a second per-run budget for
            // one run, measured. The Java grammar gives a constructor exactly
            // two spellings, `new T(` and `T::new`, each optionally qualified;
            // these two needles cover all four, and the sweep in
            // theTypeNeedlesCoverEveryConstructionForm asserts that they do.
            int n = calls(code(p), "Policy(", "Policy::new");
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
        // Each wire counted in BOTH grammar forms -- see calls(). A local per
        // wire, because the pair does not fit twice on a line.
        int sink = calls(entry, "setHaltSink(", "::setHaltSink");
        int source = calls(entry, "setHaltSource(", "::setHaltSource");
        int poller = calls(entry, "haltSwitch.start()", "haltSwitch::start");
        int notifier = calls(entry, "setHaltNotifier(", "::setHaltNotifier");
        int handler = calls(entry, "setSendHandler(", "::setSendHandler");
        int guard = calls(entry, "setConfigGuard(", "::setConfigGuard");
        check("a halt frame is routed to the switch the send path asks ("
              + sink + ")", sink == 1);
        check("and maySend() asks that same authority back (" + source + ")",
              source == 1);
        check("the sentinel poller is started (" + poller + ")", poller == 1);
        check("an auto-halt has somewhere to announce itself (" + notifier + ")",
              notifier == 1);
        check("and the send path is installed (" + handler + ")", handler == 1);
        check("and a configure that would move an armed limit is refused ("
              + guard + ")", guard == 1);

        // ---- ...BEFORE THE DIAL, which is the half the NAME claimed and the
        // body did not take. Six counts and zero offsets: a reviewer measured
        // `c.setConfigGuard(...)` moved to after `t.start()` at
        // 13 / 2200 ok / 0 FAIL / rc=0, and the five `c.set*` wires moved as a
        // block likewise. Re-measured against THESE arms on the tree that
        // carries them: the guard alone is 13 / 2257 ok / 1 FAIL / rc=1, and
        // the five wires plus the poller moved as a block is
        // 13 / 2251 ok / 7 FAIL / rc=1 (five of these arms, and two from
        // everyPathThatSpendsTheGateArmsItFirst, which the same move drags the
        // send-path arming past its decision). The window is a real race and
        // not a
        // theoretical one -- the dial runs on a daemon thread that opens a
        // real socket, and inside the window `BridgeClient.refuseConfigure`
        // returns null with no guard installed, which ACCEPTS.
        //
        // THE ANCHOR IS `t.start()` AND NOT `c.connect()`. The connect call is
        // textually EARLIER -- it sits inside the Runnable the Thread is
        // constructed with -- and it does not run until the thread is started,
        // so anchoring there would refuse correct code. `t.start()` is where
        // the client becomes live.
        //
        // ANTI-VACUITY IS `>= 0` ON EVERY ONE OF THEM, and it is load-bearing
        // exactly as it is in theGateDecidesBeforeAnythingIsQueued: indexOf
        // answers -1 for a needle that is absent and -1 is less than every
        // real offset, so a DELETED wire would satisfy "before the dial"
        // perfectly. The count arms above are what make each offset the ONLY
        // occurrence rather than the first of several.
        //
        // WHAT IT DOES NOT SEE, and the limitation is the one every
        // first-occurrence offset in this file carries:
        //
        //   - THESE ARE OFFSETS, NOT BRACE NESTING. A wire written inside a
        //     lambda that runs after the dial, or inside a branch never taken,
        //     sits at an earlier offset and passes. What it catches is the
        //     shape that actually happens: a wire MOVED below the dial, or
        //     added below it.
        //   - THE DOTTED FORM ONLY. `calls()` above sums both grammar forms,
        //     so a wire spelled purely as `c::setHaltSink` keeps the count at
        //     1 while indexOf answers -1 and this arm goes RED. That is
        //     fail-closed and deliberate: a bare method reference installs
        //     nothing until something applies it, and the offset check has no
        //     way to find where that happened.
        int dial = entry.indexOf("t.start()");
        check("the dial is where it is expected to be (" + dial + ")", dial >= 0);
        String[][] wired = {
            {"the halt sink",     "setHaltSink("},
            {"the halt source",   "setHaltSource("},
            {"the halt notifier", "setHaltNotifier("},
            {"the send handler",  "setSendHandler("},
            {"the config guard",  "setConfigGuard("},
            {"the sentinel poller", "haltSwitch.start()"},
        };
        for (String[] w : wired) {
            int at = entry.indexOf(w[1]);
            check(w[0] + " is installed before the dial (" + at + " < " + dial
                  + ")", at >= 0 && dial >= 0 && at < dial);
        }
    }

    /**
     * THE DRAIN IS STARTED, and until this method existed nothing in this file
     * said so.
     *
     * `capture.start()` was the ONE wire in {@link #ENTRY_POINT} named by no
     * `count(`, `calls(` or `indexOf(` anywhere in this class -- verified by
     * scanning every needle literal in the file, not by reading. Commented
     * out, it was 13 summary lines / 2200 ok / 0 FAIL / rc=0 against the tree
     * before this method existed. Re-measured against THIS method on the tree
     * that carries it: 13 / 2257 ok / 1 FAIL / rc=1, naming this check.
     *
     * WHAT THAT COSTS. {@code Capture.accepting} is true at field level and
     * {@code start()} is what creates the drain thread, so without it every
     * proxy exchange is offered into a queue NOTHING POLLS. The first
     * {@code DEFAULT_CAPACITY} records sit there uncounted; after that each
     * offer evicts one and counts it dropped. The store gets ZERO exchange
     * rows for the whole run, and `run.dropped_total` -- which S5 presents as
     * a coverage FLOOR -- under-reports the loss by up to a full queue. A
     * total outage that reads as a run which just saw little traffic.
     *
     * Only `pytest -m integration` could see it behaviourally. This is a
     * count, and a count is worth more than nothing for the failure that
     * actually happens: the line deleted, or never written.
     *
     * NO ORDERING IS CLAIMED, and the omission is deliberate rather than an
     * oversight. `capture.start()` sits beside `haltSwitch.start()` and before
     * the dial today, but nothing breaks if it moves after: an offer made
     * before the drain runs is queued, not lost, and delivery through the sink
     * fails until the bridge connects anyway. There is no window here of the
     * kind {@link #everyKillPathIsWiredBeforeTheDial} exists for, so this
     * method does not pretend to one. It is a WIRE-EXISTS needle read from
     * {@link #code}, so neither a comment nor a string literal can supply it.
     *
     * WHAT IT DOES NOT SEE: that the thread actually runs, that the sink is
     * connected, or that anything is ever delivered. All three need Burp.
     */
    static void theCaptureDrainIsStarted() throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int drain = calls(entry, "capture.start()", "capture::start");
        check("the capture drain is started, so a queued record has somewhere "
              + "to go (" + drain + ")", drain == 1);
    }

    /**
     * EVERY PATH THAT SPENDS THE GATE ARMS IT FIRST -- counted, because prose
     * naming the callers is what failed here.
     *
     * {@code Limits.arm} had ONE call site, inside `setSendHandler`, and
     * {@code Limits.check}'s own javadoc said the unarmed branch was
     * "Unreachable through HxExtension, which calls arm() on the same snapshot
     * on the line before issue()". THAT WAS TRUE WHEN IT WAS WRITTEN. Task 7
     * wired S4's second enforcement point, whose CRAWLER branch reaches
     * `ProxyGate.decide` -> `Policy.decide` -> `Limits.check`, and it did not
     * arm -- so every crawler request that passed scope, method and
     * dangerous.path was refused `not_configured` with the detail "the rate
     * and budget are not armed", until some unrelated `send` happened to arm
     * it. Fail-closed, and a lie about why: the denial lands under a
     * `denial.kind` an operator reads as "nobody authorised this run", with no
     * `EXTENSION_FAULT` prefix to separate a broken jar from an unconfigured
     * one.
     *
     * WHY THIS SUITE DID NOT SEE IT, all three reasons, because each is its
     * own lesson:
     *
     *   - this class counted NOTHING for `.arm(`. Deleting the call outright
     *     left 13 / 2200 ok / 0 FAIL / rc=0;
     *   - the only crawler-listener integration test drives a POST, which
     *     `method.allow` refuses BEFORE the Gate -- the test that existed
     *     stopped short of the code path;
     *   - the comment above the branch named its callers. A sentence naming a
     *     set of callers is falsified by a new caller in another file, and
     *     nothing makes a noise when that happens.
     *
     * So this is a COUNT OF CALL SITES rather than a sentence about them, in
     * both grammar forms through {@link #calls} -- `limits::arm` is a spelling
     * -- and it is TWO because there are two points that can consult the Gate.
     * Deleting either turns it red. So does ADDING a third call site, armed or
     * not, and that is the point rather than a wart: the number is a fact
     * about how many places can spend the Gate, and a wave that changes it
     * must come here and re-derive it.
     *
     * ...AND EACH ARMING COMES BEFORE THE DECISION IT ARMS. A call that
     * happens AFTER `Limits.check` has already answered is a call whose result
     * arrives too late, which is this codebase's own recurring family: the
     * count would stay at 2 and the first crawler request would still be
     * refused. The two offsets are taken as FIRST and LAST, which is exact
     * only because the count is pinned at 2 immediately above -- with a third
     * call site the middle one would be unexamined, and the count arm is what
     * stops there being one.
     *
     * WHAT IT DOES NOT SEE:
     *
     *   - BRACE NESTING, like every other offset in this file. The send arm's
     *     `limits.arm(` and `sender.issue(` are inside one lambda and the
     *     proxy pair inside one handler, and nothing here proves that; a
     *     `limits.arm(` moved into the WRONG one of the two would keep both
     *     orderings and go unnoticed.
     *   - WHETHER THE SNAPSHOT IS THE SAME ONE. Both sites are written
     *     `limits.arm(auth)` on the line above a decision taken under `auth`,
     *     and the identifier is not checked here --
     *     {@link #everyDecisionReadsOneAuthorisationSnapshot} is what holds
     *     "one read, passed in" for the file as a whole.
     *   - THAT `arm` IS ARMED-ONCE. That is {@code Limits}'s own contract and
     *     `LimiterTest`/`PolicyTest` drive it; a second call from a later
     *     snapshot returns early rather than re-arming, which is why adding
     *     the proxy call site cannot resupply a spent budget.
     */
    static void everyPathThatSpendsTheGateArmsItFirst() throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int arms = calls(entry, "limits.arm(", "limits::arm");
        check("both points that can consult the Gate arm it (" + arms + ")",
              arms == 2);
        int firstArm = entry.indexOf("limits.arm(");
        int lastArm = entry.lastIndexOf("limits.arm(");
        int issue = entry.indexOf("sender.issue(");
        int decide = entry.indexOf("gate.decide(");
        // Anti-vacuity: -1 is less than every real offset, so a deleted needle
        // would satisfy "comes first" perfectly.
        check("the send path arms (" + firstArm + ") and issues (" + issue + ")",
              firstArm >= 0 && issue >= 0);
        check("and arms before it issues (" + firstArm + " < " + issue + ")",
              firstArm >= 0 && issue >= 0 && firstArm < issue);
        check("the proxy path arms (" + lastArm + ") and decides (" + decide + ")",
              lastArm >= 0 && decide >= 0);
        check("and arms before it decides (" + lastArm + " < " + decide + ")",
              lastArm >= 0 && decide >= 0 && lastArm < decide);
        // The two are DIFFERENT call sites, not one counted twice. Without
        // this, two arms on the send path and none on the proxy path would
        // satisfy every arm above -- the count is 2, the first is before
        // issue(), and the last is still before gate.decide() because both sit
        // above the proxy handler in the file.
        check("and they are two distinct call sites (" + firstArm + " != "
              + lastArm + ")", firstArm >= 0 && lastArm > firstArm && firstArm < issue
              && lastArm > issue);
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
     * THERE WAS A FOURTH COUNT AND IT IS GONE. It read "scope is re-decided
     * before the request is sent (`decideScopeOnly(` == 1)", and it pinned a
     * DECISION that Task 9 measured cannot exist: a refusal at the second
     * callback does not stop the request, because
     * `ProxyRequestToBeSentAction.drop()` does not prevent egress on Burp
     * 2026.7.3. A check that pins a decision nothing can act on is a check
     * that certifies a hole as closed. The question is still asked and is now
     * an OBSERVATION -- see
     * {@link #theSecondCallbackObservesAndCannotRefuse}, which pins what is
     * actually true of it, including the must-be-zero that stops the refusal
     * being re-added.
     *
     * WIRE-EXISTS needles, all three, so they read {@link #code}: prose cannot
     * register a handler or ask a question. Taken in {@link #ENTRY_POINT},
     * which is the only file allowed to name burp.* at all -- see
     * {@link #montoyaIsConfinedToTheEntryPoint}, which is what makes that
     * narrowing safe rather than convenient.
     *
     * WHAT THESE DO NOT SEE: whether the handler HONOURS the verdict.
     * `if (!verdict.allow() && false)` forwards every refused request to the
     * target and reads 13 ALL PASS / 2198 ok / 0 FAIL / rc=0 -- re-measured on
     * this tree. `gate.decide(` is still called once, the offer is still
     * textually after it, and every count here is satisfied. Task 9 closed it
     * from outside: `tests/integration/test_proxy_capture.py` asserts a
     * refused request reaches the OUT-OF-SCOPE TARGET zero times, measured at
     * the target's own log and never by reading the client's response --
     * `drop()` answers the client 200 OK with 1529 bytes of Burp's own HTML
     * and is indistinguishable from a delivery by status code. That mutation
     * turns three integration tests red and no check here.
     *
     * The two position checks below cover the orderings; this one covers
     * existence.
     */
    static void theSecondEnforcementPointIsRegisteredAndAsksTheGate()
            throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int n1 = calls(entry, "registerRequestHandler(", "::registerRequestHandler");
        int n2 = calls(entry, "registerResponseHandler(", "::registerResponseHandler");
        int n3 = calls(entry, "gate.decide(", "gate::decide");
        check("registerRequestHandler appears exactly once (" + n1 + ")", n1 == 1);
        check("registerResponseHandler appears exactly once (" + n2 + ")", n2 == 1);
        check("the proxy handler asks the gate (" + n3 + ")", n3 == 1);
    }

    /**
     * THE SECOND CALLBACK OBSERVES, LOGS, AND CANNOT REFUSE.
     *
     * MEASURED, Task 9, with the probe dropping at the second callback:
     *
     *     TBSDROP id=0 path=/tbs/secret          <- drop() WAS returned
     *     Hit(method='GET', path='/tbs/secret')  <- the target received it
     *     client saw /tbs/secret: status=404     <- the TARGET's answer
     *
     * `ProxyRequestToBeSentAction.drop()` does not prevent egress on Burp
     * Suite Community 2026.7.3, while `ProxyRequestReceivedAction.drop()`
     * does -- zero hits, Burp's own 1529-byte page. The two are not
     * interchangeable. docs/burp-proxy-measurements.md, Q4, has both side by
     * side.
     *
     * THE MUST-BE-ZERO IS THE POINT OF THIS METHOD. `drop()` there is not
     * merely useless: while it was in place the refusal branch wrote a
     * `denial` row and took the `pending` entry for a request that reached the
     * target, so hx recorded a refusal that did not happen and lost the
     * exchange that did. That is fabricated evidence in the dangerous
     * direction, and the natural instinct of the next reader who finds a
     * pass-through where a scope check used to be is to put the drop back. A
     * zero is what stops that, and it reads as a rule rather than as an
     * omission.
     *
     * THE OTHER TWO ARE THE CONVERSE: the observation must still HAPPEN and
     * must still be SAID. A must-be-zero on its own is satisfied by deleting
     * the whole callback body, which would lose the one signal an operator
     * gets at the moment the boundary is crossed. So the question is counted,
     * and the log is POSITIONED between the question and the pass-through --
     * a count of `logToError(` would not do, because the entry point logs
     * elsewhere (the idle-extension refusal, the failed connect) and a needle
     * that matched those would be green with this callback silent.
     *
     * WIRE-EXISTS needles, so they read {@link #code}.
     */
    static void theSecondCallbackObservesAndCannotRefuse() throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int late = calls(entry, "ProxyRequestToBeSentAction.drop(",
                                "ProxyRequestToBeSentAction::drop");
        int early = calls(entry, "ProxyRequestReceivedAction.drop(",
                                 "ProxyRequestReceivedAction::drop");
        int asked = calls(entry, "policy.decideScopeOnly(", "policy::decideScopeOnly");
        check("the pre-send callback NEVER drops -- that action does not "
              + "prevent egress on this Burp (" + late + ")", late == 0);
        check("while the request-received callback still does, which is the "
              + "one that works (" + early + ")", early == 1);
        check("and the pre-send scope question is still asked (" + asked + ")",
              asked == 1);

        // The log sits BETWEEN the question and the pass-through, so a
        // callback that asks and says nothing is red. Positions rather than a
        // count: this file logs elsewhere too.
        int ask = entry.indexOf("policy.decideScopeOnly(");
        int log = entry.indexOf("logToError", ask);
        int through = entry.indexOf(
                "return ProxyRequestToBeSentAction.continueWith(r);");
        check("the answer is logged after it is asked (" + ask + " < " + log
              + ")", ask >= 0 && log > ask);
        check("and before the request goes through anyway (" + log + " < "
              + through + ")", through > log);
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
     * ONE refusing callback, not two. It was two until Task 9 measured that
     * `ProxyRequestToBeSentAction.drop()` does not prevent egress on Burp
     * 2026.7.3: the second callback's refusal enforced nothing and wrote a
     * `denial` row for a request that reached the target, so it is gone and
     * that callback now observes and logs. The response handler is not counted
     * here either -- it already wrapped its offer, and its action carries no
     * enforcement, it forwards either way.
     *
     * A COUNT OF ONE IS WEAKER THAN A COUNT OF TWO AGAINST A DELETION, and the
     * position checks below are what carry it: `bind` before `offer` before
     * `ret` are three indexOf's that all go to -1 or invert if the binding is
     * removed or the offer is moved ahead of it.
     */
    static void theRefusalIsHeldBeforeItIsRecorded() throws IOException {
        String entry = code(Path.of(ENTRY_POINT));
        int bound = count(entry, "Action refuse =");
        int returned = count(entry, "return refuse;");
        int bind = entry.indexOf("Action refuse =");
        int offer = entry.indexOf("capture.offer(");
        int ret = entry.indexOf("return refuse;");
        check("the one refusing callback binds its action first (" + bound + ")",
              bound == 1);
        check("and returns that local rather than a fresh call (" + returned + ")",
              returned == 1);
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
     * ONE take, and it used to be two. The second was in the second request
     * callback's refusal branch, on the reasoning that "this request is not
     * going to the target, so no response can arrive for it" -- a sentence
     * Task 9 measured FALSE, because `ProxyRequestToBeSentAction.drop()` does
     * not prevent egress on Burp 2026.7.3. Taking the entry there DISCARDED
     * THE CLOCK AND THE SOURCE of a request that was about to be answered, so
     * the response handler then missed, counted `countLost` and recorded
     * nothing. The refusal is gone and so is the take: the response handler is
     * the only place an entry is taken back, which is the only place one is
     * ever answered.
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
        int put = calls(entry, "pending.put(", "pending::put");
        int take = calls(entry, "pending.take(", "pending::take");
        check("the request handler writes the clock and the source down ("
              + put + ")", put == 1);
        check("and the response handler -- the only caller that has an answer "
              + "to pair them with -- takes them back (" + take + ")",
              take == 1);

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
     *     written. The counts below are what remains AFTER that bound: they
     *     narrow construction WITHIN the package to one file, and they count
     *     BOTH spellings a constructor has -- `Observed(` with `Observed::new`
     *     and `Denied(` with `Denied::new` -- so the reference form that
     *     defeated the earlier needle is covered here as well.
     *     {@link #theTypeNeedlesCoverEveryConstructionForm} is what holds that
     *     pairing in place;
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
        List<String> denied = new ArrayList<>();
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
            int n = calls(c, "Observed(", "Observed::new");
            if (n > 0) observed.add(p + " x" + n);
            int d = calls(c, "Denied(", "Denied::new");
            if (d > 0) denied.add(p + " x" + d);
            int j = calls(c, ".redactObservedRequest(", "::redactObservedRequest");
            if (j > 0) jobFour.add(p + " x" + j);
        }
        check("Observed is DECLARED in one file and CONSTRUCTED in one, and "
              + "the one that constructs it is " + RECORDER + " -- not " + observed,
              observed.equals(List.of(OBSERVED + " x1", RECORDER + " x1")));
        // The SAME for Denied, and this is what makes the within-package half
        // of the compiler bound complete rather than half-done: `javac` stops
        // another package from naming either record, and these two counts stop
        // a second construction site inside `hx.proxy`, in both spellings a
        // constructor has.
        check("and Denied likewise, constructed only in " + RECORDER
              + " -- not " + denied,
              denied.equals(List.of(DENIED + " x1", RECORDER + " x1")));
        check("and redacts an observed request in exactly one place, the same "
              + "one -- not " + jobFour,
              jobFour.equals(List.of(RECORDER + " x1")));
        // The entry point names NEITHER redaction method. This is the
        // must-be-zero that says the wiring stayed on the drivable side of the
        // line: put either call back in here and it is red, whatever else the
        // line does.
        int entryRedacts =
                calls(entry, ".redactObservedRequest(", "::redactObservedRequest")
              + calls(entry, ".redactResponse(", "::redactResponse");
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
            int n = calls(code(p), "Recorder(", "Recorder::new");
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
        int recordCalls = calls(entry, "recorder.record(", "recorder::record");
        check("and the entry point calls it exactly once, so the positional "
              + "arms below see every call there is (" + recordCalls + ")",
              recordCalls == 1);

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
     * EVERY NEEDLE THAT NAMES A TYPE COVERS EVERY WAY THAT TYPE CAN BE WRITTEN
     * -- and for a CONSTRUCTION that is a closed set of four.
     *
     * SEVEN INSTANCES OF ONE DEFECT ON ONE TASK, every one a needle that
     * matched the spelling someone happened to write rather than the construct
     * it was about, and every one found by a reviewer rather than by this
     * suite. Five were WORKING defects measured at a fully green run:
     *
     *     `new Socket(`     blind to `new java.net.Socket(`  -- a live TCP egress
     *     `new Observed(`   blind to `new hx.proxy.Observed(` -- raw credentials queued
     *     `Observed(`       blind to `Observed::new`          -- raw credentials queued
     *     `new Policy(`     blind to `new hx.policy.Policy(`  -- a second per-run budget
     *     `Policy(`         blind to `Policy::new`            -- a second per-run budget
     *     `import burp.`    blind to a fully-qualified Montoya type
     *     `openConnection(` blind to `URL.getContent()`       -- same family, API side
     *
     * WHY THIS ONE IS WORTH ENUMERATING WHEN `SocketHandler` WAS NOT, because
     * the two look alike and are not:
     *
     *   - the set of TYPE NAMES that can open a socket is UNBOUNDED. No needle
     *     list closes it, which is why {@link #noSecondEgressFamilyExists}
     *     declares that exclusion instead of chasing it;
     *   - the set of CONSTRUCTION SYNTAXES FOR A NAMED TYPE is CLOSED BY THE
     *     JAVA GRAMMAR. A constructor has exactly two spellings, `new T(...)`
     *     and `T::new`, and each may be qualified or not. FOUR FORMS, and the
     *     language defines the list.
     *
     * So the constructed table below is a finite game finished, not an
     * infinite one played: for each type all four forms are GENERATED, and at
     * least one of that type's needles must match each. A needle reverted to
     * `new T(` fails the qualified form; a needle left as `T(` fails the
     * reference form.
     *
     * NEEDLE OR COMPILER, and which is which is deliberate. Where a
     * compiler-enforced bound was available it was taken and is not
     * re-litigated here: {@link hx.proxy.Observed} and {@link hx.proxy.Denied}
     * are package-private, so `javac` refuses every construction from another
     * package whatever its spelling -- verified by a probe class in package
     * `hx`, which does not compile. Their rows below are what remains, the
     * bound WITHIN `hx.proxy`, where a needle is all there is. `Policy` gets no
     * such bound -- `hx.send` and `hx.proxy` both hold one and `hx` builds it,
     * so it is public of necessity -- and there the needles are the whole of
     * it.
     *
     * ANTI-VACUITY, both directions where they exist. The needles of
     * {@link #noSecondEgressFamilyExists} live in one array literal, so that
     * array is parsed out of this file and every entry must appear in a table
     * here -- adding a needle without a row is red. And every needle in either
     * table must appear as a literal OUTSIDE the tables, so a row whose needle
     * was renamed away is red; the tables are cut out of the text first,
     * because otherwise a row's own literal answers the search for its own
     * use. For the needles scattered across other methods no rule can
     * enumerate them, so that second direction is all there is for those, and
     * it is the honest limit of this check.
     *
     * THE METHOD HALF OF THE SAME GRAMMAR POINT IS HERE TOO, and it is here
     * because the sentence that used to stand in its place was FALSE. That
     * sentence said the method form was "left open deliberately: the only
     * needles it would defeat are the two deprecated-accessor ones, and no S4
     * or S7 property rests on them." MEASURED, against the tree that carried
     * it: a second Gate charge at the proxy's second callback, written
     *
     *     Function<HxRequest, Decision> g = policy::checkGate;
     *     if (d.allowed()) d = g.apply(edited);
     *
     * read 13 summary lines / 2024 ok / 0 FAIL / rc=0. That is a crawler
     * charged TWO rate tokens and TWO budget slots for one request -- S4's
     * rate limit and its per-run budget, both, and the exact defect
     * {@link #theGateIsSpentOnlyWhereTheHalvesArePaired}'s must-be-zero arm
     * exists to prevent. `client::configEpoch` against the deprecated-accessor
     * needle was green the same way. So it was a finding rather than a
     * residual, and the `called` table below is the fix.
     *
     * EVERY METHOD NEEDLE THAT IS *COUNTED* IS LISTED, must-be-zero and
     * exactly-N alike -- and the qualifier is load-bearing rather than
     * hedging.
     *
     * THAT SENTENCE WAS FALSE WHEN IT WAS WRITTEN, and it named its own
     * counter-example. It went on to exempt `withRedirectionMode(` as a needle
     * "read POSITIONALLY (`indexOf`) and never counted". It was counted, three
     * times, in an exactly-N arm inside {@link #redirectsAreNotFollowed} --
     * with no `::withRedirectionMode` companion and no row here, so it was the
     * one counted method needle on this branch whose four-form grammar set was
     * unfinished. IT IS NOW COUNTED THROUGH {@link #calls} AND HAS A ROW. Note
     * the shape of the escape, because it is the reason this paragraph is long:
     * the pairing arm below is driven from PAIRS, which is filled FROM THESE
     * TABLES, so a needle with no row is never examined at all. The sweep
     * enforced "every listed needle is used" and "every egress needle has a
     * row", and NOT the direction its own sentence claimed -- so a false
     * sentence there was invisible. Control, to prove the pairing arm works
     * and that table absence was the whole of the escape: rewriting
     * `calls(entry, "setHaltSink(", "::setHaltSink")` as
     * `count(entry, "setHaltSink(")` reddens at 2 FAIL.
     *
     * SO THE CLAIM IS NOW HALF-MECHANISED, and the half that is not says so.
     * The arm at the end of this method requires every needle PAIR handed to
     * {@link #calls} to have a row here, which is the direction that was
     * enforced by nobody. Writing it found THREE more unlisted pairs beyond
     * the one a reviewer read out --
     * `ProxyRequestReceivedAction.drop(`, `ProxyRequestToBeSentAction.drop(`
     * and the receiver-qualified `policy.decideScopeOnly(` -- which is the
     * measure of how far prose gets on this.
     *
     * WHAT IS STILL PROSE: a needle counted through {@link #count} on ONE
     * form, and a needle read only by `indexOf`. Neither is mechanised, and
     * for the second there is nothing to mechanise -- an offset does not sum,
     * so a positional needle has no second form to forget. FOUR method
     * needles are read positionally with no row, and they are listed here
     * because that list is the whole of the guarantee: `capture.offer(`
     * ({@link #theGateDecidesBeforeAnythingIsQueued},
     * {@link #theRefusalIsHeldBeforeItIsRecorded}), `logToError`
     * ({@link #theSecondCallbackObservesAndCannotRefuse}), `sender.issue(`
     * and `t.start()` ({@link #everyPathThatSpendsTheGateArmsItFirst} and
     * {@link #everyKillPathIsWiredBeforeTheDial}). The other positionally-read
     * method needles -- `http().sendRequest(`, `gate.decide(`, `limits.arm(`,
     * `pending.put(`, `recorder.record(`, `policy.decideScopeOnly(`,
     * `.authorisation()`, `HttpService.httpService(`,
     * `HttpRequest.httpRequest(`, and `.checkGate(` with `compose(` from
     * {@link #theCompositionHappensAfterTheGate} -- all have rows, because
     * they are counted somewhere too.
     *
     * What the positional exemption leaves open is narrower and is named where
     * it lives -- an ORDER check cannot see a call it does not spell, so
     * `capture::offer` used before the gate would satisfy
     * {@link #theGateDecidesBeforeAnythingIsQueued}. That is a recording-order
     * failure, not an enforcement one; it is IGNORANCE, not safety. Round 4
     * listed only the must-be-zero ones, on the argument that substituting a
     * reference for a call LOWERS an exactly-N count and fails closed. True,
     * and about the wrong operation: ADDING a second call in the other form
     * leaves the count where it was while the property is false. That is how
     * the SHIPPED send path charged the Gate twice at 13 / 2067 ok / 0 FAIL /
     * rc=0. {@link #calls} is where the sum is taken; this table is what makes
     * a check that forgets one form go red, because every needle here must
     * appear in this file OUTSIDE these tables.
     */
    static void theTypeNeedlesCoverEveryConstructionForm() throws IOException {
        // {simple name, package, the needles this file uses for that type...}
        String[][] constructed = {
            {"Socket",            "java.net",      "Socket(", "Socket::new"},
            {"URL",               "java.net",      "URL(", "URL::new"},
            {"InetSocketAddress", "java.net",      "InetSocketAddress"},
            {"DatagramSocket",    "java.net",      "DatagramSocket"},
            {"InetAddress",       "java.net",      "InetAddress"},
            {"HttpClient",        "java.net.http", "HttpClient"},
            {"ProcessBuilder",    "java.lang",     "ProcessBuilder"},
            {"Policy",            "hx.policy",     "Policy(", "Policy::new"},
            {"Recorder",          "hx.proxy",      "Recorder(", "Recorder::new"},
            {"Observed",          "hx.proxy",      "Observed(", "Observed::new"},
            {"Denied",            "hx.proxy",      "Denied(", "Denied::new"},
        };
        // Needles naming something OTHER than a construction -- a member
        // access, an instance call, a package. There is no `new` form for
        // these; what has to hold is that qualifying the type cannot hide them.
        String[][] referenced = {
            {"openConnection(",   "new java.net.URL(\"http://h/\").openConnection()"},
            {"openStream(",       "new java.net.URL(\"http://h/\").openStream()"},
            {"collaborator()",    "api.collaborator().createClient()"},
            {"Runtime.getRuntime", "java.lang.Runtime.getRuntime().exec(\"curl\")"},
            {"RedirectionMode.",  "burp.api.montoya.http.RedirectionMode.NEVER"},
            {"HttpService.httpService(",
             "burp.api.montoya.http.HttpService.httpService(h, p, s)"},
            {"HttpRequest.httpRequest(",
             "burp.api.montoya.http.message.requests.HttpRequest.httpRequest(s, b)"},
            {MONTOYA,             "burp.api.montoya.core.ByteArray b = null;"},
            {"hx.proxy",          "hx.proxy.Observed o = null;"},
        };

        // {method name, receiver used in the qualified form, needles...}
        // A method INVOCATION has two spellings too -- `recv.m(...)` and
        // `recv::m` -- and the second is an invocation in every sense that
        // matters: it reaches the same method with the same effects. Only the
        // MUST-BE-ZERO needles are listed, and that is a decision rather than
        // an omission: for a needle that must be exactly N, replacing a call
        // with a reference LOWERS the count and the check fails CLOSED. For a
        // needle that must be zero it raises nothing, and the check stays
        // green while the thing it forbids happens.
        // {method, receiver, the call's argument text, needles...}. The
        // argument text is spelled rather than generated because ARITY is a
        // fact about the method, and a needle for a no-argument method
        // legitimately carries its closing paren -- `.configEpoch()`. The
        // REFERENCE form is still derived, which is the half that has been
        // wrong.
        String[][] called = {
            {"sendRequests",          "api.http()", "(a)", "sendRequests(", "::sendRequests"},
            {"configEpoch",           "client",     "()",  ".configEpoch()", "::configEpoch"},
            {"scopeConfig",           "client",     "()",  ".scopeConfig()", "::scopeConfig"},
            {"checkGate",             "policy",     "(a)", ".checkGate(", "::checkGate"},
            {"decide",                "policy",     "(a)", "policy.decide(", "policy::decide"},
            {"redactObservedRequest", "redactor",   "(a)", ".redactObservedRequest(",
                                                           "::redactObservedRequest"},
            {"redactResponse",        "redactor",   "(a)", ".redactResponse(", "::redactResponse"},
            {"openConnection",        "u",          "()",  "openConnection(", "::openConnection"},
            {"openStream",            "u",          "()",  "openStream(", "::openStream"},
            {"collaborator",          "api",        "()",  "collaborator()", "::collaborator"},
            // ...and every EXACTLY-N method needle, which round 4 left on one
            // form on a fail-closed argument that was about substitution and
            // not about ADDITION. See {@link #calls}.
            {"sendRequest",           "api.http()", "(a)", "http().sendRequest", "::sendRequest"},
            {"http",                  "api",        "()",  ".http()", "::http"},
            {"authorisation",         "c",          "()",  ".authorisation()", "::authorisation"},
            {"decideBeforeGate",      "policy",     "(a)", ".decideBeforeGate(",
                                                           "::decideBeforeGate"},
            {"decideScopeOnly",       "policy",     "(a)", "decideScopeOnly(",
                                                           "::decideScopeOnly"},
            {"decide",                "gate",       "(a)", "gate.decide(", "gate::decide"},
            {"registerRequestHandler", "api.proxy()", "(a)", "registerRequestHandler(",
                                                           "::registerRequestHandler"},
            {"registerResponseHandler", "api.proxy()", "(a)", "registerResponseHandler(",
                                                           "::registerResponseHandler"},
            {"put",                   "pending",    "(a)", "pending.put(", "pending::put"},
            {"take",                  "pending",    "(a)", "pending.take(", "pending::take"},
            {"record",                "recorder",   "(a)", "recorder.record(",
                                                           "recorder::record"},
            {"start",                 "haltSwitch", "()",  "haltSwitch.start()",
                                                           "haltSwitch::start"},
            {"setHaltSink",           "c",          "(a)", "setHaltSink(", "::setHaltSink"},
            {"setHaltSource",         "c",          "(a)", "setHaltSource(", "::setHaltSource"},
            {"setHaltNotifier",       "sender",     "(a)", "setHaltNotifier(",
                                                           "::setHaltNotifier"},
            {"setSendHandler",        "c",          "(a)", "setSendHandler(",
                                                           "::setSendHandler"},
            {"setConfigGuard",        "c",          "(a)", "setConfigGuard(",
                                                           "::setConfigGuard"},
            // The needle the sentence above wrongly exempted, plus the two
            // this fix wave added: the drain that had no check at all, and the
            // arming call site that had none either.
            {"withRedirectionMode",   "options",    "(a)", "withRedirectionMode(",
                                                           "::withRedirectionMode"},
            {"start",                 "capture",    "()",  "capture.start()",
                                                           "capture::start"},
            {"arm",                   "limits",     "(a)", "limits.arm(",
                                                           "limits::arm"},
            // ...and the composition, counted by
            // theCompositionHappensAfterTheGate so that the two offsets it
            // then takes are known to be all of them.
            {"compose",               "Sender",     "(a, b)", "compose(",
                                                           "::compose"},
            // ...and the three the false sentence ALSO missed, found by
            // mechanising the direction it claimed rather than by re-reading
            // it. Each is a needle PAIR handed to calls() with no row here.
            // `decideScopeOnly` gets a SECOND row because a needle is a
            // spelling, not a method: the receiver-qualified pair
            // theSecondCallbackObservesAndCannotRefuse counts is a different
            // pair of literals from the bare one above, and the arm below
            // matches literals.
            {"decideScopeOnly",       "policy",     "(a)", "policy.decideScopeOnly(",
                                                           "policy::decideScopeOnly"},
            {"drop",         "ProxyRequestReceivedAction", "()",
                                       "ProxyRequestReceivedAction.drop(",
                                       "ProxyRequestReceivedAction::drop"},
            {"drop",         "ProxyRequestToBeSentAction", "()",
                                       "ProxyRequestToBeSentAction.drop(",
                                       "ProxyRequestToBeSentAction::drop"},
        };

        PAIRS.clear();
        for (String[] row : constructed)
            if (row.length > 3) PAIRS.add(Arrays.copyOfRange(row, 2, row.length));
        for (String[] row : called)
            if (row.length > 4) PAIRS.add(Arrays.copyOfRange(row, 3, row.length));

        List<String> every = new ArrayList<>();
        for (String[] row : constructed) {
            String simple = row[0], pkg = row[1];
            String[] needles = Arrays.copyOfRange(row, 2, row.length);
            for (String n : needles) every.add(n);
            // THE FOUR FORMS, generated rather than typed out, so the list
            // cannot be quietly shortened by hand.
            String[] forms = {
                "new " + simple + "(a, b)",
                "new " + pkg + "." + simple + "(a, b)",
                simple + "::new",
                pkg + "." + simple + "::new",
            };
            for (String form : forms) {
                boolean matched = false;
                for (String n : needles) if (count(form, n) >= 1) matched = true;
                check("`" + form + "` is matched by one of "
                      + Arrays.toString(needles), matched);
            }
        }
        for (String[] row : referenced) {
            every.add(row[0]);
            check("`" + row[0] + "` matches its qualified spelling `" + row[1] + "`",
                  count(row[1], row[0]) >= 1);
        }
        for (String[] row : called) {
            String method = row[0], recv = row[1], args = row[2];
            String[] needles = Arrays.copyOfRange(row, 3, row.length);
            for (String n : needles) every.add(n);
            String[] forms = { recv + "." + method + args, recv + "::" + method };
            for (String form : forms) {
                boolean matched = false;
                for (String n : needles) if (count(form, n) >= 1) matched = true;
                check("`" + form + "` is matched by one of "
                      + Arrays.toString(needles), matched);
            }
        }

        String self = codeKeepingLiterals(Path.of("test", "hx", "ChokepointTest.java"));
        check("this class can read its own source (" + self.length() + " chars)",
              self.length() > 10_000);
        int tablesAt = self.indexOf("String[][] constructed = {");
        int tablesEnd = self.indexOf("        };",
                                     self.indexOf("String[][] called = {"));
        check("the row tables were located and excluded (" + tablesAt + ".."
              + tablesEnd + ")", tablesAt >= 0 && tablesEnd > tablesAt);
        String elsewhere = tablesEnd > tablesAt
                ? self.substring(0, tablesAt) + self.substring(tablesEnd) : self;
        for (String needle : every)
            check("`" + needle + "` is a needle this file still uses",
                  count(elsewhere, "\"" + needle + "\"") >= 1);

        // EVERY COUNT OF A PAIRED NEEDLE GOES THROUGH calls(). This is the arm
        // that makes the sweep pin ITS OWN property rather than merely listing
        // forms: a check that counts `.checkGate(` and forgets `::checkGate`
        // is exactly the round-5 finding, and without this the sweep stayed
        // green on it -- measured, S at 13 / 2197 ok / 0 FAIL / rc=0.
        //
        // Balance of OCCURRENCES was tried first and is the wrong rule: a
        // needle legitimately appears in prose-free places that are not
        // counts -- `setHaltSink(` sits three times inside the STRIPPER's own
        // fixture -- and ten of thirty-three pairs were "unbalanced" while
        // every one was correct. What has to hold is narrower: where a paired
        // needle is COUNTED against a real source file, both forms are summed.
        //
        // `count(stripped,` is the one exception and it is named rather than
        // filtered by a pattern: theStripperIsNotVacuousAndDoesNotOverreach
        // counts needles inside a FIXTURE STRING to prove the stripper works,
        // which is not policing a wire and must not be summed.
        List<String> single = new ArrayList<>();
        for (String[] row : pairs()) {
            if (row.length < 2) continue;
            for (String needle : row) {
                for (String line : elsewhere.split("\n")) {
                    if (!line.contains("\"" + needle + "\"")) continue;
                    if (!line.contains("count(")) continue;
                    if (line.contains("count(stripped,")) continue;
                    single.add(needle + " @ " + line.trim());
                }
            }
        }
        check("every count of a paired needle sums both grammar forms through "
              + "calls(), not one of them " + single, single.isEmpty());

        // ...AND THE OTHER DIRECTION, which is the one the javadoc above
        // CLAIMED and which nothing enforced until this wave. Every needle
        // PAIR handed to calls() must have a row here. Without it a paired
        // needle can be counted with no row, and the arm above -- driven from
        // PAIRS, which is filled FROM THESE TABLES -- never examines it: that
        // is exactly how `withRedirectionMode(` sat in an exactly-N arm on one
        // grammar form while a sentence twelve lines up named it as never
        // counted. Three MORE unlisted pairs fell out of writing this, none of
        // them found by reading.
        //
        // Matched on the LITERALS, because a needle is a spelling: the same
        // method reached through a different receiver-qualified pair is a
        // different pair of strings and needs its own row.
        //
        // The scan takes the FIRST TWO string literals between each `calls(`
        // and the `;` that ends its statement. That reads a nested
        // `calls(text(p), "a", "b")` correctly and would misread a first
        // argument that itself contained a string literal; there is none, and
        // a new one would show up here as an unlisted pair rather than as
        // silence. `calls`'s own DECLARATION is skipped because no literal
        // stands between it and the next `;`.
        List<String> unlisted = new ArrayList<>();
        int sites = 0, scan = 0;
        while ((scan = elsewhere.indexOf("calls(", scan)) >= 0) {
            int stop = elsewhere.indexOf(";", scan);
            List<String> lits = stop < 0 ? List.<String>of()
                    : literals(elsewhere.substring(scan + "calls(".length(), stop));
            scan += "calls(".length();
            if (lits.size() < 2) continue;
            sites++;
            boolean listed = false;
            for (String[] row : pairs())
                if (row.length >= 2 && row[0].equals(lits.get(0))
                                    && row[1].equals(lits.get(1))) listed = true;
            if (!listed) unlisted.add(lits.get(0) + " + " + lits.get(1));
        }
        // Anti-vacuity: a scan that matched nothing would report no unlisted
        // pairs and say nothing at all.
        check("the calls() sites were found (" + sites + ")", sites >= 25);
        check("and every needle pair counted through calls() has a row here "
              + unlisted, unlisted.isEmpty());

        int from = self.indexOf("String[] needles = {");
        int to = self.indexOf("};", from);
        check("the egress needle array was found (" + from + ".." + to + ")",
              from >= 0 && to > from);
        List<String> missing = new ArrayList<>();
        String array = to > from ? self.substring(from, to) : "";
        int at = 0, found = 0;
        while ((at = array.indexOf('"', at)) >= 0) {
            int close = array.indexOf('"', at + 1);
            if (close < 0) break;
            String needle = array.substring(at + 1, close);
            found++;
            if (!every.contains(needle)) missing.add(needle);
            at = close + 1;
        }
        check("every egress needle was read out of the array (" + found + ")",
              found >= 12);
        check("...and every one of them has a row " + missing, missing.isEmpty());
    }

    /**
     * ONE METHOD INVOCATION, COUNTED IN EVERY GRAMMAR FORM IT HAS.
     *
     * Round 4 widened the MUST-BE-ZERO needles to `recv.m(` plus `recv::m` and
     * argued the exactly-N ones were safe because a reference SUBSTITUTED for
     * a call lowers the count and fails closed. That argument was about the
     * wrong operation. MEASURED, in the SHIPPED send path:
     *
     *     Decision d = policy.checkGate(req);
     *     Function<HxRequest, Decision> g2 = policy::checkGate;
     *     if (d.allowed()) d = g2.apply(req);
     *
     *     13 summary lines / 2067 ok / 0 FAIL / rc=0
     *
     * ADDITION, not substitution: the original spelling stays, the count stays
     * at one, and the Gate is charged TWICE for every request -- S4's rate
     * limit and its per-run budget, on the path that issues. So an exactly-N
     * count has to be a count of the SUM of the forms, and every such needle
     * in this file goes through here.
     */
    /** The needle sets that have more than one grammar form, filled by the
     *  sweep from its own tables so the two cannot drift. */
    private static final List<String[]> PAIRS = new ArrayList<>();

    static List<String[]> pairs() { return PAIRS; }

    static int calls(String haystack, String dotted, String reference) {
        return count(haystack, dotted) + count(haystack, reference);
    }

    /** The string literals in {@code s}, in order, at most two -- enough for
     *  one {@link #calls} argument pair. Escapes are stepped over so a `\"`
     *  inside a needle cannot end it early; no needle in this file has one,
     *  and the loop is written to survive the first that does. */
    static List<String> literals(String s) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (out.size() < 2 && (i = s.indexOf('"', i)) >= 0) {
            int close = i + 1;
            while (close < s.length() && s.charAt(close) != '"') {
                if (s.charAt(close) == '\\') close++;
                close++;
            }
            if (close >= s.length()) break;
            out.add(s.substring(i + 1, close));
            i = close + 1;
        }
        return out;
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
     * The file with COMMENTS blanked and STRING LITERALS KEPT.
     *
     * A third reading, and it exists for one job: asking whether this class
     * still USES a needle. That question is answered by searching for the
     * needle as a quoted literal, so {@link #code} is useless -- it blanks
     * literal bodies, which is the very text being looked for. And
     * {@link #text} is fail-OPEN here, measured: deleting
     * `count(t, "::configEpoch")` reddens the arm, but the same deletion with
     * `// TODO(plan-9): restore count(t, "::configEpoch") here` left above it
     * read 13 summary lines / 2067 ok / 0 FAIL / rc=0. That is the
     * setHaltSource-TODO failure this class was built around, arriving in the
     * check that polices the other needles.
     *
     * A needle proving A CHECK EXISTS is proving a wire exists, and prose
     * cannot wire anything -- so comments go and literals stay.
     */
    static String codeKeepingLiterals(Path p) throws IOException {
        return strip(text(p), false);
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
        return strip(src, true);
    }

    /** @param blankLiterals whether a literal's BODY is blanked too. Literals
     *  are always PARSED, whichever way this is set, so a `//` inside a string
     *  still starts no comment -- that is the over-run this class's stripper
     *  test drives from both sides. */
    static String strip(String src, boolean blankLiterals) {
        char[] out = src.toCharArray();
        int n = out.length, i = 0;
        while (i < n) {
            char c = out[i];
            if (c == '"' || c == '\'') {
                boolean block = c == '"' && i + 2 < n && out[i + 1] == '"' && out[i + 2] == '"';
                i += block ? 3 : 1;              // the opening delimiter is kept
                while (i < n) {
                    if (out[i] == '\\') {
                        if (!blankLiterals) { i += 2; continue; }
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
                    i = blankLiterals ? blank(out, i, n) : i + 1;
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
