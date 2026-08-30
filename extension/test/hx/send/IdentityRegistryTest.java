// extension/test/hx/send/IdentityRegistryTest.java
package hx.send;

import hx.TestSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * Hand-rolled runner: JUnit would be a dependency, and this jar has none.
 *
 * Every check below is `check(String, boolean)`, not a bare `assert`.
 * test.sh's `java` invocations carry no `-ea`, and without it Java assertions
 * are disabled by default -- a bare `assert` would silently do nothing and
 * this class would print ALL PASS whatever IdentityRegistry actually did.
 */
public final class IdentityRegistryTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(IdentityRegistryTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("registeringMakesAnIdentityRetrievable", IdentityRegistryTest::registeringMakesAnIdentityRetrievable);
        t("theSameGenerationIsIdempotentRatherThanAnError", IdentityRegistryTest::theSameGenerationIsIdempotentRatherThanAnError);
        t("aHigherGenerationReplacesTheValue", IdentityRegistryTest::aHigherGenerationReplacesTheValue);
        t("aLowerGenerationIsRefused", IdentityRegistryTest::aLowerGenerationIsRefused);
        t("sameGenerationWithDifferentContentDoesNotSwapTheCredential", IdentityRegistryTest::sameGenerationWithDifferentContentDoesNotSwapTheCredential);
        t("aBlankIdIsRefused", IdentityRegistryTest::aBlankIdIsRefused);
        t("aGenerationBelowOneIsRefused", IdentityRegistryTest::aGenerationBelowOneIsRefused);
        t("aBlankHeaderIsRefused", IdentityRegistryTest::aBlankHeaderIsRefused);
        t("nullOriginsIsRefusedAsWellAsAnEmptyList", IdentityRegistryTest::nullOriginsIsRefusedAsWellAsAnEmptyList);
        t("anUnknownIdentityIsNullNotAnEmptyEntry", IdentityRegistryTest::anUnknownIdentityIsNullNotAnEmptyEntry);
        t("originsAreCopiedSoACallerCannotWidenThemLater", IdentityRegistryTest::originsAreCopiedSoACallerCannotWidenThemLater);
        t("aBlankValueIsRefused", IdentityRegistryTest::aBlankValueIsRefused);
        t("noOriginsIsRefused", IdentityRegistryTest::noOriginsIsRefused);
        t("toStringDoesNotCarryTheCredential", IdentityRegistryTest::toStringDoesNotCarryTheCredential);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    static void registeringMakesAnIdentityRetrievable() {
        IdentityRegistry r = new IdentityRegistry();
        r.register("user", 1, "Cookie", "session=abc", List.of("https://app.test"));
        IdentityRegistry.Entry e = r.get("user");
        check("registering makes the identity retrievable", e != null);
        check("...at the registered generation", e.generation() == 1);
        check("...with the registered header", "Cookie".equals(e.header()));
        check("...with the registered value", "session=abc".equals(e.value()));
    }

    /** A re-sent frame is not an error: the bridge may retry, and a retry
     *  that threw would fail a run over a duplicate that changed nothing. */
    static void theSameGenerationIsIdempotentRatherThanAnError() {
        IdentityRegistry r = new IdentityRegistry();
        r.register("user", 2, "Cookie", "a", List.of("https://app.test"));
        r.register("user", 2, "Cookie", "a", List.of("https://app.test"));
        check("re-registering the same generation does not throw and leaves it in place",
              r.get("user").generation() == 2);
    }

    static void aHigherGenerationReplacesTheValue() {
        IdentityRegistry r = new IdentityRegistry();
        r.register("user", 1, "Cookie", "old", List.of("https://app.test"));
        r.register("user", 2, "Cookie", "new", List.of("https://app.test"));
        check("a higher generation replaces the value", "new".equals(r.get("user").value()));
    }

    /** MONOTONIC, for the same reason Limiter's budget is: a replayed frame
     *  must not be able to roll a session back to a credential that is dead. */
    static void aLowerGenerationIsRefused() {
        IdentityRegistry r = new IdentityRegistry();
        r.register("user", 3, "Cookie", "current", List.of("https://app.test"));
        boolean threw = false;
        try {
            r.register("user", 2, "Cookie", "stale", List.of("https://app.test"));
        } catch (IdentityRegistry.StaleGeneration expected) { threw = true; }
        check("a lower generation is refused as StaleGeneration", threw);
        check("...and the held entry is unchanged", "current".equals(r.get("user").value()));
    }

    static void anUnknownIdentityIsNullNotAnEmptyEntry() {
        check("an unknown identity is null, not an empty entry",
              new IdentityRegistry().get("nobody") == null);
    }

    /** The caller keeps its list. A registry that stored the caller's own
     *  mutable list would let a later add() widen where a credential goes. */
    static void originsAreCopiedSoACallerCannotWidenThemLater() {
        IdentityRegistry r = new IdentityRegistry();
        List<String> mine = new ArrayList<>(List.of("https://app.test"));
        r.register("user", 1, "Cookie", "v", mine);
        mine.add("https://evil.test");
        check("origins are copied, so widening the caller's list afterwards does not "
              + "widen the registered identity",
              r.get("user").origins().size() == 1);
    }

    static void aBlankValueIsRefused() {
        boolean threw = false;
        try {
            new IdentityRegistry().register("user", 1, "Cookie", "  ",
                                            List.of("https://app.test"));
        } catch (IllegalArgumentException expected) { threw = true; }
        check("a blank value is refused: it is not a credential", threw);
    }

    static void noOriginsIsRefused() {
        boolean threw = false;
        try {
            new IdentityRegistry().register("user", 1, "Cookie", "v", List.of());
        } catch (IllegalArgumentException expected) { threw = true; }
        check("no origins is refused: an identity with no origin could go to any "
              + "host in scope", threw);
    }

    /** Entry lands in exception messages and debug output. A record's
     *  generated toString would put a live session cookie in both. */
    static void toStringDoesNotCarryTheCredential() {
        IdentityRegistry r = new IdentityRegistry();
        r.register("user", 1, "Cookie", "session=SUPERSECRET", List.of("https://app.test"));
        String s = r.get("user").toString();
        check("Entry.toString() does not carry the credential value (got " + s + ")",
              !s.contains("SUPERSECRET"));
        check("...but does carry the id, so it is still useful for debugging",
              s.contains("user"));
    }

    /** Finding 1 of the Task 4 review. `compute`'s remapper used to build a
     *  new Entry from whatever the call passed, so a second frame at the SAME
     *  generation carrying a DIFFERENT credential swapped it silently -- a
     *  content change that never advanced the counter whose job is to gate
     *  content changes. The old test only ever resent identical content, so
     *  it could not see this. */
    static void sameGenerationWithDifferentContentDoesNotSwapTheCredential() {
        IdentityRegistry r = new IdentityRegistry();
        r.register("user", 2, "Cookie", "first", List.of("https://app.test"));
        r.register("user", 2, "Cookie", "second", List.of("https://evil.test"));
        check("the held value survives a same-generation re-register",
              r.get("user").value().equals("first"));
        check("and so do the held origins",
              r.get("user").origins().equals(List.of("https://app.test")));
    }

    /** Findings 2 and 3: branches the code guards and no test reached. The
     *  Python side validates these too, but the extension is meant to be an
     *  independent last line of defence, not a second opinion. */
    static void aBlankIdIsRefused() {
        check("a blank id is refused", refused(() ->
            new IdentityRegistry().register("  ", 1, "Cookie", "v",
                                            List.of("https://app.test"))));
    }

    static void aGenerationBelowOneIsRefused() {
        check("generation 0 is refused", refused(() ->
            new IdentityRegistry().register("user", 0, "Cookie", "v",
                                            List.of("https://app.test"))));
        check("a negative generation is refused", refused(() ->
            new IdentityRegistry().register("user", -1, "Cookie", "v",
                                            List.of("https://app.test"))));
    }

    static void aBlankHeaderIsRefused() {
        check("a blank header is refused", refused(() ->
            new IdentityRegistry().register("user", 1, "  ", "v",
                                            List.of("https://app.test"))));
    }

    static void nullOriginsIsRefusedAsWellAsAnEmptyList() {
        check("null origins is refused", refused(() ->
            new IdentityRegistry().register("user", 1, "Cookie", "v", null)));
    }

    /** True when the body throws IllegalArgumentException. */
    static boolean refused(Runnable body) {
        try { body.run(); return false; }
        catch (IllegalArgumentException expected) { return true; }
    }
}
