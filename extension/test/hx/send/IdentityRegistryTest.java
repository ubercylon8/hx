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
        t("aValueCarryingCRLFIsREFUSEDRatherThanEscaped", IdentityRegistryTest::aValueCarryingCRLFIsREFUSEDRatherThanEscaped);
        t("aValueCarryingNulIsRefused", IdentityRegistryTest::aValueCarryingNulIsRefused);
        t("aValueOutsideLatin1IsRefusedRatherThanSilentlyMangled", IdentityRegistryTest::aValueOutsideLatin1IsRefusedRatherThanSilentlyMangled);
        t("aHeaderNameCarryingADelimiterIsRefused", IdentityRegistryTest::aHeaderNameCarryingADelimiterIsRefused);
        t("onlyTheThreeCredentialHeadersMayBeInjectedInto", IdentityRegistryTest::onlyTheThreeCredentialHeadersMayBeInjectedInto);
        t("noRefusalMessageQuotesTheCredential", IdentityRegistryTest::noRefusalMessageQuotesTheCredential);

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

    /**
     * Finding 1 of the Task 5 review, and the one that is not tidiness.
     *
     * `Sender.compose` writes `header + ": " + value` and ends the field with
     * CRLF, so a value carrying its own CRLF composes into TWO headers -- a
     * request issued past `Policy.checkGate` carrying a field the gate never
     * saw. Measured by the reviewer, driving compose() directly:
     * {@code "sess=1\r\nX-Smuggled: yes"} produced `Cookie: sess=1` followed
     * by `X-Smuggled: yes`. A value carrying a BLANK line ends the head early
     * and turns the caller's remaining fields, `Host` included, into a body.
     *
     * AND compose()'s OWN SELF-CHECK CANNOT SEE IT. That check verifies that
     * the bytes at [start,end) equal the credential, and for a CRLF-carrying
     * value they do -- the bytes at the range ARE the value. So the range is
     * correct, the redaction is correct, and the request is wrong. That is why
     * the assertion here is that registration REFUSES, not that composition
     * escapes: an escaped credential is a different credential, and the
     * server would answer it logged-out.
     */
    static void aValueCarryingCRLFIsREFUSEDRatherThanEscaped() {
        IdentityRegistry r = new IdentityRegistry();
        check("a value carrying CRLF is refused", refused(() ->
            r.register("user", 1, "Cookie", "sess=1\r\nX-Smuggled: yes",
                       List.of("https://app.test"))));
        check("a bare LF is refused too -- one is enough to end a field for "
              + "some parsers", refused(() ->
            r.register("user", 1, "Cookie", "sess=1\nX-Smuggled: yes",
                       List.of("https://app.test"))));
        check("and a bare CR", refused(() ->
            r.register("user", 1, "Cookie", "sess=1\rX-Smuggled: yes",
                       List.of("https://app.test"))));
        check("a blank line, which would turn Host into a body, is refused",
              refused(() -> r.register("user", 1, "Cookie",
                                       "sess=1\r\n\r\nGET /evil HTTP/1.1",
                                       List.of("https://app.test"))));
        check("...and nothing was held, so no later send can use one",
              r.get("user") == null);
    }

    /** NUL cannot split a header. It is refused because a credential that is
     *  one length in this JVM and another in whatever C code sits between here
     *  and a socket is a credential whose registered range means nothing. */
    static void aValueCarryingNulIsRefused() {
        check("a value carrying NUL is refused", refused(() ->
            new IdentityRegistry().register("user", 1, "Cookie", "sess=1\0more",
                                            List.of("https://app.test"))));
    }

    /**
     * Finding 6. `Sender.wireBytes` encodes ISO-8859-1 and `String.getBytes`
     * replaces an unmappable character with '?', so `sess=€123` went out as
     * `sess=?123` -- offsets correct, redaction correct, credential dead. The
     * server answers that request logged-out and a check reads the answer as
     * "not vulnerable", which is the single outcome this feature exists to
     * prevent. Silence is the whole defect, so the fix is a refusal at the
     * point an operator can act on it.
     */
    static void aValueOutsideLatin1IsRefusedRatherThanSilentlyMangled() {
        check("a value outside Latin-1 is refused", refused(() ->
            new IdentityRegistry().register("user", 1, "Cookie", "sess=€123",
                                            List.of("https://app.test"))));
        // The high half of Latin-1 IS legal field content (RFC 9110 s5.5
        // obs-text) and survives the encoding byte for byte, so refusing it
        // would be refusing a credential that works.
        IdentityRegistry r = new IdentityRegistry();
        r.register("user", 1, "Cookie", "sess=café", List.of("https://app.test"));
        check("but an 8-bit Latin-1 value is kept: it encodes to itself",
              "sess=café".equals(r.get("user").value()));
    }

    /**
     * Finding 5. The name is not a free string: `Sender.withHeaderFirst`
     * writes whatever is registered as the request's FIRST header, so a name
     * of {@code "Cookie: a\r\nX-Evil"} composed into two headers -- measured
     * by the reviewer. The value is not the only half of the field.
     */
    static void aHeaderNameCarryingADelimiterIsRefused() {
        IdentityRegistry r = new IdentityRegistry();
        check("a header name carrying CRLF is refused", refused(() ->
            r.register("user", 1, "Cookie: a\r\nX-Evil", "v",
                       List.of("https://app.test"))));
        check("and one outside Latin-1", refused(() ->
            r.register("user", 1, "Cooki€e", "v", List.of("https://app.test"))));
        check("...and nothing was held", r.get("user") == null);
    }

    /**
     * Finding 5's other half: §4 says the extension enforces, and until this
     * round only `hx.config` restricted the injectable set to §6's three.
     *
     * A TRAILING SPACE IS REFUSED, and that is the arm that would go green
     * under the obvious implementation. `Redactor.asciiEqualsIgnoreCase`
     * TRIMS -- correctly, because it is a fail-closed gate on a name the
     * harness sent -- and reusing it here would accept `"Cookie "`, which
     * `withHeaderFirst` then emits as `Cookie : v`: a field name with a space
     * before its colon, which RFC 9112 s2.2 requires a server to reject and
     * which parsers disagree about. `Redactor.isCredentialHeader` exists
     * because acceptance and refusal want opposite answers here.
     */
    static void onlyTheThreeCredentialHeadersMayBeInjectedInto() {
        for (String name : new String[]{"Cookie", "Authorization",
                                        "Proxy-Authorization", "cookie",
                                        "AUTHORIZATION"}) {
            IdentityRegistry r = new IdentityRegistry();
            r.register("user", 1, name, "v", List.of("https://app.test"));
            check("'" + name + "' may be injected into -- field names are "
                  + "case-insensitive (RFC 9110 s5.1)", r.get("user") != null);
        }
        for (String name : new String[]{"X-Api-Key", "X-Auth-Token", "Host",
                                        "Cookie ", " Cookie", "Cookie2"}) {
            check("'" + name + "' is refused", refused(() ->
                new IdentityRegistry().register("user", 1, name, "v",
                                                List.of("https://app.test"))));
        }
    }

    /**
     * These messages travel: BridgeClient answers an IllegalArgumentException
     * from here as `bad_identity` with `e.getMessage()` as the detail, and the
     * harness logs that. Spec s5 says the credential is logged on neither
     * side, so a refusal that quoted the value -- or the one character that
     * failed -- would be the leak, arriving through the very door that exists
     * to stop one.
     */
    static void noRefusalMessageQuotesTheCredential() {
        String secret = "sess=SUPERSECRET\r\nX-Smuggled: yes";
        String message = "no refusal";
        try {
            new IdentityRegistry().register("user", 1, "Cookie", secret,
                                            List.of("https://app.test"));
        } catch (IllegalArgumentException e) {
            message = e.getMessage();
        }
        check("the CRLF refusal says nothing of the value (got: " + message + ")",
              !message.contains("SUPERSECRET") && !message.contains("no refusal"));
        check("...but does name the identity, so an operator knows which one",
              message.contains("user"));
    }

    /** True when the body throws IllegalArgumentException. */
    static boolean refused(Runnable body) {
        try { body.run(); return false; }
        catch (IllegalArgumentException expected) { return true; }
    }
}
