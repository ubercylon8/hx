// extension/src/hx/proxy/Recorder.java
package hx.proxy;

import hx.send.Redactor;

/**
 * One observed exchange turned into a redacted {@link Observed}, in a class a
 * test can execute.
 *
 * WHY THIS IS A CLASS AND NOT FOUR LINES IN THE ENTRY POINT. Those four lines
 * were in the entry point, and the same defect was found there THREE TIMES,
 * each time smaller and each time green:
 *
 *   1. the request half was redacted with {@code redactRequest} and an empty
 *      {@link Redactor.Injected}, which is `return raw.clone()` -- the
 *      operator's live cookie into a content-addressed store, verbatim;
 *   2. both redaction calls left in place and the RAW locals queued instead of
 *      their results -- one identifier each, and the structural check that
 *      pinned ORDER could not see it;
 *   3. the two redactors SWAPPED -- `redactResponse` given the request and
 *      `redactObservedRequest` given the response. Both functions still
 *      correct, both pointed at the wrong message, both halves leaking, and
 *      the structural check that pinned DATAFLOW could not see it either:
 *      each function is still called, each result is still queued.
 *
 * Every one of those checks asks a question about the TEXT of
 * {@code HxExtension}, and that file cannot be executed by this suite at all
 * -- it needs Burp to construct a single one of its arguments. Ordering is not
 * dataflow; dataflow is not application. The next hole of the same kind would
 * be smaller again. So the pairing of function to message lives HERE instead,
 * where `RecorderTest` drives it with a real {@link Redactor}, real request
 * bytes carrying a real-shaped `Cookie` and `Authorization`, and a real
 * response carrying a `Set-Cookie` -- and swapping the two calls below turns
 * that test RED rather than leaving a suite green.
 *
 * NO {@code burp.*} TYPE APPEARS HERE, which is what lets it be driven and
 * what keeps `ChokepointTest.montoyaIsConfinedToTheEntryPoint` true. The
 * entry point reads the two byte arrays off Montoya -- the one thing only it
 * can do -- and hands them over.
 *
 * WHAT IS STILL OPEN ON THE REDACTION PATH. This list covers THIS path --
 * the proxy capture path and the checks that hold it. It is not a list of
 * everything open in the extension, and the earlier claim that "every other
 * javadoc that names a residual names one of these and points here" was
 * FALSE: ChokepointTest names residuals of its own next to the checks they
 * belong to, which is where they are useful.
 *
 * EACH ITEM SAYS WHETHER IT ASSERTS IGNORANCE OR SAFETY, because those are
 * different promises. Ignorance -- "we did not test this" -- costs nothing to
 * say. Safety -- "this cannot hurt us" -- is an invariant and needs evidence
 * like any other. TWICE ON THIS TASK an item asserting safety turned out to be
 * a live finding, so no item below asserts safety without naming what would
 * have to be true.
 *
 *   1. A PREDICATE OVER A PROPERTY NO FIXTURE VARIES. IGNORANCE.
 *      `RecorderTest` drives six message shapes -- small, 64 KB, no body,
 *      HEAD-style, chunked, binary -- across EVERY {@link Source} constant, so
 *      a bypass conditioned on size, framing, body presence, encoding or
 *      source fires. One conditioned on something none of those vary does not,
 *      and no fixture set closes that: only execution against real traffic
 *      does, which is Task 9's. NARROWED THIS ROUND: `source == CRAWLER ?
 *      raw.clone() : redact(...)` used to be filed here and was not an
 *      instance of it at all -- `Source` was already varied elsewhere in the
 *      class, just never inside the redaction assertions. One loop closed it.
 *   2. EGRESS THROUGH A TYPE NEVER SPELLED AT THE CALL SITE. IGNORANCE.
 *      The set of type names that can open a socket is unbounded;
 *      `ChokepointTest.noSecondEgressFamilyExists` declares that exclusion
 *      rather than chasing it, and names the layers that do close it.
 *   3. P13, P14, P15 -- raw urls in plain columns, whether the proxy handler
 *      HONOURS its verdict, and the byte-flows reaching neither callback.
 *      IGNORANCE, all three, and each needs Burp or a schema change rather
 *      than a test here. `HxExtension`'s assumption block carries the
 *      conditions Task 9 must meet, including that a refused request must be
 *      counted AT THE TARGET and never by reading the client's response.
 *
 * WHAT CAME OFF THIS LIST, and why the removals are recorded rather than
 * tidied away: `Observed::new` / `Denied::new` inside `hx.proxy` (round 4 --
 * the compiler bounds other packages, and both constructor spellings are
 * counted within it); a METHOD REFERENCE against a must-be-zero needle (round
 * 4 -- it was a finding, not a residual: `policy::checkGate` charged the Gate
 * twice, green); and an exactly-N needle defeated by ADDITION (round 5 -- also
 * a finding, also green, and on the SHIPPED send path). All three were listed
 * here as harmless before they were measured. That is the record this list
 * exists to keep honest.
 *
 * THE PACKAGE EDGE IS NEW AND POINTS THIS WAY ON PURPOSE: {@code hx.proxy}
 * names {@code hx.send}. This class PRODUCES an {@code hx.proxy} type and
 * CONSUMES an {@code hx.send} service, so the dependency runs from the
 * consumer to the service and never back -- the same direction
 * {@code hx.proxy -> hx.bridge} already runs. Nothing pins it, and the one
 * edge that IS pinned is the opposite one:
 * `ChokepointTest.theBridgeNamesNothingInTheProxyPackage` requires that
 * {@code hx.bridge} never name {@code hx.proxy}, which this does not touch.
 * If {@code hx.send} ever needs something from {@code hx.proxy}, that is the
 * cycle to refuse, and the answer will be the one {@code ExchangeSink} took:
 * declare the interface on the side being called.
 */
public final class Recorder {

    private final Redactor redactor;

    /** The ONE Redactor, handed in for the same reason the ONE Policy is: a
     *  second one would be a second set of rules with nothing comparing them.
     *  Sharing it across proxy threads is safe because it has NO INSTANCE
     *  FIELDS -- checked, not assumed: every field on that class is
     *  `static final`, and {@link Redactor.Injected} exists precisely so that
     *  the state which IS per-request travels with the bytes instead. */
    public Recorder(Redactor redactor) {
        this.redactor = redactor;
    }

    /**
     * The two raw halves in, one redacted {@link Observed} out.
     *
     * DECLARED AS {@link Captured}, not as {@code Observed}: the concrete type
     * is package-private, so the entry point cannot name it -- which is the
     * point. It gets a record it can hand to {@link Capture#offer} and cannot
     * take apart, cannot rebuild, and cannot construct a rival to.
     *
     * WHICH FUNCTION GOES WITH WHICH MESSAGE IS THE WHOLE POINT OF THIS
     * METHOD. `redactObservedRequest` matches the three request credential
     * header names; `redactResponse` matches `Set-Cookie`. Each returns a
     * message it does not recognise VERBATIM -- which is correct behaviour for
     * a message with nothing to redact and a total leak for a message handed
     * to the wrong one. Nothing in the type system separates them: both take
     * and return {@code byte[]}.
     *
     * NEITHER ARGUMENT IS MODIFIED, and neither returned array aliases its
     * input -- both entry points copy, {@code redactObservedRequest} including
     * the case where it has nothing to do. So the bytes Burp is about to put
     * on the wire are untouched and only the copy crossing the bridge carries
     * placeholders.
     *
     * IT CAN THROW. A {@link Redactor.RangeError} out of either call is a
     * record hx cannot make safe to store, and the caller's answer is to count
     * the loss rather than queue the bytes. Deliberately not caught here: this
     * class has no counter and inventing a fallback would be inventing an
     * unredacted record.
     */
    public Captured record(String method, String url, int status, long ms,
                           byte[] rawRequest, byte[] rawResponse, Source source) {
        byte[] request = redactor.redactObservedRequest(rawRequest);
        byte[] response = redactor.redactResponse(rawResponse);
        return new Observed(method, url, status, ms, request, response, source);
    }

    /**
     * One refusal, as a record. No bodies and therefore no redaction: the
     * request never left, so there are no bytes to make safe.
     *
     * IT IS HERE FOR THE COMPILER, NOT FOR THE WORK IT DOES. {@link Denied} is
     * package-private for the same reason {@link Observed} is, and the entry
     * point lives in another package -- so this method is what lets it record
     * a refusal at all. Leaving `Denied` public so the entry point could keep
     * building its own would have left one of the two {@link Captured} kinds
     * constructible from anywhere, which is precisely the second door the
     * other one was closed against.
     */
    public Captured denial(String method, String url, String errorClass,
                           String detail, Source source) {
        return new Denied(method, url, errorClass, detail, source);
    }
}
