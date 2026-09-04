// extension/test/hx/policy/DistressTest.java
package hx.policy;

import hx.TestSupport;

/**
 * Hand-rolled runner: JUnit would be a dependency, and this jar has none.
 *
 * The clock is hand-driven -- hx.policy.TickClock, the one the Limiter task puts
 * in the test tree. Same package, so no import. Every boundary below is hit
 * exactly and nothing here sleeps: a 60-second window tested by waiting is a
 * test nobody runs twice. TickClock.advance takes MICROSECONDS, so the
 * millisecond gaps below are multiplied out at the call site.
 */
public class DistressTest {

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
        TestSupport.t(DistressTest::check, name, body);
    }

    static void expectThrows(String what, Class<?> type, Runnable body) {
        try {
            body.run();
            check(what + " (expected " + type.getSimpleName() + ")", false);
        } catch (Throwable t) {
            check(what, type.isInstance(t));
        }
    }

    // Real host names. `.test` is reserved by RFC 6761 and resolves nowhere;
    // nothing in this file opens a socket in any case.
    static final String APP = "app.example.test";
    static final String API = "api.example.test";

    /** 2026-08-22, in microseconds. A real epoch, so an accidental int
     *  somewhere in the arithmetic overflows visibly instead of passing. */
    static final long T0 = 1_787_000_000_000_000L;

    /** §4's defaults: 5xx above 20%, p50 above 5x baseline, 5 consecutive
     *  connection errors. Built through the Interface Contract's four-argument
     *  constructor, so that constructor is exercised by every case below. */
    static Distress fresh(TickClock clock) { return new Distress(clock, 0.20, 5.0, 5); }

    public static void main(String[] args) {
        t("healthyTrafficNeverTrips", DistressTest::healthyTrafficNeverTrips);
        t("aSlowButConsistentHostIsNotADistressedOne", DistressTest::aSlowButConsistentHostIsNotADistressedOne);
        t("fiveXxRateAtExactlyTheThresholdDoesNotTrip", DistressTest::fiveXxRateAtExactlyTheThresholdDoesNotTrip);
        t("oneMoreFiveXxOverTheThresholdTrips", DistressTest::oneMoreFiveXxOverTheThresholdTrips);
        t("aRateNeedsEnoughSamplesToBeARate", DistressTest::aRateNeedsEnoughSamplesToBeARate);
        t("connectionErrorsAreNotCountedAgainstTheFiveXxRate", DistressTest::connectionErrorsAreNotCountedAgainstTheFiveXxRate);
        t("fourErrorsThenASuccessThenFourMoreDoesNotTrip", DistressTest::fourErrorsThenASuccessThenFourMoreDoesNotTrip);
        t("aFiveHundredThreeIsAResponseNotAConnectionError", DistressTest::aFiveHundredThreeIsAResponseNotAConnectionError);
        t("theTenthRequestEstablishesTheBaselineTheEleventhIsMeasured", DistressTest::theTenthRequestEstablishesTheBaselineTheEleventhIsMeasured);
        t("latencyAtExactlyFiveTimesBaselineDoesNotTrip", DistressTest::latencyAtExactlyFiveTimesBaselineDoesNotTrip);
        t("oneMillisecondOverFiveTimesBaselineTrips", DistressTest::oneMillisecondOverFiveTimesBaselineTrips);
        t("aSubMillisecondBaselineDoesNotMakeJitterDistress", DistressTest::aSubMillisecondBaselineDoesNotMakeJitterDistress);
        t("theLatencyFloorDelaysTheRuleItDoesNotDisableIt", DistressTest::theLatencyFloorDelaysTheRuleItDoesNotDisableIt);
        t("theWindowRollsByCount", DistressTest::theWindowRollsByCount);
        t("theWindowRollsByTime", DistressTest::theWindowRollsByTime);
        t("hostsAreCountedSeparately", DistressTest::hostsAreCountedSeparately);
        t("aTrippedDistressStaysTripped", DistressTest::aTrippedDistressStaysTripped);
        t("aWindowThatCannotHoldASampleIsRefused", DistressTest::aWindowThatCannotHoldASampleIsRefused);
        t("theHaltedFrameCanNameTheWindow", DistressTest::theHaltedFrameCanNameTheWindow);

        // Fix round 1: the cutoff-arithmetic overflow (critical), the
        // forward-spike/backward-correction eviction freeze (moderate), and
        // the unguarded zero-baseline clamp (minor).
        t("theConstructorRefusesAWindowMsAboveTheOverflowCeiling", DistressTest::theConstructorRefusesAWindowMsAboveTheOverflowCeiling);
        t("anUnrepresentableWindowBoundTripsRatherThanGoingSilentlyDark", DistressTest::anUnrepresentableWindowBoundTripsRatherThanGoingSilentlyDark);
        t("theWindowArithmeticDoesNotOverflowNearLongMaxValueEither", DistressTest::theWindowArithmeticDoesNotOverflowNearLongMaxValueEither);
        t("aTransientForwardClockSpikeDoesNotFreezeTimeBasedEvictionBehindIt", DistressTest::aTransientForwardClockSpikeDoesNotFreezeTimeBasedEvictionBehindIt);
        t("aZeroMillisecondBaselineDoesNotCollapseTheLatencyThresholdToZero", DistressTest::aZeroMillisecondBaselineDoesNotCollapseTheLatencyThresholdToZero);
        t("anOverflowTripIsNotOverwrittenByALaterRuleInTheSameCall", DistressTest::anOverflowTripIsNotOverwrittenByALaterRuleInTheSameCall);

        // Fix round 2: four of the five thresholds could be set to values that
        // leave Distress looking configured and never tripping.
        t("aThresholdNoTrafficCanCrossIsRefused", DistressTest::aThresholdNoTrafficCanCrossIsRefused);
        t("anUnboundedWindowIsAnUnboundedAllocationPerHost", DistressTest::anUnboundedWindowIsAnUnboundedAllocationPerHost);
        t("theWindowMsCeilingSaysWhyItIsThereAndDoesNotSendTheOperatorSomewhereUnbounded", DistressTest::theWindowMsCeilingSaysWhyItIsThereAndDoesNotSendTheOperatorSomewhereUnbounded);
        t("aNegativeDurationIsClampedRatherThanPoisoningTheBaseline", DistressTest::aNegativeDurationIsClampedRatherThanPoisoningTheBaseline);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    static void healthyTrafficNeverTrips() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        // 3xx and 4xx are in here deliberately: a 404 sweep is what a lot of
        // discovery looks like, and reading one as a server error would abort
        // a run for doing its job.
        int[] statuses = {200, 200, 301, 200, 404, 200, 302, 200, 401, 200};
        for (int i = 0; i < 50; i++) {
            d.record(APP, statuses[i % statuses.length], 120, false);
            clock.advance(120_000L);
        }
        check("50 healthy requests do not trip", d.stopReason() == null);
        check("a healthy run names no host", d.stopHost() == null);
    }

    static void aSlowButConsistentHostIsNotADistressedOne() {
        // The false-positive direction, and the one that costs a client
        // engagement rather than a client system: a slow site is not a
        // distressed one. Everything here is roughly a second per request --
        // miserable, entirely normal for an internal app behind three
        // middleboxes -- and steady.
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 10; i++) { d.record(APP, 200, 900, false); clock.advance(900_000L); }
        check("a 900 ms baseline is 900 ms", d.baselineMs(APP) == 900);
        long[] jitter = {850, 875, 900, 925, 950};
        for (int i = 0; i < 40; i++) {
            d.record(APP, 200, jitter[i % jitter.length], false);
            clock.advance(jitter[i % jitter.length] * 1000L);
        }
        check("consistently slow is not distress", d.stopReason() == null);
    }

    static void fiveXxRateAtExactlyTheThresholdDoesNotTrip() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 8; i++) d.record(APP, 200, 120, false);
        d.record(APP, 503, 120, false);
        d.record(APP, 503, 120, false);
        // 2 of 10 is 20.0%, and §4 says "above 20%". Exactly at the threshold
        // is not above it.
        check("a 5xx rate of exactly 20% does not trip", d.stopReason() == null);
    }

    static void oneMoreFiveXxOverTheThresholdTrips() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 8; i++) d.record(APP, 200, 120, false);
        d.record(APP, 503, 120, false);
        d.record(APP, 503, 120, false);
        d.record(APP, 500, 120, false);          // 3 of 11 = 27.3%
        check("one 5xx over the threshold trips",
              "5xx rate 27.3% over the last 11 requests exceeds 20.0%".equals(d.stopReason()));
        check("the stop names the host", APP.equals(d.stopHost()));
    }

    static void aRateNeedsEnoughSamplesToBeARate() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        d.record(APP, 502, 120, false);
        // 1 of 1 is 100%, and it is also one transient bad gateway on the
        // first request of the run.
        check("a single 502 does not abort the run", d.stopReason() == null);
        for (int i = 0; i < 8; i++) d.record(APP, 502, 120, false);
        check("nine consecutive 502s still hold the gate", d.stopReason() == null);
        d.record(APP, 502, 120, false);
        check("the tenth 502 trips: the gate delays the rule, it does not disable it",
              d.stopReason() != null && d.stopReason().startsWith("5xx rate 100.0%"));
    }

    static void connectionErrorsAreNotCountedAgainstTheFiveXxRate() {
        // A 5xx RATE is the rate at which the application ANSWERS 5xx, so the
        // denominator is answered requests. Counting refused connections in it
        // would let two rules borrow each other's evidence, and the
        // consecutive-error rule already owns transport failure.
        //
        // The documented cost is here in the assertions rather than hidden: a
        // host alternating a 503 and a refusal needs twice as many requests
        // before a rate exists, and the interleaving is exactly what keeps the
        // streak from reaching five. Ten requests, not five, is the price.
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 5; i++) { d.record(APP, 503, 100, false); d.record(APP, 0, 30, true); }
        check("five answers is not ten, whatever the ten samples beside them are",
              d.stopReason() == null);
        check("the window still holds all ten samples", d.windowSize(APP) == 10);
        for (int i = 0; i < 5; i++) { d.record(APP, 503, 100, false); d.record(APP, 0, 30, true); }
        check("the tenth answered 5xx trips",
              d.stopReason() != null && d.stopReason().startsWith("5xx rate 100.0%"));
    }

    static void fourErrorsThenASuccessThenFourMoreDoesNotTrip() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 4; i++) d.record(APP, 0, 30, true);
        check("four consecutive connection errors do not trip", d.stopReason() == null);
        d.record(APP, 200, 120, false);          // the streak is broken here
        for (int i = 0; i < 4; i++) d.record(APP, 0, 30, true);
        check("four, a success, then four more is not five in a row", d.stopReason() == null);
        d.record(APP, 0, 30, true);
        check("the fifth in a row trips",
              "5 consecutive connection errors".equals(d.stopReason()));
        check("the connection-error stop names the host", APP.equals(d.stopHost()));
    }

    static void aFiveHundredThreeIsAResponseNotAConnectionError() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 4; i++) d.record(APP, 0, 30, true);
        // Something answered, so the transport is up. That is a different
        // failure from a refused connection and it breaks the streak, even
        // though the same sample counts against the 5xx rate.
        d.record(APP, 503, 120, false);
        for (int i = 0; i < 4; i++) d.record(APP, 0, 30, true);
        check("a 503 breaks the connection-error streak", d.stopReason() == null);
    }

    static void theTenthRequestEstablishesTheBaselineTheEleventhIsMeasured() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 9; i++) d.record(APP, 200, 100, false);
        check("no baseline after nine requests", d.baselineMs(APP) == -1);
        check("and nothing to measure against, so nothing trips", d.stopReason() == null);

        // The tenth arrives 61 seconds later, so the nine before it have aged
        // out of the WINDOW while the baseline is still taken from all ten.
        // That gap is what makes the guard observable: the window now holds a
        // single 60-second sample, so if the tenth request were measured
        // against a baseline it is still helping to establish, this is where
        // it would trip.
        clock.advance(61_000_000L);
        d.record(APP, 200, 60_000, false);
        check("the tenth request establishes the baseline", d.baselineMs(APP) == 100);
        check("the tenth request is not itself measured against it", d.stopReason() == null);

        d.record(APP, 200, 60_000, false);
        check("the eleventh is",
              d.stopReason() != null && d.stopReason().startsWith("p50 latency 60000 ms"));
    }

    static void latencyAtExactlyFiveTimesBaselineDoesNotTrip() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 10; i++) d.record(APP, 200, 100, false);
        check("the baseline is the p50 of the first ten", d.baselineMs(APP) == 100);
        // 5 x 100 ms is 500 ms. Twenty samples at exactly 500 ms move the
        // median of the window onto a slow sample and still do not trip,
        // because §4 says "above 5x".
        for (int i = 0; i < 20; i++) d.record(APP, 200, 500, false);
        check("p50 at exactly 5x the baseline does not trip", d.stopReason() == null);
    }

    static void oneMillisecondOverFiveTimesBaselineTrips() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 10; i++) d.record(APP, 200, 100, false);
        for (int i = 0; i < 10; i++) d.record(APP, 200, 501, false);
        // Ten slow samples against ten fast ones leave the median fast. That
        // is the whole point of a p50 rule: one slow request, or ten, is not
        // yet a trend, and a mean would have tripped on the first.
        check("ten slow samples still leave the median fast", d.stopReason() == null);
        d.record(APP, 200, 501, false);
        check("the eleventh makes the median slow, and 501 ms is above 500 ms",
              "p50 latency 501 ms over the last 21 requests exceeds 5.0x the 100 ms baseline"
                  .equals(d.stopReason()));
    }

    static void aSubMillisecondBaselineDoesNotMakeJitterDistress() {
        // A loopback target answers in about a millisecond, and every
        // integration test in this repo runs against loopback. With no floor,
        // 5x a 1 ms baseline is 5 ms, ordinary scheduler jitter clears it, and
        // the harness aborts its own test suite.
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 10; i++) d.record(APP, 200, 1, false);
        check("a 1 ms baseline", d.baselineMs(APP) == 1);
        for (int i = 0; i < 15; i++) d.record(APP, 200, 20, false);
        check("20 ms against a 1 ms baseline is jitter, not distress", d.stopReason() == null);
    }

    static void theLatencyFloorDelaysTheRuleItDoesNotDisableIt() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 10; i++) d.record(APP, 200, 1, false);
        for (int i = 0; i < 11; i++) d.record(APP, 200, 300, false);
        check("300 ms against a 1 ms baseline is above the floor and trips",
              d.stopReason() != null && d.stopReason().startsWith("p50 latency 300 ms"));
    }

    static void theWindowRollsByCount() {
        // Nothing advances the clock in this case, so the 60-second bound
        // cannot be what does the work. This is the count bound alone.
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 200; i++) d.record(APP, 200, 100, false);
        check("the window holds at most 50 samples", d.windowSize(APP) == 50);
        for (int i = 0; i < 10; i++) d.record(APP, 503, 100, false);
        check("40 healthy and 10 failing is exactly 20% and does not trip",
              d.stopReason() == null);
        // The eleventh evicts one more healthy sample instead of diluting
        // itself against two hundred of them. A long healthy history must not
        // mask a host that has just started failing: unbounded, this reads
        // 11/211 = 5.2% and the run walks on into a host now failing one
        // request in five.
        d.record(APP, 503, 100, false);
        check("the eleventh trips at 22.0% of a 50-sample window",
              "5xx rate 22.0% over the last 50 requests exceeds 20.0%".equals(d.stopReason()));
    }

    static void theWindowRollsByTime() {
        // Ten samples at most, so the 50-request bound cannot be what does the
        // work. This is the 60-second bound alone, at the exact microsecond on
        // both sides of the edge.
        TickClock atTheEdge = new TickClock(T0);
        Distress d1 = fresh(atTheEdge);
        for (int i = 0; i < 9; i++) d1.record(APP, 503, 100, false);
        check("nine 5xx are below the ten-sample gate", d1.stopReason() == null);
        atTheEdge.advance(60_000_000L);                  // exactly 60 s later
        d1.record(APP, 503, 100, false);
        check("a sample exactly 60 s old is still in the window", d1.windowSize(APP) == 10);
        check("so the tenth 5xx trips",
              d1.stopReason() != null && d1.stopReason().startsWith("5xx rate 100.0%"));

        TickClock pastTheEdge = new TickClock(T0);
        Distress d2 = fresh(pastTheEdge);
        for (int i = 0; i < 9; i++) d2.record(APP, 503, 100, false);
        pastTheEdge.advance(60_000_001L);                // one microsecond older
        d2.record(APP, 503, 100, false);
        check("one microsecond past the edge and the nine are gone", d2.windowSize(APP) == 1);
        check("with one sample in the window there is no rate to trip on",
              d2.stopReason() == null);
    }

    static void hostsAreCountedSeparately() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 9; i++) d.record(APP, 503, 100, false);
        for (int i = 0; i < 9; i++) d.record(API, 503, 100, false);
        // Eighteen 5xx and no trip. One window per host, or two hosts each
        // below the gate add up to one that is not -- and the host named in
        // the stop would then be whichever one happened to be last.
        check("windows do not pool across hosts", d.stopReason() == null);
        check("each host has its own window",
              d.windowSize(APP) == 9 && d.windowSize(API) == 9);
        d.record(APP, 503, 100, false);
        check("the tenth on one host trips the whole run", d.stopReason() != null);
        check("and names that host", APP.equals(d.stopHost()));
    }

    static void aTrippedDistressStaysTripped() {
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 10; i++) d.record(APP, 503, 100, false);
        String reason = d.stopReason();
        check("tripped", reason != null && APP.equals(d.stopHost()));

        // §4: one distressed host aborts the WHOLE run. There is no per-host
        // recovery to model, so a healthy second host cannot talk the first one
        // down, and the first reason is the one that becomes run.stop_reason.
        for (int i = 0; i < 200; i++) { d.record(API, 200, 20, false); clock.advance(20_000L); }
        // java.util.Objects.equals, not reason.equals(...): a sabotage that
        // makes stopReason() go null (row 1 of the sabotage table) leaves
        // `reason` null too, and reason.equals(...) on a null reference threw
        // an uncaught NullPointerException that crashed the whole harness here
        // -- silently skipping every check after this one, including both
        // remaining original cases and every fix-round test appended below.
        // Fix-round-1 verification is what caught it: the crash reproduces
        // identically against commit 4ab73d5's own DistressTest.java, so the
        // original sabotage table's "11/11, matches exactly" for row 1 was
        // true by accident -- the run never got far enough to check the rest.
        //
        // That was the ninth false claim on this branch and the one that
        // indicted the runner rather than the code; the per-method guard in
        // hx.TestSupport is the general fix, and row 1 now measures 14 FAILs
        // over a class that runs all the way to its summary line. This line
        // keeps Objects.equals anyway, because the guard is coarser than it
        // is: the guard reports ONE failure naming a throw and skips the four
        // checks after it, where this reports the property that broke.
        check("a healthy host does not clear a trip",
              java.util.Objects.equals(reason, d.stopReason()));
        check("and does not steal the stop from the host that caused it",
              APP.equals(d.stopHost()));
        check("a tripped Distress stops recording altogether", d.windowSize(API) == 0);
    }

    static void aWindowThatCannotHoldASampleIsRefused() {
        // The dangerous direction of a config typo is the one that DISABLES a
        // rule: a zero-length window makes the 5xx and latency rules
        // unfireable and a distressed host then reads as a healthy one. A
        // threshold set too tight only ever costs an early stop, which is the
        // cheap failure. So the constructor refuses the disarming values.
        TickClock clock = new TickClock(T0);
        expectThrows("a zero-request window is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 0, 60_000L, 10, 250L));
        expectThrows("a zero-millisecond window is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, 0L, 10, 250L));
        expectThrows("a 5xx rate above 1.0 is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 1.5, 5.0, 5));
        expectThrows("a latency multiple below 1.0 is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 0.5, 5));
        expectThrows("a zero-length error streak is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 0));
        expectThrows("a zero-sample baseline is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, 60_000L, 0, 250L));
    }

    static void theHaltedFrameCanNameTheWindow() {
        // §6's halted frame is {reason, host, window}. Reason and host come
        // from the stop; the window is the configuration that produced it, and
        // nothing else on the send path knows what that configuration was.
        Distress d = fresh(new TickClock(T0));
        check("the window describes both bounds",
              "last 50 requests or 60000 ms".equals(d.window()));
    }

    // ------------------------------------------------------------------
    // Fix round 1. `evict()`'s cutoff was `nowUs - windowMs * 1000L`, unsafe
    // on either operand: `windowMs * 1000L` overflows for a `windowMs` an
    // operator reaches for as a "no time bound" sentinel, and the subtraction
    // underflows for a clock reading near Long.MIN_VALUE. Either wiped the
    // window (or never aged it) on every record() while stopReason() stayed
    // null forever -- a distressed host reading as a healthy one. Below also
    // covers the forward-spike/backward-correction eviction freeze and the
    // zero-millisecond-baseline clamp flagged in the same review.
    // ------------------------------------------------------------------

    static void theConstructorRefusesAWindowMsAboveTheOverflowCeiling() {
        // The 8-arg constructor validated windowMs < 1 but had no ceiling, so
        // windowMs = Long.MAX_VALUE -- exactly what an operator reaches for as
        // a "no time bound, count-only" sentinel -- constructed without
        // complaint. windowMs * 1000L then wrapped to -1000, which pushed
        // cutoffUs into the future and wiped the window on every record(): the
        // 5xx-rate and latency rules went silently dark while stopReason()
        // stayed null forever. The runtime case is now unreachable because the
        // constructor refuses it -- literal 24-hour-in-ms bound below, not
        // derived from Distress's own constant, so this test does not agree
        // with itself no matter what that constant says.
        TickClock clock = new TickClock(T0);
        expectThrows("windowMs of Long.MAX_VALUE is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, Long.MAX_VALUE, 10, 250L));
        expectThrows("one millisecond past the 24-hour ceiling is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, 86_400_000L + 1, 10, 250L));
        Distress atCeiling = new Distress(clock, 0.20, 5.0, 5, 50, 86_400_000L, 10, 250L);
        check("24 hours itself is accepted: the ceiling is inclusive",
              atCeiling.stopReason() == null);
    }

    static void anUnrepresentableWindowBoundTripsRatherThanGoingSilentlyDark() {
        // No config bound can prevent nowUs - windowMs*1000L from underflowing
        // when the CLOCK is the extreme operand: the constructor runs before
        // any clock is ever read. A clock starting at Long.MIN_VALUE
        // underflows the very first cutoff computation. Before this fix that
        // silently wiped the window on every record() -- stopReason() stayed
        // null and windowSize() stayed 0 through 30 requests of 503s, one
        // second apart, indistinguishable from a healthy target. The
        // arithmetic must fail closed instead: an overflow trips immediately
        // rather than continuing with a window it cannot compute.
        TickClock clock = new TickClock(Long.MIN_VALUE);
        Distress d = fresh(clock);
        d.record(APP, 503, 100, false);
        check("an unrepresentable window bound trips on the very first record",
              d.stopReason() != null);
        check("...and names the host", APP.equals(d.stopHost()));

        // The full reproduction: 30 x 503, one second apart. Sticky, so the
        // first trip is the one that stands for the whole run.
        TickClock clock2 = new TickClock(Long.MIN_VALUE);
        Distress d2 = fresh(clock2);
        String firstReason = null;
        for (int i = 0; i < 30; i++) {
            d2.record(APP, 503, 100, false);
            if (firstReason == null) firstReason = d2.stopReason();
            clock2.advance(1_000_000L);
        }
        check("the reproduction trips on the first request rather than never",
              firstReason != null);
        // java.util.Objects.equals, for the reason spelled out in
        // aTrippedDistressStaysTripped above: firstReason.equals(...) on a null
        // reference throws, and a throw still costs the checks after it now
        // that the per-method guard keeps it from costing the whole class.
        check("...and does not clear across the full 30-request reproduction",
              java.util.Objects.equals(firstReason, d2.stopReason()));
    }

    static void theWindowArithmeticDoesNotOverflowNearLongMaxValueEither() {
        // The subtraction's other extreme: nowUs itself near Long.MAX_VALUE
        // does NOT overflow (Long.MAX_VALUE - 60000000 is still comfortably
        // positive), so this is the sanity check that fixing the overflow did
        // not turn an already-safe case into a spurious trip.
        TickClock clock = new TickClock(Long.MAX_VALUE - 5_000_000L);
        Distress d = fresh(clock);
        for (int i = 0; i < 5; i++) { d.record(APP, 200, 100, false); clock.advance(1_000_000L); }
        check("ordinary traffic at the top of the long range does not trip",
              d.stopReason() == null);
        check("...and the window holds all five", d.windowSize(APP) == 5);
    }

    static void aTransientForwardClockSpikeDoesNotFreezeTimeBasedEvictionBehindIt() {
        // evict()'s time loop used to inspect only the deque's front and stop
        // as soon as it was not expired. A sample recorded during a transient
        // forward clock spike keeps an inflated timestamp; once the clock
        // corrects backward and the samples in front of it age out normally,
        // the spiked sample becomes the new front -- and its inflated
        // timestamp never looks expired relative to the (now lower) current
        // time, so the loop stopped there and left genuinely stale samples
        // stuck behind it in the deque. Bounded by the count cap, but silent
        // and untested. The fix scans the whole window instead of breaking at
        // the first non-expired front element.
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);

        d.record(APP, 200, 100, false);                  // A, at T0

        clock.set(T0 + 70_000_000L);                      // a transient forward spike: +70s
        d.record(APP, 200, 100, false);                   // B, at the spike -- evicts A

        clock.set(T0 + 10_000_000L);                       // the clock corrects back to +10s
        d.record(APP, 200, 100, false);                    // C, at the corrected time
        check("right after the correction, nothing looks stale yet",
              d.windowSize(APP) == 2);

        clock.advance(60_000_001L);                        // one microsecond past C's own window
        d.record(APP, 200, 100, false);                    // D
        check("C is genuinely stale now and is evicted despite sitting behind "
              + "the spiked sample B in the deque", d.windowSize(APP) == 2);
    }

    static void aZeroMillisecondBaselineDoesNotCollapseTheLatencyThresholdToZero() {
        // Math.max(h.baselineMs, 1L) in tripOnLatency. Under the default
        // latencyMultiple (5.0) and floor (250 ms) this line is not
        // load-bearing in the rest of this suite: a clamped threshold of 5 ms
        // and an unclamped one of 0 ms are both so far below the 250 ms floor
        // that the floor is what actually suppresses a trip either way, and
        // deleting the clamp leaves every other assertion here green. A floor
        // of 0 and a wide multiple isolate the clamp itself: without it, a
        // genuinely 0 ms baseline collapses "Nx baseline" to a threshold of 0
        // no matter how generous N is, and any positive latency then reads as
        // infinitely over threshold.
        TickClock clock = new TickClock(T0);
        Distress d = new Distress(clock, 0.20, 1000.0, 5, 50, 60_000L, 10, 0L);
        for (int i = 0; i < 10; i++) d.record(APP, 200, 0, false);
        check("a baseline of genuinely 0 ms is recorded as 0, not bumped up front",
              d.baselineMs(APP) == 0);
        for (int i = 0; i < 11; i++) d.record(APP, 200, 500, false);
        check("500 ms against a clamped-to-1 zero baseline stays under a "
              + "deliberately generous 1000x threshold and does not trip",
              d.stopReason() == null);
    }

    static void anOverflowTripIsNotOverwrittenByALaterRuleInTheSameCall() {
        // record() calls evict() and then keeps going. In every case above
        // that is harmless because nothing else in the same call ever ALSO
        // trips. Force it to: build up a 20%-exactly 5xx window normally,
        // then let the clock jump to a value that underflows the cutoff
        // computation on the very request that would ALSO tip the 5xx rate
        // over the threshold. Without the guard right after evict(),
        // tripOn5xxRate runs anyway on a window whose time-based eviction
        // never ran, and its trip() call would silently overwrite the correct
        // "cannot tell whether this host is healthy" reason with a specific
        // rate figure -- exactly the second write the class comment says a
        // sticky trip must never allow.
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 8; i++) d.record(APP, 200, 100, false);
        d.record(APP, 503, 100, false);
        d.record(APP, 503, 100, false);
        check("2 of 10 is exactly 20%: not yet tripped", d.stopReason() == null);

        clock.set(Long.MIN_VALUE + 100);          // underflows the cutoff computation
        d.record(APP, 503, 100, false);           // would ALSO be 3 of 11 = 27.3%, over threshold
        check("the overflow trip wins: the window could not be evaluated at all",
              d.stopReason() != null
                  && d.stopReason().startsWith("distress window arithmetic overflowed"));
        check("...not the 5xx-rate reason a later rule in the same call would "
              + "otherwise have computed from a half-evicted window",
              !"5xx rate 27.3% over the last 11 requests exceeds 20.0%".equals(d.stopReason()));
    }
    // ------------------------------------------------------------------
    // Fix round 2. The validation above covered ONE of the five thresholds
    // against the failure it exists to prevent -- a value that leaves Distress
    // looking configured and never tripping. Four did not, and all three rules
    // could be disarmed at once through the public constructors while every
    // check in this file stayed green:
    //
    //   rule 1   maxConsecutiveErrors = Integer.MAX_VALUE   (no upper bound)
    //   rule 2   max5xxRate = 1.0                           (rate <= 1.0 always)
    //   rule 2   baselineRequests = 1_000_000               (answered < it forever)
    //   rule 3   latencyFloorMs = Long.MAX_VALUE            (no upper bound)
    //   rule 3   latencyMultiple = +Infinity                (threshold = Infinity)
    //
    // Reproduced: all three disarmed, then 20 consecutive refusals, 30 x 503
    // and 30 one-hour responses -- 90 requests of unambiguous distress --
    // yielded stopReason() == null.
    // ------------------------------------------------------------------

    static void aThresholdNoTrafficCanCrossIsRefused() {
        TickClock clock = new TickClock(T0);

        // rule 1. The streak is NOT bounded by the window -- it is a running
        // count -- so nothing else caps it and 2.1 billion consecutive refused
        // connections is a rule that never fires.
        expectThrows("a consecutive-error threshold of Integer.MAX_VALUE is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, Integer.MAX_VALUE));
        expectThrows("one past the 1000 streak ceiling is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 1001));
        check("the ceiling itself is accepted",
              new Distress(clock, 0.20, 5.0, 1000) != null);

        // rule 2. The rate is 5xx/answered, so it can never EXCEED 1.0 and a
        // threshold of exactly 1.0 is one no traffic can be above -- including
        // a host answering 100% 5xx.
        expectThrows("a 5xx threshold of exactly 1.0 is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 1.0, 5.0, 5));
        check("just below it is accepted",
              new Distress(clock, 0.999, 5.0, 5) != null);

        // rule 2 again, through the other knob. The window holds at most
        // windowRequests samples, so `answered` can never reach a baseline
        // larger than the window and the rate is never computed at all.
        expectThrows("a baseline larger than the window is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, 60_000L, 1_000_000, 250L));
        expectThrows("...even one sample larger", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, 60_000L, 51, 250L));
        check("a baseline exactly the size of the window is accepted",
              new Distress(clock, 0.20, 5.0, 5, 50, 60_000L, 50, 250L) != null);

        // rule 3. Infinity passed the old `>= 1.0` test, and
        // Math.max(baselineMs, 1L) * latencyMultiple is a MEASUREMENT times a
        // CONFIG VALUE -- the same shape as windowMs * 1000L, overflowing to a
        // threshold no long p50 can rise above.
        expectThrows("a latency multiple of +Infinity is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, Double.POSITIVE_INFINITY, 5));
        expectThrows("and NaN with it", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, Double.NaN, 5));
        expectThrows("one past the 1000x ceiling is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 1000.001, 5));
        check("the ceiling itself is accepted",
              new Distress(clock, 0.20, 1000.0, 5) != null);
        expectThrows("a NaN 5xx rate is refused too", IllegalArgumentException.class,
                     () -> new Distress(clock, Double.NaN, 5.0, 5));

        // rule 3 again, through the floor, which SUPPRESSES the rule while the
        // host answers faster than it -- so a floor nothing can exceed
        // suppresses it always.
        expectThrows("a latency floor of Long.MAX_VALUE is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, 60_000L, 10, Long.MAX_VALUE));
        expectThrows("one millisecond past the 60 s floor ceiling is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 50, 60_000L, 10, 60_001L));
        check("the ceiling itself is accepted",
              new Distress(clock, 0.20, 5.0, 5, 50, 60_000L, 10, 60_000L) != null);
    }

    static void anUnboundedWindowIsAnUnboundedAllocationPerHost() {
        // Host allocates long[baselineRequests] and its deque holds up to
        // windowRequests samples, PER HOST, and the number of hosts is bounded
        // only by the scope. windowRequests = 200_000_000 constructed fine and
        // allocated 1.6 GB inside Burp's JVM for the first host it saw.
        TickClock clock = new TickClock(T0);
        expectThrows("a 200-million-request window is refused",
                     IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 200_000_000, 60_000L, 10, 250L));
        expectThrows("one past the 10000 ceiling is refused", IllegalArgumentException.class,
                     () -> new Distress(clock, 0.20, 5.0, 5, 10_001, 60_000L, 10, 250L));
        check("the ceiling itself is accepted",
              new Distress(clock, 0.20, 5.0, 5, 10_000, 60_000L, 10, 250L) != null);
    }

    static void theWindowMsCeilingSaysWhyItIsThereAndDoesNotSendTheOperatorSomewhereUnbounded() {
        // The message used to claim windowMs * 1000 "overflows a long well
        // before Long.MAX_VALUE". It overflows above Long.MAX_VALUE / 1000 --
        // about 292,271 years -- so that was wrong by eleven orders of
        // magnitude, and it redirected the operator to windowRequests, which
        // at the time had no upper bound at all.
        TickClock clock = new TickClock(T0);
        String message = "";
        try { new Distress(clock, 0.20, 5.0, 5, 50, 86_400_001L, 10, 250L); }
        catch (IllegalArgumentException e) { message = String.valueOf(e.getMessage()); }
        check("the ceiling message no longer claims an overflow that is not there",
              !message.contains("overflow"));
        check("it gives the reason the class comment gives: the shorter of the two bounds wins ("
              + message + ")", message.contains("SHORTER"));
        check("and the windowRequests it redirects to is itself bounded",
              message.contains("itself bounded at 10000"));
    }

    static void aNegativeDurationIsClampedRatherThanPoisoningTheBaseline() {
        // record() accepted a negative ms, which went straight into
        // firstLatencies and out again as the baseline -- and then into the
        // report text, as "exceeds 5.0x the -1 ms baseline". It is a caller
        // bug, but the request has already gone out by the time record() sees
        // it: dropping the sample would shrink the window the rules decide
        // from, which is the disarming direction. So it is clamped to 0, which
        // moves the baseline DOWN and can only make rule 3 more eager.
        TickClock clock = new TickClock(T0);
        Distress d = fresh(clock);
        for (int i = 0; i < 10; i++) { d.record(APP, 200, -1, false); clock.advance(1_000L); }
        check("a negative duration does not become a negative baseline ("
              + d.baselineMs(APP) + ")", d.baselineMs(APP) == 0);

        // ...and the clamped value is what the report quotes. Enough 300 ms
        // samples to carry the median past the ten clamped zeroes: the
        // threshold is 5x max(0, 1) = 5 ms, and 300 ms is also past the 250 ms
        // floor, so the rule fires as soon as the median moves.
        for (int i = 0; i < 20; i++) { d.record(APP, 200, 300, false); clock.advance(1_000L); }
        String reason = d.stopReason();
        check("300 ms against a clamped 0 ms baseline is above the floor and trips",
              reason != null);
        check("and the reason quotes the clamped value, never a negative one ("
              + reason + ")", reason != null && reason.contains("the 0 ms baseline"));
    }
}
