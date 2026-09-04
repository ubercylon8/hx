// extension/test/hx/policy/LimiterTest.java
package hx.policy;

import hx.TestSupport;

import static hx.TestSupport.waitUntilBlockedOn;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class LimiterTest {

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
        TestSupport.t(LimiterTest::check, name, body);
    }

    static void expectThrows(String what, Class<?> type, Runnable body) {
        try {
            body.run();
            check(what + " (expected " + type.getSimpleName() + ")", false);
        } catch (Throwable t) {
            check(what, type.isInstance(t));
        }
    }

    /** 2026-08-22T00:00:00Z in microseconds. A real point on a real clock:
     *  every boundary below is an offset from it, so an off-by-one in the
     *  window arithmetic shows up as a wrong number rather than as a
     *  coincidence around zero.
     *
     *  Every expected duration below is written out as a literal microsecond
     *  count rather than derived from Limiter's own WINDOW_US -- which is why
     *  that constant is private. A test that computes its expectation from the
     *  constant it is checking agrees with itself whatever the constant says. */
    static final long T0 = 1_787_356_800_000_000L;

    static final HxRequest ACCOUNT = get("app.example.test", "/account");
    static final HxRequest API_ORDERS = get("api.example.test", "/v2/orders");

    public static void main(String[] args) throws Exception {
        t("theBucketIsExactAtItsBoundaries", LimiterTest::theBucketIsExactAtItsBoundaries);
        t("theSustainedRateIsStillTheConfiguredRate",
          LimiterTest::theSustainedRateIsStillTheConfiguredRate);
        t("retryAfterUsIsExactlyLongEnoughAndNotAMicrosecondMore", LimiterTest::retryAfterUsIsExactlyLongEnoughAndNotAMicrosecondMore);
        t("rateIsAnsweredBeforeBudget", LimiterTest::rateIsAnsweredBeforeBudget);
        t("theBudgetIsMonotonicAndTimeDoesNotRefillIt", LimiterTest::theBudgetIsMonotonicAndTimeDoesNotRefillIt);
        t("nothingOnThisClassCanRefillASpentBudget", LimiterTest::nothingOnThisClassCanRefillASpentBudget);
        t("aZeroBudgetIssuesNothing", LimiterTest::aZeroBudgetIssuesNothing);
        t("theConstructorRefusesLimitsItCannotEnforce", LimiterTest::theConstructorRefusesLimitsItCannotEnforce);
        t("theLimitIsWholeRunNotPerHost", LimiterTest::theLimitIsWholeRunNotPerHost);
        t("aBackwardsClockCanOnlyOverRestrict", LimiterTest::aBackwardsClockCanOnlyOverRestrict);
        t("theWindowArithmeticDoesNotOverflowNearLongMaxValue", LimiterTest::theWindowArithmeticDoesNotOverflowNearLongMaxValue);
        t("aRealisticIdleGapPastTheIntRangeIsNotMisreadAsStillInsideTheWindow", LimiterTest::aRealisticIdleGapPastTheIntRangeIsNotMisreadAsStillInsideTheWindow);
        t("concurrentCallersCannotExceedEitherLimit", LimiterTest::concurrentCallersCannotExceedEitherLimit);
        t("checkIsExclusiveWithItselfDeterministically", LimiterTest::checkIsExclusiveWithItselfDeterministically);
        t("waitUntilBlockedOnRequiresTheSameMonitorNotJustBlockedState", LimiterTest::waitUntilBlockedOnRequiresTheSameMonitorNotJustBlockedState);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    /**
     * The three boundaries that matter, hit exactly: the request at the limit,
     * the microsecond before the window rolls, and the microsecond it rolls.
     */
    static void theBucketIsExactAtItsBoundaries() {
        TickClock clock = new TickClock(T0);
        // Default burst == rate, which is what the sliding log this replaced
        // already allowed: five issuances in one instant.
        Limiter l = new Limiter(clock, 5, 1000);

        for (int i = 1; i <= 5; i++)
            check("rate 5/s burst 5: request " + i + " of 5 in the same microsecond is allowed",
                  l.check(ACCOUNT).allowed());

        Decision sixth = l.check(ACCOUNT);
        check("the 6th request in the same microsecond is refused", !sixth.allowed());
        check("...as rate_limited", "rate_limited".equals(sixth.errorClass()));
        // THE GUARANTEE THAT CHANGED. The sliding log made this 1_000_000 --
        // a full second, until the oldest of the five left the window. A
        // bucket refills continuously, so one token is worth 1/5 of a second.
        // The SUSTAINED rate is identical; the recovery shape is not, and
        // this line is where the difference is pinned.
        check("...retrying after one token's worth of refill, 200000us",
              sixth.retryAfterUs() == 200_000L);
        check("...with a detail that names the limit",
              String.valueOf(sixth.detail()).contains("5/s"));

        clock.set(T0 + 199_999L);
        Decision oneEarly = l.check(ACCOUNT);
        check("one microsecond before a token is worth a request it is refused",
              !oneEarly.allowed());
        check("...and the wait has shrunk to exactly 1us", oneEarly.retryAfterUs() == 1L);

        clock.set(T0 + 200_000L);
        check("at exactly one token's worth the request is allowed",
              l.check(ACCOUNT).allowed());
        check("...and the next is refused again, the bucket being empty",
              !l.check(ACCOUNT).allowed());

        // THE WORST CASE THIS DESIGN PERMITS, asserted rather than left to a
        // reader: burst + rate inside one second. Five at T0, then one per
        // 200ms for the rest of the second is five more.
        clock.set(T0 + 1_000_000L);
        int inTheStraddlingSecond = 0;
        for (int i = 0; i < 10; i++)
            if (l.check(ACCOUNT).allowed()) inTheStraddlingSecond++;
        // FOUR, not five, and the arithmetic is the point: the last refill
        // was at T0+200_000, so this second only carries 800_000us of it --
        // 4 requests at 5/s. Computed rather than observed; an expectation
        // adjusted until it matched would assert nothing.
        check("the refill since the last issuance is worth exactly its elapsed "
              + "time at the configured rate (" + inTheStraddlingSecond + ")",
              inTheStraddlingSecond == 4);
        check("issued() counted every issuance and none of the refusals",
              l.issued() == 10L);
    }

    /**
     * THE PROMISE A CLIENT IS OWED, and the one this class exists to keep.
     *
     * The bucket lets `burst + rate` through a straddling second, which the
     * sliding log did not. What it must never do is let the SUSTAINED rate
     * exceed `ratePerSecond` -- that is the number quoted to a client, and a
     * bucket that drifted above it would be a limiter that does not limit.
     *
     * Ten seconds of continuous pressure at 5/s with burst 5: at most the
     * initial burst plus ten seconds of refill.
     */
    static void theSustainedRateIsStillTheConfiguredRate() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 5, 100_000);

        long allowed = 0;
        for (long us = 0; us <= 10_000_000L; us += 10_000L) {
            clock.set(T0 + us);
            // Press harder than the limit at every tick.
            for (int i = 0; i < 3; i++)
                if (l.check(ACCOUNT).allowed()) allowed++;
        }
        // burst (5) + 10s * 5/s = 55, and never more.
        check("ten seconds of pressure yields burst + 10s of refill, not more ("
              + allowed + ")", allowed == 55L);
    }

    /**
     * retryAfterUs is a promise to the agent: wait this long and the gate will
     * let you in. Arithmetic, not a guess -- so the wait is asserted from the
     * value the Decision carried, AND against the number that value must be.
     */
    static void retryAfterUsIsExactlyLongEnoughAndNotAMicrosecondMore() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 3, 1000);

        // Empty the bucket in one instant: burst defaults to the rate, so
        // three is exactly what it holds.
        for (int i = 1; i <= 3; i++)
            check("issuance " + i + " of 3, all at T0", l.check(ACCOUNT).allowed());

        Decision d = l.check(ACCOUNT);
        check("a 4th on an empty bucket is refused", !d.allowed());
        // One token at 3/s is a third of a second, rounded UP: a wait that
        // rounded down would invite the caller back a microsecond before a
        // token exists and refuse them again.
        check("retryAfterUs is one token's refill, rounded up: 333334us",
              d.retryAfterUs() == 333_334L);

        long wait = d.retryAfterUs();
        clock.set(T0 + wait - 1);
        Decision early = l.check(ACCOUNT);
        check("a caller that waits retryAfterUs minus one microsecond is still refused",
              !early.allowed());
        check("...and is told the remaining 1us", early.retryAfterUs() == 1L);

        clock.advance(1);
        check("a caller that waits exactly retryAfterUs is allowed", l.check(ACCOUNT).allowed());
        check("none of the refusals spent an issuance", l.issued() == 4L);
    }

    /** When a request breaks both limits the earlier rule in the published
     *  order wins: ... dangerous -> rate_limited -> budget_exhausted. */
    static void rateIsAnsweredBeforeBudget() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 1, 1);

        check("the single permitted request is allowed", l.check(ACCOUNT).allowed());

        Decision both = l.check(ACCOUNT);
        check("a request that breaks BOTH limits is refused", !both.allowed());
        check("...as rate_limited, the earlier rule in the published order",
              "rate_limited".equals(both.errorClass()));

        clock.set(T0 + 1_000_000L);
        Decision after = l.check(ACCOUNT);
        check("once the window rolls the same request is budget_exhausted",
              !after.allowed() && "budget_exhausted".equals(after.errorClass()));
        check("and budget_exhausted carries no retry, because the answer will not change",
              after.retryAfterUs() == 0L);
    }

    /** A budget is per RUN. Nothing -- not the clock, not a later configure --
     *  gives a spent run more requests. */
    static void theBudgetIsMonotonicAndTimeDoesNotRefillIt() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 100, 3);

        boolean three = true;
        for (int i = 1; i <= 3; i++) three &= l.check(ACCOUNT).allowed();
        check("a budget of 3 issues 3", three);

        Decision spent = l.check(ACCOUNT);
        check("the 4th is refused", !spent.allowed());
        check("...as budget_exhausted", "budget_exhausted".equals(spent.errorClass()));
        check("...with a detail that names the budget",
              String.valueOf(spent.detail()).contains("3 of 3"));

        clock.advance(3_600_000_000L);   // one hour
        Decision anHourLater = l.check(ACCOUNT);
        check("an hour later, with every rate window long gone, it is still refused",
              !anHourLater.allowed() && "budget_exhausted".equals(anHourLater.errorClass()));

        boolean allRefused = true;
        for (int i = 0; i < 100; i++) allRefused &= !l.check(ACCOUNT).allowed();
        check("a hundred further calls are all refused", allRefused);
        check("and issued() is pinned at the budget, not counting the refusals",
              l.issued() == 3L);
    }

    /**
     * The other half of "monotonic". A `configure` frame re-authorises SCOPE,
     * not ISSUANCE -- BridgeClient already refuses to lift a halt on configure
     * for the same reason -- so a scope push must not hand the run a fresh
     * budget. The way that would happen is a later edit adding a setter, a
     * reset, or a reconfigure to this class, so the public surface is pinned
     * here. The other way it could happen is the wiring building a NEW Limiter
     * when a configure lands; that lives in HxExtension and is pinned there.
     */
    static void nothingOnThisClassCanRefillASpentBudget() {
        Set<String> want = Set.of("check", "issued");
        Set<String> found = new TreeSet<>();
        for (Method m : Limiter.class.getDeclaredMethods())
            if (Modifier.isPublic(m.getModifiers()) && !m.isSynthetic()) found.add(m.getName());
        check("Limiter's public surface is exactly check() and issued(), so no caller can "
              + "reset, raise or re-push a spent budget (found " + found + ")",
              found.equals(want));

        boolean noPublicState = true;
        for (Field f : Limiter.class.getDeclaredFields())
            if (Modifier.isPublic(f.getModifiers())) noPublicState = false;
        check("...and no public field to reach round the methods", noPublicState);

        Constructor<?>[] ctors = Limiter.class.getDeclaredConstructors();
        // TWO, since 2026-09-04, and the property this guards is unchanged:
        // limits are set ONCE, at construction, with no setter to move them
        // afterwards. The second is the three-argument overload that
        // delegates to the four-argument one with `burst = ratePerSecond`;
        // it configures nothing the other cannot. What would break the
        // property is a constructor that did NOT delegate, or any setter --
        // and the method allowlist a few lines above is what catches those.
        check("...and no more than two constructors, both setting the limits "
              + "once at construction, neither able to move them after",
              ctors.length == 2
              && java.util.Arrays.stream(ctors)
                     .map(java.lang.reflect.Constructor::getParameterCount)
                     .sorted().toList().equals(java.util.List.of(3, 4)));
    }

    /** A budget of zero means zero. The dangerous reading is "unset, so
     *  unlimited", which is how a dry run becomes a live one. */
    static void aZeroBudgetIssuesNothing() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 5, 0);

        Decision d = l.check(ACCOUNT);
        check("a budget of 0 refuses the very first request", !d.allowed());
        check("...as budget_exhausted", "budget_exhausted".equals(d.errorClass()));
        check("...and nothing was issued", l.issued() == 0L);
    }

    static void theConstructorRefusesLimitsItCannotEnforce() {
        TickClock clock = new TickClock(T0);

        // Not clamped to 1: clamping widens the limit the operator wrote, and
        // a safety limit may not move that way on its own. A throw here
        // surfaces as bad_config, which is DENY-ALL.
        expectThrows("a rate of 0 is refused, not clamped up to 1",
                     IllegalArgumentException.class, () -> new Limiter(clock, 0, 100));
        expectThrows("a negative rate is refused",
                     IllegalArgumentException.class, () -> new Limiter(clock, -1, 100));
        expectThrows("a negative budget is refused",
                     IllegalArgumentException.class, () -> new Limiter(clock, 5, -1));
        expectThrows("a limiter with no clock is refused",
                     IllegalArgumentException.class, () -> new Limiter(null, 5, 100));
        // The sliding log is one long per permitted request per second, so the
        // rate is also an allocation. 10000 is the ceiling and is allowed;
        // above it is a config typo, refused before it allocates.
        expectThrows("a rate above the 10000 ceiling is refused before allocating",
                     IllegalArgumentException.class, () -> new Limiter(clock, 10_001, 100));
        Limiter atCeiling = new Limiter(clock, 10_000, 1);
        check("a rate of exactly 10000 is accepted, so the ceiling is inclusive",
              atCeiling.check(ACCOUNT).allowed());
    }

    /** Whole-run, not per-host: 2/s against two hosts is 4/s into one estate. */
    static void theLimitIsWholeRunNotPerHost() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 2, 1000);

        check("one to app.example.test", l.check(ACCOUNT).allowed());
        check("one to api.example.test", l.check(API_ORDERS).allowed());
        Decision third = l.check(API_ORDERS);
        check("a third to a different host is still refused: the limit is whole-run",
              !third.allowed() && "rate_limited".equals(third.errorClass()));
    }

    /**
     * The Clock is injected, and the real one will be a wall clock that NTP
     * can step backwards. The window arithmetic must not open when that
     * happens: a backwards `now` makes past issuances look more recent, which
     * can only refuse more and never less.
     */
    static void aBackwardsClockCanOnlyOverRestrict() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 2, 1000);

        check("two issuances at T0", l.check(ACCOUNT).allowed() && l.check(ACCOUNT).allowed());

        clock.set(T0 - 5_000_000L);          // the clock steps five seconds back
        Decision d = l.check(ACCOUNT);
        check("a backwards clock step does not open the gate", !d.allowed());
        // The number is 500000 -- one token at 2/s -- and NOT the six seconds
        // the sliding log reported, which was an artifact of measuring from
        // the oldest issuance. The property under test is unchanged and is
        // the line above: a clock that went backwards must not open the gate.
        // A bucket satisfies it by refusing to refill on negative elapsed,
        // which can only ever leave FEWER tokens.
        check("...and the wait is one token's refill, never a negative or a "
              + "shrunk one", d.retryAfterUs() == 500_000L);
    }

    /**
     * `oldest + WINDOW_US` compared against `now` overflows when `oldest` is
     * within WINDOW_US of Long.MAX_VALUE: the sum wraps to a large negative
     * number, `now < leavesWindowAt` reads that as already outside the
     * window, and a request that should still be refused is ALLOWED instead.
     *
     * Unreachable from a wall-clock Clock -- epoch microseconds are
     * ~1.79e15, nine orders of magnitude short of the ~9.22e18 needed to
     * overflow a long -- but nothing in the Clock interface or the
     * constructor forbids an injected clock from reaching it, so it is
     * pinned directly rather than argued away.
     */
    static void theWindowArithmeticDoesNotOverflowNearLongMaxValue() {
        TickClock atMax = new TickClock(Long.MAX_VALUE);
        Limiter l = new Limiter(atMax, 2, 1000);

        check("issuance 1 of 2, at Long.MAX_VALUE", l.check(ACCOUNT).allowed());
        check("issuance 2 of 2, at the same instant", l.check(ACCOUNT).allowed());

        Decision third = l.check(ACCOUNT);
        check("a 3rd at the same instant is refused, not let through by an "
              + "overflowed comparison", !third.allowed());
        check("...as rate_limited", "rate_limited".equals(third.errorClass()));
        check("...owing one token's refill, 500000us, not a negative or garbage wait",
              third.retryAfterUs() == 500_000L);

        TickClock near = new TickClock(Long.MAX_VALUE - 500_000L);
        Limiter l2 = new Limiter(near, 2, 1000);
        check("issuance 1 of 2, 500000us before Long.MAX_VALUE",
              l2.check(ACCOUNT).allowed());
        check("issuance 2 of 2, at the same instant", l2.check(ACCOUNT).allowed());

        near.advance(100);
        Decision late = l2.check(ACCOUNT);
        check("100us later -- still inside the window, and now past "
              + "Long.MAX_VALUE -- is still refused", !late.allowed());
        // 100us of refill at 2/s earns 200 micro-tokens, leaving 999800 of
        // the 1000000 a request costs. That shortfall is MICRO-TOKENS; the
        // wait is what they take to earn, 999800/2 = 499900us. The two units
        // are easy to conflate and this comment is here because they were.
        // The subtraction that produced it ran ACROSS Long.MAX_VALUE without
        // wrapping into an allow, which is what this method exists to pin.
        check("...owing exactly the remaining 499900us",
              late.retryAfterUs() == 499_900L);
    }

    /**
     * A narrowing mutation -- `long elapsed = now - oldest;` rewritten as
     * `long elapsed = (int) (now - oldest);` -- passes every check above
     * unnoticed: they either stay inside the one-second window (elapsed a few
     * hundred thousand microseconds, comfortably inside int) or jump straight
     * to Long.MAX_VALUE-scale gaps (elapsed wraps whether it is a long or an
     * int, so the outcome looks the same either way). Nothing above exercises
     * the realistic middle: a slow-paced, budget-conserving engagement sitting
     * at the rate limit with sparse traffic, where the gap between requests is
     * minutes to hours. `int` overflows at 2^31 microseconds, ~35.79 minutes,
     * so a 40-minute idle gap -- entirely ordinary for this tool, not a
     * contrived edge case -- lands past it: `(int) 2_400_000_000L` wraps
     * negative, which reads as "still inside the one-second window" and
     * wrongly REFUSES a request the real long arithmetic must ALLOW.
     */
    static void aRealisticIdleGapPastTheIntRangeIsNotMisreadAsStillInsideTheWindow() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 1, 1000);

        check("the sole issuance, at T0", l.check(ACCOUNT).allowed());

        // 40 minutes: past the ~35.79-minute point where now - oldest exceeds
        // Integer.MAX_VALUE microseconds, and an entirely ordinary gap for an
        // engagement idling at the rate limit rather than a machine spamming it.
        clock.advance(2_400_000_000L);
        Decision d = l.check(ACCOUNT);
        check("40 minutes later the sole issuance is long outside the "
              + "one-second window, so the request is allowed -- not "
              + "misread as still inside it by an elapsed value narrowed to int",
              d.allowed());
        check("...and it was actually issued", l.issued() == 2L);
    }

    /**
     * Deterministic despite being concurrent: the clock does not move, so the
     * window never rolls and the answer is exactly `rate`, whatever order the
     * threads run in. An unsynchronised check() reads `issued`, decides, and
     * writes it back, so two threads inside that gap both find room -- and the
     * excess is requests that reached a client's estate.
     */
    static void concurrentCallersCannotExceedEitherLimit() throws Exception {
        check("8 threads x 200 calls against a rate of 5 issue exactly 5",
              5 == raceAgainst(new Limiter(new TickClock(T0), 5, 1000)));
        // A rate of 10000 cannot bind on 1600 calls, so this one is the budget
        // alone, with the same eight threads racing on it.
        check("8 threads x 200 calls against a budget of 3 issue exactly 3",
              3 == raceAgainst(new Limiter(new TickClock(T0), 10_000, 3)));
    }

    /**
     * How long 1600 non-blocking calls get before the race is called HUNG.
     *
     * `check` takes a monitor and does arithmetic; 1600 of them across eight
     * threads is a fraction of the well-under-a-second this whole class takes
     * to run. Ten seconds cannot fire on anything but a genuine park -- and a
     * genuine park is the whole reason it exists.
     *
     * WHAT IT CATCHES, measured on this file one mutation at a time against a
     * clean 11 summary lines / 0 FAIL / rc=0: a `check` that PARKS a caller it
     * made wait for its own monitor -- a rate limiter that THROTTLES the
     * caller rather than REFUSING it, the same §4 violation the capture layer
     * above exists to forbid, one layer down -- parked all eight workers, and
     * this bound turned that into a named FAIL against this class's own
     * counter: "a concurrent caller of Limiter.check had not finished after
     * 10000 ms, so it HUNG". Whether that mutation trips HERE or in
     * checkIsExclusiveWithItselfDeterministically below depends on its own
     * timing -- both were seen -- and the point is that both waits are bounded,
     * not which one goes first. Deleting this method's own `go.countDown()` is
     * caught too, by the matching bound on `go.await`: 11 summary lines,
     * 2 FAIL, rc=1. Both were 10 lines / 0 FAIL / rc=1 before the bounds.
     *
     * WHAT IT DOES NOT CATCH, and this docstring asserted the opposite until
     * it was measured: a `check` that SLEEPS instead of returning
     * `rateLimited` never reaches this method at all. It parks in
     * `theWindowIsExactAtItsBoundaries`, the FIRST of this class's fourteen
     * methods and eleven before `raceAgainst`, in a direct call with no helper
     * thread to join -- 10 summary lines, 10 ALL PASS, 0 FAIL, rc=1, and no
     * worker is ever constructed. Unchanged by every bound in this file. The
     * EXIT CODE is the only thing that sees it, with `TestSupport`'s shutdown
     * hook to name the method. See {@link hx.TestSupport#t}.
     */
    static final long RACE_DEADLINE_MS = 10_000L;

    static int raceAgainst(Limiter l) throws Exception {
        int threads = 8, callsEach = 200;
        AtomicInteger allowed = new AtomicInteger();
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            Thread w = new Thread(() -> {
                try {
                    // Bounded, and the workers are DAEMONS. A non-daemon
                    // worker that never releases holds the JVM up AFTER
                    // main() has printed ALL PASS: eleven green summary lines
                    // and a suite that still blocks to the backstop.
                    if (!go.await(RACE_DEADLINE_MS, TimeUnit.MILLISECONDS)) return;
                } catch (InterruptedException e) { return; }
                for (int i = 0; i < callsEach; i++)
                    if (l.check(ACCOUNT).allowed()) allowed.incrementAndGet();
            });
            w.setDaemon(true);
            workers.add(w);
            w.start();
        }
        go.countDown();
        for (Thread w : workers)
            TestSupport.join(w, RACE_DEADLINE_MS,
                             "a concurrent caller of Limiter.check");
        // issued() is the limiter's own count; allowed is the callers'. They
        // must agree, or one of the two is not counting what it claims to.
        if (l.issued() != allowed.get())
            check("issued() disagrees with the callers: " + l.issued() + " vs " + allowed.get(), false);
        return allowed.get();
    }

    /** How long the helper below gets to finish one non-blocking `check` once
     *  the monitor is free. Half of RACE_DEADLINE_MS against a thousandth of
     *  the work, and a HANG bound rather than a timing assertion.
     *
     *  Declared ABOVE the next method's docstring rather than between it and
     *  the method. Two javadoc comments in a row and javac attaches only the
     *  second: the first documents nothing, which is how this file's sibling
     *  in hx.TestSupport silently lost the paragraph explaining hangs. */
    static final long HELPER_RELEASE_MS = 5_000L;

    /**
     * The mutual-exclusion guard on check(), deterministically -- the guard
     * that concurrentCallersCannotExceedEitherLimit() above only catches
     * probabilistically. Measured on the reviewer's machine: removing
     * `synchronized` red 3/20 unrestricted, 3/20 under `taskset -c 0-3`, and
     * 0/40 pinned to one or two vCPUs -- indistinguishable from a correct
     * Limiter on exactly the core counts most CI runners and dev containers
     * give you. A guard must not depend on scheduling.
     *
     * check() synchronizes on `this`, so the test can take that same monitor
     * from the main thread first, start a helper that calls check(), and
     * require the helper to park on the IDENTICAL monitor before the main
     * thread lets go of it. Monitor reentrancy is what makes the outcome
     * deterministic rather than merely probable: while this thread holds the
     * monitor the helper cannot enter check() at all, so it is either
     * observed BLOCKED on `limiter` or the guard is gone.
     *
     * Identity, not just Thread.State.BLOCKED, is what waitUntilBlockedOn
     * checks: a thread parked on some unrelated lock -- a class-init monitor,
     * say -- is also BLOCKED, and accepting that would pass a Limiter with no
     * lock on check() at all, for the wrong reason.
     *
     * THE JOIN BELOW IS BOUNDED AND THROWS, and that is load-bearing rather
     * than tidy. `limiter.issued()` after it is a `synchronized` accessor, so
     * a helper still parked INSIDE check() is still holding the monitor that
     * call needs -- and entering a monitor cannot be bounded, interrupted or
     * timed out from here. Measured with the exact mutation this method exists
     * to catch, a `check` that parks a caller it made wait for the monitor:
     * on a plain `helper.join(5000)` this method printed its FAIL and then
     * parked on `issued()` forever, taking LimiterTest from ELEVEN summary
     * lines to TEN with rc=1 as the only signal -- the very truncation the
     * bounds in this file were added to remove, wearing a second shape and
     * missed by the sweep that added them. `TestSupport.join` throwing means
     * `issued()` is never reached: the only bound available for a monitor is
     * not making the call.
     */
    static void checkIsExclusiveWithItselfDeterministically() throws Exception {
        TickClock clock = new TickClock(T0);
        Limiter limiter = new Limiter(clock, 5, 1000);

        Thread helper;
        synchronized (limiter) {
            helper = new Thread(() -> limiter.check(ACCOUNT));
            helper.setDaemon(true);
            helper.start();
            check("a concurrent check() is parked on Limiter's own monitor",
                  waitUntilBlockedOn(helper, limiter));
        }
        TestSupport.join(helper, HELPER_RELEASE_MS,
                         "the concurrent check(), after limiter's monitor was released");
        check("...and proceeds once the monitor is released", !helper.isAlive());
        check("...and its issuance was actually counted", limiter.issued() == 1L);
    }

    /**
     * The identity comparison inside `TestSupport.waitUntilBlockedOn` is what
     * makes checkIsExclusiveWithItselfDeterministically() above trustworthy.
     * Strip it back to bare `Thread.State.BLOCKED` and a helper parked on ANY
     * monitor -- a class-init lock, or here, an object with nothing to do
     * with `limiter` -- would satisfy a wait for `limiter`'s monitor, for the
     * wrong reason. Pinned directly: a helper that is genuinely and
     * deterministically BLOCKED, just on the wrong lock, must not satisfy
     * waitUntilBlockedOn for a different one.
     */
    static void waitUntilBlockedOnRequiresTheSameMonitorNotJustBlockedState() throws Exception {
        TickClock clock = new TickClock(T0);
        Limiter limiter = new Limiter(clock, 5, 1000);
        Object unrelated = new Object();

        Thread helper;
        synchronized (unrelated) {
            helper = new Thread(() -> {
                synchronized (unrelated) { }
            });
            helper.setDaemon(true);
            helper.start();
            check("a helper BLOCKED on an unrelated monitor does not satisfy "
                  + "waitUntilBlockedOn for limiter's monitor, which it was "
                  + "never asked to wait on",
                  !waitUntilBlockedOn(helper, limiter));
        }
        helper.join(5000);
        check("...and the helper proceeds once its real monitor is released",
              !helper.isAlive());
    }

    /** A real request against a loopback-only test target. The limiter reads
     *  nothing out of it -- the limit is whole-run -- but a Gate takes one,
     *  and a null here would be testing a shape the send path never produces. */
    static HxRequest get(String host, String path) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Host", List.of(host));
        headers.put("User-Agent", List.of("hx/0.1"));
        headers.put("Accept", List.of("*/*"));
        return new HxRequest("GET", "https://" + host + path, host, path, "",
                             Collections.unmodifiableMap(headers), new byte[0]);
    }
}
