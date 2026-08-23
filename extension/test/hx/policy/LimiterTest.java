// extension/test/hx/policy/LimiterTest.java
package hx.policy;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class LimiterTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
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
        theWindowIsExactAtItsBoundaries();
        retryAfterUsIsExactlyLongEnoughAndNotAMicrosecondMore();
        rateIsAnsweredBeforeBudget();
        theBudgetIsMonotonicAndTimeDoesNotRefillIt();
        nothingOnThisClassCanRefillASpentBudget();
        aZeroBudgetIssuesNothing();
        theConstructorRefusesLimitsItCannotEnforce();
        theLimitIsWholeRunNotPerHost();
        aBackwardsClockCanOnlyOverRestrict();
        concurrentCallersCannotExceedEitherLimit();

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    /**
     * The three boundaries that matter, hit exactly: the request at the limit,
     * the microsecond before the window rolls, and the microsecond it rolls.
     */
    static void theWindowIsExactAtItsBoundaries() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 5, 1000);

        for (int i = 1; i <= 5; i++)
            check("rate 5/s: request " + i + " of 5 in the same microsecond is allowed",
                  l.check(ACCOUNT).allowed());

        Decision sixth = l.check(ACCOUNT);
        check("the 6th request in the same microsecond is refused", !sixth.allowed());
        check("...as rate_limited", "rate_limited".equals(sixth.errorClass()));
        check("...retrying after the whole second, 1000000us", sixth.retryAfterUs() == 1_000_000L);
        // String.valueOf, not sixth.detail(): a broken limiter returns an
        // ALLOW here, whose detail is null, and an NPE would abort the run --
        // hiding the verdict of every check after this line, which is most of
        // them.
        check("...with a detail that names the limit",
              String.valueOf(sixth.detail()).contains("5/s"));

        clock.set(T0 + 999_999L);
        Decision oneEarly = l.check(ACCOUNT);
        check("one microsecond before the window rolls it is still refused", !oneEarly.allowed());
        check("...and the wait has shrunk to exactly 1us", oneEarly.retryAfterUs() == 1L);

        clock.set(T0 + 1_000_000L);
        check("at exactly one second the oldest issuance has left the window",
              l.check(ACCOUNT).allowed());
        // All five original issuances shared T0, so the window empties in one
        // step rather than freeing a slot at a time.
        boolean fourMore = true;
        for (int i = 2; i <= 5; i++) fourMore &= l.check(ACCOUNT).allowed();
        check("...and so do the other four, all issued at the same instant", fourMore);

        Decision full = l.check(ACCOUNT);
        check("the 6th of the rolled window is refused again", !full.allowed());
        check("...for a full second measured from the new window's oldest issuance",
              full.retryAfterUs() == 1_000_000L);
        check("issued() counted the 10 issuances and none of the 3 refusals",
              l.issued() == 10L);
    }

    /**
     * retryAfterUs is a promise to the agent: wait this long and the gate will
     * let you in. Arithmetic, not a guess -- so the wait is asserted from the
     * value the Decision carried, AND against the number that value must be.
     */
    static void retryAfterUsIsExactlyLongEnoughAndNotAMicrosecondMore() {
        TickClock clock = new TickClock(T0);
        Limiter l = new Limiter(clock, 3, 1000);

        check("issuance 1 of 3, at T0", l.check(ACCOUNT).allowed());
        clock.set(T0 + 200_000L);
        check("issuance 2 of 3, 200ms later", l.check(ACCOUNT).allowed());
        clock.set(T0 + 350_000L);
        check("issuance 3 of 3, 350ms in", l.check(ACCOUNT).allowed());

        clock.set(T0 + 400_000L);
        Decision d = l.check(ACCOUNT);
        check("a 4th inside the same second is refused", !d.allowed());
        // The oldest of the last three is issuance 1 at T0. It leaves the
        // window at T0+1000000, which is 600000us after now -- NOT a full
        // second, and not the gap since the most recent issuance either.
        check("retryAfterUs is the wait for the OLDEST issuance to leave: 600000us",
              d.retryAfterUs() == 600_000L);

        long wait = d.retryAfterUs();
        clock.set(T0 + 400_000L + wait - 1);
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
        check("...and exactly one constructor, so the limits are set once, at construction",
              ctors.length == 1 && ctors[0].getParameterCount() == 3);
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
        check("...and the wait grows rather than shrinking: 6000000us",
              d.retryAfterUs() == 6_000_000L);
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

    static int raceAgainst(Limiter l) throws Exception {
        int threads = 8, callsEach = 200;
        AtomicInteger allowed = new AtomicInteger();
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            Thread w = new Thread(() -> {
                try { go.await(); } catch (InterruptedException e) { return; }
                for (int i = 0; i < callsEach; i++)
                    if (l.check(ACCOUNT).allowed()) allowed.incrementAndGet();
            });
            workers.add(w);
            w.start();
        }
        go.countDown();
        for (Thread w : workers) w.join();
        // issued() is the limiter's own count; allowed is the callers'. They
        // must agree, or one of the two is not counting what it claims to.
        if (l.issued() != allowed.get())
            check("issued() disagrees with the callers: " + l.issued() + " vs " + allowed.get(), false);
        return allowed.get();
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
