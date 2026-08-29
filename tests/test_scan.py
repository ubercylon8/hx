"""The runner, and the four things only it may say.

Every test here drives the real `scan.run` against an in-memory engagement
with hand-inserted surfaces and exchanges. No Burp: this plan's corpus is
passive, and the whole point of Task 4 is that it needs none.
"""
import sqlite3

import pytest

from hx import scan
from hx.checks import base
from hx.checks.passive import cookie_flags, security_headers


class Boom:
    id, version, klass = "hx.test.boom", "1", "passive"
    insertion_kinds = frozenset()
    def on_surface(self, ctx, surface, exchanges):
        raise RuntimeError("check exploded")


class Quiet:
    id, version, klass = "hx.test.quiet", "1", "passive"
    insertion_kinds = frozenset()
    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.clean()


class Nothing:
    id, version, klass = "hx.test.nothing", "1", "passive"
    insertion_kinds = frozenset()
    def on_surface(self, ctx, surface, exchanges):
        return None


def test_a_raising_check_yields_error_and_the_scan_continues(scan_env):
    """One bad check must not end a scan an operator has already billed for."""
    summary = scan.run(**scan_env, checks=(Boom(), Quiet()))
    verdicts = dict(scan_env["conn"].execute(
        "SELECT check_id, verdict FROM check_run").fetchall())
    assert verdicts["hx.test.boom"] == "error"
    assert verdicts["hx.test.quiet"] == "clean"
    assert summary.checks_run == 2


def test_the_error_row_carries_the_exception_in_its_reason(scan_env):
    scan.run(**scan_env, checks=(Boom(),))
    reason = scan_env["conn"].execute(
        "SELECT reason FROM check_run").fetchone()[0]
    assert "check exploded" in reason


def test_a_check_returning_nothing_is_an_error_not_clean(scan_env):
    """Silence is not a verdict. Treating None as clean would let a check that
    forgot to return render as `tested, clean`."""
    scan.run(**scan_env, checks=(Nothing(),))
    assert scan_env["conn"].execute(
        "SELECT verdict FROM check_run").fetchone()[0] == "error"


def test_a_row_is_written_pending_before_the_check_runs(scan_env):
    """The crash case. A scan killed mid-check must leave a row saying
    `started, never finished`, not no row at all -- S12's rule applied to the
    failure that leaves no other trace."""
    seen = {}

    class Peek:
        id, version, klass = "hx.test.peek", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            seen["verdict"] = scan_env["conn"].execute(
                "SELECT verdict FROM check_run WHERE check_id='hx.test.peek'"
            ).fetchone()[0]
            return base.Verdict.clean()

    scan.run(**scan_env, checks=(Peek(),))
    assert seen["verdict"] == "pending"


def test_a_finding_verdict_writes_finding_observation_and_evidence(scan_env):
    class Finds:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(Finds(),))
    conn = scan_env["conn"]
    assert conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM finding_observation").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1


def test_a_finding_not_seen_this_run_is_marked_unobserved_if_its_surface_was_tested(scan_env):
    """The retest half."""
    class Finds:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def __init__(self, on): self.on = on
        def on_surface(self, ctx, surface, exchanges):
            if not self.on:
                # Retirement now follows examination: a clean verdict must
                # name the issue type it looked for and did not find, or
                # `_mark_unobserved` has nothing to retire against.
                return base.Verdict.clean(considered=("t-issue",))
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(Finds(True),))
    scan.run(**scan_env, checks=(Finds(False),))
    # `ORDER BY run_id`, as the brief's original draft had it, is a coin
    # flip: `records.new_id` mints `r-<random hex>`, so the string order of
    # two run ids has no relationship to which run happened first.
    # MEASURED: the literal brief query failed this test on ~half of 30
    # consecutive runs. `ts_us` is the column `finding_observation` actually
    # carries for "when was this written", and ordering by it is what makes
    # this assertion about "first run, then second run" rather than about
    # UUID entropy.
    observed = [r[0] for r in scan_env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert observed == [1, 0]


def test_a_finding_whose_surface_was_not_tested_gets_no_observation_row(scan_env):
    """The boundary that makes a retest mean something. If `observed=0` were
    written for a surface nobody looked at, "not observed" would silently mean
    "not looked at" -- S12's own failure wearing a different hat."""
    summary = scan.run(**scan_env, checks=(Quiet(),), surface_filter=lambda s: False)
    assert summary.surfaces == 0
    assert scan_env["conn"].execute(
        "SELECT COUNT(*) FROM finding_observation").fetchone()[0] == 0


def test_mark_unobserved_leaves_a_finding_alone_when_its_surface_goes_untested(scan_env):
    """Row D of Task 6's sweep, MEASURED to redden nothing against the test
    the brief names for it (the one directly above). That test's database
    holds zero findings -- `surface_filter=lambda s: False` empties `tested`,
    but `_mark_unobserved`'s query over an empty `finding` table returns no
    rows whether or not the `surface_id IN (...)` filter is even applied, so
    "mark unobserved for every finding" and "mark unobserved only for tested
    surfaces" are indistinguishable there. A second surface carrying an
    EXISTING finding, retested by a run that deliberately never reaches it,
    is the input that actually separates the two: mutating `_mark_unobserved`
    to drop its `tested` filter reddens THIS test and not the one above."""
    conn = scan_env["conn"]
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-2','e-1','GET','https','app.test',443,'/other','proxy',1)")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url) VALUES('x-2', NULL, 's-2', 'proxy', 'ok', 1, 'GET',"
        " 'https://app.test/other')")

    class FindsOnSecondSurface:
        id, version, klass = "hx.test.finds2", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            if surface[0] != "s-2":
                return base.Verdict.clean()
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(FindsOnSecondSurface(),))
    assert conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1

    # The second run tests ONLY s-1, and deliberately never reaches s-2.
    scan.run(**scan_env, checks=(Quiet(),),
             surface_filter=lambda s: s[0] == "s-1")

    rows = [r[0] for r in conn.execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    # Exactly run 1's original observation. No observed=0 row was added for
    # s-2's finding by a run that never tested s-2.
    assert rows == [1]


def test_a_disabled_class_produces_no_rows_at_all(scan_env_disabled):
    """A class switched off in the engagement config did not run, and the
    coverage section must not imply it did."""
    summary = scan.run(**scan_env_disabled, checks=(Quiet(),))
    assert summary.checks_run == 0


def test_budget_exhaustion_writes_skipped_rows_for_the_remaining_surfaces(
    scan_env, monkeypatch,
):
    """Row F of Task 6's sweep, MEASURED to redden nothing: none of the
    brief's original eight tests ever passed `max_seconds`, so `_skip_rest`
    writing zero rows -- summary.skipped uncounted, summary.by_reason empty,
    no `check_run` row at all for a surface the budget never reached -- left
    every one of them green. That is exactly what S12 forbids one layer
    further down: a surface silently absent from the coverage section reads
    as untested in a way indistinguishable from one nobody thought to visit,
    and a budget cut is a different fact than that.

    `time.monotonic` is monkeypatched to a fixed sequence rather than a real
    sleep, so the deadline crossing is deterministic: one call to compute the
    deadline, then one call per surface in scan order (s-1 first, s-2 second
    -- `ORDER BY host, path_template, method` sorts '/' before '/other').
    """
    conn = scan_env["conn"]
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-2','e-1','GET','https','app.test',443,'/other','proxy',1)")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url) VALUES('x-2', NULL, 's-2', 'proxy', 'ok', 1, 'GET',"
        " 'https://app.test/other')")

    ticks = iter([0.0, 0.5, 2.0])
    monkeypatch.setattr(scan.time, "monotonic", lambda: next(ticks))

    summary = scan.run(**scan_env, checks=(Quiet(),), max_seconds=1)

    assert summary.surfaces == 1
    assert summary.skipped == 1
    assert summary.by_reason == {"budget": 1}
    rows = conn.execute(
        "SELECT surface_id, verdict, reason FROM check_run"
        " WHERE verdict='skipped'").fetchall()
    assert rows == [("s-2", "skipped", "budget")]


def test_a_surface_deleted_between_capture_and_scan_is_refused_by_the_schema(
    scan_env,
):
    """Row G's own first question, MEASURED rather than assumed: under a real
    connection -- `foreign_keys=ON`, what `db_mod.connect` and this fixture
    both use -- `finding.surface_id`, `exchange.surface_id` and
    `check_run.surface_id` are all FK references, so SQLite itself refuses a
    plain `DELETE FROM surface` the instant anything depends on that row. S8's
    "a surface vanished between capture and scan" therefore cannot happen via
    an ordinary delete; it requires deliberately bypassing the constraint
    (`PRAGMA foreign_keys=OFF`, the shape a bulk purge takes) and is the
    scenario the next test drives instead."""
    class Finds:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(Finds(),))
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        scan_env["conn"].execute("DELETE FROM surface WHERE id='s-1'")


def test_a_finding_whose_surface_vanished_is_left_alone_not_fabricated_against(
    scan_env,
):
    """Row G, spec S8: a finding whose surface vanished between capture and
    scan. Produced the only way the schema allows -- `foreign_keys=OFF`
    around the delete, exactly what a purge/retention job does -- leaving
    `finding.surface_id='s-1'` dangling with no surface row behind it.

    MEASURED: `hx.scan._mark_unobserved` never dereferences that dangling id
    at all. `tested` is built purely from the LIVE `SELECT ... FROM surface`
    this run just ran -- a vanished surface simply is not in it -- so the
    `IN (...)` clause is never even given the dangling id to look up, and
    `_exchanges_for` is only ever called with ids this run's own surface
    query just produced. The rerun below therefore raises nothing, fabricates
    no row against 's-1', and leaves the original observation exactly where
    Row D's guard already leaves any finding on an untested surface: alone.
    """
    conn = scan_env["conn"]

    class Finds:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(Finds(),))
    fid = conn.execute("SELECT id FROM finding").fetchone()[0]
    assert conn.execute(
        "SELECT surface_id FROM finding WHERE id=?", (fid,)).fetchone()[0] == "s-1"

    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DELETE FROM surface WHERE id='s-1'")
    conn.execute("PRAGMA foreign_keys=ON")
    assert conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 0

    # Must not raise, despite the finding's own surface_id no longer
    # resolving to any row.
    summary = scan.run(**scan_env, checks=(Finds(),))
    assert summary.surfaces == 0

    rows = [r[0] for r in conn.execute(
        "SELECT observed FROM finding_observation WHERE finding_id=?"
        " ORDER BY ts_us", (fid,))]
    # Exactly the one observation from before the surface vanished. No
    # observed=0 row was fabricated against the dangling id.
    assert rows == [1]


# --- Task 2: retire what was considered and not re-emitted ---
#
# `_mark_unobserved` used to retire a finding only when the whole
# `(surface, check)` answered `clean`. That was sound only while a check
# filed at most one finding per surface; `Candidate.issue_type_id` made
# N-per-surface the norm, and a check finding one of three issues answers
# `finding`, so the clean-only gate never fired for the other two -- they
# rendered live off stale observations. The two tests below pin the
# replacement: retirement follows EXAMINATION (issue type in `considered`),
# not the check's overall verdict.


def test_a_check_retires_the_one_issue_it_no_longer_finds(scan_env):
    """The defect this task exists for.

    A check that finds one of three issues answers `finding`, so the
    clean-only gate never fired and the two fixed issues rendered live off
    their stale run-1 observations, with no "appears fixed" marker.
    """
    def _candidate(ctx, exchanges, issue_type_id):
        return base.Candidate(
            title=f"t-{issue_type_id}", issue_type_id=issue_type_id,
            severity="Low", confidence="Firm", insertion=None,
            exchange_ids=(exchanges[0].id,))

    class Finds:
        id, version, klass = "hx.test.three", "1", "passive"
        insertion_kinds = frozenset()

        def __init__(self):
            self.emit = ("a", "b", "c")

        def on_surface(self, ctx, surface_row, exchanges):
            return base.Verdict.finding(
                *[_candidate(ctx, exchanges, t) for t in self.emit],
                considered=("a", "b", "c"))

    check = Finds()
    scan.run(**scan_env, checks=(check,))
    check.emit = ("a",)                      # b and c are fixed
    scan.run(**scan_env, checks=(check,))

    conn = scan_env["conn"]
    observed = dict(conn.execute(
        "SELECT f.issue_type_id, o.observed FROM finding f"
        " JOIN finding_observation o ON o.finding_id = f.id"
        " WHERE o.run_id = (SELECT id FROM run ORDER BY started_us DESC"
        "                   LIMIT 1)").fetchall())
    assert observed == {"a": 1, "b": 0, "c": 0}


def test_an_issue_type_the_check_never_considered_is_not_retired(scan_env):
    """The separating case. Retirement must follow examination, not absence.

    A check that stops looking at something has not established it is fixed,
    and a report that closed a finding on that basis would be inventing a
    fact the run does not hold.
    """
    def _candidate(ctx, exchanges, issue_type_id):
        return base.Candidate(
            title=f"t-{issue_type_id}", issue_type_id=issue_type_id,
            severity="Low", confidence="Firm", insertion=None,
            exchange_ids=(exchanges[0].id,))

    class Narrows:
        id, version, klass = "hx.test.narrow", "1", "passive"
        insertion_kinds = frozenset()

        def __init__(self):
            self.considered = ("a", "b")

        def on_surface(self, ctx, surface_row, exchanges):
            emit = [t for t in ("a", "b") if t in self.considered]
            return base.Verdict.finding(
                *[_candidate(ctx, exchanges, t) for t in emit],
                considered=self.considered)

    check = Narrows()
    scan.run(**scan_env, checks=(check,))
    check.considered = ("a",)                # b is no longer examined at all
    scan.run(**scan_env, checks=(check,))

    conn = scan_env["conn"]
    rows = conn.execute(
        "SELECT o.observed FROM finding f"
        " JOIN finding_observation o ON o.finding_id = f.id"
        " WHERE f.issue_type_id='b' ORDER BY o.ts_us").fetchall()
    assert [r[0] for r in rows] == [1], (
        "an unexamined issue type was retired: the report would tell a client "
        "an issue is fixed on the strength of the check having stopped looking")


# --- Fix round 1 ---
#
# F1 (HIGH): `_mark_unobserved` must be per-check, not per-surface. Four
# negative cases, each pinning that a finding whose OWN check did not
# cleanly re-run this run gets NO observation row -- not `observed=0`, which
# a report renders as "fixed".


def _run1_finds(scan_env, check_id="hx.test.finds"):
    class Finds:
        id, version, klass = check_id, "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))
    scan.run(**scan_env, checks=(Finds(),))


def test_a_check_that_raises_on_retest_leaves_the_finding_unobserved_not_fixed(
    scan_env,
):
    """F1, negative case 1: the SAME check raises on the retest. The check
    never delivered a clean answer, so nothing licenses `observed=0` --
    that is the exact datum a report renders as "fixed", and a crashed check
    is the one case where saying so is most wrong."""
    _run1_finds(scan_env)

    class Boom2:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            raise RuntimeError("boom")

    scan.run(**scan_env, checks=(Boom2(),))
    rows = [r[0] for r in scan_env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert rows == [1]


def test_a_check_that_goes_inconclusive_on_retest_leaves_the_finding_unobserved(
    scan_env,
):
    """F1, negative case 2: the same check answers `inconclusive`, S10's own
    "a check that cannot run says so" -- which is explicitly not a clean
    re-look and must not license `observed=0` either."""
    _run1_finds(scan_env)

    class Unsure:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.inconclusive("could not tell")

    scan.run(**scan_env, checks=(Unsure(),))
    rows = [r[0] for r in scan_env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert rows == [1]


def test_a_check_absent_from_this_runs_checks_leaves_its_findings_unobserved(
    scan_env,
):
    """F1, negative case 3: this run simply never ran the check that owns
    the finding (a --check filter, a class disabled since the last run). A
    DIFFERENT check going clean on the same surface must not be read as an
    answer about the first check's finding."""
    _run1_finds(scan_env)

    scan.run(**scan_env, checks=(Quiet(),))  # a different check.id entirely
    rows = [r[0] for r in scan_env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert rows == [1]


def test_a_check_skipped_by_budget_leaves_its_prior_findings_unobserved(
    scan_env, monkeypatch,
):
    """F1, negative case 4: the check that owns the finding was skipped by
    the budget this run (`check_run.verdict='skipped'`), never reaching
    `on_surface` at all."""
    _run1_finds(scan_env)

    class FindsAgain:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.clean()

    ticks = iter([0.0, 2.0])
    monkeypatch.setattr(scan.time, "monotonic", lambda: next(ticks))
    summary = scan.run(**scan_env, checks=(FindsAgain(),), max_seconds=1)

    assert summary.surfaces == 0
    assert summary.skipped == 1
    skipped_row = scan_env["conn"].execute(
        "SELECT verdict, reason FROM check_run ORDER BY started_us DESC"
        " LIMIT 1").fetchone()
    assert skipped_row == ("skipped", "budget")
    rows = [r[0] for r in scan_env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert rows == [1]


def test_a_check_that_returns_clean_on_retest_does_mark_the_finding_fixed(
    scan_env,
):
    """The positive half of F1's fix, alongside the four negative cases
    above: the SAME check, SAME surface, clean THIS run is still exactly
    what licenses `observed=0` -- the per-check rule narrows what counts,
    it does not remove the retest mechanism itself.

    Task 2 layers EXAMINATION on top of that: `observed=0` now also needs
    the clean verdict to name the issue type it looked for, via
    `considered`."""
    _run1_finds(scan_env)

    class FindsThenClean:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.clean(considered=("t-issue",))

    scan.run(**scan_env, checks=(FindsThenClean(),))
    rows = [r[0] for r in scan_env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert rows == [1, 0]


# F2 (MEDIUM): the per-check try must cover result handling and the finding
# write, not only the `on_surface` call.


def test_a_check_returning_a_bare_string_does_not_kill_the_scan(scan_env):
    """F2, input 1: a plausible authoring slip -- `return "clean"` instead
    of `base.Verdict.clean()`. Reading `.state` off a `str` used to raise
    `AttributeError` OUTSIDE the old try, ending the whole scan after one
    check with its row stuck `pending`."""
    class ReturnsPlainString:
        id, version, klass = "hx.test.string", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return "clean"

    summary = scan.run(**scan_env, checks=(ReturnsPlainString(), Quiet()))
    verdicts = dict(scan_env["conn"].execute(
        "SELECT check_id, verdict FROM check_run").fetchall())
    assert verdicts["hx.test.string"] == "error"
    assert verdicts["hx.test.quiet"] == "clean"
    assert summary.checks_run == 2


def test_a_candidate_naming_a_purged_exchange_does_not_kill_the_scan(scan_env):
    """F2, input 2: a `Candidate` naming an exchange id that does not
    resolve (a retention purge, a copied id) raises `IntegrityError` deep in
    `_write_finding` -- outside the old try, same failure shape as the
    string case above."""
    class BadCandidate:
        id, version, klass = "hx.test.bad", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=("x-does-not-exist",)))

    summary = scan.run(**scan_env, checks=(BadCandidate(), Quiet()))
    verdicts = dict(scan_env["conn"].execute(
        "SELECT check_id, verdict FROM check_run").fetchall())
    assert verdicts["hx.test.bad"] == "error"
    assert verdicts["hx.test.quiet"] == "clean"
    assert summary.checks_run == 2
    # No finding was left half-written by the failed candidate.
    assert scan_env["conn"].execute(
        "SELECT COUNT(*) FROM finding").fetchone()[0] == 0


# F3 (MEDIUM): a check cannot claim the runner's own vocabulary by handing
# back something that merely LOOKS like a Verdict.


def test_a_non_verdict_return_value_cannot_claim_the_runners_own_words(scan_env):
    """F3: `Verdict.__post_init__` refuses a REAL `Verdict("skipped", ...)`
    at construction (Task 1). This is the boundary that let a check dodge
    that guard entirely by never constructing one. MEASURED against the
    reviewer's own case."""
    from types import SimpleNamespace

    class Faker:
        id, version, klass = "hx.test.faker", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return SimpleNamespace(state="skipped", reason="I decided not to",
                                   candidates=())

    summary = scan.run(**scan_env, checks=(Faker(),))
    row = scan_env["conn"].execute(
        "SELECT verdict, reason FROM check_run").fetchone()
    assert row[0] == "error"
    assert row[1] != "I decided not to"
    assert summary.checks_run == 1


# F4 (MEDIUM): scan.run must heartbeat as it progresses, or a long scan is
# reaped alive by run.reap_stale and its own eventual close silently no-ops.


def test_scan_heartbeats_once_per_surface(scan_env, monkeypatch):
    """F4: without a heartbeat, a scan outliving `run.reap_stale`'s idle
    window is marked `error` while genuinely still running, and the
    completed-close at the end of `scan.run` (`WHERE status='running'`)
    then silently does nothing. Per surface is the granularity `checks_run`
    and `surfaces` already advance in."""
    conn = scan_env["conn"]
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-2','e-1','GET','https','app.test',443,'/other','proxy',1)")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url) VALUES('x-2', NULL, 's-2', 'proxy', 'ok', 1, 'GET',"
        " 'https://app.test/other')")

    calls = []
    real_heartbeat = scan.run_mod.heartbeat

    def spy(conn_, *, run_id, now_us=None):
        calls.append(run_id)
        return real_heartbeat(conn_, run_id=run_id, now_us=now_us)

    monkeypatch.setattr(scan.run_mod, "heartbeat", spy)
    scan.run(**scan_env, checks=(Quiet(),))
    assert len(calls) == 2
    assert len(set(calls)) == 1  # one run_id, heartbeated twice


# F7 (LOW): a budget-truncated scan must not close identically to a complete
# one at the `run` row.


def test_a_budget_truncated_scan_records_a_stop_reason(scan_env, monkeypatch):
    """F7: a truncated scan used to close `('completed', NULL)`, identical
    at the `run` row to a full pass -- the truncation was recoverable from
    `check_run` alone, not from the run row S12 ultimately reports off."""
    conn = scan_env["conn"]
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-2','e-1','GET','https','app.test',443,'/other','proxy',1)")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url) VALUES('x-2', NULL, 's-2', 'proxy', 'ok', 1, 'GET',"
        " 'https://app.test/other')")

    ticks = iter([0.0, 0.5, 2.0])
    monkeypatch.setattr(scan.time, "monotonic", lambda: next(ticks))
    scan.run(**scan_env, checks=(Quiet(),), max_seconds=1)

    row = conn.execute(
        "SELECT status, stop_reason FROM run WHERE kind='scan'").fetchone()
    assert row[0] == "completed"
    assert row[1] is not None
    assert "budget" in row[1]


def test_a_complete_scan_has_no_stop_reason(scan_env):
    """The other half of F7: a scan that was NOT truncated must not gain a
    stop_reason either -- an always-set reason would be just as useless as
    a never-set one, telling a report nothing about which scans to trust."""
    scan.run(**scan_env, checks=(Quiet(),))
    row = scan_env["conn"].execute(
        "SELECT stop_reason FROM run WHERE kind='scan'").fetchone()
    assert row[0] is None


# --- Fix round 2: `finding.check_id` is its own column, distinct from
# `finding.issue_type_id` (spec S10/S12's Burp-vendored-issue-type axis).
# `_mark_unobserved` must read `check_id`, never `issue_type_id`.


def test_mark_unobserved_reads_check_id_not_issue_type_id(scan_env):
    """Separates 'matches finding.check_id against the check-id slot and
    finding.issue_type_id against the issue-type slot' from any swap of the
    two -- they are different axes (schema.sql: `check_id` answers "which of
    hx's checks found this", `issue_type_id` answers "what kind of issue is
    this"), the same Python type, so nothing at the schema level or the type
    checker would catch a swapped read, and Task 2 made `_mark_unobserved`
    compare BOTH columns where it used to compare only `check_id`.

    `check_id='hx.test.finds'` (the check's own dotted id) and
    `issue_type_id='t-issue'` (a short slug) are unrelated strings chosen so
    a swapped read cannot land on the right answer by coincidence -- neither
    is a substring or reformatting of the other. Run 2's verdict names
    `considered=("t-issue",)`: it examined the ISSUE TYPE and did not find
    it. `scan.run` combines that with the check's own id into
    `('s-1', 'hx.test.finds', 't-issue')` -- `check_id` in the middle slot,
    `issue_type_id` last, matching the SELECT's own column order.

    A `_mark_unobserved` that swapped which column fills which slot would
    instead compare `('s-1', 't-issue', 'hx.test.finds')` against that same
    set -- no match, since neither `t-issue` sits in the check-id slot nor
    `hx.test.finds` in the issue-type slot of what `considered` actually
    holds. That swap turns a finding that SHOULD retire into one that stays
    live forever: the wrong outcome in the direction a client would notice
    (a fixed issue kept open), which is why `rows == [1, 0]` below -- the
    correct read -- is the assertion, not `[1]`.
    """
    _run1_finds(scan_env)
    conn = scan_env["conn"]
    assert conn.execute(
        "SELECT check_id, issue_type_id FROM finding").fetchone() == (
        "hx.test.finds", "t-issue")

    class FindsThenClean:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.clean(considered=("t-issue",))

    scan.run(**scan_env, checks=(FindsThenClean(),))
    rows = [r[0] for r in conn.execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert rows == [1, 0], (
        "the finding's check_id and issue_type_id were not matched against "
        "the considered set in the correct positions")


# --- Whole-branch review F1 (HIGH): every candidate one passive check yields
# for one surface used to collapse onto ONE dedupe key, and
# `upsert_finding`'s `DO UPDATE SET severity=excluded.severity` left the LAST
# one standing.


class _Blobs:
    """The minimum `CheckContext.blobs` a real passive check needs."""

    def __init__(self, **blobs):
        self._b = blobs

    def get(self, digest, expected_len=None):
        return self._b[digest]


_THREE_HEADERS_MISSING = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html></html>"
)


def test_several_candidates_from_one_check_on_one_surface_file_several_findings(
    scan_env,
):
    """F1. One document response missing three security headers is THREE
    findings, each keeping its own severity -- not one finding wearing
    whichever severity the last candidate happened to carry.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED against the tree
    before `issue_type_id` joined the dedupe key, on exactly this input:
    `summary.findings` said 3 while `finding` held ONE row --
    `('Missing X-Content-Type-Options', 'Low', 'CWE-16')` on the single key
    `hx.passive.security-headers|https|app.test|443|GET|/|-|-`. Note WHICH
    halves of that row came from which candidate: `upsert_finding`'s
    `DO UPDATE SET` moves `severity` and `confidence` but never `title` or
    `cwe`, so the surviving row paired the FIRST candidate's title and CWE
    with the LAST candidate's severity, and the Medium frame-protection
    issue was gone from the store entirely. The assertion is on the SET of
    (title, severity) pairs rather than a count precisely so a regression
    that restored the count by some other route -- three rows all carrying
    one candidate's severity -- still reddens it.
    """
    conn = scan_env["conn"]
    conn.execute("UPDATE exchange SET resp_blob='d1' WHERE id='x-1'")
    env = dict(scan_env, blobs=_Blobs(d1=_THREE_HEADERS_MISSING))

    summary = scan.run(**env, checks=(security_headers.SecurityHeaders(),))

    assert summary.findings == 3
    assert conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 3, (
        "summary.findings and the store disagreed: the runner counted three "
        "candidates written and the store kept fewer")
    got = set(conn.execute("SELECT title, severity FROM finding").fetchall())
    assert got == {
        ("Missing X-Content-Type-Options", "Low"),
        ("Missing frame protection (X-Frame-Options or CSP frame-ancestors)",
         "Medium"),
        ("Missing Strict-Transport-Security", "Low"),
    }


def test_the_dedupe_key_of_two_issue_types_on_one_surface_differs(scan_env):
    """The mechanism under the test above, asserted directly on the column
    the UNIQUE constraint is built from. Three findings with three equal
    dedupe keys is not a state the schema can even hold, so a count of three
    distinct keys is what separates 'the key discriminates' from 'three rows
    happened to survive'."""
    conn = scan_env["conn"]
    conn.execute("UPDATE exchange SET resp_blob='d1' WHERE id='x-1'")
    env = dict(scan_env, blobs=_Blobs(d1=_THREE_HEADERS_MISSING))

    scan.run(**env, checks=(security_headers.SecurityHeaders(),))

    keys = [r[0] for r in conn.execute("SELECT dedupe_key FROM finding")]
    assert len(set(keys)) == 3, keys
    assert all("missing-hsts" in k or "missing-frame-protection" in k
               or "missing-content-type-options" in k for k in keys), keys


# --- Whole-branch review F3 (MEDIUM): `Candidate.scope_level` was stored and
# then ignored. `path_template` was in the dedupe key unconditionally, so a
# host-scoped finding filed once per surface.


_FLAGLESS_COOKIE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Set-Cookie: session=abc; Path=/\r\n"
    b"\r\n"
)


def _three_surfaces_of_one_host(conn, blob="d1"):
    """s-1 (already there) plus s-2 and s-3, same host, same response."""
    conn.execute("UPDATE exchange SET resp_blob=? WHERE id='x-1'", (blob,))
    for surface_id, exchange_id, path in (
        ("s-2", "x-2", "/orders"), ("s-3", "x-3", "/profile"),
    ):
        conn.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host,"
            " port, path_template, discovered_by, normaliser_version)"
            " VALUES(?,'e-1','GET','https','app.test',443,?,'proxy',1)",
            (surface_id, path))
        conn.execute(
            "INSERT INTO exchange(id, run_id, surface_id, via, outcome,"
            " sent_us, method, url, resp_blob)"
            " VALUES(?, NULL, ?, 'proxy', 'ok', 1, 'GET', ?, ?)",
            (exchange_id, surface_id, f"https://app.test{path}", blob))


def test_one_host_scoped_issue_on_three_surfaces_files_one_finding(scan_env):
    """F3. `cookie_flags`' own docstring: a cookie "is set for a host and
    fixing it fixes every surface under it -- filing one finding per surface
    would hand the client the same remediation forty times".

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED before `scope_level`
    reached the key: THREE finding rows, one per surface, with three keys
    differing only in `path_template` (`/`, `/orders`, `/profile`) --
    identical titles, identical severities, identical remediation.
    """
    conn = scan_env["conn"]
    _three_surfaces_of_one_host(conn)
    env = dict(scan_env, blobs=_Blobs(d1=_FLAGLESS_COOKIE))

    scan.run(**env, checks=(cookie_flags.CookieFlags(),))

    rows = conn.execute("SELECT dedupe_key, scope_level FROM finding").fetchall()
    assert len(rows) == 1, rows
    assert rows[0][1] == "host"
    # The blanked parts are the literal `-` the key already uses for an
    # absent part, not the surface's own values.
    assert "|app.test|443|-|-|" in rows[0][0], rows[0][0]


def test_a_surface_scoped_issue_on_three_surfaces_still_files_three(scan_env):
    """The separating case. Without it, blanking `path_template` for EVERY
    finding would satisfy the test above and collapse the whole corpus onto
    one row per host."""
    conn = scan_env["conn"]
    _three_surfaces_of_one_host(conn)

    class SurfaceScoped:
        id, version, klass = "hx.test.surface-scoped", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.finding(base.Candidate(
                title="t", issue_type_id="t-issue", severity="Low",
                confidence="Firm", insertion=None, scope_level="surface",
                exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(SurfaceScoped(),))
    assert conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 3


def test_a_host_scoped_issue_on_two_hosts_still_files_two(scan_env):
    """The other separating case: `host` scope blanks the PATH, never the
    host. A single finding here would mean one client host's cookie problem
    hid another's."""
    conn = scan_env["conn"]
    conn.execute("UPDATE exchange SET resp_blob='d1' WHERE id='x-1'")
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-2','e-1','GET','https','other.test',443,'/','proxy',1)")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url, resp_blob) VALUES('x-2', NULL, 's-2', 'proxy', 'ok',"
        " 1, 'GET', 'https://other.test/', 'd1')")
    env = dict(scan_env, blobs=_Blobs(d1=_FLAGLESS_COOKIE))

    scan.run(**env, checks=(cookie_flags.CookieFlags(),))

    hosts = sorted(r[0] for r in conn.execute("SELECT host FROM finding"))
    assert hosts == ["app.test", "other.test"], hosts


# --- Fix-round-A re-review D1 (MEDIUM): the SET OF MISSING FLAGS was part of
# `cookie_flags`' `issue_type_id`, and therefore of the dedupe key. A flag set
# is instance state that changes as the client remediates, so identity moved
# under the finding and the old row was stranded.


_COOKIE_MISSING_ONLY_HTTPONLY = (
    b"HTTP/1.1 200 OK\r\n"
    b"Set-Cookie: session=abc; Path=/; SameSite=Lax; Secure\r\n"
    b"\r\n"
)


def test_a_partly_remediated_cookie_stays_one_finding(scan_env):
    """D1. One cookie, two runs, a partial fix in between: ONE finding, and
    it carries an observation from BOTH runs.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED against the tree with
    the flag set in the issue type, on exactly this input: TWO findings,
    keyed `...|cookie-session-missing-httponly-samesite-secure|...` and
    `...|cookie-session-missing-httponly|...`, and `finding_observation`
    held one row for each -- the run-1 row got NOTHING for run 2, because
    the check returned `finding` rather than `clean` and
    `_mark_unobserved` only ever considers a clean verdict. `observed=0` is
    the datum `report._latest_observed` renders as "appears fixed", so a
    stranded row with no run-2 observation at all renders as LIVE: the
    client is told the cookie still lacks SameSite and Secure after setting
    both.

    The `COUNT(o.run_id)` per finding is the assertion that says it: one
    finding, observed twice, is "the store tracked one thing across two
    runs". Two findings observed once each is the stranding.

    NOT asserted, and a residual this round does not own:
    `upsert_finding`'s `DO UPDATE SET` moves `severity` and `confidence`
    but not `title`, `description` or `cwe`, so the surviving row keeps run
    1's prose ("set without HttpOnly, SameSite, Secure") while its severity
    tracks. That is one stale sentence on a live finding, against a whole
    phantom finding before this fix, and closing it means refreshing prose
    on upsert -- a change to every check's rows, not this one's.
    """
    conn = scan_env["conn"]
    conn.execute("UPDATE exchange SET resp_blob='d1' WHERE id='x-1'")
    scan.run(**dict(scan_env, blobs=_Blobs(d1=_FLAGLESS_COOKIE)),
             checks=(cookie_flags.CookieFlags(),))
    first = conn.execute("SELECT id, dedupe_key FROM finding").fetchall()
    assert len(first) == 1, first

    conn.execute("UPDATE exchange SET resp_blob='d2' WHERE id='x-1'")
    scan.run(**dict(scan_env, blobs=_Blobs(d2=_COOKIE_MISSING_ONLY_HTTPONLY)),
             checks=(cookie_flags.CookieFlags(),))

    assert conn.execute(
        "SELECT id, dedupe_key FROM finding").fetchall() == first, (
        "the cookie's identity moved when two of its three flags were set")
    assert conn.execute(
        "SELECT f.id, COUNT(o.run_id) FROM finding f"
        " LEFT JOIN finding_observation o ON o.finding_id = f.id"
        " GROUP BY f.id").fetchall() == [(first[0][0], 2)], (
        "a finding row was left with no observation from the second run, so "
        "`report._latest_observed` still reads the first run's `True` and "
        "renders it live")


def test_two_flag_sets_of_one_cookie_share_one_dedupe_key(scan_env):
    """The mechanism under the test above, asserted on the column the UNIQUE
    constraint is built from: what a cookie is MISSING may not appear in its
    key. Two surfaces of one host, one with `Secure` already set, is the
    same defect without the second run -- one cookie, one remediation, and
    before this fix two host-scoped tickets."""
    conn = scan_env["conn"]
    conn.execute("UPDATE exchange SET resp_blob='d1' WHERE id='x-1'")
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-2','e-1','GET','https','app.test',443,'/login','proxy',1)")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url, resp_blob) VALUES('x-2', NULL, 's-2', 'proxy', 'ok',"
        " 1, 'GET', 'https://app.test/login', 'd2')")
    env = dict(scan_env, blobs=_Blobs(d1=_FLAGLESS_COOKIE,
                                      d2=_COOKIE_MISSING_ONLY_HTTPONLY))

    scan.run(**env, checks=(cookie_flags.CookieFlags(),))

    keys = [r[0] for r in conn.execute("SELECT dedupe_key FROM finding")]
    assert len(keys) == 1, keys
    assert "missing" not in keys[0], keys[0]


# --- Fix-round-A re-review D4 (LOW, and it dropped a finding in silence): the
# cookie-name slug lowercased and collapsed every run of punctuation, so two
# genuinely different cookies could file one finding while `summary.findings`
# counted both.


def _two_cookies(first: bytes, second: bytes) -> bytes:
    return (b"HTTP/1.1 200 OK\r\n"
            b"Set-Cookie: " + first + b"=a; SameSite=Lax; Secure\r\n"
            b"Set-Cookie: " + second + b"=b; SameSite=Lax; Secure\r\n"
            b"\r\n")


@pytest.mark.parametrize("first, second", [
    (b"session_id", b"session.id"),     # two punctuation classes, one slug
    (b"Session", b"session"),           # RFC 6265: cookie names are case-sensitive
])
def test_two_cookies_that_slugged_alike_file_two_findings(scan_env, first, second):
    """D4. Both cookies are on one host and are missing exactly HttpOnly, so
    the ONLY thing that can tell their findings apart is the name inside
    `issue_type_id`.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED against the lossy slug
    on exactly this input: `summary.findings` said 2 and `finding` held ONE
    row, keyed `...|cookie-session-id-missing-httponly|...`. That is F1 of
    the whole-branch review verbatim -- the second candidate's severity on
    the first candidate's title -- on the one check whose `issue_type_id`
    was supposed to make it impossible, and the dropped finding is silent.
    The store count is asserted beside `summary.findings` for that reason:
    the count alone was never the thing that was wrong.
    """
    conn = scan_env["conn"]
    conn.execute("UPDATE exchange SET resp_blob='d1' WHERE id='x-1'")
    env = dict(scan_env, blobs=_Blobs(d1=_two_cookies(first, second)))

    summary = scan.run(**env, checks=(cookie_flags.CookieFlags(),))

    keys = sorted(r[0] for r in conn.execute("SELECT dedupe_key FROM finding"))
    assert len(keys) == 2, keys
    assert summary.findings == 2, (
        "summary.findings and the store disagreed: one of the two cookies "
        "was written over the other")
    assert len(set(keys)) == 2, keys


# --- Whole-branch review F6 (MEDIUM): `_exchanges_for` did not carry the
# exchange's `outcome`, so a check could not tell a response that came back
# whole from one that never did.


def test_an_exchange_that_never_answered_makes_the_scan_say_inconclusive(
    scan_env,
):
    """F6, at the runner. `tests/test_checks_passive.py` pins the RULE; this
    pins that `_exchanges_for`'s SELECT actually hands the check the column
    the rule is built on -- a query that dropped `outcome` would leave every
    passive test above green and every real scan blind.

    MEASURED before the fix, on exactly this database: `check_run` came back
    `('hx.passive.security-headers', 'clean', None)` -- a surface holding one
    unreadable exchange recorded as tested and clean, which is S12's rule
    ("a report that cannot distinguish 'tested, clean' from 'never reached'
    is worse than no report") broken at the level the coverage section reads
    from.
    """
    conn = scan_env["conn"]
    conn.execute("UPDATE exchange SET resp_blob='d1' WHERE id='x-1'")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url) VALUES('x-2', NULL, 's-1', 'proxy',"
        " 'status_unreadable', 1, 'GET', 'https://app.test/')")
    fully_headed = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"X-Frame-Options: DENY\r\n"
        b"Strict-Transport-Security: max-age=1\r\n"
        b"\r\n<html></html>"
    )
    env = dict(scan_env, blobs=_Blobs(d1=fully_headed))

    scan.run(**env, checks=(security_headers.SecurityHeaders(),))

    verdict, reason = conn.execute(
        "SELECT verdict, reason FROM check_run").fetchone()
    assert verdict == "inconclusive", (verdict, reason)
    assert "x-2" in reason and "status_unreadable" in reason, reason
