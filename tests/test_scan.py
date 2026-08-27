"""The runner, and the four things only it may say.

Every test here drives the real `scan.run` against an in-memory engagement
with hand-inserted surfaces and exchanges. No Burp: this plan's corpus is
passive, and the whole point of Task 4 is that it needs none.
"""
import sqlite3

import pytest

from hx import scan
from hx.checks import base


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
                title="t", severity="Low", confidence="Firm",
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
                return base.Verdict.clean()
            return base.Verdict.finding(base.Candidate(
                title="t", severity="Low", confidence="Firm",
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
                title="t", severity="Low", confidence="Firm",
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
                title="t", severity="Low", confidence="Firm",
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
                title="t", severity="Low", confidence="Firm",
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
