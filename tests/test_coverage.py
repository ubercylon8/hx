"""The two extractions Task 1 makes, and the behaviour they must not move."""
from __future__ import annotations

from hx import config as config_mod
from hx import coverage as coverage_mod
from hx import run as run_mod
from hx.store import db as db_mod


def test_a_completed_run_is_never_stale():
    """Staleness is a property of `running` runs only. A completed run's
    heartbeat stopped because the run ended, which is not a dead harness."""
    assert run_mod.is_stale("completed", 0, 0, before_us=10_000) is False


def test_a_running_run_with_a_fresh_heartbeat_is_not_stale():
    assert run_mod.is_stale("running", 20_000, 0, before_us=10_000) is False


def test_a_running_run_with_an_old_heartbeat_is_stale():
    assert run_mod.is_stale("running", 5_000, 0, before_us=10_000) is True


def test_a_run_that_never_heartbeated_falls_back_to_started_us():
    """The case `reap_stale`'s COALESCE exists for: `heartbeat_us` is
    NULLable, and a run that died BEFORE its first heartbeat is precisely
    what the mechanism is for. In SQL `NULL < x` is NULL and WHERE treats
    that as false, so such a run would never be reaped."""
    assert run_mod.is_stale("running", None, 5_000, before_us=10_000) is True
    assert run_mod.is_stale("running", None, 20_000, before_us=10_000) is False


def test_the_window_is_twice_the_idle_close():
    """Deliberately WIDER than IDLE_CLOSE_US: an idle run is one nobody used,
    a stale one is a run whose process is gone. Reaping at the idle boundary
    would file every ordinary pause as a crash."""
    assert run_mod.stale_before_us(now_us=1_000_000_000) == (
        1_000_000_000 - run_mod.IDLE_CLOSE_US * 2)
    assert run_mod.stale_before_us(now_us=500, stale_after_us=100) == 400


def _store(tmp_path):
    conn = db_mod.connect(tmp_path / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES('e1','t','T',0,'active')")
    return conn


def _surface(conn, sid, method, template):
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES(?,?,?,'https','app.test',443,?,'proxy',2)",
        (sid, "e1", method, template))


def _run(conn, rid, status="completed"):
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total) VALUES(?,?,'scan','staging',"
        "0,?,0,0)", (rid, "e1", status))


def _check_run(conn, cid, rid, sid, check_id, verdict, reason=None):
    conn.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id, check_version,"
        " verdict, reason) VALUES(?,?,?,?,'1',?,?)",
        (cid, rid, sid, check_id, verdict, reason))


def test_an_empty_engagement_has_no_coverage_and_says_so(tmp_path):
    conn = _store(tmp_path)
    cov = coverage_mod.facts(conn, "e1")
    assert cov.captured == 0
    assert cov.scanned is False
    assert cov.untested == ()
    assert cov.by_check == ()


def test_a_surface_with_only_a_skipped_row_counts_as_untested(tmp_path):
    """The separating case. A `pending` row means the runner opened it and
    the process died; a `skipped` row means the budget cut the scan off
    before it. Reading either as coverage is S12's failure in the direction
    that matters -- a row that exists to record a GAP read as an answer."""
    conn = _store(tmp_path)
    _surface(conn, "s1", "GET", "/a")
    _surface(conn, "s2", "GET", "/b")
    _run(conn, "r1")
    _check_run(conn, "c1", "r1", "s1", "missing-hsts", "clean")
    _check_run(conn, "c2", "r1", "s2", "missing-hsts", "skipped")

    cov = coverage_mod.facts(conn, "e1")
    assert cov.captured == 2
    assert cov.scanned is True
    assert [tuple(r) for r in cov.untested] == [("GET", "/b")]


def test_a_surface_retested_across_runs_is_counted_once(tmp_path):
    """F5 of the report's own review: `COUNT(DISTINCT surface_id)`, not
    `COUNT(*)`. A `check_run` row exists per (surface, check) PER RUN, so
    counting rows makes three surfaces scanned twice render as 6. The error
    is always upward, the one direction a coverage figure must not lie in."""
    conn = _store(tmp_path)
    _surface(conn, "s1", "GET", "/a")
    _run(conn, "r1")
    _run(conn, "r2")
    _check_run(conn, "c1", "r1", "s1", "missing-hsts", "clean")
    _check_run(conn, "c2", "r2", "s1", "missing-hsts", "clean")

    cov = coverage_mod.facts(conn, "e1")
    assert [tuple(r) for r in cov.by_check] == [("missing-hsts", "clean", 1)]


def test_reasons_are_grouped_commonest_first(tmp_path):
    conn = _store(tmp_path)
    for n in ("s1", "s2", "s3"):
        _surface(conn, n, "GET", f"/{n}")
    _run(conn, "r1")
    _check_run(conn, "c1", "r1", "s1", "cors", "inconclusive", "no origin")
    _check_run(conn, "c2", "r1", "s2", "cors", "inconclusive", "no origin")
    _check_run(conn, "c3", "r1", "s3", "cors", "inconclusive", "budget")

    cov = coverage_mod.facts(conn, "e1")
    assert cov.reasons[("cors", "inconclusive")] == ["no origin", "budget"]


def test_a_running_run_counts_as_unfinished(tmp_path):
    """`status <> 'completed'`, so all four of running | aborted | killed |
    error are caught and a value added to the CHECK later cannot slip
    through as finished. `running` is deliberate: S5 says a run left running
    is a dead harness, and one genuinely in flight has produced partial
    coverage too."""
    conn = _store(tmp_path)
    _run(conn, "r1", status="running")
    _run(conn, "r2", status="completed")

    cov = coverage_mod.facts(conn, "e1")
    assert [r[0] for r in cov.unfinished] == ["r1"]


def test_an_enabled_class_the_build_ships_nothing_for_is_named():
    """F11 of the report's review. A check class the operator enabled and
    this build has no checks in it leaves no `check_run` row, so it leaves no
    trace in the table -- and silence there reads as coverage."""
    cfg = config_mod.Config(name="t", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    cfg.checks["nonexistent_class"] = True
    assert "nonexistent_class" in coverage_mod.unshipped_classes(cfg)
