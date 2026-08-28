"""End to end, against real Burp: everything Tasks 1-8 built, meeting a live
extension for the first time.

Every earlier test in this repository drove `hx.scan` and `hx.report`
against hand-inserted rows. This file is the one place both cross a real
Burp, a real proxy listener and a real target server -- which is exactly the
combination that found, on the previous branch, that `drop()` from one Burp
callback does not do what `drop()` from the other does. Five claims, and
three of them measured something different from what they were briefed to.

CLAIM 1's ROUTE IS NOT `/login`. The brief and its own pre-flight note both
say `/login` "returns a Set-Cookie with no Secure, HttpOnly or SameSite" --
MEASURED, against a real Burp, false: `/login`'s cookie is
`session={value}; Path=/; HttpOnly; SameSite=Lax` (pinned byte for byte by
`tests/test_target_server.py::test_the_login_route_sets_a_cookie_worth_
redacting` and by the redaction assertions in
`tests/integration/test_send_path.py`, so it is not this file's route to
change). `hx.passive.cookie_flags.CookieFlags` demands HttpOnly and SameSite
unconditionally and demands Secure only over https:// -- and this target has
no TLS -- so scanning `/login` answers `clean`, not `finding`. Verified with
a four-line script against the check's own logic before touching any test:
`missing == []` for that exact string. `target_server.py` gained a second
route, `/insecure-cookie`, whose cookie carries none of the three flags, so
`hx.passive.cookie-flags` has a real, unambiguous absence to find without
touching `/login`'s frozen string. See `FLAGLESS_COOKIE_VALUE`'s comment
there for the measurement in full.

CLAIM 3 IS CORRECTED, not merely reworded, at
`test_stopping_the_target_does_not_clear_a_finding_...` below -- see that
test's own docstring. The short version: every passive check in this corpus
is a PURE function over a surface's WHOLE captured exchange history
(`hx.checks.passive._http.bodies`/`.responses` return one entry per
readable exchange, unbounded, ordered by `rowid`), so once one exchange has
demonstrated a flaw, no amount of further browsing -- with or without the
target still running -- can make that surface's check answer `clean` again
while the offending exchange is still in the store. `observed` does not fall
to 0 because a target stopped answering; it falls to 0 only when the same
check, given the same (or more) evidence, genuinely finds nothing. This file
measures that against a real Burp rather than asserting the brief's
unmeasured expectation.

`rig.settle`'S CALL SHAPE IS ALSO NOT WHAT THE BRIEF SHOWS. The brief's own
worked example for claim 1 calls `rig.settle("SELECT COUNT(*) FROM
surface", want=1)` -- a `(sql, want=N)` form. `settle` already existed, as a
module-level function in `tests/integration/test_proxy_capture.py`, in a
`(predicate, what, timeout=...)` form, and the pre-flight for this task said
so explicitly and said its failure message -- which names
`srv.exchange_errors` and `exchange_callback_error`, the only things on this
side that separate a broken harness from a silent extension -- is the part
worth preserving. That is the third caller this task's brief itself names,
so it is the shape lifted onto `Rig` (tests/integration/conftest.py), and
every call below uses it. `Rig.browse` similarly does not match the old
module-level `browse(rig, path, *, method="GET", ...)`: it takes
`(method, path, ...)`, matching `Rig.send`'s existing order and the brief's
own claim-1 example (`rig.browse("GET", "/login")`), and every caller in
`test_proxy_capture.py` was rewritten to match when the two were lifted.
"""
from __future__ import annotations

import time

import pytest

from hx import report, scan
from tests.integration.test_proxy_capture import status_of

pytestmark = pytest.mark.integration


def rows(rig, sql: str, args=()) -> list[dict]:
    return [dict(row) for row in rig.eng.db.execute(sql, args).fetchall()]


# ---------------------------------------------------------------------------
# 1. A browsed cookie becomes a finding, with a real evidence chain.
# ---------------------------------------------------------------------------

def test_a_browsed_cookie_becomes_a_finding_with_real_evidence(rig):
    """Claim 1. `/insecure-cookie` sets `session=...` with none of Secure,
    HttpOnly or SameSite -- see this module's docstring for why the route is
    not `/login`, which the brief and its own pre-flight both misdescribe.
    """
    assert rig.configure() == 1
    rig.browse("GET", "/insecure-cookie")

    # The capture frame is UNSOLICITED and arrives AFTER the client's
    # response -- measured on the previous branch. Poll; never read once.
    rig.settle(lambda: rows(rig, "SELECT id FROM surface"), "the surface row")

    summary = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                       blobs=rig.eng.blobs, config=rig.eng.config)
    assert summary.findings >= 1

    row = rig.eng.db.execute(
        "SELECT f.title, f.surface_id, x.url FROM finding f"
        " JOIN evidence e ON e.finding_id = f.id"
        " JOIN exchange x ON x.id = e.exchange_id"
        " WHERE f.engagement_id=?", (rig.eng.id,)).fetchone()
    assert row is not None, "the finding has no evidence chain"
    title, surface_id, url = row
    assert "session" in title
    assert surface_id is not None, "the finding resolves to no surface"
    assert "/insecure-cookie" in url


# ---------------------------------------------------------------------------
# 2. Scan twice, nothing changed: one finding, two observations.
# ---------------------------------------------------------------------------

def test_scanning_twice_with_nothing_changed_retests_the_same_finding(rig):
    """Claim 2: the retest mechanism, against real captured traffic.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? A dedupe key that failed to
    match the second run's candidate to the first's finding would give TWO
    finding rows, not one. A `finding_observation` PK that collided across
    runs (the defect `scan.run`'s own module docstring measures, from
    calling `run.current_run` without closing it) would give ONE observation
    row, not two -- `_write_finding` writing over itself rather than beside
    it. Only the intended behaviour gives 1 finding, 2 observations, both
    `observed=1`.
    """
    assert rig.configure() == 1
    rig.browse("GET", "/insecure-cookie")
    rig.settle(lambda: rows(rig, "SELECT id FROM surface"), "the surface row")

    summary1 = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                        blobs=rig.eng.blobs, config=rig.eng.config)
    assert summary1.findings >= 1

    summary2 = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                        blobs=rig.eng.blobs, config=rig.eng.config)
    # The SAME finding is re-detected, not a new one -- `summary.findings`
    # counts candidates written THIS call, and `_write_finding` upserts
    # rather than inserts.
    assert summary2.findings >= 1

    findings = rows(rig, "SELECT id FROM finding WHERE engagement_id=?",
                    (rig.eng.id,))
    assert len(findings) == 1, \
        f"nothing changed between two scans and got {len(findings)} findings"
    fid = findings[0]["id"]

    obs = rows(rig, "SELECT observed, run_id FROM finding_observation"
              " WHERE finding_id=? ORDER BY ts_us", (fid,))
    assert [o["observed"] for o in obs] == [1, 1], obs
    assert obs[0]["run_id"] != obs[1]["run_id"], \
        "two scan.run() calls must close and open a fresh run each time, or " \
        "finding_observation's (finding_id, run_id) PK collapses the second " \
        "row onto the first"


# ---------------------------------------------------------------------------
# 3. A CORRECTION: stopping the target does not clear a finding.
# ---------------------------------------------------------------------------

def test_stopping_the_target_does_not_clear_a_finding_but_an_untested_surface_gets_no_observation(rig):
    """Claim 3, corrected against what was actually measured.

    THE BRIEF'S VERSION: "Fix nothing but stop serving the page, scan again
    -- the finding is marked observed=0 only because its surface was
    tested." MEASURED, against a real Burp, with the steps below run in
    order: after the target is stopped, a third `scan.run()` produces a
    THIRD `finding_observation` row with `observed=1`, not a second row with
    `observed=0`.

    WHY, and it is architectural rather than a bug this task should fix:
    every passive check (`hx.checks.passive.cookie_flags.CookieFlags`
    included) is a pure function of `hx.checks.passive._http.responses`,
    which returns one entry per exchange the surface has EVER captured,
    unbounded and never pruned (`hx.scan._exchanges_for`: `SELECT ... FROM
    exchange WHERE surface_id=? ORDER BY rowid`, no LIMIT, no time window).
    Stopping the target changes nothing about that history -- it only
    prevents a NEW exchange from being added to it (and, per
    `test_an_allowed_request_that_cannot_connect_leaves_no_trace_at_all` in
    test_proxy_capture.py, does not even do that cleanly: a connection
    failure leaves no exchange, no denial and no drop at all). The single
    flagless-cookie exchange from claim 1/2 is still the only exchange this
    surface has, so `CookieFlags.on_surface` still finds it and still
    answers `finding`, not `clean` -- and `hx.scan._mark_unobserved` only
    ever writes `observed=0` for a `(surface, check)` pair whose `check_run`
    verdict THIS run was `clean`. Nothing in this corpus, given only more
    browsing (or less), can make that pair `clean` while the exchange that
    proves the finding is still on file; only removing the exchange itself
    -- a retention/purge job, S8's Row G, explicitly out of this plan's
    scope -- could. Asserting the brief's `observed=0` here would pin a
    FALSE fact: that a finding disappears when a site goes down, which is
    the exact "looked and it's gone" reading `scan.py`'s own docstring on
    `_mark_unobserved` warns is wrong to report on weaker evidence than a
    clean answer from the SAME check.

    THE HALF OF CLAIM 3 THAT DOES HOLD -- "a surface never browsed leaves no
    observation at all" -- is measured here too, using `surface_filter`
    rather than a dead target: an operator narrowing a scan to skip a
    surface is the same fact this file can produce on demand, whereas "the
    target happens to be reachable" is not something a check ever consults.
    A surface a scan does not test gets NO `finding_observation` row at all
    -- not `observed=0`, which `scan.py`'s own docstring calls "S12's own
    failure one layer down" -- and that is measured by scanning a third time
    with the finding's own surface filtered OUT and finding the observation
    COUNT unchanged, not decremented and not incremented.

    WHAT THIS TEST PINS, AND WHAT IT DOES NOT. The `clean`-verdict filter in
    `scan.py`'s `clean = {...WHERE run_id=? AND verdict='clean'...}` query is
    NOT what this test pins: relaxing it alone to `verdict IN
    ('clean','finding')` was tried and MEASURED not to redden this test,
    because `_mark_unobserved`'s `if fid in seen: continue` guard
    (`scan.py`, a few lines below the `clean` query) short-circuits first --
    this finding IS re-detected by `summary2`, so its `fid` is in `seen` and
    the loop never reaches the `clean` check for it at all. The `check_id`
    axis of that same `clean` set is pinned instead by the unit test
    `tests/test_scan.py::test_mark_unobserved_reads_check_id_not_issue_type_id`.
    What THIS test pins is the fact one layer up: a still-live finding is
    not reported as fixed merely because its target stopped answering.

    WOULD THIS FAIL IF THAT CLAIM WERE FALSE? MEASURED: relaxing the
    `clean` query to `verdict IN ('clean','finding')` AND ALSO deleting the
    `if fid in seen: continue` guard turns the second assertion below into
    `observed came back [0, 0]` and reddens it -- either mutation alone
    leaves the guard (or the `clean` filter) still blocking the write, so
    both together are what it actually takes to make `_mark_unobserved`
    close this finding on a dead target. A regression that wrote an
    observation row for a `surface_filter`-excluded surface would move the
    THIRD scan's row count and redden the final assertion.
    """
    assert rig.configure() == 1
    rig.browse("GET", "/insecure-cookie")
    rig.settle(lambda: rows(rig, "SELECT id FROM surface"), "the surface row")

    summary1 = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                        blobs=rig.eng.blobs, config=rig.eng.config)
    assert summary1.findings >= 1
    finding = rows(rig, "SELECT id, surface_id FROM finding"
                  " WHERE engagement_id=?", (rig.eng.id,))[0]

    exchanges_before = rows(rig, "SELECT COUNT(*) AS n FROM exchange"
                           " WHERE surface_id=?", (finding["surface_id"],))[0]["n"]

    # Fix nothing; stop serving the page.
    rig.target.stop()
    # A browse against a dead target draws Burp's OWN error page -- the same
    # shape a drop does (DROP_LOOKS_LIKE in test_proxy_capture.py) -- and, per
    # the B3 gap pinned there, leaves no exchange, denial or drop at all.
    # Given long enough for a row to have crossed the bridge if one existed:
    raw = rig.browse("GET", "/insecure-cookie", timeout=20)
    # Burp's OWN error page, not the target's -- the B3 gap's own signature
    # (test_proxy_capture.py: ~1529 bytes, `<title>Burp Suite</title>`, the
    # same 200 a genuine drop draws).
    assert status_of(raw) == 200
    assert b"Burp Suite" in raw
    time.sleep(rig.SETTLE_S)
    exchanges_after = rows(rig, "SELECT COUNT(*) AS n FROM exchange"
                          " WHERE surface_id=?", (finding["surface_id"],))[0]["n"]
    assert exchanges_after == exchanges_before, (
        "the dead-target browse added an exchange -- the B3 gap this test "
        "relies on to keep the surface's evidence unchanged has closed; see "
        "test_an_allowed_request_that_cannot_connect_leaves_no_trace_at_all")

    summary2 = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                        blobs=rig.eng.blobs, config=rig.eng.config)
    assert summary2.findings >= 1, (
        "the finding was NOT re-detected once the target stopped answering. "
        "If this is because CookieFlags started answering `clean`, the "
        "architecture this test's docstring measured has changed and this "
        "test should be rewritten around the new behaviour.")

    obs = rows(rig, "SELECT observed FROM finding_observation"
              " WHERE finding_id=? ORDER BY ts_us", (finding["id"],))
    assert [o["observed"] for o in obs] == [1, 1], (
        f"observed came back {[o['observed'] for o in obs]}: a dead target "
        "made a real, still-on-file finding read as fixed, which is worse "
        "than the gap this test's docstring names -- a client would close a "
        "vulnerability that was never touched")

    # The contrast: a scan that does not test this surface at all.
    summary3 = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                        blobs=rig.eng.blobs, config=rig.eng.config,
                        surface_filter=lambda s: s[0] != finding["surface_id"])
    assert summary3.surfaces == 0, \
        "the filter excluded every surface this engagement has; a nonzero " \
        "count here means the filter itself is not doing what this test " \
        "believes"
    still = rows(rig, "SELECT observed FROM finding_observation"
                " WHERE finding_id=? ORDER BY ts_us", (finding["id"],))
    assert [o["observed"] for o in still] == [1, 1], (
        f"a surface this scan never tested got a THIRD observation row "
        f"({[o['observed'] for o in still]}) -- 'not observed' must mean "
        "'looked and it is gone', never 'nobody looked'")


# ---------------------------------------------------------------------------
# 4. The report: the finding, its evidence, and coverage for every check.
# ---------------------------------------------------------------------------

def test_the_report_names_the_finding_its_evidence_and_every_check_that_ran(rig):
    """Claim 4. `report.render` against a store a real Burp actually wrote to,
    for the first time -- every earlier test of it used hand-inserted rows.
    """
    assert rig.configure() == 1
    rig.browse("GET", "/insecure-cookie")
    rig.settle(lambda: rows(rig, "SELECT id FROM surface"), "the surface row")

    summary = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                       blobs=rig.eng.blobs, config=rig.eng.config)
    assert summary.findings >= 1

    out = report.render(rig.eng.db, engagement_id=rig.eng.id,
                        config=rig.eng.config, blobs=rig.eng.blobs)

    assert "session" in out
    assert "/insecure-cookie" in out, "the evidence row must name the real URL"

    # A coverage row for every check that RAN, not just the one that found
    # something -- registry.enabled(config) is all four passive checks by
    # default, and every one of them opened a check_run row against this
    # surface even though only cookie-flags had anything to say.
    for check_id in ("hx.passive.cookie-flags", "hx.passive.security-headers",
                      "hx.passive.secret-in-response", "hx.passive.stack-trace"):
        assert f"`{check_id}`" in out, \
            f"{check_id} is missing from the coverage table"


# ---------------------------------------------------------------------------
# 5. A dropped record renders the report's floor line.
# ---------------------------------------------------------------------------

def test_a_run_with_a_dropped_record_renders_the_floor_line(rig):
    """Claim 5. Drives a drop exactly the way
    test_proxy_capture.py::test_a_broken_recorder_does_not_gate_the_browser_
    but_a_dead_bridge_does does -- a sink that raises on the exchange frame --
    with ONE difference this test needs and that one does not: THIS sink
    succeeds on the `dropped` RETRY, because `BridgeServer._capture`'s own
    docstring (server.py) says that retry is the only path that moves
    `run.dropped_total` at all, and measures the alternative: "with a sink
    that raises on every frame, three browsed requests produced
    `exchange_errors = 6` ... and `run.dropped_total` STILL 0." A sink that
    fails unconditionally would make this test assert a floor line that
    never renders, for a reason that has nothing to do with the report.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? A `_limits` query keyed off the
    wrong column (`COUNT(*) FROM run` rather than `SUM(dropped_total)`, the
    mutation `tests/test_report.py::test_a_run_with_no_drops_says_nothing_
    about_a_floor` guards against on hand-inserted rows) would print the
    floor line for a run that dropped nothing; that case is not reachable
    from this rig without configuring first, which every test here does.
    The real guard is the SETTLE below: it polls `SUM(dropped_total)` itself,
    so a drop that never reached the run row fails this test at the wait,
    naming `exchange_errors`, before the report is ever rendered.
    """
    assert rig.configure() == 1
    real_sink = rig.srv.on_exchange

    def flaky(header, request, response):
        if header.get("t") == "dropped":
            return real_sink(header, request, response)
        raise RuntimeError("Task 9's simulated recorder failure")

    rig.srv.on_exchange = flaky
    assert status_of(rig.browse("GET", "/health")) == 200

    rig.settle(lambda: rows(rig, "SELECT COALESCE(SUM(dropped_total), 0) AS n"
                          " FROM run")[0]["n"] > 0,
              "the dropped-record count on the run row")
    assert rig.srv.exchange_errors >= 1, (
        "the exchange frame never actually failed, so the floor line below "
        "would render for a reason unrelated to this test's own sink")

    out = report.render(rig.eng.db, engagement_id=rig.eng.id,
                        config=rig.eng.config)
    assert "floor" in out.lower(), out
