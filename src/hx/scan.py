"""The runner: everything a check may not do.

A check is pure and narrow by design (see hx.checks.base). Everything else --
writing rows, computing identity, spending budget, deciding what silence
means -- is here, because each of those must have ONE implementation or the
guarantees stop being uniform across the corpus.

THE ORDERING THAT MATTERS: a `check_run` row is written `pending` BEFORE the
check is called and updated after. A scan killed mid-check then leaves a row
saying `started, never finished` rather than no row at all. S12 says a report
that cannot tell "tested, clean" from "never reached" is worse than no report,
and the crash case is the one where no other mechanism would say anything.

NO `hx.insertion` IMPORT. The spec's draft of this module once had one and
never called it: insertion derivation's consumer in this plan is Task 8's
report, which derives at render time from the exemplar exchange already on
each surface row. A passive corpus (Task 4's whole four checks) has nothing
to insert a payload into, so there is nothing here for `insertion.derive` to
do.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from hx import run as run_mod
from hx.checks import base, registry
from hx.engagement import now_us
from hx.store import db as db_mod
from hx.store import records


@dataclass
class ScanSummary:
    surfaces: int = 0
    checks_run: int = 0
    findings: int = 0
    skipped: int = 0
    by_reason: dict = field(default_factory=dict)


def run(conn, *, engagement_id, blobs, config, checks=None,
        surface_filter=None, max_seconds=None) -> ScanSummary:
    """Run the enabled corpus over every surface in the engagement."""
    checks = registry.enabled(config) if checks is None else tuple(checks)
    checks = tuple(c for c in checks if config.checks.get(c.klass, False))
    summary = ScanSummary()
    if not checks:
        return summary

    run_id = run_mod.current_run(
        conn, engagement_id=engagement_id, kind="scan",
        safety_profile=config.safety_profile)
    ctx = base.CheckContext(config=config, blobs=blobs, run_id=run_id,
                            log=lambda s: None)
    deadline = None if max_seconds is None else time.monotonic() + max_seconds

    # THE RUNNER OWNS CLOSING WHAT IT OPENED. `run.current_run`'s reuse
    # window exists for a continuous browsing session ("avoid one specific
    # afternoon" -- run.py's own docstring); a scan is the opposite shape, a
    # single bounded pass that starts and finishes inside one call. Without
    # this, MEASURED: two `scan.run()` calls a few microseconds apart --
    # exactly `test_a_finding_not_seen_this_run_is_marked_unobserved_...`,
    # which calls it twice in a row -- both land inside `current_run`'s
    # 15-minute idle window and get the SAME run_id, because nothing had
    # ever closed the first one. `finding_observation`'s primary key is
    # `(finding_id, run_id)`, so the second call's `record_observation`
    # doesn't add a second row, it OVERWRITES the first run's `observed=1`
    # with the second run's `observed=0` -- the retest's own history erases
    # itself. `observed` came back `[0]`, one row, never `[1, 0]`. Nothing in
    # this plan's cli exists yet to close a scan run from outside (unlike
    # `browse`, which cli.py's `stop` command closes explicitly), so if this
    # function does not close its own run, no code path ever does until
    # `reap_stale` finds it stale and marks it `error` -- the wrong status
    # for a scan that actually finished.
    try:
        surfaces = conn.execute(
            "SELECT id, method, scheme, host, port, path_template,"
            " exemplar_exchange_id FROM surface WHERE engagement_id=?"
            " ORDER BY host, path_template, method", (engagement_id,)).fetchall()

        tested: set[str] = set()
        seen_findings: set[str] = set()

        for surface in surfaces:
            if surface_filter is not None and not surface_filter(surface):
                continue
            if deadline is not None and time.monotonic() > deadline:
                # Out of time. The remaining checks are RECORDED as skipped,
                # never left absent -- absence is what S12 forbids.
                summary.skipped += _skip_rest(conn, run_id, surface, checks,
                                              "budget", summary)
                continue
            summary.surfaces += 1
            tested.add(surface[0])
            exchanges = _exchanges_for(conn, surface[0])

            for check in checks:
                row_id = _open_row(conn, run_id, surface, check)
                summary.checks_run += 1
                try:
                    verdict = check.on_surface(ctx, surface, exchanges)
                except Exception as exc:                    # noqa: BLE001
                    _close_row(conn, row_id, "error",
                               f"{type(exc).__name__}: {exc}")
                    continue
                if verdict is None:
                    # Silence is not a verdict. A check that forgot to
                    # return would otherwise render as `tested, clean`.
                    _close_row(conn, row_id, "error",
                               "the check returned None; silence is not a verdict")
                    continue
                if verdict.state == "finding":
                    for candidate in verdict.candidates:
                        fid = _write_finding(conn, engagement_id, run_id,
                                             surface, check, candidate)
                        seen_findings.add(fid)
                        summary.findings += 1
                _close_row(conn, row_id, verdict.state, verdict.reason)

        _mark_unobserved(conn, engagement_id, run_id, tested, seen_findings)
    except BaseException as exc:
        # Left `running` here would mean the NEXT scan.run() call inherits
        # this one's half-finished state via current_run's reuse window --
        # the same collision this try/except exists to prevent, but for a
        # crash instead of a fast retest. `error`, not `completed`: S5 "an
        # aborted run must never render as a clean one."
        run_mod.close_run(conn, run_id=run_id, status="error",
                          stop_reason=f"scan.run raised: {type(exc).__name__}: {exc}")
        raise
    run_mod.close_run(conn, run_id=run_id, status="completed")
    return summary


def _exchanges_for(conn, surface_id):
    return tuple(base.ExchangeRow(*r) for r in conn.execute(
        "SELECT id, method, url, status, req_blob, resp_blob FROM exchange"
        " WHERE surface_id=? ORDER BY rowid", (surface_id,)))


def _open_row(conn, run_id, surface, check) -> str:
    row_id = records.new_id("cr")
    with db_mod.transaction(conn):
        conn.execute(
            "INSERT INTO check_run(id, run_id, surface_id, check_id,"
            " check_version, started_us, verdict) VALUES(?,?,?,?,?,?, 'pending')",
            (row_id, run_id, surface[0], check.id, check.version, now_us()))
    return row_id


def _close_row(conn, row_id, verdict, reason) -> None:
    with db_mod.transaction(conn):
        conn.execute(
            "UPDATE check_run SET verdict=?, reason=?, ended_us=? WHERE id=?",
            (verdict, reason, now_us(), row_id))


def _skip_rest(conn, run_id, surface, checks, reason, summary) -> int:
    for check in checks:
        row_id = _open_row(conn, run_id, surface, check)
        _close_row(conn, row_id, "skipped", reason)
        summary.by_reason[reason] = summary.by_reason.get(reason, 0) + 1
    return len(checks)


def _write_finding(conn, engagement_id, run_id, surface, check, candidate) -> str:
    _, method, scheme, host, port, path_template, _exemplar = surface
    key = records.dedupe_key(
        type_=check.id, scheme=scheme, host=host, port=port, method=method,
        path_template=path_template,
        insertion_kind=candidate.insertion.kind if candidate.insertion else None,
        insertion_name=candidate.insertion.name if candidate.insertion else None)
    at = now_us()
    with db_mod.transaction(conn):
        fid = records.upsert_finding(conn, engagement_id=engagement_id,
                                     candidate=candidate, dedupe_key=key,
                                     run_id=run_id, surface_id=surface[0],
                                     host=host)
        records.record_observation(
            conn, finding_id=fid, run_id=run_id, observed=True,
            exchange_id=candidate.exchange_ids[0],
            severity_at=candidate.severity, confidence_at=candidate.confidence,
            at_us=at)
        records.record_evidence(conn, finding_id=fid,
                                exchange_ids=candidate.exchange_ids, at_us=at)
    return fid


def _mark_unobserved(conn, engagement_id, run_id, tested, seen) -> None:
    """`observed = 0` for findings this run looked for and did not see.

    ONLY WHERE THE SURFACE WAS ACTUALLY TESTED. A finding whose surface was
    never reached gets NO ROW -- because "not observed" would otherwise
    silently mean "not looked at", which is S12's own failure one layer down.
    A retest that cannot tell those apart is a retest that cannot say `fixed`.

    Row G, spec S8: a surface can vanish between capture and scan. MEASURED:
    the schema's own FK (`finding.surface_id REFERENCES surface(id)`) refuses
    a plain `DELETE FROM surface` the instant anything depends on the row --
    `tests/test_scan.py::test_a_surface_deleted_between_capture_and_scan_is_refused_by_the_schema`
    pins that. Reaching this case at all needs `PRAGMA foreign_keys=OFF`
    around the delete, the shape a bulk purge/retention job takes.

    Once it happens, `tested` is built from surface ids the scan loop
    actually iterated THIS run -- from a LIVE `SELECT ... FROM surface`, not
    from any stored finding's own `surface_id` read back afterwards -- so a
    dangling id in `finding.surface_id` simply never appears in `tested` and
    is left alone, not queried, not guessed about. There is no separate
    id-existence check to get wrong because there is no path here that would
    ever dereference one.
    """
    if not tested:
        return
    marks = ", ".join("?" * len(tested))
    rows = conn.execute(
        f"SELECT id FROM finding WHERE engagement_id=? AND surface_id IN ({marks})",
        (engagement_id, *tested)).fetchall()
    at = now_us()
    with db_mod.transaction(conn):
        for (fid,) in rows:
            if fid in seen:
                continue
            records.record_observation(
                conn, finding_id=fid, run_id=run_id, observed=False,
                exchange_id=None, severity_at=None, confidence_at=None,
                at_us=at)
