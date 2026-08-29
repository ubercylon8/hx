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
    """What a scan did, in the words `hx scan` prints at the operator.

    `findings` IS DISTINCT FINDINGS, NOT CANDIDATES WRITTEN -- D3 of the
    fix-round-A re-review (MEDIUM). It counted one per candidate upserted,
    which agreed with the store only while every finding was surface-scoped.
    F3 of the whole-branch review made a host-scoped candidate collapse onto
    ONE row however many surfaces of that host produced it, and the counter
    did not: MEASURED, 40 surfaces of one host with one flagless cookie, the
    CLI printed `findings  40` while the store and the report held 1 -- the
    exact forty tickets F3 removed, reappearing at the terminal. A number an
    operator reads must be the number the report will show.
    """
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
    # itself. `observed` came back `[0]`, one row, never `[1, 0]`.
    #
    # This does NOT mean nothing else can close a scan run -- `hx capture
    # stop` (cli.py) closes every live run by default, `--kind scan` included
    # (F6 of the task-6 review: an earlier version of this comment claimed
    # otherwise, which was false -- MEASURED against cli.py:246-262, whose
    # default query is `WHERE status='running'` with no kind filter at all).
    # What nothing else does is close a scan run AUTOMATICALLY AT THE END OF
    # ITS OWN PASS, which is the sentence this paragraph should have said the
    # first time: without the close below, a scan that finishes cleanly stays
    # `running` until an operator's `stop` or `reap_stale`'s idle window
    # catches up to it.
    try:
        surfaces = conn.execute(
            "SELECT id, method, scheme, host, port, path_template,"
            " exemplar_exchange_id FROM surface WHERE engagement_id=?"
            " ORDER BY host, path_template, method", (engagement_id,)).fetchall()

        seen_findings: set[str] = set()
        # (surface_id, check_id, issue_type_id) this run actually examined and
        # concluded about. Retirement reads this, NOT `check_run.verdict ==
        # 'clean'`: a check filing one of three findings answers `finding`,
        # and the other two still need retiring.
        considered: set[tuple[str, str, str]] = set()

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
            # F4 of the task-6 review: `hx.capture` heartbeats on every
            # exchange precisely so a live run is not mistaken for a dead
            # harness; `scan.run` heartbeated never. `open_run` stamps
            # `heartbeat_us` once at the start and nothing refreshed it, so a
            # scan running longer than `run.reap_stale`'s idle window got
            # reaped `error` WHILE STILL RUNNING -- MEASURED, with a check
            # still executing when `reap_stale` ran in another connection --
            # after which `close_run`'s `WHERE status='running'` silently
            # no-ops at the end of THIS function, permanently recording a
            # scan that finished as one that crashed. Per surface is the
            # obvious granularity: it is the same loop `checks_run` and
            # `surfaces` already advance in.
            run_mod.heartbeat(conn, run_id=run_id)
            exchanges = _exchanges_for(conn, surface[0])

            for check in checks:
                row_id = _open_row(conn, run_id, surface, check)
                summary.checks_run += 1
                # F2 of the task-6 review: this try used to wrap ONLY
                # `check.on_surface`, so anything raised while HANDLING the
                # result -- `verdict.state` on a non-Verdict, `_write_finding`
                # hitting a purged exchange id -- escaped `scan.run` entirely,
                # leaving the row `pending` and ending the whole scan. MEASURED
                # both: a check returning the bare string `"clean"` raised
                # `AttributeError` reading `.state`; a `Candidate` naming an
                # exchange id that does not resolve raised `IntegrityError`
                # out of `record_evidence`. Both now land here instead of
                # outside it. "One bad check must not end a scan an operator
                # has already billed for" -- this module's own first test --
                # was never conditional on WHERE in handling the check went
                # wrong.
                try:
                    verdict = check.on_surface(ctx, surface, exchanges)
                    if verdict is None:
                        # Silence is not a verdict. A check that forgot to
                        # return would otherwise render as `tested, clean`.
                        raise TypeError(
                            "the check returned None; silence is not a verdict")
                    if not isinstance(verdict, base.Verdict):
                        # F3 of the task-6 review: nothing here checked that
                        # what came back WAS a `Verdict`. MEASURED:
                        # `SimpleNamespace(state="skipped", reason="I decided
                        # not to")` produced a `check_run` row of `('skipped',
                        # 'I decided not to')`, indistinguishable from a real
                        # budget skip. `Verdict.__post_init__` is the
                        # enforcement point Task 1 built for exactly this --
                        # `pending`/`skipped`/`error` are the runner's words,
                        # never a check's -- but it only fires for an actual
                        # `Verdict` construction, and this boundary handed the
                        # guarantee straight back by trusting duck-typed
                        # input. Rejected the same way as `None`.
                        raise TypeError(
                            f"the check returned {verdict!r} "
                            f"({type(verdict).__name__}), not a "
                            "hx.checks.base.Verdict; a check may not "
                            "construct the runner's own vocabulary by hand")
                    # An `inconclusive` verdict carries no `considered` -- the
                    # classmethod does not offer it -- so this loop is empty
                    # for exactly the state that must retire nothing.
                    for issue_type in verdict.considered:
                        considered.add((surface[0], check.id, issue_type))
                    if verdict.state == "finding":
                        for candidate in verdict.candidates:
                            fid = _write_finding(conn, engagement_id, run_id,
                                                 surface, check, candidate)
                            # BEFORE the `add`, and that ordering is the fix:
                            # `upsert_finding` returns the id of the row the
                            # candidate landed on, which for a host-scoped
                            # finding is the SAME row every surface of that
                            # host resolves to. `seen_findings` is already the
                            # set of distinct findings this run (it is what
                            # `_mark_unobserved` reads), so membership in it
                            # is exactly "this candidate re-found something
                            # already counted". D3 of the fix-round-A
                            # re-review.
                            if fid not in seen_findings:
                                summary.findings += 1
                            seen_findings.add(fid)
                except Exception as exc:                    # noqa: BLE001
                    _close_row(conn, row_id, "error",
                               f"{type(exc).__name__}: {exc}")
                    continue
                _close_row(conn, row_id, verdict.state, verdict.reason)

        _mark_unobserved(conn, engagement_id, run_id, seen_findings, considered)
    except BaseException as exc:
        # Left `running` here would mean the NEXT scan.run() call inherits
        # this one's half-finished state via current_run's reuse window --
        # the same collision this try/except exists to prevent, but for a
        # crash instead of a fast retest. `error`, not `completed`: S5 "an
        # aborted run must never render as a clean one."
        run_mod.close_run(conn, run_id=run_id, status="error",
                          stop_reason=f"scan.run raised: {type(exc).__name__}: {exc}")
        raise
    # F7 of the task-6 review: a budget-truncated scan used to close
    # `('completed', NULL)`, identical at the `run` row to a scan that
    # covered every surface -- the truncation was recoverable from
    # `check_run` (`verdict='skipped'`, `reason='budget'`) but not from the
    # run row alone, and S12's whole subject is telling a complete pass from
    # an incomplete one apart. `stop_reason` says so when it happened, and
    # stays `None` -- not some other placeholder -- when it didn't, so a
    # complete scan is not itself misreported as "truncated for a reason".
    stop_reason = None
    if summary.by_reason:
        parts = ", ".join(f"{k}={v}" for k, v in sorted(summary.by_reason.items()))
        stop_reason = f"truncated: {parts}"
    run_mod.close_run(conn, run_id=run_id, status="completed",
                      stop_reason=stop_reason)
    return summary


def _exchanges_for(conn, surface_id):
    # `outcome` is in the SELECT, and the column order is `ExchangeRow`'s --
    # the row is built positionally, so the two lists are one contract. F6 of
    # the whole-branch review: without `outcome` here, a check could not tell
    # an exchange that came back whole from one that timed out or was cut
    # off, and read the silence as `clean`.
    return tuple(base.ExchangeRow(*r) for r in conn.execute(
        "SELECT id, method, url, status, outcome, req_blob, resp_blob"
        " FROM exchange WHERE surface_id=? ORDER BY rowid", (surface_id,)))


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
        type_=check.id, issue_type_id=candidate.issue_type_id,
        scheme=scheme, host=host, port=port, method=method,
        path_template=path_template,
        insertion_kind=candidate.insertion.kind if candidate.insertion else None,
        insertion_name=candidate.insertion.name if candidate.insertion else None,
        scope_level=candidate.scope_level)
    at = now_us()
    with db_mod.transaction(conn):
        fid = records.upsert_finding(conn, engagement_id=engagement_id,
                                     candidate=candidate, dedupe_key=key,
                                     run_id=run_id, surface_id=surface[0],
                                     host=host, check_id=check.id)
        records.record_observation(
            conn, finding_id=fid, run_id=run_id, observed=True,
            exchange_id=candidate.exchange_ids[0],
            severity_at=candidate.severity, confidence_at=candidate.confidence,
            at_us=at)
        records.record_evidence(conn, finding_id=fid,
                                exchange_ids=candidate.exchange_ids, at_us=at)
    return fid


def _mark_unobserved(conn, engagement_id, run_id, seen, considered) -> None:
    """`observed = 0` for a finding whose issue type was EXAMINED this run and
    not re-emitted.

    THE GATE THIS REPLACES was `check_run.verdict == 'clean'` for the
    finding's own (surface, check). That was sound while a check filed at most
    one finding per surface: "the check ran and found nothing" and "this
    finding is gone" were the same sentence. `issue_type_id` made
    N-per-surface the norm, and they stopped being the same sentence -- a
    check finding one of three issues answers `finding`, so the two fixed ones
    were never retired and rendered live off stale observations. A client was
    told a fixed issue was still open.

    EXAMINATION, NOT ABSENCE. A finding is retired only if its issue type is
    in `considered` -- the check looked and did not find it. A check that
    simply stopped looking retires nothing, because "I did not examine this"
    is not evidence of a fix, and S12 forbids rendering the second as the
    first.

    `considered` is built by `scan.run` from every accepted `Verdict`'s own
    `considered` field (Task 1), keyed `(surface_id, check_id, issue_type_id)`.
    An `inconclusive` verdict contributes nothing to it -- the classmethod
    does not accept `considered` at all -- so a check that raised, went
    inconclusive, was skipped by the budget, or was simply absent from this
    run's `checks` retires none of its prior findings: none of those states
    ever added an entry for them.

    Row G, spec S8: a surface can vanish between capture and scan. MEASURED:
    the schema's own FK (`finding.surface_id REFERENCES surface(id)`) refuses
    a plain `DELETE FROM surface` the instant anything depends on the row --
    `tests/test_scan.py::test_a_surface_deleted_between_capture_and_scan_is_refused_by_the_schema`
    pins that. Reaching this case at all needs `PRAGMA foreign_keys=OFF`
    around the delete, the shape a bulk purge/retention job takes. Once it
    happens, `considered` is built from THIS run's own surface loop -- a
    vanished surface never appears in it, so it is simply absent, never
    looked up, never guessed about.
    """
    if not considered:
        return
    # `finding.check_id` and `finding.issue_type_id` are different axes (see
    # schema.sql): `check_id` answers "which of hx's checks found this",
    # `issue_type_id` answers "what kind of issue is this", and both are read
    # here because `considered` is keyed on both --
    # `tests/test_scan.py::test_mark_unobserved_reads_check_id_not_issue_type_id`
    # pins that a swap of the two columns must not let this match wrongly.
    rows = conn.execute(
        "SELECT id, surface_id, check_id, issue_type_id FROM finding"
        " WHERE engagement_id=?", (engagement_id,)).fetchall()
    at = now_us()
    with db_mod.transaction(conn):
        for fid, surface_id, check_id, issue_type_id in rows:
            if fid in seen:
                continue
            if (surface_id, check_id, issue_type_id) not in considered:
                continue
            records.record_observation(
                conn, finding_id=fid, run_id=run_id, observed=False,
                exchange_id=None, severity_at=None, confidence_at=None,
                at_us=at)
