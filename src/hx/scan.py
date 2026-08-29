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

`hx.insertion` IS IMPORTED NOW, AND THE OLD REASON IT WAS NOT IS WHY. Plan
5's draft of this module had the import and never called it: with a purely
passive corpus there was nothing here to insert a payload into, and the one
consumer of a derivation was the report, which derives at render time from
the exemplar exchange already on each surface row. Plan 6's probe pass is the
first caller that has a use for one -- an active check is handed the points
it declared it can reach -- so the import is here because something calls it,
which is the same test it failed before. The report still derives its own at
render time: S5 says there is no `insertion` table in v1, so a derivation is
a derivation whenever it runs, and neither side stores one for the other.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from hx import insertion as insertion_mod
from hx import run as run_mod
from hx.checks import base, probe, registry
from hx.engagement import now_us
from hx.store import blobs as blobs_mod
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

    `checks_run` IS `check_run` ROWS WRITTEN, and that is the same rule as
    the paragraph above: a number an operator reads must be one they can go
    and verify. Fix round 1 (LOW) found the two skip paths disagreeing about
    it -- a probe skip incremented this (the counter sits right after
    `_open_row`) and `_skip_rest`'s budget skip did not, so the SAME
    situation, "four rows opened, four skipped, nothing executed", printed
    `checks 4 / skipped 4` down one path and `checks 0 / skipped 4` down the
    other. Rows-written is the meaning that survives: it equals
    `SELECT COUNT(*) FROM check_run WHERE run_id=?` exactly, for every way a
    row can end, which is a claim a test can make and an operator can check.
    "Checks that actually executed" is NOT this number and is not lost --
    it is `checks_run` minus `skipped`, and the CLI prints both lines.
    """
    surfaces: int = 0
    checks_run: int = 0
    findings: int = 0
    skipped: int = 0
    by_reason: dict = field(default_factory=dict)


def run(conn, *, engagement_id, blobs, config, checks=None,
        surface_filter=None, max_seconds=None, bridge=None) -> ScanSummary:
    """Run the enabled corpus over every surface in the engagement.

    `bridge` IS TAKEN, NEVER BUILT. It is a `hx.bridge.server.BridgeServer`
    already connected to a live extension, and this function has no business
    constructing one: it holds no engagement root, no jar and no Burp home,
    so a session opened here would be a JVM whose lifetime is a local
    variable's. `hx scan` (cli.py) opens `session.session(...)` when the
    enabled corpus contains an active check and hands `live.bridge` down.
    A passive-only scan is passed nothing and pays none of Burp's startup.

    `bridge=None` IS NOT A REASON TO SAY NOTHING. Every active check still
    gets a `check_run` row, closed `skipped` with a reason naming the missing
    bridge -- S12: a report that cannot tell "tested, clean" from "never
    reached" is worse than no report, and an active corpus that quietly
    produced no rows at all reads as the first while being the second.
    """
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
            # DERIVED ONCE PER SURFACE, AND ONLY IF SOMETHING ASKS.
            # `insertion.derive` reads a blob off disk and parses a whole
            # request; a passive-only scan must not pay for that, and neither
            # must an active check that declared no insertion kinds. `None`
            # here means "not derived yet", which is a different fact from
            # `()`, "derived, and this surface has none".
            insertions = None

            for check in checks:
                row_id = _open_row(conn, run_id, surface, check)
                summary.checks_run += 1
                # DISPATCH ON THE HOOK, NOT ON `check.klass`. `registry.
                # validate` already guarantees that a check implements
                # exactly one hook the runner calls and that its class
                # permits it -- `_HOOKS` gives `on_surface` to `passive` and
                # `probes` to the four active classes, and no class gets
                # both. A `klass == "passive"` test here would be a second
                # copy of that rule, free to disagree with the registry the
                # day a class is added, and the registry is the one that
                # fails at import.
                hook = _runner_hook(check)
                sender = None
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
                    if hook == _PROBE_HOOK:
                        if bridge is None:
                            # Never silence. The one thing an active check
                            # cannot do without is a route to the wire, and
                            # the row has to say that rather than be absent.
                            _skip(conn, row_id, summary, "no_bridge",
                                  "no bridge: this scan opened no Burp "
                                  "session, so this active check had no "
                                  "route to the target and sent nothing")
                            continue
                        if _citable_exemplar(surface, exchanges) is None:
                            # THE EVIDENCE AN ACTIVE CHECK WILL CITE HAS TO
                            # EXIST BEFORE IT IS WORTH SENDING ANYTHING.
                            # Nothing in this build records an exchange for a
                            # probe's own traffic, so every active check in
                            # this corpus names `surface.exemplar_exchange_id`
                            # as the evidence for whatever it finds -- and that
                            # column is NULL for a surface whose first sighting
                            # was purged, or dangling if the purge ran with the
                            # foreign key off. MEASURED, both shapes, with a
                            # check declaring no insertion kinds (which is
                            # `hx.active.cors`, the one that reaches this at
                            # all -- a check WITH declared kinds already skips,
                            # because `_insertions_for` can derive nothing from
                            # an exemplar it cannot read):
                            #
                            #   * NULL: `Candidate(exchange_ids=(None,))`
                            #     constructed, `evidence` took a row with a
                            #     NULL `exchange_id`, and the report rendered
                            #     "1 of the 1 shown could not be resolved to a
                            #     request" -- a finding with nothing behind it;
                            #   * dangling: `record_evidence` raised
                            #     `IntegrityError: FOREIGN KEY constraint
                            #     failed`, the blanket `except` below turned it
                            #     into an `error` row, and a real finding was
                            #     lost.
                            #
                            # Both are now this skip, which is the honest
                            # sentence: the check was not run, it was not run
                            # clean, and the probe traffic is not spent on a
                            # surface whose answer could not have been
                            # evidenced. `Candidate.__post_init__` refuses the
                            # blank id as well, so a check that gets one from
                            # somewhere other than this column still cannot
                            # file an unverifiable finding.
                            _skip(conn, row_id, summary, "no_exemplar",
                                  "this surface's exemplar exchange is not on "
                                  "file, and it is the evidence an active "
                                  "check cites for anything it finds here; a "
                                  "finding would have had no exchange to "
                                  "chain to")
                            continue
                        wanted = frozenset(getattr(
                            check, "insertion_kinds", frozenset()) or ())
                        if wanted and insertions is None:
                            insertions = _insertions_for(
                                blobs, surface, exchanges)
                        # A check declaring NO insertion kinds is not skipped
                        # for having no points: it shapes its own request --
                        # a header it adds, a method it re-issues -- rather
                        # than filling in a parameter it found. That is the
                        # shape the next task's CORS check takes (Plan 6 Task
                        # 8, `src/hx/checks/active/cors.py`, not written
                        # yet): its `insertion_kinds` is empty on purpose,
                        # and skipping a check for having none of what it
                        # never asked for would silence the first check in
                        # this build that sends.
                        usable = tuple(i for i in (insertions or ())
                                       if i.kind in wanted)
                        if wanted and not usable:
                            _skip(conn, row_id, summary, "no_insertion_point",
                                  "no insertion point of kind "
                                  f"{sorted(wanted)} on this surface, so "
                                  "there was nowhere for this check to put a "
                                  "payload; it was not run, not run clean")
                            continue
                        sender = probe.ProbeSender(
                            bridge, scheme=surface[2], host=surface[3],
                            port=surface[4], path_template=surface[5])
                        verdict = check.probes(ctx, surface, usable, sender)
                    else:
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
                except probe.ProbeRefused as exc:
                    # BEFORE the `except Exception`, and that ordering is the
                    # whole point. A refusal is not a crash and it is not an
                    # answer: S10 says a check that could not run says
                    # `inconclusive`, and `ProbeSender` raises rather than
                    # returning so that no check can read `budget_exhausted`
                    # as a response and carry on to `clean`. Landing it in
                    # `error` would be almost as bad -- an operator reading
                    # `error` goes looking for a bug in hx, when what
                    # happened is that the target, the extension or the
                    # budget said no. `requests_sent` is still written, and it
                    # counts ISSUANCES rather than attempts: `hx.policy.
                    # Limiter` decides scope, method, dangerous, rate and
                    # budget before issuing and increments `issued` on the
                    # allow path only ("Refusals are not issuances and do not
                    # appear here"), so a probe refused by one of those did
                    # not reach the target and this row says 0. A refusal that
                    # may already have left -- `transport_error`, `timeout`,
                    # `bridge_lost`, a truncated answer -- is counted. See
                    # `hx.checks.probe`'s `_NOT_ISSUED`.
                    _close_row(conn, row_id, "inconclusive",
                               f"probe refused: {exc}",
                               requests_sent=sender.sent if sender else 0)
                    continue
                except Exception as exc:                    # noqa: BLE001
                    _close_row(conn, row_id, "error",
                               f"{type(exc).__name__}: {exc}",
                               requests_sent=sender.sent if sender else 0)
                    continue
                _close_row(conn, row_id, verdict.state, verdict.reason,
                           requests_sent=sender.sent if sender else 0)

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
    #
    # `by_reason` CARRIES MORE THAN `budget` NOW. The probe pass adds
    # `no_bridge`, `no_exemplar` and `no_insertion_point`, and all belong in
    # this sentence
    # for the reason the budget one does: a pass that left rows `skipped` did
    # not do everything it set out to do, and the run row is where a report
    # decides whether to trust it. The word stays `truncated` and the KEY is
    # what distinguishes them -- `truncated: no_bridge=4` says which four
    # rows to go and read, which is more than a differently-worded prefix
    # would have said.
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


# The one hook `run()` drives through the wire. Named once because two
# questions read it: which branch of the per-check dispatch a check takes,
# and -- through `needs_a_bridge` below -- whether `hx scan` has to start a
# Burp at all. Those must be the same answer or the CLI pays for a session
# the runner never sends through.
_PROBE_HOOK = "probes"


def needs_a_bridge(check) -> bool:
    """Whether `run()` will drive this check through a pass that SENDS.

    `hx scan` (cli.py) asks this to decide whether to open a session, and it
    has to be the SAME question `run()` answers when it dispatches. Fix round
    1 (LOW): the CLI used to ask `check.klass != "passive"` instead -- a
    class-string restatement of a rule the registry owns, and precisely what
    `_runner_hook` refuses to do one function below. The two agree today and
    could stop agreeing tomorrow without a word: `_HOOKS` decides per class
    which hooks are legal, so a future non-passive class given
    `("on_surface", "on_corpus")` rather than `("probes", ...)` would read as
    active to a class-string test while the runner called `on_surface` and
    sent nothing -- a 10-second JVM started, per scan, to be handed no
    traffic. Asking the hook cannot drift, because it is the dispatch.
    """
    return _runner_hook(check) == _PROBE_HOOK


def _runner_hook(check) -> str:
    """Which of the hooks this runner calls the check implements.

    `registry._RUNNER_CALLS` IS READ, NOT RESTATED. It is the registry's
    answer to "will anything ever invoke this hook", `validate()` refuses a
    check at import whose only hook is not in it, and a second list here
    would be free to drift from the one that does the refusing -- the exact
    shape of the F7 defect that put that tuple there. Underscored and read
    across modules on purpose: the coupling is real, and naming it is better
    than copying it.

    Returns `""` for a check implementing none of them. That is an import
    error for anything in `CHECKS`, but `scan.run` also takes a `checks=`
    argument that never went through `validate` (every test in
    `tests/test_scan.py` uses it), so the fallback lands in the per-check
    `try` as an `error` row for that check rather than as an exception
    escaping the scan.
    """
    for hook in registry._RUNNER_CALLS:
        if callable(getattr(check, hook, None)):
            return hook
    return ""


def _citable_exemplar(surface, exchanges) -> str | None:
    """The exemplar exchange id, if the row it names is still there.

    Two ways it is not, and they are one question rather than two: the column
    is NULL (a surface whose first sighting was purged, or a schema-level
    `ON DELETE SET NULL`), or it names an id no `exchange` row has any more (a
    bulk purge run with `PRAGMA foreign_keys=OFF`, the shape S8's Row G takes
    -- with the pragma ON the delete is simply refused).

    ANSWERED FROM THE ROWS ALREADY FETCHED, not with a second query.
    `_exchanges_for` has just read every exchange of this surface, and the
    exemplar is by definition one of them -- `hx.capture` writes the exchange
    and then points the surface at it -- so a `SELECT` here would be a second
    trip to ask something the caller is already holding. `_insertions_for`
    resolves the same id the same way, a few lines down, for the same reason.
    """
    exemplar_id = surface[6]
    if not exemplar_id:
        return None
    return exemplar_id if any(x.id == exemplar_id for x in exchanges) else None


def _insertions_for(blobs, surface, exchanges) -> tuple:
    """Insertion points derived from this surface's exemplar request.

    `surface.exemplar_exchange_id` -> that exchange's `req_blob` -> bytes is
    the path `hx.insertion`'s own docstring names, and the same one
    `hx.report._insertion_coverage` walks. The exemplar is found in the rows
    already fetched for this surface rather than by a second query: it is the
    first exchange that proved the surface exists (`hx.capture`), so it is
    one of them.

    EVERY FAILURE IS AN EMPTY TUPLE, not a raise. A surface whose blob is
    gone, or whose captured request had no head terminator, is a surface with
    no derivable points -- which the caller already has a word for, `skipped`
    with a reason -- and taking the whole scan down over one unreadable row is
    the trade S12 argues against. `CorruptBlob` is caught by name for the
    reason F8 gives one layer up: a bare `except Exception` here would swallow
    `blobs=None`, and a caller's own programming error is meant to surface.

    THE MISSING-EXEMPLAR CASE NO LONGER ARRIVES HERE, and the two lines that
    answer it are kept anyway. `run()` skips an active check on a surface whose
    exemplar is NULL or dangling before this is called (`_citable_exemplar`),
    because that surface has no evidence for a finding to cite whether or not
    an insertion point could be derived from it. This function is still pure
    and still total for the same input, so the guard costs two lines and means
    a second caller cannot inherit a crash.
    """
    exemplar_id = surface[6]
    if not exemplar_id:
        return ()
    digest = next((x.req_blob for x in exchanges if x.id == exemplar_id), None)
    if not digest:
        return ()
    try:
        raw = blobs.get(digest)
    except blobs_mod.CorruptBlob:
        return ()
    return insertion_mod.derive(raw, surface[5])


def _skip(conn, row_id, summary, key, reason) -> None:
    """Close an opened row `skipped`, and COUNT it where the operator looks.

    `summary.by_reason` is what `hx scan` prints as `skipped N (key)` and
    what turns the run's own `stop_reason` from `None` into a sentence, so a
    skip that updated only the `check_run` row would be recoverable from the
    store and invisible at the terminal. `key` is the short one for that
    tally; `reason` is the sentence the row carries.
    """
    _close_row(conn, row_id, "skipped", reason)
    summary.skipped += 1
    summary.by_reason[key] = summary.by_reason.get(key, 0) + 1


def _open_row(conn, run_id, surface, check) -> str:
    row_id = records.new_id("cr")
    with db_mod.transaction(conn):
        conn.execute(
            "INSERT INTO check_run(id, run_id, surface_id, check_id,"
            " check_version, started_us, verdict) VALUES(?,?,?,?,?,?, 'pending')",
            (row_id, run_id, surface[0], check.id, check.version, now_us()))
    return row_id


def _close_row(conn, row_id, verdict, reason, requests_sent=0) -> None:
    """Close the row, and record what the check spent getting there.

    `requests_sent` IS WRITTEN HERE BECAUSE THE SENDER CANNOT WRITE IT.
    `probe.ProbeSender` counts in memory and holds no database connection --
    `base.CheckContext`'s "a check that can write is a check that can write
    the wrong thing" would stop being literally true the moment it did -- so
    the count crosses into the store at exactly one place, the same place the
    verdict does, and for every way a row can end: clean, finding,
    inconclusive, error, skipped. The column's `DEFAULT 0` covers a passive
    row that never had a sender, and passing 0 explicitly for one costs
    nothing and keeps this the only writer.
    """
    with db_mod.transaction(conn):
        conn.execute(
            "UPDATE check_run SET verdict=?, reason=?, ended_us=?,"
            " requests_sent=? WHERE id=?",
            (verdict, reason, now_us(), requests_sent, row_id))


def _skip_rest(conn, run_id, surface, checks, reason, summary) -> int:
    """Every remaining check of one surface, opened and closed `skipped`.

    `checks_run` is advanced here, which it was not before fix round 1
    (LOW). These rows ARE `check_run` rows -- `_open_row` writes each one --
    and `ScanSummary.checks_run` is defined as rows written, so a path that
    wrote four and counted none made the same scan print `checks 0 /
    skipped 4` where the probe pass prints `checks 4 / skipped 4`. The
    counter now moves wherever a row is opened, down both paths.
    """
    for check in checks:
        row_id = _open_row(conn, run_id, surface, check)
        summary.checks_run += 1
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
