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
the exemplar exchange already on each surface row. This plan's probe pass is
the first caller that has a use for one -- an active check is handed the points
it declared it can reach -- so the import is here because something calls it,
which is the same test it failed before. The report still derives its own at
render time: S5 says there is no `insertion` table in v1, so a derivation is
a derivation whenever it runs, and neither side stores one for the other.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from hx import identity as identity_mod
from hx import insertion as insertion_mod
from hx import run as run_mod
from hx.checks import base, probe, registry
# `_http._detail` FORMATS A PER-POINT LIST THE WAY A COVERAGE ROW SHOWS IT,
# read across the module boundary rather than copied, for the reason
# `hx.checks.active._probe_util.verdict` reads it: an operator reading that
# row must see the same shape -- at most three, then a count -- whether the
# list came from a passive check's unreadable exchanges, an active check's
# gaps, or the skip below. It lives under `checks.passive` because that is
# where the first caller was; its own docstring says it takes the list and
# not an `Evidence` precisely so the rest of the corpus can use it.
from hx.checks.passive import _http
from hx.engagement import now_us
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from hx.store import records


class IdentityDead(Exception):
    """The session could not be proved live, so the run stops.

    NOT a verdict and not an `inconclusive` row -- an exception, because
    there is no honest partial answer here. Master spec section 7 requires
    the halt in as many words ("on failure the run halts rather than
    continuing") and the identity design's section 6 gives the reason: the
    alternative is SILENT. A run that carried on under a dead session would
    answer `clean` for every surface it touched, and those answers are
    indistinguishable in the report from an application that genuinely has
    nothing wrong with it.

    RAISED WHILE THERE IS STILL TRAFFIC TO PREVENT, and only then. The
    opening canary and every canary that falls due mid-run raise it; the
    CLOSING canary does not, because at the close there is nothing left to
    halt -- every request has already been made -- and raising would throw
    away a completed pass's rows to prevent traffic that no longer exists.
    Section 11 names the remedy for that case and it is not a halt: "a
    failing canary downgrades the whole window to `assumed`, so the run
    under-claims instead of over-claiming, and retires nothing".

    A REFUSED REGISTRATION IS NOT THIS. `BridgeServer.register_identity`
    raises `BridgeError` (a peer that refused the frame, or one that is
    gone) and `codec.FrameError` (a credential that cannot be written as
    itself), and both propagate as themselves: the run stops either way --
    `run()`'s own `except BaseException` closes the row `error` and re-raises
    -- and each of those messages says which of the two actually happened,
    which "could not be proved live" would not.

    IT CARRIES ITS OWN `stop_reason`, AND `run` STORES THAT RATHER THAN
    `str(self)`. F1 of fix round A. `run`'s `except BaseException` wrote
    `f"...: {exc}"` into `run.stop_reason`, and `hx.report._provenance`
    renders a non-completed run's `stop_reason` onto the CLIENT-FACING page
    through a `_redact` that strips URL userinfo and nothing else -- so every
    string any raise site ever interpolates into this exception was one edit
    away from the deliverable, and one of them already carried a failing
    refresh command's stderr out of `hx.identity.refresh`.

    So the two halves are separated and they are not the same sentence. The
    MESSAGE is for the operator's terminal and may say as much as it likes,
    including chaining an exception from outside this process. The
    `stop_reason` is composed by the raise site out of values this module
    holds -- an identity id, which phase of the bracket failed, and a
    refusal class from the wire's own vocabulary -- and is the only half
    that crosses into the store. The cut is here as well as at
    `hx.identity.refresh` on purpose: a containment that lives only at
    today's one leaking call site is a containment the next call site does
    not get.
    """

    def __init__(self, message: str, *, stop_reason: str) -> None:
        # KEYWORD-ONLY AND REQUIRED, so a raise site cannot acquire the old
        # behaviour by forgetting: without it this class would default to
        # storing its own message again the first time someone added a
        # fourth raise site in a hurry.
        super().__init__(message)
        self.stop_reason = stop_reason


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

    `refused` IS NOT `by_reason`, AND MIXING THEM WOULD MISREPORT BOTH. F11
    of the whole-branch review. `by_reason` counts rows the runner SKIPPED --
    it never called the check -- and the CLI prints each as `skipped N
    (key)`. This counts probes that ended in a `ProbeRefused` -- a refusal
    from the extension or the bridge, or an answer that did not come back
    whole -- keyed by the wire's own class, on rows where the check DID run
    and then answered `inconclusive` or reported what the surviving points
    found. A
    `budget_exhausted` folded into `by_reason` would print as a skipped
    check, which is a row an operator can go and read and would not find.
    Both feed the run's `stop_reason`, separately labelled, because a run
    that says `completed` after spending its whole budget at surface 10 of
    500 overstates its own coverage.
    """
    surfaces: int = 0
    checks_run: int = 0
    findings: int = 0
    skipped: int = 0
    by_reason: dict = field(default_factory=dict)
    refused: dict = field(default_factory=dict)
    # `proven` / `assumed` / `dead` for a run that issued under an identity,
    # None for one that did not -- `hx.identity.IdentityWindow.state_for_run`,
    # settled by the closing canary.
    #
    # THE ONE PLACE THIS BUILD CAN PUT IT. Spec section 6 writes the state on
    # `exchange`, and that same section's 2026-08-30 amendment records why the
    # column cannot be written yet: `Capture.java` delivers `via: proxy` and
    # nothing else, so this build stores no send-path exchange row for a probe
    # at all. The `run` table has no identity column either. So the run's own
    # summary object is what carries the fact out to its caller.
    #
    # A RUN-LEVEL FACT AND NOT A PER-PROBE ONE, because `IdentityWindow`
    # collapses to the worst window in the run: one failed canary anywhere
    # makes the whole run `assumed`, which under-claims rather than
    # over-claims. The narrower thing section 6's amendment says the
    # retirement gate actually needs -- "whether every probe a given
    # `check_run` sent was issued inside a proven window" -- is answered by
    # this from above rather than from below: a run that is `proven` had every
    # window in it proven.
    #
    # Nothing prints it today: `hx scan` (cli.py) echoes surfaces, checks,
    # findings, skips and refusals, and this is not one of them.
    identity_state: str | None = None
    # The canaries' OWN requests. Section 6: the canary "is counted in
    # `requests_sent` for the run, because it is a request `hx` put on the
    # client's system" -- and it belongs to no `check_run` row, because no
    # check asked for it. Counted beside the probes rather than folded into
    # them for the reason `refused` is not folded into `by_reason`: a number
    # an operator reads has to be one they can go and check against a row
    # that exists.
    canary_requests: int = 0


def run(conn, *, engagement_id, blobs, config, checks=None,
        surface_filter=None, max_seconds=None, bridge=None,
        identity=None) -> ScanSummary:
    """Run the enabled corpus over every surface in the engagement.

    `identity` IS A RESOLVED CREDENTIAL, NEVER A DECLARATION. It is a
    `hx.identity.Resolved` -- the secret, which spec section 3 keeps off
    `Config` because `scope_version.yaml` copies a config verbatim into an
    append-only table. Passing None does NOT mean anonymous: this function
    then resolves `config.scan_identity` itself (`_resolve_scan_identity`),
    which is the only thing in the product that reads that field, and
    anonymous is what it answers when the field is absent.

    WHAT AN IDENTITY BUYS AND WHAT IT COSTS. Every `ProbeSender` this
    function builds is bound to it, so every probe of the run issues under
    one session; and the run is BRACKETED by canaries (section 6), so a
    session that dies mid-run is caught rather than producing hours of
    unauthenticated traffic every check reads as "not vulnerable". A canary
    that cannot be satisfied raises `IdentityDead` out of this function
    rather than letting the pass continue.

    A CHECK STILL KNOWS NOTHING ABOUT ANY OF IT (section 8). It is handed a
    sender already bound, exactly as it is handed one already bound to a
    surface, and cannot choose an identity, read one, or ask whether one
    applied.

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
    # otherwise, which was false -- MEASURED against `cli.stop`, whose
    # default query is `SELECT id FROM run WHERE status='running'` with no
    # kind filter at all).
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

        # INSIDE THE TRY, so that a run halted over a dead session closes its
        # own row `error` with the halt named in `stop_reason` -- S5's "an
        # aborted run must never render as a clean one" -- rather than
        # leaving a `running` row for `reap_stale` to guess about. AFTER the
        # surfaces are read, because the opening canary is ordinary traffic
        # and needs an address to go to, and the run's own first surface is
        # the one host it is certain to be probing.
        bracket = _identity_bracket(bridge, config, identity, checks,
                                    surfaces, surface_filter, summary)
        if bracket is not None:
            bracket.start()
        # Read once: a refresh mints a new credential at a new generation but
        # never a new id, so this is stable for the life of the run even
        # though `bracket.resolved` is not.
        identity_id = None if bracket is None else bracket.identity_id

        seen_findings: set[str] = set()
        # (surface_id, check_id, issue_type_id) this run examined AND may
        # speak for the client's own view of. Retirement reads this, NOT
        # `check_run.verdict == 'clean'`: a check filing one of three
        # findings answers `finding`, and the other two still need retiring.
        # The second clause is `_retirable`'s and it is why nothing an
        # ACTIVE check said can be in here: every probe this build sends is
        # unauthenticated, so what it saw is not necessarily the view the
        # client's users are in.
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
            # READ ONCE PER SURFACE, AND ONLY IF SOMETHING ASKS. The exemplar
            # request is a blob off disk; a passive-only scan must not pay for
            # it. `_UNREAD` is the third state the two obvious ones cannot
            # spell: `None` from `_exemplar_request` means "read, and there is
            # nothing there", which is a different fact from "not read yet"
            # and has to stay different or an unreadable blob is re-read once
            # per check.
            #
            # BOTH ACTIVE DERIVATIONS COME OFF THESE BYTES -- the concrete
            # probe path and the insertion points -- so they are one read and
            # not two. `insertions` keeps its own lazy `None`, because a check
            # declaring no kinds must still not pay for `insertion.derive`'s
            # parse of the whole request.
            exemplar_request = _UNREAD
            insertions = None

            for check in checks:
                # THE CANARY GOES BETWEEN CHECKS, AND HERE IS WHY IT IS AT
                # THE TOP OF THIS LOOP RATHER THAN AFTER THE ROW CLOSES: a
                # probing row closes at three places (a verdict, a refusal, a
                # crash) and two of them `continue` out of the loop body, so
                # a call sited after them would be reached by one path in
                # three. `_spent` -- which all three call, exactly once per
                # row -- is what counts the probes toward the next canary;
                # this is what acts on the count. Raises `IdentityDead` for a
                # session that cannot be proved live again, before the next
                # check sends anything.
                if bracket is not None:
                    bracket.canary_if_due()
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
                        if surface[1] not in _PROBEABLE_METHODS:
                            # A GET IS THE ONLY REQUEST THIS BUILD CAN BUILD.
                            # N2 of the scoped re-review: `ProbeSender.
                            # _request_bytes` emits a GET and nothing else --
                            # body-parameter and mutating probes were excluded
                            # from this plan at design time -- and this loop
                            # read `surface.method` only to build a dedupe
                            # key. So `POST /cart/add` was probed with `GET
                            # /cart/add` and closed `clean` with `considered`
                            # populated, MEASURED: three GETs on the wire and
                            # five `clean` rows naming a surface none of them
                            # addressed. A surface's method is part of its
                            # identity (`hx.surface.normalise`), so that
                            # request tested a DIFFERENT surface and
                            # `_mark_unobserved` stood ready to retire this
                            # one's findings on the strength of it.
                            #
                            # Decided here, before a sender exists, for the
                            # reason `no_probe_path` is: a question that
                            # cannot be asked must not cost a request. `kind`
                            # (`schema.sql`, `idempotent_read` /
                            # `state_changing` / `unknown`) records the same
                            # fact and is not in this SELECT; the method is,
                            # it is what `surface.kind_for` derives `kind`
                            # FROM, and it is the narrower test -- `kind`
                            # calls OPTIONS an idempotent read, and `GET /x`
                            # is still not the surface `OPTIONS /x` names.
                            #
                            # AND A `HEAD` SURFACE LEAVES BY THE SAME DOOR,
                            # which is finding 9 of the final review and the
                            # second reason `kind` is the wrong test: `kind`
                            # calls HEAD an idempotent read too. It was
                            # probed for a round because a GET sees
                            # everything a HEAD could have shown -- safe for
                            # a `clean` row, and not safe for a FINDING,
                            # since three of the five checks match on a
                            # response BODY and a HEAD response has none. The
                            # skip is spelt with this same vocabulary rather
                            # than a new word: the fact an operator needs is
                            # identical, that hx could not address the
                            # surface the row names.
                            _skip(conn, row_id, summary, "not_a_get_surface",
                                  "this surface was captured as a "
                                  f"{surface[1]} request and this build can "
                                  "send nothing but a GET (body and mutating "
                                  "probes are outside this build by design), "
                                  "so a probe here would be a request to a "
                                  "different surface -- a method is part of "
                                  "a surface's identity -- and the check was "
                                  "not run, not run clean")
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
                            # all -- a check WITH declared kinds already
                            # skipped, deriving nothing from an exemplar that
                            # was not there):
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
                        if exemplar_request is _UNREAD:
                            exemplar_request = _exemplar_request(
                                blobs, surface, exchanges)
                        probe_path = (
                            None if exemplar_request is None
                            else insertion_mod.request_path(exemplar_request))
                        if probe_path is None:
                            # THE SURFACE ROW IS AN IDENTITY, NOT AN ADDRESS.
                            # `path_template` is what `hx.surface` normalised
                            # this endpoint to -- `/user/{id}/profile` for
                            # every id -- and a probe sent there reaches a URL
                            # that cannot exist. The address is the exemplar
                            # request's own path, and when that cannot be read
                            # (no blob, a corrupt one, a request line with no
                            # target, `OPTIONS *`) there is nowhere honest to
                            # send anything. Decided BEFORE a sender exists,
                            # like the `no_exemplar` skip above it, so no
                            # traffic is spent on a question that could not
                            # have been asked.
                            _skip(conn, row_id, summary, "no_probe_path",
                                  "this surface's exemplar request does not "
                                  "yield a concrete path to probe, and a "
                                  "surface's path_template is its identity "
                                  "rather than an address; the check was not "
                                  "run, not run clean")
                            continue
                        wanted = frozenset(getattr(
                            check, "insertion_kinds", frozenset()) or ())
                        if wanted and insertions is None:
                            insertions = insertion_mod.derive(
                                exemplar_request, surface[5])
                        # A check declaring NO insertion kinds is not skipped
                        # for having no points: it shapes its own request --
                        # a header it adds, a method it re-issues -- rather
                        # than filling in a parameter it found. That is the
                        # shape `hx.active.cors` takes
                        # (`src/hx/checks/active/cors.py`, registered on this
                        # branch): its `insertion_kinds` is empty on purpose,
                        # and skipping a check for having none of what it
                        # never asked for would silence the first check in
                        # this build that sends.
                        declared = tuple(i for i in (insertions or ())
                                         if i.kind in wanted)
                        # A POINT THE SEND PATH WILL REFUSE IS NOT HANDED OVER.
                        # F2 of the whole-branch review: `insertion.derive`
                        # sorts by `(kind, name)`, so `cookie` came first, and
                        # `hx.active.reflected-input` spent its first probe of
                        # every cookie-bearing surface on a request
                        # `Sender.decide()` refuses by design
                        # (`unmanaged_credential`) -- taking the whole check
                        # down with it and never reaching the query and
                        # path-segment points that would have worked. The
                        # refusal is a property of the POINT rather than of
                        # the payload, so it is decidable here, before a
                        # sender exists and before any budget is spent.
                        # DECIDED IN ONE PLACE, `probe.unprobeable`, rather
                        # than in each check that declares a `header` or
                        # `cookie` kind. What a client is told about the
                        # coverage this costs is `report._limits`'.
                        refusals = tuple(probe.unprobeable(i) for i in declared)
                        usable = tuple(i for i, why in zip(declared, refusals)
                                       if why is None)
                        if wanted and not usable and declared:
                            # A DIFFERENT FACT FROM `no_insertion_point`, and
                            # it gets its own key because the two send an
                            # operator to different places: one says this
                            # surface has nothing of the kind this check
                            # wants, the other says it has them and none can
                            # be reached.
                            _skip(conn, row_id, summary,
                                  "no_probeable_insertion_point",
                                  f"the {len(declared)} insertion point(s) of "
                                  f"kind {sorted(wanted)} on this surface are "
                                  "all ones the send path refuses to carry a "
                                  "probe to -- a cookie, or one of the "
                                  "credential headers "
                                  f"{sorted(probe.CREDENTIAL_HEADERS)} the "
                                  "extension did not inject -- so there was "
                                  "nowhere for this check to put a payload it "
                                  "could send; it was not run, not run clean"
                                  # WHICH POINTS, not merely that there were
                                  # some. Concern 5 of fix round 3:
                                  # `unprobeable` builds a sentence per point
                                  # naming which of its two rules refused it,
                                  # and this was the only caller -- it tested
                                  # each for `None` and threw the strings
                                  # away, so no row an operator could read
                                  # ever said whether a cookie or a credential
                                  # header was what stopped the check.
                                  #
                                  # `refusals` GOES IN WHOLE. Every entry on
                                  # this branch is a sentence: it is reached
                                  # only when `usable` is empty, which is
                                  # exactly when no `unprobeable` answered
                                  # `None`. A filter here would be a guard no
                                  # input can exercise.
                                  + _http._detail(refusals))
                            continue
                        if wanted and not usable:
                            _skip(conn, row_id, summary, "no_insertion_point",
                                  "no insertion point of kind "
                                  f"{sorted(wanted)} on this surface, so "
                                  "there was nowhere for this check to put a "
                                  "payload; it was not run, not run clean")
                            continue
                        sender = probe.ProbeSender(
                            bridge, scheme=surface[2], host=surface[3],
                            port=surface[4], path=probe_path,
                            identity_id=identity_id)
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
                    reason = verdict.reason
                    # An `inconclusive` verdict carries no `considered` -- the
                    # classmethod does not offer it -- so this loop is empty
                    # for exactly the state that must retire nothing, and
                    # `_retirable` empties it for every check the runner
                    # drove through the wire. The verdict itself is not
                    # touched either way: a `finding` is still written and
                    # still reported, a `clean` is still `clean`, and what
                    # `report._coverage` renders for the row is unchanged.
                    for issue_type in _retirable(hook, verdict):
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
                               requests_sent=_spent(summary, sender, bracket))
                    continue
                except Exception as exc:                    # noqa: BLE001
                    _close_row(conn, row_id, "error",
                               f"{type(exc).__name__}: {exc}",
                               requests_sent=_spent(summary, sender, bracket))
                    continue
                _close_row(conn, row_id, verdict.state, reason,
                           requests_sent=_spent(summary, sender, bracket))

        if bracket is not None:
            # BEFORE `_mark_unobserved`, and that ordering is load-bearing.
            # The closing canary is what settles the run's state -- a window
            # is only proof if BOTH its canaries passed -- and retirement is
            # the last thing this function does that a state could change.
            bracket.finish()
            summary.identity_state = bracket.state
        _mark_unobserved(conn, engagement_id, run_id, seen_findings, considered)
    except BaseException as exc:
        # Left `running` here would mean the NEXT scan.run() call inherits
        # this one's half-finished state via current_run's reuse window --
        # the same collision this try/except exists to prevent, but for a
        # crash instead of a fast retest. `error`, not `completed`: S5 "an
        # aborted run must never render as a clean one."
        run_mod.close_run(conn, run_id=run_id, status="error",
                          stop_reason=_halt_reason(exc))
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
    # `no_bridge`, `not_a_get_surface`, `no_exemplar`, `no_probe_path`,
    # `no_insertion_point` and `no_probeable_insertion_point`, and all belong
    # in this sentence for the reason the budget one does: a pass that left
    # rows `skipped` did not do everything it set out to do, and the run row
    # is where a report decides whether to trust it. The word stays
    # `truncated` and the KEY is what distinguishes them -- `truncated:
    # skipped no_bridge=4` says which four rows to go and read, which is more
    # than a differently-worded prefix would have said.
    #
    # AND A SKIP IS NOT THE ONLY WAY TO STOP SHORT -- F11 of the whole-branch
    # review. `budget_exhausted` never reaches `by_reason`: it arrives as a
    # refusal, closes its `check_run` row `inconclusive`, and left a scan
    # that spent its whole `max_requests` at surface 10 of 500 closing
    # `('completed', NULL)`, byte-identical at the run row to a pass that
    # covered all 500. It was recoverable from the coverage rows, so the run
    # row was incomplete rather than false -- but S12's subject is exactly
    # telling a complete pass from an incomplete one, and `stop_reason` is
    # where that is said. The two tallies are labelled rather than merged:
    # `skipped` names rows the runner never ran, `probes refused` names the
    # wire's own classes on rows that did run, and an operator chasing one
    # looks in a different place from an operator chasing the other.
    parts = []
    if summary.by_reason:
        parts.append("skipped " + ", ".join(
            f"{k}={v}" for k, v in sorted(summary.by_reason.items())))
    if summary.refused:
        parts.append("probes refused " + ", ".join(
            f"{k}={v}" for k, v in sorted(summary.refused.items())))
    stop_reason = f"truncated: {'; '.join(parts)}" if parts else None
    run_mod.close_run(conn, run_id=run_id, status="completed",
                      stop_reason=stop_reason)
    return summary


def _halt_reason(exc) -> str:
    """What a run that RAISED writes to `run.stop_reason`.

    ONE EXCEPTION TYPE DOES NOT GET TO SPEAK FOR ITSELF HERE, and F1 of fix
    round A is why. This string is stored and then RENDERED:
    `report._provenance` puts a non-completed run's `stop_reason` on the
    client-facing page, through a `_redact` that is `records.redact_url` and
    strips URL userinfo and nothing else. `IdentityDead` is the one exception
    reaching this line whose text is assembled from something outside this
    process -- a refresh command's own output, by way of
    `hx.identity.refresh` -- so its text is not what is stored. Its
    `stop_reason`, composed at the raise site from an identity id and which
    phase of the bracket failed, is.

    EVERY OTHER EXCEPTION KEEPS ITS TEXT, and that is a decision rather than
    an omission. A `sqlite3.Error`, a `BridgeError` or a `codec.FrameError`
    says what happened and there is nothing else available to say it;
    `report._provenance`'s own comment has named this field
    attacker-influenceable free text since fix round B and routes it through
    `_redact` for that reason; and narrowing it to a bare type name would
    take away the only diagnosis a crashed run has. What made `IdentityDead`
    different is not that its text is untrusted -- all of them are -- but
    that a SUBPROCESS'S STDERR reached it, which no other exception on this
    path can do.
    """
    if isinstance(exc, IdentityDead):
        return f"scan.run raised: IdentityDead: {exc.stop_reason}"
    return f"scan.run raised: {type(exc).__name__}: {exc}"


# --- the identity a run issues under --------------------------------------


def _identity_bracket(bridge, config, identity, checks, surfaces,
                      surface_filter, summary):
    """The identity in force for this run, or None for an anonymous one.

    FOUR WAYS TO GET NONE, and every one of them means "this run issues
    nothing under an identity" rather than "the identity was ignored":

      * no bridge. `run()` has no route to the wire at all and every probing
        check is about to be skipped `no_bridge`, so there is no traffic to
        bracket.
      * no check the runner drives through the wire. `needs_a_bridge` is the
        same question `hx scan` asks before it pays for a JVM; a bracket here
        would put two canary requests on a client's system for a pass that
        sends nothing else.
      * no surface this run will probe. The canary is ordinary traffic and
        needs an address, and there is no honest one to invent for a run with
        nowhere to send anything.
      * nothing declared. No `identity=` and no `config.scan_identity`.

    ASKED IN THAT ORDER, CHEAPEST AND MOST INERT FIRST. Resolution is last
    because it is the only step with a side effect outside this process: a
    static identity reads the environment and RAISES when the variable is
    missing, and a programmatic one runs the operator's refresh command. A
    run that was never going to send should do neither.
    """
    if bridge is None or not any(needs_a_bridge(c) for c in checks):
        return None
    target = next((s for s in surfaces
                   if surface_filter is None or surface_filter(s)), None)
    if target is None:
        return None
    resolved = identity if identity is not None else _resolve_scan_identity(config)
    if resolved is None:
        return None
    return _IdentityBracket(bridge, resolved, _declaration(config, resolved.id),
                            target=target, origins=tuple(config.scope_include),
                            summary=summary)


def _resolve_scan_identity(config):
    """The identity `config.scan_identity` names, resolved, or None.

    THE ONLY READER OF THAT FIELD IN THE PRODUCT. Spec section 4 gives an
    operator `scan_identity: user` and the loader validates that it names a
    declared identity; without this, that would be a config key nothing acts
    on, which is the state section 1 opens by complaining about ("`config.
    yaml` accepts an `identities` block that nothing reads").

    THE ENVIRONMENT IS READ HERE AND NOWHERE ELSE ON THIS PATH. `resolve`
    takes the mapping as an argument precisely so that the read is at a call
    site rather than buried in the resolver, and the value it returns is a
    `Resolved` -- which never touches `Config` and never reaches
    `scope_version.yaml`.

    A PROGRAMMATIC IDENTITY IS MINTED, NOT READ. It has no `value_from_env`
    to resolve (`resolve` refuses one by name), so its first credential comes
    from the same command a refresh would run. Generation 0 is the
    "nothing registered yet" value: `refresh` returns `generation + 1`
    unconditionally, so the first mint is generation 1 -- the same number
    `resolve` gives a static identity, and the lowest `codec.identity_body`
    will carry.
    """
    if config.scan_identity is None:
        return None
    declared = _declaration(config, config.scan_identity)
    if declared.strategy == "static":
        return identity_mod.resolve(declared, dict(os.environ))
    return identity_mod.refresh(declared, 0)


def _declaration(config, identity_id):
    """The `Identity` declaration behind an id, which must exist.

    A `Resolved` carries the credential and not the liveness proof, so the
    canary, the refresh command and `every_n_probes` all come from the
    config's own declaration. An id with none is a caller's mistake rather
    than an operator's: `config.load_text` refuses a `scan_identity` naming
    an undeclared identity, so this is only reachable by passing `identity=`
    a `Resolved` this config never declared -- and section 4 requires a
    liveness block for every identity precisely because one without a proof
    could never be `proven`.
    """
    declared = config.identities.get(identity_id)
    if declared is None:
        raise ValueError(
            f"identity {identity_id!r} is not declared in this config, so it "
            "has no liveness proof and a run cannot be bracketed by one. "
            f"Declared: {sorted(config.identities) or 'none'}")
    return declared


class _IdentityBracket:
    """One run's identity, and the canaries that bracket its traffic.

    SPEC SECTION 6 IS THE WHOLE OF THIS CLASS. A canary at the start of a run
    proves the session was live AT THE START and says nothing about the
    request issued an hour later, so `proven` is a property of a window
    bracketed by two passing canaries: one at the start, one every
    `every_n_probes` probes, one at the end always. `hx.identity.
    IdentityWindow` holds that bookkeeping; this holds the traffic and the
    decisions.

    THE WINDOW IS OPENED ONCE PER BRACKET, WITH THE SETTLED RESULT. `open()`
    latches its FIRST argument for the life of the run -- the run either had
    a proved starting point or it did not -- so a driver that called it once
    per raw canary attempt would record `dead` for a run that failed its
    opening canary, refreshed, passed, and by section 6's table CONTINUES.
    `_settle` therefore does the refresh-and-re-canary dance first and
    returns both halves of the answer: what the canary said, and what it said
    once the one refresh a programmatic identity gets had been tried.

    THE TWO HALVES ARE USED FOR DIFFERENT THINGS, and that is not a
    duplication. The settled half decides whether the run goes on; the raw
    half decides what to say about the window that just ENDED, because a
    canary that failed means the traffic behind it was issued into an unknown
    state whether or not a refresh then brought the session back. Section 6:
    "When a canary fails, every exchange back to the last passing canary is
    downgraded from `proven` to `assumed`."
    """

    def __init__(self, bridge, resolved, declared, *, target, origins,
                 summary) -> None:
        self._bridge = bridge
        self._declared = declared
        # (scheme, host, port) from the run's own first surface. The canary is
        # ordinary traffic and needs an address; `liveness.path` is
        # origin-form (the config loader refuses anything else), so the origin
        # comes from a surface this run is actually going to probe rather than
        # from a scope pattern, which may be a glob with no host in it. A run
        # spanning several hosts proves its session on this one: an identity
        # declares ONE `liveness` block (section 4), so its proof is per
        # identity and not per host.
        self._target = (target[2], target[3], target[4])
        # Section 5: `origins` bounds where the credential may be applied and
        # "defaults to the hosts in `scope.include`". The extension reads the
        # host out of each entry (`Sender.hostOf`: everything after `://` and
        # before the first `/`, `:` or `?`), so a URL-prefix pattern bounds
        # the credential to that host and a pattern with no host in it bounds
        # it to nothing -- fail-closed, and visible as an `identity_origin`
        # refusal rather than as a credential going somewhere it should not.
        self._origins = origins
        self._summary = summary
        self.resolved = resolved
        self.window = identity_mod.IdentityWindow(
            due_every=declared.liveness.every_n_probes)
        self._due = False

    @property
    def identity_id(self) -> str:
        return self.resolved.id

    @property
    def state(self) -> str:
        return self.window.state_for_run()

    def start(self) -> None:
        """Register the credential, prove the session, open the window.

        The registration is NOT wrapped: `register_identity` raises
        `BridgeError` or `codec.FrameError` and each says what actually
        happened -- see `IdentityDead`'s own docstring.
        """
        self._bridge.register_identity(self.resolved, origins=self._origins)
        _raw, settled = self._settle()
        self.window.open(passed=settled)
        if not settled:
            raise IdentityDead(
                f"identity {self.resolved.id!r} could not be proved live "
                f"before the first probe: {self._declared.liveness.path} did "
                "not answer with the signature this identity is declared to "
                "prove itself by. Halting rather than scanning anonymously: "
                "an unauthenticated run of an authenticated application "
                "answers `clean` about a view none of its users are in",
                stop_reason=(f"identity {self.resolved.id!r} could not be "
                             "proved live before the first probe"))

    def note(self, probes: int) -> None:
        """Count probes issued inside the current window.

        Called once per `check_run` row with what that row's sender issued,
        so the canary falls due AT A CHECK BOUNDARY rather than between two
        probes of one check: a check that sends 60 probes with
        `every_n_probes` at 25 draws one canary after it, not two during it.
        The count then restarts FROM that canary rather than carrying a
        remainder: `note_probe` zeroes its own counter each time it comes
        due, and `IdentityWindow.open` zeroes it again when the next window
        opens. So `every_n_probes` bounds how much traffic one undetected
        death can contaminate -- which is what section 6 asks of it -- rather
        than fixing the exact request a canary lands on.
        """
        for _ in range(probes):
            if self.window.note_probe():
                self._due = True

    def canary_if_due(self) -> None:
        """The mid-run canary, if `every_n_probes` have gone by.

        A failure closes the window that just ended as unproven WHETHER OR
        NOT the refresh below rescues the run -- section 6's downgrade -- and
        a session that cannot be brought back halts the run here, with probes
        still to come.
        """
        if not self._due:
            return
        self._due = False
        raw, settled = self._settle()
        self.window.close(passed=raw)
        if not settled:
            raise IdentityDead(
                f"identity {self.resolved.id!r} stopped being live during the "
                f"run: {self._declared.liveness.path} no longer answers with "
                "the signature it is declared to prove itself by. Halting "
                "rather than issuing the rest of this run's probes "
                "unauthenticated, which would answer `clean` for every "
                "surface still to come",
                stop_reason=(f"identity {self.resolved.id!r} stopped being "
                             "live during the run"))
        self.window.open(passed=True)

    def finish(self) -> None:
        """The closing canary, which always runs and never halts.

        Section 6 requires one at the end of the run "always, even if no
        probe was sent since the last one", because a window is only proof if
        BOTH its canaries passed. It does not raise: see `IdentityDead`.

        No refresh either, and for the same reason -- a refresh exists to
        keep the run's remaining traffic authenticated, and there is none.
        Renewing the session here would be a request on a client's system
        that buys nothing, and it would also hide the failure this canary
        exists to report.
        """
        self.window.close(passed=self._canary())

    def _settle(self) -> tuple[bool, bool]:
        """`(what the canary said, what it said after the one refresh)`.

        Section 6's outcome table, implemented literally. A passing canary
        settles as itself. A failing one on a `static` identity settles as
        itself too -- there is no command to run -- and the caller halts. A
        failing one on a `programmatic` identity gets exactly one refresh,
        re-registered AT THE NEW GENERATION, and the canary is asked again.

        THE NEW GENERATION IS WHAT MAKES THE RE-REGISTRATION MEAN ANYTHING.
        `IdentityRegistry.register` keeps the entry it already holds for an
        EQUAL generation ("a second frame at the SAME generation carrying a
        DIFFERENT credential swapped it silently: a content change that never
        advanced the counter whose whole job is to gate content changes") and
        refuses a lower one. So a refresh that did not advance would be
        accepted, change nothing, and leave the run issuing under the dead
        credential -- which is why `hx.identity.refresh` returns
        `generation + 1` unconditionally.
        """
        raw = self._canary()
        if raw or self._declared.strategy != "programmatic":
            return raw, raw
        try:
            self.resolved = identity_mod.refresh(self._declared,
                                                 self.resolved.generation)
        except identity_mod.IdentityError as exc:
            # The session is dead and cannot be renewed, which is this
            # exception's own subject -- the cause is chained, so the
            # command's exit code or its empty output is still in the
            # traceback an operator reads.
            #
            # `{exc}` IS IN THE MESSAGE AND NOT IN THE `stop_reason`, and
            # that is F1 of fix round A in one line. This is the only place
            # in the runner where a string built outside the process reaches
            # an exception a halted run records: `hx.identity.refresh` no
            # longer repeats the command's stderr, and this half keeps the
            # containment even if a future message there does.
            raise IdentityDead(
                f"identity {self.resolved.id!r} failed its canary and could "
                f"not be refreshed: {exc}",
                stop_reason=(f"identity {self.resolved.id!r} failed its "
                             "canary and its refresh command failed too")
            ) from exc
        self._bridge.register_identity(self.resolved, origins=self._origins)
        return raw, self._canary()

    def _canary(self) -> bool:
        """One liveness request, through the ordinary send path.

        Section 6: "The canary is ordinary traffic. It goes through the send
        path like any other request, carries the identity, and is subject to
        scope, the method allowlist, the rate limit and the budget." So it is
        a `ProbeSender` like a check's -- which also means a refusal is a
        FAILURE and not an exception (`hx.identity.canary` catches
        `ProbeRefused`): a canary that could not be sent has proved nothing.

        A FRESH SENDER PER CANARY, so `sent` and `refused` are this canary's
        own. `_spent` folds those refusals in where the probes' are counted,
        rather than letting them vanish because no `check_run` row owns them,
        and is passed no bracket, because a canary is not a probe.
        """
        scheme, host, port = self._target
        sender = probe.ProbeSender(
            self._bridge, scheme=scheme, host=host, port=port,
            path=self._declared.liveness.path, identity_id=self.resolved.id)
        try:
            return identity_mod.canary(self._declared.liveness, sender)
        finally:
            self._summary.canary_requests += _spent(self._summary, sender)


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
    trip to ask something the caller is already holding. `_exemplar_request`
    resolves the same id the same way, a few lines down, for the same reason.
    """
    exemplar_id = surface[6]
    if not exemplar_id:
        return None
    return exemplar_id if any(x.id == exemplar_id for x in exchanges) else None


def _retirable(hook, verdict) -> tuple[str, ...]:
    """The issue types this verdict may retire a finding on.

    AN ACTIVE CHECK RETIRES NOTHING. Retirement is `_mark_unobserved`
    writing `observed = 0`, which `report._findings` renders to a client as
    "appears fixed; verify before closing" -- a claim about the application
    as the client's own users meet it. Every probe this build sends is
    UNAUTHENTICATED (`ProbeSender._request_bytes` emits a request line, a
    `Host` and at most the one header the check is probing), so an active
    check's `clean` is a statement about the logged-out view and nothing
    else. It is reported, because a reflection found in the logged-out view
    is still a reflection; it may not close anything.

    DECIDED OFF `hook`, WHICH IS THE DISPATCH ITSELF. `run` picks the probe
    pass with the same value, `registry._HOOKS` gives `probes` to the four
    active classes and `on_surface` to `passive`, and `validate()` refuses
    at import a check whose class and hook disagree. So a sixth active check
    inherits this by being an active check: there is no list of check ids
    here to update, and no rule for its author to remember.

    IT RAISES RATHER THAN DROPPING QUIETLY, and that is the half that keeps
    the two ends of the rule together. The five active checks pass what they
    examined to `_probe_util.verdict` as `examined`, which uses it to refuse
    a `clean` that tested nothing and does NOT put it on the verdict -- so a
    probing check reaching here with a non-empty `considered` is one whose
    author believed it would retire something. Silently discarding it would
    leave that belief in the tree, unfalsified, exactly as fix round 5's
    suppression would have. `run`'s per-check `except Exception` turns this
    into an `error` row for that check, which is loud, retires nothing, and
    ends no scan.

    WHY THE SEVENTH SPELLING FORCED THIS. Six ways an active check could
    answer `clean` off a probe that tested nothing were closed by the status
    doctrine (`_probe_util.unanswered`), by the skips in `run` above, and by
    `_probe_util.verdict`'s `unprobed` branch -- and the EIGHTH was closed by
    that same doctrine a round later, when it stopped being an enumeration of
    refusing statuses and became the rule that only a 2xx is an answer. The
    seventh is an application that answers a logged-out request with a 200
    LOGIN PAGE: a complete, well-formed, application-composed response,
    indistinguishable from an answer at every level a status rule operates.
    That one is an ARGUMENT AND NOT A MEASUREMENT, and saying otherwise is a
    mistake this branch has already made once: fix round 3 measured five
    `clean` rows and a retired finding behind a `302 /login` (see
    `_probe_util.unanswered`), which is the shape a status CAN catch and is
    now caught. A fixture whose anonymous view differs from its anonymous
    view does not exist, so the 200 login page has never been put in front of
    this corpus and cannot be.

    WHAT IS MEASURED is the same `clean` arriving off a genuine answer:
    `tests/integration/test_active_checks.py::test_a_second_scan_is_stable_
    and_a_wholly_fixed_target_retires_nothing` repairs all five vulnerable
    routes and, with this function passing `considered` through, closes all
    five findings -- `[1, 1, 0]` each, rendered five times as "appears fixed;
    verify before closing". Nothing in those rows distinguishes them from
    what a login page would have produced, which is the whole argument.

    Fix round 5 tried to contain the login page by suppressing retirement
    only where the surface's captured request carried a credential header.
    Its own report established why that could not hold: the predicate keyed
    on the exemplar, which is
    the FIRST sighting, so a surface browsed logged-out and then logged-in
    stayed "anonymous" and went on retiring -- the unsafe direction -- and
    more fundamentally `Redactor.redactObservedRequest` replaces a
    credential header's VALUE before the bytes are hashed (S7), so only the
    NAME survives and an analytics or consent cookie is indistinguishable
    from a session. The discriminator could not see what it claimed to.
    Retirement is a passive-corpus property until probes can authenticate.

    THE PASSIVE CORPUS IS UNTOUCHED, and the asymmetry is not a compromise:
    a passive check reads the captured traffic ITSELF -- the very exchanges
    the operator's own browser produced, session and all -- so it was never
    looking at a different view of the application, and this whole question
    is one only a re-issued request can have.

    THE ACCEPTED COST, stated where the decision was taken: the active
    corpus has no automatic retest story at all. A client re-running a scan
    after a fix sees the active finding still listed, and must verify it by
    hand before closing it. `report._limits` says so in as many words.
    """
    if hook != _PROBE_HOOK:
        return verdict.considered
    if verdict.considered:
        raise ValueError(
            "an active check returned considered="
            f"{list(verdict.considered)}; a check the runner drives through "
            "the wire may not retire anything, because every probe this "
            "build sends is unauthenticated and cannot tell the client's "
            "own view of the application from the logged-out one. Pass what "
            "was examined to `_probe_util.verdict` as `examined` instead -- "
            "it is what lets a check say `clean` -- and leave `considered` "
            "to the passive corpus")
    return ()


# "Not read yet", and it cannot be `None` -- see the surface loop. Both facts
# a caller needs (the concrete probe path, the insertion points) come off one
# blob read, and `None` is already the answer to "read it; there is nothing
# there".
_UNREAD = object()

# The surface methods a probe can honestly address, and there is exactly one.
# `ProbeSender._request_bytes` builds a GET and only a GET, and a surface's
# method is part of its identity -- so a GET probe answers for a `GET`
# surface and for nothing else.
#
# `OPTIONS` AND `HEAD` ARE BOTH OUT, ON THE SAME ARGUMENT. S4's method
# allowlist permits both and `surface.kind_for` calls both idempotent reads,
# but `OPTIONS /x`, `HEAD /x` and `GET /x` are three surface rows and a check
# may not close one by testing another. `HEAD` was admitted for a round on an
# RFC 9110 s9.3.2 reading -- HEAD is GET without the body, so a GET probe
# sees everything the captured request could have shown and more -- which is
# sound for a `clean` row and NOT sound for a finding: `reflected_input`,
# `sql_error` and `path_traversal` read a response HEAD OR BODY, and a HEAD
# response has no body, so a body-derived finding filed against a `HEAD`
# surface describes something that surface never does, in a description that
# does not say the method was changed. The exclusion is therefore wider than
# the hazard -- a HEAD surface really can reflect into a header, and that
# finding is given up with the unsound ones -- and it is still the right
# trade, because the identity argument does not distinguish them: a GET is
# not the request the client's users make to that surface either way. Finding 9 of the final review, ruled
# the way the OPTIONS line four rows up was already ruled: the consistency is
# worth more than the coverage, and browsers rarely issue HEAD anyway.
#
# Case-sensitive, for the reason `surface.kind_for` gives: `get` is not GET,
# and a lowercase verb must not inherit a safe method's permissions.
_PROBEABLE_METHODS = frozenset({"GET"})


def _exemplar_request(blobs, surface, exchanges) -> bytes | None:
    """This surface's exemplar REQUEST bytes, or None if they cannot be read.

    `surface.exemplar_exchange_id` -> that exchange's `req_blob` -> bytes is
    the path `hx.insertion`'s own docstring names, and the same one
    `hx.report._insertion_coverage` walks. The exemplar is found in the rows
    already fetched for this surface rather than by a second query: it is the
    first exchange that proved the surface exists (`hx.capture`), so it is
    one of them.

    TWO DERIVATIONS, ONE READ. `insertion.derive` turns these bytes into the
    points a check may fill in, and `insertion.request_path` turns them into
    the address a probe is sent to. Reading the blob once per surface rather
    than once per question is why this returns the bytes instead of either
    answer.

    EVERY FAILURE IS `None`, not a raise. A surface whose blob is gone is a
    surface no active check can probe -- which the caller has words for,
    `skipped` with a reason -- and taking the whole scan down over one
    unreadable row is the trade S12 argues against. `CorruptBlob` is caught by
    name for the reason F8 gives one layer up: a bare `except Exception` here
    would swallow `blobs=None`, and a caller's own programming error is meant
    to surface.

    THE MISSING-EXEMPLAR CASE NO LONGER ARRIVES HERE, and the two lines that
    answer it are kept anyway. `run()` skips an active check on a surface whose
    exemplar is NULL or dangling before this is called (`_citable_exemplar`),
    because that surface has no evidence for a finding to cite whether or not
    a probe could be built from it. This function is still pure and still
    total for the same input, so the guard costs two lines and means a second
    caller cannot inherit a crash.
    """
    exemplar_id = surface[6]
    if not exemplar_id:
        return None
    digest = next((x.req_blob for x in exchanges if x.id == exemplar_id), None)
    if not digest:
        return None
    try:
        return blobs.get(digest)
    except blobs_mod.CorruptBlob:
        return None


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


def _spent(summary, sender, bracket=None) -> int:
    """What this check's sender issued, folding what it was refused into the
    run's tally -- and its issuances into the identity window -- on the way
    past.

    ONE CALL PER ROW, at each of the three places a probing row can close.
    `requests_sent` and `summary.refused` are two halves of the same fact --
    what this check spent, and what it did not get to spend -- and reading
    them at one point is what keeps the second from being counted twice or
    missed on the `error` path. THE WINDOW IS COUNTED HERE FOR THAT SAME
    REASON: spec section 6 puts a canary every `every_n_probes` PROBES, and
    this is the one place that sees every probe a row issued however the row
    ended. `bracket` is None for an anonymous run and for the canary's own
    sender -- a canary is not a probe, and counting it toward the schedule
    it is itself running would be a canary counting itself down.

    THE RUNNER CANNOT SEE THESE REFUSALS ANY MORE, which is why they are read
    off the sender rather than counted where `except ProbeRefused` sits.
    Since F2 a check catches its own refusals per insertion point and returns
    a verdict, so most refusals never propagate here at all -- and the run row
    still has to be able to say the pass ran out of budget.
    """
    if sender is None:
        return 0
    for cls, n in sender.refused.items():
        summary.refused[cls] = summary.refused.get(cls, 0) + n
    if bracket is not None:
        bracket.note(sender.sent)
    return sender.sent


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

    AND SINCE FIX ROUND 6, ONLY A PASSIVE CHECK EVER GETS INTO IT.
    `scan.run` reads `_retirable`, which returns nothing for a check driven
    through the wire: every probe this build sends is unauthenticated, so an
    active `clean` is a statement about the logged-out view and not about
    the one the client's users are in. That function carries the argument
    and the two spellings the branch tried before it. So "in `considered`"
    means "examined, by a check that read the captured traffic itself", and
    that is the only reading under which retirement is sound today.

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
