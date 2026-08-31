"""The active corpus against a real Burp and a real, genuinely vulnerable
target -- the first traffic this project has ever aimed at a flaw.

EVERY BYTE STAYS ON THIS MACHINE. The five checks under test send a canary, an
unmatched quote, a six-level traversal, an arbitrary `Origin` and a marker URL,
at whatever host the surface names -- so the only thing standing between this
suite and somebody else's server is that the surfaces here can name nothing but
the fixture's own loopback target. Every path browsed below comes from
`target_server.VULNERABLE_ROUTES` and is browsed through `rig.browse`, which
builds its absolute URI from `rig.target.origin` and nothing else; the
constructor of that server refuses any address outside 127.0.0.0/8. No test in
this file takes a hostname from anywhere.

WHAT DRIVES THE SCAN, AND WHY IT IS NOT `hx scan`. The brief's shape is `hx
capture start` -> browse -> `hx scan`. The rig IS that first command's product
-- a live, loopback-verified Burp with an authorised extension and a
`BridgeServer` on the other end of it -- and `hx scan`'s only extra move is to
open a second one (`cli.py` calls `session.session(...)` when an active class is
enabled, which `tests/integration/test_cli_session.py` already drives end to end
against the real CLI). Spending a second 900 MB JVM per test here would buy a
second copy of that coverage and nothing about the checks. So the scan is
`scan.run(..., bridge=rig.srv)`: the same call `hx scan` makes, handed the same
kind of bridge, against the Burp the rig already has.

AND IT RUNS AT THE RIG'S OWN 3/s, WHICH IS THE POINT OF THE FILE AS MUCH AS THE
CHECKS ARE. `hx.policy.Limiter` REFUSES an over-rate request rather than
queueing it, so sixteen probes at three a second are only reachable if the
sender obeys the `retry_after_us` the refusal carries. This file first ran with
the rate raised to 200 -- a fixture knob that hid the missing half of that
contract, documented at the call site so no green run could be read as evidence
that an unpaced scan works. The half is written now (`hx.checks.probe`), the
knob is gone, and the invariant below (`sum(requests_sent)` == what the target
received == `PROBES_PER_SCAN`) has to hold THROUGH the refusals and the waits:
every probe eventually issued exactly once, counted exactly once, and seen by
the target exactly once.

AND ONE SURFACE WHOSE PATH THE NORMALISER TEMPLATES, WHICH IS THE THIRD TEST
BELOW. Every route in `VULNERABLE_ROUTES` is static, so `path_template ==
path` for all five surfaces above and `hx.surface`'s normaliser never ran on
any data this corpus was measured against. F1 of the whole-branch review lived
exactly there: all five checks probed `surface.path_template` literally, which
on a templated surface is an address that cannot exist, and every one of them
answered `clean` with `considered` populated -- retiring live findings from a
404. 35 integration tests and 1262 unit tests stayed green. The assertion that
would have caught it is against the TARGET's own request log, which is the one
witness this side cannot fake: what arrived, and that it carried no `{`.

WHAT ONLY A TARGET THAT CHANGES CAN SHOW, and why the second test below is the
point of the whole task: `test_scan_and_report.py` proves a finding is re-found
by a second scan, and its own claim 3 measures that a finding cannot be retired
by taking the target away -- the exchange that proves it is still on file, so
every passive check goes on answering `finding` for ever. Only an active check
can see a target actually change, and `target.fix(check_id)` is how one is made
to: every route is repaired, every check gets a complete answer and says
`clean` off a probe that really went, and NOT ONE finding closes.

That test asserted the opposite until fix round 6. It fixed CORS alone and
required that finding to retire while the four beside it stayed live, which was
`Verdict.considered` working end to end. Every probe this build sends is
unauthenticated, so an active `clean` is a statement about the logged-out view
of the application, and an application answering a logged-out request with a
200 login PAGE is indistinguishable from the genuine answers that test now
produces. `hx.scan._retirable` refuses the whole class rather than trying to
tell them apart; retirement is a passive-corpus property until probes can
authenticate.

AND TWO SURFACES NO CHECK MAY CLOSE, WHICH ARE THE LAST TWO TESTS. The same
blind spot as the templated path, twice more. Every route above answers 2xx
and every surface above is a GET, so until now no integration test had put
either a response the doctrine reads as a REFUSAL or a surface a probe cannot
address in front of a check -- and N1 and N2 of the scoped re-review lived in
exactly that gap, each caught by a human reading rather than by a suite. A
`302 Found / Location: /login` was read as a conclusive negative by every
check that had a point to probe, and retired a live finding; a `POST` surface
was probed with a GET,
which is a request to a different surface, and closed `clean` on the strength
of it. Both were fixed with coverage at `scan.run` against fake bridges. Here
they are measured through Burp, a socket and a server that answers.

AND ONE SURFACE THE BROWSER WAS LOGGED IN TO, WHICH IS THE LAST TEST AND THE
FOURTH INSTANCE OF THAT SAME BLIND SPOT. Every surface above was browsed
anonymously, so no captured surface in this file had ever carried a `cookie`
insertion point: F2's fix (a point the send path refuses is dropped rather
than probed) and the `no_probeable_insertion_point` skip that names WHICH
point were covered by fake bridges and by nothing end to end. `Rig.browse`
could always carry headers -- `test_proxy_capture.py` sends a session cookie
through it to prove the redaction -- but no active check had ever been run
against what that produces. The last test logs in through `/login`, browses
the two routes with the cookie `/login` issues, and measures the skip and its
per-point sentence; browsing carries a session because it goes through the
proxy listener's operator branch, which is scope-only, while every probe hx
issues is refused a credential header it did not inject. That asymmetry is
S4's operator/agent split, and `Rig.browse`'s own docstring carries it.
"""
from __future__ import annotations

import time
from collections import Counter

import pytest

from hx import insertion, report, scan
from hx.checks import base, probe, registry
from hx.checks.active import cors, reflected_input
from tests.integration.target_server import (
    LOGIN_WALL_ROUTE, SESSION_COOKIE_VALUE, STATE_CHANGING_ROUTE,
    TEMPLATED_ROUTE, TEMPLATED_SURFACE, VULNERABLE_ROUTES)

pytestmark = pytest.mark.integration

# What one scan of the five vulnerable surfaces costs, MEASURED (see
# `test_every_active_check_finds_its_own_endpoint`'s own assertion, which pins
# the number against the target server's log rather than against this constant).
# Five CORS probes, one per surface; four reflected-input probes plus one
# escalation on the surface that reflects; four sql-error probes; one open
# redirect; one traversal.
PROBES_PER_SCAN = 16

# Every check that SENDS. Read off the registry rather than spelled here, so a
# check added to the corpus without a vulnerable route (or without this file
# being thought about) fails in `test_target_server.py`'s route-map assertion
# and again here, rather than quietly never being scanned.
ACTIVE_CHECK_IDS = frozenset(c.id for c in registry.CHECKS if c.klass != "passive")


def rows(rig, sql: str, args=()) -> list[dict]:
    return [dict(row) for row in rig.eng.db.execute(sql, args).fetchall()]


def _configure(rig) -> None:
    """Authorise the extension AT THE ENGAGEMENT'S OWN RATE -- no knob.

    `rig.configure()` with no `rate_rps` sends the rate the engagement config
    carries, which this rig sets to 3/s (`conftest`, deliberately not
    `hx.config`'s default of 5 so that a configured rate and an ignored
    configure body are distinguishable). That is a production rate: S4 puts the
    profile in the single digits.

    IT USED TO SAY `rate_rps=200`, AND THE REASON IT NO LONGER DOES IS THE
    SUBJECT OF THIS FILE. `hx.policy.Limiter` refuses an over-rate request --
    `Decision.rateLimited(retryAfterUs, ...)` -- it does not block and it does
    not queue, and until fix round A nothing on the Python side consumed the
    hint. MEASURED here at 3/s before that: of the sixteen probes one scan
    issues, three were answered and every attempt after them came back
    `rate_limited` -- twelve `inconclusive` rows, one finding of the five, and
    four of the five checks never given an answer on any surface they were
    meant to find one on. Raising the rate made the checks measurable and hid
    that; `ProbeSender.get` waiting the hint out is what makes the raise
    unnecessary, and running here at 3/s is the only thing that proves it
    against a real limiter rather than a double.

    `limit.rate_rps` is armed on the FIRST configure of a run (see
    `conftest.build_config_body`), which is what this is.
    """
    assert rig.configure() == 1


def _browse_the_vulnerable_surfaces(rig) -> None:
    """One browse per vulnerable route, and the surfaces they produce.

    The query strings matter and are not decoration: `hx.insertion.derive`
    reads a surface's insertion points off its exemplar REQUEST, so a route
    browsed without its parameter offers a check nowhere to put a payload and
    is skipped `no_insertion_point` -- a green run in which four of the five
    checks never sent anything.
    """
    for path in sorted(VULNERABLE_ROUTES.values()):
        rig.browse("GET", path)
    rig.settle(
        lambda: len(rows(rig, "SELECT id FROM surface")) == len(VULNERABLE_ROUTES),
        f"one surface per vulnerable route ({len(VULNERABLE_ROUTES)})")


def _scan(rig, **kwargs) -> scan.ScanSummary:
    """The call `hx scan` makes, against the bridge the rig already has."""
    return scan.run(rig.eng.db, engagement_id=rig.eng.id, blobs=rig.eng.blobs,
                    config=rig.eng.config, bridge=rig.srv, **kwargs)


def _last_scan_run(rig) -> str:
    return rows(rig, "SELECT id FROM run WHERE engagement_id=? AND kind='scan'"
                " ORDER BY started_us DESC, rowid DESC LIMIT 1",
                (rig.eng.id,))[0]["id"]


def _check_runs(rig, run_id: str) -> list[dict]:
    return rows(rig, "SELECT c.check_id, c.verdict, c.reason, c.requests_sent,"
                " s.path_template FROM check_run c"
                " JOIN surface s ON s.id = c.surface_id"
                " WHERE c.run_id=? ORDER BY s.path_template, c.check_id",
                (run_id,))


def _active_findings(rig) -> list[dict]:
    return rows(rig, "SELECT f.id, f.check_id, f.issue_type_id, f.title,"
                " f.severity, f.insertion_name, s.path_template FROM finding f"
                " JOIN surface s ON s.id = f.surface_id"
                " WHERE f.engagement_id=? AND f.check_id LIKE 'hx.active.%'"
                " ORDER BY f.check_id", (rig.eng.id,))


def _observations(rig, finding_id: str) -> list[int]:
    return [r["observed"] for r in rows(
        rig, "SELECT observed FROM finding_observation WHERE finding_id=?"
        " ORDER BY ts_us, rowid", (finding_id,))]


# ---------------------------------------------------------------------------
# 1. Every active check finds its own endpoint, spends a bounded number of
#    requests doing it, and the report says so.
# ---------------------------------------------------------------------------

def test_every_active_check_finds_its_own_endpoint(rig):
    """The corpus meeting a target that actually answers its payloads.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? Every earlier test of these five
    checks fed them a hand-built `ProbeResponse` off a `FakeBridge`; not one of
    them proved that the bytes `ProbeSender` puts on the request line survive
    Burp, a socket and a real server, or that what comes back parses as the
    same response. A check whose payload was mangled in transit -- an
    unescaped `../` normalised by something in the middle, an `Origin` Burp
    declined to forward, a canary percent-encoded twice -- answers `clean` here
    and reddens the per-check assertion below, naming the route it failed on.
    """
    _configure(rig)
    _browse_the_vulnerable_surfaces(rig)
    hits_before = len(rig.target.hits)

    started = time.monotonic()
    summary = _scan(rig)
    elapsed = time.monotonic() - started
    assert summary.surfaces == len(VULNERABLE_ROUTES)

    run_id = _last_scan_run(rig)
    check_runs = _check_runs(rig, run_id)

    # NOTHING WENT WRONG QUIETLY. `error` is a bug in hx; an `inconclusive`
    # row that SENT something is what a refusal becomes (`rate_limited`,
    # `scope_denied`, a truncated response) or what a status the doctrine
    # will not read as an answer becomes. Either would leave a check looking
    # like it ran while it found nothing, which is the confusion S12 exists
    # to remove -- and `rate_limited` is exactly how this test failed the
    # first time it was run, at this same 3/s (see `_configure`). It passes
    # here because the sender waits the refusal's own `retry_after_us` out,
    # not because the fixture raised the rate.
    bad = [r for r in check_runs
           if r["verdict"] == "error"
           or (r["verdict"] == "inconclusive" and r["requests_sent"] > 0)]
    assert bad == [], f"a check neither ran nor was skipped: {bad}"

    # AN `inconclusive` ROW THAT SENT NOTHING IS A DIFFERENT FACT, AND THE
    # RIGHT ONE. N3 of the scoped re-review: `open_redirect` and
    # `path_traversal` probe a point only when its NAME matches their own
    # filter, so on somebody else's vulnerable route they decline before a
    # request exists. That used to read `clean` with `requests_sent = 0`,
    # which told `report._coverage` -- which counts surfaces per (check,
    # verdict) -- that the check had examined a surface it never sent
    # anything to. Asserted rather than waved past: only those two checks may
    # decline, never on their own route, and the row says why.
    for row in check_runs:
        if row["verdict"] != "inconclusive":
            continue
        assert row["check_id"] in {"hx.active.open-redirect",
                                   "hx.active.path-traversal"}, row
        own = VULNERABLE_ROUTES[row["check_id"]].split("?")[0]
        assert row["path_template"] != own, (
            "a check declined the very route the fixture built to be "
            f"vulnerable to it: {row}")
        assert "nothing was sent" in row["reason"], row

    # AND IT WAS PACED RATHER THAN LUCKY. `Limiter`'s window is a sliding log
    # of the last `rate_rps` issuances, so issuance k cannot happen until one
    # second after issuance k-rate_rps: sixteen probes at 3/s cannot be
    # delivered in less than (16-1)//3 = 5 seconds, whatever else is true. A
    # scan that finished faster than that did not send sixteen requests
    # through this limiter, and the equality below would then be measuring
    # something other than what it says.
    #
    # The ceiling is the other failure: a sender that ignored the hint and
    # waited its own full clamp on every probe, twice, would take ~33 s and
    # still be green on everything above. It is deliberately loose -- the
    # margin over the expected ~5.1 s is for a loaded machine, not for a
    # second pacing strategy.
    rps = rig.eng.config.rate_limit_rps
    floor_s = (PROBES_PER_SCAN - 1) // rps
    assert floor_s <= elapsed <= floor_s + PROBES_PER_SCAN, (
        f"{PROBES_PER_SCAN} probes at {rps}/s took {elapsed:.2f}s; the "
        f"limiter's own arithmetic puts the floor at {floor_s}s and anything "
        "far above it is a sender waiting more than it was asked to")

    findings = _active_findings(rig)
    assert Counter(f["check_id"] for f in findings) == \
        {check_id: 1 for check_id in ACTIVE_CHECK_IDS}, (
            f"expected exactly one finding per active check, got "
            f"{[(f['check_id'], f['path_template']) for f in findings]}")

    # Each one filed against the surface the fixture built for it. A check
    # finding its issue on somebody else's route would still satisfy the count
    # above and would mean the corpus is answering to the wrong evidence.
    for finding in findings:
        want = VULNERABLE_ROUTES[finding["check_id"]].split("?")[0]
        assert finding["path_template"] == want, finding

    # `requests_sent` IS NON-ZERO WHERE AN ACTIVE CHECK FOUND SOMETHING. A
    # finding filed by a check that sent nothing would mean the verdict came
    # from somewhere other than the wire. Only the active rows: a passive
    # finding on one of these surfaces (`hx.passive.security-headers` files
    # two against `/search` -- missing-content-type-options and
    # missing-frame-protection. The third spec, missing-hsts, is gated
    # `applies=https` and this rig's origin is `http://`, so it never fires
    # here) is a real finding that correctly spent no requests at all.
    for row in check_runs:
        if row["check_id"] not in ACTIVE_CHECK_IDS:
            assert row["requests_sent"] == 0, \
                f"a passive check recorded traffic it cannot send: {row}"
            continue
        if row["verdict"] == "finding":
            assert row["requests_sent"] >= 1, row
        assert row["requests_sent"] <= 4, (
            f"{row['check_id']} spent {row['requests_sent']} requests on "
            f"{row['path_template']}: the corpus is canary-first and no check "
            "here has more than one insertion point to probe, plus at most one "
            "escalation")

    # AND BOUNDED, AGAINST THE ONE WITNESS THIS SIDE CANNOT FAKE. The target
    # server's own log is what actually arrived; `requests_sent` is what hx
    # believes it spent. At the raised rate this held only because nothing was
    # ever refused. At 3/s it has to hold THROUGH the refusals and the waits
    # that answered them -- measured against a real Burp: 16 probes issued,
    # 5 `rate_limited` refusals, one apiece across 5 of those probes -- which
    # makes it the proof of both halves of fix round A at once: every probe
    # was eventually issued exactly once (the retry works), counted exactly
    # once (a refusal the gate decided before issuing adds nothing, so the
    # retry does not double-count), and seen by the target exactly once (no
    # wait replayed a request that had already left).
    spent = sum(r["requests_sent"] for r in check_runs)
    arrived = len(rig.target.hits) - hits_before
    assert spent == arrived == PROBES_PER_SCAN, (
        f"hx counted {spent} requests, the target received {arrived}, "
        f"and one scan of these {len(VULNERABLE_ROUTES)} surfaces costs "
        f"{PROBES_PER_SCAN}")
    assert spent <= rig.eng.config.max_requests

    # The CORS probe is the one whose payload is a HEADER rather than a path,
    # so it is the one the request line could never show. The target's log is
    # where it is visible at all.
    origins = [h.headers.get("Origin") for h in rig.target.hits
               if h.path == VULNERABLE_ROUTES["hx.active.cors"]]
    assert cors._PROBE_ORIGIN in origins, origins


def test_the_report_names_every_active_finding_and_every_check_that_ran(rig):
    """S12, for the half of the corpus that sends.

    `test_scan_and_report.py` renders a report over passive findings only. This
    one has to carry five more, each with an insertion point, a payload-shaped
    description and a coverage row -- and the coverage table has to name the
    active checks that ran CLEAN on the other four surfaces, which is the
    difference between "we probed this and it held" and "we never asked".
    """
    _configure(rig)
    _browse_the_vulnerable_surfaces(rig)
    _scan(rig)

    out = report.render(rig.eng.db, engagement_id=rig.eng.id,
                        config=rig.eng.config, blobs=rig.eng.blobs)

    for finding in _active_findings(rig):
        assert finding["title"] in out, \
            f"{finding['check_id']}'s finding is missing from the report"
        assert finding["path_template"] in out

    for check in registry.CHECKS:
        assert f"`{check.id}`" in out, \
            f"{check.id} is missing from the coverage table"


# ---------------------------------------------------------------------------
# 2. The retest story: stable across a scan that changes nothing, and not one
#    finding closed by a fix that is real on every route.
# ---------------------------------------------------------------------------

def test_a_second_scan_is_stable_and_a_wholly_fixed_target_retires_nothing(rig):
    """The property no unit test can reach, in three scans.

    SCAN 1 and SCAN 2 change nothing. Five findings must stay five findings --
    one ROW per issue, not two -- with a second observation each. A dedupe key
    that failed to match the second run's candidates to the first's would give
    ten rows; a `finding_observation` PK colliding across runs would give one
    observation instead of two (the defect `scan.run`'s own docstring
    measures). Neither can be produced by hand-inserted rows, because both are
    about what a REAL second probe of a real target produces.

    SCAN 3 FOLLOWS FIVE REAL FIXES, and is the sharpest available statement of
    what fix round 6 removed. Every vulnerable route is repaired -- each one
    goes on answering 200 and simply stops being vulnerable, so every check
    gets an ordinary, complete, application-composed answer and every one of
    them says `clean` off a probe that really went. Not one finding may close.

    THIS TEST ASSERTED THE OPPOSITE UNTIL FIX ROUND 6, AND IT ASSERTS IT
    AGAIN NEXT DOOR. It was `..._and_a_fixed_endpoint_retires_only_its_own_
    finding`: it fixed CORS alone and required `[1, 1, 0]` for that finding
    and `[1, 1, 1]` for the four beside it. THIS SCAN IS ANONYMOUS -- the
    rig's config names no `scan_identity` -- so every probe it sends is
    unauthenticated, a `clean` here is a statement about the logged-out view
    of the application, and the shape that makes that fatal (an application
    answering a logged-out request with a 200 login PAGE) is
    indistinguishable from the five genuine answers below.
    `tests/integration/test_identity.py::test_a_proven_run_retires_the_
    finding_it_can_no_longer_find` is this scan with a session hx proved
    live, and it requires the retirement. The pair is the whole of section
    9's gate: same corpus, same repair, same `clean` off a probe that really
    went, and the outcome turns on whether the run could prove the view it
    was looking at.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED on this exact scan,
    with `_probe_util.verdict` putting `examined` back on the verdict and
    `scan._retirable` passing a probing check's `considered` through --
    which together are the behaviour up to fix round 5:

        {'hx.active.cors': [1, 1, 0], 'hx.active.open-redirect': [1, 1, 0],
         'hx.active.path-traversal': [1, 1, 0], 'hx.active.reflected-input':
         [1, 1, 0], 'hx.active.sql-error': [1, 1, 0]}

    and the rendered page carried "**not observed the last time its check
    tested this surface -- appears fixed; verify before closing**" five
    times, once per finding. Every assertion below reddens on that, and the
    last of them is the sentence a client would have read.

    NOT VACUOUS: the check rows are asserted to be REAL `clean` answers with
    requests on the wire, so what is measured is a suppressed retirement and
    not a scan that skipped everything.
    """
    _configure(rig)
    _browse_the_vulnerable_surfaces(rig)

    _scan(rig)
    first = {f["check_id"]: f["id"] for f in _active_findings(rig)}
    assert set(first) == ACTIVE_CHECK_IDS, first

    _scan(rig)
    second = {f["check_id"]: f["id"] for f in _active_findings(rig)}
    assert second == first, (
        "a scan that changed nothing produced different finding rows: "
        f"{first} then {second}")
    for check_id, finding_id in first.items():
        assert _observations(rig, finding_id) == [1, 1], \
            f"{check_id}: {_observations(rig, finding_id)}"

    # Fix every endpoint. Nothing else about the target, the store or the
    # config changes, and every route goes on answering.
    for check_id in ACTIVE_CHECK_IDS:
        rig.target.fix(check_id)

    _scan(rig)
    third = {f["check_id"]: f["id"] for f in _active_findings(rig)}
    assert third == first, \
        "the third scan invented or lost a finding row; only observations move"

    # EVERY CHECK REALLY LOOKED, AND REALLY FOUND NOTHING. Without this the
    # assertion below is satisfied by a scan that skipped the corpus, and by
    # every future change that stops it sending.
    rows = {(r["path_template"], r["check_id"]): r
            for r in _check_runs(rig, _last_scan_run(rig))}
    for check_id, route in VULNERABLE_ROUTES.items():
        row = rows[(route.split("?")[0], check_id)]
        assert (row["verdict"], row["requests_sent"] > 0) == ("clean", True), (
            f"{check_id} did not answer `clean` off a probe that went, so "
            f"nothing below measures a suppressed retirement: {dict(row)}")

    # TWO OBSERVATIONS, NOT THREE, and the missing row is the whole point.
    # `record_observation(observed=1)` is written by `_write_finding` when a
    # finding is RE-FOUND, and none of them was -- every route is repaired. So
    # the only row scan 3 could have added is the `observed=0` that
    # `_mark_unobserved` writes, and it writes none. A third entry here can
    # therefore only be a retirement.
    for check_id, finding_id in first.items():
        assert _observations(rig, finding_id) == [1, 1], (
            f"{check_id} retired: {_observations(rig, finding_id)}. This "
            "scan is anonymous, so every probe in it was sent "
            "unauthenticated and no active check may tell a client their "
            "issue appears fixed")

    # WHERE THE CLIENT WOULD HAVE READ IT, and what the page says instead.
    out = report.render(rig.eng.db, engagement_id=rig.eng.id,
                        config=rig.eng.config, blobs=rig.eng.blobs)
    assert "appears fixed" not in out, out
    assert "An active finding is never automatically marked as fixed" in out


# ---------------------------------------------------------------------------
# 3. A templated surface: the probe goes to the address, not to the identity.
# ---------------------------------------------------------------------------

def test_a_templated_surface_is_probed_at_its_own_concrete_path(rig):
    """F1, end to end, against the one witness this side cannot fake.

    `/user/12345/profile` normalises to the surface `/user/{id}/profile`, and
    the id segment is REFLECTED -- so `hx.active.reflected-input` finds it
    only if its probe reaches a URL that exists and carries its canary in the
    place the template merely names.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? Measured against this exact
    route with the pre-fix corpus: every probe went to `/user/{id}/profile`,
    the target answered 404 from its own catch-all, nothing reflected, and
    all five checks recorded `clean` -- the finding assertion below reddens,
    and so does the hit-log assertion, which is the one that says WHY.
    """
    _configure(rig)
    rig.browse("GET", TEMPLATED_ROUTE)
    rig.settle(
        lambda: len(rows(rig, "SELECT id FROM surface")) == 1,
        "one surface for the templated route")
    hits_before = len(rig.target.hits)

    # THE SURFACE REALLY IS TEMPLATED. Without this the rest measures a
    # static route, passes, and proves nothing -- which is precisely how the
    # five surfaces above kept this defect invisible.
    surfaces = rows(rig, "SELECT path_template FROM surface")
    assert [s["path_template"] for s in surfaces] == [TEMPLATED_SURFACE]

    _scan(rig)

    findings = [f for f in _active_findings(rig)
                if f["check_id"] == "hx.active.reflected-input"]
    assert len(findings) == 1, (
        "the reflected id segment was not found; a probe that went to the "
        f"template reaches a 404 and reflects nothing. {findings}")
    assert findings[0]["path_template"] == TEMPLATED_SURFACE
    assert findings[0]["insertion_name"] == "{id}", (
        "the finding must name the insertion point the template calls it, "
        "which is the surface's identity and what a retest matches on")

    # THE ASSERTION THAT WOULD HAVE CAUGHT F1. `hits` is what the target
    # actually received; every path in it must be a real address, and no
    # request may carry a placeholder. `hx` cannot fake this: the log is
    # written by the server before it answers.
    arrived = rig.target.hits[hits_before:]
    assert arrived, "the scan sent nothing at all"
    for hit in arrived:
        assert "{" not in hit.path and "}" not in hit.path, hit
        segments = hit.path.split("/")
        assert len(segments) == 4 and segments[1] == "user" \
            and segments[3] == "profile", hit

    # AND THE PAYLOAD LANDED IN THE SEGMENT THE TEMPLATE NAMES, rather than
    # beside the exemplar's own id. A `str.replace` of `{id}` against the
    # concrete path substitutes nothing and re-sends `12345` -- a probe that
    # tests nothing and reads as clean.
    probed_ids = {hit.path.split("/")[2] for hit in arrived}
    assert probed_ids - {"12345"}, (
        "every probe re-sent the exemplar's own id, so none of them carried "
        f"a payload at all: {probed_ids}")

    # NOTHING WENT WRONG QUIETLY, the same guard the first test makes. A
    # `ValueError` from `ProbeSender`'s placeholder refusal lands `error`
    # here rather than `clean`, which is the safe direction and still a
    # failure of this test.
    run_id = _last_scan_run(rig)
    bad = [r for r in _check_runs(rig, run_id)
           if r["check_id"] in ACTIVE_CHECK_IDS and r["verdict"] == "error"]
    assert bad == [], bad

    # The escalation is what makes it the Medium finding rather than the Low
    # one: the `<>"\'` wrapper survived the round trip through Burp, a real
    # socket, and a route that percent-decodes its own path segment.
    assert findings[0]["severity"] == "Medium", (
        f"the escalation's {reflected_input._META_CHARS!r} wrapper did not "
        "come back intact; it rides a PATH SEGMENT here rather than a query "
        "string, through Burp and a real socket")


# ---------------------------------------------------------------------------
# 4. A response that is not an answer, and a surface no probe can address.
# ---------------------------------------------------------------------------

def test_a_login_wall_is_not_a_clean_result(rig):
    """N1, end to end: the corpus meeting a target that stops answering.

    Two scans of one surface. In the first the route reflects `tab` and
    `hx.active.reflected-input` files a finding against it. Then
    `require_login()` puts a `302 Found / Location: /login` in front of the
    same route -- the ordinary shape of an authenticated, browser-facing
    application meeting an unauthenticated request, which is every request
    this build sends -- and the second scan probes it again.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED against this exact route
    with `unanswered` blind to a 3xx, which is its state before fix round 3:
    every check that sent anything -- `cors`, `reflected-input` and
    `sql-error`, one probe each -- closed `clean`, telling `report._coverage`
    that three surfaces had been tested by three probes that reached a login
    page. (The other two sent nothing and answered `inconclusive` either way:
    their own name filters decline `tab`, which is N3's fix and not this
    one's.)

    N1's OWN HARM WAS THE RETIREMENT behind that 302 -- `considered`
    populated, `observed = 0`, and "appears fixed; verify before closing"
    rendered for a live cross-site scripting vector. It is closed twice over
    now and this doctrine is the half that does not depend on the run: an
    `inconclusive` verdict carries no `considered`, so no session any run
    could prove would let one of these rows retire anything. (`scan._retirable`
    is the other half, and it is about a `clean` verdict rather than this
    one.) The observations are asserted below as the consequence, and the
    `inconclusive` verdicts are the claim.
    """
    _configure(rig)
    rig.browse("GET", LOGIN_WALL_ROUTE)
    rig.settle(
        lambda: len(rows(rig, "SELECT id FROM surface")) == 1,
        "one surface for the login-wall route")

    _scan(rig)
    first = {f["check_id"]: f["id"] for f in _active_findings(rig)}
    assert set(first) == {"hx.active.reflected-input"}, (
        "the route has to be FOUND before the wall goes up; a wall in front "
        f"of a surface nothing was found on proves nothing: {first}")
    finding_id = first["hx.active.reflected-input"]
    assert _observations(rig, finding_id) == [1]

    # The wall. Nothing else about the target, the store or the config moves.
    rig.target.require_login()
    hits_before = len(rig.target.hits)

    _scan(rig)
    check_runs = [r for r in _check_runs(rig, _last_scan_run(rig))
                  if r["check_id"] in ACTIVE_CHECK_IDS]
    assert {r["verdict"] for r in check_runs} == {"inconclusive"}, (
        "a probe that got a redirect to a login page tested nothing, and "
        f"`clean` says the opposite: {check_runs}")

    # AND THE PROBES REALLY WENT, which is what separates this from a skip.
    # `inconclusive` is also what a surface nobody could address produces, so
    # without this the assertion above would be satisfied by a scan that sent
    # nothing at all -- and by every future change that stops it sending.
    spent = sum(r["requests_sent"] for r in check_runs)
    arrived = len(rig.target.hits) - hits_before
    assert spent == arrived >= 3, (
        f"hx counted {spent} probes and the target received {arrived}; the "
        "wall has to be measured against requests that actually reached it")
    assert any("status 302" in (r["reason"] or "") for r in check_runs), (
        "the rows must name the redirect they got rather than some other "
        f"gap: {[r['reason'] for r in check_runs]}")

    # AND THE FINDING IS STILL LIVE -- guarded twice, and this scan is
    # anonymous so both guards hold. The `inconclusive` above carries no
    # `considered` at all, which is true whatever a run proves; and
    # `scan._retirable` honours an active check's `considered` only for a run
    # whose canary came back `proven`, which this run has no identity to
    # attempt.
    assert {f["check_id"]: f["id"] for f in _active_findings(rig)} == first
    assert _observations(rig, finding_id) == [1], (
        "the login wall retired the finding: a client is told a live "
        "vulnerability appears fixed on the strength of a probe that never "
        f"got past /login. {_observations(rig, finding_id)}")

    # AND THE CLIENT-FACING SENTENCE IS NOT ON THE PAGE. The store is where
    # the retirement happens; this is where it would have been read.
    out = report.render(rig.eng.db, engagement_id=rig.eng.id,
                        config=rig.eng.config, blobs=rig.eng.blobs)
    assert "appears fixed" not in out, out


def test_a_state_changing_surface_is_skipped_rather_than_probed_with_a_get(rig):
    """N2, end to end: a surface captured with a method no probe can build.

    `ProbeSender._request_bytes` builds a GET and only a GET, and a surface's
    method is part of its identity -- so a GET probe of `POST /api/orders`
    tests a different surface, and any verdict it produces is about that other
    surface. `scan.run` skips it, `not_a_get_surface`.

    THE FINDING IS WRITTEN, NOT FOUND, and it has to be: no probe in this
    build can file one against a POST surface, which is precisely the fix. The
    row stands in for one filed before that fix existed, or by a build that
    can send a POST, or imported from a previous engagement -- the store holds
    findings across all three. It goes in through `scan._write_finding`, the
    runner's own writer, so it is the row a scan would have produced rather
    than a hand-shaped one, and what is under test is not how it got there but
    what a GET of a different surface is allowed to do to it.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED against this exact
    surface with the skip removed: three GETs of `/api/orders` on the wire
    (a bare one, one carrying a canary in `sku`, one carrying a quote),
    `summary.by_reason` empty, `cors`, `reflected-input` and `sql-error` all
    closing `clean` off them, and -- in the build of the day -- the finding
    above coming back `observed = 0`, retired by a request to a surface this
    engagement never captured. The retirement half is now the runner's
    (`scan._retirable`); the three `clean` rows are still this skip's, and
    they are a coverage claim no request to this surface backs.
    """
    _configure(rig)
    rig.browse("POST", STATE_CHANGING_ROUTE, body=b'{"sku": 1}')
    rig.settle(
        lambda: len(rows(rig, "SELECT id FROM surface")) == 1,
        "one surface for the state-changing route")

    surface = rows(rig, "SELECT id, method, scheme, host, port, kind,"
                   " path_template, exemplar_exchange_id FROM surface")[0]
    assert (surface["method"], surface["kind"]) == ("POST", "state_changing"), (
        "the rig has to CAPTURE the method, or this measures a GET surface "
        f"with a longer name: {surface}")

    finding_id = _file_a_finding_on(rig, surface)
    assert _observations(rig, finding_id) == [1]
    hits_before = len(rig.target.hits)

    summary = _scan(rig)
    assert summary.by_reason == {"not_a_get_surface": len(ACTIVE_CHECK_IDS)}, (
        "every active check must be skipped for the method, and skipped for "
        f"THAT reason: {summary.by_reason}")

    check_runs = [r for r in _check_runs(rig, _last_scan_run(rig))
                  if r["check_id"] in ACTIVE_CHECK_IDS]
    assert {r["verdict"] for r in check_runs} == {"skipped"}, check_runs
    assert all(r["requests_sent"] == 0 for r in check_runs), check_runs

    # THE ONE WITNESS THIS SIDE CANNOT FAKE. A skip that still sent something
    # would leave rows saying one thing and a target log saying another, and
    # the log is what a GET probe of this surface would appear in.
    assert rig.target.hits[hits_before:] == [], (
        "the scan sent requests at a surface it recorded as unprobeable: "
        f"{[(h.method, h.path) for h in rig.target.hits[hits_before:]]}")

    # AND THE FINDING IS UNTOUCHED. Guarded twice: a `clean` row here would
    # have claimed, in Coverage, to have tested a surface no request
    # addressed -- and it would also have offered this finding for retirement
    # on the strength of a request to a DIFFERENT surface, which is what the
    # measurement in this docstring recorded. The offer would be refused for
    # this anonymous run in any case (`scan._retirable`), and the skip is what
    # stops the offer being made at all.
    assert _observations(rig, finding_id) == [1], (
        "a GET of a surface hx never captured retired a finding filed "
        f"against the POST one: {_observations(rig, finding_id)}")

    # The run row says so too, so an operator reading the summary of the pass
    # is not told it covered what it skipped.
    run_row = rows(rig, "SELECT status, stop_reason FROM run WHERE id=?",
                   (_last_scan_run(rig),))[0]
    assert "not_a_get_surface" in (run_row["stop_reason"] or ""), run_row


def _file_a_finding_on(rig, surface) -> str:
    """One finding already on file against `surface`, through the runner's own
    writer.

    Everything the dedupe key is computed from comes off the surface row, so
    the row this leaves is the one a scan of that surface would have left --
    see the caller's docstring for why a scan cannot leave it any more. The
    issue type is read off the check rather than spelt here, for the reason
    every other dedupe-key value on this row is: a literal that drifted from
    `reflected_input._ISSUE_TYPE` would file a row no later scan of this
    surface could ever match, and the caller's "this finding is untouched"
    would be satisfied by a finding nothing could touch.
    """
    check = next(c for c in registry.CHECKS
                 if c.id == "hx.active.reflected-input")
    exemplar = surface["exemplar_exchange_id"]
    assert exemplar, surface
    candidate = base.Candidate(
        title="Reflected input in a query parameter",
        issue_type_id=reflected_input._ISSUE_TYPE,
        severity="Medium", confidence="Firm",
        insertion=base.Insertion("query", "sku"),
        exchange_ids=(exemplar,),
        payload="Zq7pLx3nV0aB")
    return scan._write_finding(
        rig.eng.db, rig.eng.id, rig.run_id,
        (surface["id"], surface["method"], surface["scheme"], surface["host"],
         surface["port"], surface["path_template"], exemplar),
        check, candidate)


# ---------------------------------------------------------------------------
# 5. A surface the browser was logged in to.
# ---------------------------------------------------------------------------

CORS_ROUTE = VULNERABLE_ROUTES["hx.active.cors"]
CORS_SURFACE = CORS_ROUTE.split("?")[0]
REFLECTING_ROUTE = VULNERABLE_ROUTES["hx.active.reflected-input"]
REFLECTING_SURFACE = REFLECTING_ROUTE.split("?")[0]


def _log_in(rig) -> str:
    """Browse `/login` and come back with the `Cookie` header a browser would
    send next.

    THE VALUE IS THE SERVER'S OWN, not a literal typed here. `/login` answers
    `Set-Cookie: session=<SESSION_COOKIE_VALUE>; Path=/; HttpOnly; SameSite=
    Lax` and the cookie this returns is parsed off that response, so a test
    built on it carries a realistic session and cannot drift from the route
    that issues one.

    A BROWSE MAY CARRY A COOKIE THAT A PROBE MAY NOT, AND THAT ASYMMETRY IS S4
    WORKING AS DESIGNED. This goes through the PROXY LISTENER, whose operator
    branch is `Policy.decideScopeOnly` -- scope, and nothing after it
    (`ProxyGate.decide`: "It does not reach the Gate, so an operator's
    browsing spends no rate token and no budget slot"), so the method
    allowlist, the dangerous-path denylist, the rate limit and the budget are
    all the crawler's branch and none of them is asked here. The
    `unmanaged_credential` refusal is `Sender.decide()`'s and lives on the
    SEND path. So the operator's browser carries its session exactly as a
    browser does, everything hx itself issues carries none, and the gap
    between those two requests is the whole subject of the test below.

    IT ALSO LEAVES `/login` AS AN ANONYMOUS SURFACE, which the test uses as
    its control: one scan, two surfaces, one of them authenticated.
    """
    raw = rig.browse("GET", "/login")
    head = raw.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        name, _sep, value = line.partition(b":")
        if name.strip().lower() == b"set-cookie":
            return value.decode("latin-1").strip().split(";")[0]
    raise AssertionError(f"/login set no cookie: {head!r}")


def test_a_cookie_bearing_surface_names_the_point_the_send_path_refuses(rig):
    """AN AUTHENTICATED BROWSE, end to end, and the refusal it produces.

    An operator logs in through `/login` and browses `/api/profile` and
    `/search` carrying the cookie that route issued. That is the only way a
    `cookie` insertion point can reach the store at all, and until fix round 5
    no active check had ever been run against one: F2's fix (a point the send
    path refuses is dropped rather than probed), the
    `no_probeable_insertion_point` skip and fix round 4's per-point refusal
    detail were all covered by fake bridges and by nothing end to end.

    A BROWSE MAY CARRY A COOKIE THAT A PROBE MAY NOT, and that asymmetry is S4
    working as designed -- `_log_in`'s own docstring carries the argument. The
    consequence measured here is the one an operator reads: the check that
    declares the `cookie` kind is skipped, and the row NAMES the point rather
    than saying only that something was refused.

    WHAT THIS TEST NO LONGER MEASURES. It was
    `test_a_fix_on_an_authenticated_surface_is_not_reported_as_fixed`, and it
    fixed the CORS route and asserted that the finding did not retire because
    the CAPTURE had carried a credential header. Fix round 6 removed that
    discriminator: retirement is gone from the whole active corpus, so the
    surviving claim is measured on plain anonymous surfaces by
    `test_a_second_scan_is_stable_and_a_wholly_fixed_target_retires_nothing`,
    where the fix is real on all five routes. What is left here is the cookie
    point and the skip that names it, which nothing else in this suite
    reaches.
    """
    _configure(rig)
    cookie = _log_in(rig)
    rig.browse("GET", CORS_ROUTE, headers=[("Cookie", cookie)])
    rig.browse("GET", REFLECTING_ROUTE, headers=[("Cookie", cookie)])
    rig.settle(lambda: len(rows(rig, "SELECT id FROM surface")) == 3,
               "three surfaces: /login, the CORS route and the reflecting one")

    # GUARD 1: THE COOKIE REALLY TRAVELLED, in both browses. Without this,
    # everything below is satisfied by a request that carried no session at
    # all -- and "no cookie point was derived" is also what a broken browse
    # produces.
    served = rig.target.hits_for(CORS_SURFACE) \
        + rig.target.hits_for(REFLECTING_SURFACE)
    assert [hit.headers.get("Cookie") for hit in served] == [cookie, cookie], \
        served

    # GUARD 2: AND WHAT REACHED THE STORE IS THE HEADER NAME WITHOUT ITS
    # VALUE. `Redactor.redactObservedRequest` replaces the value before the
    # bytes are hashed (S7), so the blob reads `Cookie: {{observed:cookie}}` --
    # which is the only reason an insertion point of that kind can be derived
    # from it at all, and the reason no rule on this side can ever tell a
    # session cookie from an analytics one.
    surfaces = {r["path_template"]: r for r in rows(
        rig, "SELECT id, path_template, exemplar_exchange_id FROM surface")}
    captured = {}
    for template in (CORS_SURFACE, REFLECTING_SURFACE, "/login"):
        blob = rows(rig, "SELECT req_blob FROM exchange WHERE id=?",
                    (surfaces[template]["exemplar_exchange_id"],))[0]["req_blob"]
        captured[template] = rig.eng.blobs.get(blob)
    assert b"Cookie:" in captured[CORS_SURFACE], captured[CORS_SURFACE]
    for template, blob in captured.items():
        assert SESSION_COOKIE_VALUE.encode() not in blob, (
            f"{template}'s blob holds the live session value; redaction runs "
            "before the digest, so this is not recoverable afterwards")

    # GUARD 3: THE POINT IS DERIVED AND IS ONE THE SEND PATH REFUSES, asserted
    # off the real blob rather than constructed.
    points = insertion.derive(captured[CORS_SURFACE], CORS_SURFACE)
    assert [(p.kind, probe.unprobeable(p) is not None) for p in points] == \
        [("cookie", True)], points

    summary = _scan(rig)
    found = {f["check_id"]: f["id"] for f in _active_findings(rig)}
    assert set(found) == {"hx.active.cors", "hx.active.reflected-input"}, (
        "both routes have to be found, or the scan below never ran the "
        f"checks whose rows are asserted: {found}")

    # THE CHECK THAT COULD NOT BE HANDED A POINT SAYS WHICH POINT, on the row
    # an operator reads. `hx.active.reflected-input` is the one check that
    # declares the `cookie` kind, so it is the one for which `/api/profile`
    # HAS a point of a kind it wants and every one of them is refused -- the
    # other three declare `query` and `path_segment` only, find none, and are
    # skipped `no_insertion_point`, which is a different fact and has its own
    # key. Measured: {'no_insertion_point': 7, 'no_probeable_insertion_point':
    # 1} across the three surfaces.
    assert summary.by_reason.get("no_probeable_insertion_point") == 1, \
        summary.by_reason
    refused_row = [r for r in _check_runs(rig, _last_scan_run(rig))
                   if r["path_template"] == CORS_SURFACE
                   and r["check_id"] == "hx.active.reflected-input"][0]
    assert refused_row["verdict"] == "skipped", refused_row
    assert "a cookie is probed by sending a Cookie header" in \
        refused_row["reason"], refused_row
