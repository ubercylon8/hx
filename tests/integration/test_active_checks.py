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

THE RATE LIMIT IS RAISED IN `_configure`, DELIBERATELY AND WITH A MEASUREMENT
BEHIND IT -- see that function's docstring. It is the one fixture knob here that
hides a real product limitation, and it says so out loud rather than passing
quietly.

WHAT THE PASSIVE CORPUS CANNOT DELIVER, and why the second test below is the
point of the whole task: `test_scan_and_report.py` proves a finding is re-found
by a second scan, and its own claim 3 measures that a finding CANNOT be retired
by taking the target away -- the exchange that proves it is still on file, so
every passive check goes on answering `finding` for ever. Only a target that
CHANGES can prove the other half, and only an active check can see that change:
`target.fix(check_id)` removes exactly one flaw, the check that owns it answers
`clean` while still naming what it considered, and `hx.scan._mark_unobserved`
closes that finding and no other. That is `Verdict.considered` working end to
end, and it exists nowhere else in this suite.
"""
from __future__ import annotations

from collections import Counter

import pytest

from hx import report, scan
from hx.checks import registry
from hx.checks.active import cors
from tests.integration.target_server import VULNERABLE_ROUTES

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
    """Authorise the extension, with a rate this scan can actually finish at.

    THE RIG'S OWN 3/s DOES NOT WORK HERE, AND THE REASON IS A REAL GAP IN THE
    PRODUCT rather than a property of this fixture. `hx.policy.Limiter` REFUSES
    over-rate requests -- `Decision.rateLimited(retryAfterUs, ...)`, carrying a
    hint -- it does not block and it does not queue. Nothing on the Python side
    consumes that hint: `BridgeServer.send`'s own docstring says "NOTHING IN
    THIS FILE RETRIES", `ProbeSender.get` turns the refusal into `ProbeRefused`,
    and `hx.scan.run` turns that into an `inconclusive` row. The probe pass
    issues its requests as fast as the send path answers them -- 0.57 ms p50
    through this whole rig, measured in `target_server.py`'s own header -- so at
    any single-digit `rate_limit_rps` a scan of more than `rate_rps` probes goes
    `inconclusive` from the fourth request onward. MEASURED here first, at the
    rig's own 3/s: of the sixteen probes one scan issues, three were answered
    and every attempt after them came back `rate_limited` -- twelve
    `inconclusive` rows, one finding of the five, and four of the five checks
    never given an answer on any surface they were meant to find one on.

    That is a defect in the corpus's pacing, not in this test, and it is
    reported as one. What this file can honestly do is not pretend otherwise:
    the rate is raised to a number that lets the checks be measured against a
    real Burp, and the number is written down here with the reason, so nobody
    reads a green run as evidence that an unpaced scan works at a production
    rate. `limit.rate_rps` is armed on the FIRST configure of a run (see
    `conftest.build_config_body`), which is what this is.
    """
    assert rig.configure(rate_rps=200) == 1


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

    summary = _scan(rig)
    assert summary.surfaces == len(VULNERABLE_ROUTES)

    run_id = _last_scan_run(rig)
    check_runs = _check_runs(rig, run_id)

    # NOTHING WENT WRONG QUIETLY. `inconclusive` is what a refusal becomes
    # (`rate_limited`, `scope_denied`, a truncated response); `error` is a bug
    # in hx. Either would leave a check looking like it ran while it found
    # nothing, which is the confusion S12 exists to remove -- and one of them
    # is exactly how this test failed the first time it was run (see
    # `_configure`).
    bad = [r for r in check_runs if r["verdict"] in ("error", "inconclusive")]
    assert bad == [], f"a check neither ran nor was skipped: {bad}"

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
    # three against `/search`, which answers `text/html` and carries none of
    # them) is a real finding that correctly spent no requests at all.
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
    # believes it spent. They are equal only if every probe left, none was
    # refused before it did, and nothing issued traffic the count does not know
    # about.
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
# 2. The retest story: stable across a scan that changes nothing, and one
#    finding -- exactly one -- retired by a fix.
# ---------------------------------------------------------------------------

def test_a_second_scan_is_stable_and_a_fixed_endpoint_retires_only_its_own_finding(rig):
    """The property no unit test can reach, in three scans.

    SCAN 1 and SCAN 2 change nothing. Five findings must stay five findings --
    one ROW per issue, not two -- with a second observation each. A dedupe key
    that failed to match the second run's candidates to the first's would give
    ten rows; a `finding_observation` PK colliding across runs would give one
    observation instead of two (the defect `scan.run`'s own docstring
    measures). Neither can be produced by hand-inserted rows, because both are
    about what a REAL second probe of a real target produces.

    SCAN 3 follows `target.fix("hx.active.cors")`, which stops that one route
    reflecting an origin it never heard of and changes nothing else. What has
    to happen then is the whole of `Verdict.considered`: `Cors.probes` answers
    `clean` while still naming all three issue types it examined,
    `_mark_unobserved` finds its earlier finding's type in that set and NOT in
    this run's findings, and writes `observed=0` -- for that finding and no
    other. The four beside it must stay `observed=1`, and they are the
    separating case: a retirement gate keyed on the CHECK RUN rather than on
    the issue type, or on the surface rather than on the check, would close
    some of them too.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? A `considered` that named nothing
    would leave the CORS finding `observed=1` for ever -- a client told a
    vulnerability they fixed is still open. A `considered` that named too much,
    or a `_mark_unobserved` that ignored `issue_type_id`, would retire the
    other four as well -- a client told four live vulnerabilities are fixed.
    The two assertions below separate those two failures from each other and
    from the intended behaviour.
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

    # Fix ONE endpoint. Nothing else about the target, the store or the config
    # changes.
    rig.target.fix("hx.active.cors")

    _scan(rig)
    third = {f["check_id"]: f["id"] for f in _active_findings(rig)}
    assert third == first, \
        "the third scan invented or lost a finding row; only observations move"

    cors_id = first["hx.active.cors"]
    assert _observations(rig, cors_id) == [1, 1, 0], (
        "the CORS finding did not retire when its route was fixed: "
        f"{_observations(rig, cors_id)}. `Verdict.considered` is what closes "
        "it, and a client cannot be shown a fixed issue as still open")

    for check_id, finding_id in first.items():
        if check_id == "hx.active.cors":
            continue
        assert _observations(rig, finding_id) == [1, 1, 1], (
            f"{check_id} retired too: {_observations(rig, finding_id)}. Its "
            "route was never touched, and telling a client a live "
            "vulnerability is fixed is the worse half of this mechanism")

    # AND THE RETIREMENT CAME FROM AN ANSWER, NOT FROM ABSENCE. `observed=0` is
    # only allowed to mean "the same check looked again and did not find it";
    # a CORS row that was `skipped`, `error` or missing this run would be
    # "nobody looked", which S12 forbids rendering as the first.
    third_run = _last_scan_run(rig)
    cors_rows = [r for r in _check_runs(rig, third_run)
                 if r["check_id"] == "hx.active.cors"
                 and r["path_template"] == VULNERABLE_ROUTES["hx.active.cors"]]
    assert [(r["verdict"], r["requests_sent"]) for r in cors_rows] == [("clean", 1)], \
        cors_rows
