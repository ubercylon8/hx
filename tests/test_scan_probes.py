"""The probe pass: the runner half of `check.probes`.

No pytest fixtures, on purpose. `tests/conftest.py`'s `scan_env` builds a
surface with no `exemplar_exchange_id` and no blob store, which is exactly
right for a passive corpus and useless here -- an active check needs an
exemplar request to derive insertion points from, and half these tests need
to vary that request. `_env()` below is the plain helper this project's unit
tests use for that (see `tests/test_probe.py`'s own note, and
`tests/test_checks_http.py`'s `ctx_for`), and it takes the request bytes as
an argument so the varying is visible at each call site.

NO JVM AND NO SOCKET. Everything here runs against `FakeBridge`, the
`BridgeServer.send`-shaped double `tests/test_probe.py` already justifies:
`send()` returns a dict only for a `result` frame and RAISES `BridgeError`
for every refusal, which is the shape `ProbeSender` translates. The real
Burp path is the integration suite's.

The blob store is REAL, not faked. `hx.store.blobs.BlobStore` on a tmp_path
costs nothing, and the derivation this pass depends on runs
`blobs.get(digest)` -- a fake that returned bytes for any string would hide
a digest the runner never actually stored.
"""
from __future__ import annotations

import sqlite3
from urllib.parse import unquote_to_bytes

import pytest

from hx import config as config_mod
from hx import insertion as insertion_mod
from hx import scan
from hx import surface as surface_mod
from hx.checks import base, probe, registry
from hx.checks.active import cors
from hx.checks.passive import _http
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from tests.test_probe import FakeBridge

# One captured GET carrying a query parameter, a cookie and a header. Its
# only job is to give `insertion.derive` something to find; the assertions
# below name the kinds they care about rather than the count, because the
# count is `hx.insertion`'s business and `tests/test_insertion.py` pins it.
REQ_WITH_QUERY = (
    b"GET /?q=1 HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"Cookie: session=abc\r\n"
    b"\r\n"
)
REQ_WITHOUT_QUERY = (
    b"GET / HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"\r\n"
)


def _env(tmp_path, *, request_bytes=REQ_WITH_QUERY, exemplar=True,
         path_template="/", method="GET"):
    """An in-memory engagement with one surface, one exchange, one blob.

    `exemplar=False` writes the exchange and leaves `surface.
    exemplar_exchange_id` NULL -- a surface whose first sighting was purged,
    which is the case `_exemplar_request` has to survive without taking the
    scan down.

    `path_template` is the surface row's own, and it is a SEPARATE argument
    from `request_bytes` on purpose: a templated surface and the concrete
    request it was normalised from are two different strings, and the whole
    of F1 was code that treated them as one.

    `method` is the SURFACE's, which is part of its identity -- `POST /x` and
    `GET /x` are two surfaces (`hx.surface.normalise`) -- and it is what
    decides whether this build can probe it at all. The caller passing a
    non-GET method is expected to pass matching `request_bytes`; nothing here
    derives one from the other, because the whole of N2 was code that assumed
    the two agreed.
    """
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','T','T',1,'active')")
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, kind, discovered_by, normaliser_version)"
        " VALUES('s-1','e-1',?,'https','app.test',443,?,?,'proxy',1)",
        (method, path_template, surface_mod.kind_for(method)))
    store = blobs_mod.BlobStore(tmp_path / "blobs")
    digest, _ = store.put(request_bytes)
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url, req_blob) VALUES('x-1', NULL, 's-1', 'proxy', 'ok', 1,"
        " ?, 'https://app.test/?q=1', ?)", (method, digest))
    if exemplar:
        conn.execute(
            "UPDATE surface SET exemplar_exchange_id='x-1' WHERE id='s-1'")
    cfg = config_mod.Config(
        name="T", client="T", scope_include=["*.test"],
        checks=dict(config_mod.DEFAULT_CHECKS))
    return {"conn": conn, "engagement_id": "e-1", "blobs": store,
            "config": cfg}


def _last_verdict(conn):
    """The verdict of the most recently written `check_run` row.

    `_row` takes the FIRST row for a check id, which is the right answer for
    a one-scan test and the wrong one for the two-scan tests that assert what
    the SECOND pass wrote."""
    return conn.execute(
        "SELECT verdict FROM check_run ORDER BY rowid DESC LIMIT 1").fetchone()[0]


def _row(conn, check_id=None):
    if check_id is None:
        return conn.execute(
            "SELECT verdict, reason, requests_sent FROM check_run").fetchone()
    return conn.execute(
        "SELECT verdict, reason, requests_sent FROM check_run"
        " WHERE check_id=?", (check_id,)).fetchone()


class _Probe:
    """The minimal active check: records what it was handed, says clean."""
    id, version, klass = "hx.test.probe", "1", "active_safe"
    insertion_kinds = frozenset({"query"})

    def __init__(self):
        self.seen = {}
        self.calls = 0

    def probes(self, ctx, surface, insertions, send):
        self.calls += 1
        self.seen["insertions"] = insertions
        self.seen["sender"] = send
        self.seen["surface"] = surface
        return base.Verdict.clean()


def _replying_bridge(body=b"HTTP/1.1 200 OK\r\n\r\nhi"):
    fb = FakeBridge()
    fb.reply({"status": 200, "outcome": "ok"}, body)
    return fb


# --- what an active check is handed ---------------------------------------


def test_an_active_check_is_handed_a_sender_and_its_insertion_points(tmp_path):
    """The seam itself. Before this pass an `active_safe` check could not be
    registered at all -- `registry.validate` refused it because nothing
    called `probes` -- so this is the first assertion in the tree that the
    runner drives one."""
    env = _env(tmp_path)
    check = _Probe()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())

    assert check.calls == 1
    assert check.seen["insertions"], "a check was handed no insertion points"
    assert isinstance(check.seen["sender"], probe.ProbeSender)
    assert _row(env["conn"])[0] == "clean"


def test_the_points_handed_over_are_the_kinds_the_check_declared(tmp_path):
    """`insertion_kinds` is a declaration the runner acts on, not a label.
    The exemplar carries a cookie as well as a query parameter; a check that
    said `query` gets query points and is not handed the cookie to reason
    about."""
    env = _env(tmp_path)
    check = _Probe()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())
    kinds = {i.kind for i in check.seen["insertions"]}
    assert kinds == {"query"}
    assert [i.name for i in check.seen["insertions"]] == ["q"]


def test_the_sender_is_bound_to_this_surface_and_not_to_the_target_at_large(
        tmp_path):
    """A `ProbeSender` the runner built with the wrong columns would send
    real traffic to the wrong host and the check would never know. The bridge
    records what it was asked for; scheme/host/port must be this surface's."""
    env = _env(tmp_path)
    fb = _replying_bridge()

    class Sends(_Probe):
        def probes(self, ctx, surface, insertions, send):
            send.get("/?q=1")
            return base.Verdict.clean()

    scan.run(**env, checks=(Sends(),), bridge=fb)
    assert fb.last_req == {"target_host": "app.test", "target_port": 443,
                           "tls": True}


# --- never silence --------------------------------------------------------


def test_an_active_check_without_a_bridge_is_skipped_not_silent(tmp_path):
    """S12: a report that cannot distinguish "tested, clean" from "never
    reached" is worse than no report. No bridge means never reached, and the
    row has to say so -- an active corpus that produced no rows at all would
    read as the first while being the second."""
    env = _env(tmp_path)
    check = _Probe()
    summary = scan.run(**env, checks=(check,), bridge=None)

    verdict, reason, _sent = _row(env["conn"])
    assert verdict == "skipped"
    assert "bridge" in reason
    assert check.calls == 0, "the check was called with no route to the wire"
    assert summary.skipped == 1
    assert summary.by_reason == {"no_bridge": 1}


class _Finds(_Probe):
    """An active check that files one finding, so a LATER scan has something
    it could wrongly retire."""
    id = "hx.test.finds"

    def probes(self, ctx, surface, insertions, send):
        self.calls += 1
        return base.Verdict.finding(base.Candidate(
            title="t", issue_type_id="probed", severity="Low",
            confidence="Firm", insertion=None, exchange_ids=("x-1",)))


class _NoPointsFinds:
    """`hx.active.cors`'s shape: no declared insertion kinds, and a finding
    whose evidence is the surface's own exemplar exchange.

    Both halves matter and neither is arbitrary. A check with declared kinds
    never reaches a missing exemplar -- `_insertions_for` derives nothing from
    an exemplar it cannot read and the runner skips it -- so the empty
    `insertion_kinds` is what makes this shape the one that gets there (a
    check WITH kinds is skipped `no_insertion_point`, deriving nothing from an
    exemplar the runner could not read). And
    `exchange_ids=(surface[6],)` is not this test's invention: it is what every
    active check in this corpus writes, because nothing in this build records
    an exchange for a probe's own traffic.
    """
    id, version, klass = "hx.test.nopoints-finds", "1", "active_safe"
    insertion_kinds = frozenset()

    def __init__(self):
        self.calls = 0

    def probes(self, ctx, surface, insertions, send):
        self.calls += 1
        send.get("/")
        return base.Verdict.finding(base.Candidate(
            title="t", issue_type_id="probed", severity="Low",
            confidence="Firm", insertion=None,
            exchange_ids=(surface[6],)))


def test_a_no_bridge_skip_retires_nothing(tmp_path):
    """The consequence that makes the `skipped` row worth writing. A check
    that never ran examined nothing, so it enters nothing for retirement and
    `_mark_unobserved` closes none of its prior findings -- "I did not look"
    must not read as "it is fixed". Two real scans rather than a hand-built
    `finding` row: the first one is what puts the finding there, so the
    dedupe key and the observation are the runner's own.

    OVER-DETERMINED SINCE FIX ROUND 6 and kept for the day it is not: this
    check is active, and `scan._retirable` would empty its contribution even
    if it HAD been called. What still separates something here is the
    `skipped` row -- the alternative to a skip is an `error` or a silence,
    and only one of the three is what a no-bridge scan should write."""
    env = _env(tmp_path)
    scan.run(**env, checks=(_Finds(),), bridge=_replying_bridge())
    scan.run(**env, checks=(_Finds(),), bridge=None)
    assert _last_verdict(env["conn"]) == "skipped"
    observed = [r[0] for r in env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert observed == [1], "a check that never ran retired its own finding"


# --- a surface this build cannot send a request to ------------------------
#
# N2 of the scoped re-review. `ProbeSender._request_bytes` can build nothing
# but a GET -- body-parameter and mutating probes were excluded from this
# plan at design time -- and `scan.run` read `surface.method` only to build a
# dedupe key. So a `POST /cart/add` surface was probed with `GET /cart/add`
# and the row closed `clean` with `considered` populated, on the strength of
# a request to a DIFFERENT surface.

REQ_POST = (
    b"POST /cart/add?sku=1 HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"\r\n"
)


def test_a_surface_this_build_cannot_send_to_is_skipped_not_probed(tmp_path):
    """Decided BEFORE a sender exists, the same shape as `no_probe_path` and
    `no_exemplar`: nothing is spent, nothing goes on the wire, and the row
    says the check was not run rather than run clean."""
    env = _env(tmp_path, request_bytes=REQ_POST, path_template="/cart/add",
               method="POST")
    check = _Probe()
    fb = _replying_bridge()
    summary = scan.run(**env, checks=(check,), bridge=fb)

    verdict, reason, sent = _row(env["conn"])
    assert verdict == "skipped", f"{verdict}: {reason}"
    assert "POST" in reason and "GET" in reason
    assert check.calls == 0, "a check was handed a surface it cannot address"
    assert fb.calls == 0, "a GET went on the wire for a POST surface"
    assert sent == 0
    assert summary.by_reason == {"not_a_get_surface": 1}


def test_no_active_check_answers_clean_for_a_state_changing_surface(tmp_path):
    """The registry's own corpus, and the measurement N2 records: five rows
    reading `clean` for `POST /cart/add`, three GETs on the wire, and
    `_mark_unobserved` ready to retire a finding recorded against the POST
    surface on the strength of them."""
    env = _env(tmp_path, request_bytes=REQ_POST, path_template="/cart/add",
               method="POST")
    fb = _replying_bridge()
    active = tuple(c for c in registry.CHECKS if c.klass != "passive")
    scan.run(**env, checks=active, bridge=fb)

    verdicts = {v for (v,) in env["conn"].execute(
        "SELECT DISTINCT verdict FROM check_run")}
    assert verdicts == {"skipped"}, verdicts
    assert fb.bodies == [], fb.bodies


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_a_read_surface_is_still_probed(method):
    """The separating case. HEAD is in because a GET is a HEAD plus a body
    (RFC 9110 s9.3.2): the probe sees everything the captured request could
    have shown and more, so it tests the surface the row names."""
    assert method in scan._PROBEABLE_METHODS


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE",
                                    "OPTIONS", "get"])
def test_no_other_method_is(method):
    """`OPTIONS` is out even though `hx.surface.kind_for` calls it an
    idempotent read and S4's allowlist permits it: `GET /x` and `OPTIONS /x`
    are two surfaces, and a GET tests the first one whichever row it is
    filed under. `get` is out because `kind_for` is case-sensitive per RFC
    9110 s9.1 and a lowercase verb must not inherit a safe method's
    permissions."""
    assert method not in scan._PROBEABLE_METHODS


def test_a_surface_with_no_insertion_points_is_skipped_with_a_reason(tmp_path):
    """Also never silence. A surface nothing could be probed on is a fact the
    coverage section has to carry, and it is a different fact from a surface
    that was probed and came back clean."""
    env = _env(tmp_path, request_bytes=REQ_WITHOUT_QUERY)
    check = _Probe()
    summary = scan.run(**env, checks=(check,), bridge=_replying_bridge())

    verdict, reason, _sent = _row(env["conn"])
    assert verdict == "skipped"
    assert "insertion point" in reason and "query" in reason
    assert check.calls == 0
    assert summary.by_reason == {"no_insertion_point": 1}


def test_a_surface_whose_exemplar_is_gone_is_skipped_rather_than_crashing(
        tmp_path):
    """Row G's shape, one layer down. A surface can lose its exemplar to a
    purge, and `insertion.derive` then has no bytes to read. One unreadable
    row must not end a scan an operator has already billed for -- it must
    produce the same honest `skipped` any other underivable surface does.

    THE REASON CHANGED IN TASK 13 AND THE OUTCOME DID NOT. It used to be
    `no_insertion_point`, because a missing exemplar reaches the runner as
    "nothing could be derived" -- true, and not the whole truth: what is
    actually gone is the evidence any finding on this surface would have cited,
    which is a fact about the surface rather than about this check's declared
    kinds. `no_exemplar` is now decided first, for every active check, and the
    two tests below are the cases that separates."""
    env = _env(tmp_path, exemplar=False)
    summary = scan.run(**env, checks=(_Probe(),), bridge=_replying_bridge())
    assert _row(env["conn"])[0] == "skipped"
    assert summary.by_reason == {"no_exemplar": 1}


def test_a_check_that_declares_no_kinds_is_also_skipped_when_the_exemplar_is_gone(
        tmp_path):
    """The case a purged exemplar used to reach, and what it did there.

    A check declaring no insertion kinds is deliberately NOT skipped for having
    no points (the test below this one), so before Task 13 it was the one shape
    that ran on a surface whose exemplar was gone -- and every active check in
    this corpus cites `surface.exemplar_exchange_id` as the evidence for what
    it finds. MEASURED, with the check below and a NULL exemplar:
    `Candidate(exchange_ids=(None,))` constructed (a one-tuple is not empty),
    `record_evidence` wrote a row whose `exchange_id` was NULL -- the column is
    nullable -- and `hx.report._evidence` rendered the finding with "1 of the 1
    shown could not be resolved to a request". A claim the operator has no way
    to check, which is exactly what `Candidate`'s own docstring says a
    candidate may not be.

    Nothing is sent, either: the skip is decided before the sender exists, so
    the probe traffic is not spent on a surface whose answer could not have
    been evidenced.
    """
    env = _env(tmp_path, exemplar=False)
    fb = _replying_bridge()
    check = _NoPointsFinds()
    summary = scan.run(**env, checks=(check,), bridge=fb)

    verdict, reason, sent = _row(env["conn"])
    assert (verdict, sent) == ("skipped", 0)
    assert "exemplar" in reason
    assert check.calls == 0
    assert summary.by_reason == {"no_exemplar": 1}
    assert env["conn"].execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 0
    assert env["conn"].execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 0


def test_an_exemplar_id_whose_row_was_purged_is_skipped_not_an_error(tmp_path):
    """The other half of the same purge, and the one that LOST a finding.

    `surface.exemplar_exchange_id REFERENCES exchange(id)` with the pragma ON
    refuses the delete outright, so reaching this needs `PRAGMA
    foreign_keys=OFF` -- which is the shape a bulk purge or retention job takes
    (S8's Row G, and `tests/test_scan.py::test_a_surface_deleted_between_
    capture_and_scan_is_refused_by_the_schema` pins the refusal). The column is
    then not NULL, it DANGLES.

    MEASURED before the fix: `record_evidence` raised `IntegrityError: FOREIGN
    KEY constraint failed`, `scan.run`'s blanket `except Exception` closed the
    row `error`, and the finding was gone -- not silently (an `error` row is
    visible in coverage, so S12 is not violated) but gone. A real finding
    reported as a bug in hx.
    """
    env = _env(tmp_path)
    conn = env["conn"]
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DELETE FROM exchange WHERE id='x-1'")
    conn.execute("PRAGMA foreign_keys=ON")
    assert conn.execute(
        "SELECT exemplar_exchange_id FROM surface").fetchone()[0] == "x-1"

    summary = scan.run(**env, checks=(_NoPointsFinds(),),
                       bridge=_replying_bridge())
    verdict, reason, _sent = _row(conn)
    assert verdict == "skipped", (
        f"a dangling exemplar came back {verdict!r}: {reason}")
    assert summary.by_reason == {"no_exemplar": 1}


def test_a_purged_exemplar_does_not_stop_a_passive_check_reading_the_surface(
        tmp_path):
    """The separating case, and the reason this skip lives in the probe branch.

    A passive check reads the exchanges, not the exemplar, and a surface can
    have plenty of those after the one that first proved it exists is gone. It
    still runs, still answers, and still retires what it considered -- the skip
    above is about the evidence an ACTIVE finding would cite, not about the
    surface being unusable."""
    env = _env(tmp_path, exemplar=False)

    class Passive:
        id, version, klass = "hx.test.passive", "1", "passive"
        insertion_kinds = frozenset()

        def on_surface(self, ctx, surface, exchanges):
            assert exchanges, "the surface's exchanges are still readable"
            return base.Verdict.clean(considered=("looked",))

    summary = scan.run(**env, checks=(Passive(),), bridge=_replying_bridge())
    assert _row(env["conn"])[0] == "clean"
    assert summary.by_reason == {}


def test_a_check_declaring_no_insertion_kinds_runs_on_a_bare_surface(tmp_path):
    """THE SEPARATING CASE for the two skips above, and it is not
    hypothetical: Plan 6's next task writes `src/hx/checks/active/cors.py`
    with `insertion_kinds = frozenset()`, because a CORS finding has no
    insertion point -- the request is shaped by a header the check adds, not
    by a parameter it found. Skipping a check for having none of what it
    never asked for would silence the first check in this build that sends,
    which is why this test is here before that file is."""
    env = _env(tmp_path, request_bytes=REQ_WITHOUT_QUERY)

    class NoPoints:
        id, version, klass = "hx.test.nopoints", "1", "active_safe"
        insertion_kinds = frozenset()

        def __init__(self):
            self.calls = 0

        def probes(self, ctx, surface, insertions, send):
            self.calls += 1
            return base.Verdict.clean()

    check = NoPoints()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())
    assert check.calls == 1
    assert _row(env["conn"])[0] == "clean"


# --- a refusal is not an answer -------------------------------------------


def test_a_refusal_becomes_inconclusive_never_clean(tmp_path):
    """S10: a check that could not run says `inconclusive`. Driven through
    the REAL `ProbeSender` against a refusing bridge rather than by raising
    `ProbeRefused` from the check by hand -- that is the path a real refusal
    takes, and a runner that only handled a hand-raised one would let
    `budget_exhausted` off the extension arrive as something else."""
    env = _env(tmp_path)
    fb = FakeBridge()
    fb.refuse("budget_exhausted", "the run's request budget is spent")

    class Sends(_Probe):
        def probes(self, ctx, surface, insertions, send):
            send.get("/?q=1")
            return base.Verdict.clean()

    scan.run(**env, checks=(Sends(),), bridge=fb)
    verdict, reason, sent = _row(env["conn"])
    assert verdict == "inconclusive"
    assert "budget_exhausted" in reason
    # AND THE ROW SAYS ZERO REQUESTS. `hx.policy.Limiter` answers
    # `budget_exhausted` BEFORE it issues anything and increments `issued` on
    # the allow path only -- "Refusals are not issuances and do not appear
    # here" -- so nothing reached the target and `requests_sent` is what says
    # so. This assertion read `== 1` until fix round A, on the strength of a
    # comment ("the attempt spent the budget and touched the target") that
    # `Limiter` contradicts in its own words; the number reaches a client's
    # report as the traffic hx generated.
    assert sent == 0
    # And the class is named ONCE. `BridgeError`'s message already opens with
    # it, so the reason used to read `probe refused: budget_exhausted:
    # budget_exhausted: the run's request budget is spent`.
    assert reason == ("probe refused: budget_exhausted: "
                      "the run's request budget is spent")


def test_a_refusal_after_the_request_left_is_counted(tmp_path):
    """The other direction, and the separating case for the assertion above.
    A `transport_error` is a request that reached the wire and then failed,
    so it IS traffic -- understating what hx put on a client's system is the
    direction this count may not lean, and a rule written as "refusals are
    free" would zero this row too."""
    env = _env(tmp_path)
    fb = FakeBridge()
    fb.refuse("transport_error", "connection reset")

    class Sends(_Probe):
        def probes(self, ctx, surface, insertions, send):
            send.get("/?q=1")
            return base.Verdict.clean()

    scan.run(**env, checks=(Sends(),), bridge=fb)
    verdict, _reason, sent = _row(env["conn"])
    assert verdict == "inconclusive"
    assert sent == 1


def test_a_refusal_is_not_an_error_row(tmp_path):
    """The distinction the `except ProbeRefused` ordering exists for. `error`
    sends an operator looking for a bug in hx; what happened is that the
    target, the extension or the budget said no, and `inconclusive` with the
    wire's own class is the sentence that says which."""
    env = _env(tmp_path)
    fb = FakeBridge()
    fb.refuse("scope_denied")

    class Sends(_Probe):
        def probes(self, ctx, surface, insertions, send):
            send.get("/?q=1")
            return base.Verdict.clean()

    scan.run(**env, checks=(Sends(),), bridge=fb)
    assert _row(env["conn"])[0] != "error"


def test_a_refusal_retires_nothing(tmp_path):
    """`Verdict.inconclusive` takes no `considered`, and a refusal never
    reaches a verdict at all -- so a check whose probes were denied must
    close none of its earlier findings. The alternative is telling a client
    an issue is fixed because Burp refused to test it.

    OVER-DETERMINED SINCE FIX ROUND 6, like the no-bridge skip above: this
    check is active and `scan._retirable` would empty its contribution
    anyway. The `inconclusive` row is what still separates something -- a
    refusal that landed as `error` would send an operator looking for a bug
    in hx, and one that landed as `clean` would be F4 again."""
    env = _env(tmp_path)
    scan.run(**env, checks=(_Finds(),), bridge=_replying_bridge())

    class Refused(_Finds):
        def probes(self, ctx, surface, insertions, send):
            send.get("/?q=1")
            raise AssertionError("unreachable: the send above is refused")

    fb = FakeBridge()
    fb.refuse("rate_limited")
    scan.run(**env, checks=(Refused(),), bridge=fb)
    assert _last_verdict(env["conn"]) == "inconclusive"
    observed = [r[0] for r in env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert observed == [1], "a refused check retired its own finding"


def test_a_probing_check_that_raises_anything_else_is_still_error(tmp_path):
    """`except ProbeRefused` sits in front of `except Exception`, and that
    ordering must not swallow the second. One bad check still lands `error`
    and still does not end the scan."""
    env = _env(tmp_path)

    class Boom(_Probe):
        id = "hx.test.boom"

        def probes(self, ctx, surface, insertions, send):
            send.get("/?q=1")
            raise RuntimeError("check exploded")

    quiet = _Probe()
    scan.run(**env, checks=(Boom(), quiet), bridge=_replying_bridge())
    verdict, reason, sent = _row(env["conn"], "hx.test.boom")
    assert verdict == "error"
    assert "check exploded" in reason
    assert sent == 1, "what a crashing check spent is still what it spent"
    assert quiet.calls == 1
    assert _row(env["conn"], "hx.test.probe")[0] == "clean"


# --- requests_sent --------------------------------------------------------


def test_requests_sent_is_written_when_the_row_closes(tmp_path):
    """The sender counts in memory -- it holds no database connection, so
    that `CheckContext`'s "a check that can write is a check that can write
    the wrong thing" stays literally true -- and the runner writes the count.
    The stored number must equal what the check actually spent."""
    env = _env(tmp_path)
    spent = {}

    class Sends(_Probe):
        def probes(self, ctx, surface, insertions, send):
            for _ in range(3):
                send.get("/?q=1")
            spent["n"] = send.sent
            return base.Verdict.clean()

    scan.run(**env, checks=(Sends(),), bridge=_replying_bridge())
    assert spent["n"] == 3
    assert _row(env["conn"])[2] == 3


def test_a_passive_row_records_no_requests(tmp_path):
    """The separating case: `requests_sent` must not become "some number the
    runner happened to have". A passive check has no sender and sends
    nothing, and its row says 0."""
    env = _env(tmp_path)

    class Passive:
        id, version, klass = "hx.test.passive", "1", "passive"
        insertion_kinds = frozenset()

        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.clean(considered=("looked",))

    scan.run(**env, checks=(Passive(),), bridge=_replying_bridge())
    assert _row(env["conn"]) == ("clean", None, 0)


def test_checks_run_counts_the_rows_a_probe_skip_wrote(tmp_path):
    """The other half of the fix-round-1 (LOW) agreement. `checks_run` is
    `check_run` rows written, down every path -- an operator reading
    `checks 2 / skipped 2` can go and find two rows, and the same scan
    truncated by the budget instead of by a missing bridge reports the same
    two numbers."""
    env = _env(tmp_path)

    class Second(_Probe):
        id = "hx.test.probe2"

    summary = scan.run(**env, checks=(_Probe(), Second()), bridge=None)
    rows = env["conn"].execute("SELECT COUNT(*) FROM check_run").fetchone()[0]
    assert summary.checks_run == rows == 2
    assert summary.skipped == 2


# --- dispatch is on the hook, not on the class string ---------------------


def test_an_active_class_other_than_active_safe_gets_the_probe_pass(tmp_path):
    """`_HOOKS` gives `probes` to all four active classes, so a runner that
    tested `klass == "active_safe"` would silently drop `active_timing`,
    `active_mutate` and `active_dos` -- each of which would then open a row
    per surface and end it `error` on a missing `on_surface`."""
    env = _env(tmp_path)

    class Timing(_Probe):
        id, klass = "hx.test.timing", "active_timing"

    check = Timing()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())
    assert check.calls == 1
    assert _row(env["conn"])[0] == "clean"


def test_dispatch_follows_the_hook_even_when_the_class_disagrees(tmp_path):
    """THE SEPARATING CASE for the rule, and deliberately a check the
    registry would refuse at import: `active_safe` may not implement
    `on_surface`, so this pairing can never ship. It exists to tell the two
    dispatch rules apart -- on the hook, this check is called correctly; on
    `check.klass`, it is called through `probes` it does not have and ends
    `error`. The registry owns the class/hook pairing, and `scan.run` must
    not carry a second copy of that rule free to drift from it."""
    env = _env(tmp_path)

    class Mislabelled:
        id, version, klass = "hx.test.mislabelled", "1", "active_safe"
        insertion_kinds = frozenset({"query"})

        def __init__(self):
            self.calls = 0

        def on_surface(self, ctx, surface, exchanges):
            self.calls += 1
            return base.Verdict.clean(considered=("looked",))

    check = Mislabelled()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())
    assert check.calls == 1
    assert _row(env["conn"])[0] == "clean"


def test_a_passive_and_an_active_check_each_get_their_own_hook(tmp_path):
    """Dispatch is per CHECK, not per scan. A mixed corpus is the normal case
    from Plan 6 onward, and a runner that picked one hook for the whole pass
    would error every check of the other kind."""
    env = _env(tmp_path)

    class Passive:
        id, version, klass = "hx.test.passive", "1", "passive"
        insertion_kinds = frozenset()

        def __init__(self):
            self.calls = 0

        def on_surface(self, ctx, surface, exchanges):
            self.calls += 1
            return base.Verdict.clean(considered=("looked",))

    passive, active = Passive(), _Probe()
    scan.run(**env, checks=(passive, active), bridge=_replying_bridge())
    assert passive.calls == 1 and active.calls == 1
    verdicts = dict(env["conn"].execute(
        "SELECT check_id, verdict FROM check_run").fetchall())
    assert verdicts == {"hx.test.passive": "clean", "hx.test.probe": "clean"}


# --- the derivation is lazy and happens once ------------------------------


def test_insertion_points_are_derived_once_per_surface(tmp_path, monkeypatch):
    """`insertion.derive` reads a blob off disk and parses a whole request.
    Two active checks on one surface is the normal case, and deriving per
    check would pay that cost once per check for a byte-identical answer."""
    env = _env(tmp_path)
    calls = []
    real = insertion_mod.derive

    def spy(request_bytes, path_template):
        calls.append(path_template)
        return real(request_bytes, path_template)

    monkeypatch.setattr(scan.insertion_mod, "derive", spy)

    class Second(_Probe):
        id = "hx.test.probe2"

    scan.run(**env, checks=(_Probe(), Second()), bridge=_replying_bridge())
    assert calls == ["/"]


def test_a_passive_only_scan_derives_nothing(tmp_path, monkeypatch):
    """The cost a passive scan must not pay. `hx scan` with no active class
    enabled is the common case and stays entirely offline -- no session, and
    no blob read for a request nothing will probe.

    BOTH SEAMS ARE GUARDED, and the second is why this test is not merely
    about `derive` any more: the blob read moved out to `_exemplar_request`
    when the probe path started coming off the same bytes, so a passive scan
    could have begun paying for the read without ever calling `derive` -- and
    the version of this test that watched only `derive` would not have
    noticed.
    """
    env = _env(tmp_path)
    monkeypatch.setattr(
        scan.insertion_mod, "derive",
        lambda *a, **k: pytest.fail("a passive scan derived insertion points"))
    monkeypatch.setattr(
        scan, "_exemplar_request",
        lambda *a, **k: pytest.fail("a passive scan read the exemplar blob"))

    class Passive:
        id, version, klass = "hx.test.passive", "1", "passive"
        insertion_kinds = frozenset()

        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.clean()

    scan.run(**env, checks=(Passive(),), bridge=None)
    assert _row(env["conn"])[0] == "clean"


def test_a_bridgeless_active_scan_derives_nothing_either(tmp_path, monkeypatch):
    """The skip comes FIRST. With no route to the wire there is nothing to
    derive points for, and reading the blob to describe a request that will
    never be sent is work for an answer nobody gets."""
    env = _env(tmp_path)
    monkeypatch.setattr(
        scan.insertion_mod, "derive",
        lambda *a, **k: pytest.fail("derived points with no bridge to use them"))
    monkeypatch.setattr(
        scan, "_exemplar_request",
        lambda *a, **k: pytest.fail("read the exemplar blob with no bridge"))
    scan.run(**env, checks=(_Probe(),), bridge=None)
    assert _row(env["conn"])[0] == "skipped"


def test_the_shipped_cors_check_cannot_file_a_finding_it_could_not_evidence(
        tmp_path):
    """The same two cases, against the real check rather than a stand-in.

    `_NoPointsFinds` above is a faithful copy of the shape, and a copy is
    exactly what stops being faithful. `hx.active.cors` is the only registered
    check whose `insertion_kinds` is empty, which makes it the only one that
    can reach a missing exemplar at all, and it cites `surface[6]` verbatim.
    The vulnerable branch is driven both ways here so the skip cannot be
    mistaken for the reply simply not being a finding: with the exemplar
    present, the identical bridge reply files one.
    """
    reply = (b"HTTP/1.1 200 OK\r\n"
             b"Access-Control-Allow-Origin: " + cors._PROBE_ORIGIN.encode() +
             b"\r\nAccess-Control-Allow-Credentials: true\r\n\r\n{}")

    intact = _env(tmp_path / "intact")
    scan.run(**intact, checks=(cors.Cors(),),
             bridge=_replying_bridge(reply))
    assert _row(intact["conn"])[0] == "finding", \
        "the reply is not the vulnerable shape; the skip below proves nothing"

    purged = _env(tmp_path / "purged", exemplar=False)
    summary = scan.run(**purged, checks=(cors.Cors(),),
                       bridge=_replying_bridge(reply))
    assert _row(purged["conn"])[0] == "skipped"
    assert summary.by_reason == {"no_exemplar": 1}
    assert purged["conn"].execute(
        "SELECT COUNT(*) FROM finding").fetchone()[0] == 0


# --- the address a probe is sent to ---------------------------------------
#
# F1 of the whole-branch review, at the runner's end. A surface's identity is
# its `path_template` -- `hx.surface` normalises `/user/12345/profile` to
# `/user/{id}/profile` -- and every active check built its probe out of that
# string, so on any templated surface the request went to a URL that cannot
# exist, the 404 carried nothing any check looks for, and `clean` was
# recorded with `considered` populated. 35 integration tests and 1262 unit
# tests stayed green because every surface either suite ever built was
# UNTEMPLATED: `path_template == path` for all of them, so the two strings
# this defect confuses were the same string.

# The exemplar of a templated surface: a concrete request line, whose path
# `hx.surface` normalises to `TEMPLATED` below -- asserted rather than
# claimed, by the first test in this section.
REQ_TEMPLATED = (
    b"GET /user/12345/profile?q=1 HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"\r\n"
)
TEMPLATED = "/user/{id}/profile"
ADDRESS = "/user/12345/profile"


def _templated_env(tmp_path):
    return _env(tmp_path, request_bytes=REQ_TEMPLATED, path_template=TEMPLATED)


def _paths_on_the_wire(fb):
    """The request-line target of every request the bridge was handed."""
    return [body.split(b" ")[1].decode("latin-1") for body in fb.bodies]


def test_this_sections_surface_is_one_the_real_normaliser_would_produce():
    """The fixture is not a fiction. A hand-written `path_template` that
    `hx.surface` would never mint would make every test below it measure a
    shape no scan can reach, which is the same blindness as measuring only
    static routes."""
    cfg = config_mod.Config(name="T", client="T", scope_include=["*.test"])
    assert surface_mod.path_template(
        ADDRESS, preserve=frozenset(cfg.preserve_segments),
        slug_threshold=cfg.slug_threshold) == TEMPLATED
    assert TEMPLATED != ADDRESS


def test_the_sender_is_bound_to_the_exemplars_path_not_the_template(tmp_path):
    env = _templated_env(tmp_path)
    check = _Probe()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())
    assert check.seen["sender"].path == ADDRESS
    assert check.seen["surface"][5] == TEMPLATED, (
        "the check is still handed the template -- it is the surface's "
        "identity and what a path_segment insertion is named against")


def test_no_shipped_active_check_puts_a_placeholder_on_the_wire(tmp_path):
    """THE WHOLE CORPUS, against a templated surface, with the bridge as the
    witness. Driven through the real registry rather than a stand-in: F1 was
    in all five checks at once, and a test naming one of them would have gone
    green on a fix that reached only that one.

    MEASURED before the fix, with this exact surface: `hx.active.cors` sent
    `GET /user/{id}/profile`, `hx.active.sql-error` sent
    `GET /user/{id}/profile?q=<value>%27`, and both answered `clean` with
    their issue types in `considered`.
    """
    env = _templated_env(tmp_path)
    fb = _replying_bridge()
    checks = tuple(c for c in registry.CHECKS if c.klass != "passive")
    assert len(checks) == 5, checks
    scan.run(**env, checks=checks, bridge=fb)

    sent = _paths_on_the_wire(fb)
    assert sent, "no active check sent anything; this test would prove nothing"
    address = ADDRESS.split("/")          # ['', 'user', '12345', 'profile']
    for path in sent:
        assert "{" not in path and "}" not in path, path
        # Built FROM the address, not merely free of braces: the same
        # segments, except index 2 -- the one `{id}` names -- where a
        # path-segment probe substitutes its payload. A path assembled out of
        # anything else fails this whatever it is spelt with.
        segments = path.split("?")[0].split("/")
        assert len(segments) == len(address), path
        differing = [i for i, (seg, want) in enumerate(zip(segments, address))
                     if seg != want]
        assert differing in ([], [2]), path

    rows = env["conn"].execute(
        "SELECT check_id, verdict FROM check_run").fetchall()
    assert [r for r in rows if r[1] == "error"] == []


def test_a_check_that_probes_the_template_errors_rather_than_answering_clean(
        tmp_path):
    """THE STRUCTURAL HALF. The four tests above say the shipped checks build
    the right path today; this one says a check that goes back to reading
    `surface[5]` CANNOT answer `clean` from it. `ProbeSender.get` raises a
    `ValueError` -- a programmer's mistake, not a refusal from the wire -- so
    the row lands `error`, which is visible in coverage and retires nothing.
    """
    env = _templated_env(tmp_path)
    fb = _replying_bridge()

    class ProbesTheTemplate(_Probe):
        id = "hx.test.probes-the-template"

        def probes(self, ctx, surface, insertions, send):
            self.calls += 1
            send.get(surface[5])
            return base.Verdict.clean()

    scan.run(**env, checks=(ProbesTheTemplate(),), bridge=fb)
    verdict, reason, _sent = _row(env["conn"])
    assert verdict == "error", reason
    assert "placeholder" in reason
    assert fb.calls == 0, "a request to a URL that cannot exist still left"
    assert env["conn"].execute(
        "SELECT COUNT(*) FROM finding_observation").fetchone()[0] == 0


@pytest.mark.parametrize("request_bytes,why", [
    (b"OPTIONS * HTTP/1.1\r\nHost: app.test\r\n\r\n",
     "asterisk-form: a request target with no path at all"),
    (b"\r\n\r\n", "no request line to read"),
])
def test_a_surface_with_no_concrete_path_is_skipped_never_clean(
        tmp_path, request_bytes, why):
    """S12 again, one column further in. The surface row's `path_template` is
    an identity, so a surface whose exemplar yields no ADDRESS has nowhere a
    probe could honestly go -- and the alternative to this skip is sending
    one at the template, which is F1."""
    env = _env(tmp_path, request_bytes=request_bytes)
    fb = _replying_bridge()
    check = _Probe()
    summary = scan.run(**env, checks=(check,), bridge=fb)

    verdict, reason, sent = _row(env["conn"])
    assert (verdict, sent) == ("skipped", 0), why
    assert "path" in reason
    assert check.calls == 0
    assert fb.calls == 0, "the skip is decided before a sender exists"
    assert summary.by_reason == {"no_probe_path": 1}


def test_a_surface_whose_exemplar_request_was_never_stored_is_skipped(tmp_path):
    """The same skip from the other direction: the exchange row is there, so
    `_citable_exemplar` is satisfied and a finding WOULD have something to
    cite, but its request blob is not -- so there is no address to send to.
    `hx.capture` writes `req_blob` NULL for a request it never saw the bytes
    of."""
    env = _env(tmp_path)
    env["conn"].execute("UPDATE exchange SET req_blob=NULL WHERE id='x-1'")
    summary = scan.run(**env, checks=(_NoPointsFinds(),),
                       bridge=_replying_bridge())
    assert _row(env["conn"])[0] == "skipped"
    assert summary.by_reason == {"no_probe_path": 1}



# --- points the send path structurally refuses ----------------------------
#
# F2 of the whole-branch review. `Sender.decide()` refuses any request
# carrying a `Cookie`, `Authorization` or `Proxy-Authorization` header the
# extension did not itself inject; `insertion.derive` returns points sorted
# by `(kind, name)`, so `cookie` sorted FIRST and `hx.active.reflected-input`
# spent its first probe of every cookie-bearing surface -- that is, every
# authenticated engagement -- on a guaranteed refusal, which then propagated
# out of the check and took its query and path-segment points with it.
#
# Every request below is a `FakeBridge` call. Nothing here binds a socket.

REQ_AUTHENTICATED = (
    b"GET /search?q=hello HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"Cookie: session=abc; csrf=def\r\n"
    b"Authorization: Bearer token-value\r\n"
    b"Accept: text/html\r\n"
    b"\r\n"
)
REQ_COOKIE_ONLY = (
    b"GET /dashboard HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"Cookie: session=abc\r\n"
    b"\r\n"
)


def _headers_on_the_wire(fb):
    """Every header name every request the bridge was handed carried."""
    out = []
    for body in fb.bodies:
        for line in body.split(b"\r\n")[1:]:
            if b":" in line:
                out.append(line.split(b":", 1)[0].decode("latin-1"))
    return out


class _AllKinds(_Probe):
    """A check declaring every kind `insertion.derive` can produce for a
    GET, so what it is HANDED is the runner's decision and not its own."""
    id = "hx.test.allkinds"
    insertion_kinds = frozenset({"query", "path_segment", "header", "cookie"})


def test_a_point_the_send_path_refuses_is_never_handed_to_a_check(tmp_path):
    """POINT ONE OF F2. The refusal is a property of the point, decidable
    before anything is sent, so the attempt is not made at all: it would
    spend a bridge round trip and could only ever answer
    `unmanaged_credential`. The query and header points on the same surface
    still arrive."""
    env = _env(tmp_path, request_bytes=REQ_AUTHENTICATED)
    check = _AllKinds()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())

    handed = {(i.kind, i.name) for i in check.seen["insertions"]}
    assert ("query", "q") in handed
    assert ("header", "Accept") in handed
    assert ("cookie", "session") not in handed
    assert ("cookie", "csrf") not in handed
    assert ("header", "Authorization") not in handed
    # ANTI-VACUITY: the points really are on this surface, so their absence
    # above is the runner declining them rather than the derivation never
    # having found them.
    derived = {(i.kind, i.name) for i in insertion_mod.derive(
        REQ_AUTHENTICATED, "/search")}
    assert {("cookie", "session"), ("cookie", "csrf"),
            ("header", "Authorization")} <= derived


def test_a_surface_whose_only_points_are_refused_ones_says_so(tmp_path):
    """A DIFFERENT SKIP FROM `no_insertion_point`, and the difference is the
    whole of S12: this surface HAS points of a kind the check wants, and
    none of them can be reached. Saying "no insertion point of kind
    ['cookie', ...] on this surface" would be false about the surface."""
    env = _env(tmp_path, request_bytes=REQ_COOKIE_ONLY, path_template="/dashboard")
    fb = _replying_bridge()
    check = _AllKinds()
    summary = scan.run(**env, checks=(check,), bridge=fb)

    verdict, reason, sent = _row(env["conn"])
    assert (verdict, sent) == ("skipped", 0)
    assert summary.by_reason == {"no_probeable_insertion_point": 1}
    assert "refuses" in reason
    assert check.calls == 0
    assert fb.calls == 0, "a probe was spent on a guaranteed refusal"


REQ_ONLY_REFUSED_POINTS = (
    b"GET /dashboard HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"Cookie: session=abc; csrf=def\r\n"
    b"Authorization: Bearer t\r\n"
    b"\r\n"
)


def test_the_skip_says_which_points_the_send_path_refused(tmp_path):
    """Concern 5 of fix round 3, and the difference between "some" and
    "which".

    `probe.unprobeable` builds a sentence per point saying which of its TWO
    rules refused it -- a cookie of any name, or a header the extension did
    not inject -- and `scan.run` was its only caller: it tested each answer
    for `None` and discarded the string. The row therefore named the rule set
    (`CREDENTIAL_HEADERS`) and never the points, so an operator reading
    `hx.report._coverage` could not tell a surface stopped by one session
    cookie from one stopped by a bearer token, and had no name to go and look
    at.

    THREE POINTS, TWO RULES, and that is what makes this more than a spelling
    test: `insertion.derive` sorts by `(kind, name)`, all three fit under
    `_http._GAPS_SHOWN`, and the two rules have to read differently in the one
    row. A `True`/`False` refusal could not produce any of it.
    """
    env = _env(tmp_path, request_bytes=REQ_ONLY_REFUSED_POINTS,
               path_template="/dashboard")
    summary = scan.run(**env, checks=(_AllKinds(),), bridge=_replying_bridge())

    verdict, reason, sent = _row(env["conn"])
    assert (verdict, sent) == ("skipped", 0)
    assert summary.by_reason == {"no_probeable_insertion_point": 1}
    for point in ("cookie 'csrf'", "cookie 'session'", "header 'Authorization'"):
        assert point in reason, (point, reason)
    assert "a cookie is probed by sending a Cookie header" in reason
    assert "credential header it did not inject" in reason
    # AND IT IS THE SHAPE A COVERAGE ROW EXPECTS. `_http._detail` is what
    # bounds this list at three and counts the rest; a reason built by hand
    # here would be a second spelling free to grow without bound, in the one
    # column `report._coverage` deliberately does not group on.
    assert reason.endswith(_http._detail(tuple(
        probe.unprobeable(i)
        for i in insertion_mod.derive(REQ_ONLY_REFUSED_POINTS, "/dashboard")))), \
        reason


def test_the_shipped_reflected_input_check_probes_a_cookie_bearing_surface(
        tmp_path):
    """THE DEFECT, AGAINST THE REAL CHECK. `hx.active.reflected-input` is the
    corpus's flagship and F2's measured victim: on this exemplar it used to
    send `Cookie: csrf=<canary>` first, be refused `unmanaged_credential`,
    and close the whole surface `inconclusive` having tested nothing.

    Driven through `scan.run` and the real registry entry rather than the
    check alone, because the fix is split across the two: the runner declines
    the cookie and credential-header points, and the check no longer lets a
    refusal end its loop.
    """
    env = _env(tmp_path, request_bytes=REQ_AUTHENTICATED,
               path_template="/search")
    fb = _replying_bridge()
    check = next(c for c in registry.CHECKS
                 if c.id == "hx.active.reflected-input")
    scan.run(**env, checks=(check,), bridge=fb)

    verdict, reason, sent = _row(env["conn"])
    assert verdict == "clean", f"{verdict}: {reason}"
    assert sent >= 1, "the check probed nothing at all"
    assert "Cookie" not in _headers_on_the_wire(fb)
    assert "Authorization" not in _headers_on_the_wire(fb)
    # The points it DID reach: the query parameter on the request line, and
    # the one ordinary header.
    assert any(b"GET /search?q=" in body for body in fb.bodies), fb.bodies
    assert "Accept" in _headers_on_the_wire(fb)


# --- an active check retires nothing ---------------------------------------
#
# FIX ROUND 6, AND IT IS A CAPABILITY REMOVED ON PURPOSE. Retirement is
# `_mark_unobserved` writing `observed = 0`, which `report._findings` renders
# to a client as "appears fixed; verify before closing". Every probe this
# build sends is unauthenticated, so an active check's `clean` is a statement
# about the LOGGED-OUT view of the application -- and the shape that made
# that fatal is an application answering a logged-out request with a 200
# login PAGE, which no set of statuses can tell from an answer. Fix round 5
# tried to suppress retirement only where the capture carried a credential
# header; that predicate keyed on the FIRST sighting and could only read a
# header NAME (the value is redacted before the digest, S7), so it could not
# tell a session cookie from an analytics one. The rule is now flat, lives at
# the runner (`scan._retirable`), and the tests below drive it from three
# directions: a real check that would have retired, a synthetic one that
# tries to, and the whole registry.
#
# POINT TWO OF F2 IS STILL HERE, in the first test: a refusal on one
# insertion point must not abort the check, so the point that DID answer is
# still probed and its finding still re-found.

# An ordinary anonymous capture with two reflecting parameters. It carried
# `Cookie: session=abc` from F2 until fix round 5, which removed it because
# the rule of the day keyed on that header; nothing keys on it now, and the
# constant stays anonymous because the surface it stands for -- a search page
# a browser reached without logging in -- is the simplest thing that produces
# two findings.
REQ_TWO_PARAMS = (
    b"GET /search?q=hello&r=world HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"\r\n"
)


class _EchoBridge(FakeBridge):
    """A reflecting target: the request line's target comes back in the body,
    percent-decoded the way an application's own framework hands it to a
    template. `hx.active.reflected-input` finds a reflection on every query
    parameter against this, which is what gives the tests below something
    real that a retirement would have closed.

    `blind_to` names a query parameter this target does NOT echo -- one of
    two reflections genuinely fixed. It is the separating case: without it,
    "nothing was retired" cannot be told apart from "this scan never had a
    fixed issue in front of it".
    """

    def __init__(self, blind_to: str | None = None) -> None:
        super().__init__()
        self._blind_to = blind_to

    def send(self, req, body=b"", timeout=30.0, *, enforce_locally=True):
        target = body.split(b"\r\n", 1)[0].split(b" ")[1]
        if self._blind_to and f"{self._blind_to}=".encode() in target:
            target = target.split(b"?")[0]
        self.reply({"status": 200, "outcome": "ok"},
                   b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                   + unquote_to_bytes(target))
        return super().send(req, body, timeout,
                            enforce_locally=enforce_locally)


def _observations(conn):
    return conn.execute(
        "SELECT f.insertion_name, o.observed FROM finding_observation o"
        " JOIN finding f ON f.id = o.finding_id"
        " ORDER BY f.insertion_name, o.ts_us").fetchall()


def _reflected_input():
    return next(c for c in registry.CHECKS
                if c.id == "hx.active.reflected-input")


def test_a_refusal_on_one_point_does_not_cost_the_other_its_probe(tmp_path):
    """POINT TWO OF F2, which is what survives of this test after fix round
    6. Two reflecting parameters, then a rescan in which the first point is
    refused: the second must still be probed and still be re-found, which is
    the third `("r", 1)` row below. Before F2 the refusal propagated out of
    the check's own loop and took every point after it, so there was no third
    row at all.

    `budget_exhausted` rather than `rate_limited` because the sender retries
    the second -- three attempts and two waits -- so a `times=1` rate limit
    would be paced out and answered rather than refused.

    IT NO LONGER SEPARATES ANYTHING ABOUT RETIREMENT. It used to: `q`'s
    finding staying live was the refusal withholding `considered`. Nothing an
    active check says retires anything now, so that half is guaranteed by the
    runner and asserted where the runner is -- see the two tests below.
    """
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")
    scan.run(**env, checks=(_reflected_input(),), bridge=_EchoBridge())
    assert _observations(env["conn"]) == [("q", 1), ("r", 1)], (
        "the first scan did not find both reflections; nothing below "
        "would prove anything")

    refusing = _EchoBridge()
    refusing.refuse("budget_exhausted", "the run's request budget is spent",
                    times=1)
    scan.run(**env, checks=(_reflected_input(),), bridge=refusing)

    verdict, reason, _sent = _row(env["conn"])
    assert verdict == "finding", f"{verdict}: {reason}"
    assert _observations(env["conn"]) == [("q", 1), ("r", 1), ("r", 1)], (
        "the point that answered was never reached, so the refusal took the "
        "whole check down with it")


def test_a_point_that_answered_and_found_nothing_does_not_retire(tmp_path):
    """THE CAPABILITY REMOVED, on the sharpest case available: a REAL check,
    a REAL probe, and a flaw that is genuinely gone.

    Same two parameters, no refusal, and the target has stopped reflecting
    `q`. The check sends, gets an ordinary 200, finds nothing in it and says
    `clean` for `q` -- and `q`'s finding still may not close, because the
    request that produced that `clean` carried no session and an application
    that answers a logged-out request with a 200 login page is
    indistinguishable from this one here.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? This is the test that reddened.
    Up to fix round 5 it was `test_a_point_that_answered_and_found_nothing_
    still_retires` and asserted `[("q", 1), ("q", 0), ("r", 1), ("r", 1)]`,
    against this exact bridge and this exact check. `("q", 0)` is the
    retirement, and it is what `report._findings` renders as "appears fixed;
    verify before closing".

    NOT VACUOUS: the row proves the probe really went and really answered
    (`clean`, with requests on the wire), and
    `test_a_passive_check_still_retires` below shows the retirement machinery
    itself is still live on the same store.
    """
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")
    scan.run(**env, checks=(_reflected_input(),), bridge=_EchoBridge())
    assert _observations(env["conn"]) == [("q", 1), ("r", 1)]

    scan.run(**env, checks=(_reflected_input(),),
             bridge=_EchoBridge(blind_to="q"))

    verdict, reason, sent = _row(env["conn"])
    assert verdict == "finding", f"{verdict}: {reason}"
    assert sent > 0, (
        "the second scan sent nothing, so the `q` row is not a real `clean` "
        "and this measures a skip rather than a suppressed retirement")
    assert _observations(env["conn"]) == [("q", 1), ("r", 1), ("r", 1)], (
        "an active check retired a finding: a client is told a live "
        "vulnerability appears fixed on the strength of a probe that saw "
        "only the logged-out view")


def test_the_verdict_and_the_row_are_exactly_what_the_check_said(tmp_path):
    """WHAT IS AND IS NOT SUPPRESSED. Only the retirement goes. The finding
    is still filed, the row still says `finding`, `requests_sent` is still
    the traffic that went, and the Reason cell is still what the verdict
    carried -- which for a `finding` is nothing.

    THE LAST ASSERTION IS THE ONE WITH HISTORY. Fix round 5 appended a
    sentence to this cell on every row it suppressed ("...UNAUTHENTICATED
    view of an authenticated surface: it is reported, and it retires nothing
    here"), because retirement was CONDITIONAL then and a reader of one row
    could not tell which kind it was. It is unconditional now: every active
    row behaves the same way, `report._limits` says so once, and a constant
    string repeated on every active row would be noise in the cell that
    carries gap lists and skip reasons."""
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")
    scan.run(**env, checks=(_reflected_input(),), bridge=_EchoBridge())

    verdict, reason, sent = _row(env["conn"])
    # 4 = two reflecting parameters, each costing a canary probe and then the
    # escalation `reflected_input` spends to learn whether the context lets a
    # character-bearing value through.
    assert (verdict, sent) == ("finding", 4), (verdict, reason, sent)
    assert env["conn"].execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 2
    assert reason is None, reason


def test_an_active_check_that_populates_considered_is_an_error_row(tmp_path):
    """THE RUNNER REFUSES IT RATHER THAN DROPPING IT, and this is the half a
    future active check meets. The five shipped checks name what they
    examined to `_probe_util.verdict` as `examined`, which never reaches
    `Verdict.considered` -- so a probing check arriving here with a populated
    one is an author who believed it would retire something, and silently
    discarding it would leave that belief in the tree unfalsified. It lands
    as an `error` row through `run`'s per-check `except Exception`: loud,
    scoped to the one check, and retiring nothing.

    The message names both ends, because an author reading it has to know
    where to put the value instead."""
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")

    class Retires(_Probe):
        id = "hx.test.retires"

        def probes(self, ctx, surface, insertions, send):
            self.calls += 1
            return base.Verdict.clean(considered=("probed",))

    check = Retires()
    scan.run(**env, checks=(check,), bridge=_replying_bridge())

    assert check.calls == 1, "the check never ran, so nothing was refused"
    verdict, reason, _sent = _row(env["conn"], "hx.test.retires")
    assert verdict == "error", (verdict, reason)
    assert "considered" in reason and "examined" in reason, reason


def test_no_probing_check_in_the_corpus_retires_anything(tmp_path):
    """THE WHOLE REGISTRY, and driven through the runner rather than the
    checks -- which is where the rule lives, so that a sixth active check
    inherits it without being told.

    Every check gets an ordinary 200 that its own filter accepts, so each of
    them answers `clean` (or `finding`) having genuinely examined something:
    the surface carries `q`, `redirect_uri` and `file`. The capture is
    ANONYMOUS, which is the case fix round 5's rule deliberately left
    retiring -- so this is the measurement that moved.

    Read off `scan.run`'s own call to `_mark_unobserved` rather than
    reconstructed from the rows: `check_run.verdict` is NOT the retirement
    gate (a check filing one of three findings answers `finding` and the
    other two would still retire), so a test that read the verdicts would be
    asserting against the mechanism this fix does not touch."""
    env = _env(tmp_path, request_bytes=REQ_EVERY_SHAPE, path_template="/search")
    active = tuple(c for c in registry.CHECKS if c.klass != "passive")
    assert len(active) == 5, "the corpus changed shape; re-read this test"

    considered = _considered_by(env, active, _replying_bridge())
    assert considered == set(), (
        "an active check entered an issue type into the set "
        "`_mark_unobserved` retires on; every probe this build sends is "
        f"unauthenticated: {sorted(considered)}")

    # NOT VACUOUS, TWICE OVER, and the first half is the one that matters.
    # EVERY check reached a conclusion off a probe that went, so each of them
    # would have contributed under the old rule -- without this, five checks
    # that quietly stopped examining anything satisfy the assertion above.
    # Fix round 5 got this control by re-running the corpus on an ANONYMOUS
    # capture, which is no longer a case that contributes anything.
    rows = env["conn"].execute(
        "SELECT check_id, verdict, requests_sent FROM check_run").fetchall()
    assert {c.id for c in active} == {r[0] for r in rows}, rows
    for check_id, verdict, sent in rows:
        assert (verdict in ("clean", "finding")) and sent > 0, (
            f"{check_id} examined nothing on this surface, so its empty "
            f"contribution above says nothing: {(verdict, sent)}")

    # And the spy itself sees what it is meant to see: same store shape, one
    # passive check, and it contributes.
    passive = _env(tmp_path / "passive", request_bytes=REQ_EVERY_SHAPE,
                   path_template="/search")
    assert _considered_by(passive, (_PassiveOnce(),), None), (
        "the spy saw nothing even from a passive check, so the assertion "
        "above is satisfied by a broken measurement")


def _considered_by(env, checks, bridge) -> set:
    """The `(check_id, issue_type_id)` pairs one scan would retire on."""
    seen = set()
    real = scan._mark_unobserved

    def spy(conn, engagement_id, run_id, found, considered):
        seen.update((cid, issue) for _s, cid, issue in considered)
        return real(conn, engagement_id, run_id, found, considered)

    scan._mark_unobserved = spy
    try:
        scan.run(**env, checks=checks, bridge=bridge)
    finally:
        scan._mark_unobserved = real
    return seen


def test_a_passive_check_still_retires(tmp_path):
    """THE RULE IS THE PROBE'S, NOT THE FINDING'S OR THE SURFACE'S. A passive
    check reads the captured exchanges themselves -- the very traffic the
    operator's own browser produced, session and all -- so it was never
    looking at a different view of the application, and nothing about it
    changed. A rule keyed on the finding, or on the surface, or written into
    `_mark_unobserved` rather than into what reaches it would have taken the
    passive corpus's whole retest story with it."""
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")
    check = _PassiveOnce()
    scan.run(**env, checks=(check,), bridge=None)
    assert _observations(env["conn"]) == [("q", 1)]

    scan.run(**env, checks=(check,), bridge=None)
    assert _observations(env["conn"]) == [("q", 1), ("q", 0)], (
        "a passive check stopped being able to show a fix, which is not what "
        "this rule is about")


class _PassiveOnce:
    """Finds it the first time it is asked and considers it clean after.

    The two states one behind the other are what a retirement needs, and a
    passive check is the only way to reach `scan.run`'s other branch. The
    candidate is minimal and cites the surface's own exemplar, which is what
    `Candidate.__post_init__` requires."""

    id, version, klass = "hx.test.passive-once", "1", "passive"
    _ISSUE = "test-passive-issue"

    def __init__(self) -> None:
        self.calls = 0

    def on_surface(self, ctx, surface, exchanges):
        self.calls += 1
        if self.calls > 1:
            return base.Verdict.clean(considered=(self._ISSUE,))
        return base.Verdict.finding(base.Candidate(
            title="Something a passive check found",
            issue_type_id=self._ISSUE, severity="Low", confidence="Firm",
            insertion=base.Insertion("query", "q"),
            exchange_ids=(surface[6],)), considered=(self._ISSUE,))


# --- a login wall is not a clean result ------------------------------------
#
# N1 of the scoped re-review. Every probe this build sends is unauthenticated
# (disclosed in `report._limits`), and the ordinary answer a BROWSER-FACING
# application gives an unauthenticated request is not a 401 -- it is a 302 to
# a login page, which is exactly the traffic hx captures through a proxy. A
# 3xx used to sit outside `_probe_util._NOT_AN_ANSWER` on the ground that it
# is `open_redirect`'s own finding; it is, and that is a fact about ONE check
# rather than about the doctrine.


class _LoginWallBridge(FakeBridge):
    """A target that has stopped answering: every request is bounced to a
    login page. Nothing here refuses -- the bridge, the gate and the budget
    are all happy, and a complete HTTP response comes back. What did not
    happen is the application answering."""

    def __init__(self) -> None:
        super().__init__()
        self.reply({"status": 302, "outcome": "ok"},
                   b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n")


def _latest_row(conn):
    return conn.execute(
        "SELECT verdict, reason, requests_sent FROM check_run"
        " ORDER BY ended_us DESC, started_us DESC LIMIT 1").fetchone()


def test_a_login_redirect_is_not_a_clean_result(tmp_path):
    """MEASURED END TO END, the way the re-review measured it. Run 1 the
    target reflects and two findings are filed; run 2 the same target sits
    behind a login wall and answers 302 to everything. Nothing was tested,
    so the row may not say `clean`: `report._coverage` groups on (check_id,
    verdict) and counts surfaces, and a client reading `clean` there is
    reading a coverage claim no request backs.

    THE OBSERVATION ASSERTION IS NO LONGER WHAT THIS SEPARATES, and the name
    changed with it. Until fix round 6 the harm was the RETIREMENT -- a
    `clean` here populated `considered` and `_mark_unobserved` wrote
    `observed = 0`, which `report._findings` renders as "appears fixed;
    verify before closing" for a live cross-site scripting vector. No active
    check retires anything now, so that row is guarded by the runner whatever
    this doctrine does; it is asserted below as the consequence and the
    `inconclusive` verdict is the claim."""
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")
    scan.run(**env, checks=(_reflected_input(),), bridge=_EchoBridge())
    assert _observations(env["conn"]) == [("q", 1), ("r", 1)], (
        "the first scan did not find both reflections; nothing below "
        "would prove anything")

    scan.run(**env, checks=(_reflected_input(),), bridge=_LoginWallBridge())

    verdict, reason, sent = _latest_row(env["conn"])
    assert verdict == "inconclusive", f"{verdict}: {reason}"
    assert sent > 0, "the second scan probed nothing, so it proves nothing"
    assert _observations(env["conn"]) == [("q", 1), ("r", 1)], (
        "a live finding was retired on the strength of a probe that reached "
        "a login page -- which the runner now forbids outright, so this is "
        "the second guard failing as well as the first")


# One request carrying a point every probing check's own name filter accepts,
# so that a corpus-wide assertion is about the doctrine and not about which
# checks happened to find something to probe.
REQ_EVERY_SHAPE = (
    b"GET /search?q=hello&redirect_uri=/home&file=notes.txt HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"\r\n"
)


def test_every_probing_check_reads_a_login_wall_as_a_gap(tmp_path):
    """The whole active corpus, not one check. The registry's own checks are
    driven against a target that 302s everything; not one of them may close
    `clean`, because `clean` is the coverage table's claim that this surface
    was tested and none of them tested anything."""
    env = _env(tmp_path, request_bytes=REQ_EVERY_SHAPE,
               path_template="/search")
    active = tuple(c for c in registry.CHECKS if c.klass != "passive")
    assert len(active) == 5, "the corpus changed shape; re-read this test"
    scan.run(**env, checks=active, bridge=_LoginWallBridge())

    rows = dict(env["conn"].execute(
        "SELECT check_id, verdict FROM check_run").fetchall())
    clean = sorted(cid for cid, v in rows.items() if v == "clean")
    assert clean == [], f"a login wall was read as a clean result: {clean}"


# --- a check whose own filter matched nothing -----------------------------
#
# N3 of the scoped re-review. `open_redirect` and `path_traversal` each apply
# a name filter of their own AFTER the runner has handed them their points,
# so a surface with query parameters but no matching NAME reached their
# verdict with nothing probed. `considered` was empty, so nothing retired --
# but the row read `clean` with `requests_sent = 0`, and `report._coverage`
# counts surfaces per (check, verdict). A real engagement rendered most of
# the corpus as `open-redirect | clean` for a check that probed a handful.


def test_a_check_whose_filter_matched_nothing_does_not_answer_clean(tmp_path):
    """Measured at the runner, where the coverage row is actually written:
    `q` is a real, probeable query point -- so the runner does NOT skip this
    surface -- and neither of the two name-filtering checks probes it."""
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")
    filtering = tuple(c for c in registry.CHECKS if c.id in {
        "hx.active.open-redirect", "hx.active.path-traversal"})
    assert len(filtering) == 2
    fb = _replying_bridge()
    scan.run(**env, checks=filtering, bridge=fb)

    rows = env["conn"].execute(
        "SELECT check_id, verdict, requests_sent FROM check_run"
        " ORDER BY check_id").fetchall()
    assert [(v, n) for _c, v, n in rows] == [("inconclusive", 0),
                                             ("inconclusive", 0)], rows
    assert fb.calls == 0, "a check that answered for this surface sent nothing"


# --- a truncated run may not close as a completed one ---------------------
#
# F11 of the whole-branch review. `stop_reason` was built from `by_reason`,
# which counts SKIPS. `budget_exhausted` is not a skip: it arrives as a
# refusal and closes its `check_run` row `inconclusive`, so a scan that spent
# its whole `max_requests` at surface 10 of 500 closed `('completed', NULL)`
# -- byte-identical at the run row to a pass that covered all 500.


def _run_row(conn):
    return conn.execute(
        "SELECT status, stop_reason FROM run WHERE kind='scan'").fetchone()


def test_a_budget_exhausted_scan_says_so_at_the_run_row(tmp_path):
    """The run row is where a report decides whether to trust a pass, and a
    pass that ran out of budget did not do what it set out to do."""
    env = _env(tmp_path)
    fb = FakeBridge()
    fb.refuse("budget_exhausted", "the run's request budget is spent")
    summary = scan.run(**env, checks=(_reflected_input(),), bridge=fb)

    status, stop_reason = _run_row(env["conn"])
    assert status == "completed"
    assert stop_reason is not None, (
        "a scan that spent its whole budget closed identically to one that "
        "covered every surface")
    assert "budget_exhausted" in stop_reason
    assert summary.refused == {"budget_exhausted": 1}
    # The row itself is unchanged: still `inconclusive`, still not a skip.
    assert _row(env["conn"])[0] == "inconclusive"
    assert summary.by_reason == {}


def test_a_refusal_the_check_swallowed_still_reaches_the_run_row(tmp_path):
    """THE SEAM F11 ACTUALLY CROSSES. Since F2 a check catches its own
    refusals per insertion point and answers with a verdict, so `scan.run`'s
    `except ProbeRefused` never fires for them -- counting refusals there
    would have recorded nothing at all for the case this fix is about. The
    count is read off the sender instead. Here the check reports a finding
    from the point that answered, so nothing raised anywhere, and the run row
    must still say a probe was refused."""
    env = _env(tmp_path, request_bytes=REQ_TWO_PARAMS, path_template="/search")
    refusing = _EchoBridge()
    refusing.refuse("budget_exhausted", "the run's request budget is spent",
                    times=1)
    summary = scan.run(**env, checks=(_reflected_input(),), bridge=refusing)

    assert _row(env["conn"])[0] == "finding", "nothing was found; retest me"
    assert summary.refused == {"budget_exhausted": 1}
    assert "budget_exhausted" in _run_row(env["conn"])[1]


def test_a_scan_that_was_neither_skipped_nor_refused_has_no_stop_reason(
        tmp_path):
    """The other half, as with the budget skip: an always-set reason tells a
    report nothing about which scans to trust."""
    env = _env(tmp_path)
    summary = scan.run(**env, checks=(_reflected_input(),),
                       bridge=_replying_bridge())
    assert summary.refused == {}
    assert _run_row(env["conn"]) == ("completed", None)


def test_a_paced_rate_limit_is_not_reported_as_a_truncation(tmp_path,
                                                            monkeypatch):
    """THE SEPARATING CASE for "terminal refusals only". `ProbeSender` waits
    out a `rate_limited` refusal and retries; a scan that was merely paced
    ran everything it set out to run, and a run row calling that truncated
    would train an operator to ignore the field."""
    monkeypatch.setattr(scan.probe.time, "sleep", lambda s: None)
    env = _env(tmp_path)
    fb = _replying_bridge()
    fb.refuse("rate_limited", "rate limit 3/s", retry_after_us=1000, times=1)
    summary = scan.run(**env, checks=(_reflected_input(),), bridge=fb)

    assert _row(env["conn"])[0] == "clean"
    assert summary.refused == {}
    assert _run_row(env["conn"]) == ("completed", None)
