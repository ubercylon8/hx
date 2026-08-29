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

import pytest

from hx import config as config_mod
from hx import insertion as insertion_mod
from hx import scan
from hx.checks import base, probe, registry
from hx.checks.active import cors
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
         path_template="/"):
    """An in-memory engagement with one surface, one exchange, one blob.

    `exemplar=False` writes the exchange and leaves `surface.
    exemplar_exchange_id` NULL -- a surface whose first sighting was purged,
    which is the case `_exemplar_request` has to survive without taking the
    scan down.

    `path_template` is the surface row's own, and it is a SEPARATE argument
    from `request_bytes` on purpose: a templated surface and the concrete
    request it was normalised from are two different strings, and the whole
    of F1 was code that treated them as one.
    """
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','T','T',1,'active')")
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-1','e-1','GET','https','app.test',443,?,'proxy',1)",
        (path_template,))
    store = blobs_mod.BlobStore(tmp_path / "blobs")
    digest, _ = store.put(request_bytes)
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url, req_blob) VALUES('x-1', NULL, 's-1', 'proxy', 'ok', 1,"
        " 'GET', 'https://app.test/?q=1', ?)", (digest,))
    if exemplar:
        conn.execute(
            "UPDATE surface SET exemplar_exchange_id='x-1' WHERE id='s-1'")
    cfg = config_mod.Config(
        name="T", client="T", scope_include=["*.test"],
        checks=dict(config_mod.DEFAULT_CHECKS))
    return {"conn": conn, "engagement_id": "e-1", "blobs": store,
            "config": cfg}


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
        return base.Verdict.clean(considered=("probed",))


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
            return base.Verdict.clean(considered=("probed",))

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
            exchange_ids=(surface[6],)), considered=("probed",))


def test_a_no_bridge_skip_retires_nothing(tmp_path):
    """The consequence that makes the `skipped` row worth writing. A check
    that never ran examined nothing, so `considered` gains nothing and
    `_mark_unobserved` closes none of its prior findings -- "I did not look"
    must not read as "it is fixed". Two real scans rather than a hand-built
    `finding` row: the first one is what puts the finding there, so the
    dedupe key and the observation are the runner's own."""
    env = _env(tmp_path)
    scan.run(**env, checks=(_Finds(),), bridge=_replying_bridge())
    scan.run(**env, checks=(_Finds(),), bridge=None)
    observed = [r[0] for r in env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY ts_us")]
    assert observed == [1], "a check that never ran retired its own finding"


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
            return base.Verdict.clean(considered=("probed",))

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
            return base.Verdict.clean(considered=("probed",))

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
            return base.Verdict.clean(considered=("probed",))

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
            return base.Verdict.clean(considered=("probed",))

    scan.run(**env, checks=(Sends(),), bridge=fb)
    assert _row(env["conn"])[0] != "error"


def test_a_refusal_retires_nothing(tmp_path):
    """`Verdict.inconclusive` takes no `considered`, and a refusal never
    reaches a verdict at all -- so a check whose probes were denied must
    close none of its earlier findings. The alternative is telling a client
    an issue is fixed because Burp refused to test it."""
    env = _env(tmp_path)
    scan.run(**env, checks=(_Finds(),), bridge=_replying_bridge())

    class Refused(_Finds):
        def probes(self, ctx, surface, insertions, send):
            send.get("/?q=1")
            raise AssertionError("unreachable: the send above is refused")

    fb = FakeBridge()
    fb.refuse("rate_limited")
    scan.run(**env, checks=(Refused(),), bridge=fb)
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
            return base.Verdict.clean(considered=("probed",))

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
    no blob read for points nothing will probe."""
    env = _env(tmp_path)
    monkeypatch.setattr(
        scan.insertion_mod, "derive",
        lambda *a, **k: pytest.fail("a passive scan derived insertion points"))

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
# `hx.surface` would normalise to `TEMPLATED_SURFACE` below.
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
            return base.Verdict.clean(considered=("probed",))

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

