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
from hx.checks import base, probe
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


def _env(tmp_path, *, request_bytes=REQ_WITH_QUERY, exemplar=True):
    """An in-memory engagement with one surface, one exchange, one blob.

    `exemplar=False` writes the exchange and leaves `surface.
    exemplar_exchange_id` NULL -- a surface whose first sighting was purged,
    which is the case `_insertions_for` has to survive without taking the
    scan down.
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
        " VALUES('s-1','e-1','GET','https','app.test',443,'/','proxy',1)")
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
    produce the same honest `skipped` any other underivable surface does."""
    env = _env(tmp_path, exemplar=False)
    summary = scan.run(**env, checks=(_Probe(),), bridge=_replying_bridge())
    assert _row(env["conn"])[0] == "skipped"
    assert summary.by_reason == {"no_insertion_point": 1}


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
    # The attempt spent the budget and touched the target whether or not an
    # answer came back; a count that omitted refusals would understate the
    # traffic hx put on a client's system.
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
