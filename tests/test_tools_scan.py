# tests/test_tools_scan.py
"""scan.run and crawl.run at the dispatcher.

`crawl.run` used to be registered and permanently unavailable; both of those
tests moved on with the tool. What is left here is the same shape `scan.run`
already had: a real handler, gated by `needs_egress` and a run-kind bracket
the dispatcher and the handler enforce together. The envelope-level tests for
`crawl.run`'s own behaviour -- the identity refusal, the summary projection
-- live in `tests/test_crawl_tool.py`, closer to the handler they exercise;
what belongs here is that the DISPATCHER's guards see it the same way they
see `scan.run`.
"""
from __future__ import annotations

from hx import run as run_mod
from hx import scan as scan_mod
from hx.crawl import run as crawl_run_mod
from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401
from tests.test_probe import FakeBridge


def _crawl_session():
    """What `ctx.session` needs for `crawl.run` to get past the dispatcher's
    `no_session` guard and reach the handler's own `crawler_port` read."""
    return type("S", (), {"bridge": FakeBridge(), "crawler_port": 41999})()


def test_crawl_run_needs_a_session(tool_ctx):
    """`needs_egress=True` on the spec means the dispatcher refuses
    `no_session` before the handler ever runs -- the same guard `scan.run`
    gets, and the one the old stub never reached because it always raised
    first.

    MUTATION: drop `needs_egress=True` from the `crawl.run` registration.
    Must go red -- `tool_ctx` has no open run either, so a mutated
    dispatcher would let the call reach the handler, whose own run-kind
    guard would then answer `refused / wrong_run_kind` instead of
    `unavailable / no_session`.
    """
    env = dispatch_mod.dispatch(tool_ctx, "crawl.run",
                                {"target": "http://127.0.0.1:8080/"},
                                why="see whether a session is required")
    assert env.outcome == "unavailable"
    assert env.reason == "no_session"


def test_crawl_run_refuses_outside_a_crawl_run(tool_ctx, monkeypatch):
    """The same mechanical reason `scan.run` refuses outside a `scan` run:
    `crawl.run` has no run of its own to auto-open, so a run this layer did
    not open is a run `run.finish` would never close.

    A session is set up (so the dispatcher's `no_session` guard does not
    fire first) but the open run is `manual`, never `crawl` -- this must be
    refused by the HANDLER'S OWN check, not by the egress guard above it.

    MUTATION: drop the handler's run-kind guard. Must go red -- the crawler
    itself is stubbed to fail loudly if reached (rather than risk a real
    Chromium launch under the mutation), so a mutated handler that fell
    through to it would error instead of answering `wrong_run_kind`.
    """
    def _must_not_run(**kw):
        raise AssertionError("crawl.run must not reach the crawler here")

    monkeypatch.setattr(crawl_run_mod, "crawl", _must_not_run)

    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="manual",
        safety_profile=tool_ctx.config.safety_profile)
    tool_ctx.session = _crawl_session()

    env = dispatch_mod.dispatch(tool_ctx, "crawl.run",
                                {"target": "http://127.0.0.1:8080/"},
                                why="try it without a crawl run")
    assert env.outcome == "refused"
    assert env.reason == "wrong_run_kind"
    assert "run.start" in (env.detail or "")


def test_crawl_run_reports_the_summary_through_the_dispatcher(
        tool_ctx, monkeypatch):
    """The handler's projection reaches the agent through `dispatch`, not
    only when called directly -- the same round trip `scan.run`'s summary
    test below makes.

    MUTATION: have the handler return the bare `CrawlSummary` instead of
    `as_tool_result(summary)`. Must go red -- `dispatch` would then try to
    fold a namedtuple into the envelope's `result`, and
    `env.result["pages"]` (subscripting a namedtuple with a string key)
    raises `TypeError` rather than answering `2`.
    """
    summary = crawl_run_mod.CrawlSummary(
        pages=2, rendered=2, degraded=0, failed=0, capped=0, requests=4,
        dropped_hosts=("cdn.test",), truncated_by=None)

    def fake_crawl(**kw):
        return summary

    monkeypatch.setattr(crawl_run_mod, "crawl", fake_crawl)

    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="crawl",
        safety_profile=tool_ctx.config.safety_profile)
    tool_ctx.session = _crawl_session()

    env = dispatch_mod.dispatch(tool_ctx, "crawl.run",
                                {"target": "http://127.0.0.1:8080/"},
                                why="crawl the seed")
    assert env.outcome == "ok"
    assert env.result["pages"] == 2
    assert env.result["dropped_hosts"] == ["cdn.test"]
    assert env.result["truncated_by"] is None


def test_scan_run_refuses_outside_a_scan_run(tool_ctx):
    """`hx.scan.run` calls `run.current_run(kind='scan')`, which AUTO-OPENS a
    run when none is open -- and a run the tool layer did not open is a run
    nothing will close, which makes the next `run.start(kind='scan')` refuse
    `run_open` forever. Requiring the bracket keeps `current_run` in its
    finding role and never in its opening one.

    A session is set up (so the dispatcher's `no_session` guard does not fire
    first) but the open run is `manual`, never `scan` -- this must be refused
    by the HANDLER'S OWN check, not by the egress guard above it.
    """
    from tests.test_probe import FakeBridge

    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="manual",
        safety_profile=tool_ctx.config.safety_profile)
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()

    env = dispatch_mod.dispatch(tool_ctx, "scan.run", {},
                                why="try it without a scan run")
    assert env.outcome == "refused"
    assert env.reason == "wrong_run_kind"
    assert "run.start" in (env.detail or "")


def test_scan_run_reports_the_summary_an_operator_would_see(
        live_session, monkeypatch):
    """`checks_run` is check_run ROWS WRITTEN and `findings` is DISTINCT
    findings -- both hard-won meanings (see ScanSummary's docstring), and a
    tool that recomputed either would be a third place they can disagree."""
    summary = scan_mod.ScanSummary(
        surfaces=3, checks_run=5, skipped=2, findings=1)

    def fake_run(conn, **kw):
        return summary

    monkeypatch.setattr(scan_mod, "run", fake_run)

    env = dispatch_mod.dispatch(live_session, "scan.run", {},
                                why="run the corpus")
    assert env.outcome == "ok"
    assert env.result["surfaces"] == 3
    assert env.result["checks_run"] == 5
    assert env.result["skipped"] == 2
    assert env.result["findings"] == 1
    # NOT re-derived from anything but `checks_run` and `skipped` -- the CLI's
    # own relationship, per `ScanSummary`'s docstring, not a value the store
    # holds anywhere on its own.
    assert env.result["executed"] == 3


def test_a_dead_identity_is_unavailable_rather_than_an_error(
        live_session, monkeypatch):
    """`IdentityDead` means the scan HALTED rather than completing clean, and
    section 12 is explicit that those must not render alike. `error` would
    say hx broke; `unavailable / identity_dead` says the session died and the
    coverage is short."""
    def dead(*a, **kw):
        raise scan_mod.IdentityDead("staff could not be proved live",
                                    stop_reason="identity staff dead")

    monkeypatch.setattr(scan_mod, "run", dead)

    env = dispatch_mod.dispatch(live_session, "scan.run", {},
                                why="run against a dying identity")
    assert env.outcome == "unavailable"
    assert env.reason == "identity_dead"


def test_unknown_check_ids_are_refused_and_the_known_ones_are_named(
        live_session):
    """A typo'd check id that was silently dropped would produce a scan that
    ran fewer checks than the agent asked for and reported success."""
    env = dispatch_mod.dispatch(
        live_session, "scan.run", {"checks": ["hx.passive.no-such-check"]},
        why="typo'd a check id")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert "hx.passive.no-such-check" in (env.detail or "")
    assert "checks.list" in (env.detail or "")
