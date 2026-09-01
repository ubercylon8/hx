# tests/test_tools_scan.py
"""scan.run and crawl.run.

`crawl.run` is registered and always unavailable, and the test for that is
the most important one in this file. An agent with NO crawl tool has no
reason to say discovery was proxy-only; an agent that asks and is told
`not_implemented` does. That is section 12's rule applied to the agent's
knowledge of its own instrument, and a tool that quietly did not exist would
be the silence the rule is against.
"""
from __future__ import annotations

from hx import run as run_mod
from hx import scan as scan_mod
from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401


def test_crawl_run_is_registered_and_permanently_unavailable(tool_ctx):
    env = dispatch_mod.dispatch(tool_ctx, "crawl.run",
                                {"target": "http://127.0.0.1:8080/"},
                                why="see whether crawling exists")
    assert env.outcome == "unavailable"
    assert env.reason == "not_implemented"
    # AND IT SAYS WHAT TO DO INSTEAD. An `unavailable` that names no
    # alternative leaves an agent with a dead end where it needs a next step.
    assert "proxy" in (env.detail or "").lower()


def test_crawl_run_is_unavailable_even_with_a_live_session(tool_ctx):
    """`unavailable` here is about the FEATURE, not about the instrument. A
    version that answered `no_session` would tell an agent that starting a
    session would help, and it would not. No `why` either: a call that can
    never mutate anything must never be told it needs one."""
    tool_ctx.session = object()
    env = dispatch_mod.dispatch(tool_ctx, "crawl.run",
                                {"target": "http://127.0.0.1:8080/"})
    assert env.outcome == "unavailable"
    assert env.reason == "not_implemented"


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
