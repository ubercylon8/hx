# tests/test_crawl_tool.py -- the tool envelope, not the browser
"""`crawl.run` as the agent sees it. The crawl itself is stubbed throughout;
what is under test is the envelope, the refusals and the flags.

Dispatcher-level round trips (does `dispatch()` see the same `needs_egress`
and run-kind guards it gives `scan.run`) live in `tests/test_tools_scan.py`,
next to `scan.run`'s own. This file calls the handler directly, the way the
plan's own Step 1 does, so a guard's ORDER inside the handler is pinned even
against a `ctx` that would crash if touched (`ctx=None`).
"""
from __future__ import annotations

import dataclasses

import pytest

from hx import run as run_mod
from hx.crawl import browser as browser_mod
from hx.crawl import frontier as frontier_mod
from hx.crawl import run as crawl_run
from hx.tools import errors, registry
from hx.tools.impl import scan as scan_impl
from tests.test_probe import FakeBridge


@pytest.fixture
def tool_run_crawl(tool_ctx):
    """A `tool_ctx` with a `crawl` run already open and a fake session on it
    -- the bracket `crawl.run`'s own guard requires, and the `crawler_port`
    every successful call reads."""
    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="crawl",
        safety_profile=tool_ctx.config.safety_profile)
    tool_ctx.session = type(
        "S", (), {"bridge": FakeBridge(), "crawler_port": 41999,
                  "operator_port": 41998})()
    return tool_ctx


def test_crawl_run_is_registered_as_needing_egress():
    """MUTATION: drop `needs_egress=True`. Must go red -- a crawl that does
    not declare egress skips the checks every other sending tool passes.
    """
    spec = registry.lookup("crawl.run")
    assert spec is not None
    assert spec.needs_egress is True
    assert spec.mutates is True


def test_the_summary_it_returns_names_truncation():
    """A truncated crawl must say so in the tool result, not only in a log.
    MUTATION: omit `truncated_by` from the returned dict. Must go red.
    """
    summary = crawl_run.CrawlSummary(
        pages=3, rendered=2, degraded=1, failed=0, capped=0, requests=9,
        dropped_hosts=("cdn.test",), truncated_by="max_pages")
    body = crawl_run.as_tool_result(summary)
    assert body["truncated_by"] == "max_pages"
    assert body["dropped_hosts"] == ["cdn.test"]
    assert body["degraded"] == 1


def test_asking_for_an_identity_is_refused_and_names_the_reason():
    """Authenticated crawling is deferred. A parameter the agent may pass
    that is silently ignored is worse than one that is rejected: the agent
    would report having crawled as a user.

    MUTATION: ignore `identity` instead of raising. Must go red -- `ctx` is
    `None` here on purpose, so a mutated handler that let this call fall
    through to any other guard (the run-kind check, the missing-`target`
    check) hits `ctx.open_runs()` or similar on `None` and raises
    `AttributeError`, which `pytest.raises(ToolUnavailable, ...)` does not
    accept either. There is no other path to the same green result.
    """
    with pytest.raises(errors.ToolUnavailable, match="authenticated"):
        scan_impl.crawl(ctx=None, identity="admin")


def test_identity_is_refused_before_anything_else_is_even_looked_at():
    """The refusal fires even with a well-formed `target` present, which is
    the proof identity is checked FIRST rather than merely checked somewhere
    before the run-kind guard happens to be hit with `ctx=None` too.

    MUTATION: move the identity check after the run-kind guard. Must go red
    -- with a `target` supplied, that guard is the next thing reached, and
    it touches `ctx.open_runs()` on a `None` ctx, raising `AttributeError`
    rather than the `ToolUnavailable` this test requires.
    """
    with pytest.raises(errors.ToolUnavailable, match="authenticated"):
        scan_impl.crawl(ctx=None, identity="admin", target="http://x.test/")


def test_it_refuses_outside_a_crawl_run(tool_ctx):
    """The same mechanical reason `scan.run` refuses outside a `scan` run:
    `crawl.run` has no run of its own to auto-open, so a run this layer did
    not open is a run `run.finish` would never close.

    MUTATION: drop the run-kind guard. Must go red -- `tool_ctx` has no
    session, so a mutated handler would fall through to `ctx.session.
    crawler_port` and raise `AttributeError` on `None`, not the intended
    `ToolRefused`.
    """
    with pytest.raises(errors.ToolRefused) as exc_info:
        scan_impl.crawl(ctx=tool_ctx, target="http://127.0.0.1:8080/")
    assert exc_info.value.reason == "wrong_run_kind"


def test_it_refuses_with_no_target(tool_run_crawl, monkeypatch):
    """MUTATION: drop the `target` check. Must go red -- with the run-kind
    and session guards satisfied by `tool_run_crawl`, a mutated handler
    would reach the (stubbed) crawler with `seeds=[None]` and return
    normally instead of raising.
    """
    def _must_not_run(**kw):
        raise AssertionError("the crawler must not run without a target")

    monkeypatch.setattr(crawl_run, "crawl", _must_not_run)
    with pytest.raises(errors.ToolRefused) as exc_info:
        scan_impl.crawl(ctx=tool_run_crawl)
    assert exc_info.value.reason == "bad_args"


def test_it_drives_the_crawler_through_the_crawler_port_not_the_operator_one(
        tool_run_crawl, monkeypatch):
    """`operator_port` and `crawler_port` are NOT interchangeable (Ruling
    21): the extension tells the operator's own browsing from an agent's
    crawl by WHICH LISTENER a request arrived on, and nothing in the
    traffic itself. Dialling the wrong one silently swaps the two rule
    sets.

    MUTATION: pass `ctx.session.operator_port` instead of `.crawler_port`.
    Must go red -- the two ports are set to different, distinctive values
    on the fixture, so the assertion below tells them apart directly; there
    is no other value in this handler that could produce 41999.
    """
    seen = {}

    def fake_crawl(**kw):
        seen.update(kw)
        return crawl_run.CrawlSummary(
            pages=1, rendered=1, degraded=0, failed=0, capped=0, requests=1,
            dropped_hosts=(), truncated_by=None)

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/")
    assert seen["proxy_port"] == 41999


def test_it_builds_the_budget_from_the_call_and_the_session_config(
        tool_run_crawl, monkeypatch):
    """`max_pages`/`max_seconds` come from the agent's own call; `max_
    requests` comes from `ctx.config` -- the schema carries no such
    parameter (Global Constraints), so the budget must not invent one from
    a hardcoded number or accept one from the agent.

    MUTATION: hardcode `max_requests` in the `Budget` instead of reading
    `ctx.config.max_requests`. Must go red -- the fixture's config is set to
    the distinctive value 777 below, which no plausible hardcoded default
    (2000, 5000, ...) would match.
    """
    tool_run_crawl.config = dataclasses.replace(
        tool_run_crawl.config, max_requests=777)
    seen = {}

    def fake_crawl(**kw):
        seen.update(kw)
        return crawl_run.CrawlSummary(
            pages=0, rendered=0, degraded=0, failed=0, capped=0, requests=0,
            dropped_hosts=(), truncated_by=None)

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/",
                    max_pages=5, max_seconds=30)
    assert seen["budget"] == frontier_mod.Budget(
        max_pages=5, max_seconds=30, max_requests=777)


def test_a_missing_browser_reaches_the_agent_as_unavailable_not_broken(
        tool_run_crawl, monkeypatch):
    """F3: `browser.BrowserUnavailable` is not a `ToolError`, and `dispatch`
    (`hx.tools.dispatch`) renders any non-`ToolError` exception as
    `envelope.failed` -- which tells the agent hx itself is broken. A Burp
    that has never downloaded its own bundled browser is the MOST LIKELY
    failure of `crawl.run`, and it has a clear operator fix (open Burp's own
    browser once so it downloads Chromium); that is an unavailability, not a
    defect, and this module's own docstring is about exactly that
    distinction for the old always-unavailable stub.

    `find_chromium`'s own message is carried through verbatim rather than
    reworded here.

    MUTATION: drop the `except browser_mod.BrowserUnavailable` wrap around
    the `crawl_run_mod.crawl` call inside `scan_impl.crawl` (let it
    propagate bare). Must go red -- `pytest.raises(errors.ToolUnavailable,
    ...)` would instead see the raw `browser_mod.BrowserUnavailable`
    propagate uncaught, which is not a `ToolUnavailable` at all.
    """
    def fake_crawl(**kw):
        raise browser_mod.BrowserUnavailable(
            "no bundled Chromium under /home/x/.BurpSuite/burpbrowser")

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    with pytest.raises(errors.ToolUnavailable,
                       match="no bundled Chromium") as exc_info:
        scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/")
    assert exc_info.value.reason == "not_configured"


def test_it_returns_the_projection_the_agent_reads(
        tool_run_crawl, monkeypatch):
    """The handler must hand back `as_tool_result`'s dict, not the raw
    `CrawlSummary` namedtuple -- an agent reading `.truncated_by` off a
    namedtuple would get it, but `.not_done` does not exist there at all.

    MUTATION: return the bare `CrawlSummary` instead of `as_tool_result
    (summary)`. Must go red -- `not_done` is only ever added by the
    projection.
    """
    def fake_crawl(**kw):
        return crawl_run.CrawlSummary(
            pages=4, rendered=3, degraded=1, failed=0, capped=0, requests=7,
            dropped_hosts=("evil.test",), truncated_by="max_seconds")

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    body = scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/")
    assert body["truncated_by"] == "max_seconds"
    assert body["dropped_hosts"] == ["evil.test"]
    assert "not_done" in body
