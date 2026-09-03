# src/hx/tools/impl/scan.py
"""Running the corpus, and driving the crawler for one bounded sweep.

`crawl.run` USED TO BE REGISTERED AND ALWAYS UNAVAILABLE, back when hx had no
crawler at all: registering a tool that never succeeds looked like noise and
was the opposite -- an agent with no `crawl` tool had no reason to say
discovery was proxy-only, and one that asked and was told `not_implemented`
did. Now `hx.crawl.run.crawl` exists, and this module drives it the way `run`
below drives the check corpus: synchronously, inside a run the tool layer
opened, with the session's `crawler_port`.
"""
from __future__ import annotations

from ... import scan as scan_mod
from ...checks import registry as check_registry
from ...crawl import browser as browser_mod
from ...crawl import frontier as frontier_mod
from ...crawl import run as crawl_run_mod
from .. import registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: Wall-clock ceiling for one `scan.run`. All v1 tools are synchronous -- no
#: job runner, no job table, no polling -- so a scan is a call an agent waits
#: on, and an unbounded one is a conversation that never comes back. The
#: caller may ask for less and not for more.
MAX_SECONDS = 1800

#: `crawl.run`'s own defaults, applied when the agent omits `max_pages` /
#: `max_seconds`. The same numbers `hx crawl`'s CLI options default to --
#: one bounded sweep should mean the same bound whichever surface asks for
#: it, and a caller that wants less is always free to say so.
DEFAULT_MAX_PAGES = 200
DEFAULT_MAX_SECONDS = 600


def run(ctx, *, surface_ids=None, checks=None,
        max_seconds: int = MAX_SECONDS) -> dict:
    """Run the enabled corpus over some or all surfaces. Synchronous.

    IT MUST BE CALLED INSIDE A `scan` RUN, and the reason is mechanical
    rather than tidy. `hx.scan.run` resolves its run with
    `hx.run.current_run(kind="scan")`, which AUTO-OPENS one when none is
    open. A run the tool layer did not open is a run `run.finish` will never
    close, and the next `run.start(kind="scan")` then refuses `run_open`
    forever against a run nobody remembers. Requiring the bracket keeps
    `current_run` in its finding role and never in its opening one.
    """
    open_now = dict((kind, rid) for rid, kind in ctx.open_runs())
    if "scan" not in open_now:
        raise ToolRefused(
            "wrong_run_kind",
            "scan.run belongs inside a scan run, and none is open. "
            "`run.start` with kind='scan' first -- a scan run is what "
            "`check_run` rows are attributed to, and one this layer did not "
            "open is one nothing will close.")

    corpus = None
    if checks is not None:
        known = {c.id: c for c in check_registry.CHECKS}
        unknown = sorted(set(checks) - set(known))
        if unknown:
            # NEVER SILENTLY DROPPED. A typo'd id that vanished would produce
            # a scan that ran fewer checks than was asked for and reported
            # success, which is a coverage lie with a green tick on it.
            raise ToolRefused(
                "bad_args",
                f"unknown check ids {unknown}. `checks.list` names every "
                "check in the corpus, including the disabled ones.")
        corpus = tuple(known[c] for c in checks)

    wanted = None if surface_ids is None else set(surface_ids)
    try:
        summary = scan_mod.run(
            ctx.conn, engagement_id=ctx.engagement.id, blobs=ctx.blobs,
            config=ctx.config, checks=corpus,
            # A PREDICATE, because that is what `hx.scan.run` takes. `surface`
            # rows arrive as sqlite rows and `[0]` is the id -- read
            # `hx.scan.run`'s own use of `surface_filter` and follow it
            # rather than trusting this index.
            surface_filter=(None if wanted is None
                            else (lambda s: s[0] in wanted)),
            max_seconds=min(max_seconds, MAX_SECONDS),
            # `needs_egress=True` on the spec means `dispatch` already
            # refused `unavailable / no_session` before this handler ran, so
            # `ctx.session` is never None here.
            bridge=ctx.session.bridge,
            # NOT OVERRIDDEN. `hx.scan.run` resolves `config.scan_identity`
            # itself and is the only thing in the product that reads that
            # field; passing None here is what lets it. An identity chosen
            # per call would put the run's bracket and the run's traffic
            # under two different answers.
            identity=None)
    except scan_mod.IdentityDead as exc:
        # THE SCAN HALTED RATHER THAN COMPLETING CLEAN, and section 12 is
        # explicit that those two must not render alike. `error` would say hx
        # broke; this says the session died and the coverage is short.
        raise ToolUnavailable("identity_dead", str(exc)) from exc

    return {
        "surfaces": summary.surfaces,
        "checks_run": summary.checks_run,
        "skipped": summary.skipped,
        "findings": summary.findings,
        # `checks_run` is ROWS WRITTEN and `findings` is DISTINCT findings --
        # both meanings were argued for in `ScanSummary`'s docstring after a
        # scan printed `findings 40` while the store held 1. Read, never
        # recomputed: a second place these are derived is a second place they
        # can disagree with the report.
        "executed": summary.checks_run - summary.skipped,
    }


def crawl(ctx, **kw) -> dict:
    """Drive a browser over in-scope pages through the proxy. Synchronous
    and bounded; must be called inside a crawl run.

    IDENTITY IS REFUSED, NOT IGNORED, and checked FIRST -- before `ctx` is
    touched at all. Authenticated crawling is deferred to its own spec: a
    parameter the agent may pass that is silently ignored is worse than one
    that is rejected, because the agent would report having crawled as a
    user when it did not. Browsing through the proxy under an identity is
    how an authenticated application gets covered instead.

    IT MUST BE CALLED INSIDE A `crawl` RUN, for the mechanical reason
    `run` above documents for `scan.run`: `crawl.run` has no run of its own
    to auto-open, so a call with none open is a call whose traffic nothing
    would be attributed to and whose run `run.finish` would never see.
    """
    if kw.get("identity"):
        raise ToolUnavailable(
            "not_implemented",
            "authenticated crawling is not in this build. The crawler runs "
            "unauthenticated, so anything behind a login was not reached by "
            "it -- browse the application through the proxy instead, which "
            "is how S9 covers authenticated applications. Re-run without "
            "`identity`.")

    open_now = dict((kind, rid) for rid, kind in ctx.open_runs())
    if "crawl" not in open_now:
        raise ToolRefused(
            "wrong_run_kind",
            "crawl.run belongs inside a crawl run, and none is open. "
            "`run.start` with kind='crawl' first -- a crawl run is what "
            "this traffic is attributed to, and one this layer did not "
            "open is one nothing will close.")

    target = kw.get("target")
    if not target:
        raise ToolRefused(
            "bad_args",
            "crawl.run needs a `target` to seed the crawl from.")

    try:
        summary = crawl_run_mod.crawl(
            seeds=[target],
            # THE CRAWLER PORT, NEVER THE OPERATOR ONE (Ruling 21).
            # `operator_port` and `crawler_port` are not interchangeable: the
            # extension tells the operator's own browsing from an agent's
            # crawl by WHICH LISTENER a request arrived on, and nothing in
            # the traffic itself -- dialling the wrong one silently swaps
            # the two rule sets. `needs_egress=True` on the spec means
            # `dispatch` already refused `unavailable / no_session` before
            # this handler ran, so `ctx.session` is never None here.
            proxy_port=ctx.session.crawler_port,
            budget=frontier_mod.Budget(
                max_pages=kw.get("max_pages") or DEFAULT_MAX_PAGES,
                max_seconds=kw.get("max_seconds") or DEFAULT_MAX_SECONDS,
                # NOT AN AGENT-FACING PARAMETER. The request budget is what
                # already authorised this session's extension
                # (`session.config_body`'s `limit.max_requests`), and
                # letting a tool call ask for more than the session was
                # launched with would be a second, disagreeing answer to a
                # question the extension has already been told.
                max_requests=ctx.config.max_requests))
    except browser_mod.BrowserUnavailable as exc:
        # F3: a Burp that has never downloaded its own bundled browser is
        # the MOST LIKELY failure of `crawl.run`, and `dispatch` renders any
        # exception that is not a `ToolError` as `envelope.failed` (`this
        # tool is broken`) -- see `hx.tools.dispatch`. That is the wrong
        # claim: the operator has a clear fix (open Burp's own browser once
        # so it downloads Chromium), same as this module's own docstring
        # describes for the old always-unavailable stub. `find_chromium`
        # already writes a good operator-facing message; it is carried
        # through rather than re-worded here.
        raise ToolUnavailable("not_configured", str(exc)) from exc
    return crawl_run_mod.as_tool_result(summary)


registry.register(spec.ToolSpec(
    name="scan.run", handler=run, needs_egress=True, mutates=True,
    summary="Run the enabled checks over some or all surfaces. Synchronous "
            "and bounded; must be called inside a scan run.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "surface_ids": {"type": "array", "maxItems": 500,
                        "items": {"type": "string", "maxLength": 64},
                        "description": "omit to scan every surface"},
        "checks": {"type": "array", "maxItems": 100,
                   "items": {"type": "string", "maxLength": 64},
                   "description": "check ids from checks.list; omit for the "
                                  "enabled corpus"},
        "max_seconds": {"type": "integer", "minimum": 1,
                        "maximum": MAX_SECONDS},
    }}))

registry.register(spec.ToolSpec(
    name="crawl.run", handler=crawl, needs_egress=True, mutates=True,
    summary="Drive a browser over in-scope pages through the proxy so their "
            "requests are captured. Synchronous and bounded; must be called "
            "inside a crawl run. Submits no forms and clicks nothing.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "target": {"type": "string", "maxLength": 2048},
        "identity": {"type": "string", "maxLength": 64},
        "max_pages": {"type": "integer", "minimum": 1, "maximum": 10000},
        "max_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
    }}))
