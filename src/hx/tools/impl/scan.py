# src/hx/tools/impl/scan.py
"""Running the corpus, and the one tool that never runs at all.

`crawl.run` IS REGISTERED AND ALWAYS UNAVAILABLE, and registering a tool that
never succeeds looks like noise and is the opposite. An agent with no `crawl`
tool has no reason to say discovery was proxy-only; an agent that asks and is
told `not_implemented` does. That is section 12's governing rule -- a report
that cannot distinguish "tested, clean" from "never reached" is worse than no
report -- applied to the agent's own knowledge of its instrument, and it is
what `unavailable` exists for.
"""
from __future__ import annotations

from ... import scan as scan_mod
from ...checks import registry as check_registry
from .. import registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: Wall-clock ceiling for one `scan.run`. All v1 tools are synchronous -- no
#: job runner, no job table, no polling -- so a scan is a call an agent waits
#: on, and an unbounded one is a conversation that never comes back. The
#: caller may ask for less and not for more.
MAX_SECONDS = 1800


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
    raise ToolUnavailable(
        "not_implemented",
        "hx has no crawler in v1. Discovery is the operator's browser "
        "through the proxy (`hx capture start`), and `surface.query` shows "
        "what that has reached. Say so in the report: a surface nobody "
        "browsed is a surface nothing tested.")


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
    name="crawl.run", handler=crawl,
    summary="NOT IMPLEMENTED in v1 and always answers unavailable. Listed "
            "so that a report can say discovery was proxy-only.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "target": {"type": "string", "maxLength": 2048},
        "identity": {"type": "string", "maxLength": 64},
        "max_pages": {"type": "integer", "minimum": 1, "maximum": 10000},
        "max_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
    }}))
