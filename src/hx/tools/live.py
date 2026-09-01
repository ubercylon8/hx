"""The session bracket: which runs get a Burp, and who owns it.

SPEC SECTION 8 GIVES THE SHAPE. `run.start` opens the bracket and
`run.finish` closes it; an egress tool outside that bracket answers
`unavailable / no_session`. This is "each command owns its own Burp" -- the
rule already chosen for the CLI -- scaled to a session rather than replaced.

FOUR WAYS TO HAVE NO SESSION, AND THEY ARE FOUR DIFFERENT NEXT ACTIONS. That
is why `open_for` returns a reason rather than a bool:

  not_needed     this run kind never wanted one (browse, crawl)
  no_host        this ADAPTER cannot hold one -- use `hx mcp`
  launch_failed  Burp would not start, or started dead
  session_held   another run has it; finish that one

Section 12's rule is that a report which cannot distinguish "tested, clean"
from "never reached" is worse than no report, and the same rule applies to an
agent's knowledge of its own instrument. A single `live: false` would collapse
four distinguishable situations into one shrug -- which is exactly the
argument that registers `crawl.run` rather than omitting it.

A FAILED LAUNCH DOES NOT STOP THE RUN FROM OPENING. Refusing `run.start`
outright would leave no `run` row and no `agent_action` row: no trace that the
instrument failed, on the one call that was trying to set it up. The run
opens, the failure is in the result and in the journal, non-egress work
proceeds, and every egress tool answers `no_session` on its own -- so nothing
false can be concluded from it.
"""
from __future__ import annotations

import os

from .. import identity as identity_mod
from .. import session as session_mod

#: Run kinds that imply traffic this side issues. `browse` is the operator's
#: own browser through `hx capture start`, which owns its own Burp -- spec
#: section 8: "a browse run never needed the tool layer to launch anything".
#: `crawl` is here for completeness and is not in the set, because `crawl.run`
#: is permanently unavailable and a crawl run has nothing to send.
EGRESS_KINDS = frozenset({"manual", "scan"})

#: `hx.session.session`'s `instance`, which names both the `-Dhx.instance` the
#: extension reports and the directory under the engagement root this session
#: owns. Distinct from "capture" and "scan" so an agent's session and an
#: operator's `hx capture start` do not collide on a bridge socket path.
INSTANCE = "tools"


def open_for(ctx, run_id: str, kind: str) -> dict:
    """Launch Burp for a run of this kind, or say why not. NEVER RAISES.

    A raise here would come out of `run.start`, and `dispatch` would render it
    `error / internal` -- "hx is broken" for a Burp that is merely not
    installed. The distinction between a defect and a missing instrument is
    the one this whole return value exists to draw.
    """
    if kind not in EGRESS_KINDS:
        return {"live": False, "reason": "not_needed",
                "detail": f"a {kind} run issues no traffic from this side, "
                          "so it needs no session"}
    if ctx.stack is None:
        return {"live": False, "reason": "no_host",
                "detail": "this adapter is one process per call and cannot "
                          "hold a Burp open across calls: `hx.session."
                          "session()` tears it down on every exit. Run the "
                          "tool layer under `hx mcp`, which is one long-lived "
                          "process, or use the 11 tools that need no session."}
    if ctx.session is not None:
        return {"live": False, "reason": "session_held",
                "detail": f"run {ctx._session_run_id} holds this engagement's "
                          "Burp; one session at a time. Finish that run first "
                          "-- a scan and a manual pass are different runs and "
                          "should not share an instrument."}
    try:
        live = ctx.stack.enter_context(
            session_mod.session(ctx.engagement, instance=INSTANCE))
    except Exception as exc:            # noqa: BLE001 -- see the docstring
        return {"live": False, "reason": "launch_failed",
                "detail": f"{type(exc).__name__}: {exc}"}
    # A SESSION THAT ARRIVES DEAD IS NOT A SESSION. `gone()` has two ways to
    # be true and only one is a dead JVM: an extension that dropped the
    # bridge reconnects at DENY-ALL, which is a Burp that is up, proxies
    # nothing and records nothing. Handing that back as `live` would give
    # every later tool a session object whose every send is refused.
    dead = live.gone()
    if dead is not None:
        ctx.stack.close()
        return {"live": False, "reason": "launch_failed", "detail": dead}
    ctx.session = live
    ctx._session_run_id = run_id
    ctx._registered = set()
    return {"live": True, "operator_port": live.operator_port,
            "crawler_port": live.crawler_port, "epoch": live.epoch}


def close_for(ctx, run_id: str) -> bool:
    """Tear down the session if this run owns it. True if it did.

    `ExitStack.close()` unwinds everything on the stack and leaves it
    reusable, which is what makes one stack enough for a session that opens
    and closes many times across one `hx mcp` conversation.
    """
    if ctx.session is None or ctx._session_run_id != run_id:
        return False
    ctx.stack.close()
    ctx.session = None
    ctx._session_run_id = None
    ctx._registered = set()
    return True


def ensure_identity(ctx, identity_id: str) -> tuple[str, int]:
    """Resolve and register one identity; return `(id, generation)`.

    THE CREDENTIAL NEVER COMES BACK. Principle 5 puts resolution below the
    tool layer, and this function is that boundary: a `Resolved` is built,
    handed straight to the extension, and dropped. What returns is a name and
    a number, which is what an exchange row stores and what a journal may
    hold.

    REGISTERED ONCE PER (id, generation) PER SESSION.
    `BridgeServer.register_identity` refuses a generation that does not
    advance what the extension already holds -- `stale_generation` -- so a
    second registration of the same pair is an ERROR rather than a no-op, and
    a tool that re-registered on every send would fail on its second one.

    Raises ValueError for an undeclared identity (a caller's mistake, and the
    message lists what IS declared) and BridgeError for a refusal from the
    extension.
    """
    declared = ctx.config.identities.get(identity_id)
    if declared is None:
        raise ValueError(
            f"identity {identity_id!r} is not declared in this config. "
            f"Declared: {sorted(ctx.config.identities) or 'none'}")
    resolved = identity_mod.resolve(declared, dict(os.environ))
    key = (resolved.id, resolved.generation)
    if key not in ctx._registered:
        ctx.session.bridge.register_identity(
            resolved, origins=tuple(declared.origins))
        ctx._registered.add(key)
    return key
