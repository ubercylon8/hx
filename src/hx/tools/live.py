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

import contextlib
import os

from .. import identity as identity_mod
from .. import session as session_mod

#: Run kinds that imply traffic this side issues. `browse` is the operator's
#: own browser through `hx capture start`, which owns its own Burp -- spec
#: section 8: "a browse run never needed the tool layer to launch anything".
#: `crawl` IS in the set: `crawl.run` drives a real browser through this
#: session's `crawler_port`, and a crawl run with no session would have no
#: proxy port to hand it -- `run.start(kind="crawl")` would answer
#: `not_needed`, no Burp would launch, and `crawl.run` would find no
#: `crawler_port` to dial, presenting as a crawl that found nothing rather
#: than as the missing instrument it actually is.
EGRESS_KINDS = frozenset({"manual", "scan", "crawl"})

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
        return _held(ctx)
    try:
        # NESTED, so that `close_for` can unwind the session and NOTHING
        # ELSE. `ctx.stack` is the ADAPTER'S, and Task 8 hands `hx mcp`'s own
        # long-lived stack straight to `build_context` -- anything that
        # adapter ever registers there would otherwise be torn down by an
        # ordinary `run.finish`. Created once per context and reused (see
        # `ToolContext._session_stack`), because a fresh inner stack per
        # session leaves a spent callback on the adapter's stack per session.
        if ctx._session_stack is None:
            ctx._session_stack = ctx.stack.enter_context(contextlib.ExitStack())
        live = ctx._session_stack.enter_context(
            session_mod.session(ctx.engagement, instance=INSTANCE))
    except Exception as exc:            # noqa: BLE001 -- see the docstring
        return {"live": False, "reason": "launch_failed",
                "detail": f"{type(exc).__name__}: {exc}"}
    # A SESSION THAT ARRIVES DEAD IS NOT A SESSION. `gone()` has two ways to
    # be true and only one is a dead JVM: an extension that dropped the
    # bridge reconnects at DENY-ALL, which is a Burp that is up, proxies
    # nothing and records nothing. Handing that back as `live` would give
    # every later tool a session object whose every send is refused.
    #
    # GUARDED, because this function's contract is "NEVER RAISES" without
    # qualification and a reader relies on that rather than on an argument
    # that `gone()` and `close()` happen not to raise today. NOT folded into
    # the `try` above, though, which is the shape that first suggests itself:
    # by this line the session is already ON the inner stack, so a single
    # wide `try` would answer `launch_failed` while leaving a live JVM held
    # by a stack nothing will close until the adapter exits -- and the next
    # `open_for` would enter a SECOND session onto the same stack.
    try:
        dead = live.gone()
    except Exception as exc:            # noqa: BLE001
        # A `gone()` that cannot answer is not evidence of a live session.
        dead = f"its liveness could not be read: {type(exc).__name__}: {exc}"
    if dead is not None:
        try:
            ctx._session_stack.close()
        except Exception as exc:        # noqa: BLE001
            # Reported, not raised, and not hidden either: the teardown of a
            # session that was never handed out is exactly the kind of
            # failure that leaves a JVM behind, so it belongs in the detail
            # an operator reads.
            dead = (f"{dead}; and tearing it down failed too: "
                    f"{type(exc).__name__}: {exc}")
        return {"live": False, "reason": "launch_failed", "detail": dead}
    ctx.session = live
    ctx._session_run_id = run_id
    ctx._registered = set()
    return {"live": True, "operator_port": live.operator_port,
            "crawler_port": live.crawler_port, "epoch": live.epoch}


def _held(ctx) -> dict:
    """`session_held`, and WHETHER THE HOLDER IS STILL ALIVE.

    "Blocked by a live session" and "blocked by a corpse" are different facts
    and only one of them means wait. A JVM that died mid-run leaves
    `ctx.session` set, so every later egress run is refused -- and an agent
    told only `session_held` would keep waiting for a run that will never
    give the instrument back on its own.

    OWNERSHIP IS NOT TAKEN HERE, alive or dead. The run that opened a session
    is the run that closes it; `run.finish` on the owner tears down a corpse
    exactly as it tears down a live one, and a second run helping itself to
    another run's teardown is how two runs come to share an instrument.
    """
    try:
        dead = ctx.session.gone()
    except Exception as exc:            # noqa: BLE001 -- open_for never raises
        # A `gone()` that cannot answer is not evidence of a live session.
        dead = f"its liveness could not be read ({type(exc).__name__}: {exc})."
    owner = ctx._session_run_id
    if dead is None:
        detail = (f"run {owner} holds this engagement's Burp; one session at "
                  "a time. Finish that run first -- a scan and a manual pass "
                  "are different runs and should not share an instrument.")
    else:
        detail = (f"run {owner} holds this engagement's Burp and it is no "
                  f"longer live: {dead} Waiting will not free it -- run.finish "
                  f"on {owner} tears the dead session down, and only the run "
                  "that opened a session may close it.")
    return {"live": False, "reason": "session_held",
            "owner_alive": dead is None, "detail": detail}


def close_for(ctx, run_id: str) -> bool:
    """Tear down the session if this run owns it. True if it did.

    THE SESSION AND ONLY THE SESSION. The stack closed here is
    `_session_stack`, nested inside the adapter's own `ctx.stack` -- because
    Task 8 hands `hx mcp`'s long-lived stack to `build_context`, and anything
    that adapter registers on it (its store, its serve loop's own clean-up)
    must survive an ordinary `run.finish`. Closing the OUTER stack still
    unwinds this one, so a crash kills the JVM either way; what the nesting
    buys is that a routine close does not.

    THE BOOKKEEPING IS CLEARED WHATEVER THE TEARDOWN DOES. If `close()`
    raised and the three assignments below it were skipped, `ctx.session`
    would stay set for a session that is gone, and every later egress run
    would be told `session_held` naming a run that is already closed -- a
    tool layer permanently unable to open a session again, recoverable only
    by restarting `hx mcp`. The raise is still allowed out (`dispatch` renders
    it, and a teardown that failed is worth an `error`); what is not allowed
    is for it to take the context with it.
    """
    if ctx.session is None or ctx._session_run_id != run_id:
        return False
    try:
        ctx._session_stack.close()
    finally:
        ctx.session = None
        ctx._session_run_id = None
        ctx._registered = set()
    return True


def declaration_of(ctx, identity_id: str):
    """The `Identity` this config declares under `identity_id`, or ValueError.

    SPLIT OUT OF `ensure_identity` FOR RULING 16, and it is the whole of the
    check that costs nothing. `ensure_identity` RESOLVES and REGISTERS, and a
    registration can fire the extension's liveness canary against the
    client's application -- so a tool replaying under several identities
    checks EVERY name here first and only then resolves any of them. A typo
    in the third name discovered after the first two had been registered
    would be a typo found after traffic had reached the client, which is the
    thing "resolve before sending" exists to prevent.

    ONE FUNCTION RATHER THAN A SECOND COPY OF THE SENTENCE. The message an
    agent reads for an undeclared name is one message, and a copy is what
    drifts.
    """
    found = ctx.config.identities.get(identity_id)
    if found is None:
        raise ValueError(
            f"identity {identity_id!r} is not declared in this config. "
            f"Declared: {sorted(ctx.config.identities) or 'none'}")
    return found


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
    declared = declaration_of(ctx, identity_id)
    resolved = identity_mod.resolve(declared, dict(os.environ))
    key = (resolved.id, resolved.generation)
    if key not in ctx._registered:
        ctx.session.bridge.register_identity(
            resolved, origins=tuple(declared.origins))
        ctx._registered.add(key)
    return key
