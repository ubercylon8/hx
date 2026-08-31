"""The one door every tool call goes through.

THE PUBLISHED DECISION ORDER IS

    not_registered -> halted -> missing_why -> bad_args -> no_session

and it is published for the reason the send path's is (section 4): a gate whose
order is undocumented is a gate whose behaviour is discovered by experiment.
Earliest matching rule wins; each is terminal.

`not_registered` FIRST, because the registry is the allowlist and a name that
is not in it is not a tool to have opinions about.

`halted` BEFORE `missing_why`, so an operator who has hit STOP gets "the
engagement is halted" rather than a lecture about argument hygiene for a call
that was never going to run.

`halted` APPLIES ONLY TO `mutates` TOOLS, deliberately. A halt stops the
engagement from changing; it does not blind the operator's agent. Someone who
has just hit STOP wants to ask what was happening, and every tool that can
answer that is a read.

`no_session` LAST, because it is the most expensive question to answer and the
only one that depends on state outside this process.

THIS FUNCTION NEVER RAISES. Every outcome -- refusal, unavailability, and a
defect in hx itself -- comes back as an envelope, and every call writes exactly
one `agent_action` row. An adapter that had to catch exceptions as well as read
envelopes would be two error paths, and the second would be the one nobody
tested.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Any

from . import envelope, journal, registry, schema
from .errors import ToolError

_log = logging.getLogger(__name__)

#: Design section 5. Asserted by a test, so it cannot become a comment.
DECISION_ORDER = ("not_registered", "halted", "missing_why", "bad_args",
                  "no_session")


@dataclasses.dataclass
class ToolContext:
    """Everything a handler is allowed to reach.

    IT CARRIES NO CREDENTIAL. Principle 5 puts identity resolution below this
    layer: a handler that could reach a `Resolved` could put one in a return
    value, and the return value is journalled.

    `session` is None throughout Plan A -- nothing here needs egress -- and
    Plan B fills it from `run.start`. `needs_egress` tools are already refused
    against it, so the seam is a field rather than a change.
    """

    engagement: Any
    conn: Any
    blobs: Any
    config: Any
    halt: Any
    run_id: str | None = None
    session: Any = None
    actor: str = "agent"


def dispatch(ctx: ToolContext, name: str, args: dict[str, Any] | None = None,
             *, why: str | None = None) -> envelope.Envelope:
    """Validate, authorise, call, journal. Never raises."""
    args = dict(args or {})
    tool = registry.lookup(name)
    if tool is None:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "not_registered",
            f"{name} is not a tool. Ask checks.list or read the tool list."))

    if tool.mutates and ctx.halt.halted:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "halted", ctx.halt.reason))

    if tool.requires_why and not (why or "").strip():
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "missing_why",
            f"{name} changes state, so it needs a `why`: it is written to "
            "agent_action and read by whoever asks what this run did."))

    problems = schema.validate(tool.params, args)
    if problems:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "bad_args", "; ".join(problems)))

    # EVERYTHING BELOW THIS LINE HAS PASSED A SCHEMA, and that is what makes
    # `validated=True` safe -- see `_journalled`.
    if tool.needs_egress and ctx.session is None:
        return _journalled(ctx, name, args, why, envelope.unavailable(
            name, "no_session",
            f"{name} sends requests and there is no live session. Start a run "
            "first."), validated=True)

    try:
        result = tool.handler(ctx, **args)
    except ToolError as exc:
        env = envelope.Envelope(tool=name, outcome=exc.outcome,
                                reason=exc.reason, detail=exc.detail)
    except Exception as exc:  # noqa: BLE001 -- see the module docstring
        # Named, not swallowed. The class and message go into the envelope and
        # the journal so a defect is visible without a traceback reaching an
        # agent that would try to act on it.
        env = envelope.failed(name, f"{type(exc).__name__}: {exc}")
    else:
        env = envelope.answered(name, result)
    return _journalled(ctx, name, args, why, env, validated=True)


def _shape(args: dict[str, Any]) -> dict[str, Any]:
    """The argument NAMES of a call nothing validated, never its values."""
    return {"unvalidated_argument_names": sorted(args)}


def _journalled(ctx: ToolContext, name: str, args: dict[str, Any],
                why: str | None, env: envelope.Envelope,
                *, validated: bool = False) -> envelope.Envelope:
    """Write the row and hand back the envelope.

    ARGUMENT VALUES ARE JOURNALLED ONLY FOR A CALL THAT PASSED A SCHEMA.
    `hx.tools.journal` stores `args_blob` verbatim, and Principle 5 is the
    argument for why that is safe: identity is passed by name and resolved
    below this layer. That argument covers arguments a schema ACCEPTED. It
    covers nothing about the four refusals above, which happen before or at
    validation and carry a dict nobody has checked -- and since every tool
    schema sets `additionalProperties: false`, `{"password": ...}` sent to a
    real tool IS a `bad_args` refusal. So an unvalidated call journals its
    sorted key NAMES and nothing else.

    The names are kept rather than dropped because they are the whole
    loop-prevention signal: "I keep calling this with a password field" is
    what an agent needs to read back, and it needs no value to say it.

    A journal failure must not turn a successful call into a failed one, nor a
    refusal into a success: the envelope is returned either way, and the write
    is the thing that is allowed to be missing. An engagement whose database
    has gone read-only has larger problems than an unrecorded row, and the
    caller finding out about them from `surface.query` would be misleading.

    MISSING, BUT NEVER SILENT. This block was written `except Exception: pass`,
    and the paragraph above was the argument for it -- correctly, right up to
    the word `pass`. A swallowed failure lets the journal go incomplete with
    nothing anywhere saying so, and `run.journal` and `run.resume` then answer
    "what have I already tried" out of a record that is quietly short. That is
    section 12's governing rule broken inside the table built to keep it: a
    journal that cannot tell "did not happen" from "happened and was not
    recorded". `hx.bridge.server` sets the convention this uses.
    """
    try:
        journal.record(ctx.conn, engagement_id=ctx.engagement.id,
                       run_id=ctx.run_id, tool=name,
                       args=args if validated else _shape(args), why=why,
                       env=env, blobs=ctx.blobs, actor=ctx.actor)
    except Exception:  # noqa: BLE001
        _log.exception("could not journal %s; the call itself stands", name)
    return env
