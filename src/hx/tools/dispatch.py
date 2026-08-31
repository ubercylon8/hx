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

`halted` ALSO DOES NOT APPLY TO `HALT_EXEMPT`, which today holds exactly
`run.finish`. The rule the gate encodes is "a halted engagement must not do
MORE"; closing an open run does less, not more, and in Plan B `run.finish` is
what stops the Burp JVM -- so refusing it under a halt would leave a JVM
running with nothing left holding it, which is exactly what section 8's
bracket exists to prevent. `HALT_EXEMPT` is a named, greppable set checked
here, not a per-spec boolean on `ToolSpec`: a boolean would invite a future
tool to opt itself out of the halt gate one flag at a time, and the set makes
every exemption a decision visible in one place instead of scattered across
specs.

`no_session` LAST, because it is the most expensive question to answer and the
only one that depends on state outside this process.

THE TWO LENGTH GUARDS -- `why` OVER 500 CHARACTERS, `name` OVER 64 -- SIT
BELOW `lookup` AND THE HALT CHECK, deliberately, and did not always: a
too-long `why` used to answer `bad_args` on a halted engagement, ahead of
`halted`, and a too-long unknown name used to answer `bad_args` ahead of
`not_registered`. Neither length is a `bad_args` question the published order
puts before those two: a name over 64 characters is simply not a registered
name (nothing in `V1_TOOL_NAMES` is that long, so `lookup` already returns
`None` for it), and a `why` over 500 characters is an argument problem the
order deliberately ranks below `halted`. The four TYPE guards immediately
below this docstring are a different kind of guard and stay above `lookup`:
a non-string `name` cannot be looked up at all, hashable or not.

THIS FUNCTION NEVER RAISES. Every outcome -- refusal, unavailability, and a
defect in hx itself -- comes back as an envelope, and every call writes AT
MOST one `agent_action` row -- a failure to write it is logged, never silent;
see `_journalled`. An adapter that had to catch exceptions as well as read
envelopes would be two error paths, and the second would be the one nobody
tested.

`name`, `args` and `why` ARE THEMSELVES UNTRUSTED. They arrive over MCP or
JSON-RPC, where nothing stops a `name` that is a list, an `args` that is a
string, or a `why` that is an integer. The four guards at the top of
`dispatch` catch exactly that, before `registry.lookup` (which needs a
hashable `name`), before `dict(args or {})` (which needs a mapping or None),
before `schema.validate`'s internal `sorted()` over argument names (which
needs every key to be a string), and before `.strip()` on `why`. Each is a
`bad_args` refusal, journalled like any other -- a malformed call is exactly
what `agent_action` exists to make visible, not a crash that erases it.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Any

from .. import run as run_mod
from . import envelope, journal, registry, schema
from .errors import ToolError

_log = logging.getLogger(__name__)

#: Design section 5. Asserted by a test, so it cannot become a comment.
DECISION_ORDER = ("not_registered", "halted", "missing_why", "bad_args",
                  "no_session")

#: Tools the halt gate does not apply to, even though they mutate. `run.finish`
#: is the only member: closing an open run does LESS, not more, and section
#: 8's bracket needs it reachable under a halt so Plan B's Burp JVM is never
#: left running with nothing holding it. A named set here rather than a
#: `ToolSpec` boolean, so a future tool cannot opt itself out of the halt gate
#: one flag at a time -- every exemption is a decision visible in this one
#: place, and a test asserts the set holds exactly this.
HALT_EXEMPT = frozenset({"run.finish"})


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
    session: Any = None
    actor: str = "agent"
    _bound_run_id: str | None = dataclasses.field(default=None, repr=False)
    #: `None` means "not resolved for this call yet", never "resolved to
    #: zero open runs" -- `hx.run.open_runs` returns a `list`, so the
    #: sentinel and a genuine empty answer cannot collide. Reset by
    #: `dispatch()`; see `open_runs()`.
    _open_runs_cache: list[tuple[str, str]] | None = dataclasses.field(
        default=None, repr=False)

    def open_runs(self) -> list[tuple[str, str]]:
        """`(id, kind)` for every run of this engagement still open --
        resolved from the store AT MOST ONCE PER `dispatch()` CALL, memoised
        here and reused by every reader inside it, `run_id` included.

        A SECOND FINDING OF THE FINAL REVIEW, IN THE FIRST FINDING'S OWN FIX.
        Before this, `run_id` queried live on EVERY access, and a handler
        that reads it more than once -- `finding.record` does, at its guard
        and again at each of two writes -- could see two different answers
        to the same question inside one call. MEASURED: one `manual` run
        open, the guard at `finding.record`'s top passes; before the writes
        run, a concurrent actor (an operator's `hx scan`, a second agent's
        `run.start`) opens a run of a DIFFERENT kind -- ordinary concurrent
        use, the exact case `hx.run.current_run`'s docstring blesses ("a
        crawl running while you browse is two runs"). The now-ambiguous
        resolution turns `None` between the guard and the write, and
        `finding_observation.run_id` (`NOT NULL`) raises `IntegrityError`,
        rolling the transaction back -- the agent's finding and its evidence
        are lost, and it is told hx is broken (`error/internal`) rather than
        given a clean disambiguation.

        `dispatch()` clears this cache at the TOP of every call, before the
        first guard runs -- so the four call-shape refusals, the handler
        (whatever it reads and however many times), and `_journalled`'s own
        trailing read afterward all see ONE snapshot, taken at the first
        access within this call. `run.finish` reads it directly too (for its
        `kind` branch and its ambiguous-refusal message) rather than issuing
        its own live query, for the same reason `finding.record`'s two later
        reads must agree with its first: one resolution, not three.

        EXPLICIT BINDING STILL WINS. This cache backs only the UNBOUND path
        -- `run_id`'s bound check runs first and returns immediately when
        `run.start` (or a caller) has set `_bound_run_id`, so a `ctx.run_id =
        ...` assignment mid-handler is never shadowed by a snapshot taken
        before it.
        """
        if self._open_runs_cache is None:
            self._open_runs_cache = run_mod.open_runs(
                self.conn, engagement_id=self.engagement.id)
        return self._open_runs_cache

    @property
    def run_id(self) -> str | None:
        """The open run -- BOUND if `run.start` (or a caller) set one on this
        context, else RESOLVED FROM THE STORE (see `open_runs()` for the
        per-call memoisation that makes repeated reads agree).

        THE OPEN RUN IS A PROPERTY OF THE ENGAGEMENT, NOT OF THE PROCESS. The
        CLI adapter builds a fresh `ToolContext` -- nothing bound -- for every
        `hx tool` invocation, so a plain field that only ever held what THIS
        process set would leave `run.finish` and every run-scoped tool
        permanently unreachable through it: `run.start` binds a run in one
        process and exits, and the next process's context has never heard of
        it. Resolving from `hx.run.open_runs` instead means a run a prior
        `run.start` opened is still findable.

        AMBIGUITY IS NEVER GUESSED. Two runs of different kinds may
        legitimately be open at once -- `run.start`'s own refusal only blocks
        a second run of the SAME kind, because "a crawl running while you
        browse is two runs" (`hx.run.current_run`'s docstring gives the
        rule). So this resolves to a run only when exactly one is open; zero
        or several both come back `None` rather than picking one. A caller
        that must tell two open runs apart -- `run.finish`'s `kind` argument,
        `finding.record`'s ambiguous-refusal message -- reads `open_runs()`
        itself rather than trusting this property to guess.

        NOT `hx.run.current_run`. That function auto-opens a run, which is
        right for `hx capture start` -- a forgotten command should not cost
        an hour of unrecorded browsing -- and wrong here: silently handing
        back some OTHER run's id would make `run.start`'s `run_open` refusal
        a lie about which run is open, and would make `run.finish` close a
        run nobody asked it to.
        """
        if self._bound_run_id is not None:
            return self._bound_run_id
        rows = self.open_runs()
        return rows[0][0] if len(rows) == 1 else None

    @run_id.setter
    def run_id(self, value: str | None) -> None:
        # `run.start` binds with this; `run.finish` clears with it -- both are
        # a plain `ctx.run_id = ...` at the call site, unchanged by this
        # property existing. Checked FIRST by the getter above, so this
        # always wins over whatever `open_runs()` cached earlier in the call.
        self._bound_run_id = value


def dispatch(ctx: ToolContext, name: str, args: dict[str, Any] | None = None,
             *, why: str | None = None) -> envelope.Envelope:
    """Validate, authorise, call, journal. Never raises."""
    # ONE run-resolution snapshot per call, taken lazily on first read and
    # reused by everything below -- the guards, the handler (however many
    # times IT reads `ctx.run_id` or `ctx.open_runs()`), and `_journalled`'s
    # own trailing read. Without this reset a context left over from a prior
    # dispatch would hand a NEW call the OLD call's snapshot; see
    # `ToolContext.open_runs` for the defect this closes.
    ctx._open_runs_cache = None

    # A malformed `why` is never written to `agent_action.why`, in any of the
    # rows the four guards below produce -- refused or not. `str(123)` there
    # would read as an operator's reason for a state change nobody gave, so a
    # non-string `why` is refused rather than coerced, and every row journalled
    # before that refusal fires carries None instead of the raw value.
    safe_why = why if why is None or isinstance(why, str) else None

    if not isinstance(name, str):
        # `agent_action.tool` is NOT NULL TEXT. A name malformed enough that
        # it cannot be looked up still gets a row -- rendered, not dropped --
        # because an agent looping on a malformed call is exactly what this
        # table exists to make visible.
        placeholder = f"<{type(name).__name__}>"
        return _journalled(ctx, placeholder, {}, safe_why, envelope.refused(
            placeholder, "bad_args",
            f"tool name must be a string, got {type(name).__name__}"))

    if args is not None and not isinstance(args, dict):
        return _journalled(ctx, name, {}, safe_why, envelope.refused(
            name, "bad_args",
            f"arguments must be an object, got {type(args).__name__}"))

    args = dict(args or {})

    if not all(isinstance(key, str) for key in args):
        # The same guard that keeps `schema.validate`'s internal
        # `sorted(set(value) - set(props))` from raising on a set of mixed
        # str and non-str keys: a JSON object's keys are always strings, so a
        # non-string key here did not come from JSON at all.
        return _journalled(ctx, name, {}, safe_why, envelope.refused(
            name, "bad_args", "argument names must be strings"))

    if why is not None and not isinstance(why, str):
        return _journalled(ctx, name, args, safe_why, envelope.refused(
            name, "bad_args", f"why must be a string, got {type(why).__name__}"))

    # THE TWO LENGTH GUARDS BELOW USED TO SIT HERE, ABOVE `registry.lookup`
    # AND THE HALT CHECK, WHICH INVERTED THE PUBLISHED ORDER FOR BOTH. A name
    # over 64 characters is simply not a registered name -- `bad_args` for it
    # answered before `not_registered` got a chance to, on a call the order
    # says `not_registered` should own. A `why` over 500 characters is an
    # argument problem, and the order puts `bad_args` after `halted`
    # deliberately: an operator who has hit STOP should hear "the engagement
    # is halted", not a lecture about `why`'s length, for a call that was
    # never going to run either way. Both guards move below `lookup` and the
    # halt check for exactly that reason -- see the module docstring's
    # account of the four TYPE guards that must stay above them, which this
    # does not touch: a non-string name or `why` cannot be looked up or
    # `.strip()`-ed at all, so those four are a different kind of guard from
    # these two.

    tool = registry.lookup(name)
    if tool is None:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "not_registered",
            f"{name} is not a tool. Run `hx tool --list` to see the "
            "registered tools; checks.list only lists security checks."))

    if tool.mutates and ctx.halt.halted and name not in HALT_EXEMPT:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "halted", ctx.halt.reason))

    if tool.requires_why and not (why or "").strip():
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "missing_why",
            f"{name} changes state, so it needs a `why`: it is written to "
            "agent_action and read by whoever asks what this run did."))

    if len(name) > 64:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "bad_args",
            f"tool name must be at most 64 characters, got {len(name)}"))

    if why is not None and len(why) > 500:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "bad_args",
            f"why must be at most 500 characters, got {len(why)}"))

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
    covers nothing about the refusals above -- the four decision-order ones,
    and the four call-shape guards ahead of them -- which happen before or at
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
