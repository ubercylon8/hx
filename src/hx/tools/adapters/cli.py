"""`hx tool` -- the tool layer from a shell.

The adapter the test suite drives, and the one an agent with a shell can use
with no MCP wiring at all. Plan B adds `hx mcp` beside it over the same
`dispatch`.

EXIT STATUS FOLLOWS `Envelope.ran`, not the outcome: `ok` and `empty` are both
0, because a query that matched nothing ran correctly, and a shell that treated
"no findings" as a failure would make every clean engagement look broken.
Everything else is 1.
"""
from __future__ import annotations

import json

import click

from ... import halt as halt_mod
from .. import dispatch as dispatch_mod
from .. import impl  # noqa: F401  -- registers every tool
from .. import registry


def build_context(engagement, *, stack=None) -> dispatch_mod.ToolContext:
    """A context over an open engagement.

    NOTHING IS BOUND HERE, and that is fine: each `hx tool` invocation is its
    own process, so a context built here has never seen a `run.start` this
    process ran. `ToolContext.run_id` does not need it to have -- unbound, it
    resolves the open run from the store, and a run `run.start` opened in an
    EARLIER `hx tool` process is still there to find. What this adapter
    cannot do is hold a run across invocations in the FIELD -- there is no
    long-lived object here for `run.start` to bind onto that a later call
    would see -- which is exactly why the resolution had to move to the
    store rather than staying a process-local field.

    `stack` IS NONE FROM THIS ADAPTER AND THAT IS THE HONEST ANSWER, not a
    limitation waiting to be lifted. `hx.session.session()` tears Burp down on
    every exit, so a JVM launched inside a one-shot `hx tool` process dies
    with it -- there is no object here for a session to outlive. `run.start`
    is told so and reports `session: {live: false, reason: "no_host"}`, which
    names `hx mcp` as the adapter that can. The parameter exists because
    `hx mcp` builds its context through this same function.
    """
    return dispatch_mod.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db),
        stack=stack)


def render_listing() -> str:
    """Every tool, for an operator or an agent orienting itself."""
    lines = []
    for name in sorted(registry.TOOLS):
        tool = registry.TOOLS[name]
        marks = "".join(("!" if tool.mutates else " ",
                         "*" if tool.needs_egress else " "))
        lines.append(f"{marks} {name:<20} {tool.summary}")
    lines.append("")
    lines.append("! changes state and needs --why    * needs a live session")
    return "\n".join(lines)


def run_tool(engagement, name: str, args_json: str | None,
             why: str | None) -> tuple[str, int]:
    """Dispatch and render. Returns the text to print and the exit status."""
    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"--json is not JSON: {exc}") from exc
    if not isinstance(args, dict):
        raise click.ClickException("--json must be an object")
    env = dispatch_mod.dispatch(build_context(engagement), name, args, why=why)
    return json.dumps(env.as_dict(), indent=2, sort_keys=True), 0 if env.ran else 1
