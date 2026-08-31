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


def build_context(engagement) -> dispatch_mod.ToolContext:
    """A context over an open engagement.

    `run_id` starts None: a fresh process has no open run, and `run.start` is
    how one is bound. That is also why the CLI adapter cannot hold a run across
    invocations -- each `hx tool` is its own process. An agent that needs a run
    to persist wants the MCP adapter, which is one long-lived process; that is
    Plan B, and it is the reason Plan B and not this task carries the session.
    """
    return dispatch_mod.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db))


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
