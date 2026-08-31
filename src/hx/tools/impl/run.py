"""The run lifecycle: section 8's bracket, and in Plan B the JVM's.

`run.start` and `run.finish` are the only pair in the seventeen that mean
something to the layer itself rather than to the store: `ctx.run_id` is bound
by one and cleared by the other, and every row anything else writes hangs off
it. Plan B gives the same pair a live Burp to bracket, which is why the design
puts the session here rather than in a tool of its own.
"""
from __future__ import annotations

from ... import run as run_mod
from .. import envelope, registry, spec
from ..errors import ToolUnavailable

#: `killed` is absent DELIBERATELY. The run table admits five statuses; that
#: one is the operator's word for what they did to a run, and an agent writing
#: it would put a human act in the run table. `aborted` is the agent's word
#: for a run it stopped itself.
AGENT_STATUSES = ("completed", "aborted", "error")

#: The journal answers "what have I already tried"; it is read, not paged
#: through, so its default is smaller than a query's.
JOURNAL_DEFAULT = 20


def start(ctx, kind: str) -> dict:
    """Open a run and bind it to this context."""
    run_id = run_mod.open_run(ctx.conn, engagement_id=ctx.engagement.id,
                              kind=kind,
                              safety_profile=ctx.config.safety_profile)
    ctx.run_id = run_id
    return {"id": run_id, "kind": kind,
            "safety_profile": ctx.config.safety_profile}


def finish(ctx, status: str, note: str | None = None) -> dict:
    """Close the bound run.

    `no_run` rather than a refusal: nothing said no, there was simply nothing
    to close. Section 12's distinction, one tool down.
    """
    if ctx.run_id is None:
        raise ToolUnavailable(
            "no_run", "no run is open on this context; run.start opens one")
    closed = ctx.run_id
    run_mod.close_run(ctx.conn, run_id=closed, status=status, stop_reason=note)
    ctx.run_id = None
    return {"id": closed, "status": status}


def journal(ctx, since: int | None = None, last_n: int | None = None,
            tool: str | None = None) -> dict:
    """What this agent has already tried, newest first.

    NEWEST FIRST because the question is "what did I just do", not "what is the
    history of this engagement". An agent re-reading its own journal after a
    compaction wants the last thing it tried at the top.

    `next_cursor` IS ALWAYS NULL, and that is a limitation rather than an
    oversight: section 8 gives this tool `since` and `last_n` and no cursor, so
    `truncated` means "narrow with `since`, or raise `last_n`". Paging a
    descending time series through a cursor needs a `before`, which section 8
    does not name and this plan does not invent.
    """
    limit = JOURNAL_DEFAULT if last_n is None else last_n
    where = ["engagement_id = ?", "actor = ?"]
    params: list = [ctx.engagement.id, ctx.actor]
    if since is not None:
        where.append("ts_us >= ?")
        params.append(since)
    if tool is not None:
        where.append("tool = ?")
        params.append(tool)
    clause = " AND ".join(where)
    total = ctx.conn.execute(
        f"SELECT COUNT(*) FROM agent_action WHERE {clause}", params).fetchone()[0]
    rows = ctx.conn.execute(
        f"SELECT ts_us, tool, why, result_summary FROM agent_action"
        f" WHERE {clause} ORDER BY ts_us DESC, rowid DESC LIMIT ?",
        (*params, limit + 1)).fetchall()
    return envelope.page(
        [{"ts_us": r[0], "tool": r[1], "why": r[2], "result": r[3]}
         for r in rows],
        total=total, limit=limit)


registry.register(spec.ToolSpec(
    name="run.start", handler=start, mutates=True,
    summary="Open a run. Every row anything else writes hangs off it.",
    params={"type": "object", "additionalProperties": False,
            "required": ["kind"],
            "properties": {"kind": {
                "type": "string", "enum": sorted(run_mod.RUN_KINDS),
                "description": "browse for proxy traffic, scan for a check "
                               "pass, crawl for discovery, manual otherwise"}}}))

registry.register(spec.ToolSpec(
    name="run.finish", handler=finish, mutates=True,
    summary="Close the open run.",
    params={"type": "object", "additionalProperties": False,
            "required": ["status"],
            "properties": {
                "status": {"type": "string", "enum": list(AGENT_STATUSES),
                           "description": "completed, or aborted if you "
                                          "stopped it, or error"},
                "note": {"type": "string", "maxLength": 500,
                         "description": "why it ended this way"}}}))

registry.register(spec.ToolSpec(
    name="run.journal", handler=journal,
    summary="What you have already tried this engagement, newest first.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "since": {"type": "integer", "minimum": 0,
                  "description": "only actions at or after this ts_us"},
        "last_n": {"type": "integer", "minimum": 1,
                   "maximum": envelope.MAX_LIMIT,
                   "description": f"how many, default {JOURNAL_DEFAULT}"},
        "tool": {"type": "string", "maxLength": 64,
                 "description": "only this tool's actions"}}}))
