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
from ..errors import ToolRefused, ToolUnavailable

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
    # Check for existing running runs of the same kind for this engagement.
    # Per-kind, not per-engagement: a crawl running while you browse is two runs,
    # because the enforcement rules differ by exactly that distinction.
    existing = ctx.conn.execute(
        "SELECT id FROM run WHERE engagement_id=? AND kind=? AND status='running'",
        (ctx.engagement.id, kind)).fetchone()
    if existing is not None:
        raise ToolRefused(
            "run_open",
            f"a {kind} run is already open: {existing[0]}; run.finish closes it")

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

RECENT_LIMIT = 20


def resume(ctx) -> dict:
    """The purpose-built recovery brief, section 8.

    `RECENT_LIMIT` caps this brief rather than letting it grow with the
    engagement. It is read when a context window is already under pressure, so
    everything except the recent actions is a COUNT: a brief proportional to
    the store would be unreadable in exactly the situation it exists for.

    "`run.journal` and `run.resume` exist because a long run compacts. Without
    them the agent re-scans surfaces it already covered and cannot tell what it
    has done. This is the loop-prevention hole and the compaction-recovery
    hole, and they are the same hole."

    THE HALT COMES BEFORE THE WORK. An agent resuming into a halted engagement
    will otherwise read a run that is open, surfaces that are untested and
    findings that are thin, and conclude it has work to do -- when the true
    answer is that an operator stopped it. That is one refusal repeated until
    the budget is gone.
    """
    conn, eid = ctx.conn, ctx.engagement.id
    run = None
    if ctx.run_id is not None:
        row = conn.execute(
            "SELECT id, kind, status, started_us, requests_issued FROM run"
            " WHERE id=?", (ctx.run_id,)).fetchone()
        if row is not None:
            run = {"id": row[0], "kind": row[1], "status": row[2],
                   "started_us": row[3], "requests_issued": row[4]}
    surfaces = conn.execute(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE id NOT IN"
        " (SELECT surface_id FROM check_run WHERE surface_id IS NOT NULL))"
        " FROM surface WHERE engagement_id=?", (eid,)).fetchone()
    findings = dict(conn.execute(
        "SELECT severity, COUNT(*) FROM finding WHERE engagement_id=?"
        " GROUP BY severity", (eid,)).fetchall())
    recent = conn.execute(
        "SELECT ts_us, tool, why, result_summary FROM agent_action"
        " WHERE engagement_id=? AND actor=? ORDER BY ts_us DESC, rowid DESC"
        " LIMIT ?", (eid, ctx.actor, RECENT_LIMIT)).fetchall()
    return {
        "engagement": {"id": eid, "name": ctx.config.name,
                       "client": ctx.config.client,
                       "safety_profile": ctx.config.safety_profile},
        "halt": {"armed": ctx.halt.halted, "reason": ctx.halt.reason},
        "run": run,
        "surfaces": {"total": surfaces[0], "untested": surfaces[1]},
        "findings": findings,
        "recent": [{"ts_us": r[0], "tool": r[1], "why": r[2], "result": r[3]}
                   for r in recent],
    }


registry.register(spec.ToolSpec(
    name="run.resume", handler=resume,
    summary="Where you are: the halt, the open run, coverage, findings, and "
            "the last few things you tried. Read this first after a compaction.",
    params={"type": "object", "additionalProperties": False, "properties": {}}))
