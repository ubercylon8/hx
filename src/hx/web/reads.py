"""Read-only queries, one function per screen.

NOT THE TOOL LAYER, deliberately. `tools/dispatch.py` journals every call --
`journal.record` defaults to `actor="agent"` -- so routing a page view
through it would write one `agent_action` row per view, and the agent
transcript screen would fill with the act of reading it. The audit trail
would stop being able to answer "what did the agent do", which is the
question it exists to answer. The envelopes disagree too: handles and
digests, match-addressed reads and token-budget caps are shaped for a model
with a context window, and a human with a browser has neither constraint.

Every function here takes a connection the caller opened read-only and
returns plain data. None of them render.
"""
from __future__ import annotations

import sqlite3

from hx import coverage as coverage_mod
from hx import run as run_mod


def _run_rows(conn: sqlite3.Connection, engagement_id: str) -> tuple:
    """Every run, newest first, with a display status that tells the truth.

    A run left `running` by a dead harness RENDERS as `error` here and is
    not written back: these connections are read-only, and `run.reap_stale`
    is the writer's job. S5 is explicit -- "an aborted run must never render
    as a clean one, and neither must one that merely STOPPED BEING UPDATED"
    -- and a screen showing `running` for a run the reaper would kill is the
    first thing an operator sees after a crash.
    """
    before = run_mod.stale_before_us()
    out = []
    for row in conn.execute(
            "SELECT id, kind, status, started_us, ended_us, stop_reason,"
            " requests_issued, dropped_total, heartbeat_us, identity_state"
            " FROM run WHERE engagement_id=? ORDER BY started_us DESC, id",
            (engagement_id,)).fetchall():
        stale = run_mod.is_stale(row[2], row[8], row[3], before_us=before)
        out.append({
            "id": row[0], "kind": row[1],
            "status": "error" if stale else row[2],
            "stale": stale,
            "started_us": row[3], "ended_us": row[4],
            "stop_reason": (
                "heartbeat went stale: the harness stopped without closing "
                "this run, so its coverage is incomplete" if stale
                else row[5]),
            "requests_issued": row[6], "dropped_total": row[7],
            "identity_state": row[9],
        })
    return tuple(out)


def overview(conn: sqlite3.Connection, engagement_id: str, config) -> dict:
    """Everything the engagement overview screen shows.

    The coverage figures come from `hx.coverage`, the SAME function
    `report.render` uses, so the screen and the deliverable cannot disagree
    about what was tested. That is not tidiness: a screen with its own
    coverage query loses the denominator, the named untested surfaces and
    the "these numbers are partial" prefix, and shows a reassuring number on
    exactly the engagements where the report shows a warning.
    """
    eng = conn.execute(
        "SELECT id, name, client, created_us, status FROM engagement"
        " WHERE id=?", (engagement_id,)).fetchone()
    scopes = conn.execute(
        "SELECT id, sha256, effective_from_us, author, reason FROM"
        " scope_version WHERE engagement_id=? ORDER BY effective_from_us DESC,"
        " id", (engagement_id,)).fetchall()
    authorizations = conn.execute(
        "SELECT signatory, doc_sha256, valid_from_us, valid_to_us,"
        " scope_sha256 FROM authorization WHERE engagement_id=?"
        " ORDER BY valid_from_us", (engagement_id,)).fetchall()
    severities = {
        row[0]: row[1] for row in conn.execute(
            "SELECT severity, COUNT(*) FROM finding WHERE engagement_id=?"
            " GROUP BY severity", (engagement_id,)).fetchall()}
    statuses = {
        row[0]: row[1] for row in conn.execute(
            "SELECT status, COUNT(*) FROM finding WHERE engagement_id=?"
            " GROUP BY status", (engagement_id,)).fetchall()}
    runs = _run_rows(conn, engagement_id)
    return {
        "engagement": eng,
        "scopes": scopes,
        "authorizations": authorizations,
        "severities": severities,
        "statuses": statuses,
        "runs": runs,
        # S5: a run with drops has coverage numbers that are a FLOOR, not a
        # count. Summed across every run, and rendered beside the figures it
        # qualifies rather than on a page of its own -- putting the caveat
        # somewhere else is how the honest version loses to the reassuring
        # one.
        "dropped_total": sum(r["dropped_total"] or 0 for r in runs),
        "coverage": coverage_mod.facts(conn, engagement_id),
        "unshipped": coverage_mod.unshipped_classes(config),
        "surfaces": conn.execute(
            "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
            (engagement_id,)).fetchone()[0],
        "exchanges": conn.execute(
            "SELECT COUNT(*) FROM exchange x JOIN run r ON r.id = x.run_id"
            " WHERE r.engagement_id=?", (engagement_id,)).fetchone()[0],
    }
