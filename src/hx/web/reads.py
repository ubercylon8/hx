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

#: `finding.severity`'s CHECK constraint, in the order a reader wants them.
#: Copied deliberately rather than derived: the column's vocabulary is
#: closed, and a filter that accepted something the column cannot hold would
#: silently return nothing and look like a clean result.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

#: `finding.status`'s CHECK constraint. WIDER than `triage.TARGETS`, and
#: deliberately: triage may only WRITE two of these, but a store can hold
#: any of the five and a filter that could not name them would hide rows.
STATUSES = ("new", "triaged", "confirmed", "false_positive", "reported")


class FilterError(Exception):
    """A filter value outside the column's closed vocabulary."""


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


def surfaces(conn: sqlite3.Connection, engagement_id: str) -> tuple:
    """Every captured surface, with how much was done to it.

    `answered` counts DISTINCT checks whose verdict is in
    `coverage.ANSWERED` -- the same definition the report and the overview
    use. A `pending` or `skipped` row records a gap, and a column that
    counted them would say a check ran when none did, which is S12's failure
    at the level of a single table cell.
    """
    marks = ",".join("?" for _ in coverage_mod.ANSWERED)
    rows = conn.execute(
        "SELECT s.id, s.method, s.scheme, s.host, s.port, s.path_template,"
        " s.query_key_set, s.kind, s.discovered_by,"
        " (SELECT COUNT(*) FROM exchange x WHERE x.surface_id = s.id),"
        f" (SELECT COUNT(DISTINCT cr.check_id) FROM check_run cr"
        f"  WHERE cr.surface_id = s.id AND cr.verdict IN ({marks}))"
        " FROM surface s WHERE s.engagement_id=?"
        " ORDER BY s.path_template, s.method, s.id",
        (*coverage_mod.ANSWERED, engagement_id)).fetchall()
    return tuple({
        "id": r[0], "method": r[1], "scheme": r[2], "host": r[3],
        "port": r[4], "path_template": r[5], "query_key_set": r[6],
        "kind": r[7], "discovered_by": r[8], "exchanges": r[9],
        "answered": r[10],
    } for r in rows)


def findings(conn: sqlite3.Connection, engagement_id: str, *,
             severity: str | None = None,
             status: str | None = None) -> tuple:
    """Findings, most severe first, optionally filtered.

    An unrecognised filter value RAISES rather than being ignored. A screen
    that quietly drops a filter shows more rows than were asked for while
    looking as though it obeyed, and the operator's conclusion -- "I
    filtered to confirmed and there were none" -- becomes a false statement
    about their own data.
    """
    if severity is not None and severity not in SEVERITIES:
        raise FilterError(
            f"{severity!r} is not a severity; this store holds "
            f"{list(SEVERITIES)}")
    if status is not None and status not in STATUSES:
        raise FilterError(
            f"{status!r} is not a status; this store holds {list(STATUSES)}")

    where = ["f.engagement_id=?"]
    args: list = [engagement_id]
    if severity is not None:
        where.append("f.severity=?")
        args.append(severity)
    if status is not None:
        where.append("f.status=?")
        args.append(status)

    order = " ".join(
        f"WHEN '{name}' THEN {n}" for n, name in enumerate(SEVERITIES))
    rows = conn.execute(
        "SELECT f.id, f.title, f.severity, f.confidence, f.status,"
        " f.check_id, f.host, s.method, s.path_template"
        " FROM finding f LEFT JOIN surface s ON s.id = f.surface_id"
        " WHERE " + " AND ".join(where) +
        f" ORDER BY CASE f.severity {order} ELSE 99 END, f.title, f.id",
        args).fetchall()
    return tuple({
        "id": r[0], "title": r[1], "severity": r[2], "confidence": r[3],
        "status": r[4], "check_id": r[5], "host": r[6],
        "method": r[7], "path_template": r[8],
    } for r in rows)
