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
from hx.store.blobs import CorruptBlob

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
    coverage = coverage_mod.facts(conn, engagement_id)
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
        "coverage": coverage,
        "unshipped": coverage_mod.unshipped_classes(config),
        # NOT a second `SELECT COUNT(*) FROM surface` -- `coverage.captured`
        # is exactly that query, already run above. `overview.html` renders
        # both figures on the same page, and a second query here was
        # cross-task drift (Task 1 wrote `facts`, Task 3 wrote this
        # function, and neither reviewer could see the other) rather than a
        # second fact.
        "surfaces": coverage.captured,
        "exchanges": conn.execute(
            "SELECT COUNT(*) FROM exchange x JOIN run r ON r.id = x.run_id"
            " WHERE r.engagement_id=?", (engagement_id,)).fetchone()[0],
    }


def dropped_total(conn: sqlite3.Connection, engagement_id: str) -> int:
    """Every exchange this engagement's runs report having dropped, summed.

    S5's floor caveat is not only the overview's: the surfaces screen's
    per-surface exchange counts and its surface list are the same floor
    when any run dropped traffic, and `overview`'s own copy sums this same
    column inline with the runs table it renders beside -- this is the
    figure on its own, for the one other screen that needs it without
    wanting the runs too.
    """
    return conn.execute(
        "SELECT COALESCE(SUM(dropped_total), 0) FROM run WHERE"
        " engagement_id=?", (engagement_id,)).fetchone()[0]


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


#: The encoding every captured byte is shown through, matching
#: `tools/impl/http.py`'s own `TEXT`. latin-1 round-trips all 256 byte
#: values, so the viewer shows what was actually on the wire and agrees
#: with what `http.grep` matched against. utf-8 with `errors="replace"`
#: would show a body the target never sent.
TEXT = "latin-1"


def finding_detail(conn: sqlite3.Connection, finding_id: str) -> dict | None:
    row = conn.execute(
        "SELECT f.id, f.title, f.description, f.impact, f.remediation, f.cwe,"
        " f.references_json, f.severity, f.severity_source, f.confidence,"
        " f.created_by, f.status, f.check_id, f.issue_type_id, f.payload,"
        " f.insertion_name, f.insertion_kind, f.host, f.scope_level,"
        " f.first_seen_run, f.last_seen_run, s.method, s.path_template"
        " FROM finding f LEFT JOIN surface s ON s.id = f.surface_id"
        " WHERE f.id=?", (finding_id,)).fetchone()
    if row is None:
        return None
    keys = ("id", "title", "description", "impact", "remediation", "cwe",
            "references_json", "severity", "severity_source", "confidence",
            "created_by", "status", "check_id", "issue_type_id", "payload",
            "insertion_name", "insertion_kind", "host", "scope_level",
            "first_seen_run", "last_seen_run", "method", "path_template")
    return dict(zip(keys, row))


def evidence(conn: sqlite3.Connection, finding_id: str) -> tuple:
    """The evidence chain, in the order it was attached.

    Joined out to the exchange so a row can be read without a second click:
    what was sent, what came back, and whether the exchange completed at
    all. `outcome` is on the row deliberately -- evidence pointing at a
    timed-out exchange is evidence of nothing, and a chain that hid that
    would let a finding look better supported than it is.
    """
    rows = conn.execute(
        "SELECT e.id, e.seq, e.role, e.kind, e.exchange_id, e.ref, e.note,"
        " e.captured_us, x.method, x.url, x.status, x.outcome"
        " FROM evidence e LEFT JOIN exchange x ON x.id = e.exchange_id"
        " WHERE e.finding_id=? ORDER BY e.seq, e.id", (finding_id,)).fetchall()
    keys = ("id", "seq", "role", "kind", "exchange_id", "ref", "note",
            "captured_us", "method", "url", "status", "outcome")
    return tuple(dict(zip(keys, r)) for r in rows)


def observations(conn: sqlite3.Connection, finding_id: str) -> tuple:
    """Whether each run still saw this finding.

    `observed = 0` on the latest run is what the report renders as "appears
    fixed; verify before closing", and the screen must be able to say the
    same thing -- a retest whose result lives only in the deliverable is a
    retest the operator cannot check before shipping it.
    """
    rows = conn.execute(
        "SELECT o.run_id, o.observed, o.severity_at, o.confidence_at,"
        " o.ts_us, r.kind, r.status FROM finding_observation o"
        " JOIN run r ON r.id = o.run_id WHERE o.finding_id=?"
        " ORDER BY o.ts_us, o.run_id", (finding_id,)).fetchall()
    keys = ("run_id", "observed", "severity_at", "confidence_at", "ts_us",
            "kind", "status")
    return tuple(dict(zip(keys, r)) for r in rows)


def _body(blobs, digest, expected_len=None) -> tuple[str, str | None]:
    """One blob as text, or an honest account of why it is not here.

    Returns `(text, problem)`. A body that COULD NOT BE READ must never
    render as a body that was EMPTY -- that is S12's distinction at the
    level of one panel, and returning `b""` on `CorruptBlob` is exactly the
    collapse it forbids.
    """
    if digest is None:
        return "", None
    try:
        return blobs.get(digest, expected_len).decode(TEXT), None
    except CorruptBlob as exc:
        return "", f"this body could not be read: {exc}"
    except OSError as exc:
        return "", f"this body could not be read: {exc}"


def exchange(conn: sqlite3.Connection, blobs, exchange_id: str) -> dict | None:
    """One exchange, both halves, as text.

    NO REDACTION HAPPENS HERE. `Redactor.java` runs extension-side before
    hashing, so these bytes already carry `{{identity:<id>:authz}}` and
    `{{observed:set-cookie}}` where credentials were. S4: Python must never
    gain a second place that decides any of this. The URL COLUMN is
    different and is redacted in the template, through `records.redact_url`
    -- the rule the Java side already shares character for character.
    """
    row = conn.execute(
        "SELECT id, run_id, surface_id, via, outcome, sent_us, recv_us,"
        " method, url, status, req_blob, resp_blob, resp_len, body_shed,"
        " identity, identity_state, resolved_ip"
        " FROM exchange WHERE id=?", (exchange_id,)).fetchone()
    if row is None:
        return None
    keys = ("id", "run_id", "surface_id", "via", "outcome", "sent_us",
            "recv_us", "method", "url", "status", "req_blob", "resp_blob",
            "resp_len", "body_shed", "identity", "identity_state",
            "resolved_ip")
    out = dict(zip(keys, row))
    out["request"], out["request_problem"] = _body(blobs, row[10])
    out["response"], out["response_problem"] = _body(blobs, row[11], row[12])
    return out
