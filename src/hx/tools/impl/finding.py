"""What the agent believes, and what it is showing you.

TWO PROPERTIES THIS MODULE DOES NOT INVENT, because `checks.base.Candidate`
already had them for checks and they are better rules for an agent:

  - A FINDING MUST CITE EXCHANGES. `Candidate.exchange_ids` is required, so an
    agent-recorded finding cannot exist without traffic behind it. That is what
    keeps a `created_by='agent'` row answerable in a client deliverable.
  - THE AGENT DOES NOT SPELL ITS OWN DEDUPE KEY. Candidate's own docstring:
    "The check does NOT compute the dedupe key. That is one canonical string
    and one place must build it, or two checks will spell the same finding two
    ways and the UNIQUE constraint will hold two rows." An agent is a worse
    offender than a check, not a better one.

`type_` IS `agent`, NOT A CHECK ID. It is the first of the nine parts, so an
agent finding can never collide with a check's finding of the same issue type
on the same surface -- and two agent recordings of the same thing collapse onto
one row, which is the behaviour a re-run needs.

STATUS IS NOT AN ARGUMENT. Section 8 keeps `finding.set_status` out of the
agent's hands entirely; `upsert_finding` writes `new` and never moves it. The
schema here has no `status` property, so asking for one is `bad_args` -- the
absence is the rule, and `trg_agent_cannot_confirm` is what survives someone
adding the tool back.
"""
from __future__ import annotations

from ...checks import base as checks_base
from ...engagement import now_us
from ...store import db as db_mod
from ...store import records
from .. import envelope, registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: One word, two columns, deliberately. It is the first part of the dedupe key
#: for anything an agent records -- which is what keeps an agent finding from
#: colliding with a check's finding of the same issue type on the same surface
#: -- and it is `finding.created_by`, which section 12 renders. The two are the
#: same claim about the same row, so they are one constant; and if the dedupe
#: prefix were ever changed independently, `created_by`'s CHECK constraint
#: would refuse the write rather than let the two drift quietly apart.
AGENT_TYPE = "agent"

#: The `evidence.role` column has no CHECK constraint -- it was written by one
#: caller with one literal, so it never needed one. Now that a tool can set it,
#: the vocabulary has to live somewhere, and a closed set here is what stops it
#: becoming free text that no report can group by.
EVIDENCE_ROLES = ("proof", "baseline", "context")

CURSOR_PREFIX = "o-"


def _offset(cursor):
    if cursor is None:
        return 0
    if not cursor.startswith(CURSOR_PREFIX) or not cursor[2:].isdigit():
        raise ToolRefused("bad_args", f"{cursor!r} is not a cursor from this tool")
    return int(cursor[2:])


def record(ctx, *, title, issue_type_id, severity, confidence, surface_id,
           exchange_ids, description=None, impact=None, remediation=None,
           cwe=None, payload=None, scope_level="surface",
           insertion_kind=None, insertion_name=None) -> dict:
    """Write a finding the agent believes in. Returns its id and dedupe key."""
    if ctx.run_id is None:
        raise ToolUnavailable(
            "no_run", "a finding belongs to a run; run.start opens one")
    if not exchange_ids:
        raise ToolRefused(
            "bad_args",
            "a finding must cite the exchanges that show it. Record the "
            "traffic first, then record what it demonstrates.")
    surface = ctx.conn.execute(
        "SELECT id, method, scheme, host, port, path_template FROM surface"
        " WHERE id=? AND engagement_id=?",
        (surface_id, ctx.engagement.id)).fetchone()
    if surface is None:
        raise ToolRefused("bad_args", f"no surface {surface_id!r} in this engagement")
    known = {r[0] for r in ctx.conn.execute(
        "SELECT id FROM exchange WHERE id IN (%s)"
        % ",".join("?" * len(exchange_ids)), exchange_ids).fetchall()}
    missing = [x for x in exchange_ids if x not in known]
    if missing:
        raise ToolRefused("bad_args", f"no such exchanges: {sorted(missing)}")

    insertion = None
    if insertion_kind or insertion_name:
        if not (insertion_kind and insertion_name):
            raise ToolRefused(
                "bad_args", "an insertion point needs both a kind and a name")
        insertion = checks_base.Insertion(kind=insertion_kind, name=insertion_name)

    candidate = checks_base.Candidate(
        title=title, issue_type_id=issue_type_id, severity=severity,
        confidence=confidence, insertion=insertion,
        exchange_ids=tuple(exchange_ids), description=description,
        impact=impact, remediation=remediation, cwe=cwe,
        scope_level=scope_level, payload=payload)

    _sid, method, scheme, host, port, path_template = surface
    key = records.dedupe_key(
        type_=AGENT_TYPE, issue_type_id=issue_type_id, scheme=scheme,
        host=host, port=port, method=method, path_template=path_template,
        insertion_kind=insertion.kind if insertion else None,
        insertion_name=insertion.name if insertion else None,
        scope_level=scope_level)
    at = now_us()
    with db_mod.transaction(ctx.conn):
        fid = records.upsert_finding(
            ctx.conn, engagement_id=ctx.engagement.id, candidate=candidate,
            dedupe_key=key, run_id=ctx.run_id, surface_id=surface_id,
            host=host, check_id=None, created_by=AGENT_TYPE)
        records.record_observation(
            ctx.conn, finding_id=fid, run_id=ctx.run_id, observed=True,
            exchange_id=exchange_ids[0], severity_at=severity,
            confidence_at=confidence, at_us=at)
        records.record_evidence(ctx.conn, finding_id=fid,
                                exchange_ids=tuple(exchange_ids), at_us=at)
    return {"id": fid, "dedupe_key": key}


def query(ctx, severity=None, status=None, host=None, surface_id=None,
          created_by=None, limit=None, cursor=None) -> dict:
    """Findings matching the filter, most severe first."""
    limit = envelope.DEFAULT_LIMIT if limit is None else limit
    offset = _offset(cursor)
    where = ["engagement_id = ?"]
    params: list = [ctx.engagement.id]
    for column, value in (("severity", severity), ("status", status),
                          ("host", host), ("surface_id", surface_id),
                          ("created_by", created_by)):
        if value is not None:
            where.append(f"{column} = ?")
            params.append(value)
    clause = " AND ".join(where)
    # Severity order is the report's, not alphabetical: Critical before High
    # before Medium. Alphabetical would put Critical after Low and an agent
    # reading the first page would meet the least important thing first.
    order = ("ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1"
             " WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, id")
    total = ctx.conn.execute(
        f"SELECT COUNT(*) FROM finding WHERE {clause}", params).fetchone()[0]
    rows = ctx.conn.execute(
        f"SELECT id, title, issue_type_id, severity, confidence, status,"
        f" created_by, host, surface_id, check_id, cwe FROM finding"
        f" WHERE {clause} {order} LIMIT ? OFFSET ?",
        (*params, limit + 1, offset)).fetchall()
    facets = {"severity": dict(ctx.conn.execute(
        f"SELECT severity, COUNT(*) FROM finding WHERE {clause}"
        f" GROUP BY severity", params).fetchall())}
    return envelope.page(
        [{"id": r[0], "title": r[1], "issue_type_id": r[2], "severity": r[3],
          "confidence": r[4], "status": r[5], "created_by": r[6],
          "host": r[7], "surface_id": r[8], "check_id": r[9], "cwe": r[10]}
         for r in rows],
        total=total, limit=limit, facets=facets,
        cursor_of=lambda _row: f"{CURSOR_PREFIX}{offset + limit}")


def attach(ctx, finding_id, exchange_id, role="proof", note=None) -> dict:
    """Add one exchange to a finding's evidence chain."""
    if role not in EVIDENCE_ROLES:
        raise ToolRefused("bad_args",
                          f"role must be one of {list(EVIDENCE_ROLES)}")
    exists = ctx.conn.execute(
        "SELECT 1 FROM finding WHERE id=? AND engagement_id=?",
        (finding_id, ctx.engagement.id)).fetchone()
    if exists is None:
        raise ToolRefused("bad_args", f"no finding {finding_id!r}")
    if ctx.conn.execute("SELECT 1 FROM exchange WHERE id=?",
                        (exchange_id,)).fetchone() is None:
        raise ToolRefused("bad_args", f"no exchange {exchange_id!r}")
    records.record_evidence(ctx.conn, finding_id=finding_id,
                            exchange_ids=(exchange_id,), at_us=now_us(),
                            role=role, note=note)
    return {"id": finding_id, "exchange_id": exchange_id, "role": role}


_TEXT = {"type": "string", "maxLength": 4000}

registry.register(spec.ToolSpec(
    name="finding.record", handler=record, mutates=True,
    summary="Record a finding. It must cite the exchanges that show it.",
    params={"type": "object", "additionalProperties": False,
            "required": ["title", "issue_type_id", "severity", "confidence",
                         "surface_id", "exchange_ids"],
            "properties": {
                "title": {"type": "string", "maxLength": 200},
                "issue_type_id": {
                    "type": "string", "maxLength": 100,
                    "description": "stable lowercase-kebab name for the KIND "
                                   "of issue, e.g. missing-hsts; never the "
                                   "code path that noticed it"},
                "severity": {"type": "string",
                             "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                "confidence": {"type": "string",
                               "enum": ["Certain", "Firm", "Tentative"]},
                "surface_id": {"type": "string", "maxLength": 64},
                "exchange_ids": {"type": "array",
                                 "items": {"type": "string", "maxLength": 64},
                                 "description": "the traffic that shows it"},
                "description": _TEXT, "impact": _TEXT, "remediation": _TEXT,
                "cwe": {"type": "string", "maxLength": 32},
                "payload": {"type": "string", "maxLength": 2000,
                            "description": "the value it was demonstrated "
                                           "with, before transport encoding"},
                "scope_level": {"type": "string",
                                "enum": ["engagement", "host", "surface",
                                         "insertion"]},
                "insertion_kind": {
                    "type": "string",
                    "enum": sorted(checks_base.INSERTION_KINDS)},
                "insertion_name": {"type": "string", "maxLength": 200}}}))

registry.register(spec.ToolSpec(
    name="finding.query", handler=query,
    summary="Findings, most severe first.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "severity": {"type": "string",
                     "enum": ["Critical", "High", "Medium", "Low", "Info"]},
        "status": {"type": "string",
                   "enum": ["new", "triaged", "confirmed", "false_positive",
                            "reported"]},
        "host": {"type": "string", "maxLength": 253},
        "surface_id": {"type": "string", "maxLength": 64},
        "created_by": {"type": "string", "enum": ["agent", "human", "check"]},
        "limit": {"type": "integer", "minimum": 1,
                  "maximum": envelope.MAX_LIMIT},
        "cursor": {"type": "string", "maxLength": 32}}}))

registry.register(spec.ToolSpec(
    name="evidence.attach", handler=attach, mutates=True,
    summary="Add one exchange to a finding's evidence chain.",
    params={"type": "object", "additionalProperties": False,
            "required": ["finding_id", "exchange_id"],
            "properties": {
                "finding_id": {"type": "string", "maxLength": 64},
                "exchange_id": {"type": "string", "maxLength": 64},
                "role": {"type": "string", "enum": list(EVIDENCE_ROLES),
                         "description": "proof shows it; baseline is the "
                                        "control it differs from; context is "
                                        "neither"},
                "note": {"type": "string", "maxLength": 500}}}))
