"""The attack surface, as the agent sees it.

ORDERING IS RISK-FIRST AND STABLE: state-changing surfaces before idempotent
reads, then host, path, method, id. Principle 3 asks for "stable ordering by
novelty/risk", and rowid order would hand an agent whatever the proxy happened
to see first -- which is the order a human browsed in, not an order that means
anything.

PAGING IS BY OFFSET, cursor `o-<n>`. Keyset paging over that compound ordering
would have to carry the whole sort tuple in the cursor. The engagement store
has one writer and a query is not held open across a scan, so the failure mode
-- a row inserted mid-page shifting the boundary by one -- is small. It is
still real, and it is written down here rather than discovered later.
"""
from __future__ import annotations

from .. import envelope, registry, spec

#: The one ordering, used by the page and by the count, so they cannot drift.
_ORDER = ("ORDER BY (kind = 'state_changing') DESC, host, path_template,"
          " method, id")


def query(ctx, host=None, method=None, kind=None, discovered_by=None,
          untested=None, limit=None, cursor=None) -> dict:
    """Surfaces matching the filter, riskiest first."""
    limit = envelope.DEFAULT_LIMIT if limit is None else limit
    offset = envelope.parse_offset(cursor)
    where = ["engagement_id = ?"]
    params: list = [ctx.engagement.id]
    for column, value in (("host", host), ("method", method),
                          ("kind", kind), ("discovered_by", discovered_by)):
        if value is not None:
            where.append(f"{column} = ?")
            params.append(value)
    if untested:
        # "Untested" is the coverage question section 12 turns into a report
        # table: a surface no check_run row names has not been looked at, which
        # is not the same as one that was looked at and came back clean.
        where.append("id NOT IN (SELECT surface_id FROM check_run"
                     " WHERE surface_id IS NOT NULL)")
    clause = " AND ".join(where)
    total = ctx.conn.execute(
        f"SELECT COUNT(*) FROM surface WHERE {clause}", params).fetchone()[0]
    rows = ctx.conn.execute(
        f"SELECT id, method, scheme, host, port, path_template, query_key_set,"
        f" kind, discovered_by, first_seen_run, last_seen_run"
        f" FROM surface WHERE {clause} {_ORDER} LIMIT ? OFFSET ?",
        (*params, limit + 1, offset)).fetchall()
    facets = {
        "host": dict(ctx.conn.execute(
            f"SELECT host, COUNT(*) FROM surface WHERE {clause}"
            f" GROUP BY host ORDER BY COUNT(*) DESC", params).fetchall()),
        "kind": dict(ctx.conn.execute(
            f"SELECT kind, COUNT(*) FROM surface WHERE {clause}"
            f" GROUP BY kind", params).fetchall()),
    }
    return envelope.page(
        [{"id": r[0], "method": r[1], "scheme": r[2], "host": r[3],
          "port": r[4], "path_template": r[5], "query_keys": r[6],
          "kind": r[7], "discovered_by": r[8],
          "first_seen_run": r[9], "last_seen_run": r[10]} for r in rows],
        total=total, limit=limit, facets=facets,
        cursor_of=lambda _row: f"{envelope.CURSOR_PREFIX}{offset + limit}")


def detail(ctx, surface_id: str) -> dict | None:
    """One surface, with what has been tested on it.

    Returns None -- which the envelope reads as `empty` -- for a surface that
    does not exist. `unavailable` would claim the tool could not look, and an
    agent would go looking for a broken tool instead of a wrong id.

    THE `engagement_id` IN THE WHERE CLAUSE IS DEFENCE IN DEPTH OVER A
    STRUCTURAL GUARANTEE, and there is deliberately no test for it. Section 3
    makes the engagement the isolation unit -- its own directory, its own
    database -- and two engagements cannot share one store:
    `trg_engagement_singleton` aborts a second `engagement` row, and
    `surface.engagement_id REFERENCES engagement(id)` under `foreign_keys=ON`
    aborts a surface naming any other. Both measured. A test for cross-
    engagement leakage would have to disable the trigger AND the foreign keys
    to build the row it then asserts is unreachable, which would exercise the
    fixture rather than the product. The clause stays because it costs
    nothing and it is what the day someone relaxes those guarantees will need.
    """
    row = ctx.conn.execute(
        "SELECT id, method, scheme, host, port, path_template, query_key_set,"
        " kind, discovered_by, normaliser_version, first_seen_run,"
        " last_seen_run, exemplar_exchange_id FROM surface"
        " WHERE id=? AND engagement_id=?",
        (surface_id, ctx.engagement.id)).fetchone()
    if row is None:
        return None
    checks = ctx.conn.execute(
        "SELECT check_id, verdict, reason, requests_sent FROM check_run"
        " WHERE surface_id=? ORDER BY started_us DESC, rowid DESC",
        (surface_id,)).fetchall()
    exchanges = ctx.conn.execute(
        "SELECT COUNT(*) FROM exchange WHERE surface_id=?",
        (surface_id,)).fetchone()[0]
    return {
        "id": row[0], "method": row[1], "scheme": row[2], "host": row[3],
        "port": row[4], "path_template": row[5], "query_keys": row[6],
        "kind": row[7], "discovered_by": row[8], "normaliser_version": row[9],
        "first_seen_run": row[10], "last_seen_run": row[11],
        "exemplar_exchange_id": row[12],
        "exchanges": exchanges,
        "checks": [{"check_id": c[0], "verdict": c[1], "reason": c[2],
                    "requests_sent": c[3]} for c in checks],
    }


registry.register(spec.ToolSpec(
    name="surface.query", handler=query,
    summary="Attack surface, riskiest first. Filter, then page with the cursor.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "host": {"type": "string", "maxLength": 253},
        "method": {"type": "string", "maxLength": 16},
        "kind": {"type": "string",
                 "enum": ["idempotent_read", "state_changing", "unknown"]},
        "discovered_by": {"type": "string",
                          "enum": ["proxy", "crawl", "import", "agent"]},
        "untested": {"type": "boolean",
                     "description": "only surfaces no check has run against"},
        "limit": {"type": "integer", "minimum": 1,
                  "maximum": envelope.MAX_LIMIT,
                  "description": f"default {envelope.DEFAULT_LIMIT}"},
        "cursor": {"type": "string", "maxLength": 32,
                   "description": "the next_cursor from a previous page"}}}))

registry.register(spec.ToolSpec(
    name="surface.detail", handler=detail,
    summary="One surface, with every check that has run against it.",
    params={"type": "object", "additionalProperties": False,
            "required": ["surface_id"],
            "properties": {"surface_id": {"type": "string", "maxLength": 64}}}))
