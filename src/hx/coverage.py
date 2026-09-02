"""The coverage facts, computed once and rendered twice.

S12 -- "a report that cannot distinguish 'tested, clean' from 'never
reached' is worse than no report" -- is carried by a handful of numbers, and
the way to break it is not to get one of them wrong. It is to compute them
TWICE, in two places, and let the two drift. `report._coverage` had these
queries fused with its Markdown; the web app's overview screen needs the
same figures in HTML. A second implementation would lose what this one
learned the hard way -- the denominator, the NAMED untested surfaces, and
the "these numbers are partial" prefix -- and would show a reassuring
number on exactly the engagements where the report shows a warning.

`scanned` and `unfinished` are computed HERE, alongside the rest, for the
reason `report.render` already computes them once and passes them down:
several sections make a statement about each and none may be free to
disagree with the others.

WHAT THIS MODULE DOES NOT DO IS RENDER. It returns data. `report._coverage`
turns it into Markdown and the overview template turns it into HTML, and
neither is the other's business.
"""
from __future__ import annotations

import dataclasses
import sqlite3

from hx.checks import registry

#: A `check_run.verdict` that means a check actually ANSWERED for a surface.
#: `pending` (the runner opened the row and the process died) and `skipped`
#: (the budget cut the scan off before it) are rows that record a GAP, and
#: counting either as coverage reads a gap as an answer.
ANSWERED = ("clean", "finding", "inconclusive", "error")


@dataclasses.dataclass(frozen=True)
class Coverage:
    """Every number the coverage story is told with.

    `untested` and `unfinished` are rows, not counts, because both are lists
    a reader acts on: the surfaces nothing answered for, and the runs whose
    numbers are a floor. A count alone is what S12 calls unfalsifiable.
    """

    captured: int
    scanned: bool
    unfinished: tuple
    untested: tuple
    by_check: tuple
    reasons: dict


def facts(conn: sqlite3.Connection, engagement_id: str) -> Coverage:
    """Read every coverage figure for one engagement, in one place."""
    captured = conn.execute(
        "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
        (engagement_id,)).fetchone()[0]

    scanned = bool(conn.execute(
        "SELECT 1 FROM check_run cr JOIN run r ON r.id = cr.run_id"
        " WHERE r.engagement_id=? LIMIT 1", (engagement_id,)).fetchone())

    unfinished = tuple(conn.execute(
        "SELECT id, kind, status, stop_reason, started_us FROM run"
        " WHERE engagement_id=? AND status <> 'completed'"
        " ORDER BY started_us, id", (engagement_id,)).fetchall())

    marks = ",".join("?" for _ in ANSWERED)
    untested = tuple(conn.execute(
        "SELECT s.method, s.path_template FROM surface s"
        " WHERE s.engagement_id=? AND NOT EXISTS ("
        "   SELECT 1 FROM check_run cr JOIN run r ON r.id = cr.run_id"
        "   WHERE cr.surface_id = s.id AND r.engagement_id = s.engagement_id"
        f"    AND cr.verdict IN ({marks}))"
        " ORDER BY s.path_template, s.method, s.id",
        (engagement_id, *ANSWERED)).fetchall())

    # COUNT(DISTINCT surface_id), not COUNT(*): a `check_run` row exists per
    # (surface, check) PER RUN, so counting rows counts a retested surface
    # once per run it was retested in -- three surfaces scanned twice
    # rendered "6". The error is always upward, the one direction a coverage
    # figure must not lie in.
    by_check = tuple(conn.execute(
        "SELECT cr.check_id, cr.verdict, COUNT(DISTINCT cr.surface_id)"
        " FROM check_run cr"
        " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
        " GROUP BY cr.check_id, cr.verdict"
        " ORDER BY cr.check_id, cr.verdict", (engagement_id,)).fetchall())

    # Ordered by how many surfaces recorded each reason, then by the reason
    # text -- so the one a reader most needs is the one that survives a
    # caller's cap, and the tiebreak is stable across renders.
    reasons: dict = {}
    for check_id, verdict, reason, _surfaces in conn.execute(
            "SELECT cr.check_id, cr.verdict, cr.reason,"
            " COUNT(DISTINCT cr.surface_id) AS n FROM check_run cr"
            " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
            " AND cr.reason IS NOT NULL AND cr.reason <> ''"
            " GROUP BY cr.check_id, cr.verdict, cr.reason"
            " ORDER BY cr.check_id, cr.verdict, n DESC, cr.reason",
            (engagement_id,)).fetchall():
        reasons.setdefault((check_id, verdict), []).append(reason)

    return Coverage(captured=captured, scanned=scanned, unfinished=unfinished,
                    untested=untested, by_check=by_check, reasons=reasons)


def unshipped_classes(config) -> tuple:
    """Check classes this engagement enables that this build ships none of.

    Not a query: it is a fact about the BUILD and this engagement's config,
    true whether or not a scan has ever run. It belongs beside the coverage
    numbers because it is the one gap they cannot show -- a class with no
    checks in it leaves no `check_run` row, so it leaves no trace in the
    table, and silence there reads as coverage.
    """
    return tuple(sorted(
        klass for klass, on in config.checks.items()
        if on and not any(c.klass == klass for c in registry.CHECKS)))
