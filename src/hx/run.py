"""Run lifecycle: opening, keeping alive, closing, and reaping the dead.

S5 gives the `run` table `heartbeat_us` and `dropped_total`, and until this
module nothing wrote to either.

The rule worth stating out loud is the one about a run nobody closed. A run
left `running` with a stale heartbeat is a run whose harness DIED -- the
machine slept, the process was killed, the terminal closed. It resolves to
`error`, never to `completed`, because a report generated from a session that
stopped halfway and claims to be complete is the worst output this project
could produce. S5: "an aborted run must never render as a clean one, and
neither must one that merely STOPPED BEING UPDATED."
"""
from __future__ import annotations

import sqlite3

from hx.engagement import now_us as _now_us
from hx.store.records import new_id

# 15 minutes. Long enough that a coffee break does not split a browsing
# session into two runs; short enough that a crash is noticed the same
# afternoon rather than at report time.
IDLE_CLOSE_US = 15 * 60 * 1_000_000

# S5's vocabulary, and it is closed. A typo'd kind reaching the table would be
# invisible to every query that filters on one.
RUN_KINDS = frozenset({"browse", "crawl", "manual", "scan"})


def open_run(conn: sqlite3.Connection, *, engagement_id: str, kind: str,
             safety_profile: str, now_us: int | None = None) -> str:
    if kind not in RUN_KINDS:
        raise ValueError(f"unknown run kind {kind!r}; S5 names {sorted(RUN_KINDS)}")
    at = _now_us() if now_us is None else now_us
    run_id = new_id("r")
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, heartbeat_us, requests_issued, dropped_total)"
        " VALUES(?,?,?,?,?,'running',?,0,0)",
        (run_id, engagement_id, kind, safety_profile, at, at))
    return run_id


def heartbeat(conn: sqlite3.Connection, *, run_id: str,
              now_us: int | None = None) -> None:
    at = _now_us() if now_us is None else now_us
    conn.execute("UPDATE run SET heartbeat_us=? WHERE id=? AND status='running'",
                 (at, run_id))


def close_run(conn: sqlite3.Connection, *, run_id: str,
              now_us: int | None = None, status: str = "completed",
              stop_reason: str | None = None) -> None:
    at = _now_us() if now_us is None else now_us
    conn.execute(
        # Plain assignment, not COALESCE(?, stop_reason). The preserve form was
        # a provable no-op: this statement only touches status='running' rows,
        # and nothing writes stop_reason before a close, so there was never an
        # existing value to preserve. A no-op that looks like a rule is worse
        # than no rule -- it is the shape Task 2 spent a round on.
        "UPDATE run SET status=?, ended_us=?, stop_reason=?"
        " WHERE id=? AND status='running'",
        (status, at, stop_reason, run_id))


def current_run(conn: sqlite3.Connection, *, engagement_id: str, kind: str,
                safety_profile: str, now_us: int | None = None) -> str:
    """The live run of this kind, opening one if there is none.

    Auto-open exists to avoid one specific afternoon: browsing an application
    for an hour and then discovering nothing was recorded because a command
    was forgotten. `hx capture start` will open a deliberately named run when
    Task 8 adds it -- the CLI registers only `new` and `info` today -- and this
    is the fallback rather than the only path.

    A run of a DIFFERENT kind does not satisfy this call. A crawl running
    while you browse is two runs, because the enforcement rules differ by
    exactly that distinction and attributing crawler traffic to a human would
    make the denial rows lie about who was driving.
    """
    at = _now_us() if now_us is None else now_us
    row = conn.execute(
        "SELECT id, heartbeat_us FROM run"
        " WHERE engagement_id=? AND kind=? AND status='running'"
        " ORDER BY started_us DESC LIMIT 1",
        (engagement_id, kind)).fetchone()
    if row is not None:
        # Strictly greater: at exactly the window the run is still live. The
        # boundary is tested from both sides because a test that only probes
        # the far side passes on an off-by-one.
        if at - row[1] <= IDLE_CLOSE_US:
            return row[0]
        close_run(conn, run_id=row[0], now_us=row[1], status="completed",
                  stop_reason="idle")
    return open_run(conn, engagement_id=engagement_id, kind=kind,
                    safety_profile=safety_profile, now_us=at)


def reap_stale(conn: sqlite3.Connection, *, now_us: int | None = None,
               stale_after_us: int | None = None) -> list[str]:
    """Resolve runs whose harness died to `error`. Returns their ids.

    Deliberately a WIDER window than IDLE_CLOSE_US: an idle run is one nobody
    used, and a stale one is a run whose process is gone. Reaping at the idle
    boundary would file every ordinary pause as a crash.
    """
    at = _now_us() if now_us is None else now_us
    window = IDLE_CLOSE_US * 2 if stale_after_us is None else stale_after_us
    # COALESCE, not a bare comparison: heartbeat_us is NULLable, and in SQL
    # `NULL < x` is NULL, which WHERE treats as false. A `running` run that
    # never heartbeated at all would therefore never be reaped -- and a run
    # that died before its first heartbeat is precisely the case this
    # mechanism exists for. It falls back to started_us, which is NOT NULL, so
    # a run that started long ago and never reported is stale on its own
    # evidence.
    rows = conn.execute(
        "SELECT id FROM run WHERE status='running'"
        " AND COALESCE(heartbeat_us, started_us) < ?",
        (at - window,)).fetchall()
    ids = [r[0] for r in rows]
    for run_id in ids:
        conn.execute(
            "UPDATE run SET status='error', ended_us=?, stop_reason=?"
            " WHERE id=? AND status='running'",
            (at, "heartbeat went stale: the harness stopped without closing "
                 "this run, so its coverage is incomplete", run_id))
    return ids


def count_drop(conn: sqlite3.Connection, *, run_id: str, n: int = 1) -> None:
    """Record exchanges the extension could not hand over.

    S5: a run with drops has coverage numbers that are a FLOOR, not a count.
    Accumulates rather than sets, because drops arrive in bursts as the queue
    fills and each burst is real.
    """
    conn.execute("UPDATE run SET dropped_total = dropped_total + ? WHERE id=?",
                 (n, run_id))
