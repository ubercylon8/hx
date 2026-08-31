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

# The identity design's section 6 vocabulary, and it is closed for the reason
# `RUN_KINDS` is: `run.identity_state` and `exchange.identity_state` both
# carry it as a CHECK constraint, and `hx.scan._retirable` gates a client-
# facing retirement on one of the three by name. A fourth spelling reaching
# the column would be refused by SQLite with a message naming neither the
# value nor the alternatives.
IDENTITY_STATES = frozenset({"proven", "assumed", "dead"})


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


def record_identity(conn: sqlite3.Connection, *, run_id: str,
                    identity_id: str, generation: int, state: str) -> None:
    """Which identity a run issued under, and what its liveness settled at.

    NOT PART OF `close_run`, and the split is the same one `count_drop`
    makes. `close_run` is a lifecycle transition guarded on
    `status='running'`; this is a FACT ABOUT WHAT THE RUN DID, and it has to
    be recordable on the halt path -- where `hx.scan.run` writes it a line
    before closing the row `error` -- as readily as on the happy one. A
    version folded into `close_run` would also have to be threaded through
    `current_run`'s idle close and `reap_stale`, neither of which knows
    anything about an identity.

    THE STATE IS CHECKED HERE AS WELL AS BY THE COLUMN. `schema.sql`'s CHECK
    is the backstop and its message is SQLite's ("CHECK constraint failed"),
    which names neither the value nor the vocabulary. `hx.scan` composes this
    argument from three places -- `IdentityWindow.state_for_run()`, and two
    literals on the halt path -- and a fourth caller spelling `alive` would
    otherwise be diagnosed by a constraint rather than by a sentence.

    Deliberately no `WHERE status='running'`: a run whose identity is being
    recorded on the way out of a crash is one this statement must still
    reach, and there is no second writer for it to race.
    """
    if state not in IDENTITY_STATES:
        raise ValueError(
            f"{state!r} is not an identity state; the identity design's "
            f"section 6 names {sorted(IDENTITY_STATES)}, and `run."
            "identity_state` carries the same CHECK constraint `exchange."
            "identity_state` does")
    conn.execute(
        "UPDATE run SET identity=?, identity_generation=?, identity_state=?"
        " WHERE id=?", (identity_id, generation, state, run_id))


def open_runs(conn: sqlite3.Connection, *,
              engagement_id: str) -> list[tuple[str, str]]:
    """`(id, kind)` for every run of this engagement still `status='running'`.

    THE ONE PLACE THAT ANSWERS "WHAT IS OPEN". `dispatch.ToolContext.run_id`
    resolves an unbound context through this query rather than each of its
    callers running its own -- the tool layer's own review put it plainly:
    "do not make the tools query the store one at a time; the resolution
    belongs in one place." `run.finish`'s `kind` disambiguation and
    `run.resume`'s `open_runs` brief both read it too, so a run opened by one
    process and found by another (the CLI's `hx tool` is a fresh process per
    invocation) see the same list.

    Ordered by `started_us` so a caller that wants "the" open run when there
    is exactly one gets it without sorting, and a caller listing all of them
    lists them in the order they were opened.
    """
    return conn.execute(
        "SELECT id, kind FROM run WHERE engagement_id=? AND status='running'"
        " ORDER BY started_us", (engagement_id,)).fetchall()


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
        # COALESCE, exactly as `reap_stale` does below and for the same
        # reason: `heartbeat_us` is NULLABLE (schema.sql declares it plain
        # `INTEGER`, no DEFAULT), and `at - NULL` is not a comparison in
        # Python -- it is `TypeError: unsupported operand type(s) for -: 'int'
        # and 'NoneType'`, raised on whichever thread happened to call this.
        #
        # FOUND BY MEASUREMENT, in Task 9's fix round, from a rig that inserts
        # a `run` row by hand without the column. That raised out of
        # `hx.capture.on_exchange`, which runs on the bridge's READ THREAD,
        # where `BridgeServer._capture` catches it, files the record as a drop
        # and keeps the channel -- so the whole of the symptom was an empty
        # table. `reap_stale` had this COALESCE and a comment explaining it;
        # this function, four lines up in the same module, did not.
        #
        # `started_us` is the fallback and it is NOT NULL, so a run that never
        # heartbeated is judged on when it started -- which is the honest
        # reading: nothing has reported on it since it opened.
        "SELECT id, COALESCE(heartbeat_us, started_us) FROM run"
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

    An accumulator only floors anything if it cannot go backwards. `n=-5`
    measured `dropped_total = -5` here, and a run's own drop reports could
    then erase the signal that its coverage is incomplete -- one malformed
    frame turning an incomplete run into a clean-looking one, which is the
    direction S5 spends this column to prevent. `n=0` is refused with it: a
    `dropped` frame reporting no drops is a frame that means nothing, and the
    caller's own `n` is malformed either way. `hx.capture` checks the same
    bound BEFORE it opens a run, so a stream of these cannot manufacture
    empty runs; this is the floor at the writer, where it also covers callers
    that do not exist yet.
    """
    if n < 1:
        raise ValueError(
            f"a drop report of {n!r} is not a drop report; dropped_total is "
            "an accumulator and S5 makes it the reason a run's coverage "
            "numbers are a floor, so it must never move backwards")
    conn.execute("UPDATE run SET dropped_total = dropped_total + ? WHERE id=?",
                 (n, run_id))
