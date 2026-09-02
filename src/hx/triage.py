"""The only writer of `finding_status_event`.

S8: "Creating an engagement and confirming a finding are human acts; they
live in the CLI and the web app." This module is the second half of that
sentence, and it is why `finding.set_status` sits in
`tools.spec.NEVER_AGENT_FACING` rather than in the registry: the agent has
no path here, because the registry is an allowlist and nothing outside it
has a code path at all.

THE EVENT IS THE RECORD; `finding.status` IS A CACHE. `schema.sql` says so
on the column, and the two are written in one transaction so they cannot
disagree. `finding_status_event` is append-only under two triggers, for the
reason `scope_version` is: it is the audit trail of who changed a finding's
status and when, and a status transition that could be silently rewritten
afterwards is not an audit trail.

`actor` IS NOT A PARAMETER. Both callers -- `hx triage` and the web app's
POST route -- are humans by construction, and a parameter here is a slot
some later caller fills in with the wrong thing. The store's own
`trg_agent_cannot_confirm` pair remains the enforcement; this is the belt
beside that brace.
"""
from __future__ import annotations

import dataclasses
import sqlite3

from hx.engagement import now_us as _now_us
from hx.store import db as db_mod
from hx.store.records import new_id

#: S11: "finding triage (`new -> confirmed | false_positive` with a note)".
#: `triaged` and `reported` are in the schema's CHECK constraint and are
#: deliberately unreachable in v1 -- nothing sets `reported`, because nothing
#: yet marks a finding as having gone into a deliverable, and a status
#: reachable only by accident is worse than one that is not reachable.
TARGETS = ("confirmed", "false_positive")

#: Dismissing a finding is the decision a client can challenge and a retest
#: has to honour, so "why did you drop this" is answered at the moment it is
#: dropped. Confirming is the bulk action and carries no friction.
NOTE_REQUIRED = ("false_positive",)

ACTOR = "human"


class TriageError(Exception):
    """A status change this module refuses to make."""


@dataclasses.dataclass(frozen=True)
class StatusChange:
    """What happened, including the case where nothing did.

    `changed` exists so a caller can tell a real transition from an
    idempotent repeat without comparing statuses itself, and `event_id` is
    `None` in exactly that case -- there is no row to point at.
    """

    finding_id: str
    from_status: str
    to_status: str
    event_id: str | None
    changed: bool
    ts_us: int


def set_status(conn: sqlite3.Connection, *, finding_id: str, to_status: str,
               note: str | None = None,
               now_us: int | None = None) -> StatusChange:
    """Record a human triage decision on one finding.

    Refusals happen BEFORE anything is written, and the tests assert the
    event count rather than the exception for that reason: a guard that
    raises after inserting is a guard that does not guard.
    """
    if to_status not in TARGETS:
        raise TriageError(
            f"{to_status!r} is not a triage decision; S11 gives exactly "
            f"{list(TARGETS)} (triaged and reported are unreachable in v1)")

    text = None if note is None else note.strip()
    if to_status in NOTE_REQUIRED and not text:
        raise TriageError(
            f"a note is required to set {to_status}: it is the answer to "
            '"why was this dropped", it goes into the client deliverable, '
            "and a retest has to honour it")

    row = conn.execute("SELECT status FROM finding WHERE id=?",
                       (finding_id,)).fetchone()
    if row is None:
        raise TriageError(f"no finding {finding_id!r} in this engagement")
    current = row[0]
    at = _now_us() if now_us is None else now_us

    if current == to_status:
        # A double-clicked button, or two operators reaching the same
        # conclusion. The outcome the caller asked for is the outcome they
        # have, and `confirmed -> confirmed` in an append-only audit trail is
        # noise in the one place noise costs the most.
        return StatusChange(finding_id=finding_id, from_status=current,
                            to_status=to_status, event_id=None, changed=False,
                            ts_us=at)

    event_id = new_id("se")
    with db_mod.transaction(conn):
        conn.execute(
            "INSERT INTO finding_status_event(id, finding_id, from_status,"
            " to_status, actor, note, ts_us) VALUES(?,?,?,?,?,?,?)",
            (event_id, finding_id, current, to_status, ACTOR, text, at))
        conn.execute("UPDATE finding SET status=? WHERE id=?",
                     (to_status, finding_id))

    return StatusChange(finding_id=finding_id, from_status=current,
                        to_status=to_status, event_id=event_id, changed=True,
                        ts_us=at)


def history(conn: sqlite3.Connection, finding_id: str) -> tuple:
    """Every status event for one finding, oldest first.

    `ts_us, rowid` rather than `ts_us` alone, matching `OperatorHalt`'s own
    ordering: two events inside one microsecond are possible and the later
    INSERT is the later event.
    """
    return tuple(conn.execute(
        "SELECT from_status, to_status, actor, note, ts_us"
        " FROM finding_status_event WHERE finding_id=?"
        " ORDER BY ts_us, rowid", (finding_id,)).fetchall())


def latest_note(conn: sqlite3.Connection, finding_id: str) -> str | None:
    """The note on the most recent status event, or None.

    The report's finding section reads this. A bare `status: false_positive`
    in a client deliverable is S12's rule wearing a different hat: it cannot
    distinguish "we checked and it is not real" from "we did not want to
    write it up".
    """
    row = conn.execute(
        "SELECT note FROM finding_status_event WHERE finding_id=?"
        " ORDER BY ts_us DESC, rowid DESC LIMIT 1", (finding_id,)).fetchone()
    return None if row is None else row[0]
