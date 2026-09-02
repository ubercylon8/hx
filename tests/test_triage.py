"""The only writer of `finding_status_event`, and what it refuses."""
from __future__ import annotations

import pytest

from hx import triage as triage_mod


def _finding(conn, fid="f-1", status="new"):
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES(?,'e-1',?,'Missing HSTS','Low','Firm','check',?,'surface')",
        (fid, f"k-{fid}", status))


def _events(conn, fid="f-1"):
    return conn.execute(
        "SELECT id, from_status, to_status, actor, note FROM"
        " finding_status_event WHERE finding_id=? ORDER BY ts_us, rowid",
        (fid,)).fetchall()


def test_confirming_writes_one_event_and_moves_the_projection(engagement_conn):
    _finding(engagement_conn)
    change = triage_mod.set_status(engagement_conn, finding_id="f-1",
                                   to_status="confirmed")

    assert change.changed is True
    assert change.from_status == "new"
    assert change.to_status == "confirmed"
    events = _events(engagement_conn)
    assert len(events) == 1
    assert events[0][1:5] == ("new", "confirmed", "human", None)
    assert engagement_conn.execute(
        "SELECT status FROM finding WHERE id='f-1'").fetchone()[0] == "confirmed"


def test_the_actor_is_always_human(engagement_conn):
    """Not a parameter. Both callers are humans, and a parameter is a slot a
    future caller fills in wrongly. The enforcement that matters is still
    S8's -- `finding.set_status` is in NEVER_AGENT_FACING, so the agent has
    no path -- and this is the belt beside it."""
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed")
    assert _events(engagement_conn)[0][3] == "human"


def test_repeating_the_current_status_writes_nothing(engagement_conn):
    """A double-clicked button must not put `confirmed -> confirmed` in an
    audit trail. Idempotent rather than refused: the outcome the caller
    wanted is the outcome they have."""
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed")
    before = len(_events(engagement_conn))

    change = triage_mod.set_status(engagement_conn, finding_id="f-1",
                                   to_status="confirmed")

    assert change.changed is False
    assert change.event_id is None
    assert len(_events(engagement_conn)) == before


def test_false_positive_without_a_note_is_refused_and_writes_nothing(
        engagement_conn):
    """THE COUNT IS THE ASSERTION. Checking only that it raised would pass
    code that inserts the event and then rejects, which is the failure this
    test exists for."""
    _finding(engagement_conn)
    with pytest.raises(triage_mod.TriageError, match="note is required"):
        triage_mod.set_status(engagement_conn, finding_id="f-1",
                              to_status="false_positive")

    assert _events(engagement_conn) == []
    assert engagement_conn.execute(
        "SELECT status FROM finding WHERE id='f-1'").fetchone()[0] == "new"


def test_a_whitespace_only_note_does_not_count_as_a_note(engagement_conn):
    _finding(engagement_conn)
    with pytest.raises(triage_mod.TriageError, match="note is required"):
        triage_mod.set_status(engagement_conn, finding_id="f-1",
                              to_status="false_positive", note="   \n ")
    assert _events(engagement_conn) == []


def test_dismissing_with_a_note_records_the_reason(engagement_conn):
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive",
                          note="staging only; header set at the CDN")

    assert _events(engagement_conn)[0][4] == "staging only; header set at the CDN"


def test_a_confirmation_can_be_corrected_and_the_trail_keeps_both(
        engagement_conn):
    """The append-only log is what makes a correctable decision safe: both
    the mistake and the correction stay visible."""
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed")
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="misread the diff")

    events = _events(engagement_conn)
    assert [(e[1], e[2]) for e in events] == [
        ("new", "confirmed"), ("confirmed", "false_positive")]


def test_a_status_outside_S11s_two_is_refused(engagement_conn):
    """S11: "finding triage (new -> confirmed | false_positive with a note)".
    `triaged` and `reported` are in the schema's CHECK and unreachable in
    v1, so a caller reaching for one is a caller who has not read S11."""
    _finding(engagement_conn)
    with pytest.raises(triage_mod.TriageError, match="reported"):
        triage_mod.set_status(engagement_conn, finding_id="f-1",
                              to_status="reported", note="in the deliverable")
    assert _events(engagement_conn) == []


def test_an_unknown_finding_is_refused(engagement_conn):
    with pytest.raises(triage_mod.TriageError, match="no finding"):
        triage_mod.set_status(engagement_conn, finding_id="f-nope",
                              to_status="confirmed")


def test_history_is_oldest_first(engagement_conn):
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed", now_us=10)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="n", now_us=20)

    rows = triage_mod.history(engagement_conn, "f-1")
    assert [r[1] for r in rows] == ["confirmed", "false_positive"]


def test_latest_note_is_the_most_recent_events(engagement_conn):
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="first", now_us=10)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed", now_us=20)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="second", now_us=30)

    assert triage_mod.latest_note(engagement_conn, "f-1") == "second"


def test_latest_note_breaks_a_tied_timestamp_by_the_later_insert(
        engagement_conn):
    """Two events can land in the same microsecond; `ts_us DESC, rowid DESC`
    settles the tie on the later INSERT rather than leaving SQLite free to
    return either row for a bare `ORDER BY ts_us DESC`."""
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed", now_us=10)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="second",
                          now_us=10)

    assert triage_mod.latest_note(engagement_conn, "f-1") == "second"


def test_the_trigger_still_refuses_an_agent_confirmation(engagement_conn):
    """Not this module's guard -- the store's. Pinned here because
    `triage.py` is now the thing standing between an agent and this table,
    and the day someone gives `set_status` an `actor` parameter, this is the
    test that says the schema still says no."""
    import sqlite3
    _finding(engagement_conn)
    with pytest.raises(sqlite3.IntegrityError, match="may not set status"):
        engagement_conn.execute(
            "INSERT INTO finding_status_event(id, finding_id, to_status,"
            " actor, ts_us) VALUES('se-x','f-1','confirmed','agent',1)")
