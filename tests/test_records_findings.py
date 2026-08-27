"""Identity for findings, and the one place it is computed.

S5's dedupe_key is a single canonical string. Its field ORDER and its
`-`-for-absent rule are not stylistic: SQLite treats NULLs as distinct in a
UNIQUE index, so a NULL anywhere in this key silently defeats the constraint
the whole retest story rests on.
"""
import pytest

from hx.checks import base
from hx.store import records


def key(**over):
    args = dict(type_="xss", scheme="https", host="app.test", port=443,
                method="GET", path_template="/api/orders/{id}",
                insertion_kind="query", insertion_name="q")
    args.update(over)
    return records.dedupe_key(**args)


def test_the_field_order_is_the_spec_s():
    assert key() == "xss|https|app.test|443|GET|/api/orders/{id}|query|q"


def test_absent_parts_are_a_literal_dash_never_none():
    """The load-bearing rule. A NULL here is distinct from every other NULL in
    a UNIQUE index, so two identical findings would both insert and the
    engagement would grow a duplicate every run."""
    k = key(insertion_kind=None, insertion_name=None)
    assert k.endswith("|-|-")
    assert "None" not in k


def test_method_is_part_of_identity():
    """S5 says why: GET /api/order/{n} leaking another tenant's data and
    POST /api/order/{n} accepting mass-assignment are different findings."""
    assert key(method="GET") != key(method="POST")


def test_insertion_kind_is_part_of_identity():
    assert key(insertion_kind="query") != key(insertion_kind="header")


def test_upsert_is_idempotent_across_runs(engagement_conn):
    """Two runs seeing one finding produce ONE finding row and TWO
    observations. That is the whole retest mechanism."""
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    a = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=c, dedupe_key=key(), run_id="r-1")
    b = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=c, dedupe_key=key(), run_id="r-2")
    assert a == b
    n = engagement_conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    assert n == 1


def test_upsert_moves_last_seen_run_and_never_first_seen(engagement_conn):
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-1")
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-2")
    row = engagement_conn.execute(
        "SELECT first_seen_run, last_seen_run FROM finding").fetchone()
    assert row == ("r-1", "r-2")


def test_a_check_written_finding_is_new_and_created_by_check(engagement_conn):
    """The trigger already forbids the agent writing confirmed or reported.
    This asserts the other half: what a check DOES write."""
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-1")
    row = engagement_conn.execute(
        "SELECT status, created_by FROM finding").fetchone()
    assert row == ("new", "check")


def test_a_re_upsert_does_not_reset_a_humans_triage(engagement_conn):
    """An operator marked it false_positive; the next scan must not undo that.
    Without this the triage in S11's UI would be erased by the next run."""
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    engagement_conn.execute(
        "UPDATE finding SET status='false_positive' WHERE id=?", (fid,))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-2")
    status = engagement_conn.execute(
        "SELECT status FROM finding").fetchone()[0]
    assert status == "false_positive"


def test_evidence_rows_are_ordered_by_seq(engagement_conn):
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1", "x-2"))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=c.exchange_ids, at_us=1)
    seqs = [r[0] for r in engagement_conn.execute(
        "SELECT seq FROM evidence WHERE finding_id=? ORDER BY seq", (fid,))]
    assert seqs == [0, 1]


def test_re_recording_evidence_does_not_grow_the_chain(engagement_conn):
    """Row E of Task 5's sweep, and it found a defect in the plan itself.

    The plan specified that `record_evidence` REPLACES -- `DELETE FROM
    evidence` then re-insert. The schema forbids it: `trg_evidence_no_delete`
    raises `evidence is immutable`, because evidence is what a disputed
    finding is proven with. So the plan's version raised `IntegrityError` on
    the second recording of any finding, and no test could see it, because
    nothing recorded twice.

    What the plan WANTED is still right: a finding seen in three runs must not
    carry its exchange three times, or S12's report renders one problem as
    three. This asserts that property, reached the only way an append-only
    table allows -- skip what is already there.
    """
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1", "x-2"))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    for _ in range(2):
        records.record_evidence(engagement_conn, finding_id=fid,
                                exchange_ids=c.exchange_ids, at_us=1)

    seqs = [r[0] for r in engagement_conn.execute(
        "SELECT seq FROM evidence WHERE finding_id=? ORDER BY seq", (fid,))]
    # Two exchanges recorded twice is still two rows, numbered 0 and 1 -- not
    # four rows, and not two rows numbered 0,0,1,1.
    assert seqs == [0, 1]


def test_evidence_records_a_genuinely_new_exchange_on_a_later_run(engagement_conn):
    """The separating case for the skip. Without it, `record_evidence` could
    refuse everything after the first call and the test above would still
    pass -- a chain that never grows is not the same as one that grows only
    for new evidence.
    """
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-1",), at_us=1)
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-1", "x-9"), at_us=2)
    rows = engagement_conn.execute(
        "SELECT seq, exchange_id FROM evidence WHERE finding_id=? ORDER BY seq",
        (fid,)).fetchall()
    assert rows == [(0, "x-1"), (1, "x-9")]
