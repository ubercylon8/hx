"""Identity for findings, and the one place it is computed.

S5's dedupe_key is a single canonical string. Its field ORDER and its
`-`-for-absent rule are not stylistic. `finding.dedupe_key` is `TEXT NOT
NULL`, so a bare `None` is rejected loudly -- measured: `INSERT INTO
finding(...) VALUES(..., NULL, ...)` raises `IntegrityError: NOT NULL
constraint failed: finding.dedupe_key`, not silence. (F6 of the task-5
review: this docstring used to say a NULL here "silently defeats the
constraint", which the measurement above contradicts.) What the `-` rule
actually forecloses is the SILENT failure mode the loud one is not: SQLite
treats NULLs as distinct in a UNIQUE index, so a design that let an absent
PART reach SQL as a real NULL -- a raw column in the composite UNIQUE, or a
key built by SQL `||` concatenation, where `NULL || anything` is itself
`NULL` -- would let the same finding insert again on every scan with the
constraint sitting there looking like it worked. Collapsing every part into
one Python string with a literal placeholder for an absent part is what
keeps that failure mode out of reach in the first place.
"""
import dataclasses
import sqlite3

import pytest

from hx.checks import base
from hx.store import records


def key(**over):
    args = dict(type_="hx.passive.xss", issue_type_id="reflected-xss",
                scheme="https", host="app.test", port=443,
                method="GET", path_template="/api/orders/{id}",
                insertion_kind="query", insertion_name="q",
                scope_level="surface")
    args.update(over)
    return records.dedupe_key(**args)


def test_the_field_order_is_the_canonical_one():
    """S5 writes eight parts. The repository's key has NINE: `issue_type_id`
    was added immediately after `type_` by F1 of the whole-branch review, and
    `records.dedupe_key`'s own docstring is the authority on why. This test
    is the transcription of that format, so a part quietly moving or being
    dropped is a failure here rather than a silently re-filed engagement."""
    assert key() == ("hx.passive.xss|reflected-xss|https|app.test|443|GET|"
                     "/api/orders/{id}|query|q")


def test_the_issue_type_is_part_of_identity():
    """F1 of the whole-branch review, HIGH. `type_` is the CHECK; every part
    after `issue_type_id` is the SURFACE. Without this part, every candidate
    one passive check yields for one surface has a byte-identical key and
    `upsert_finding` keeps one row -- measured, three security headers
    missing from one response filed one finding at the wrong severity."""
    assert key(issue_type_id="missing-hsts") != key(
        issue_type_id="missing-frame-protection")


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


# --- Whole-branch review F3 (MEDIUM): `scope_level` was stored on the row
# and never consulted here, so a host-scoped finding filed once per surface.


def test_every_scope_level_has_a_key_rule():
    """`_SCOPE_BLANKS` and the vocabulary must not drift apart. A new
    scope_level added to `base.SCOPE_LEVELS` without a decision here would
    otherwise raise at the first finding that used it -- or, worse, quietly
    take `surface`'s behaviour had this been written with a `.get` default."""
    assert set(records._SCOPE_BLANKS) == set(base.SCOPE_LEVELS)


def test_host_scope_drops_the_path_and_the_method_from_the_key():
    """The finding IS the host. One flagless cookie on forty pages is one
    remediation, and forty keys differing only in `path_template` is forty
    tickets for it -- see `cookie_flags`' own docstring."""
    a = key(scope_level="host", path_template="/a", method="GET")
    b = key(scope_level="host", path_template="/b", method="POST")
    assert a == b
    assert "|-|-|" in a          # method and path_template, both blanked


def test_host_scope_keeps_the_host_scheme_and_port():
    """The separating case in the other direction: blanking the host too
    would make two clients' hosts one finding."""
    assert key(scope_level="host", host="a.test") != key(
        scope_level="host", host="b.test")
    assert key(scope_level="host", scheme="http") != key(
        scope_level="host", scheme="https")
    assert key(scope_level="host", port=443) != key(
        scope_level="host", port=8443)


def test_engagement_scope_drops_the_host_as_well():
    """`engagement` is the widest scope S5 has. Nothing about WHERE the
    finding was seen can be identity, or it is not engagement-wide."""
    a = key(scope_level="engagement", host="a.test", path_template="/a")
    b = key(scope_level="engagement", host="b.test", path_template="/b")
    assert a == b


def test_surface_and_insertion_scope_keep_every_part():
    """An insertion point is NARROWER than a surface, not wider, so it drops
    nothing a surface keeps -- and `surface` is S5's key exactly as written.
    Anti-vacuity for the two tests above: if blanking were unconditional,
    both of these would collapse too."""
    for scope in ("surface", "insertion"):
        assert key(scope_level=scope, path_template="/a") != key(
            scope_level=scope, path_template="/b")
        assert key(scope_level=scope, method="GET") != key(
            scope_level=scope, method="POST")


def test_an_unknown_scope_level_is_refused():
    """`Candidate.__post_init__` already refuses one, but this function is
    also called directly, and a scope it does not know must not silently
    become a key with nothing blanked."""
    with pytest.raises(ValueError, match="scope_level"):
        key(scope_level="galaxy")


def test_upsert_is_idempotent_across_runs(engagement_conn):
    """Two runs seeing one finding produce ONE finding row, not two. Whether
    each run also produced its own observation is `record_observation`'s
    concern, not `upsert_finding`'s -- see the `test_record_observation_*`
    tests below, corrected here in F2 of the task-5 review: this docstring
    used to claim "TWO observations" while the test below writes none."""
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    a = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=c, dedupe_key=key(), run_id="r-1")
    b = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=c, dedupe_key=key(), run_id="r-2")
    assert a == b
    n = engagement_conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    assert n == 1


def test_an_upsert_never_moves_the_issue_type_off_its_own_key(engagement_conn):
    """D5 of the fix-round-A re-review. `dedupe_key` arrives as a free
    parameter, independent of `candidate`, and `issue_type_id` is the key's
    2nd part -- so the only way a conflicting row can carry a DIFFERENT
    issue type is a caller whose key and candidate disagree. That is a bug in
    the caller, and `issue_type_id=excluded.issue_type_id` in the
    `DO UPDATE SET` list silently resolved it in the wrong direction: the row
    ended up stored under a key that no longer contained its own issue type.

    The invariant asserted here is the one a reader can check by eye -- a
    finding's `issue_type_id` is the 2nd part of its `dedupe_key` -- and it
    holds for the second write as well as the first.
    """
    k = key(issue_type_id="reflected-xss")
    good = base.Candidate(title="t", issue_type_id="reflected-xss",
                          severity="Low", confidence="Firm",
                          insertion=None, exchange_ids=("x-1",))
    wrong = base.Candidate(title="t", issue_type_id="stored-xss",
                           severity="Low", confidence="Firm",
                           insertion=None, exchange_ids=("x-1",))

    a = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=good, dedupe_key=k, run_id="r-1")
    b = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=wrong, dedupe_key=k, run_id="r-2")

    assert a == b
    stored_key, stored_type = engagement_conn.execute(
        "SELECT dedupe_key, issue_type_id FROM finding").fetchone()
    assert stored_type == stored_key.split("|")[1], (
        "the row's issue_type_id is no longer the one its own dedupe_key "
        "was built from")
    assert stored_type == "reflected-xss"


def test_upsert_moves_last_seen_run_and_never_first_seen(engagement_conn):
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-1")
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-2")
    row = engagement_conn.execute(
        "SELECT first_seen_run, last_seen_run FROM finding").fetchone()
    assert row == ("r-1", "r-2")


def test_upsert_writes_the_payload_and_moves_it_with_the_description(
        engagement_conn):
    """F10 of the whole-branch review. `finding.payload` has been in the
    schema and in this INSERT since the column existed, and every check in
    the first corpus that HAS payloads left it None -- so the column was
    NULL on every row.

    The re-upsert half is why it is in the `DO UPDATE SET` list. Two active
    checks mint a fresh random payload per run, so a column left alone would
    hold run 1's value beside a `description`, `severity` and `confidence`
    that all move to run 2's -- one row describing two demonstrations. It is
    not part of `dedupe_key`, so moving it re-files nothing: the same row is
    updated, not a second one written.
    """
    first = base.Candidate(title="t", issue_type_id="t-issue",
                           severity="Low", confidence="Firm", insertion=None,
                           exchange_ids=("x-1",), payload="aaa'")
    records.upsert_finding(engagement_conn, engagement_id="e-1",
                           candidate=first, dedupe_key=key(), run_id="r-1")
    assert engagement_conn.execute(
        "SELECT payload FROM finding").fetchone()[0] == "aaa'"

    second = dataclasses.replace(first, payload="bbb'", description="later")
    records.upsert_finding(engagement_conn, engagement_id="e-1",
                           candidate=second, dedupe_key=key(), run_id="r-2")
    rows = engagement_conn.execute(
        "SELECT payload, description FROM finding").fetchall()
    assert rows == [("bbb'", "later")]


def test_a_check_written_finding_is_new_and_created_by_check(engagement_conn):
    """The trigger already forbids the agent writing confirmed or reported.
    This asserts the other half: what a check DOES write."""
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-1")
    row = engagement_conn.execute(
        "SELECT status, created_by FROM finding").fetchone()
    assert row == ("new", "check")


def test_a_re_upsert_does_not_reset_a_humans_triage(engagement_conn):
    """An operator marked it false_positive; the next scan must not undo that.
    Without this the triage in S11's UI would be erased by the next run."""
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
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
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
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
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
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
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
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


def test_evidence_accumulates_one_row_per_genuinely_new_observation(engagement_conn):
    """F1 of the task-5 review, pinned directly: the claim the old docstring
    made -- "a chain that does not grow on re-observation" -- is false of the
    real path, because `record_exchange` mints a fresh `x-<random>` id per
    row. Two runs, each producing its OWN new exchange (never the same id
    twice, unlike the re-recording test above), must leave TWO evidence rows,
    not one. If `record_evidence` were changed to actually implement the
    false claim -- deduping by finding_id rather than by exchange id, say --
    this is the test that would catch it.
    """
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-1",), at_us=1)
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-2",), at_us=2)
    rows = engagement_conn.execute(
        "SELECT seq, exchange_id FROM evidence WHERE finding_id=? ORDER BY seq",
        (fid,)).fetchall()
    assert rows == [(0, "x-1"), (1, "x-2")]


def test_a_mid_loop_failure_leaves_no_partial_chain(engagement_conn):
    """F5 of the task-5 review: `record_evidence` writes N rows on an
    autocommit connection unless wrapped in `db.transaction`. A dangling
    exchange id -- one naming no real `exchange` row -- fails the FOREIGN KEY
    check on ITS OWN insert, the second of two, so this is a real mid-loop
    failure, not a mock. Wrapped, the whole call rolls back and neither row
    survives; unwrapped, the first (`x-1`) would already be committed.
    """
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1", "x-2"))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    with pytest.raises(sqlite3.IntegrityError):
        records.record_evidence(engagement_conn, finding_id=fid,
                                exchange_ids=("x-1", "x-does-not-exist"),
                                at_us=1)
    n = engagement_conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE finding_id=?", (fid,)).fetchone()[0]
    assert n == 0


def test_record_observation_inserts_a_row(engagement_conn):
    """F2 of the task-5 review: `record_observation` had zero tests -- its
    entire body could be replaced with `return None` and the suite stayed
    green. This is the insert path."""
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_observation(engagement_conn, finding_id=fid, run_id="r-1",
                               observed=True, exchange_id="x-1",
                               severity_at="Low", confidence_at="Firm",
                               at_us=1)
    row = engagement_conn.execute(
        "SELECT finding_id, run_id, observed, exchange_id, severity_at,"
        " confidence_at FROM finding_observation").fetchone()
    assert row == (fid, "r-1", 1, "x-1", "Low", "Firm")


def test_record_observation_false_is_its_own_case(engagement_conn):
    """`observed=False` must be stored as `0`, not silently treated the same
    as `observed=True` by a writer that never looks at the flag."""
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_observation(engagement_conn, finding_id=fid, run_id="r-1",
                               observed=False, exchange_id=None,
                               severity_at="Low", confidence_at="Firm",
                               at_us=1)
    observed = engagement_conn.execute(
        "SELECT observed FROM finding_observation").fetchone()[0]
    assert observed == 0


def test_record_observation_upserts_on_conflict(engagement_conn):
    """The `ON CONFLICT(finding_id, run_id)` path: a second call for the same
    finding and run must UPDATE the one row `finding_observation`'s primary
    key allows, not raise and not duplicate."""
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_observation(engagement_conn, finding_id=fid, run_id="r-1",
                               observed=True, exchange_id="x-1",
                               severity_at="Low", confidence_at="Firm",
                               at_us=1)
    records.record_observation(engagement_conn, finding_id=fid, run_id="r-1",
                               observed=False, exchange_id="x-2",
                               severity_at="Low", confidence_at="Firm",
                               at_us=2)
    n = engagement_conn.execute(
        "SELECT COUNT(*) FROM finding_observation").fetchone()[0]
    assert n == 1
    row = engagement_conn.execute(
        "SELECT observed, exchange_id, ts_us FROM finding_observation").fetchone()
    assert row == (0, "x-2", 2)


def test_record_observation_refreshes_severity_and_confidence_together(engagement_conn):
    """F7 of the task-5 review: the DO UPDATE used to refresh `observed`,
    `exchange_id` and `ts_us` but leave `severity_at`/`confidence_at` at the
    FIRST call's values. A second call in the same run with a changed
    severity must not leave the row half-updated -- one row is one answer,
    and all five fields move together or none do."""
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_observation(engagement_conn, finding_id=fid, run_id="r-1",
                               observed=True, exchange_id="x-1",
                               severity_at="Low", confidence_at="Firm",
                               at_us=1)
    records.record_observation(engagement_conn, finding_id=fid, run_id="r-1",
                               observed=True, exchange_id="x-2",
                               severity_at="Critical", confidence_at="Certain",
                               at_us=2)
    row = engagement_conn.execute(
        "SELECT severity_at, confidence_at FROM finding_observation").fetchone()
    assert row == ("Critical", "Certain")


def test_record_evidence_still_defaults_to_proof_and_can_be_told_otherwise(
        engagement_conn):
    """The default keeps every check-runner call site unchanged; the parameter
    is what `evidence.attach` needs. Both, or neither is safe."""
    c = base.Candidate(title="t", issue_type_id="t-issue", severity="Low",
                       confidence="Firm", insertion=None,
                       exchange_ids=("x-1", "x-2"))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-1",), at_us=1)
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-2",), at_us=2,
                            role="baseline", note="unauthenticated control")
    rows = engagement_conn.execute(
        "SELECT role, note FROM evidence WHERE finding_id=? ORDER BY seq",
        (fid,)).fetchall()
    assert rows == [("proof", None), ("baseline", "unauthenticated control")]
