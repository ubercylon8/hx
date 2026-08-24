import pathlib
import re
import sqlite3
from importlib import resources

import pytest

from hx import engagement as engagement_mod
from hx.store import db as db_mod
from hx.store import records

# Every class the extension may put on an `error` frame -- DERIVED from the
# emit sites, not transcribed from S6.
#
# It was transcribed, and it drifted twice in the same direction. `halted` was
# emitted by three sites and named in no list at all, and was pinned here with
# a comment saying so -- a spec fix recorded as a test comment, which is the
# thing dfc2080 was written to stop. `unknown_frame` was worse: emitted by
# BridgeClient's `default ->` arm, in neither S6 nor
# docs/bridge-protocol.md, and in NONE of DENIAL_KIND, EXCHANGE_OUTCOME or
# UNRECORDABLE -- so test_every_error_class_has_somewhere_to_go passed while an
# emittable class had nowhere to go. A hand-maintained list cannot catch a
# class nobody thought to add to it; that is the definition of the failure.
#
# Both are in S6 and in the protocol doc now, and this set is read off the
# code. The regexes below match the emit spellings this tree actually uses. A
# class emitted through a spelling they do not know drops OUT of the derived
# set, which turns the equality tests below red rather than passing quietly --
# see test_the_class_set_really_was_derived_and_is_not_a_narrowed_scan.
_EMIT_PATTERNS = (
    # Java: BridgeClient.error(f, "class", ...) and Sender.error(id, "class", ...)
    r'\berror\(\s*\w+\s*,\s*"([a-z_]+)"',
    # Java: Policy / Limits denials
    r'\bDecision\.deny\(\s*"([a-z_]+)"',
    # Python: BridgeError(..., error_class="class")
    r"""\berror_class\s*=\s*["']([a-z_]+)["']""",
)


def _emitted_error_classes() -> set[str]:
    """Scan BOTH implementations for the classes they can put on the wire."""
    root = pathlib.Path(__file__).resolve().parents[1]
    found: set[str] = set()
    for tree in (root / "extension" / "src", root / "src" / "hx"):
        assert tree.is_dir(), tree
        for path in sorted(tree.rglob("*")):
            if path.suffix not in (".java", ".py"):
                continue
            text = path.read_text(encoding="utf-8")
            for pattern in _EMIT_PATTERNS:
                found.update(re.findall(pattern, text))
    # `rate_limited` has its own constructor rather than Decision.deny,
    # because it is the one class carrying retry_after_us (S6). Named here
    # rather than given a fourth regex for a single site -- and the site is
    # asserted, so this line cannot outlive it.
    limiter = root / "extension" / "src" / "hx" / "policy" / "Limiter.java"
    assert "Decision.rateLimited(" in limiter.read_text(encoding="utf-8"), (
        "rate_limited is added by hand because Limiter uses "
        "Decision.rateLimited(); that call is gone, so re-derive it properly")
    found.add("rate_limited")
    return found


ERROR_CLASSES = frozenset(_emitted_error_classes())


@pytest.fixture
def conn(tmp_path):
    c = db_mod.connect(tmp_path / "hx.db")
    db_mod.init_schema(c)
    c.execute("INSERT INTO engagement(id, name, client, created_us, status)"
              " VALUES('e-1','Example','Example Ltd',1,'active')")
    c.execute("INSERT INTO run(id, engagement_id, kind, safety_profile,"
              " started_us, status)"
              " VALUES('r-1','e-1','manual','production',1700000000000000,'running')")
    yield c
    c.close()


def test_a_denial_row_says_what_was_refused_and_why(conn):
    row_id = records.record_denial(
        conn, run_id="r-1", kind="dangerous",
        method="POST", url="https://app.example.test/account/delete",
        detail="path matches dangerous.path /account/delete",
        at_us=1700000000000042)
    assert re.fullmatch(r"d-[0-9a-f]{12}", row_id)
    row = conn.execute("SELECT * FROM denial WHERE id=?", (row_id,)).fetchone()
    assert row["run_id"] == "r-1"
    assert row["ts_us"] == 1700000000000042
    assert row["kind"] == "dangerous"
    assert row["method"] == "POST"
    assert row["url"] == "https://app.example.test/account/delete"
    assert row["reason"] == "path matches dangerous.path /account/delete"


def test_every_mapped_error_class_is_a_kind_the_schema_accepts(conn):
    for error_class, kind in records.DENIAL_KIND.items():
        records.record_denial(conn, run_id="r-1", kind=kind, method="GET",
                              url="https://app.example.test/api/orders",
                              detail=error_class, at_us=1)
    assert conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == \
        len(records.DENIAL_KIND)


def test_the_protocol_doc_lists_exactly_the_classes_the_code_emits():
    """The drift this whole item is about, made a test instead of a habit.

    `halted` was emitted by three sites and named in neither S6 nor
    docs/bridge-protocol.md; `unknown_frame` was emitted by one and named in
    neither, AND in none of the store's three routing tables. Both were found
    by a human reading the code against the document, which is not a control.

    So the document is compared to the emit sites. ERROR_CLASSES is derived
    from the code (see _emitted_error_classes) and this reads the doc's own
    list, so the two sides of the comparison have independent sources -- which
    is the property the hand-maintained version lacked.
    """
    doc = (pathlib.Path(__file__).resolve().parents[1]
           / "docs" / "bridge-protocol.md").read_text(encoding="utf-8")
    body = doc.split("`class` is one of:", 1)[1]
    listed = set()
    for line in body.splitlines()[1:]:
        if not line.strip():
            continue
        if not line.startswith("    "):
            break
        # A NAME line starts at exactly four spaces and is followed by its
        # description; the description's continuation lines are indented to
        # line up under it, and must not be read as names.
        entry = re.fullmatch(r"    ([a-z_]+)\s+\S.*", line)
        if entry:
            listed.add(entry.group(1))
    assert listed == set(ERROR_CLASSES), (
        f"only in the doc: {sorted(listed - set(ERROR_CLASSES))}; "
        f"only in the code: {sorted(set(ERROR_CLASSES) - listed)}")


def test_the_class_set_really_was_derived_and_is_not_a_narrowed_scan():
    """A regex that stopped matching would shrink ERROR_CLASSES quietly, and
    every set-equality test here would then be comparing two small sets.

    The floor is the count the code emits today, and the classes a scan that
    lost its Java arm or its Python arm would drop first are named
    individually: `unknown_frame` has a single Java site, `bridge_lost` is
    mostly Python, and `rate_limited` is the one added by hand.
    """
    assert len(ERROR_CLASSES) == 16, sorted(ERROR_CLASSES)
    for expected in ("halted", "unknown_frame", "bridge_lost", "rate_limited",
                     "scope_denied", "not_configured"):
        assert expected in ERROR_CLASSES, (
            f"{expected!r} is emitted by this tree and the scan did not find "
            "it; a spelling changed and the derivation went narrow silently")


def test_every_error_class_has_somewhere_to_go():
    """A new error class with no row to go in is a silent denial, and S4 says
    denials are never silent. This fails the moment one is added without
    deciding where it lands -- including into records.UNRECORDABLE, which is
    the honest answer for the seven that Plan 1's schema has no vocabulary
    for."""
    accounted = (set(records.DENIAL_KIND) | set(records.EXCHANGE_OUTCOME)
                 | set(records.UNRECORDABLE))
    assert accounted == ERROR_CLASSES


def test_the_two_maps_overlap_exactly_where_the_precedence_note_says(conn):
    """`scope_denied` and `rate_limited` are in BOTH maps and nothing said
    which wins -- not a test, not even a true comment.

    Both come out of Policy.decide, which Sender.issue calls BEFORE
    http.send: S4's pinned order (not_configured -> halted -> scope_denied ->
    method_denied -> dangerous_denied -> rate_limited -> budget_exhausted) is
    settled while the request is still inside the JVM. So both are denials,
    and mapping either through EXCHANGE_OUTCOME writes a `via='send'` row for
    a request that was never sent -- over-counting requests_issued and every
    coverage number derived from it.

    A third class landing in both maps has to come here and be decided.
    """
    assert set(records.DENIAL_KIND) & set(records.EXCHANGE_OUTCOME) == \
        records.PRE_ISSUANCE
    for error_class in sorted(records.PRE_ISSUANCE):
        records.record_denial(conn, run_id="r-1",
                              kind=records.DENIAL_KIND[error_class],
                              method="GET",
                              url="https://app.example.test/api/orders",
                              detail=error_class, at_us=1)
    assert conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == \
        len(records.PRE_ISSUANCE)
    assert conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0, (
        "a request refused before issuance has no exchange row; one written "
        "here is a request the report would claim was sent"
    )


def test_the_two_classes_that_are_not_pre_issuance_are_not_post_issuance_either():
    """This test used to say "only these two ever did [leave the JVM]", and
    that was the false half of the same comment a second time.

    Neither `timeout` nor `bridge_lost` says whether the request was issued.
    MEASURED, driving the real Sender with an Http that counts its calls:

        E1  past-deadline AND out-of-scope  ->  class=timeout  http.calls=0
            detail: deadline passed 1000us before this frame was decided;
                    not issued
        E2  deadline expired MID-FLIGHT     ->  class=timeout  http.calls=1
            detail: response arrived 1000us after the deadline

    and `server._send` raises `bridge_lost` when `self._conn is None`, with
    nothing written to any socket because there is no socket. So the two
    classes EXCHANGE_OUTCOME names beyond PRE_ISSUANCE are exactly the two
    that cannot be routed from their class -- which is what row_for() is for.
    """
    assert set(records.EXCHANGE_OUTCOME) - records.PRE_ISSUANCE == \
        records.AMBIGUOUS_ISSUANCE
    assert records.AMBIGUOUS_ISSUANCE == {"timeout", "bridge_lost"}
    assert not (records.AMBIGUOUS_ISSUANCE & records.PRE_ISSUANCE), (
        "a class cannot be both settled-before-issuance and unknowable")


def test_an_ambiguous_class_will_not_be_routed_without_being_told():
    """The refusal itself. A default here is the module guessing, and the
    guess a caller who had not thought about it would get is the one that
    inflates requests_issued."""
    for error_class in sorted(records.AMBIGUOUS_ISSUANCE):
        with pytest.raises(ValueError, match="cannot be routed from the class"):
            records.row_for(error_class)


def test_a_never_issued_request_gets_no_exchange_row():
    """S4's harm, closed. Plan 4 following EXCHANGE_OUTCOME writes a
    `via='send'` exchange row for a request that never left the JVM;
    `requests_issued` and every coverage number derived from it are then
    inflated -- a report claiming reach the run never had."""
    assert records.row_for("timeout", issued=False) is None
    assert records.row_for("bridge_lost", issued=False) is None
    # ...and the legitimate row is not lost with it. A response that arrived
    # after the deadline is an exchange; something answered.
    assert records.row_for("timeout", issued=True) == ("exchange", "timeout")
    assert records.row_for("bridge_lost", issued=True) == \
        ("exchange", "bridge_lost")


def test_row_for_gets_the_precedence_right_where_reading_a_map_would_not():
    """The two classes in BOTH maps are denials. Reading EXCHANGE_OUTCOME
    directly answers "exchange" for them, which is the harm above by a
    different route."""
    for error_class in sorted(records.PRE_ISSUANCE):
        assert records.row_for(error_class) == \
            ("denial", records.DENIAL_KIND[error_class])
        assert error_class in records.EXCHANGE_OUTCOME, (
            "the premise of this test is that the map would say otherwise")


def test_row_for_has_an_answer_for_every_error_class():
    """The same guarantee test_every_error_class_has_somewhere_to_go makes
    about the three sets, made about the function callers actually use."""
    for error_class in sorted(ERROR_CLASSES):
        kwargs = {"issued": True} if error_class in records.AMBIGUOUS_ISSUANCE else {}
        records.row_for(error_class, **kwargs)     # must not raise
    with pytest.raises(ValueError, match="not an error class"):
        records.row_for("no_such_class")


def test_the_extension_fault_marker_is_the_same_string_on_both_sides():
    """`not_configured` is overloaded and only the detail separates the two
    readings, so the marker is a wire contract between two languages.

    A prefix each side spells for itself is a prefix that drifts, and the
    failure is silent in the worst direction: a Python side testing for
    "extension fault: " against a Java side emitting "extension-fault: " sees
    every crashed send path as an unauthorised run, which is precisely the
    confusion the marker was added to end.
    """
    java = (pathlib.Path(__file__).resolve().parents[1]
            / "extension" / "src" / "hx" / "bridge" / "BridgeClient.java")
    assert java.is_file(), java
    declarations = re.findall(
        r'public static final String EXTENSION_FAULT = "([^"]*)";', java.read_text())
    assert declarations == [records.EXTENSION_FAULT], (
        f"BridgeClient.java declares {declarations!r}; "
        f"records.EXTENSION_FAULT is {records.EXTENSION_FAULT!r}")
    # ...and it is actually USED at the two sites that mean "this jar is
    # broken", rather than declared and forgotten.
    assert java.read_text().count("EXTENSION_FAULT +") == 2


def test_a_kind_outside_the_vocabulary_is_refused_before_sqlite_sees_it(conn):
    with pytest.raises(ValueError, match="not a denial kind"):
        records.record_denial(conn, run_id="r-1", kind="unmanaged_credential",
                              method="GET", url="https://app.example.test/api/orders",
                              detail="Authorization header we did not inject",
                              at_us=1)
    assert conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == 0


def test_a_denial_against_an_unknown_run_is_refused_by_the_foreign_key(conn):
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        records.record_denial(conn, run_id="r-does-not-exist", kind="scope",
                              method="GET", url="https://elsewhere.example.test/",
                              detail="host not in scope", at_us=1)


def test_a_denial_with_no_run_is_allowed(conn):
    """not_configured happens at 02:00 before any run exists, and that denial
    is exactly the one worth having."""
    row_id = records.record_denial(conn, run_id=None, kind="not_configured",
                                   method="GET", url="https://app.example.test/",
                                   detail="no configure frame acknowledged yet",
                                   at_us=1)
    assert conn.execute("SELECT run_id FROM denial WHERE id=?",
                        (row_id,)).fetchone()["run_id"] is None


def test_an_exchange_row_records_the_pair_and_derives_recv_us(conn):
    row_id = records.record_exchange(
        conn, run_id="r-1", method="GET",
        url="https://app.example.test/api/orders?page=2", status=200,
        req_blob="a" * 64, resp_blob="b" * 64, ms=42,
        at_us=1700000000000000, resp_len=1312)
    assert re.fullmatch(r"x-[0-9a-f]{12}", row_id)
    row = conn.execute("SELECT * FROM exchange WHERE id=?", (row_id,)).fetchone()
    assert row["via"] == "send"
    assert row["outcome"] == "ok"
    assert row["status"] == 200
    assert row["sent_us"] == 1700000000000000
    assert row["recv_us"] == 1700000000042000
    assert row["resp_len"] == 1312
    assert row["body_shed"] == 0


def test_a_solicited_exchange_is_never_shed(conn):
    """S6: solicited exchanges are never shed -- they are about to become
    evidence. Only unsolicited proxy observations may set body_shed."""
    for outcome in ("ok", "timeout", "bridge_lost"):
        records.record_exchange(conn, run_id="r-1", method="GET",
                                url="https://app.example.test/api/orders",
                                status=200 if outcome == "ok" else None,
                                req_blob="a" * 64, resp_blob=None, ms=1,
                                at_us=1, outcome=outcome)
    assert conn.execute("SELECT COUNT(*) FROM exchange WHERE body_shed != 0"
                        ).fetchone()[0] == 0


def test_an_outcome_outside_the_vocabulary_is_refused(conn):
    with pytest.raises(ValueError, match="not an exchange outcome"):
        records.record_exchange(conn, run_id="r-1", method="GET",
                                url="https://app.example.test/api/orders",
                                status=None, req_blob=None, resp_blob=None,
                                ms=0, at_us=1, outcome="transport_error")


def test_an_ok_exchange_with_no_status_is_refused(conn):
    with pytest.raises(ValueError, match="no status"):
        records.record_exchange(conn, run_id="r-1", method="GET",
                                url="https://app.example.test/api/orders",
                                status=None, req_blob="a" * 64, resp_blob=None,
                                ms=7, at_us=1)


# The status each outcome may legally carry. A table rather than a
# conditional expression, so a new outcome forces a decision here instead of
# inheriting whichever branch it happens to fall into. The previous version of
# the test below wrote `599` for every outcome except `ok` -- which meant this
# module's own fixture was writing `outcome='conn_refused', status=599` rows:
# the very pairing S5 forbids, exercised in violation by the test that was
# supposed to be checking the vocabulary.
LEGAL_STATUS = {
    "ok": 200,
    "truncated": 200,           # the response arrived; it was cut short
    "status_unreadable": 599,   # S5's conservative sentinel, and only that
    "scope_denied": None,       # refused before issuance; nothing answered
    "rate_limited": None,
    "timeout": None,            # S5: a transport failure has no HTTP status
    "conn_refused": None,
    "dns_error": None,
    "tls_error": None,
    "bridge_lost": None,
}


def test_every_outcome_this_module_accepts_is_one_the_schema_accepts(conn):
    """The ValueError above is redundant with a CHECK constraint only while
    the two vocabularies agree. They stopped agreeing once the extension
    started emitting `status_unreadable`: records.py would have let it through
    and SQLite would have refused the row, on exactly the exchange the field
    was added to make legible. This drives every value rather than reading
    them."""
    assert set(LEGAL_STATUS) == records.EXCHANGE_OUTCOMES, (
        "a new outcome needs a decision about the status it may carry before "
        "this test can drive it through an INSERT"
    )
    for outcome in sorted(records.EXCHANGE_OUTCOMES):
        records.record_exchange(conn, run_id="r-1", method="GET",
                                url="https://app.example.test/api/orders",
                                status=LEGAL_STATUS[outcome],
                                req_blob="a" * 64, resp_blob=None, ms=1,
                                at_us=1, outcome=outcome)
    assert conn.execute("SELECT COUNT(DISTINCT outcome) FROM exchange"
                        ).fetchone()[0] == len(records.EXCHANGE_OUTCOMES)


def test_the_module_and_the_schema_agree_on_the_outcome_vocabulary():
    """The other direction, which no INSERT can reach: a value SQLite would
    accept that record_exchange refuses is unreachable evidence, and the
    caller sees a ValueError naming a vocabulary that is not the real one."""
    sql = resources.files("hx.store").joinpath("schema.sql").read_text(
        encoding="utf-8")
    m = re.search(
        r"CREATE TABLE IF NOT EXISTS exchange\b.*?"
        r"\boutcome\s+TEXT NOT NULL\s*CHECK \(outcome IN \((.*?)\)\)",
        sql, re.S)
    assert m is not None, (
        "the exchange.outcome CHECK is no longer where this guard looks for "
        "it; without this assertion the comparison below would pass vacuously"
    )
    assert set(re.findall(r"'([a-z_]+)'", m.group(1))) == \
        records.EXCHANGE_OUTCOMES


# Outcomes that mean nothing on the far side ever answered with a status.
# Spelled out here rather than imported from records, so that dropping a value
# from the module's own set narrows the guard AND fails this file, instead of
# narrowing it silently.
NO_STATUS = ("timeout", "conn_refused", "dns_error", "tls_error", "bridge_lost")


@pytest.mark.parametrize("outcome", NO_STATUS)
def test_a_transport_failure_that_also_carries_a_status_is_refused(conn, outcome):
    """S5: "a transport failure has no HTTP status".

    A row saying both "the connection was refused" and "the peer answered 200"
    is not a fact about anything, and it is a check's input later. This module
    had exactly one coherence guard -- `ok` with no status -- and the converse
    was unguarded in both directions.
    """
    with pytest.raises(ValueError, match="has no HTTP status"):
        records.record_exchange(conn, run_id="r-1", method="GET",
                                url="https://app.example.test/api/orders",
                                status=200, req_blob="a" * 64, resp_blob=None,
                                ms=1, at_us=1, outcome=outcome)
    assert conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0


def test_the_statusless_outcomes_are_outcomes_this_module_accepts():
    """A guard keyed on a value the vocabulary does not contain is a guard
    that can never fire, and reads in review exactly like one that does."""
    assert records.NO_STATUS_OUTCOMES == frozenset(NO_STATUS)
    assert records.NO_STATUS_OUTCOMES <= records.EXCHANGE_OUTCOMES


@pytest.mark.parametrize("status", [200, 404, 500, 598, 600, None])
def test_status_unreadable_without_its_599_sentinel_is_refused(conn, status):
    """The pairing this task was the deliberate verification for.

    S5 is explicit that `status` HOLDS 599 for `status_unreadable` "so S4's
    auto-halt counts it as an error rather than a healthy sample", and that
    the outcome is the only thing separating that sentinel from a peer that
    genuinely answered 599.

    The extension pairs them by construction -- Sender.STATUS_UNREADABLE is
    599 -- so nothing writes a bad row today. But record_exchange is the
    SINGLE place that pairing reaches disk, and a later caller writing
    `status=reply.get("status", 200)` would file an unreadable status as a
    healthy 200 sample: the exact reading the amendment exists to prevent,
    with the store's blessing and no test to notice.
    """
    with pytest.raises(ValueError, match="599"):
        records.record_exchange(conn, run_id="r-1", method="GET",
                                url="https://app.example.test/api/orders",
                                status=status, req_blob="a" * 64,
                                resp_blob="b" * 64, ms=42, at_us=1,
                                outcome="status_unreadable")
    assert conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0


def test_a_status_unreadable_exchange_keeps_its_599_and_stays_distinguishable(conn):
    """The wire value and the column value are deliberately the same string,
    so this is a pass-through with no mapping layer to get wrong.

    S6: `status` stays 599 because the conservative reading is what makes S4's
    auto-halt count an unreadable status as an error rather than a healthy
    sample. `outcome` is the only thing separating that sentinel from a peer
    that genuinely answered 599 -- which is why both rows below exist."""
    unreadable = records.record_exchange(
        conn, run_id="r-1", method="GET",
        url="https://app.example.test/api/orders", status=599,
        req_blob="a" * 64, resp_blob="b" * 64, ms=42, at_us=1,
        outcome="status_unreadable", resp_len=13)
    genuine = records.record_exchange(
        conn, run_id="r-1", method="GET",
        url="https://app.example.test/api/slow", status=599,
        req_blob="a" * 64, resp_blob="c" * 64, ms=42, at_us=1,
        outcome="ok", resp_len=13)

    rows = {r["id"]: r["outcome"] for r in conn.execute(
        "SELECT id, outcome FROM exchange WHERE status=599")}
    assert rows == {unreadable: "status_unreadable", genuine: "ok"}


def test_a_halted_run_is_aborted_once_and_keeps_the_first_reason(conn):
    assert records.abort_run(
        conn, run_id="r-1",
        stop_reason="5xx rate 0.40 on app.example.test (50 requests / 37s)",
        at_us=1700000000900000) is True
    row = conn.execute("SELECT status, stop_reason, ended_us FROM run"
                       " WHERE id='r-1'").fetchone()
    assert row["status"] == "aborted"
    assert row["stop_reason"].startswith("5xx rate 0.40")
    assert row["ended_us"] == 1700000000900000

    assert records.abort_run(conn, run_id="r-1",
                             stop_reason="5 consecutive connection errors",
                             at_us=1700000001000000) is False
    assert conn.execute("SELECT stop_reason FROM run WHERE id='r-1'"
                        ).fetchone()["stop_reason"].startswith("5xx rate 0.40")


def test_aborting_a_run_that_is_not_in_this_store_is_an_error(conn):
    with pytest.raises(ValueError, match="no run"):
        records.abort_run(conn, run_id="r-nope", stop_reason="x", at_us=1)


def test_ids_have_the_shape_the_rest_of_the_store_uses():
    """`hx.engagement._new_id` is this function's twin. They are not one
    function yet -- engagement.py belongs to Plan 1 and collapsing them is a
    refactor with its own test surface -- so this pins the shape rather than
    letting the two drift apart unnoticed."""
    assert re.fullmatch(r"d-[0-9a-f]{12}", records.new_id("d"))
    assert re.fullmatch(r"d-[0-9a-f]{12}", engagement_mod._new_id("d"))
    assert len({records.new_id("d") for _ in range(1000)}) == 1000
