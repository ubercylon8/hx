"""`hx.checks.active.sql_error`.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures -- see `tests/test_checks_cors.py`'s own note,
which this file follows. `_FakeSender` below is the `probe.ProbeSender`
-shaped double for `probes()`'s fourth argument, adapted from
`test_checks_open_redirect.py`'s: it answers with a fixed `(status, head,
body)` per call (or the last one, for calls beyond what was given), which
is enough here because this check reads a signature out of the body/head it
is handed rather than echoing the request back the way
`test_checks_reflected_input.py`'s fake does.

NO JVM AND NO SOCKET. `SqlError` is driven directly with a fake sender; the
real Burp path is Task 13's (`tests/integration/`).
"""
from __future__ import annotations

import pytest

from hx.checks import base, probe
from hx.checks.active import sql_error as sqle


def _head(headers: dict[str, str] | None = None) -> bytes:
    lines = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    return f"HTTP/1.1 500 Internal Server Error\r\n{lines}".encode("latin-1")


class _FakeSender:
    """A `ProbeSender`-shaped double.

    `responses` is a list of `(status, head_headers, body)` triples, or a
    single `Exception` to raise on the first call. Calls beyond the list
    re-answer with the last entry, matching
    `test_checks_open_redirect.py`'s own `_FakeSender`.
    """

    def __init__(self, *,
                responses: list[tuple[int, dict[str, str], bytes]] | None = None,
                exc: Exception | None = None) -> None:
        self._responses = responses or []
        self._exc = exc
        self.sent = 0
        self.paths: list[str] = []

    def get(self, path, *, headers=None, timeout=30.0):
        self.sent += 1          # ATTEMPTS, and deliberately not the real
                                 # sender's rule. `hx.checks.probe` counts
                                 # ISSUANCES -- a refusal the gate decided
                                 # before issuing is not one -- but this
                                 # double's `sent` doubles as its own call
                                 # cursor, and no check ever reads the
                                 # field, so the difference stays inside
                                 # these tests. What the stored number
                                 # means is pinned in tests/test_probe.py.
        self.paths.append(path)
        if self._exc is not None:
            raise self._exc
        idx = min(self.sent - 1, len(self._responses) - 1)
        status, hdrs, body = self._responses[idx]
        return probe.ProbeResponse(status=status, head=_head(hdrs), body=body,
                                   outcome="ok")


def _sender_returning(status: int, body: bytes,
                      headers: dict[str, str] | None = None) -> _FakeSender:
    return _FakeSender(responses=[(status, headers or {}, body)])


def _sender_raising(exc: Exception) -> _FakeSender:
    return _FakeSender(exc=exc)


def ctx_for():
    return base.CheckContext(config=None, blobs=None, run_id="r-1",
                             log=lambda s: None)


ctx = ctx_for()

# (id, method, scheme, host, port, path_template, exemplar_exchange_id) --
# the exact 7-tuple `hx.scan.run` selects and hands to `check.probes` (see
# `scan.py`'s `"SELECT id, method, scheme, host, port, path_template,
# exemplar_exchange_id FROM surface"`).
surface = ("s-1", "GET", "https", "app.test", 443, "/items", "x-1")

_QUERY = base.Insertion("query", "id")
_PATH_SEGMENT = base.Insertion("path_segment", "{id}")

_MYSQL_BODY = b"<html>You have an error in your SQL syntax; check the manual</html>"
_CLEAN_BODY = b"<html>ordinary response, nothing wrong here</html>"


# ---- the five sketched cases -----------------------------------------


def test_a_vendor_signature_in_the_body_is_a_finding():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == sqle._ISSUE_TYPE
    assert v.candidates[0].insertion == _QUERY


def test_a_response_with_no_signature_anywhere_is_clean():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(200, _CLEAN_BODY))
    assert v.state == "clean"
    assert v.considered == (sqle._ISSUE_TYPE,), (
        "the point WAS probed, so the issue type must be considered or a "
        "later fix can never be seen as retiring anything")


def test_a_clean_answer_names_only_what_was_actually_probed():
    sender = _sender_returning(200, _CLEAN_BODY)
    v = sqle.SqlError().probes(ctx, surface, (_QUERY, _PATH_SEGMENT), sender)
    assert sender.sent == 2, "every declared insertion point was examined"
    assert v.considered == (sqle._ISSUE_TYPE,)


def test_no_insertions_probed_means_nothing_considered():
    sender = _sender_returning(200, _CLEAN_BODY)
    v = sqle.SqlError().probes(ctx, surface, (), sender)
    assert sender.sent == 0
    assert v.state == "clean"
    assert v.considered == (), (
        "nothing was examined on this surface, so nothing may be "
        "considered -- naming the issue type here would let a real, "
        "never-tested finding be silently retired")


def test_one_request_per_point_even_with_a_dozen_table_entries():
    """Budget: the signature table has more than a dozen entries; matching
    them all against one response must not cost more than one request."""
    sender = _sender_returning(200, _CLEAN_BODY)
    sqle.SqlError().probes(ctx, surface, (_QUERY, _PATH_SEGMENT), sender)
    assert sender.sent == 2
    assert len(sqle._SIGNATURES) > 10


# ---- honesty: the description reports what matched, not a generic claim --


def test_the_description_names_the_matched_signature_and_vendor():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    description = v.candidates[0].description
    assert "You have an error in your SQL syntax" in description
    assert "MySQL" in description


def test_the_description_names_the_response_body_when_that_is_where_it_matched():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    assert "the response body" in v.candidates[0].description


def test_the_description_names_a_response_header_when_that_is_where_it_matched():
    signature = "SQLSTATE[42000]"
    v = sqle.SqlError().probes(
        ctx, surface, (_QUERY,),
        _sender_returning(500, b"nothing in the body",
                          headers={"X-Db-Error": signature}))
    assert v.state == "finding"
    assert "a response header" in v.candidates[0].description
    assert "the response body" not in v.candidates[0].description


def test_a_different_vendor_signature_names_that_vendor_not_a_generic_one():
    postgres_body = b"org.postgresql.util.PSQLException: ERROR: syntax error"
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, postgres_body))
    description = v.candidates[0].description
    assert "org.postgresql.util.PSQLException" in description
    assert "PostgreSQL" in description
    assert "MySQL" not in description


def test_the_description_does_not_claim_the_query_can_be_manipulated():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    description = v.candidates[0].description.lower()
    assert "not proof that the query can be manipulated" in description
    for overclaim in ("data was extracted", "confirmed exploit",
                      "successfully injected"):
        assert overclaim not in description


# ---- refusal and budget ---------------------------------------------------


def test_a_refusal_propagates_rather_than_becoming_a_verdict():
    sender = _sender_raising(probe.ProbeRefused("rate_limited"))
    with pytest.raises(probe.ProbeRefused) as exc:
        sqle.SqlError().probes(ctx, surface, (_QUERY,), sender)
    assert exc.value.reason == "rate_limited"


def test_a_refused_attempt_still_spent_the_budget():
    sender = _sender_raising(probe.ProbeRefused("budget_exhausted"))
    with pytest.raises(probe.ProbeRefused):
        sqle.SqlError().probes(ctx, surface, (_QUERY,), sender)
    assert sender.sent == 1


# ---- the value sent ---------------------------------------------------


def test_the_probe_value_ends_in_an_unmatched_quote():
    sender = _sender_returning(200, _CLEAN_BODY)
    sqle.SqlError().probes(ctx, surface, (_QUERY,), sender)
    # the query value is percent-encoded on the wire: a literal `'` becomes
    # `%27`.
    assert "%27" in sender.paths[0]


def test_each_insertion_point_gets_its_own_random_prefix():
    sender = _sender_returning(200, _CLEAN_BODY)
    sqle.SqlError().probes(ctx, surface, (_QUERY, _PATH_SEGMENT), sender)
    assert sender.paths[0] != sender.paths[1]


# ---- insertion kinds and identity --------------------------------------


def test_the_check_is_wired_for_the_registry():
    c = sqle.SqlError()
    assert c.id == "hx.active.sql-error"
    assert c.klass == "active_safe"
    assert c.insertion_kinds == frozenset({"query", "path_segment"})


def test_only_declared_insertion_kinds_are_probed_others_are_skipped():
    header_insertion = base.Insertion("header", "X-Id")
    sender = _sender_returning(200, _CLEAN_BODY)
    v = sqle.SqlError().probes(ctx, surface, (header_insertion,), sender)
    assert sender.sent == 0
    assert v.state == "clean"
    assert v.considered == ()


def test_a_finding_names_the_insertion_it_came_from():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    assert v.candidates[0].insertion == _QUERY


def test_the_finding_cites_the_surfaces_exemplar_exchange():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    assert v.candidates[0].exchange_ids == ("x-1",)


def test_a_findings_issue_type_is_one_it_considered():
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    assert v.state == "finding"
    for candidate in v.candidates:
        assert candidate.issue_type_id in v.considered


def test_two_points_that_both_disclose_errors_are_two_findings():
    """Two parameters, independently disclosing errors, must not collapse
    into one row -- `records.dedupe_key` distinguishes them by
    `candidate.insertion`, and this check must actually set it."""
    sender = _FakeSender(responses=[
        (500, {}, _MYSQL_BODY),
        (500, {}, _MYSQL_BODY),
    ])
    v = sqle.SqlError().probes(ctx, surface, (_QUERY, _PATH_SEGMENT), sender)
    assert v.state == "finding"
    assert len(v.candidates) == 2
    assert {c.insertion for c in v.candidates} == {_QUERY, _PATH_SEGMENT}


def test_a_path_segment_placeholder_is_filled_in():
    sender = _sender_returning(200, _CLEAN_BODY)
    sqle.SqlError().probes(ctx, surface, (_PATH_SEGMENT,), sender)
    assert "{id}" not in sender.paths[0]
