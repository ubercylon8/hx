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

from urllib.parse import quote

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

    `path` is what the real `ProbeSender` exposes as its own: the CONCRETE
    path of the surface's exemplar request, which is what a check builds
    every probe out of. It defaults to this file's own `surface`'s
    `path_template` because that surface is not templated -- the two are the
    same string for it -- and the tests that need them to differ pass it
    explicitly.
    """

    def __init__(self, *,
                responses: list[tuple[int, dict[str, str], bytes]] | None = None,
                exc: Exception | None = None,
                path: str = "/items/12345") -> None:
        self.path = path
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
        entry = self._responses[idx]
        if isinstance(entry, Exception):
            # AN ENTRY MAY BE A REFUSAL -- see
            # `test_checks_open_redirect.py`'s own note: `exc` refuses every
            # call, which cannot express "the first point is refused and the
            # second answers".
            raise entry
        status, hdrs, body = entry
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
# TEMPLATED, AND THE SENDER'S DEFAULT `path` IS WHAT IT WAS TEMPLATED FROM.
# This row used to read `/items` while `_PATH_SEGMENT` below named `{id}`,
# so `path_template.replace("{id}", value)` had nothing to replace and
# `test_a_path_segment_placeholder_is_filled_in` asserted `"{id}" not in
# "/items"` -- true of a request that carried no payload at all. A templated
# surface beside the concrete address it came from is what a real scan hands
# this check, and it is the shape F1 hid.
# `/items/12345` is what `hx.surface` templated INTO this row -- `12345` is
# the segment `_DIGITS` matched -- and it is the address `_FakeSender`
# defaults its `path` to.
surface = ("s-1", "GET", "https", "app.test", 443, "/items/{id}", "x-1")

_QUERY = base.Insertion("query", "id")
_PATH_SEGMENT = base.Insertion("path_segment", "{id}")

_MYSQL_BODY = b"<html>You have an error in your SQL syntax; check the manual</html>"
_CLEAN_BODY = b"<html>ordinary response, nothing wrong here</html>"


# ---- the five sketched cases -----------------------------------------


def test_a_vendor_signature_in_the_body_is_a_finding():
    sender = _sender_returning(500, _MYSQL_BODY)
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,), sender)
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == sqle._ISSUE_TYPE
    assert v.candidates[0].insertion == _QUERY
    # F10: the payload as this check MEANT it -- before the percent-encoding
    # that carries it on the request line, and ending in the unmatched quote
    # that is the whole probe. Checked against what actually went out, not
    # only for shape: the value is random per point per run, so this column
    # is the only record of WHICH string was sent.
    payload = v.candidates[0].payload
    assert payload.endswith("'"), payload
    assert quote(payload, safe="") in sender.paths[0]


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
    """N3 of the scoped re-review turned the verdict here from `clean` to
    `inconclusive`. `considered` was already empty, so nothing was ever
    retired on this path -- what was false was the coverage row: `clean`
    asserts "tested and nothing found", and this surface was not tested."""
    sender = _sender_returning(200, _CLEAN_BODY)
    v = sqle.SqlError().probes(ctx, surface, (), sender)
    assert sender.sent == 0
    assert v.state == "inconclusive"
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


def test_a_refusal_ends_one_point_and_never_the_whole_check():
    """F2 of the whole-branch review, in this check's spelling: a refusal on
    one insertion point must not discard the points after it. The query
    parameter is refused; the path segment is still probed and its driver
    error still found."""
    sender = _FakeSender(responses=[
        probe.ProbeRefused("rate_limited"),
        (200, {}, _MYSQL_BODY),
    ])
    v = sqle.SqlError().probes(ctx, surface, (_QUERY, _PATH_SEGMENT), sender)
    assert sender.sent == 2, "the refusal took the second point down with it"
    assert v.state == "finding"
    assert v.candidates[0].insertion == _PATH_SEGMENT
    assert v.considered == (), (
        "one point was never answered, so nothing on this surface may be "
        "retired on the strength of the other")


def test_a_refusal_with_nothing_found_is_inconclusive_never_clean():
    sender = _FakeSender(responses=[probe.ProbeRefused("budget_exhausted")])
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,), sender)
    assert v.state == "inconclusive"
    assert "budget_exhausted" in v.reason
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
    assert v.state == "inconclusive"
    assert v.considered == ()
    for kind in sqle.SqlError.insertion_kinds:
        assert kind in v.reason, kind


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


def test_a_path_segment_probe_replaces_the_addresss_own_segment():
    """RENAMED FROM `test_a_path_segment_placeholder_is_filled_in`, which
    asserted `"{id}" not in sender.paths[0]` against a probe built from a
    template that had no `{id}` in it either -- vacuously true, and true as
    well of the probe this check would send today if `substitute_segment`
    did nothing. The separating assertion is that the ADDRESS's own segment
    is gone: a `str.replace` of the placeholder against a concrete path
    leaves `12345` exactly where it was and sends the exemplar's own request
    back with no payload in it."""
    sender = _sender_returning(200, _CLEAN_BODY)
    sqle.SqlError().probes(ctx, surface, (_PATH_SEGMENT,), sender)
    assert sender.paths[0].startswith("/items/")
    assert "{id}" not in sender.paths[0]
    assert "12345" not in sender.paths[0], sender.paths[0]
    # The quote is what makes it this check's probe rather than any other's.
    assert "%27" in sender.paths[0]


# ---- a refusal from the target is not a clean answer ---------------------
#
# F4 of the whole-branch review. 5xx is in the refusal set AND is where a
# driver error usually arrives, so the ordering inside `probes()` -- match
# first, ask about the status only when nothing matched -- is what these two
# separate.


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_a_status_that_refused_with_no_signature_is_inconclusive(status):
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(status, _CLEAN_BODY))
    assert v.state == "inconclusive"
    assert str(status) in v.reason
    assert v.considered == ()


def test_a_driver_error_on_a_five_hundred_is_still_a_finding():
    """The case that decides the ordering: a database error is
    overwhelmingly disclosed ON a 500, so a doctrine applied before the match
    would turn this check's own finding into a gap."""
    v = sqle.SqlError().probes(ctx, surface, (_QUERY,),
                               _sender_returning(500, _MYSQL_BODY))
    assert v.state == "finding"
    assert v.considered == (sqle._ISSUE_TYPE,)
