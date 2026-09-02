"""`hx.checks.active.sql_behaviour`.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures -- see `tests/test_checks_cors.py`'s own note.
`_FakeSender` is the `probe.ProbeSender`-shaped double, taken from
`test_checks_sql_error.py`'s, because this check reads the same
`(status, head, body)` triple. It differs in one way that matters: this
check sends TWO probes per insertion point and reasons about the difference
between them, so the double must be able to answer differently on the first
and second call rather than repeating one response.

NO JVM AND NO SOCKET. `SqlBehaviour` is driven directly with a fake sender.

WHY THIS CHECK EXISTS, measured on 2026-09-02 against OWASP Juice Shop:
`hx.active.sql-error` probed `q` on `/rest/products/search`, got HTTP 500 --
the injection actually firing -- and recorded `inconclusive`, because that
check reads a SQL error STRING out of the body and `_probe_util.unanswered`
treats a non-2xx as a gap. The whole engagement reported zero findings. This
check reads the DIFFERENCE between two responses instead, so a status change
is its signal rather than its blind spot.
"""
from __future__ import annotations

import pytest

from hx.checks import base, probe
from hx.checks.active import sql_behaviour as sqlb


def _head(status_line: str = "HTTP/1.1 200 OK",
          headers: dict[str, str] | None = None) -> bytes:
    lines = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    return f"{status_line}\r\n{lines}".encode("latin-1")


class _FakeSender:
    """A `ProbeSender`-shaped double that can answer differently per call.

    `responses` is a list of `(status, body)` pairs or `Exception`s, consumed
    in order; calls beyond the list re-answer with the last entry. An entry
    may be an exception so that "the first probe is refused and the second
    answers" is expressible -- the case a single `exc` cannot reach.
    """

    def __init__(self, *, responses=None, path: str = "/items/12345") -> None:
        self.path = path
        self._responses = responses or []
        self.sent = 0
        self.paths: list[str] = []

    def get(self, path, *, headers=None, timeout=30.0):
        self.sent += 1
        self.paths.append(path)
        idx = min(self.sent - 1, len(self._responses) - 1)
        entry = self._responses[idx]
        if isinstance(entry, Exception):
            raise entry
        status, body = entry
        return probe.ProbeResponse(
            status=status,
            head=_head(f"HTTP/1.1 {status} X"),
            body=body, outcome="ok")


def ctx_for():
    return base.CheckContext(config=None, blobs=None, run_id="r-1",
                             log=lambda s: None)


ctx = ctx_for()

# The exact 7-tuple `hx.scan.run` hands to `check.probes`, and the concrete
# address it was templated from -- the pairing `test_checks_sql_error.py`
# documents at length.
surface = ("s-1", "GET", "https", "app.test", 443, "/items/{id}", "x-1")

_QUERY = base.Insertion("query", "id")
_PATH_SEGMENT = base.Insertion("path_segment", "{id}")

_OK_BODY = b"<html>three results for your search, nothing unusual here</html>"
_ERR_BODY = b"<html>Internal Server Error</html>"


def _run(responses, insertions=(_QUERY,), path="/items/12345"):
    sender = _FakeSender(responses=responses, path=path)
    return sqlb.SqlBehaviour().probes(ctx, surface, insertions, sender), sender


# --- the signal -----------------------------------------------------------

def test_a_status_differential_files_one_tentative_candidate():
    """THE JUICE SHOP SHAPE. The unbalanced quote breaks the statement and
    the escaped one does not, so the two answers differ. That is the whole
    signal, and it is deliberately NOT a `Certain` one -- see the honesty
    test below.

    MUTATION: make `_material` return False when only the status changed.
    This test must go red.
    """
    verdict, _ = _run([(500, _ERR_BODY), (200, _OK_BODY)])

    assert verdict.state == "finding"
    assert len(verdict.candidates) == 1
    candidate = verdict.candidates[0]
    assert candidate.severity == "High"
    assert candidate.confidence == "Tentative"
    assert candidate.cwe == "CWE-89"
    assert candidate.insertion == _QUERY


def test_a_body_differential_without_a_status_change_still_files():
    """An application that swallows the error and returns 200 with a
    different body is still telling us the quote reached a parser.

    MUTATION: drop `len_delta` and `new_tokens` from `_material`, leaving
    only `status_changed`. This test must go red.
    """
    verdict, _ = _run([(200, b"<html>error parsing your query oh dear</html>"),
                       (200, _OK_BODY)])

    assert verdict.state == "finding"


def test_two_identical_answers_are_clean():
    """No difference is no signal. `clean` and not `inconclusive`: two probes
    were sent and both answered, so this point WAS examined."""
    verdict, _ = _run([(200, _OK_BODY), (200, _OK_BODY)])

    assert verdict.state == "clean"
    assert sqlb.ISSUE_TYPE in verdict.considered


def test_two_identical_errors_are_a_gap_not_a_finding_and_not_clean():
    """A surface that answers 500 to everything has no differential -- and
    it is NOT `clean` either, which is the half this test originally got
    wrong. An endpoint that refuses every request refuses an unbalanced
    quote and an escaped one alike, so nothing here separates `tested,
    clean` from `never reached`.

    The corpus contract that forced this out:
    `test_scan_probes.py::test_every_probing_check_reads_a_login_wall_as_a_gap`
    drives every active check against a target that 302s everything and
    forbids `clean` from all of them.

    MUTATION: compare the quote probe against a hardcoded 200 instead of
    against the escaped probe -- it would file a finding. Or drop the
    `unanswered` branch -- it would say `clean`. Either must go red.
    """
    verdict, _ = _run([(500, _ERR_BODY), (500, _ERR_BODY)])

    assert verdict.state == "inconclusive"
    assert "refuses every request" in verdict.reason


def test_two_identical_answers_behind_a_login_wall_are_a_gap():
    """The shape the corpus contract actually drives: a 302 to a login page
    for everything. Both probes match, neither answered, nothing was
    learned."""
    verdict, _ = _run([(302, b""), (302, b"")])

    assert verdict.state == "inconclusive"


# --- the inversion this check exists for ----------------------------------

def test_a_non_2xx_on_the_quote_probe_is_data_not_a_gap():
    """THE POINT OF THE WHOLE CHECK, stated as a test.

    `_probe_util.unanswered` reads a 2xx and nothing else as an answer, and
    its five sibling checks are right to use it -- they reason about response
    CONTENT, which a 500 does not give them. This check reasons about the
    DIFFERENCE between two responses, and a status change is the cleanest
    form of that. So the 500 here must reach the comparison rather than being
    recorded as a gap.

    MUTATION: call `_probe_util.unanswered` on either probe and record a gap.
    This test must go red -- it would come back `inconclusive`, which is
    exactly what `sql-error` reported against Juice Shop.
    """
    verdict, _ = _run([(500, _ERR_BODY), (200, _OK_BODY)])

    assert verdict.state == "finding", (
        "a non-2xx must be read as data by this check, not as a gap")
    assert verdict.reason is None


# --- honesty --------------------------------------------------------------

def test_the_description_says_a_validator_produces_the_same_signal():
    """S12 applied to a Tentative finding. A quote differential proves the
    quote reached something that PARSES it -- not that it reached SQL. An
    input validator or WAF that rejects `'` and accepts `''` produces an
    identical signal, and a reader who is not told that will read High
    severity as a confirmed injection.

    MUTATION: delete the validator sentence from `_describe`. Must go red.
    """
    verdict, _ = _run([(500, _ERR_BODY), (200, _OK_BODY)])
    description = verdict.candidates[0].description

    assert "validator" in description.lower() or "waf" in description.lower()
    assert "500" in description and "200" in description
    assert "confirm" in description.lower()


def test_the_finding_carries_the_payload_that_produced_it():
    verdict, _ = _run([(500, _ERR_BODY), (200, _OK_BODY)])

    assert verdict.candidates[0].payload.endswith("'")


# --- gaps: what was not sent was not tested -------------------------------

def test_a_refusal_on_the_first_probe_is_a_gap_not_clean():
    """MUTATION: swallow `ProbeRefused` and continue. Must go red."""
    verdict, _ = _run([probe.ProbeRefused("budget_exhausted"),
                       (200, _OK_BODY)])

    assert verdict.state == "inconclusive"
    assert "budget_exhausted" in verdict.reason


def test_a_refusal_on_the_second_probe_is_also_a_gap():
    """The escaped probe is half the comparison; without it there is nothing
    to compare the quote against, and a lone 500 is not a finding."""
    verdict, _ = _run([(500, _ERR_BODY),
                       probe.ProbeRefused("rate_limited")])

    assert verdict.state == "inconclusive"
    assert "rate_limited" in verdict.reason


def test_a_surface_with_no_probeable_point_is_inconclusive_not_clean():
    """Nothing was sent, so nothing was tested, and that is not `clean` --
    the branch every active check in this corpus carries."""
    verdict, sender = _run([(200, _OK_BODY)],
                           insertions=(base.Insertion("header", "X-Trace"),))

    assert verdict.state == "inconclusive"
    assert sender.sent == 0


# --- probe construction ---------------------------------------------------

def test_both_probes_go_to_the_same_insertion_point():
    _, sender = _run([(500, _ERR_BODY), (200, _OK_BODY)])

    assert sender.sent == 2
    assert all(p.startswith("/items/12345?id=") for p in sender.paths)


def test_a_path_segment_placeholder_is_filled_in():
    _, sender = _run([(500, _ERR_BODY), (200, _OK_BODY)],
                     insertions=(_PATH_SEGMENT,))

    assert sender.sent == 2
    assert all("{id}" not in p for p in sender.paths)


def test_the_two_probes_differ_only_in_the_quote():
    """The escaped probe must be the SAME value with the quote doubled, so
    that shape and length stay comparable. Two unrelated payloads would make
    every length delta meaningless."""
    _, sender = _run([(500, _ERR_BODY), (200, _OK_BODY)])
    first, second = sender.paths

    assert first != second
    assert len(second) == len(first) + len("%27")


@pytest.mark.parametrize("kind", ["cookie", "header", "body_form", "body_json"])
def test_only_query_and_path_segment_points_are_probed(kind):
    """The two body kinds are here deliberately: the extension's default
    method allowlist is GET/HEAD/OPTIONS, so no check in this build can reach
    a request body at all. A check that tried would be refused at the JVM,
    and this asserts it never asks."""
    _, sender = _run([(200, _OK_BODY)],
                     insertions=(base.Insertion(kind, "x"),))

    assert sender.sent == 0
