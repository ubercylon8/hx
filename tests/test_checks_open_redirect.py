"""`hx.checks.active.open_redirect`.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures -- see `tests/test_checks_cors.py`'s own note,
which this file follows. `_FakeSender` below is the `probe.ProbeSender`
-shaped double for `probes()`'s fourth argument, adapted from
`test_checks_cors.py`'s to answer with a STATUS as well as headers (this
check reads both) and to hand back a *sequence* of responses, one per call,
because unlike CORS this check can issue more than one request per surface
-- one per canary-shaped query parameter.

NO JVM AND NO SOCKET. `OpenRedirect` is driven directly with a fake sender;
the real Burp path is Task 13's (`tests/integration/`).
"""
from __future__ import annotations

import pytest

from hx.checks import base, probe
from hx.checks.active import open_redirect as oredir


def _head(headers: dict[str, str]) -> bytes:
    lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return f"HTTP/1.1 200 OK\r\n{lines}".encode("latin-1")


class _FakeSender:
    """A `ProbeSender`-shaped double.

    `responses` is a list of `(status, headers)` pairs, or a single
    `Exception` to raise on the first call. Calls beyond the list re-answer
    with the last entry -- convenient for tests that only care about the
    first response a canary-shaped parameter draws.
    """

    def __init__(self, *, responses: list[tuple[int, dict[str, str]]] | None = None,
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
        status, hdrs = self._responses[idx]
        return probe.ProbeResponse(status=status, head=_head(hdrs), body=b"",
                                   outcome="ok")


def _sender_returning(status: int, headers: dict[str, str]) -> _FakeSender:
    return _FakeSender(responses=[(status, headers)])


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
surface = ("s-1", "GET", "https", "app.test", 443, "/go", "x-1")

_REDIRECT_INSERTION = base.Insertion("query", "redirect_uri")
_UNRELATED_INSERTION = base.Insertion("query", "id")

_MARKER_LOCATION = f"https://{oredir._MARKER_HOST}/steal"


# ---- the five sketched cases ---------------------------------------------


def test_a_location_pointing_at_the_marker_host_is_a_finding():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": _MARKER_LOCATION}))
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == oredir._ISSUE_TYPE
    assert v.candidates[0].insertion == _REDIRECT_INSERTION


def test_a_location_that_keeps_the_targets_host_is_clean():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": "https://app.test/dashboard"}))
    assert v.state == "clean"
    assert v.considered == (oredir._ISSUE_TYPE,), (
        "the parameter WAS probed, so the issue type must be considered or "
        "a later fix can never be seen as retiring anything")


def test_a_relative_location_is_not_an_open_redirect():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": "/dashboard"}))
    assert v.state == "clean"


def test_the_check_never_requests_the_location_it_was_given():
    """The safety property. The sender saw exactly the probe request and
    never a second one aimed at the redirect target -- there is no route in
    this check from a response it received to a new `sender.get()` call."""
    sender = _sender_returning(302, {"Location": _MARKER_LOCATION})
    v = oredir.OpenRedirect().probes(ctx, surface, (_REDIRECT_INSERTION,),
                                     sender)
    assert v.state == "finding"
    assert sender.sent == 1, "a finding must cost exactly the one probe request"
    assert sender.paths == [sender.paths[0]]
    assert _MARKER_LOCATION not in sender.paths[0], (
        "the ONE request sent must be the probe carrying the marker in the "
        "parameter, never a request built from the Location this check read "
        "back")


def test_a_parameter_that_cannot_redirect_is_not_probed():
    """Budget: canary-first means not every query parameter earns a
    request."""
    sender = _sender_returning(200, {})
    v = oredir.OpenRedirect().probes(ctx, surface, (_UNRELATED_INSERTION,),
                                     sender)
    assert sender.sent == 0
    assert v.state == "clean"
    assert v.considered == (), (
        "nothing was actually examined on this surface, so nothing may be "
        "considered -- naming the issue type here would let a real, "
        "never-tested finding be silently retired"
    )


# ---- refusal and budget ---------------------------------------------------


def test_a_refusal_propagates_rather_than_becoming_a_verdict():
    """`ProbeSender.get()` RAISES `ProbeRefused` on every refusal and never
    returns one (see `hx/checks/probe.py`); catching it here and answering
    `inconclusive` (or worse, `clean`) would be this check doing the
    runner's job. `hx.scan.run`'s `except ProbeRefused` is what turns this
    into `inconclusive`, exercised end to end by
    `tests/test_scan_probes.py::test_a_refusal_becomes_inconclusive_never_clean`."""
    sender = _sender_raising(probe.ProbeRefused("rate_limited"))
    with pytest.raises(probe.ProbeRefused) as exc:
        oredir.OpenRedirect().probes(ctx, surface, (_REDIRECT_INSERTION,),
                                     sender)
    assert exc.value.reason == "rate_limited"


def test_a_refused_attempt_still_spent_the_budget():
    sender = _sender_raising(probe.ProbeRefused("budget_exhausted"))
    with pytest.raises(probe.ProbeRefused):
        oredir.OpenRedirect().probes(ctx, surface, (_REDIRECT_INSERTION,),
                                     sender)
    assert sender.sent == 1


def test_only_canary_shaped_parameters_are_probed_others_are_skipped():
    """A mix of a redirect-shaped and an unrelated parameter: only the
    former costs a request."""
    sender = _sender_returning(200, {})
    oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION, _UNRELATED_INSERTION), sender)
    assert sender.sent == 1
    assert "redirect_uri" in sender.paths[0]
    assert "id=" not in sender.paths[0]


# ---- non-redirect statuses -------------------------------------------------


def test_a_200_with_a_location_header_is_not_a_redirect():
    """A `Location` only means anything on a 3xx status (RFC 9110 s10.2.2);
    reading it off a 200 answers a question the response was not asking."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(200, {"Location": _MARKER_LOCATION}))
    assert v.state == "clean"


def test_a_redirect_with_no_location_at_all_is_clean():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,), _sender_returning(302, {}))
    assert v.state == "clean"


def test_a_protocol_relative_location_at_the_marker_host_is_a_finding():
    """`//host/path` is a real redirect shape some servers emit, not merely
    a relative one -- `urlsplit` resolves its host the same as an absolute
    URL would."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": f"//{oredir._MARKER_HOST}/x"}))
    assert v.state == "finding"


# ---- the shape of the check itself ----------------------------------------


def test_the_check_is_wired_for_the_registry():
    c = oredir.OpenRedirect()
    assert c.id == "hx.active.open-redirect"
    assert c.klass == "active_safe"
    assert c.insertion_kinds == frozenset({"query"})


def test_only_query_insertions_are_considered_others_are_ignored():
    """`insertion_kinds` is `{"query"}`; a non-query insertion reaching
    `probes()` (which should not happen given `scan.run`'s own filter, but
    this check must not assume it) is simply skipped, not probed."""
    header_insertion = base.Insertion("header", "redirect")
    sender = _sender_returning(200, {})
    v = oredir.OpenRedirect().probes(ctx, surface, (header_insertion,), sender)
    assert sender.sent == 0
    assert v.state == "clean"
    assert v.considered == ()


def test_the_probe_carries_the_marker_url_in_the_parameter():
    sender = _sender_returning(200, {})
    oredir.OpenRedirect().probes(ctx, surface, (_REDIRECT_INSERTION,), sender)
    assert oredir._MARKER_HOST in sender.paths[0]
    # .test is reserved by RFC 2606 for exactly this: a value guaranteed
    # never to be a real, resolvable production target.
    assert oredir._MARKER_HOST.endswith(".test")


def test_a_finding_names_the_insertion_it_came_from():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": _MARKER_LOCATION}))
    assert v.candidates[0].insertion == _REDIRECT_INSERTION


def test_the_finding_cites_the_surfaces_exemplar_exchange():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": _MARKER_LOCATION}))
    assert v.candidates[0].exchange_ids == ("x-1",)


def test_a_findings_issue_type_is_one_it_considered():
    """The drift-catching test this whole suite of checks carries: a
    candidate whose issue type is not in `considered` can never be
    retired."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": _MARKER_LOCATION}))
    assert v.state == "finding"
    for candidate in v.candidates:
        assert candidate.issue_type_id in v.considered


def test_two_canary_shaped_parameters_that_both_redirect_are_two_findings():
    """Two parameters, independently redirecting, must not collapse into
    one row -- `records.dedupe_key` distinguishes them by
    `candidate.insertion`, and this check must actually set it."""
    other = base.Insertion("query", "next")
    sender = _FakeSender(responses=[
        (302, {"Location": _MARKER_LOCATION}),
        (302, {"Location": _MARKER_LOCATION}),
    ])
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION, other), sender)
    assert v.state == "finding"
    assert len(v.candidates) == 2
    assert {c.insertion for c in v.candidates} == {_REDIRECT_INSERTION, other}
