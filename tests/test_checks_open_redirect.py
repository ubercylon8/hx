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

    `path` is what the real `ProbeSender` exposes as its own: the CONCRETE
    path of the surface's exemplar request, which is what a check builds
    every probe out of. It defaults to this file's own `surface`'s
    `path_template` because that surface is not templated -- the two are the
    same string for it -- and the tests that need them to differ pass it
    explicitly.
    """

    def __init__(self, *, responses: list[tuple[int, dict[str, str]]] | None = None,
                exc: Exception | None = None, path: str = "/go") -> None:
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
            # AN ENTRY MAY BE A REFUSAL. `exc` above refuses every call,
            # which cannot express "the first point is refused and the
            # second answers" -- the only shape that separates a check that
            # continues past a refusal from one that stops at it.
            raise entry
        status, hdrs = entry
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
# A SECOND redirect-shaped name, so a test can refuse one point and still
# have one this check would probe. `next` is in `_REDIRECT_NAME_HINTS`.
_SECOND_REDIRECT_INSERTION = base.Insertion("query", "next")

_MARKER_LOCATION = f"https://{oredir._MARKER_HOST}/steal"


# ---- the five sketched cases ---------------------------------------------


def test_a_location_pointing_at_the_marker_host_is_a_finding():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": _MARKER_LOCATION}))
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == oredir._ISSUE_TYPE
    assert v.candidates[0].insertion == _REDIRECT_INSERTION
    # F10: `finding.payload` exists and `upsert_finding` writes it; every
    # active check left it NULL until this fix.
    assert v.candidates[0].payload == oredir._MARKER_URL


def test_a_location_that_keeps_the_targets_host_is_not_a_finding():
    """N1 OF THE SCOPED RE-REVIEW CHANGED THE OTHER HALF OF THIS. It is not
    the finding -- the marker is not where the browser is being sent -- and
    it is not `clean` either: the endpoint redirected somewhere this check
    did not ask for, and the response carries nothing that separates "the
    parameter was validated" from "the parameter was never read, this is
    just where unauthenticated requests go". Only the first of those may
    retire a finding, so the honest answer is `inconclusive`."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": "https://app.test/dashboard"}))
    assert v.state == "inconclusive"
    assert v.considered == (), (
        "`Verdict.inconclusive` takes no `considered`, which is what stops a "
        "redirect the check cannot interpret from retiring a live finding")


def test_a_relative_location_is_not_an_open_redirect():
    """Not a finding, and -- same reasoning -- not a clean result: `/login`
    is the commonest relative `Location` a browser-facing application gives
    an unauthenticated probe, and this check sends nothing else."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": "/dashboard"}))
    assert v.state == "inconclusive"


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


def test_a_refusal_ends_one_point_and_never_the_whole_check():
    """F2 of the whole-branch review. `ProbeSender.get()` RAISES on every
    refusal so no check can read one as a response -- but a check that let
    that propagate out of its own loop threw away every insertion point
    after the refused one. The first parameter here is refused and the
    second is probed and found vulnerable; before the fix the exception left
    this method before the second was reached."""
    sender = _FakeSender(responses=[
        probe.ProbeRefused("rate_limited"),
        (302, {"Location": _MARKER_LOCATION}),
    ])
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION, _SECOND_REDIRECT_INSERTION),
        sender)
    assert sender.sent == 2, "the refusal took the second point down with it"
    assert v.state == "finding"
    assert v.candidates[0].insertion == _SECOND_REDIRECT_INSERTION
    assert v.considered == (), (
        "one point was never answered, so this surface's issue type was not "
        "examined and a prior finding of it must not be retired")


def test_a_refusal_with_nothing_found_is_inconclusive_never_clean():
    """The other branch. Nothing was found and one point never answered, so
    `clean` -- which is what a swallowed refusal would produce -- is exactly
    the "tested, clean" S12 forbids for a surface that was never reached."""
    sender = _FakeSender(responses=[probe.ProbeRefused("budget_exhausted")])
    v = oredir.OpenRedirect().probes(ctx, surface, (_REDIRECT_INSERTION,),
                                     sender)
    assert v.state == "inconclusive"
    assert "budget_exhausted" in v.reason
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


def test_a_redirect_with_no_location_at_all_is_not_clean():
    """A 3xx that names nowhere is a response this check cannot read at all,
    which is the plainest case of "not an answer"."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,), _sender_returning(302, {}))
    assert v.state == "inconclusive"


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


# ---- a refusal from the target is not a clean answer ---------------------
#
# F4 of the whole-branch review. The doctrine lives in `_probe_util`; these
# are this check's end of it, and the 3xx case is why the set had to be
# chosen rather than "every status that is not 2xx".


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 429, 500, 503])
def test_a_status_that_refused_is_inconclusive_not_clean(status):
    """A response with no `Location` because a WAF answered instead is not a
    target that validated the parameter, and only one of those may retire a
    finding."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,), _sender_returning(status, {}))
    assert v.state == "inconclusive"
    assert str(status) in v.reason
    assert v.considered == ()


def test_a_redirect_status_is_this_checks_finding_and_never_a_gap():
    """THE SEPARATING CASE, and why putting 3xx INTO `_probe_util.
    _NOT_AN_ANSWER` did not delete this check. `unanswered` is consulted only
    on the branch where the marker did not match, so a `Location` naming the
    marker becomes a candidate before the doctrine is ever asked, and a
    candidate wins over a gap. No exemption, no per-check status set -- the
    ordering does it."""
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,),
        _sender_returning(302, {"Location": oredir._MARKER_URL}))
    assert v.state == "finding"


def test_a_two_hundred_with_no_location_is_still_clean():
    v = oredir.OpenRedirect().probes(
        ctx, surface, (_REDIRECT_INSERTION,), _sender_returning(200, {}))
    assert v.state == "clean"
    assert v.considered == (oredir._ISSUE_TYPE,)
