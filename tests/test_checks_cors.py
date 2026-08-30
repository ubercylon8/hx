"""`hx.checks.active.cors`, the first check that sends.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures for this kind of thing -- see
`tests/test_checks_passive.py`'s `ctx_for`/`rows`/`resp` and
`tests/test_probe.py`'s own note. `_FakeSender` below is the `probe.
ProbeSender`-shaped double for `probes()`'s fourth argument: it returns a
`probe.ProbeResponse` on success and RAISES `probe.ProbeRefused` on a
refusal, exactly like the real sender's contract in `hx/checks/probe.py`
(`get()` never returns a refusal as a value).

NO JVM AND NO SOCKET. `Cors` is driven directly with a fake sender; the real
Burp path is Task 13's (`tests/integration/`).
"""
from __future__ import annotations

import pytest

from hx.checks import base, probe
from hx.checks.active import cors


def _head(headers: dict[str, str]) -> bytes:
    lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return f"HTTP/1.1 200 OK\r\n{lines}".encode("latin-1")


class _FakeSender:
    """A `ProbeSender`-shaped double. Exactly one of `headers`/`exc` is set.

    `path` is what the real `ProbeSender` exposes as its own: the CONCRETE
    path of the surface's exemplar request, which is where this check sends
    its one probe. It defaults to this file's own `surface`'s
    `path_template` because that surface is not templated -- the two are the
    same string for it -- and the tests that need them to differ pass it
    explicitly.
    """

    def __init__(self, *, headers: dict[str, str] | None = None,
                exc: Exception | None = None, path: str = "/",
                status: int = 200) -> None:
        self.path = path
        self._status = status
        self._headers = headers
        self._exc = exc
        self.sent = 0
        self.last_path: str | None = None
        self.last_headers: dict[str, str] | None = None

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
        self.last_path = path
        self.last_headers = headers
        if self._exc is not None:
            raise self._exc
        return probe.ProbeResponse(status=self._status,
                                   head=_head(self._headers or {}),
                                   body=b"", outcome="ok")


def _sender_returning(headers: dict[str, str]) -> _FakeSender:
    return _FakeSender(headers=headers)


def _sender_raising(exc: Exception) -> _FakeSender:
    return _FakeSender(exc=exc)


def _counting_sender() -> _FakeSender:
    return _FakeSender(headers={})


def ctx_for():
    return base.CheckContext(config=None, blobs=None, run_id="r-1",
                             log=lambda s: None)


ctx = ctx_for()

# (id, method, scheme, host, port, path_template, exemplar_exchange_id) --
# the exact 7-tuple `hx.scan.run` selects and hands to `check.probes` (see
# `scan.py`'s `"SELECT id, method, scheme, host, port, path_template,
# exemplar_exchange_id FROM surface"`).
surface = ("s-1", "GET", "https", "app.test", 443, "/", "x-1")


# ---- the four sketched cases -------------------------------------------


def test_an_arbitrary_origin_reflected_with_credentials_is_a_finding():
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN,
         "Access-Control-Allow-Credentials": "true"}))
    assert v.state == "finding"
    assert cors._PROBE_ORIGIN in v.candidates[0].description
    # F10: `finding.payload` exists and `upsert_finding` writes it. The value
    # this was demonstrated with is the Origin the probe carried; leaving the
    # column NULL made the first corpus with real payloads populate none.
    assert v.candidates[0].payload == cors._PROBE_ORIGIN


def test_a_target_that_ignores_the_origin_is_clean():
    v = cors.Cors().probes(ctx, surface, (), _sender_returning({}))
    assert v.state == "clean"
    assert v.considered == (), (
        "an active check may not retire anything, so no verdict it returns "
        "may carry `considered` -- `hx.scan._retirable` refuses one that "
        "does")


def test_a_refusal_propagates_with_its_reason_intact():
    """ADAPTED FROM THE BRIEF'S SKETCH, which called `.probes()` directly and
    asserted `v.state == "inconclusive"`. That return shape is one this
    check's `probes()` must never produce on a refusal: `hx/checks/probe.py`
    is explicit that `ProbeSender.get()` RAISES `ProbeRefused` on every
    refusal and never returns one, precisely so a refusal cannot be mistaken
    for an answer, and turning a raise into `inconclusive` is `hx.scan.run`'s
    job (`except ProbeRefused` in `scan.py`, exercised end to end by
    `tests/test_scan_probes.py::test_a_refusal_becomes_inconclusive_never_clean`),
    not any individual check's. A check that caught it here could just as
    easily catch it and answer `clean`."""
    with_refusing_sender = _sender_raising(probe.ProbeRefused("rate_limited"))
    with pytest.raises(probe.ProbeRefused) as exc:
        cors.Cors().probes(ctx, surface, (), with_refusing_sender)
    assert exc.value.reason == "rate_limited"


def test_the_check_sends_exactly_one_request():
    sender = _counting_sender()
    cors.Cors().probes(ctx, surface, (), sender)
    assert sender.sent == 1, "CORS needs one GET; more is budget spent for nothing"


# ---- the shape of the check itself --------------------------------------


def test_the_check_is_wired_for_the_registry():
    c = cors.Cors()
    assert c.id == "hx.active.cors"
    assert c.klass == "active_safe"
    assert c.insertion_kinds == frozenset(), (
        "a CORS finding has no insertion point: the request is shaped by a "
        "header the check adds, not by a parameter it found")


def test_the_probe_carries_an_origin_that_cannot_be_the_target():
    sender = _sender_returning({})
    cors.Cors().probes(ctx, surface, (), sender)
    assert sender.last_headers is not None
    origin = sender.last_headers.get("Origin")
    assert origin == cors._PROBE_ORIGIN
    # .test is reserved by RFC 2606 for exactly this: a value guaranteed
    # never to be a real, resolvable production target.
    assert origin.rstrip("/").rsplit(".", 1)[-1] == "test" or ".test" in origin


# ---- what the check concludes, and why ----------------------------------


def test_reflection_without_credentials_is_a_weaker_finding():
    """The weaker case named in the check's own docstring: an arbitrary
    origin is trusted, but with no credentials allowed there is no session
    for a reflecting attacker to ride."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN}))
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == cors._REFLECTS_NO_CREDENTIALS
    with_creds = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN,
         "Access-Control-Allow-Credentials": "true"}))
    assert base.SEVERITIES  # sanity: both severities are legal schema values
    assert v.candidates[0].severity in base.SEVERITIES
    assert with_creds.candidates[0].severity in base.SEVERITIES
    # The credentialed case is strictly the more serious of the two, which is
    # what makes this the SEPARATING case rather than two independent facts.
    order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    assert order[with_creds.candidates[0].severity] > order[v.candidates[0].severity]


def test_a_present_but_non_true_credentials_header_is_not_reported_as_absent():
    """Fix round 1 (LOW). `_credentials_allowed` answers False for
    `Access-Control-Allow-Credentials: False` -- it is present, just not the
    exact `true` a browser honours -- and the reflects-no-credentials
    description used to hardcode "with no Access-Control-Allow-Credentials
    header" for every case that reached this branch, which misstates what
    was actually observed when a header WAS sent. A client reading this
    sentence cannot see the code that produced it and would be told
    something false about their own target."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN,
         "Access-Control-Allow-Credentials": "False"}))
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == cors._REFLECTS_NO_CREDENTIALS
    description = v.candidates[0].description
    assert "no Access-Control-Allow-Credentials header" not in description, (
        "the header WAS present (False); the description must not claim "
        "it was absent")
    assert "False" in description, (
        "the description must state what was actually observed")


def test_wildcard_with_credentials_is_the_lowest_severity_finding():
    """`*` plus `Access-Control-Allow-Credentials: true` is a response a
    browser refuses to honour (the fetch spec forbids the combination), so
    it is a misconfiguration worth reporting but not one anything can
    currently exploit through a browser -- hence the lowest severity of the
    three conclusions this check can reach."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": "*",
         "Access-Control-Allow-Credentials": "true"}))
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == cors._WILDCARD_WITH_CREDENTIALS
    order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    reflect_with_creds = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN,
         "Access-Control-Allow-Credentials": "true"}))
    assert (order[v.candidates[0].severity]
            <= order[reflect_with_creds.candidates[0].severity])


def test_a_plain_wildcard_with_no_credentials_is_clean():
    """`Access-Control-Allow-Origin: *` alone is the standard shape of a
    public, unauthenticated API and must not itself be a finding."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": "*"}))
    assert v.state == "clean"


def test_an_allowlisted_origin_that_does_not_reflect_is_clean():
    """The server answering with a fixed, legitimate origin -- never our
    probe's -- is a target that read the Origin header and rejected it."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": "https://good.example"}))
    assert v.state == "clean"


# ---- examined / dedupe identity ------------------------------------------


def test_every_issue_type_this_check_can_conclude_is_in_examined():
    """`_EXAMINED` is what `_probe_util.verdict` is told, and naming fewer
    than all three would understate this check's coverage on every row it
    closes `clean`. It was `considered` and therefore what could be retired
    until fix round 6; an active check retires nothing now, and the set is
    still the check's own statement of what it looked for."""
    assert set(cors._EXAMINED) == {
        cors._REFLECTS_WITH_CREDENTIALS,
        cors._REFLECTS_NO_CREDENTIALS,
        cors._WILDCARD_WITH_CREDENTIALS,
    }


def test_a_cors_candidates_issue_type_is_one_it_examined():
    """The drift-catching test this whole suite of checks carries: a
    candidate minting an issue type the check does not list as examined is
    two spellings of one question, and `report._coverage` would show a row
    claiming to have looked for something no finding is ever filed under."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN,
         "Access-Control-Allow-Credentials": "true"}))
    assert v.state == "finding"
    for candidate in v.candidates:
        assert candidate.issue_type_id in cors._EXAMINED


def test_a_refusal_propagates_rather_than_becoming_a_verdict():
    """The check does not catch `ProbeRefused`, and must not: S10 says a
    check that could not run is `inconclusive`, and `hx.scan.run`'s own
    `except probe.ProbeRefused` is what writes that row. A check that
    swallowed the refusal would answer `clean` for a probe that never got an
    answer, which is the confusion S12 calls worse than no report.

    This replaces `test_a_refused_attempt_still_spent_the_budget`, whose
    claim -- and whose assertion on the DOUBLE's counter -- encoded the rule
    fix round A corrected: `hx.policy.Limiter` refuses `budget_exhausted`
    before issuing anything, so nothing was spent and nothing was touched.
    What `requests_sent` counts is a property of the real sender and is
    pinned there, in `tests/test_probe.py`, not against a stand-in."""
    sender = _sender_raising(probe.ProbeRefused("budget_exhausted"))
    with pytest.raises(probe.ProbeRefused):
        cors.Cors().probes(ctx, surface, (), sender)


# ---- evidence --------------------------------------------------------


def test_the_finding_cites_the_surfaces_exemplar_exchange():
    """A candidate with no exchange behind it has nothing to chain (S12).
    Nothing in this build's probe path writes a fresh exchange row for a
    probe's own request/response yet -- that is Task 13's -- so the surface's
    exemplar (the exchange that already proved it exists) is what this check
    cites."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN,
         "Access-Control-Allow-Credentials": "true"}))
    assert v.candidates[0].exchange_ids == ("x-1",)


@pytest.mark.parametrize("headers", [
    {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN,
     "Access-Control-Allow-Credentials": "true"},
    {"Access-Control-Allow-Origin": cors._PROBE_ORIGIN},
    {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
])
def test_every_finding_has_an_insertion_of_none(headers):
    """S5: a CORS finding has no insertion point, the same reasoning §5
    gives for TLS and cookie-flag findings."""
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(headers))
    assert v.state == "finding"
    assert all(c.insertion is None for c in v.candidates)


# ---- a refusal from the target is not a clean answer ---------------------
#
# F4 of the whole-branch review: every active check treated ANY status as a
# conclusive negative, so a WAF's 403, a 500 or a maintenance page recorded
# `clean` with `considered` populated and retired live findings. Retirement
# is gone from the active corpus since fix round 6 and the doctrine is not:
# `clean` still asserts a test happened, and the coverage table is what a
# client reads it off. It lives in `_probe_util`; these two tests are this
# check's end of it.


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_a_status_that_refused_is_inconclusive_not_clean(status):
    """A response with no CORS headers because nothing answered looks
    identical, header for header, to one from a correctly configured target,
    and `clean` would claim the second of those."""
    v = cors.Cors().probes(ctx, surface, (), _FakeSender(headers={},
                                                         status=status))
    assert v.state == "inconclusive"
    assert str(status) in v.reason
    assert v.considered == ()


def test_the_same_missing_headers_on_a_200_are_still_clean():
    """The separating case. Treating every status as a refusal would leave
    this check unable to report a tested surface at all, which is S12's
    other direction on the coverage axis."""
    v = cors.Cors().probes(ctx, surface, (), _FakeSender(headers={},
                                                         status=200))
    assert v.state == "clean"
