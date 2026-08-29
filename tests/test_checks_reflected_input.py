"""`hx.checks.active.reflected_input`.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures -- see `tests/test_checks_cors.py`'s own note,
which this file follows. `_FakeSender` below is the `probe.ProbeSender`
-shaped double for `probes()`'s fourth argument, adapted again from
`test_checks_open_redirect.py`'s: unlike either predecessor this check's
target can actually REFLECT what it is sent, so the fake sender here
constructs its response FROM the request it received -- percent-decoding the
path the way a real server/application would before deciding whether to
echo it back raw or HTML-escaped -- rather than answering with one fixed
response regardless of what the marker was. That is what lets these tests
assert on behaviour (`_probe_util.canary()` mints a fresh, unpredictable
value every call) instead of a marker literal the test would otherwise have
to know in advance.

NO JVM AND NO SOCKET. `ReflectedInput` is driven directly with a fake
sender; the real Burp path is Task 13's (`tests/integration/`).
"""
from __future__ import annotations

import html
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from hx.checks import base, probe
from hx.checks.active import reflected_input as ri


def _head(content_type: str = "text/html") -> bytes:
    return f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n".encode(
        "latin-1")


class _FakeSender:
    """A `ProbeSender`-shaped double whose response ECHOES the request.

    `mode`:
      * `"raw"`     -- the path (percent-decoded, as an application would
                       see it after its own framework unquotes the query
                       string or path segment) and the headers are reflected
                       into the body verbatim: an unsafe, un-escaping target.
      * `"escaped"` -- the same text, but HTML-escaped first: a target that
                       reflects input but neutralises it first.
      * `"off"`     -- a fixed body containing none of what was sent: a
                       target that does not reflect this input at all.

    `exc`, if set, is raised on every call instead of answering -- mirrors
    `test_checks_open_redirect.py`'s `_sender_raising`.
    """

    def __init__(self, *, mode: str = "raw",
                exc: Exception | None = None) -> None:
        self._mode = mode
        self._exc = exc
        self.sent = 0
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, path, *, headers=None, timeout=30.0):
        self.sent += 1          # a refused attempt still spent the budget,
                                 # matching the real sender's own ordering.
        headers = dict(headers or {})
        self.calls.append((path, headers))
        if self._exc is not None:
            raise self._exc
        if self._mode == "off":
            body = b"an ordinary response, none of the request echoed back"
        else:
            text = unquote(path) + "\n" + "\n".join(
                f"{k}: {v}" for k, v in headers.items())
            if self._mode == "escaped":
                text = html.escape(text)
            body = text.encode("utf-8", errors="ignore")
        return probe.ProbeResponse(status=200, head=_head(), body=body,
                                   outcome="ok")


def _sender_raising(exc: Exception) -> _FakeSender:
    return _FakeSender(mode="off", exc=exc)


def ctx_for():
    return base.CheckContext(config=None, blobs=None, run_id="r-1",
                             log=lambda s: None)


ctx = ctx_for()

# (id, method, scheme, host, port, path_template, exemplar_exchange_id) --
# the exact 7-tuple `hx.scan.run` selects and hands to `check.probes` (see
# `scan.py`'s `"SELECT id, method, scheme, host, port, path_template,
# exemplar_exchange_id FROM surface"`).
surface = ("s-1", "GET", "https", "app.test", 443, "/search", "x-1")

_QUERY_A = base.Insertion("query", "q")
_QUERY_B = base.Insertion("query", "term")
_HEADER = base.Insertion("header", "X-Client-Info")
_COOKIE = base.Insertion("cookie", "session")
_PATH_SEGMENT = base.Insertion("path_segment", "{id}")


# ---- the six sketched cases -------------------------------------------


def test_a_canary_that_comes_back_is_a_finding_naming_the_insertion_point():
    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,),
                                   _FakeSender(mode="raw"))
    assert v.state == "finding"
    assert v.candidates[0].insertion == _QUERY_A
    assert v.candidates[0].issue_type_id == ri._ISSUE_TYPE


def test_a_canary_that_does_not_come_back_is_clean():
    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,),
                                   _FakeSender(mode="off"))
    assert v.state == "clean"


def test_a_clean_answer_names_every_insertion_point_it_probed():
    """Otherwise a fixed parameter can never be retired."""
    sender = _FakeSender(mode="off")
    v = ri.ReflectedInput().probes(
        ctx, surface, (_QUERY_A, _HEADER, _COOKIE), sender)
    assert v.state == "clean"
    assert sender.sent == 3, "every declared insertion point was examined"
    assert v.considered == (ri._ISSUE_TYPE,), (
        "the surface WAS probed, so the issue type must be considered or a "
        "later fix can never be seen as retiring anything")


def test_each_insertion_point_gets_its_own_canary():
    """Two points sharing a marker make one reflection look like two."""
    sender = _FakeSender(mode="off")
    ri.ReflectedInput().probes(ctx, surface, (_QUERY_A, _QUERY_B), sender)
    assert sender.sent == 2

    def marker_of(path: str, name: str) -> str:
        return parse_qs(urlsplit(path).query)[name][0]

    marker_a = marker_of(sender.calls[0][0], "q")
    marker_b = marker_of(sender.calls[1][0], "term")
    assert marker_a != marker_b


def test_one_request_per_point_until_something_reflects():
    """Canary-first: the budget spent on a surface that reflects nothing
    equals the number of insertion points, not a multiple of it."""
    sender = _FakeSender(mode="off")
    ri.ReflectedInput().probes(
        ctx, surface, (_QUERY_A, _QUERY_B, _HEADER, _COOKIE), sender)
    assert sender.sent == 4


def test_the_finding_does_not_claim_exploitability_it_did_not_prove():
    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,),
                                   _FakeSender(mode="raw"))
    assert v.state == "finding"
    description = v.candidates[0].description
    assert "not that it is exploitable" in description
    for overclaim in ("XSS", "cross-site scripting", "successfully",
                      "confirmed exploit"):
        assert overclaim.lower() not in description.lower(), (
            f"description overclaims with {overclaim!r}: {description!r}")


def test_a_header_only_reflection_says_so_not_the_body():
    """Report what was observed, not what sounds worse. A marker echoed
    into a response HEADER only must not be described as landing in the
    response body -- the two are different risks and the description must
    say which one this check actually saw."""
    class _HeaderEcho:
        def __init__(self):
            self.sent = 0

        def get(self, path, *, headers=None, timeout=30.0):
            self.sent += 1
            marker = parse_qs(urlsplit(path).query)["q"][0]
            head = (f"HTTP/1.1 200 OK\r\nX-Echo: {marker}\r\n\r\n"
                    .encode("latin-1"))
            return probe.ProbeResponse(status=200, head=head,
                                       body=b"nothing in the body",
                                       outcome="ok")

    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,), _HeaderEcho())
    assert v.state == "finding"
    description = v.candidates[0].description
    assert "a response header" in description
    assert "the response body (" not in description


# ---- escalation: context, only after a canary comes back -----------------


def test_escalation_costs_exactly_one_more_request():
    sender = _FakeSender(mode="raw")
    ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,), sender)
    assert sender.sent == 2, (
        "one canary, and -- because it reflected -- exactly one more to "
        "characterise the context; never more")


def test_characters_that_survive_unescaped_are_the_stronger_finding():
    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,),
                                   _FakeSender(mode="raw"))
    assert v.state == "finding"
    assert v.candidates[0].severity == "Medium"
    assert "unescaped" in v.candidates[0].title


def test_a_reflection_that_gets_html_escaped_is_reported_at_lower_severity():
    """The alphanumeric canary still comes back (html.escape leaves it
    untouched) so this is still a finding, but the escalation's `<>"'`
    wrapper does not survive -- the weaker, more honest conclusion."""
    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,),
                                   _FakeSender(mode="escaped"))
    assert v.state == "finding"
    assert v.candidates[0].severity == "Low"
    assert "unescaped" not in v.candidates[0].title
    sender = _FakeSender(mode="escaped")
    ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,), sender)
    assert sender.sent == 2, "escalation still costs one request, win or lose"


def test_the_escalation_wrapper_never_reaches_the_meta_chars_helper_alone():
    """`_probe_util.canary()` itself never carries `<`, `>`, `"` or `'` --
    only this check's own escalation step adds them, on top of a fresh
    canary, and never mutates `canary()`'s own contract."""
    from hx.checks.active import _probe_util
    for _ in range(50):
        assert not any(c in _probe_util.canary() for c in ri._META_CHARS)


# ---- refusal and budget ---------------------------------------------------


def test_a_refusal_propagates_rather_than_becoming_a_verdict():
    """`ProbeSender.get()` RAISES `ProbeRefused` on every refusal and never
    returns one; catching it here and answering `inconclusive` (or worse,
    `clean`) would be this check doing the runner's job."""
    sender = _sender_raising(probe.ProbeRefused("rate_limited"))
    with pytest.raises(probe.ProbeRefused) as exc:
        ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,), sender)
    assert exc.value.reason == "rate_limited"


def test_a_refused_attempt_still_spent_the_budget():
    sender = _sender_raising(probe.ProbeRefused("budget_exhausted"))
    with pytest.raises(probe.ProbeRefused):
        ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,), sender)
    assert sender.sent == 1


def test_a_refusal_on_the_escalation_request_also_propagates():
    """The refusal can land on the SECOND request just as easily as the
    first -- the baseline canary reflects, and then the escalation itself is
    refused. Still a raise, still never a verdict."""
    class _ReflectsThenRefuses:
        def __init__(self):
            self.sent = 0
            self.calls = []

        def get(self, path, *, headers=None, timeout=30.0):
            self.sent += 1
            self.calls.append((path, headers))
            if self.sent == 1:
                text = unquote(path)
                return probe.ProbeResponse(status=200, head=_head(),
                                           body=text.encode(), outcome="ok")
            raise probe.ProbeRefused("rate_limited")

    sender = _ReflectsThenRefuses()
    with pytest.raises(probe.ProbeRefused):
        ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,), sender)
    assert sender.sent == 2


# ---- insertion kinds --------------------------------------------------


def test_only_declared_insertion_kinds_are_probed_others_are_skipped():
    """`insertion_kinds` is the four given in the interface; a kind outside
    it reaching `probes()` (which should not happen given `scan.run`'s own
    filter, but this check must not assume it) is simply skipped."""
    body_form = base.Insertion("body_form", "q")
    sender = _FakeSender(mode="off")
    v = ri.ReflectedInput().probes(ctx, surface, (body_form,), sender)
    assert sender.sent == 0
    assert v.state == "clean"
    assert v.considered == ()


@pytest.mark.parametrize("insertion,expect_in_path,expect_in_headers", [
    (_QUERY_A, "q=", None),
    (_PATH_SEGMENT, None, None),
    (_HEADER, None, "X-Client-Info"),
    (_COOKIE, None, "Cookie"),
])
def test_each_kind_places_its_value_where_it_belongs(
        insertion, expect_in_path, expect_in_headers):
    surface_with_id = ("s-1", "GET", "https", "app.test", 443,
                       "/items/{id}", "x-1")
    sender = _FakeSender(mode="off")
    ri.ReflectedInput().probes(ctx, surface_with_id, (insertion,), sender)
    assert sender.sent == 1
    path, headers = sender.calls[0]
    if expect_in_path:
        assert expect_in_path in path
    if expect_in_headers:
        assert expect_in_headers in headers
    if insertion.kind == "path_segment":
        assert "{id}" not in path, "the template placeholder must be filled in"


def test_a_repeated_path_placeholder_is_filled_in_at_every_occurrence():
    """`hx.insertion.derive` collects placeholders into a set keyed by name,
    so a template repeating `{id}` twice yields ONE `Insertion` for it --
    both occurrences are the same insertion point and both must carry the
    probe value, or the request would still name the real value at the spot
    left untouched."""
    surface_with_repeat = ("s-1", "GET", "https", "app.test", 443,
                           "/a/{id}/b/{id}", "x-1")
    sender = _FakeSender(mode="off")
    ri.ReflectedInput().probes(ctx, surface_with_repeat, (_PATH_SEGMENT,),
                               sender)
    assert sender.sent == 1
    path, _headers = sender.calls[0]
    assert "{id}" not in path


def test_two_reflecting_insertion_points_are_two_findings():
    """Two points, independently reflecting, must not collapse into one row
    -- `records.dedupe_key` distinguishes them by `candidate.insertion`, and
    this check must actually set it."""
    sender = _FakeSender(mode="raw")
    v = ri.ReflectedInput().probes(
        ctx, surface, (_QUERY_A, _QUERY_B), sender)
    assert v.state == "finding"
    assert len(v.candidates) == 2
    assert {c.insertion for c in v.candidates} == {_QUERY_A, _QUERY_B}


# ---- the shape of the check itself ----------------------------------------


def test_the_check_is_wired_for_the_registry():
    c = ri.ReflectedInput()
    assert c.id == "hx.active.reflected-input"
    assert c.klass == "active_safe"
    assert c.insertion_kinds == frozenset(
        {"query", "path_segment", "header", "cookie"})


def test_a_findings_issue_type_is_one_it_considered():
    """The drift-catching test this whole suite of checks carries: a
    candidate whose issue type is not in `considered` can never be
    retired."""
    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,),
                                   _FakeSender(mode="raw"))
    assert v.state == "finding"
    for candidate in v.candidates:
        assert candidate.issue_type_id in v.considered


def test_the_finding_cites_the_surfaces_exemplar_exchange():
    v = ri.ReflectedInput().probes(ctx, surface, (_QUERY_A,),
                                   _FakeSender(mode="raw"))
    assert v.candidates[0].exchange_ids == ("x-1",)


def test_the_marker_never_contains_meta_characters_before_escalation():
    """The baseline probe itself -- before any escalation -- must never be
    the thing that could execute. Read the first call's path/headers back
    and confirm none of `_META_CHARS` appears there for a surface that
    never reflects (so no escalation request is ever issued)."""
    sender = _FakeSender(mode="off")
    ri.ReflectedInput().probes(ctx, surface, (_QUERY_A, _HEADER), sender)
    for path, headers in sender.calls:
        haystack = path + " ".join(headers.values())
        assert not any(c in haystack for c in ri._META_CHARS)
