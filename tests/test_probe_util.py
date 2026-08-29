"""`hx.checks.active._probe_util`: what the five active checks must agree on.

Canary minting and reflection testing, which `reflected_input.py` would
otherwise have grown on its own -- and, since the whole-branch review, the
two questions where five separate answers would each be a false `clean`:
where a payload goes in a templated path (`substitute_segment`, F1) and
whether a response answered at all (`unanswered`/`verdict`, F4).

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures -- see `tests/test_probe.py`'s own note.
"""
from __future__ import annotations

import pytest

from hx.checks import base, probe
from hx.checks.active import _probe_util


def _response(*, head: bytes = b"", body: bytes = b"",
              status: int | None = 200) -> probe.ProbeResponse:
    return probe.ProbeResponse(status=status, head=head, body=body,
                               outcome="ok")


def _candidate() -> base.Candidate:
    return base.Candidate(
        title="t", issue_type_id="probed", severity="Low",
        confidence="Firm", insertion=None, exchange_ids=("x-1",))


# ---- canary() --------------------------------------------------------------


def test_canary_is_alphanumeric_only():
    """The inertness guarantee: a value with no character capable of closing
    a tag, an attribute, a quoted string, or a script context, wherever it
    lands. A marker that could run is a payload, not a probe."""
    value = _probe_util.canary()
    assert value.isalnum()


def test_canary_is_long_enough_not_to_collide():
    value = _probe_util.canary()
    assert len(value) >= 16


def test_two_canaries_are_never_the_same():
    """Reflected input probes many insertion points per surface; a marker
    that could repeat would let two reflecting points be mistaken for one."""
    values = {_probe_util.canary() for _ in range(500)}
    assert len(values) == 500


# ---- reflected() -------------------------------------------------------


def test_a_marker_present_in_the_body_is_reflected():
    marker = _probe_util.canary()
    resp = _response(body=f"<p>hello {marker} world</p>".encode())
    assert _probe_util.reflected(resp, marker)


def test_a_marker_present_only_in_a_response_header_is_still_reflected():
    """A value can be echoed into either half of the response -- a
    diagnostic header, a mirrored `Set-Cookie` -- and a check for the body
    alone would call a target clean for reflecting input straight back in
    its headers."""
    marker = _probe_util.canary()
    resp = _response(
        head=f"HTTP/1.1 200 OK\r\nX-Echo: {marker}\r\n\r\n".encode())
    assert _probe_util.reflected(resp, marker)


def test_a_marker_absent_from_both_halves_is_not_reflected():
    marker = _probe_util.canary()
    resp = _response(head=b"HTTP/1.1 200 OK\r\n\r\n",
                     body=b"nothing interesting here")
    assert not _probe_util.reflected(resp, marker)


def test_one_canary_is_never_read_as_another():
    """Two insertion points, two markers: the response for one must never
    register as a hit for the other's marker."""
    planted = _probe_util.canary()
    different = _probe_util.canary()
    resp = _response(body=planted.encode())
    assert not _probe_util.reflected(resp, different)


# ---- substitute_segment() -------------------------------------------------
#
# F1's real fix, and the part of it that is not obvious. The sender is bound
# to the exemplar's CONCRETE path, which no longer contains the placeholder
# to replace, so the template is consulted only for which segment INDEX the
# insertion names.


def test_the_addresss_own_segment_is_the_one_replaced():
    assert _probe_util.substitute_segment(
        "/user/12345/profile", "/user/{id}/profile", "{id}", "PAYLOAD") == \
        "/user/PAYLOAD/profile"


def test_every_occurrence_is_replaced_not_only_the_first():
    """`hx.insertion.derive` keys placeholders by name, so a template
    repeating `{id}` yields ONE insertion point for both occurrences: a
    substitution that reached only one would leave the real value at the
    spot it skipped, in a request the check believes carries its payload
    everywhere."""
    assert _probe_util.substitute_segment(
        "/a/11111/b/22222", "/a/{id}/b/{id}", "{id}", "P") == "/a/P/b/P"


def test_a_segment_the_template_keeps_is_left_alone():
    """Only the segments the template calls this placeholder move -- a
    second, differently-named placeholder keeps the address's own value,
    which is what makes two insertion points two probes rather than one."""
    assert _probe_util.substitute_segment(
        "/order/9/doc/abc", "/order/{id}/doc/{slug}", "{id}", "P") == \
        "/order/P/doc/abc"


def test_a_plain_text_replace_would_have_been_wrong_here():
    """The separating case, stated as the defect it prevents: `str.replace`
    of the placeholder against the CONCRETE path finds nothing, returns the
    address unchanged, and sends the exemplar's own value back as though it
    were a payload."""
    address, template = "/user/12345/profile", "/user/{id}/profile"
    assert address.replace("{id}", "PAYLOAD") == address
    assert _probe_util.substitute_segment(
        address, template, "{id}", "PAYLOAD") != address


@pytest.mark.parametrize("address,template,placeholder", [
    # The two paths disagree about how many segments they have.
    ("/user/12345/profile/extra", "/user/{id}/profile", "{id}"),
    ("/user/12345", "/user/{id}/profile", "{id}"),
    # The template does not carry this placeholder at all.
    ("/user/12345/profile", "/user/{id}/profile", "{uuid}"),
    # Neither does an untemplated one.
    ("/search", "/search", "{id}"),
])
def test_a_substitution_that_cannot_be_made_is_None_not_the_address(
        address, template, placeholder):
    """`None`, and never the address unchanged. Returning the address would
    hand the caller a probe that carries no payload and reads as a test that
    happened; `None` is what makes the caller record a gap instead."""
    assert _probe_util.substitute_segment(
        address, template, placeholder, "PAYLOAD") is None


# ---- unanswered() ---------------------------------------------------------


@pytest.mark.parametrize("status", [
    400, 401, 403, 404, 405, 429,
    300, 301, 302, 303, 304, 307, 308,
    500, 502, 503, 599,
])
def test_a_refusing_status_is_named_as_one(status):
    reason = _probe_util.unanswered(_response(status=status))
    assert reason is not None
    assert str(status) in reason


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_not_an_answer_for_any_check_that_shares_this_doctrine(
        status):
    """N1 of the scoped re-review, and the case that cost the most. A 3xx
    used to sit outside the set on the ground that it is `open_redirect`'s
    own FINDING. It is -- and that is a fact about one check, not about the
    doctrine: every probe this build sends is unauthenticated, and the
    ordinary answer a browser-facing application gives an unauthenticated
    request is a 302 to a login page. Read as a conclusive negative, that
    retired live findings on all five checks.

    `open_redirect` is unharmed because of WHERE it asks: its marker in a
    `Location` is a candidate, and `unanswered` is consulted only where its
    own match failed. Any OTHER 3xx is a gap for it too -- the endpoint sent
    us somewhere we did not ask for, and nothing here can tell whether it
    looked at the parameter at all."""
    assert _probe_util.unanswered(_response(status=status)) is not None


@pytest.mark.parametrize("status", [400, 405])
def test_a_rejected_request_is_not_a_conclusive_negative_either(status):
    """The second-order members of the same family. Every probe drops the
    endpoint's OTHER query parameters, so a 400 from a multi-parameter
    endpoint is the EXPECTED answer rather than an unusual one, and a 405 is
    the endpoint declining the only method this build can send. Neither is
    evidence the payload was safe: the earlier justification -- "a fact about
    the endpoint the check may reason about" -- named no check that reasons
    about it, and none does."""
    assert _probe_util.unanswered(_response(status=status)) is not None


@pytest.mark.parametrize("status", [200, 201, 204, 206, 418])
def test_an_answering_status_is_not_a_gap(status):
    """What is left: a response the application itself composed. 418 is here
    as the separating case -- an odd 4xx is not automatically a refusal, and
    the set is enumerated rather than spelt "anything that is not 2xx"."""
    assert _probe_util.unanswered(_response(status=status)) is None


def test_a_response_with_no_status_at_all_is_a_gap():
    """Unreachable through `ProbeSender.get` (only `outcome == "ok"` is
    handed back), and answered anyway in the safe direction: a status nobody
    could read is not a status that said the target was clean."""
    assert _probe_util.unanswered(_response(status=None)) is not None


# ---- verdict() ------------------------------------------------------------
#
# The same three branches as `_http.verdict`, which is the point: the two
# halves of one corpus answering "when may I say clean" differently is the
# drift F4 found. The active half then adds a fourth branch and a refusal
# that the passive half has no use for -- see the N3 section at the end.


def test_nothing_found_and_nothing_refused_is_clean_and_considers():
    v = _probe_util.verdict([], [], considered=("probed",))
    assert v.state == "clean"
    assert v.considered == ("probed",)


def test_nothing_found_with_a_gap_is_inconclusive_and_considers_nothing():
    v = _probe_util.verdict([], ["q: status 403"], considered=("probed",))
    assert v.state == "inconclusive"
    assert "403" in v.reason
    assert v.considered == (), (
        "`Verdict.inconclusive` takes no `considered` at all, which is the "
        "property that stops a refused probe retiring a live finding")


def test_a_candidate_wins_over_a_gap():
    """What was found was found. A database error legitimately arrives ON a
    500, so a doctrine that downgraded a finding to `inconclusive` because
    of the status it came back on would delete `sql_error`'s whole point."""
    v = _probe_util.verdict([_candidate()], ["q: status 500"],
                            considered=("probed",))
    assert v.state == "finding"
    assert len(v.candidates) == 1


def test_a_gap_withholds_considered_from_a_finding_too():
    """The active half of F5. `considered` is what retires, and a surface
    where one point answered and another was refused has not examined the
    refused one -- so the finding is reported and its neighbours are not
    closed on the strength of a probe that never got an answer."""
    v = _probe_util.verdict([_candidate()], ["q: status 403"],
                            considered=("probed",))
    assert v.state == "finding"
    assert v.considered == ()


def test_the_reason_shows_the_gaps_the_way_a_coverage_row_does():
    """One formatter for both halves of the corpus (`_http._detail`), so an
    operator reading a coverage row sees gaps spelt one way whichever check
    wrote it."""
    v = _probe_util.verdict([], [f"p{i}: status 403" for i in range(5)])
    assert "p0: status 403" in v.reason
    assert "and 2 more" in v.reason



# ---- a check that probed nothing may not answer clean ---------------------
#
# N3 of the scoped re-review. `open_redirect` and `path_traversal` each apply
# a name filter of their own before a point earns a probe, and a surface on
# which that filter matched nothing reached `verdict([], [], considered=())`
# -> `clean` with `requests_sent = 0`. Nothing was retired (`considered` was
# empty, which is why this is not the same severity as N1), but
# `report._coverage` groups on (check_id, verdict) and counts SURFACES, so a
# real engagement rendered `hx.active.open-redirect | clean | <most of the
# corpus>` for a check that probed a handful. `clean` asserts "tested and
# nothing found"; on those rows nothing was tested. S12 on the coverage axis.


def test_a_check_that_probed_nothing_says_so_and_is_not_clean():
    v = _probe_util.verdict([], [], unprobed="no point here was probeable")
    assert v.state == "inconclusive"
    assert v.reason == "no point here was probeable"
    assert v.considered == ()


def test_a_gap_outranks_the_unprobed_sentence():
    """Ordering, and it matters: a surface where one point was refused and
    another never matched the filter has a gap to report, and the gap names
    the wire's own class -- which sends an operator somewhere the filter
    sentence would not."""
    v = _probe_util.verdict([], ["q: probe refused (budget_exhausted)"],
                            unprobed="no point here was probeable")
    assert v.state == "inconclusive"
    assert "budget_exhausted" in v.reason


def test_a_candidate_outranks_the_unprobed_sentence_too():
    """Structurally unreachable -- nothing probed means nothing found -- and
    answered in the same order as every other branch rather than left to be
    reasoned about."""
    v = _probe_util.verdict([_candidate()], [], considered=("probed",),
                            unprobed="no point here was probeable")
    assert v.state == "finding"


def test_clean_with_nothing_considered_is_refused_outright():
    """THE STRUCTURAL HALF, and the reason this is not four `if` statements
    in four checks. `clean` with an empty `considered` is exactly the row
    N3 is about: a check saying "tested, nothing found" while naming no
    issue type it tested for. There is no caller for which that is the
    right answer, so the funnel refuses it rather than each caller
    remembering not to ask. `hx.scan.run` turns the raise into an `error`
    row, which retires nothing -- the safe direction."""
    with pytest.raises(ValueError) as exc:
        _probe_util.verdict([], [])
    assert "considered" in str(exc.value)
