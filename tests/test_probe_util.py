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


@pytest.mark.parametrize("status", [402, 406, 407, 408, 409, 410, 413, 414,
                                    415, 418, 422, 423, 428, 431, 451])
def test_a_status_the_old_enumeration_omitted_is_a_gap_too(status):
    """THE EIGHTH SPELLING, and the reason this doctrine is an allowlist
    rather than a list of six numbers. Each of these read as the application
    ANSWERING while the set was enumerated; measured end to end in
    `tests/test_scan_probes.py::test_every_probing_check_reads_a_refused_
    request_as_a_gap`, a target answering 422, 410, 407, 406 or 414 to every
    request produced five `clean` rows and five tested Coverage rows off nine
    requests none of which was answered -- under a Limits bullet denying that
    could happen. FIVE rows off NINE requests, not five off five: two of these
    checks send one probe apiece and three send three, and a request count
    that happened to match the row count would be describing a corpus this
    build does not ship.

    422 IS THE ORDINARY CASE. The enumeration's own justification for holding
    400 was that every probe this build sends drops the endpoint's other query
    parameters, so a validation rejection is the EXPECTED answer from a
    multi-parameter endpoint. That argument is about the situation and not
    about the number: FastAPI/pydantic, Rails and a great many Node validation
    layers spell the same rejection 422. `410` is `404`'s sibling and `407` is
    `401`'s -- and a 407 is not composed by the application at all. `418` is
    here as the case that CHANGED SIDES: it used to be the separating example
    for "an odd 4xx is not automatically a refusal", which is exactly the
    reasoning that left the other fourteen out."""
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


@pytest.mark.parametrize("status", [200, 201, 202, 204, 206, 226, 299])
def test_an_answering_status_is_a_2xx_and_only_a_2xx(status):
    """The whole of what is left, and it is a rule rather than a list: the
    application processed the payload and composed a reply. 299 is here as
    the edge of the range and 226 as a real, rarely-seen member of it -- both
    are answers by the same rule, and neither needs anybody to have thought
    of it in advance, which is the property an enumeration could not have."""
    assert _probe_util.unanswered(_response(status=status)) is None


@pytest.mark.parametrize("status", [100, 101, 102, 199])
def test_an_informational_status_is_not_an_answer_either(status):
    """Unreachable through `ProbeSender` (the Java side reads one complete
    response and a 1xx is not it), and answered anyway in the direction the
    allowlist makes free: a status this build has never seen is a gap without
    anyone having to add it."""
    assert _probe_util.unanswered(_response(status=status)) is not None


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


def test_nothing_found_and_nothing_refused_is_clean():
    v = _probe_util.verdict([], [], examined=("probed",))
    assert v.state == "clean"


def test_nothing_found_with_a_gap_is_inconclusive():
    v = _probe_util.verdict([], ["q: status 403"], examined=("probed",))
    assert v.state == "inconclusive"
    assert "403" in v.reason


def test_a_candidate_wins_over_a_gap():
    """What was found was found. A database error legitimately arrives ON a
    500, so a doctrine that downgraded a finding to `inconclusive` because
    of the status it came back on would delete `sql_error`'s whole point."""
    v = _probe_util.verdict([_candidate()], ["q: status 500"],
                            examined=("probed",))
    assert v.state == "finding"
    assert len(v.candidates) == 1


def test_no_verdict_this_funnel_builds_carries_considered():
    """FIX ROUND 6, AND THIS IS THE HALF THAT LIVES IN THE CHECKS. An active
    check retires nothing, so `examined` feeds the `clean` guard below and
    stops there -- it deliberately never reaches `Verdict.considered`, which
    `hx.scan._retirable` would refuse from a probing check anyway. Both ends
    are asserted so neither can quietly move on its own: this pins the
    check's end, `tests/test_scan_probes.py::test_an_active_check_that_
    populates_considered_is_an_error_row` pins the runner's.

    Every branch, because `clean` is not the only one that used to carry it:
    a finding used to carry `considered` too (and lose it to a gap), which
    is what let one check's finding on a surface retire that check's OTHER
    issue types there."""
    for v in (_probe_util.verdict([], [], examined=("probed",)),
              _probe_util.verdict([_candidate()], [], examined=("probed",)),
              _probe_util.verdict([_candidate()], ["q: status 403"],
                                  examined=("probed",)),
              _probe_util.verdict([], ["q: status 403"], examined=("probed",)),
              _probe_util.verdict([], [], unprobed="nothing here")):
        assert v.considered == (), v


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
# which that filter matched nothing reached `verdict([], [])` -> `clean` with
# `requests_sent = 0`. Nothing was retired even then (it named nothing it had
# examined, which is why this is not the same severity as N1), but
# `report._coverage` groups on (check_id, verdict) and counts SURFACES, so a
# real engagement rendered `hx.active.open-redirect | clean | <most of the
# corpus>` for a check that probed a handful. `clean` asserts "tested and
# nothing found"; on those rows nothing was tested. S12 on the coverage axis.


def test_a_check_that_probed_nothing_says_so_and_is_not_clean():
    v = _probe_util.verdict([], [], unprobed="no point here was probeable")
    assert v.state == "inconclusive"
    assert v.reason == "no point here was probeable"


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
    v = _probe_util.verdict([_candidate()], [], examined=("probed",),
                            unprobed="no point here was probeable")
    assert v.state == "finding"


def test_clean_with_nothing_examined_is_refused_outright():
    """THE STRUCTURAL HALF, and the reason this is not four `if` statements
    in four checks. `clean` with nothing examined is exactly the row N3 is
    about: a check saying "tested, nothing found" while naming no issue type
    it tested for. There is no caller for which that is the right answer, so
    the funnel refuses it rather than each caller remembering not to ask.
    `hx.scan.run` turns the raise into an `error` row, which is loud and
    retires nothing -- the safe direction.

    STILL LOAD-BEARING AFTER FIX ROUND 6, and more narrowly so: this used to
    guard the coverage row AND the retirement a populated `considered`
    licensed. The retirement is gone for every active check, and the
    coverage row is reason enough on its own -- S12 is about exactly that
    distinction."""
    with pytest.raises(ValueError) as exc:
        _probe_util.verdict([], [])
    assert "examined" in str(exc.value)
