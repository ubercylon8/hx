"""`hx.checks.active.path_traversal`.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures -- see `tests/test_checks_cors.py`'s own note,
which this file follows. `_FakeSender` below is adapted from
`test_checks_sql_error.py`'s own (itself adapted from
`test_checks_open_redirect.py`'s): a fixed `(status, headers, body)` per
call, since this check reads a signature out of the body/head it is handed.

NO JVM AND NO SOCKET. `PathTraversal` is driven directly with a fake sender;
the real Burp path is Task 13's (`tests/integration/`).
"""
from __future__ import annotations

import pytest

from hx.checks import base, probe
from hx.checks.active import path_traversal as ptrav


def _head(headers: dict[str, str] | None = None) -> bytes:
    lines = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    return f"HTTP/1.1 200 OK\r\n{lines}".encode("latin-1")


class _FakeSender:
    """A `ProbeSender`-shaped double, matching
    `test_checks_sql_error.py`'s own.

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
                path: str = "/download/report-2026.pdf") -> None:
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
# This row used to read `/download` while `_PATH_SEGMENT` below named
# `{filename}`, so the substitution had nothing to replace and
# `test_a_path_segment_placeholder_is_filled_in` was vacuous -- the shape F1
# hid. `{filename}` is not a placeholder `hx.surface._template_segment` can
# mint (its vocabulary is `{id}`, `{uuid}`, `{hex}`, `{slug}`, none of which
# `_looks_like_file_target` accepts); it is the fiction this file needs to
# exercise the path-segment branch at all, and it was here before this row
# was templated.
# `/download/report-2026.pdf` is the concrete address this row stands for,
# and it is what `_FakeSender` defaults its `path` to.
surface = ("s-1", "GET", "https", "app.test", 443,
           "/download/{filename}", "x-1")

_FILE_PARAM = base.Insertion("query", "file")
_UNRELATED_PARAM = base.Insertion("query", "id")
# A SECOND file-shaped name, so a test can refuse one point and still have
# one this check would probe. `template` is in `_FILE_NAME_HINTS`.
_SECOND_FILE_PARAM = base.Insertion("query", "template")
_PATH_SEGMENT = base.Insertion("path_segment", "{filename}")

_PASSWD_BODY = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
_CLEAN_BODY = b"<html>no such file</html>"


# ---- the five sketched cases -----------------------------------------


def test_the_root_account_line_in_the_body_is_a_finding():
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _PASSWD_BODY))
    assert v.state == "finding"
    assert v.candidates[0].issue_type_id == ptrav._ISSUE_TYPE
    assert v.candidates[0].insertion == _FILE_PARAM


def test_a_response_with_no_signature_anywhere_is_clean():
    """THE STATUS USED TO BE 404 HERE, and that is now `inconclusive`: a 404
    is the target refusing rather than answering, and a check that read it as
    a conclusive negative retired findings (F4 of the whole-branch review).
    200 is the answer this test always meant -- the application served
    something and it carried no file content."""
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _CLEAN_BODY))
    assert v.state == "clean"
    assert v.considered == (ptrav._ISSUE_TYPE,), (
        "the point WAS probed, so the issue type must be considered or a "
        "later fix can never be seen as retiring anything")


def test_a_parameter_that_does_not_look_like_a_file_is_not_probed():
    """Budget: name-based canary-first, like `open_redirect.py`."""
    sender = _sender_returning(200, _CLEAN_BODY)
    v = ptrav.PathTraversal().probes(ctx, surface, (_UNRELATED_PARAM,),
                                     sender)
    assert sender.sent == 0
    assert v.state == "clean"
    assert v.considered == (), (
        "nothing was actually examined on this surface, so nothing may be "
        "considered -- naming the issue type here would let a real, "
        "never-tested finding be silently retired")


def test_only_file_shaped_parameters_are_probed_among_a_mix():
    sender = _sender_returning(200, _CLEAN_BODY)
    ptrav.PathTraversal().probes(
        ctx, surface, (_FILE_PARAM, _UNRELATED_PARAM), sender)
    assert sender.sent == 1
    assert "file=" in sender.paths[0]
    assert "id=" not in sender.paths[0]


def test_one_request_per_point_regardless_of_table_size():
    sender = _sender_returning(200, _CLEAN_BODY)
    ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM, _PATH_SEGMENT),
                                 sender)
    assert sender.sent == 2
    assert len(ptrav._SIGNATURES) >= 3


# ---- honesty: the description reports what matched, not a generic claim --


def test_the_description_names_the_matched_line_and_the_file():
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _PASSWD_BODY))
    description = v.candidates[0].description
    assert "root:x:0:0:" in description
    assert "/etc/passwd" in description
    assert "root account" in description


def test_the_description_names_the_response_body_when_that_is_where_it_matched():
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _PASSWD_BODY))
    assert "the response body" in v.candidates[0].description


def test_the_description_names_a_response_header_when_that_is_where_it_matched():
    v = ptrav.PathTraversal().probes(
        ctx, surface, (_FILE_PARAM,),
        _sender_returning(200, b"nothing in the body",
                          headers={"X-Debug": "root:x:0:0:"}))
    assert v.state == "finding"
    assert "a response header" in v.candidates[0].description
    assert "the response body" not in v.candidates[0].description


def test_a_different_matched_line_names_that_account_not_a_generic_one():
    daemon_only = b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, daemon_only))
    description = v.candidates[0].description
    assert "daemon:x:1:1:" in description
    assert "daemon account" in description


def test_the_description_does_not_claim_arbitrary_file_access():
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _PASSWD_BODY))
    description = v.candidates[0].description.lower()
    assert "does not show" in description
    for overclaim in ("arbitrary file read confirmed", "full filesystem access",
                      "remote code execution"):
        assert overclaim not in description


# ---- refusal and budget ---------------------------------------------------


def test_a_refusal_ends_one_point_and_never_the_whole_check():
    """F2 of the whole-branch review, in this check's spelling. Two
    file-shaped parameters: the first is refused, the second is probed and
    /etc/passwd comes back."""
    sender = _FakeSender(responses=[
        probe.ProbeRefused("rate_limited"),
        (200, {}, _PASSWD_BODY),
    ])
    v = ptrav.PathTraversal().probes(
        ctx, surface, (_FILE_PARAM, _SECOND_FILE_PARAM), sender)
    assert sender.sent == 2, "the refusal took the second point down with it"
    assert v.state == "finding"
    assert v.candidates[0].insertion == _SECOND_FILE_PARAM
    assert v.considered == ()


def test_a_refusal_with_nothing_found_is_inconclusive_never_clean():
    sender = _FakeSender(responses=[probe.ProbeRefused("budget_exhausted")])
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,), sender)
    assert v.state == "inconclusive"
    assert "budget_exhausted" in v.reason
    assert sender.sent == 1


# ---- the payload sent ---------------------------------------------------


def test_the_payload_never_appears_as_a_raw_dot_dot_slash_on_the_wire():
    """The safety property: the literal `../` is percent-encoded before it
    ever reaches `path`, so hx's own request line never carries a raw
    traversal segment for some intermediate proxy to normalise."""
    sender = _sender_returning(200, _CLEAN_BODY)
    ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,), sender)
    assert "../" not in sender.paths[0]
    assert "%2F" in sender.paths[0] or "%2f" in sender.paths[0]


def test_the_traversal_depth_is_bounded_not_excessive():
    assert 1 <= ptrav._TRAVERSAL_DEPTH <= 10


def test_the_target_file_is_the_deliberately_harmless_one():
    assert ptrav._TARGET_FILE == "/etc/passwd"


# ---- insertion kinds and identity --------------------------------------


def test_the_check_is_wired_for_the_registry():
    c = ptrav.PathTraversal()
    assert c.id == "hx.active.path-traversal"
    assert c.klass == "active_safe"
    assert c.insertion_kinds == frozenset({"query", "path_segment"})


def test_only_declared_insertion_kinds_are_probed_others_are_skipped():
    header_insertion = base.Insertion("header", "file")
    sender = _sender_returning(200, _CLEAN_BODY)
    v = ptrav.PathTraversal().probes(ctx, surface, (header_insertion,),
                                     sender)
    assert sender.sent == 0
    assert v.state == "clean"
    assert v.considered == ()


def test_a_finding_names_the_insertion_it_came_from():
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _PASSWD_BODY))
    assert v.candidates[0].insertion == _FILE_PARAM


def test_the_finding_cites_the_surfaces_exemplar_exchange():
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _PASSWD_BODY))
    assert v.candidates[0].exchange_ids == ("x-1",)


def test_a_findings_issue_type_is_one_it_considered():
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(200, _PASSWD_BODY))
    assert v.state == "finding"
    for candidate in v.candidates:
        assert candidate.issue_type_id in v.considered


def test_two_file_shaped_parameters_that_both_disclose_are_two_findings():
    """Two parameters, independently disclosing file content, must not
    collapse into one row -- `records.dedupe_key` distinguishes them by
    `candidate.insertion`, and this check must actually set it."""
    other = base.Insertion("query", "template")
    sender = _FakeSender(responses=[
        (200, {}, _PASSWD_BODY),
        (200, {}, _PASSWD_BODY),
    ])
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM, other),
                                     sender)
    assert v.state == "finding"
    assert len(v.candidates) == 2
    assert {c.insertion for c in v.candidates} == {_FILE_PARAM, other}


def test_a_path_segment_probe_replaces_the_addresss_own_segment():
    """RENAMED FROM `test_a_path_segment_placeholder_is_filled_in`, for the
    reason `tests/test_checks_sql_error.py`'s namesake gives: the old
    assertion held against a probe that carried no payload at all. The
    address's own segment being gone is what separates them."""
    sender = _sender_returning(200, _CLEAN_BODY)
    ptrav.PathTraversal().probes(ctx, surface, (_PATH_SEGMENT,), sender)
    assert sender.paths[0].startswith("/download/")
    assert "{filename}" not in sender.paths[0]
    assert "report-2026.pdf" not in sender.paths[0], sender.paths[0]


# ---- a refusal from the target is not a clean answer ---------------------
#
# F4 of the whole-branch review. A 404 is the ordinary answer to a traversal
# a target refused to serve AND to a resource that has simply gone, and the
# second is not evidence the first was fixed.


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_a_status_that_refused_with_no_signature_is_inconclusive(status):
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(status, _CLEAN_BODY))
    assert v.state == "inconclusive"
    assert str(status) in v.reason
    assert v.considered == ()


def test_file_content_on_a_refusing_status_is_still_a_finding():
    """A candidate wins over a gap: `/etc/passwd`'s own content coming back
    proves the traversal landed whatever the status line said."""
    v = ptrav.PathTraversal().probes(ctx, surface, (_FILE_PARAM,),
                                     _sender_returning(500, _PASSWD_BODY))
    assert v.state == "finding"
