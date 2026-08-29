"""`_http`'s head/body split and header parsing, driven directly.

RFC 9112 s2.2 requires a recipient to accept a bare LF as a line terminator.
`bodies()`/`responses()` used to split on `raw.partition(b"\\r\\n\\r\\n")`
alone, so a bare-LF response matched nothing there and came back as an EMPTY
body plus the WHOLE response as one unsplit head. `secret_in_response` and
`stack_trace` then searched nothing and answered `clean`; `security_headers`
and `cookie_flags` read no headers at all, so the former claimed every
header missing and the latter saw no cookies. All four were wrong, and the
tool reported clean because it had failed to read -- the one direction an
assessment must never be wrong in.

These tests sit below the four checks, directly against `_http`, so a future
regression here is caught before it fans out into all four.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures for this kind of thing -- `ctx_for`, `rows` and
`resp` below are the same shape `tests/test_checks_passive.py` already
established for driving these checks.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.passive import _http


class FakeBlobs:
    def __init__(self, **blobs): self._b = blobs
    def get(self, digest, expected_len=None): return self._b[digest]


def ctx_for(**blobs):
    return base.CheckContext(config=None, blobs=FakeBlobs(**blobs),
                             run_id="r-1", log=lambda s: None)


def rows(resp_blob="d1", url="https://app.test/x", status=200, outcome="ok"):
    return (base.ExchangeRow(id="x-1", method="GET", url=url, status=status,
                             outcome=outcome, req_blob=None,
                             resp_blob=resp_blob),)


_LF_RESPONSE = (b"HTTP/1.1 200 OK\n"
                b"Content-Type: text/html\n"
                b"Set-Cookie: session=1\n"
                b"\n"
                b"<html>AKIAIOSFODNN7EXAMPLE</html>")

# The ordinary path this fix must leave alone.
_CRLF_RESPONSE = (b"HTTP/1.1 200 OK\r\n"
                  b"Content-Type: text/html\r\n"
                  b"\r\n"
                  b"<html>ok</html>")


def test_a_bare_lf_response_still_yields_its_body():
    ev = _http.bodies(ctx_for(d1=_LF_RESPONSE), rows())
    assert b"AKIAIOSFODNN7EXAMPLE" in ev.entries[0][1], (
        "the body came back empty, so every body-searching check answers "
        "clean on this server -- a false negative in an assessment")


def test_a_bare_lf_response_still_yields_its_headers():
    ev = _http.responses(ctx_for(d1=_LF_RESPONSE), rows())
    head = ev.entries[0][1]
    assert _http.header_values(head, "content-type") == ["text/html"]
    assert _http.header_values(head, "set-cookie") == ["session=1"]
    assert _http.header_names(head) == ["Content-Type", "Set-Cookie"]


def test_a_crlf_response_is_unchanged():
    """The separating case: the fix must not alter the ordinary path."""
    ev = _http.responses(ctx_for(d1=_CRLF_RESPONSE), rows())
    assert _http.header_values(ev.entries[0][1], "content-type") == ["text/html"]


def test_a_crlf_response_body_is_unchanged():
    """The separating case for `bodies()`: an ordinary CRLF body must come
    back exactly as before, not merely "non-empty"."""
    ev = _http.bodies(ctx_for(d1=_CRLF_RESPONSE), rows())
    assert ev.entries[0][1] == b"<html>ok</html>"


def test_a_lone_cr_inside_a_header_value_does_not_split_it():
    """Guard against over-splitting: normalising must not invent header
    boundaries the wire did not carry. A bare CR is data, not a terminator
    -- RFC 9112 only recognises CRLF and a bare LF as ending a line."""
    head = b"HTTP/1.1 200 OK\r\nX-Note: a\rb\r\n"
    assert _http.header_values(head, "x-note") == ["a\rb"]


def test_a_bare_lf_head_is_not_pulled_forward_by_crlfcrlf_in_the_body():
    """`_split_head_body` picks the EARLIEST of the two terminators. A body
    that happens to contain `\\r\\n\\r\\n` later must not pull the boundary
    forward past a head that already ended on a bare `\\n\\n`. This is the
    direction a "try CRLF first, fall back to LF" rewrite gets wrong: that
    version would find the later `\\r\\n\\r\\n` first and cut there instead,
    leaving `BODY` stuck onto the head as if it were another header line."""
    raw = b"HTTP/1.1 200 OK\n\nBODY\r\n\r\nMORE"
    ev = _http.bodies(ctx_for(d1=raw), rows())
    assert ev.entries[0][1] == b"BODY\r\n\r\nMORE"


def test_a_crlf_head_is_not_pulled_forward_by_lflf_in_the_body():
    """The other direction of the same property: a body that happens to
    contain a bare `\\n\\n` later must not pull the boundary forward past a
    head that already ended on `\\r\\n\\r\\n`. A "try CRLF first" rewrite
    happens to get this direction right by construction, but a naive
    "whichever `.find()` is not -1, preferring LF" rewrite would not."""
    raw = b"HTTP/1.1 200 OK\r\n\r\nBODY\n\nMORE"
    ev = _http.bodies(ctx_for(d1=raw), rows())
    assert ev.entries[0][1] == b"BODY\n\nMORE"
