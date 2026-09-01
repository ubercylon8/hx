"""The parsers, at their new address.

These four moved out of `hx.checks.passive._http` so `hx.issue` could read a
content type without a core module importing from `hx.checks`. The tests that
prove their BEHAVIOUR still live in the passive-check suites, which is right --
they were earned there. What is proved here is the move itself: one
implementation, reachable from both names, with the bare-LF and repeated-header
rules intact at the new address.
"""
from hx import http_text
from hx.checks.passive import _http


def test_the_old_private_names_are_the_new_public_ones():
    """A re-export, not a copy. `is` rather than `==`: two functions that
    agree today and were edited separately tomorrow are exactly the drift
    this move exists to prevent."""
    assert _http._split_head_body is http_text.split_head_body
    assert _http._header_lines is http_text.header_lines
    assert _http.header_names is http_text.header_names
    assert _http.header_values is http_text.header_values


def test_a_bare_lf_response_still_splits():
    """RFC 9112 s2.2. The version that only knew CRLF handed every
    body-searching check an EMPTY body and answered `clean` because it failed
    to read."""
    head, body = http_text.split_head_body(b"HTTP/1.1 200 OK\nX: 1\n\nhello")
    assert head == b"HTTP/1.1 200 OK\nX: 1"
    assert body == b"hello"


def test_the_first_terminator_wins():
    """A body containing CRLFCRLF must not pull the boundary back past a head
    that ended with a bare LF."""
    raw = b"HTTP/1.1 200 OK\n\nbody with \r\n\r\n inside"
    head, body = http_text.split_head_body(raw)
    assert head == b"HTTP/1.1 200 OK"
    assert body == b"body with \r\n\r\n inside"


def test_repeated_headers_all_come_back():
    """`Set-Cookie` legitimately repeats; a parser returning the first would
    check one cookie of five and report the surface clean."""
    head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2"
    assert http_text.header_values(head, "set-cookie") == ["a=1", "b=2"]
