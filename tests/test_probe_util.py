"""`hx.checks.active._probe_util`, the canary-minting and reflection-testing
helpers `reflected_input.py` would otherwise have to grow on its own.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures -- see `tests/test_probe.py`'s own note.
"""
from __future__ import annotations

from hx.checks import probe
from hx.checks.active import _probe_util


def _response(*, head: bytes = b"", body: bytes = b"") -> probe.ProbeResponse:
    return probe.ProbeResponse(status=200, head=head, body=body, outcome="ok")


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
