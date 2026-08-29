"""`hx.checks.probe`, the one route from a check to the wire.

No pytest fixtures: this project's tests use plain helper functions rather
than `conftest.py` fixtures for this kind of thing -- see
`tests/test_checks_http.py`'s `FakeBlobs`/`ctx_for`. `FakeBridge` below is
the same shape for `BridgeServer.send`.

FakeBridge REPRODUCES THE REAL SEND SHAPE, NOT THE TASK BRIEF'S DRAFT.
`BridgeServer.send()` (src/hx/bridge/server.py) returns a dict only for a
`result` frame; every refusal -- this side's own local enforcement, a
timed-out or disconnected peer, or an `error` frame from the extension --
comes back as a RAISED `BridgeError` with the wire's class on
`.error_class` (pinned by `tests/test_bridge_server.py`'s
`test_send_raises_the_peers_class_and_its_retry_hint` and neighbours). The
brief's step-3 draft has `send` return a dict carrying a `"class"` key on
refusal, which no real implementation of `send` ever produces; `FakeBridge`
matches the actual method instead so these tests exercise the real seam.
"""
from __future__ import annotations

import pytest

from hx.bridge import server
from hx.checks import probe


class FakeBridge:
    """A `BridgeServer.send`-shaped double: a dict back on success, a raised
    `server.BridgeError` on every refusal -- never a dict with a class key."""

    def __init__(self) -> None:
        self._header: dict | None = None
        self._body: bytes = b""
        self._refusal: tuple[str, str] | None = None
        self.last_req: dict | None = None
        self.last_body: bytes | None = None

    def reply(self, header: dict, body: bytes = b"") -> None:
        self._header = header
        self._body = body

    def refuse(self, cls: str, detail: str = "") -> None:
        self._refusal = (cls, detail)

    def send(self, req: dict, body: bytes = b"", timeout: float = 30.0,
              *, enforce_locally: bool = True) -> dict:
        self.last_req = req
        self.last_body = body
        if self._refusal is not None:
            cls, detail = self._refusal
            raise server.BridgeError(
                f"{cls}: {detail}".rstrip(": "), error_class=cls)
        return {**self._header, server.BridgeServer.BODY_KEY: self._body}


def _sender(bridge):
    return probe.ProbeSender(bridge, scheme="https", host="app.test",
                             port=443, path_template="/a")


def test_a_probe_returns_the_response_and_counts_the_request():
    fb = FakeBridge()
    fb.reply({"status": 200, "outcome": "ok"},
             b"HTTP/1.1 200 OK\r\nX-A: b\r\n\r\nhi")
    s = _sender(fb)
    r = s.get("/a?q=1")
    assert r.status == 200 and r.body == b"hi"
    assert probe._http.header_values(r.head, "x-a") == ["b"]
    assert s.sent == 1


@pytest.mark.parametrize("cls", [
    "budget_exhausted", "halted", "rate_limited", "scope_denied",
    "method_denied", "dangerous_denied", "transport_error", "timeout",
    "bridge_lost", "not_configured",
])
def test_every_refusal_raises_and_names_itself(cls):
    fb = FakeBridge()
    fb.refuse(cls)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert exc.value.reason == cls


def test_a_refused_attempt_is_still_counted():
    # The budget was spent whether or not an answer came back, and a
    # requests_sent that undercounts refusals understates the traffic this
    # tool put on a client's system.
    fb = FakeBridge()
    fb.refuse("rate_limited")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert s.sent == 1


def test_a_response_that_did_not_come_back_whole_is_also_refused():
    # A `result` frame is not automatically a whole answer: Sender.java sets
    # outcome="status_unreadable" when the peer's status line could not be
    # read, and _http.py treats that the same way -- a gap, not proof of
    # absence. get() applies the same rule at the wire rather than handing a
    # check a response it could misread as clean.
    fb = FakeBridge()
    fb.reply({"status": 599, "outcome": "status_unreadable"}, b"")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert exc.value.reason == "status_unreadable"


def test_the_sender_only_ever_issues_GET():
    # S7: the method allowlist is GET/HEAD/OPTIONS and Config carries no
    # method key. A sender that could emit POST would be refused by the
    # extension anyway -- this pins that hx does not even try.
    fb = FakeBridge()
    fb.reply({"status": 200, "outcome": "ok"}, b"HTTP/1.1 200 OK\r\n\r\n")
    s = _sender(fb)
    s.get("/a")
    assert fb.last_body.startswith(b"GET ")


def test_the_sender_cannot_be_pointed_at_another_host():
    # A check receives a sender already bound to its surface. Redirect
    # following and cross-host probing are both out of reach by construction,
    # not by convention.
    fb = FakeBridge()
    s = _sender(fb)
    assert not hasattr(s, "host")
    with pytest.raises(ValueError):
        s.get("https://evil.test/a")
