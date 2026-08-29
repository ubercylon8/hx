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

IT ALSO CARRIES THE RETRY HINT, AND CAN STOP REFUSING. `BridgeError.
retry_after_us` is the field `hx.policy.Limiter` populates for `rate_limited`
and the one `ProbeSender.get` now waits out, so a double that could not carry
it could not exercise the pacing at all. `refuse(..., times=1)` is the shape
a real rate limit has -- refuse, then allow once the window frees -- and it
is what lets these tests prove a wait ENDS rather than only that it happens.
The hints here are microseconds in the single thousands, so the suite pays
milliseconds for a real `time.sleep`; the two tests that need a large or a
repeated wait patch `probe.time.sleep` and read what it was asked for,
because a bound worth pinning is not worth waiting out.
"""
from __future__ import annotations

import time

import pytest

from hx.bridge import server
from hx.checks import probe


class FakeBridge:
    """A `BridgeServer.send`-shaped double: a dict back on success, a raised
    `server.BridgeError` on every refusal -- never a dict with a class key."""

    def __init__(self) -> None:
        self._header: dict | None = None
        self._body: bytes = b""
        self._refusal: tuple[str, str, object] | None = None
        self._refusals_left: int | None = None
        self.calls = 0
        self.last_req: dict | None = None
        self.last_body: bytes | None = None

    def reply(self, header: dict, body: bytes = b"") -> None:
        self._header = header
        self._body = body

    def refuse(self, cls: str, detail: str = "", *, retry_after_us=None,
               times: int | None = None) -> None:
        """Refuse with `cls`. `times=None` refuses for ever; `times=N` refuses
        the first N sends and then answers with whatever `reply` was given."""
        self._refusal = (cls, detail, retry_after_us)
        self._refusals_left = times

    def send(self, req: dict, body: bytes = b"", timeout: float = 30.0,
              *, enforce_locally: bool = True) -> dict:
        self.calls += 1
        self.last_req = req
        self.last_body = body
        if self._refusal is not None and self._refusals_left != 0:
            if self._refusals_left is not None:
                self._refusals_left -= 1
            cls, detail, hint = self._refusal
            raise server.BridgeError(
                f"{cls}: {detail}".rstrip(": "), error_class=cls,
                retry_after_us=hint)
        return {**self._header, server.BridgeServer.BODY_KEY: self._body}


def _sender(bridge):
    return probe.ProbeSender(bridge, scheme="https", host="app.test",
                             port=443, path_template="/a")


def _ok(fb: FakeBridge) -> None:
    fb.reply({"status": 200, "outcome": "ok"},
             b"HTTP/1.1 200 OK\r\nX-A: b\r\n\r\nhi")


def test_a_probe_returns_the_response_and_counts_the_request():
    fb = FakeBridge()
    _ok(fb)
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


# --- what `requests_sent` counts -------------------------------------------
#
# ISSUANCES, NOT ATTEMPTS. This pair replaces `test_a_refused_attempt_is_
# still_counted`, which encoded the opposite rule ("the budget was spent
# whether or not an answer came back") and was wrong for every gate class:
# `hx.policy.Limiter.check` increments `issued` on the ALLOW path only and
# says so in its own words -- "Refusals are not issuances and do not appear
# here" -- so a request the gate refused never left the JVM and the target
# never saw it. `check_run.requests_sent` reaches a client's report as the
# traffic hx generated, and it is also what a bounded retry would otherwise
# double-count.


@pytest.mark.parametrize("cls", [
    "scope_denied", "method_denied", "dangerous_denied", "rate_limited",
    "budget_exhausted", "halted", "not_configured",
])
def test_a_refusal_the_gate_decided_before_issuing_counts_nothing(cls):
    """Each of the seven is decided before a request is issued -- the first
    five by `Limiter`/`Policy` inside the JVM, the last two by
    `BridgeServer.send` before a frame is even written -- so none of them is
    traffic, and a report that counted them would overstate what hx put on a
    client's system."""
    fb = FakeBridge()
    fb.refuse(cls)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert s.sent == 0


@pytest.mark.parametrize("cls", [
    "transport_error", "timeout", "bridge_lost", "a_class_from_a_later_build",
])
def test_a_refusal_that_may_already_have_left_counts_as_a_request(cls):
    """The default direction, and it is deliberately the counting one. These
    three classes describe a request that reached the wire and then failed,
    and the fourth is a class this build has never seen: a rule written as an
    enumeration of what COUNTS would file every future class as free traffic,
    which is the one direction this number must not lean."""
    fb = FakeBridge()
    fb.refuse(cls)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert s.sent == 1


def test_a_response_that_did_not_come_back_whole_is_also_refused():
    # A `result` frame is not automatically a whole answer: Sender.java sets
    # outcome="status_unreadable" when the peer's status line could not be
    # read, and _http.py treats that the same way -- a gap, not proof of
    # absence. get() applies the same rule at the wire rather than handing a
    # check a response it could misread as clean. It is still a request that
    # was issued -- the peer answered it -- so it is still counted.
    fb = FakeBridge()
    fb.reply({"status": 599, "outcome": "status_unreadable"}, b"")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert exc.value.reason == "status_unreadable"
    assert s.sent == 1


# --- pacing: the one refusal class that is a request to wait ---------------


def test_a_rate_limited_probe_waits_the_hint_out_and_then_succeeds():
    """The half of the `retry_after_us` contract that was never written.

    `Limiter` refuses an over-rate request and says exactly when the window
    frees; `tests/integration/test_send_path.py::test_the_rate_limit_trips_
    and_its_retry_hint_is_true` states the contract as "the agent obeys
    `retry_after_us`". Nothing obeyed it until the probe pass became the
    first thing in the product to issue requests in a loop, and an unpaced
    loop at a production rate reports `inconclusive` for every probe after
    the `rate_rps`'th.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? A sender that raised on the
    first refusal never makes the second call, so `fb.calls` is 1 and the
    `get` raises instead of returning.
    """
    fb = FakeBridge()
    _ok(fb)
    fb.refuse("rate_limited", "rate limit 3/s", retry_after_us=1000, times=1)
    s = _sender(fb)

    started = time.monotonic()
    r = s.get("/a")

    assert r.status == 200
    assert fb.calls == 2
    assert time.monotonic() - started >= 1000 / 1_000_000
    # ONE issuance, not two. The refused attempt never left the JVM, so a
    # sender that counted attempts would report this probe as twice the
    # traffic it actually was -- which is why the counting rule above and
    # this retry are one change and not two.
    assert s.sent == 1


def test_the_wait_is_bounded_and_ends_in_a_refusal(monkeypatch):
    """A limiter that never frees must not spin. Three attempts, two waits,
    and then the refusal the check would have got anyway -- with the
    requests still counted at zero, because none of them was issued."""
    waits: list[float] = []
    monkeypatch.setattr(probe.time, "sleep", waits.append)
    fb = FakeBridge()
    fb.refuse("rate_limited", "rate limit 3/s", retry_after_us=1000)
    s = _sender(fb)

    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")

    assert exc.value.reason == "rate_limited"
    assert probe._RATE_LIMIT_ATTEMPTS == 3
    assert fb.calls == probe._RATE_LIMIT_ATTEMPTS
    assert len(waits) == probe._RATE_LIMIT_ATTEMPTS - 1
    assert s.sent == 0


def test_an_over_large_hint_is_clamped_rather_than_obeyed(monkeypatch):
    """The hint crosses a trust boundary. `Limiter` computes it as
    `WINDOW_US - elapsed` with `0 < elapsed < WINDOW_US`, so it can never
    legitimately exceed one second -- and a peer that answered with ten
    minutes would otherwise stall a scan for ten minutes per probe. The
    clamp costs nothing a real limiter would ever ask for."""
    waits: list[float] = []
    monkeypatch.setattr(probe.time, "sleep", waits.append)
    fb = FakeBridge()
    fb.refuse("rate_limited", "", retry_after_us=600_000_000)  # ten minutes
    s = _sender(fb)

    with pytest.raises(probe.ProbeRefused):
        s.get("/a")

    ceiling = probe._RETRY_CEILING_S + probe._RETRY_SLACK_S
    assert waits == [ceiling, ceiling]


@pytest.mark.parametrize("hint", [None, 0, -1, "soon"])
def test_a_rate_limit_with_no_usable_hint_is_terminal(hint):
    """The direction that spins. `Limiter` always sends a positive hint when
    it refuses for rate, so a missing, zero, negative or non-numeric one
    means something else answered -- and inventing a wait for a refusal that
    did not ask for one is how a scan loops against a peer that will never
    let it through."""
    fb = FakeBridge()
    fb.refuse("rate_limited", "", retry_after_us=hint)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert fb.calls == 1


@pytest.mark.parametrize("cls", [
    "budget_exhausted", "scope_denied", "method_denied", "dangerous_denied",
    "halted", "not_configured", "transport_error", "timeout", "bridge_lost",
    "a_class_from_a_later_build",
])
def test_no_other_class_is_retried_even_when_it_carries_a_hint(cls):
    """`rate_limited` is an ALLOWLIST of one, not a denylist. A budget that
    is spent stays spent, scope and method are deterministic policy, `halted`
    and `not_configured` are session state, and a transport failure may
    already have reached the target -- replaying that one blindly is the
    thing S6 forbids. A class this build has never seen is terminal too,
    which is what an allowlist buys."""
    fb = FakeBridge()
    fb.refuse(cls, "", retry_after_us=1000)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert fb.calls == 1


# --- the client-facing string ----------------------------------------------


def test_the_refusal_names_its_class_once():
    """OBSERVED, against a real Burp: `probe refused: rate_limited:
    rate_limited: rate limit 3/s: ...`. `BridgeError`'s message already opens
    with the class, `ProbeRefused` put the reason in front of it again, and
    `hx.scan.run` prefixes the whole thing a third time on its way into
    `check_run.reason` -- which is what a client reads in the report's
    coverage rows."""
    fb = FakeBridge()
    fb.refuse("rate_limited", "rate limit 3/s: 3 requests issued in the last second")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert str(exc.value) == (
        "rate_limited: rate limit 3/s: 3 requests issued in the last second")
    assert str(exc.value).count("rate_limited") == 1
    assert exc.value.detail == "rate limit 3/s: 3 requests issued in the last second"


def test_a_refusal_carrying_no_detail_is_just_its_class():
    """`BridgeServer.send` raises a bare `BridgeError("halted",
    error_class="halted")` for a local halt, so stripping the class prefix
    leaves the class itself -- which must become an empty detail rather than
    `halted: halted`."""
    fb = FakeBridge()
    fb.refuse("halted")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert str(exc.value) == "halted"
    assert exc.value.detail == ""


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
