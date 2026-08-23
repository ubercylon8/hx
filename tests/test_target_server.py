"""The instrument, checked before anything is measured with it.

Six assertions in tests/integration/test_send_path.py are of the form "the
target server never received this request". Every one of them passes forever
if the request log records nothing -- which is the failure this file exists to
make impossible. It is in the FAST suite on purpose: it needs a loopback
socket and a few milliseconds, not a 900 MB JVM.

One test here is not about the log at all. This server CLOSES every
connection, and that is the only reason a send through Burp costs 0.27 ms
rather than 1,003 ms -- which is in turn the only reason the integration
suite's rate-limit test can trip a sub-second limit. A maintainer "fixing"
the target to keep-alive would not fail that test, it would make it vacuous,
so the close is asserted here where it costs milliseconds.
"""
from __future__ import annotations

import http.client
import json
import socket
import time

import pytest

from tests.integration import target_server as ts


@pytest.fixture
def target():
    server = ts.TargetServer("127.0.0.1")
    server.start()
    yield server
    server.stop()


def _get(server: ts.TargetServer, path: str, headers: dict | None = None):
    conn = http.client.HTTPConnection(server.host, server.port, timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def test_a_served_request_is_recorded_before_it_is_answered(target):
    status, _headers, body = _get(target, "/api/orders")
    assert status == 200
    assert json.loads(body)["orders"][0]["id"] == 1

    assert len(target.hits) == 1
    hit = target.hits[0]
    assert hit.method == "GET"
    assert hit.path == "/api/orders"
    assert hit.query == ""


def test_every_response_is_followed_by_a_close(target):
    """The property the integration suite's rate-limit test stands on.

    Burp's send call returns when the SOCKET closes, not when the response is
    complete: against a peer that holds the connection open it waits a fixed
    ~1002 ms for a FIN, which is 1,003 ms per request instead of 0.27 ms. At
    a second a send the bridge's single read loop cannot place two sends
    inside one second, and no sub-second rate limit is reachable at all.

    Read to EOF rather than trusting a header. `Connection: close` is a claim
    and the FIN is the fact -- Burp does not trust the header either -- and
    the request below is HTTP/1.1 with no Connection header of its own,
    exactly what the rig puts on the wire.
    """
    sock = socket.create_connection((target.host, target.port), timeout=5)
    chunks = []
    try:
        sock.sendall(f"GET /health HTTP/1.1\r\nHost: {target.host}\r\n\r\n"
                     .encode("iso-8859-1"))
        while True:
            data = sock.recv(4096)
            if not data:                      # FIN
                break
            chunks.append(data)
    except TimeoutError as exc:
        raise AssertionError(
            "the target held the connection open after answering; every send "
            "through Burp now costs ~1.003s and no sub-second rate limit can "
            "be tripped. See _Handler.protocol_version."
        ) from exc
    finally:
        sock.close()

    raw = b"".join(chunks)
    assert raw.startswith(b"HTTP/1.0 200 OK\r\n"), raw
    # Explicit anyway, so the byte count Burp reports is not the count of
    # everything it read until teardown.
    assert b"Content-Length: 12\r\n" in raw, raw
    assert raw.endswith(b'{"ok": true}'), raw


def test_the_routes_the_gate_should_refuse_are_recorded_too(target):
    """A log that only records the requests hx is allowed to make cannot
    witness one it was not. Every route answers and every route is logged."""
    _get(target, "/account/logout")
    conn = http.client.HTTPConnection(target.host, target.port, timeout=5)
    try:
        conn.request("POST", "/api/orders", body=b'{"total":"1.00"}',
                     headers={"Content-Type": "application/json"})
        assert conn.getresponse().status == 201
    finally:
        conn.close()

    assert [(h.method, h.path) for h in target.hits] == [
        ("GET", "/account/logout"),
        ("POST", "/api/orders"),
    ]
    assert target.hits[1].body == b'{"total":"1.00"}'


def test_a_request_header_is_recorded_verbatim(target):
    """The unmanaged-credential assertion reads Cookie back off this log."""
    _get(target, "/api/orders", {"Cookie": f"session={ts.SESSION_COOKIE_VALUE}"})
    assert target.hits[0].headers["Cookie"] == f"session={ts.SESSION_COOKIE_VALUE}"


def test_the_login_route_sets_a_cookie_worth_redacting(target):
    status, headers, _body = _get(target, "/login")
    assert status == 200
    assert headers["Set-Cookie"] == (
        f"session={ts.SESSION_COOKIE_VALUE}; Path=/; HttpOnly; SameSite=Lax")


def test_the_flaky_route_returns_the_status_it_is_asked_for(target):
    assert _get(target, "/flaky?status=500")[0] == 500
    assert _get(target, "/flaky?status=503")[0] == 503
    assert _get(target, "/flaky")[0] == 500


def test_the_slow_route_is_slow_and_can_also_be_a_five_hundred(target):
    began = time.monotonic()
    status, _headers, _body = _get(target, "/slow?ms=150&status=500")
    assert status == 500
    assert time.monotonic() - began >= 0.15


def test_an_absurd_delay_is_clamped_rather_than_honoured():
    """A typo in a query string must not wedge the suite for an hour.

    The clamp is lowered to 50 ms for this test rather than waiting out the
    5 s default: a guard whose test costs five seconds every fast run is a
    guard someone eventually deletes.
    """
    server = ts.TargetServer("127.0.0.1", max_delay_s=0.05)
    server.start()
    try:
        began = time.monotonic()
        _get(server, "/slow?ms=3600000")
        assert time.monotonic() - began < 1.0
    finally:
        server.stop()


def test_two_loopback_targets_keep_separate_logs():
    """The whole out-of-scope claim rests on this.

    127.0.0.2 is a second loopback address: a real listening server that only
    this machine can reach. An out-of-scope send that escaped the gate would
    be DELIVERED there and appear in ITS log -- which is a different and much
    stronger observation than a connection refusal, since a refusal looks
    identical whether the gate worked or the port was simply shut.
    """
    first = ts.TargetServer("127.0.0.1")
    second = ts.TargetServer("127.0.0.2")
    first.start()
    second.start()
    try:
        assert first.port != second.port or first.host != second.host
        _get(first, "/health")
        assert [h.path for h in first.hits] == ["/health"]
        assert second.hits == []
        _get(second, "/health")
        assert [h.path for h in second.hits] == ["/health"]
    finally:
        first.stop()
        second.stop()


def test_a_non_loopback_target_is_refused_by_the_constructor():
    """Nothing in this project has ever sent a request off the machine. This
    is the line that keeps a typo in a test from changing that."""
    with pytest.raises(ValueError, match="loopback only"):
        ts.TargetServer("0.0.0.0")
    with pytest.raises(ValueError, match="loopback only"):
        ts.TargetServer("192.168.1.10")


def test_stop_is_safe_on_a_server_that_never_started():
    """BaseServer.shutdown() blocks on an event only serve_forever() sets, so
    calling it on an unstarted server hangs forever -- and a teardown that
    hangs is worse than one that leaks, because pytest reports neither. The
    rig registers stop() BEFORE start(), so this path is real."""
    server = ts.TargetServer("127.0.0.1")
    server.stop()
