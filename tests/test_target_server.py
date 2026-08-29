"""The instrument, checked before anything is measured with it.

Assertion after assertion in tests/integration/test_send_path.py is of the
form "the target server never received this request" -- deliberately, because
that and "an error came back" are different claims and only the first is S4's
invariant. Every one of them passes forever if the request log records
nothing, or if the method never reached a handler, or if `hits_for` selects
nothing: those are the failures this file exists to make impossible. It is in
the FAST suite on purpose: it needs a loopback socket and a few milliseconds,
not a 900 MB JVM.

Deliberately NOT a count of those assertions. This file used to open with one
and it was wrong by three; a number that has to be re-counted by hand every
time a test is added is the same claim-that-nobody-checks the whole branch has
been removing.

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
import pathlib
import socket
import time
from urllib.parse import quote

import pytest

from hx import config, surface
from hx.checks import registry
from hx.checks.active import cors, open_redirect, path_traversal
from hx.checks.active import reflected_input, sql_error
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


def _request(server: ts.TargetServer, method: str, path: str):
    """One request by an arbitrary method, read to EOF.

    http.client refuses to read a body for HEAD, so this speaks the protocol
    directly: the point of several of the tests below is exactly what the
    server does or does not put on the wire.
    """
    sock = socket.create_connection((server.host, server.port), timeout=5)
    chunks = []
    try:
        sock.sendall(f"{method} {path} HTTP/1.1\r\nHost: {server.host}\r\n\r\n"
                     .encode("iso-8859-1"))
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    return b"".join(chunks)


def test_every_method_the_gate_can_be_asked_for_is_recorded(target):
    """The allowlist names GET, HEAD and OPTIONS; POST and DELETE are what it
    refuses. All five have to land in this log, because a request the gate
    LET THROUGH by mistake is exactly the one nobody would think to add a
    handler for -- and see the test below for what happens without one."""
    for method in ("GET", "HEAD", "OPTIONS", "POST", "DELETE"):
        _request(target, method, "/api/orders")

    assert [(h.method, h.path) for h in target.hits] == [
        (m, "/api/orders")
        for m in ("GET", "HEAD", "OPTIONS", "POST", "DELETE")
    ]


def test_a_method_with_no_handler_answers_501_and_leaves_no_trace(target):
    """The instrument's one blind spot, pinned rather than discovered later.

    BaseHTTPRequestHandler answers a method it has no `do_*` for from
    handle_one_request, which never reaches `_dispatch` -- so the request is
    answered and NOT recorded. That is the whole reason _Handler carries a
    do_* per method this suite can encounter rather than only the ones it
    expects to succeed. A method added to `method.allow` without a handler
    here would make "the target never received it" true by construction.
    """
    raw = _request(target, "PUT", "/api/orders")
    assert b" 501 " in raw, raw
    assert target.hits == [], (
        "if this ever starts recording, delete this test and the comment on "
        "_Handler.do_GET -- the blind spot it warns about would be closed")


def test_head_is_answered_without_a_body(target):
    """RFC 9110 s9.3.2, and `_reply`'s one conditional. A HEAD that carried a
    body would desynchronise any client reading by Content-Length."""
    raw = _request(target, "HEAD", "/api/orders")
    head, sep, body = raw.partition(b"\r\n\r\n")
    assert sep, raw
    assert body == b"", raw
    # The length is still ANNOUNCED, which is what makes the absence of the
    # body a protocol property rather than an empty resource.
    assert b"Content-Length: 41" in head, head


def test_hits_for_selects_by_path_and_ignores_the_query(target):
    """The integration suite takes counts off this, and a hits_for that
    answered [] would make every one of them pass forever.

    No number here on purpose: this wave wrote "six" into three separate
    comments about this one function and it was thirteen call sites each
    time."""
    _get(target, "/health")
    _get(target, "/slow?ms=1&status=200")
    _get(target, "/slow?ms=1&status=500")

    assert [h.path for h in target.hits_for("/slow")] == ["/slow", "/slow"]
    assert [h.query for h in target.hits_for("/slow")] == \
        ["ms=1&status=200", "ms=1&status=500"]
    assert len(target.hits_for("/health")) == 1
    assert target.hits_for("/api/orders") == []
    # Not a prefix match and not a substring match: `/slow` must not collect
    # a hit on `/slowest`, or a count taken from it silently includes traffic
    # from another route.
    assert target.hits_for("/slo") == []
    assert target.hits_for("/health?x=1") == []


def test_the_hints_route_puts_interim_heads_in_front_of_the_real_answer(target):
    """The exchange spec s4's 20% rule has to survive.

    A CDN in front of a failing origin sends `103 Early Hints` and then the
    origin's 500. Montoya parses the FIRST head as the response, so a status
    read off the transport is 103 and every one of the origin's 500s records
    as healthy -- which is what Sender.finalStatus exists to correct and what
    the integration suite proves end to end. This is the instrument that
    produces the exchange, checked here where it costs milliseconds.
    """
    raw = _request(target, "GET", "/hints?n=1&status=500")
    assert raw.startswith(ts.INTERIM_HEAD), raw
    after = raw[len(ts.INTERIM_HEAD):]
    assert after.startswith(b"HTTP/1.0 500 "), after
    assert after.endswith(b'{"hinted": true}'), after
    assert [(h.method, h.path) for h in target.hits] == [("GET", "/hints")]


def test_the_hints_route_emits_the_number_asked_for_and_no_more(target):
    """`n` is what makes both sides of Sender.MAX_INTERIM_HEADS reachable: a
    scan that reads the final head, and one that runs out of budget and must
    answer STATUS_UNREADABLE rather than the peer's chosen 1xx.

    The clamp is the same guard as MAX_DELAY_S -- a typo must cost a failure,
    not a wedged run -- and it is asserted rather than assumed, because a
    route that silently emitted `n` heads for any n is a route a hostile
    number controls.
    """
    for n in (0, 1, 9):
        server = ts.TargetServer("127.0.0.1")
        server.start()
        try:
            raw = _request(server, "GET", f"/hints?n={n}&status=200")
        finally:
            server.stop()
        assert raw.count(ts.INTERIM_HEAD) == n, (n, raw)
        assert raw.count(b"HTTP/1.0 200 ") == 1, raw

    server = ts.TargetServer("127.0.0.1")
    server.start()
    try:
        raw = _request(server, "GET", "/hints?n=100000")
    finally:
        server.stop()
    assert raw.count(ts.INTERIM_HEAD) == ts.MAX_HINT_HEADS, raw
    assert ts.MAX_HINT_HEADS > 8, (
        "MAX_HINT_HEADS must stay clear of Sender.MAX_INTERIM_HEADS (8) or "
        "the exhausted-scan case stops being reachable from this route")


def test_the_hints_route_can_close_without_ever_sending_a_final_head(target):
    """The CDN whose origin died after the early hints went out.

    `n` alone can only produce the ending where the scan runs out of BUDGET.
    This is the other one the whole-branch review found open: one interim
    head, then the connection ends, and `Sender.scanStatus` reported that
    1xx as the exchange's final status. The integration suite drives it
    against a real Burp; this is the instrument that produces it, checked
    where it costs milliseconds.

    The assertion that matters is the ABSENCE. A route that emitted the
    interim head and then the 500 anyway would leave the integration test
    passing for the wrong reason -- it would be measuring the budget ending
    a second time -- so the second `HTTP/` is what this counts.
    """
    raw = _request(target, "GET", "/hints?n=1&close=1")
    assert raw == ts.INTERIM_HEAD, (
        "the route sent something after the interim head, so this is not the "
        f"truncated ending: {raw!r}")
    assert raw.count(b"HTTP/") == 1, raw
    assert [(h.method, h.path) for h in target.hits] == [("GET", "/hints")]


def test_the_upgrade_route_completes_a_protocol_switch_and_stops(target):
    """The instrument for the MIRROR of the early-hints finding.

    `/hints?n=1&close=1` above is a 1xx head with nothing behind it because the
    origin died. This is a 1xx head with nothing behind it because there is
    NOTHING TO PUT THERE: RFC 9110 s15.2.2 ends HTTP at the empty line after a
    `101 Switching Protocols`, so a correct, successful upgrade and a truncated
    early hint are the same shape on the wire and only the code tells them
    apart. A scan that reads the shape rather than the code reports 599 for
    every WebSocket upgrade hx makes -- and ten of those auto-halt a run
    against a host that answered all ten correctly.

    So the byte after the head is asserted, not just the head. `0x81` is a
    WebSocket text frame, and it is what a scan that keeps hunting for a final
    status line behind the 101 would find and fail to read.
    """
    raw = _request(target, "GET", "/upgrade")
    assert raw == ts.UPGRADE_HEAD + ts.UPGRADE_FRAME, raw
    assert raw.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"), raw
    assert raw.count(b"HTTP/") == 1, (
        "a second head behind the 101 would make this the early-hints case "
        f"again rather than a completed switch: {raw!r}")
    assert raw[len(ts.UPGRADE_HEAD)] == 0x81, raw[len(ts.UPGRADE_HEAD):]
    assert [(h.method, h.path) for h in target.hits] == [("GET", "/upgrade")]


def test_the_upgrade_route_can_leave_the_head_with_nothing_at_all_behind_it(target):
    """`frame=0`: the head, and then EOF.

    The two shapes fail differently -- out of BYTES versus a byte that is not
    a status line -- so a fix measured against only one of them is measured
    against half the route.
    """
    raw = _request(target, "GET", "/upgrade?frame=0")
    assert raw == ts.UPGRADE_HEAD, raw
    assert raw.endswith(b"\r\n\r\n"), raw


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


# ---------------------------------------------------------------------------
# The vulnerable routes: the instrument the active corpus is measured with.
#
# Every assertion below is written against the CHECK'S OWN constants -- its
# probe origin, its marker host, its signature table, its traversal payload --
# rather than against a literal pasted from them. A route that stops answering
# what its check actually sends is the one failure that makes the integration
# suite's "each check found its finding" vacuous, and it costs milliseconds to
# catch here instead of a JVM to catch there.
# ---------------------------------------------------------------------------

def test_every_active_check_has_exactly_one_vulnerable_route(target):
    """The map is the contract the integration suite reads. A check added to
    the registry without a route here would be scanned against nothing and
    would answer `clean` -- indistinguishable, in a report, from a check that
    was run against something and found it sound."""
    active = {c.id for c in registry.CHECKS if c.klass != "passive"}
    assert set(ts.VULNERABLE_ROUTES) == active, (
        "every active check needs a route it can find something on, and every "
        "route here needs a check that probes it")
    for check_id, path in ts.VULNERABLE_ROUTES.items():
        status, _headers, _body = _get(target, path)
        assert status in (200, 302), (check_id, path, status)


def test_the_cors_route_reflects_an_arbitrary_origin_with_credentials(target):
    status, headers, _body = _get(
        target, ts.VULNERABLE_ROUTES["hx.active.cors"],
        headers={"Origin": cors._PROBE_ORIGIN})
    assert status == 200
    assert headers["Access-Control-Allow-Origin"] == cors._PROBE_ORIGIN
    assert headers["Access-Control-Allow-Credentials"] == "true"


def test_a_fixed_cors_route_stops_reflecting_and_nothing_else_changes(target):
    """What `fix()` has to mean for the retirement half of the retest story: a
    fixed configuration still answers, it just stops trusting an origin it
    never heard of. A route that started 404ing or erroring instead would
    retire the finding for the wrong reason."""
    target.fix("hx.active.cors")
    status, headers, body = _get(
        target, ts.VULNERABLE_ROUTES["hx.active.cors"],
        headers={"Origin": cors._PROBE_ORIGIN})
    assert status == 200
    assert json.loads(body) == {"user": "alice"}
    assert "Access-Control-Allow-Origin" not in headers
    assert "Access-Control-Allow-Credentials" not in headers


def test_fix_refuses_a_name_no_route_here_answers_for(target):
    """A typo would fix nothing and the retirement assertion that followed it
    would fail somewhere else, naming the retirement machinery."""
    with pytest.raises(ValueError, match="no vulnerable route"):
        target.fix("hx.active.corse")


def test_the_redirect_route_puts_the_markers_url_in_location_unvalidated(target):
    status, headers, _body = _get(target, f"/go?next={open_redirect._MARKER_URL}")
    assert status == 302
    assert headers["Location"] == open_redirect._MARKER_URL


def test_the_redirect_route_does_not_echo_a_value_that_is_not_a_url(target):
    """Every other active check probes `next` too. If this route echoed their
    canaries, `hx.active.reflected-input` would file a second finding on the
    same surface and the one-route-one-check attribution would be gone."""
    status, headers, body = _get(target, "/go?next=Zq7pLx3nV0aB")
    assert status == 200
    assert "Location" not in headers
    assert b"Zq7pLx3nV0aB" not in body


def test_the_search_route_reflects_its_input_unescaped(target):
    """Both halves of what `reflected_input` asks: the bare canary comes back,
    and so does one wrapped in the four metacharacters that decide whether the
    finding is Medium or Low."""
    wrapped = f'{reflected_input._META_CHARS}Zq7pLx3nV0aB{reflected_input._META_CHARS}'
    status, headers, body = _get(target, f"/search?q={quote(wrapped, safe='')}")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert wrapped.encode() in body, (
        "the wrapper came back escaped or not at all, so the escalation "
        "request can only ever produce the weaker Low finding")


def test_the_lookup_route_discloses_a_driver_error_only_for_a_broken_query(target):
    signature = sql_error._SIGNATURES[0][0]
    status, _headers, body = _get(target, "/db/lookup?id=42%27")
    assert status == 500
    assert signature.encode() in body

    status, _headers, body = _get(target, "/db/lookup?id=42")
    assert status == 200
    assert signature.encode() not in body


def test_the_lookup_route_does_not_quote_the_value_it_was_given(target):
    """A real driver message quotes the offending value, and this one must not:
    `sql_error`'s probe is a canary plus a quote, and echoing it would make
    `reflected-input` file a finding here as well."""
    _status, _headers, body = _get(target, "/db/lookup?id=Zq7pLx3nV0aB%27")
    assert b"Zq7pLx3nV0aB" not in body


def test_the_files_route_serves_the_fixtures_own_passwd_for_a_traversal(target):
    payload = quote(path_traversal._TRAVERSAL_PAYLOAD, safe="")
    status, _headers, body = _get(target, f"/files?file={payload}")
    assert status == 200
    signature = path_traversal._SIGNATURES[0][0]
    assert signature.encode() in body
    assert body.decode() == ts.FAKE_PASSWD, (
        "the traversal must be answered from FAKE_PASSWD and never from a "
        "file on the machine running this suite")


def test_the_files_route_answers_an_ordinary_name_without_echoing_it(target):
    status, _headers, body = _get(target, "/files?file=Zq7pLx3nV0aB.txt")
    assert status == 200
    assert b"Zq7pLx3nV0aB" not in body
    assert path_traversal._SIGNATURES[0][0].encode() not in body


def test_the_fixtures_passwd_is_not_the_machines(target):
    """FAKE_PASSWD is invented, and the only thing that keeps it invented is
    that nothing reads the real file. If these two are ever equal, something
    started serving the host's own account list to a payload."""
    real = pathlib.Path("/etc/passwd")
    if real.exists():
        assert real.read_text(errors="replace") != ts.FAKE_PASSWD


# ---------------------------------------------------------------------------
# The one route whose path the normaliser TEMPLATES.
#
# Every route in VULNERABLE_ROUTES is static, so `path_template == path` for
# every surface this suite builds and `hx.surface`'s normaliser never ran on
# the active corpus's own data. F1 of the whole-branch review lived in that
# blind spot. These tests are the instrument for the integration test that
# closes it, in the fast suite for the same reason the rest of this file is.
# ---------------------------------------------------------------------------

def test_the_templated_route_is_a_path_hx_surface_actually_templates():
    """The claim the whole route rests on, made against the real normaliser
    and its real defaults rather than by eye. A route whose path came back
    unchanged would leave the integration test measuring a static surface
    again -- passing, and proving nothing."""
    cfg = config.Config(name="t", client="t", scope_include=["*"])
    templated = surface.path_template(
        ts.TEMPLATED_ROUTE, preserve=frozenset(cfg.preserve_segments),
        slug_threshold=cfg.slug_threshold)
    assert templated == ts.TEMPLATED_SURFACE
    assert templated != ts.TEMPLATED_ROUTE


def test_the_templated_route_reflects_the_id_segment(target):
    status, headers, body = _get(target, ts.TEMPLATED_ROUTE)
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"12345" in body


def test_the_templated_route_answers_any_id_not_only_the_browsed_one(target):
    """Matched by shape, because every probe REPLACES that segment: a handler
    keyed on the browsed path would 404 every probe and the integration test
    would measure a refusal instead of a reflection."""
    status, _headers, body = _get(target, "/user/Zq7pLx3nV0aB/profile")
    assert status == 200
    assert b"Zq7pLx3nV0aB" in body


def test_the_templated_routes_reflection_survives_the_escalation_wrapper(target):
    """The second half of what `reflected_input` asks, exactly as
    `test_the_search_route_reflects_its_input_unescaped` asks it of `/search`
    -- except that here the value rides a PATH SEGMENT, so the route has to
    percent-decode it the way a vulnerable application would."""
    wrapped = f"{reflected_input._META_CHARS}Zq7pLx3nV0aB{reflected_input._META_CHARS}"
    status, _headers, body = _get(
        target, f"/user/{quote(wrapped, safe='')}/profile")
    assert status == 200
    assert wrapped.encode() in body


@pytest.mark.parametrize("path", [
    "/user/12345", "/user//profile", "/user/12345/profile/extra",
    "/users/12345/profile", "/user/12345/settings",
])
def test_nothing_else_reaches_the_templated_route(target, path):
    """The handler matches a shape, and a shape that matched too much would
    answer for paths other routes own -- or for a 404 this suite relies on."""
    assert _get(target, path)[0] == 404

