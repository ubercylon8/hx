"""A loopback-only HTTP target for the integration suite.

Nothing in this project has ever sent a request off the machine, and this
module is what keeps that true while still proving the send path end to end:
`hx` needs something real to answer, so it gets a server on 127.0.0.0/8 and
nowhere else. The constructor refuses any other address rather than trusting
every future caller to pass a loopback one.

Two instances run at once. The in-scope target binds 127.0.0.1 and the
out-of-scope target binds 127.0.0.2 -- a second loopback address, reachable
from this machine and only this machine. That pairing is what makes "the
request was refused" and "the request was never issued" different claims: a
scope-denied send that escaped the gate would be DELIVERED to the second
server and appear in its log, rather than dying on a connection refusal that
looks identical whether the gate worked or the port was simply shut.

Every request is recorded BEFORE it is answered, so the assertions in
test_send_path.py can be made against what the server saw rather than against
what the bridge said.
"""
from __future__ import annotations

import functools
import json
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# The value that must never be found on disk. It stands in for a live
# production session cookie, and it is distinctive enough that a byte search
# over the whole blob tree means something. It is written in exactly one
# place: the redaction assertions and the credential assertions both import
# it, so a change here cannot leave one of them checking a stale literal.
SESSION_COOKIE_VALUE = "s3cr3t-live-session-2f9a41c0"

# `/login`'s own cookie, byte for byte: `session={SESSION_COOKIE_VALUE};
# Path=/; HttpOnly; SameSite=Lax`. Task 9 measured `hx.passive.cookie-flags`
# against it, expecting a finding the way the plan's own brief described the
# route ("no Secure, HttpOnly or SameSite"), and got `clean`: HttpOnly and
# SameSite ARE set, and the check does not demand Secure of an http:// origin
# (`cookie_flags.py`'s own comment says so -- "a Secure cookie on an http://
# origin is never sent at all"). `/login`'s exact Set-Cookie string is pinned
# elsewhere -- `tests/test_target_server.py::test_the_login_route_sets_a_
# cookie_worth_redacting` and `tests/integration/test_send_path.py`'s
# redaction assertions both match it byte for byte -- so it is not this
# route's to change. `/insecure-cookie` exists so a check with a real,
# unambiguous absence to find has one, without touching the frozen string.
FLAGLESS_COOKIE_VALUE = "s3cr3t-legacy-session-9b21fe70"

# The most /slow will ever sleep, whatever the query string says. A typo in a
# test ("ms=3600000") would otherwise wedge the suite for an hour with no
# diagnostic; five seconds is longer than any deadline this suite sets and
# still short enough that a wedged run is a failure rather than a lunch break.
# Per-server overridable, so the test for the clamp does not cost five
# seconds of every fast run.
MAX_DELAY_S = 5.0

# The most interim `103 Early Hints` heads /hints will emit, whatever `n`
# says. Same reason as MAX_DELAY_S: a typo in a query string must cost a
# failure rather than a wedged run.
#
# 16, and deliberately NOT read from Sender.MAX_INTERIM_HEADS, which is 8. The
# number under test and the number a test computes its input from must be two
# numbers -- a route that clamped to the extension's own constant would emit
# exactly as many heads as the scan tolerates however that constant moved, and
# the exhaustion case would stop being reachable without a word. 16 is enough
# for the far side of 8 with room to spare, and small enough that an absurd
# `n` is bounded well short of anything that could look like a response body.
MAX_HINT_HEADS = 16

# One interim head, byte for byte. HTTP/1.1 because a 1xx is a 1.1 feature;
# the FINAL head that follows it is HTTP/1.0, which is what makes this server
# close (see _Handler.protocol_version), and the two versions differing is
# the point rather than an oversight -- Sender.statusCodeOf reads the code out
# of any line beginning `HTTP/`, and the response a real CDN puts in front of
# a failing origin is assembled from two hops that need not agree either.
INTERIM_HEAD = (b"HTTP/1.1 103 Early Hints\r\n"
                b"Link: </static/app.css>; rel=preload; as=style\r\n\r\n")

# A SUCCESSFUL protocol switch, byte for byte. `101` is the one 1xx that is
# FINAL: RFC 9110 s15.2.2 -- the empty line below ends HTTP on this connection
# and no further status line ever follows -- so this is a complete, correct
# response with nothing missing from it, and a scan that calls "a 1xx head with
# nothing parseable behind it" unreadable calls THIS unreadable. The route
# exists so that claim can be checked against a real Burp rather than against a
# fake reply: what `statusCode()` and `toByteArray()` do with a 101 is Burp's
# behaviour, not ours to assume.
#
# The accept value is the RFC 6455 s1.3 worked example, and it is the correct
# accept for the `Sec-WebSocket-Key` the integration test sends -- a real
# handshake rather than a 101 pasted in front of a plain GET.
UPGRADE_HEAD = (b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")

# One unmasked WebSocket text frame carrying `hello` (RFC 6455 s5.2), which is
# what a server sends first on a connection it has just taken over. These bytes
# are NOT HTTP and must not be read as a status line: the byte after the head is
# 0x81, and a scan that keeps looking for a final head after a 101 finds this.
UPGRADE_FRAME = b"\x81\x05hello"


@dataclass(frozen=True)
class Hit:
    """One request, as the target server received it.

    `headers` collapses repeated field names to the last value. Nothing in
    this suite asserts on a repeated request header; if something ever does,
    it needs the raw list rather than this mapping.
    """

    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes


def _int_param(params: dict[str, list[str]], name: str, default: int) -> int:
    values = params.get(name)
    if not values:
        return default
    try:
        return int(values[0])
    except ValueError:
        return default


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 -- BaseHTTPRequestHandler's default -- and it is load-bearing.
    # It is what makes this server CLOSE the connection after every response.
    #
    # The cost of a send through Burp is decided entirely by whether the peer
    # closes. Burp's send call returns when the SOCKET closes, not when the
    # response is complete: measured on the wire, the whole response is in
    # hand in ~80 us, and against a peer that holds the connection open Burp
    # then waits a fixed ~1002 ms for a FIN it has already stopped needing
    # and closes the connection itself. Per request that is 1,003 ms against
    # a keep-alive target and 0.27 ms (p50, n=300) against one that closes.
    # There is no throttle at any level and no configuration that changes it;
    # Burp does not trust a `Connection: close` HEADER either, it waits for
    # the actual FIN. Those two are Burp's own call. Measured through this
    # rig's whole path instead -- Python, the socket, the JVM, this server,
    # and back -- the same pair is 0.57 ms p50 (n=300, min 0.33, p90 1.25)
    # and 1,004 ms p50 (n=8, min 1,003), so the bridge adds a fraction of a
    # millisecond and decides nothing. Both re-measured against Burp
    # 2026.7.3 on this machine, back to back with the rate limit configured
    # out of the way; PACED at the 3/s this rig configures, the same send
    # costs 3.1 ms p50 because every one of them is cold.
    #
    # So do not "fix" this to HTTP/1.1 keep-alive. At a second a send, one
    # bridge read loop cannot place two sends inside one second, and NO
    # `limit.rate_rps` this suite could configure could ever be exceeded --
    # which would not fail test_the_rate_limit_trips_and_its_retry_hint_is_true
    # in tests/integration/test_send_path.py, it would make it vacuous.
    # tests/test_target_server.py asserts the close directly, in the fast
    # suite, so that edit goes red rather than quiet.
    #
    # Content-Length is NOT what this line is for: _reply() sends it on every
    # response whatever the protocol version, so the byte count Burp reads
    # and the length hx records are explicit either way.
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        """Silence the stderr access log.

        The structured request log on TargetServer is the record the
        assertions read; the stderr line is the same information interleaved
        with Burp's own launcher output, in a suite where reading the output
        is how a failure gets diagnosed.
        """

    # One do_* per method this suite can encounter, and they are NOT
    # ceremony. BaseHTTPRequestHandler answers a method it has no do_* for
    # with a 501 from handle_one_request, which never reaches _dispatch and
    # therefore leaves NO HIT -- so the log would be blind precisely where it
    # matters most, on a method the gate was supposed to refuse. GET, HEAD and
    # OPTIONS are what `method.allow` permits; POST and DELETE are what it
    # forbids, and the forbidden ones are the reason this list is not just
    # GET. tests/test_target_server.py exercises all five and pins the 501
    # blind spot, so a method added to the allowlist without a handler here
    # goes red in the fast suite.
    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_OPTIONS(self):
        self._dispatch("OPTIONS")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        # Recorded BEFORE the answer. A route that raises on its way to a
        # response must still leave evidence that the request arrived --
        # "the target never received it" is the claim this log carries.
        self.server.target.record(Hit(
            method=method,
            path=parts.path,
            query=parts.query,
            headers={name: value for name, value in self.headers.items()},
            body=body,
        ))

        params = parse_qs(parts.query)
        if parts.path == "/health":
            self._reply(200, {"ok": True})
        elif parts.path == "/api/orders":
            # POST is the method the allowlist forbids. It answers 201 rather
            # than refusing: if the allowlist ever fails open, the evidence
            # should be a created order in this log, not an error a caller
            # could mistake for the gate having worked.
            self._reply(201 if method == "POST" else 200,
                        {"created": True} if method == "POST"
                        else {"orders": [{"id": 1, "total": "12.00"}]})
        elif parts.path == "/account/logout":
            # On the dangerous-path denylist, and deliberately harmless here.
            self._reply(200, {"logged_out": True})
        elif parts.path == "/login":
            self._reply(200, {"welcome": True}, extra=[
                ("Set-Cookie",
                 f"session={SESSION_COOKIE_VALUE}; Path=/; HttpOnly; SameSite=Lax"),
            ])
        elif parts.path == "/insecure-cookie":
            # A `session` cookie with NONE of the three flags
            # `hx.passive.cookie-flags` looks for -- see FLAGLESS_COOKIE_VALUE's
            # comment for why /login's own cookie cannot stand in for this.
            self._reply(200, {"welcome": True}, extra=[
                ("Set-Cookie", f"session={FLAGLESS_COOKIE_VALUE}"),
            ])
        elif parts.path == "/flaky":
            self._reply(_int_param(params, "status", 500), {"error": "upstream"})
        elif parts.path == "/hints":
            # `n` interim heads, then the real answer. This is a CDN in front
            # of a failing origin, which is the exchange spec s4's 20% rule
            # has to survive: Montoya parses the FIRST head as the response
            # and reports its 103, so a status read off the transport records
            # a healthy sample for every one of the origin's 500s and the
            # auto-halt never fires. Sender.finalStatus reads the bytes
            # instead. Written straight to the wire because
            # BaseHTTPRequestHandler has no notion of an interim response;
            # `wfile` is unbuffered (socketserver's wbufsize is 0), so these
            # heads are on the socket before _reply's are.
            for _ in range(min(_int_param(params, "n", 1), MAX_HINT_HEADS)):
                self.wfile.write(INTERIM_HEAD)
            if _int_param(params, "close", 0):
                # ...and NOTHING after them. A CDN that has already sent its
                # `103 Early Hints` when the origin behind it dies: the
                # interim head is on the wire, the final one never arrives,
                # and the connection ends. This is the shape the whole-branch
                # review found `Sender.scanStatus` reporting the 103 as final
                # for. `close=1` is what lets that be checked against a real
                # Burp rather than against a fake HttpReply -- MEASURED, with
                # only scanStatus differing between the two runs, this route
                # answered `{status: 103, outcome: 'ok'}` before the fix and
                # `{status: 599, outcome: 'status_unreadable'}` after it.
                self.wfile.flush()
                self.close_connection = True
                return
            self._reply(_int_param(params, "status", 500), {"hinted": True})
        elif parts.path == "/upgrade":
            # A protocol switch that SUCCEEDS. Written straight to the wire
            # for the same reason /hints is -- BaseHTTPRequestHandler has no
            # notion of a response that ends HTTP -- and then the connection
            # is done: there is no final head to follow, and its absence is
            # not a truncation.
            #
            # `frame=0` drops the WebSocket frame, leaving the head and
            # nothing else. Both shapes matter and they fail differently: with
            # no frame a scan runs out of BYTES behind the 101, and with one it
            # reads 0x81 as "not a status line". A fix that only covered the
            # first would still report 599 for every real upgrade.
            self.wfile.write(UPGRADE_HEAD)
            if _int_param(params, "frame", 1):
                self.wfile.write(UPGRADE_FRAME)
            self.wfile.flush()
            self.close_connection = True
            return
        elif parts.path == "/slow":
            time.sleep(min(_int_param(params, "ms", 250) / 1000.0,
                           self.server.target.max_delay_s))
            self._reply(_int_param(params, "status", 200), {"slow": True})
        else:
            self._reply(404, {"error": "no such route"})

    def _reply(self, status: int, payload: dict,
               extra: tuple[tuple[str, str], ...] = ()) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class _Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError)):
            # A peer that goes away mid-exchange: Burp dropping a connection
            # on a deadline, or a test client closing early. Both are normal
            # here and neither is a defect;
            # the default prints a full traceback to stderr, which competes
            # with the diagnostics a failing integration test actually needs.
            # Anything else still gets the loud treatment.
            return
        super().handle_error(request, client_address)


class TargetServer:
    """One loopback HTTP target, with a log of everything it received."""

    def __init__(self, host: str = "127.0.0.1",
                 max_delay_s: float = MAX_DELAY_S) -> None:
        if not host.startswith("127."):
            raise ValueError(
                f"target servers are loopback only, not {host!r}: nothing in "
                "this project has ever sent a request off the machine"
            )
        self.max_delay_s = max_delay_s
        self._hits: list[Hit] = []
        self._lock = threading.Lock()
        self._httpd = _Server((host, 0), _Handler)
        # Read by every handler through self.server. Set before any thread is
        # serving, so there is no window in which a handler sees it missing.
        self._httpd.target = self
        self.host, self.port = self._httpd.server_address[0], self._httpd.server_address[1]
        # poll_interval, not the 0.5 s default: shutdown() only returns after
        # the loop next wakes, so the default costs up to half a second per
        # teardown and this suite tears down two servers per test.
        self._thread = threading.Thread(
            target=functools.partial(self._httpd.serve_forever, poll_interval=0.05),
            name=f"target-{self.host}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Safe to call whether or not start() ever ran.

        BaseServer.shutdown() waits on an event that only serve_forever()
        sets, so calling it on a server whose thread never started blocks for
        ever. The rig registers this callback BEFORE calling start(), exactly
        so a failure during construction is cleaned up -- which makes the
        unstarted case the normal one on the unhappy path, and a teardown
        that hangs is worse than one that leaks: pytest reports neither, but
        it at least finishes after a leak.
        """
        if self._thread.is_alive():
            self._httpd.shutdown()
            self._thread.join(timeout=5)
        self._httpd.server_close()

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    def record(self, hit: Hit) -> None:
        # ThreadingHTTPServer answers each request on its own thread.
        with self._lock:
            self._hits.append(hit)

    @property
    def hits(self) -> list[Hit]:
        """A snapshot. Callers iterate it while the server may still be
        answering, and a list mutating under a comprehension is a flake that
        only ever appears on someone else's machine."""
        with self._lock:
            return list(self._hits)

    def hits_for(self, path: str) -> list[Hit]:
        """Every hit on `path`, ignoring the query string.

        The integration suite takes COUNTS off this -- "the target served
        exactly two", "the log did not move" -- so a version answering `[]`
        would make every one of them pass forever. That is why
        tests/test_target_server.py covers it in the FAST suite, where it
        costs milliseconds rather than a JVM.

        Deliberately not a count of those call sites. This file has already
        carried one such number that was wrong by three.
        """
        return [hit for hit in self.hits if hit.path == path]

    # There is deliberately no clear(). The log is the one witness this
    # project's denial assertions cannot fake, every test gets a server of its
    # own, and nothing has ever needed to erase it -- so a method whose only
    # possible effect is to empty it is a loaded gun pointed at the evidence.
