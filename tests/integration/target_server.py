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

SOME OF THESE ROUTES ARE GENUINELY VULNERABLE, and that is what they are for:
`hx.checks.active` is a corpus that SENDS, and a check that has never met a
target that answers its payload is a check nobody has run. `VULNERABLE_ROUTES`
below names one route per active check, each with a comment saying which. The
loopback rule stops being incidental at that point -- it is the only thing
between a payload and somebody else's server -- so the constructor's refusal of
any host outside 127.0.0.0/8 is now load-bearing rather than tidy, and no test
in this directory takes a hostname from anywhere but a TargetServer it built.
"""
from __future__ import annotations

import functools
import json
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

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

# ---------------------------------------------------------------------------
# The deliberately vulnerable routes, one per active check.
#
# EVERY ONE OF THEM IS ON THIS LOOPBACK SERVER AND NOWHERE ELSE. The
# constructor above refuses any host outside 127.0.0.0/8, and these routes are
# the first thing in this project that answers an ATTACK payload -- a canary, a
# quote, a traversal sequence, an arbitrary Origin. `hx.checks.active` sends
# those at whatever host the surface names, so the surface must never name
# anything but this server: the integration test browses only `origin + path`
# for the origin this fixture bound, and takes a hostname from nowhere else.
#
# ONE ROUTE ANSWERS FOR EXACTLY ONE CHECK, and the routes that are not that
# check's are deliberately mute: `/files` does not echo the name it was given,
# `/db/lookup` does not quote the value in its error, `/go` answers 200 to
# anything that is not already an absolute URL. Every active check probes every
# insertion point it declares on every surface, so a route that echoed its input
# as well as redirecting off it would file two findings and the retest
# assertions built on this map ("this route was fixed, that one was not") would
# have to disentangle which check moved. The exception is
# `hx.passive.security-headers`,
# which fires on `/search` because that route answers `text/html` and carries
# none of the headers a document should: that is real, it is stable across
# scans, and it is left alone.
#
# `VULNERABLE_ROUTES` is the browse path INCLUDING the query string, because the
# query string is load-bearing: `hx.insertion.derive` reads insertion points off
# the exemplar request, so a surface browsed without `?q=` offers a check
# nowhere to put a payload and is skipped `no_insertion_point`. The path
# template a finding is filed against is this path up to the `?`.
VULNERABLE_ROUTES: dict[str, str] = {
    "hx.active.cors": "/api/profile",
    "hx.active.open-redirect": "/go?next=/account",
    "hx.active.path-traversal": "/files?file=readme.txt",
    "hx.active.reflected-input": "/search?q=hello",
    "hx.active.sql-error": "/db/lookup?id=42",
}

# ONE ROUTE WHOSE PATH `hx.surface` WILL TEMPLATE, and the reason it is not in
# the map above. Every route in `VULNERABLE_ROUTES` is static -- not one
# carries a numeric, uuid, hex or slug segment -- so `path_template == path`
# for every surface this suite has ever built, and the normaliser never ran on
# any data the active corpus was measured against. F1 of the whole-branch
# review lived in exactly that blind spot: all five checks probed
# `surface.path_template` literally, which on a templated surface is an
# address that cannot exist, and 35 integration tests and 1262 unit tests
# stayed green.
#
# `12345` is what `hx.surface._template_segment` replaces with `{id}`, so the
# surface this produces is `/user/{id}/profile` and the exemplar request that
# proved it exists is this concrete path. The route REFLECTS the id segment,
# which makes `hx.active.reflected-input` the check that finds it -- the one
# active check that probes a `path_segment` and therefore the one whose probe
# has to substitute INTO the concrete address rather than into the template.
#
# NOT in `VULNERABLE_ROUTES` because that map is keyed by check id: it holds
# exactly one route per check and `hx.active.reflected-input` already has
# `/search`. A second entry cannot be added, and the arithmetic of the tests
# that read it -- one finding per check, 16 probes per scan -- is about that
# map rather than about this file. This route is browsed by the one test that
# names it.
TEMPLATED_ROUTE = "/user/12345/profile"

# The surface `TEMPLATED_ROUTE` normalises to, spelt once so a test asserting
# on it and the route it browses cannot drift apart.
TEMPLATED_SURFACE = "/user/{id}/profile"

# ONE ROUTE THAT CAN STOP ANSWERING, and it is TEMPLATED_ROUTE's blind spot in
# a second spelling. Every route in `VULNERABLE_ROUTES` and `TEMPLATED_ROUTE`
# answers 2xx, so no integration test had ever put a response that
# `hx.checks.active._probe_util.unanswered` reads as a REFUSAL in front of a
# check. N1 of the scoped re-review lived exactly there: a `302 Found /
# Location: /login` -- what a browser-facing application answers an
# unauthenticated request with, and every probe this build sends is
# unauthenticated -- was read as a conclusive negative by every check that had
# a point to probe, and a live `reflected-input` finding came back
# `observed = 0`, which `hx.report` renders to a client as "appears fixed;
# verify before closing". That was five checks on the re-review's own fixture,
# whose surface carried a parameter each of them accepts, and three on this
# route: `open-redirect` and `path-traversal` decline `tab` by their own name
# filters and send nothing here whatever the wall does.
#
# TWO STATES, AND THE MEASUREMENT NEEDS BOTH. While it is answering, this
# route REFLECTS `tab` into an HTML document exactly as `/search` reflects
# `q`, so `hx.active.reflected-input` files a finding against this surface.
# `TargetServer.require_login()` then puts the wall up for the rest of the run
# and the next probe of that same surface meets the 302. A wall in front of a
# surface nothing was ever found on could show that no check answers `clean`;
# it could not show what a `clean` there would have COST, which until fix
# round 6 was the retirement and is now the coverage row.
#
# NOT in `VULNERABLE_ROUTES`, for `TEMPLATED_ROUTE`'s reason: that map holds
# one route per check and `hx.active.reflected-input` already has `/search`.
# This route is browsed by the one test that names it.
LOGIN_WALL_ROUTE = "/account/summary?tab=orders"

# Where the wall sends a request it will not answer. `/login` is a route this
# server already has, so the destination is a page that exists rather than a
# dangling one, and it is RELATIVE -- what an application redirecting to its
# own login page emits, and deliberately not the absolute, off-host `Location`
# that is `hx.active.open-redirect`'s finding. Nothing in hx follows it; what
# is under test is that the status and the header are the ones a browser would
# have obeyed.
LOGIN_WALL_LOCATION = "/login"

# ONE SURFACE CAPTURED WITH A METHOD NO PROBE CAN BUILD -- the same blind spot
# a third time. Every surface the active corpus had ever been measured against
# was a GET, so no integration test had put a `state_changing` surface in
# front of a check: N2 of the scoped re-review. `hx.checks.probe.ProbeSender.
# _request_bytes` builds a GET and only a GET, and a surface's method is part
# of its identity (`hx.surface.normalise`), so `POST /api/orders` probed with
# `GET /api/orders` is a request that tested a DIFFERENT surface -- and the
# `clean` row it produced stood ready to retire this surface's findings.
# `hx.scan.run` skips it now, `not_a_get_surface`.
#
# `/api/orders` RATHER THAN A NEW ROUTE, because that route is already this
# shape and has been since the send path: it answers a POST 201 and a GET 200.
# The GET is what makes the counterfactual sharp rather than incidental -- a
# probe of this surface gets an ordinary, complete answer, so nothing but the
# method could tell hx it had addressed a different row. The query string is
# here for the reason `VULNERABLE_ROUTES` carries one: without it the four
# checks that declare insertion kinds have nowhere to put a payload and are
# skipped `no_insertion_point` whatever the method rule does, which would
# leave `hx.active.cors` as the only check the measurement could move.
STATE_CHANGING_ROUTE = "/api/orders?sku=1"


# MySQL's own wording for a query that did not parse, matching
# `hx.checks.active.sql_error._SIGNATURES`' first entry. It deliberately does
# NOT quote the value it was given, unlike the real driver message: see the
# one-route-one-check paragraph above.
MYSQL_SYNTAX_ERROR = (
    "Fatal error: Uncaught mysqli_sql_exception: You have an error in your "
    "SQL syntax; check the manual that corresponds to your MySQL server "
    "version for the right syntax to use near ''' at line 1 in "
    "/var/www/app/lookup.php:41"
)

# SYNTHETIC. Not this machine's `/etc/passwd`, not any machine's: five invented
# lines shaped like the file `hx.checks.active.path_traversal` looks for, so the
# traversal it proves is proved against a fixture's own bytes and nothing is
# ever read off the host running the suite. `root:x:0:0:` is the signature that
# check matches first.
FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/sh\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)


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
        elif parts.path == "/api/profile":
            # For `hx.active.cors`. Reflects whatever `Origin` it was sent and
            # allows credentials with it -- the High-severity shape that check
            # names, and the one a browser will actually honour.
            #
            # THE HEADER IS ONLY ABSENT WHEN THE ORIGIN IS ALLOWLISTED, which
            # is what `fix("hx.active.cors")` switches on: a fixed CORS
            # configuration does not stop answering, it stops reflecting an
            # origin it never heard of. The probe's Origin is
            # `https://hx-cors-probe.test` and is on nobody's allowlist, so the
            # fixed route answers the same 200 with no CORS header at all --
            # which is exactly what `Cors.probes` reads as clean.
            origin = self.headers.get("Origin")
            extra = []
            if origin and not self.server.target.is_fixed("hx.active.cors"):
                extra = [("Access-Control-Allow-Origin", origin),
                         ("Access-Control-Allow-Credentials", "true")]
            self._reply(200, {"user": "alice"}, extra=tuple(extra))
        elif parts.path == "/go":
            # For `hx.active.open-redirect`. `next` is one of the parameter
            # names that check's canary-first filter accepts, and an absolute
            # (or protocol-relative) value goes straight into `Location` with
            # nothing validated. A value that is not already a URL -- every
            # other check's canary and quote -- gets a plain 200 and is not
            # echoed anywhere, so only the redirect check has anything to find
            # here.
            #
            # FIXED, it validates instead of redirecting: the same
            # non-redirecting 200 an unrecognised value already gets, which is
            # the ONE response `open_redirect.probes` reads as clean (a 3xx to
            # anywhere is `inconclusive` -- see `_probe_util._NOT_AN_ANSWER`),
            # so a fixed route here answers the check rather than walling it.
            dest = params.get("next", [""])[0]
            if (dest.startswith(("http://", "https://", "//"))
                    and not self.server.target.is_fixed(
                        "hx.active.open-redirect")):
                self._reply(302, {"redirecting": True},
                            extra=(("Location", dest),))
            else:
                self._reply(200, {"redirecting": False})
        elif parts.path == "/search":
            # For `hx.active.reflected-input`. `q` comes back into an HTML
            # document with no encoding whatsoever, so the escalation request's
            # `<>"'`-wrapped canary survives intact and the finding is the
            # Medium `unescaped` one. NOT `_reply`: `json.dumps` escapes the
            # `"` in that wrapper, which would answer the check's second
            # question with a fact about JSON encoding rather than about this
            # application.
            #
            # FIXED, it stops putting the term in the document at all rather
            # than encoding it: this fixture answers the question "did this
            # input come back?", and an ENCODED reflection is a third state
            # (`reflected_input` would find the canary -- it is alphanumeric
            # and survives encoding -- and file the Low `plain` finding, so
            # the check would not answer `clean` and the fix would not read as
            # one). Dropping it is the state that makes `clean` the honest
            # answer. The page still answers 200 with the same shape.
            term = params.get("q", [""])[0]
            if self.server.target.is_fixed("hx.active.reflected-input"):
                term = "your search"
            self._reply_text(
                200, "<html><body><h1>Search</h1>"
                     f"<p>No results for {term}</p></body></html>")
        elif parts.path == "/db/lookup":
            # For `hx.active.sql-error`. A value carrying an unmatched single
            # quote -- which is the whole of that check's payload -- reaches a
            # query and the driver's own wording comes back. Any other value
            # gets a 200 that says nothing about what was asked for.
            #
            # FIXED, the parameter is bound rather than interpolated: the
            # quote reaches no query, no driver wording comes back, and the
            # route answers the ordinary 200 any other value already gets. NOT
            # a 500 without the wording -- `_probe_util.unanswered` reads a
            # 5xx as a refusal, so `sql_error` would answer `inconclusive` and
            # the fix would read as a wall.
            ident = params.get("id", [""])[0]
            if "'" in ident and not self.server.target.is_fixed(
                    "hx.active.sql-error"):
                self._reply_text(500, MYSQL_SYNTAX_ERROR,
                                 content_type="text/plain; charset=utf-8")
            else:
                self._reply(200, {"found": False})
        elif parts.path == "/files":
            # For `hx.active.path-traversal`. `file` is one of the file-shaped
            # parameter names that check probes, and a value that climbs out of
            # the intended directory and names `etc/passwd` is served -- from
            # FAKE_PASSWD, never from this machine. `parse_qs` has already
            # percent-decoded the value, which is the decode a vulnerable
            # application would do itself and the reason the check never has to
            # put a raw `../` on hx's own request line.
            #
            # FIXED, the path is confined: the traversal resolves inside the
            # intended directory and the ordinary 200 comes back with no file
            # content in it. NOT a 403 or a 404 -- both are in
            # `_probe_util._NOT_AN_ANSWER`, so `path_traversal` would answer
            # `inconclusive` and the fix would be indistinguishable from a
            # wall, which is the very confusion `require_login` exists to
            # keep separate.
            name = params.get("file", [""])[0]
            if ("../" in name and name.endswith("etc/passwd")
                    and not self.server.target.is_fixed(
                        "hx.active.path-traversal")):
                self._reply_text(200, FAKE_PASSWD,
                                 content_type="text/plain; charset=utf-8")
            else:
                # Deliberately does not echo `name`: see the one-route-one-check
                # paragraph beside VULNERABLE_ROUTES.
                self._reply(200, {"served": True})
        elif parts.path == "/account/summary":
            # THE LOGIN WALL -- see LOGIN_WALL_ROUTE. Two states, and the
            # switch between them is one way (`TargetServer.require_login`).
            #
            # Answering, it is `/search` with a different parameter name: `tab`
            # comes back into an HTML document with no encoding, which is what
            # gives `hx.active.reflected-input` a finding to file here before
            # the wall goes up. NOT `_reply`, for the reason `/search` gives.
            #
            # Walled, it reflects NOTHING. A 302 whose body carried the canary
            # back would be a candidate, and a candidate wins over a gap in
            # `_probe_util.verdict` -- so the finding would stay live because
            # it was re-found rather than because the redirect was read as a
            # refusal, and the test would pass while measuring the wrong
            # sentence.
            if self.server.target.login_required():
                self._reply(302, {"login_required": True},
                            extra=(("Location", LOGIN_WALL_LOCATION),))
            else:
                tab = params.get("tab", [""])[0]
                self._reply_text(
                    200, "<html><body><h1>Account</h1>"
                         f"<p>Showing {tab}</p></body></html>")
        elif self._templated_id(parts.path) is not None:
            # For `hx.active.reflected-input`, through a PATH SEGMENT rather
            # than a query parameter -- see TEMPLATED_ROUTE's own comment for
            # why this route is not in VULNERABLE_ROUTES.
            #
            # `unquote` is the decode a vulnerable application does itself,
            # exactly as `parse_qs` does it for `/files` and `/search`:
            # `reflected_input` percent-encodes every value that rides the
            # request line, so without it the escalation's `<>"'` wrapper
            # would come back as `%3C%3E%22%27` and answer a question about
            # encoding rather than about this application. NOT `_reply`, for
            # the reason `/search` gives: `json.dumps` would escape the `"`.
            ident = unquote(self._templated_id(parts.path))
            self._reply_text(
                200, "<html><body><h1>Profile</h1>"
                     f"<p>User {ident}</p></body></html>")
        else:
            self._reply(404, {"error": "no such route"})

    @staticmethod
    def _templated_id(path: str) -> str | None:
        """The middle segment of `/user/<id>/profile`, or None for any other
        path.

        Matched by SHAPE rather than by equality with `TEMPLATED_ROUTE`,
        because the whole point of the route is that a probe replaces that
        segment with something else: a handler keyed on the literal browsed
        path would 404 every probe and the test would measure a refusal.
        """
        segments = path.split("/")
        if len(segments) != 4:
            return None
        blank, user, ident, profile = segments
        if (blank, user, profile) != ("", "user", "profile") or not ident:
            return None
        return ident

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

    def _reply_text(self, status: int, text: str, *,
                    content_type: str = "text/html; charset=utf-8",
                    extra: tuple[tuple[str, str], ...] = ()) -> None:
        """`_reply`, for a body that is not JSON and must not be escaped.

        Every route above this one answers `json.dumps(payload)`, which is
        right for them and wrong for the three vulnerable routes that have to
        put bytes on the wire EXACTLY as they were given them: a reflected
        `<>"'` wrapper, a driver's error string, a file's own content. JSON
        encoding any of those would make the response answer a question about
        encoding rather than about the application.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
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
        self._fixed: set[str] = set()
        self._login_required = False
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

    def fix(self, check_id: str) -> None:
        """Repair `VULNERABLE_ROUTES[check_id]`, for the rest of this run.

        ONE ROUTE, THE ONE THIS FIXTURE MAPS TO THIS CHECK -- not every route
        the check could find something on. `LOGIN_WALL_ROUTE` and
        `TEMPLATED_ROUTE` also reflect input and `hx.active.reflected-input`
        finds both; they are deliberately outside the map (see their own
        comments) and are untouched here, because the tests built on them are
        about a wall and a normaliser and must not move when a retest test
        calls this.

        WHAT A FIX HAS TO LOOK LIKE, and it is the same rule at all five
        routes: the route goes on ANSWERING and stops being vulnerable. A fix
        that started answering 403, 404 or 5xx would land in
        `_probe_util._NOT_AN_ANSWER`, the check would say `inconclusive`, and
        the test would be measuring a wall while claiming to measure a repair
        -- which is exactly the distinction `require_login` exists to keep
        separate. Each branch below says which shape it chose and why.

        ALL FIVE IDS ARE HONOURED, AND FOUR OF THEM WERE NOT UNTIL FIX ROUND
        6. Only `/api/profile` consulted `is_fixed`, so `fix("hx.active.
        reflected-input")` -- a name this method's own `VULNERABLE_ROUTES`
        check accepts -- changed nothing, `/search` went on reflecting, and
        the check went on filing a finding while the docstring argued at
        length that the name was checked precisely so this could not happen.
        Nothing called it with another id, so no green test was vacuous; the
        next retest test somebody wrote would have been.

        ONE DIRECTION ONLY, and there is deliberately no `unfix`. Every route
        starts vulnerable and each of these calls removes one flaw; a knob that
        could put a flaw BACK would let a test assert something about a fixed
        route and then quietly re-arm the thing it just proved gone, which is
        the shape of every vacuous retest. A run wanting the vulnerable route
        back gets a fresh server, which every test already does.

        THE NAME IS CHECKED, and it is now worth checking. A typo raises here
        rather than fixing nothing and sending the test that follows it to
        fail somewhere else entirely.
        """
        if check_id not in VULNERABLE_ROUTES:
            raise ValueError(
                f"{check_id!r} has no vulnerable route here; this fixture "
                f"knows {sorted(VULNERABLE_ROUTES)}")
        with self._lock:
            self._fixed.add(check_id)

    def is_fixed(self, check_id: str) -> bool:
        """Read by a handler thread on every request; see `fix`."""
        with self._lock:
            return check_id in self._fixed

    def require_login(self) -> None:
        """Put `LOGIN_WALL_ROUTE` behind its login wall for the rest of this
        run.

        NOT A SECOND `fix()`, and the difference is the whole point. `fix()`
        removes a flaw and the route goes on ANSWERING, which is what lets a
        check say `clean` at all. This removes the ANSWER: the flaw is
        untouched and may well still be there, and a probe that meets the 302
        has tested nothing. A build that reads the two as the same thing
        records `tested, clean` for a surface it never reached, which is N1 of
        the scoped re-review and the reason this method exists. (N1's own harm
        was a live finding retired behind that 302; no active check retires
        anything since fix round 6, and the coverage row is what is left --
        S12 forbids both.)

        ONE DIRECTION ONLY, for `fix()`'s reason, and the asymmetry bites
        harder here: a knob that could take the wall back down would let a
        test assert that a finding survived a login wall and then quietly log
        back in before the scan that had to prove it.
        """
        with self._lock:
            self._login_required = True

    def login_required(self) -> bool:
        """Read by a handler thread on every request; see `require_login`."""
        with self._lock:
            return self._login_required

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
