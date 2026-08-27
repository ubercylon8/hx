"""S4's SECOND enforcement point, against a real Burp.

Everything before Task 9 was fakes and unit tests. `ProxyGate` was driven with
hand-built requests, `Recorder` with hand-built bytes, `Capture` with hand-built
frames -- and not one of those can see whether the Montoya handler that holds
them together actually HONOURS what they decide. `if (!verdict.allow() && false)`
is green in the entire Java suite. Only a browser, a proxy listener and a target
server that keeps its own log can say otherwise.

THREE RULES THIS FILE IS WRITTEN UNDER, each bought with a finding.

  1. A REFUSAL IS COUNTED AT THE TARGET, NEVER AT THE CLIENT. Burp answers a
     dropped request `HTTP/1.1 200 OK` with 1529 bytes of its own HTML
     (measured in test_proxy_facts.py, Q3), so a drop and a delivery are
     INDISTINGUISHABLE by status code. A test reading the client's response
     proves nothing and is the shape that sails through review. Where the
     client's 200 appears below it is pinned as the TRAP, next to the target
     assertion that is the actual evidence.

  2. THE RECORD ARRIVES AFTER THE RESPONSE, so every row is POLLED. Measured:
     browsing five times and reading the table the instant each client response
     completed gave 1, 1, 2, 3, 4 rows -- the capture frame crosses the bridge
     on its own thread, behind the browser. A test that read the table once
     would flake in the direction of "no row".

  3. A SINK THAT THROWS IS SILENT BY DESIGN. `BridgeServer._capture` catches
     everything the sink raises, keeps the channel, and files the loss as a
     `dropped` frame -- S4: a lost record changes what hx KNOWS, never what it
     ALLOWS. The observable of a broken sink is therefore a healthy Burp, a
     green handshake, traffic flowing, and an EMPTY DATABASE. So every wait
     below reports `exchange_errors` and `exchange_callback_error` on timeout,
     because the natural diagnosis of that state is to blame the extension.
"""
from __future__ import annotations

import os
import socket
import time

import pytest

from tests.integration.target_server import SESSION_COOKIE_VALUE

pytestmark = pytest.mark.integration

# Long enough for a frame that crosses a Unix socket in under a millisecond
# once the response is complete (measured: the row was on disk 50 ms after the
# client's response on every run taken here), short enough that a wedged
# extension is a failure in seconds rather than a stalled suite.
SETTLE_S = 10.0

# What Burp answers a client whose request it dropped. NOT evidence of
# anything: a DELIVERED request returns 200 too. It is asserted where it
# appears so that the trap is pinned rather than merely avoided -- if a future
# Burp ever answers something a client CAN tell apart, that is a better world
# and this is where it shows up. test_proxy_facts.py pins the byte count.
DROP_LOOKS_LIKE = 200


def browse(rig, path, *, port=None, method="GET", to=None, headers=(),
           body=b"", timeout=30.0) -> bytes:
    """One request through Burp's proxy, and the whole response off the wire.

    The FORWARD-PROXY form: the request line carries the absolute URI, which is
    how a browser configured to use a proxy addresses one and how the
    destination reaches Burp at all. The `Host` line is set to match only so
    the target server sees a well-formed request.

    Raw sockets rather than `http.client` for the same reason
    `test_proxy_facts._Probe.raw_through_proxy` uses them: the byte count of
    the FULL response is half of what a drop is recognised by, and no
    http.client API exposes it. Reading to EOF is bounded twice over -- the
    socket timeout above, and Burp closing the connection itself.

    `port` defaults to the OPERATOR listener. The crawler's is `rig.crawler_port`
    and the difference between them is the whole of S4's source attribution.
    """
    dest = to or rig.target
    lines = [f"{method} {dest.origin}{path} HTTP/1.1",
             f"Host: {dest.host}:{dest.port}",
             "Connection: close"]
    lines += [f"{name}: {value}" for name, value in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    # ISO-8859-1 for the same reason Sender.parse reads it that way: HTTP field
    # values are octets, and one octet is one char here.
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + body
    sock = socket.create_connection(("127.0.0.1", port or rig.proxy_port),
                                    timeout=timeout)
    try:
        sock.sendall(raw)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


def status_of(raw: bytes) -> int:
    """The status code off a raw response, or -1 when there is no head at all.

    -1 rather than an exception: a connection that produced nothing is a
    measurement (Burp closed on us), and it belongs in the assertion's message
    beside the target's log rather than as a traceback three frames up.
    """
    head = raw.split(b"\r\n", 1)[0]
    if not head.startswith(b"HTTP/"):
        return -1
    try:
        return int(head.split()[1])
    except (IndexError, ValueError):
        return -1


def rows(rig, sql: str, args=()) -> list[dict]:
    return [dict(row) for row in rig.eng.db.execute(sql, args).fetchall()]


def settle(rig, predicate, what: str, timeout: float = SETTLE_S) -> None:
    """Wait for a row to arrive, and say WHY it did not if it never does.

    The message is the point. A sink that raises produces exactly the same
    observable as an extension that sent nothing -- an empty table -- and the
    two have opposite fixes. `exchange_errors` and `exchange_callback_error`
    are the only things on this side that can tell them apart, so they are in
    every timeout message rather than left for whoever is debugging to find.
    """
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return
        time.sleep(0.1)
    pytest.fail(
        f"{what} never arrived within {timeout}s. This side's sink failed "
        f"{rig.srv.exchange_errors} time(s), last: "
        f"{rig.srv.exchange_callback_error!r}. A sink that throws is caught, "
        "counted and swallowed by BridgeServer._capture -- deliberately -- so "
        "an empty table is what a BROKEN HARNESS looks like as well as a "
        "silent extension. Read that number before reading Burp's log at "
        f"{rig.workdir / 'burp' / 'burp.log'}. Target log: "
        f"{[(h.method, h.path) for h in rig.target.hits]}")


def blob_tree(rig) -> list[bytes]:
    """Every byte of every blob this engagement holds.

    Wider than the two digests an exchange row names, deliberately: the claim
    in S7 is that a live credential is not IN THE STORE, and a leak that landed
    under some other digest -- a second copy of the request, a retry, a frame
    this test did not think of -- would satisfy a two-blob check completely.
    """
    root = rig.eng.root / "blobs"
    return [path.read_bytes() for path in root.rglob("*")
            if path.is_file() and path.parent.name != "tmp"]


# ---------------------------------------------------------------------------
# 1. The happy path: a browse becomes a row, and the bytes are on disk.
# ---------------------------------------------------------------------------

def test_an_in_scope_browse_becomes_an_exchange_row_with_both_blobs(rig):
    """The whole capture path, end to end, for the first time.

    Every component below was tested alone against a fake. This is the first
    time a real browser's request crosses a real Burp, a real proxy listener,
    a real extension, a real Unix socket and `hx.capture` into a real database.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? Measured, by deleting the
    `on_exchange=` sink from the rig -- the state this rig was in before Task 9,
    where BridgeServer reads Plan 4's frames and discards them: the exchange
    row never appears and `settle` fails naming the empty table. The blob
    assertions are not decoration either -- `blobs.get` verifies the digest and
    the length it was stored under, so a row naming bytes that are not there,
    or are not the bytes the digest claims, raises CorruptBlob rather than
    passing.
    """
    assert rig.configure() == 1

    response = browse(rig, "/api/orders")
    assert status_of(response) == 200

    # The target's own log FIRST. "hx recorded an exchange" and "the request
    # was actually delivered" are different claims, and only this one can say
    # the second -- the row is written from what the extension observed, so a
    # row proves the extension saw something, not that a server answered.
    assert [(hit.method, hit.path) for hit in rig.target.hits] \
        == [("GET", "/api/orders")]

    settle(rig, lambda: rows(rig, "SELECT id FROM exchange"), "the exchange row")
    row = rows(rig, "SELECT * FROM exchange")[0]

    assert row["method"] == "GET"
    assert row["url"] == f"{rig.target.origin}/api/orders"
    assert row["status"] == 200
    # 'proxy', not 'send'. `record_exchange` DEFAULTS to 'send' -- every call
    # site that predates Plan 4 is one of those -- so this column is what says
    # the row came from the second enforcement point rather than the first.
    assert row["via"] == "proxy"
    assert row["outcome"] == "ok"
    # The back-reference `hx.capture` writes in the same transaction as the
    # row. A NULL here is unrecoverable afterwards and is what every coverage
    # query joins on.
    assert row["surface_id"] is not None

    request_bytes = rig.eng.blobs.get(row["req_blob"])
    response_bytes = rig.eng.blobs.get(row["resp_blob"], row["resp_len"])
    assert request_bytes.startswith(b"GET /api/orders HTTP/1.1\r\n")
    assert b'{"orders": [{"id": 1, "total": "12.00"}]}' in response_bytes

    # 0o600 on the live path, not only in the blob store's own unit tests.
    # These files hold a client's traffic; an engagement directory is 0o700 and
    # what is inside it gets no less.
    for digest in (row["req_blob"], row["resp_blob"]):
        mode = os.stat(rig.eng.blobs.path_for(digest)).st_mode & 0o777
        assert mode == 0o600, f"blob {digest} is mode {mode:o}"


# ---------------------------------------------------------------------------
# 2. P14: does the handler HONOUR its verdict?
# ---------------------------------------------------------------------------

def test_an_out_of_scope_browse_never_reaches_the_target(rig):
    """P14, which five fix rounds could not close. Settled here, or nowhere.

    `ProxyGate` decides. `HxExtension.handleRequestReceived` acts. NO UNIT TEST
    CAN SEE THE SECOND: `if (!verdict.allow() && false)` leaves the whole Java
    suite green, because every test there drives the gate directly and reads
    the Verdict it returns. What the Montoya handler then does with that
    Verdict is invisible to all of them.

    THE ASSERTION IS THE TARGET SERVER'S LOG. It cannot be the client's
    response: Burp answers a dropped request `200 OK` with 1529 bytes of its
    own HTML, so a drop and a delivery are the same status code (Q3 in
    test_proxy_facts.py). The 200 is asserted below as the TRAP -- so that this
    file records why the client is not the witness -- and never as evidence.

    THREE CONTROLS, because "the log did not move" is satisfied by a great many
    things that are not enforcement:

      - the offside server is hit DIRECTLY first, so its log is a log that
        provably CAN move and provably IS being recorded. Without this, a
        target that had failed to start, or a `record()` that had stopped
        appending, passes this test forever;
      - an IN-SCOPE request goes through the SAME listener, so the proxy path
        is known to be carrying traffic at the moment the refusal is measured.
        A Burp that dropped everything -- an unconfigured extension, a jar that
        failed to load -- would otherwise satisfy the refusal completely;
      - the denial ROW is asserted, so "nothing arrived" is separated from
        "hx refused it". A connection Burp simply failed to make looks
        identical at the target and leaves no row.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? Measured, with
    `if (!verdict.allow())` changed to `if (!verdict.allow() && false)` in
    `HxExtension.handleRequestReceived` and the jar rebuilt: the offside target
    logged the request, and this test failed on the line below rather than on
    the row. That mutation is green in all 13 Java suites.
    """
    assert rig.configure() == 1

    # Control 1: the offside log moves when something reaches it.
    direct = socket.create_connection((rig.offside.host, rig.offside.port),
                                      timeout=10)
    try:
        direct.sendall(b"GET /health HTTP/1.1\r\n"
                       b"Host: " + rig.offside.host.encode() + b"\r\n"
                       b"Connection: close\r\n\r\n")
        while direct.recv(65536):
            pass
    finally:
        direct.close()
    assert [(h.method, h.path) for h in rig.offside.hits] == [("GET", "/health")]

    # Control 2: this listener is carrying traffic right now.
    assert status_of(browse(rig, "/health")) == 200
    assert rig.target.hits_for("/health"), \
        "the in-scope control never reached the target, so the refusal below " \
        "would be satisfied by a proxy that is not working at all"

    # The measurement. 127.0.0.2 is out of scope -- the engagement's
    # `scope.include` is the 127.0.0.1 target's origin and nothing else -- and
    # it is LISTENING throughout, so a refusal that merely failed to forward is
    # separable from one that stopped the bytes.
    before = len(rig.offside.hits)
    refused = browse(rig, "/health?out-of-scope=1", to=rig.offside)

    settle(rig, lambda: rows(rig, "SELECT id FROM denial WHERE via='proxy'"),
           "the denial row")
    # Settled, then given the same window again: the denial arriving proves the
    # extension decided, not that the bytes stayed put. A request that leaked
    # would reach a loopback server well inside this.
    time.sleep(0.5)

    assert len(rig.offside.hits) == before, (
        "THE VERDICT WAS NOT HONOURED. The out-of-scope target received "
        f"{[(h.method, h.path) for h in rig.offside.hits[before:]]}. The "
        "extension refused this request -- there is a denial row for it -- and "
        "the bytes went out anyway, which is the one failure this enforcement "
        "point exists to prevent.")

    denial = rows(rig, "SELECT * FROM denial WHERE via='proxy'")[0]
    assert denial["kind"] == "scope"
    assert denial["method"] == "GET"
    assert denial["url"] == f"{rig.offside.origin}/health?out-of-scope=1"
    assert denial["via"] == "proxy"

    # THE TRAP, pinned rather than avoided. This 200 is Burp's own error page
    # and says nothing whatsoever about whether the request was delivered --
    # the in-scope control above returned 200 as well, and it WAS delivered.
    assert status_of(refused) == DROP_LOOKS_LIKE, (
        f"a dropped request now draws {status_of(refused)} from Burp rather "
        f"than {DROP_LOOKS_LIKE}. That is a NEW MEASUREMENT and possibly a "
        "better world -- a status a client can tell apart from a delivery "
        "would make a whole class of test honest. Re-measure Q3 in "
        "test_proxy_facts.py and docs/burp-proxy-measurements.md together.")


# ---------------------------------------------------------------------------
# 3. One endpoint, two ids, one surface.
# ---------------------------------------------------------------------------

def test_two_ids_under_one_endpoint_are_one_surface(rig):
    """S5's "identity is the TEMPLATE" on real captured traffic.

    `hx.surface.normalise` has its own unit tests and they hand it strings. This
    is the first time the string comes off a real request that a real browser
    made through a real proxy -- which is where the URL's exact spelling stops
    being this project's choice. Burp rewrites the request line from the
    absolute form the client sent to the origin form, and `r.url()` is what the
    extension puts on the wire; if those two ever disagreed about the path, the
    template would be derived from something no test here composed.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? Two exchanges are asserted
    alongside the one surface, and that pairing is the whole guard: a
    normaliser that templated nothing gives 2 surfaces and 2 exchanges, one
    that over-templated gives 1 and 2 with the wrong template, and a capture
    path that recorded nothing at all gives 0 and 0. Only the intended
    behaviour gives 1 surface, 2 exchanges and `/api/orders/{id}`.
    """
    assert rig.configure() == 1

    for order_id in (1, 2):
        assert status_of(browse(rig, f"/api/orders/{order_id}")) == 404, \
            "the target has no such route, which is fine -- a 404 is an " \
            "exchange like any other and the surface is about the URL"

    settle(rig, lambda: len(rows(rig, "SELECT id FROM exchange")) == 2,
           "both exchange rows")

    urls = sorted(row["url"] for row in rows(rig, "SELECT url FROM exchange"))
    assert urls == [f"{rig.target.origin}/api/orders/1",
                    f"{rig.target.origin}/api/orders/2"], \
        "two distinct requests must stay two exchanges -- the merge is a " \
        "property of the SURFACE, never of the evidence"

    surfaces = rows(rig, "SELECT * FROM surface")
    assert len(surfaces) == 1, \
        f"one endpoint became {len(surfaces)} surfaces: " \
        f"{[s['path_template'] for s in surfaces]}"
    assert surfaces[0]["path_template"] == "/api/orders/{id}"
    assert surfaces[0]["method"] == "GET"
    assert surfaces[0]["host"] == rig.target.host
    assert surfaces[0]["port"] == rig.target.port
    # The proxy discovered it, not the crawler and not an agent's own send.
    # S5 draws a coverage figure straight off this column.
    assert surfaces[0]["discovered_by"] == "proxy"

    # The exemplar is the FIRST exchange that proved the surface exists, and it
    # is not rewritten by the second sighting -- otherwise "show me an example
    # of this endpoint" answers with whatever happened most recently.
    first = rows(rig, "SELECT id FROM exchange ORDER BY sent_us, rowid")[0]
    assert surfaces[0]["exemplar_exchange_id"] == first["id"]


# ---------------------------------------------------------------------------
# 4. S7 on the live path, in both directions.
# ---------------------------------------------------------------------------

def test_a_live_cookie_reaches_the_target_and_never_the_blob_store(rig):
    """S7's rule where it finally matters: real bytes, real store, real disk.

    TWO DIRECTIONS, because they are two functions and the pairing of each to
    its own message is the defect `Recorder` was extracted to prevent -- found
    three times, green every time. `redactObservedRequest` matches the request's
    `Cookie`; `redactResponse` matches the response's `Set-Cookie`. Each returns
    a message it does not recognise VERBATIM, which is correct for a message
    with nothing to redact and a total leak for a message handed to the wrong
    one. Swap them and both halves leak while every structural check stays
    green.

    THE REQUEST DIRECTION IS THE HOLE FIVE FIX ROUNDS CLOSED. The proxy path
    once redacted the request with `redactRequest` and an empty
    `Redactor.Injected`, which is `return raw.clone()` -- the operator's live
    session cookie into a content-addressed store, verbatim, where the digest
    already names the bytes and no later pass can take it back.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? Measured, with
    `Recorder.record` changed to hand back `rawRequest`/`rawResponse`
    unredacted and the jar rebuilt: the cookie value was found in the blob tree
    and this test failed on the scan below. THREE separate guards make it
    non-vacuous, and each was chosen because the leak it rules out passes the
    others:

      - the TARGET's log must contain the real value, so the cookie provably
        travelled. A test that only searched for absence passes perfectly
        against a request that never carried a cookie at all;
      - the PLACEHOLDERS must be present, so an empty, truncated or missing
        blob cannot satisfy the absence;
      - the search is over the WHOLE blob tree, not the two digests this row
        names, so a copy stored under any other digest is caught.
    """
    assert rig.configure() == 1

    sent = f"session={SESSION_COOKIE_VALUE}"
    assert status_of(browse(rig, "/login", headers=[("Cookie", sent)])) == 200

    # Guard 1: the value really was on the wire, in both directions. /login
    # answers with a Set-Cookie carrying the same value.
    hits = rig.target.hits_for("/login")
    assert [hit.headers.get("Cookie") for hit in hits] == [sent], \
        "the request never carried the cookie, so its absence downstream " \
        "proves nothing at all"

    settle(rig, lambda: rows(rig, "SELECT id FROM exchange"), "the exchange row")
    row = rows(rig, "SELECT * FROM exchange")[0]
    request_bytes = rig.eng.blobs.get(row["req_blob"])
    response_bytes = rig.eng.blobs.get(row["resp_blob"], row["resp_len"])

    # Guard 2: the placeholders are there, so absence is redaction rather than
    # an empty blob. They are FIXED strings and that is a requirement, not a
    # style: the store is content-addressed, so a hash or a length here would
    # give one page browsed under two sessions two different digests.
    assert b"Cookie: {{observed:cookie}}" in request_bytes, request_bytes
    assert b"{{observed:set-cookie}}" in response_bytes, response_bytes

    needle = SESSION_COOKIE_VALUE.encode()
    assert needle not in request_bytes
    assert needle not in response_bytes

    # Guard 3: the whole tree, not the two digests above.
    leaked = [blob for blob in blob_tree(rig) if needle in blob]
    assert leaked == [], (
        f"{len(leaked)} blob(s) in {rig.eng.root / 'blobs'} contain a live "
        "session cookie. The store is CONTENT-ADDRESSED: the digest was "
        "computed over these bytes, so this is not recoverable by redacting "
        f"afterwards. First: {leaked[0][:200]!r}")


# ---------------------------------------------------------------------------
# 5. The operator/crawler split, end to end.
# ---------------------------------------------------------------------------

def test_the_operator_listener_allows_the_post_the_crawler_listener_refuses(rig):
    """S4's split: one request, two listeners, two answers.

    NOTHING SHORT OF TWO REAL LISTENERS PROVES IT. The rule is that the source
    is a property of the CONNECTION -- `Source.forListenerPort`, fed from
    `InterceptedRequest.listenerInterface()` -- and never of anything in the
    traffic, because a header can be forged by a hostile page and a page that
    could make its requests look human-driven would dodge the crawler's rules
    entirely, the dangerous-path denylist included. A fake can hand
    `forListenerPort` two ints; only Burp can put the same bytes on two ports.

    THE OPERATOR IS NOT METHOD-CHECKED, DELIBERATELY. `ProxyGate` asks Policy
    for SCOPE ONLY on that branch: a human clicking a form is a deliberate act
    by the person legally responsible for the engagement, and refusing their
    login POST drives them off the proxy -- at which point hx records nothing
    at all. The crawler gets the full order, method allowlist included.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? Measured, by removing
    `-Dhx.crawler_port` from `launch_burp`: `Source.forListenerPort` reads the
    absent property's 0 as "no crawler configured", attributes EVERY request to
    the operator however many listeners are running, the crawler's POST is
    delivered, and this test fails on the target's log below. That is the
    precise shape of the `-Dhx.halt_sentinel` incident one plan earlier, and it
    is why the property is passed from the config file Burp was handed rather
    than from an argument that could drift from it.
    """
    assert rig.configure() == 1

    # The operator's POST. Allowed -- scope, and nothing after it.
    operator = browse(rig, "/api/orders", method="POST", body=b'{"item": 1}')
    assert status_of(operator) == 201, \
        "the operator branch must not be method-checked; 201 is the target's " \
        "own answer and 200 would be Burp's drop page"

    settle(rig, lambda: rows(rig, "SELECT id FROM exchange WHERE method='POST'"),
           "the operator's POST exchange")

    # The SAME request on the OTHER port. Refused: the crawler gets the agent's
    # rules in full and POST is not in `method.allow`.
    before = rig.target.hits_for("/api/orders")
    crawler = browse(rig, "/api/orders", method="POST", body=b'{"item": 1}',
                     port=rig.crawler_port)

    settle(rig, lambda: rows(rig, "SELECT id FROM denial WHERE kind='method'"),
           "the crawler's method denial")
    time.sleep(0.5)          # the same window again, for bytes in flight

    after = rig.target.hits_for("/api/orders")
    assert [hit.method for hit in after] == [hit.method for hit in before], (
        "the crawler's POST reached the target: the log went from "
        f"{[h.method for h in before]} to {[h.method for h in after]}. Either "
        "the listener was attributed to the operator -- check "
        "-Dhx.crawler_port against the second listener in "
        f"{rig.workdir / 'burp' / 'proxy-listeners.json'} -- or the handler "
        "did not honour its verdict.")
    assert [hit.method for hit in after].count("POST") == 1, \
        "exactly one of the two POSTs may have been delivered"

    denial = rows(rig, "SELECT * FROM denial WHERE kind='method'")[0]
    assert denial["method"] == "POST"
    assert denial["via"] == "proxy"

    # The two answers land on two RUNS, which is the same distinction one level
    # up: `hx.capture._run` maps source -> kind, and attributing crawler
    # traffic to a browse run would make the denial rows lie about who was
    # driving.
    kinds = {row["id"]: row["kind"] for row in rows(rig, "SELECT id, kind FROM run")}
    exchange_run = rows(rig, "SELECT run_id FROM exchange WHERE method='POST'")[0]
    assert kinds[exchange_run["run_id"]] == "browse"
    assert kinds[denial["run_id"]] == "crawl"

    # And the trap again: the refused POST drew a 200, the allowed one a 201.
    # The client can tell those apart only because the target chose 201 for a
    # created order; had it answered 200, the two responses would differ in
    # nothing a client could act on.
    assert status_of(crawler) == DROP_LOOKS_LIKE


# ---------------------------------------------------------------------------
# 6. The run that opens itself.
# ---------------------------------------------------------------------------

def test_the_first_exchange_opens_a_browse_run_of_its_own(rig):
    """Auto-open, on the live path, and it does NOT adopt the rig's run.

    `run.current_run` is per-KIND: a run of a different kind does not satisfy
    the call, because a crawl running while you browse is two runs and the
    enforcement rules differ by exactly that distinction. The rig hand-inserts
    a `manual` run for the send-path tests to hang their rows off, so this is
    the case where that rule is visible -- the `manual` row is live, and a
    `browse` frame opens a second run anyway.

    That is CORRECT, and it is worth pinning precisely because it looks like a
    bug: a reader finding two running runs after one request will want to
    "fix" the rig by making capture adopt whichever run is open. Doing so would
    file a crawler's traffic under a human's run the first time both are live.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? The three assertions are chosen so
    that each plausible wrong behaviour reddens one of them: adopting the
    `manual` run gives one run and a non-'browse' kind; opening a run per
    request gives three runs for two requests; and a capture path that never
    ran leaves `requests_issued` at 0 on every row.
    """
    assert rig.configure() == 1

    manual = rows(rig, "SELECT * FROM run WHERE id=?", (rig.run_id,))[0]
    assert manual["kind"] == "manual" and manual["requests_issued"] == 0

    assert status_of(browse(rig, "/health")) == 200
    assert status_of(browse(rig, "/api/orders")) == 200

    settle(rig, lambda: len(rows(rig, "SELECT id FROM exchange")) == 2,
           "both exchange rows")

    opened = rows(rig, "SELECT * FROM run WHERE kind='browse'")
    assert len(opened) == 1, \
        f"two requests opened {len(opened)} browse runs; one browsing session " \
        "is one run until it goes idle"
    run = opened[0]
    assert run["id"] != rig.run_id
    assert run["status"] == "running"
    assert run["requests_issued"] == 2
    assert run["dropped_total"] == 0
    # The heartbeat moved off `started_us`, which is what keeps a live run from
    # being closed `idle` under it.
    assert run["heartbeat_us"] >= run["started_us"]

    # The rig's own run is untouched: capture did not adopt it and did not
    # count against it.
    still = rows(rig, "SELECT * FROM run WHERE id=?", (rig.run_id,))[0]
    assert still["requests_issued"] == 0 and still["status"] == "running"

    # Every exchange is on the run that opened itself.
    assert {row["run_id"] for row in rows(rig, "SELECT run_id FROM exchange")} \
        == {run["id"]}


# ---------------------------------------------------------------------------
# 7. Capture never gates enforcement -- and the control channel is not capture.
# ---------------------------------------------------------------------------

def test_a_broken_recorder_does_not_gate_the_browser_but_a_dead_bridge_does(rig):
    """S4's two halves, and they point in OPPOSITE directions.

    THE FIRST HALF is the promise: "a wedged harness, a full queue or a dropped
    record changes what hx KNOWS, never what it ALLOWS". The extension sits in
    the request path of a real person's browser during a live engagement,
    possibly against a production system, and a slow or broken Python side must
    never become a stall -- or worse, a refusal -- on the client's application.
    That would turn a harness bug into an incident. No unit test can make this
    claim: the harness and the browser have to be real and separate for
    "recording failed and browsing did not" to mean anything.

    THE SECOND HALF is the opposite, and this is a CORRECTION to what this task
    was briefed to assert. The brief said to stop `BridgeServer`, keep
    browsing, and assert the requests still reach the target. THEY DO NOT, and
    they must not. Killing the bridge is not a capture failure -- it is the
    loss of the AUTHORISATION CHANNEL, and DENY-ALL is the initial and terminal
    state at both enforcement points. `BridgeClient.readLoop`'s finally calls
    `denyAll()` on every exit path, `ProxyGate.decide` refuses an epoch-0
    authorisation before it touches Policy, and the browser gets Burp's drop
    page for everything. MEASURED: target log frozen at 3 hits across a browse
    after `srv.stop()`, client answered 200 in 1529 bytes.

    Asserting the brief's version would have pinned a fail-OPEN as correct
    behaviour -- a Burp that kept issuing after its control channel died, with
    nothing left able to halt it. That is the 02:00 window S4 spends DENY-ALL
    to close.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? The first half's guard is
    `exchange_errors`: if the sink were not actually being called and failing,
    that counter stays 0 and the assertion below reddens -- so "the browser
    kept working" cannot pass by the recorder having quietly kept working too.
    The row count is asserted frozen for the same reason. The second half's
    guard is the bounded wait: a Burp that went on delivering after the bridge
    died never satisfies it and the test fails naming the hits it kept taking.
    """
    assert rig.configure() == 1

    # A working browse first, so what follows is a CHANGE rather than a state
    # the rig might have been in all along.
    assert status_of(browse(rig, "/health")) == 200
    settle(rig, lambda: rows(rig, "SELECT id FROM exchange"), "the first row")

    # --- half one: the recorder breaks, the browser does not ---------------
    def exploding(header, request, response):
        raise RuntimeError("the harness's recorder is broken")

    rig.srv.on_exchange = exploding
    hits_before = len(rig.target.hits)
    rows_before = len(rows(rig, "SELECT id FROM exchange"))

    for i in range(3):
        broken = browse(rig, f"/api/orders?while-broken={i}")
        assert status_of(broken) == 200
        # The target's answer, not Burp's page: 41 bytes of orders JSON is
        # something only the target can produce.
        assert b'"orders"' in broken

    assert len(rig.target.hits) == hits_before + 3, (
        "a broken recorder gated the browser: the target went from "
        f"{hits_before} to {len(rig.target.hits)} hits across three requests. "
        "S4 is unconditional -- a lost record changes what hx KNOWS, never "
        "what it ALLOWS.")

    # The sink really did fail, and really did fail on every frame. Six, not
    # three: `_capture` hands each loss back as a one-record `dropped` frame so
    # the run's coverage floor can move, and this sink raises on that too.
    assert rig.srv.exchange_errors >= 6, (
        f"only {rig.srv.exchange_errors} sink failures were recorded for three "
        "browsed requests, so the recorder was not actually broken and the "
        "assertion above measured nothing")
    assert isinstance(rig.srv.exchange_callback_error, RuntimeError)
    assert len(rows(rig, "SELECT id FROM exchange")) == rows_before, \
        "a sink that raises must record nothing; anything else means the " \
        "failure was not where this test put it"

    # --- half two: the bridge dies, and enforcement follows it -------------
    rig.srv.stop()

    def refuses_now() -> bool:
        """One browse; True once the target's log stops moving.

        Bounded, and the bound is the assertion: a Burp that never stops
        delivering never returns True and `wait` below fails with the hits it
        went on taking. The loop exists because the extension notices the
        closed socket on its own read thread, which is fast but not
        instantaneous.
        """
        before = len(rig.target.hits)
        browse(rig, "/health?after-the-bridge-died=1")
        time.sleep(0.3)
        return len(rig.target.hits) == before

    deadline = time.time() + 15
    while not refuses_now():
        if time.time() > deadline:
            pytest.fail(
                "the extension went on issuing after its control channel "
                f"died: the target has taken {len(rig.target.hits)} hits. "
                "DENY-ALL is the terminal state at both enforcement points, "
                "and a Burp still forwarding traffic with no bridge is one "
                "nothing left alive can halt.")

    # Held, not merely reached: two more browses must change nothing.
    frozen = len(rig.target.hits)
    for i in range(2):
        after = browse(rig, f"/health?still-dead={i}")
        assert status_of(after) == DROP_LOOKS_LIKE
    time.sleep(0.5)
    assert len(rig.target.hits) == frozen, (
        "the refusal did not hold: the target took "
        f"{len(rig.target.hits) - frozen} more request(s) after the bridge "
        "died.")


# ---------------------------------------------------------------------------
# 7. B3: an allowed request that fails at the transport. MEASURED, NOT FIXED.
# ---------------------------------------------------------------------------


def test_an_allowed_request_that_cannot_connect_leaves_no_trace_at_all(rig):
    """THE MEASUREMENT B3 IS PARKED ON. This test PINS A GAP, not a fix.

    An in-scope request that passes the gate and then fails to connect --
    connection refused, DNS failure, TLS failure -- produces **no exchange
    row, no denial row and no drop**. S5's `conn_refused | dns_error |
    tls_error` outcomes are unreachable from the proxy path, and S5's own
    stated reason for having `outcome` at all -- "a check reads silence as
    not vulnerable" -- applies one layer earlier than it was written for.

    WHAT WAS MEASURED HERE, against Burp Suite Community 2026.7.3:

      - Burp answers the CLIENT with its own error page, `HTTP/1.1 200 OK`,
        ~1535 bytes, `<title>Burp Suite</title>`. That is the same SHAPE a
        dropped request produces (`DROP_LOOKS_LIKE`, ~1529 bytes), so a client
        cannot tell "hx refused this" from "nothing answered" either.
      - `exchange`: no row. `denial`: no row. `run.dropped_total`: unmoved.
        `BridgeServer.exchange_errors`: 0 -- so this is not a sink that failed,
        it is a record that was never made.

    AND WHAT THAT IMPLIES ABOUT THE CALLBACK, stated as the inference it is
    rather than as an observation: `handleResponseReceived` did not run for
    that message. Had it run and found the `Pending` entry there would be an
    exchange row; had it run and MISSED, `Capture.countLost` would have moved
    `dropped_total`. Neither happened, so the entry is still sitting in
    `Pending` waiting to be evicted by capacity pressure -- and
    `Pending.evicted()` has no reader outside its own test.

    WHY IT IS NOT FIXED HERE, rather than left to look like an oversight:

      - THERE IS NO FAILURE CALLBACK TO USE. Measured off the jar this
        extension compiles against (montoya-api.jar,
        `Implementation-Version: 2025.10`):
        `ProxyRequestHandler` and `ProxyResponseHandler` declare exactly two
        methods each and `HttpHandler` exactly two, and none of the six is a
        failure or timeout notification. There is nothing to register.
      - A TIME-BASED SWEEP OF `Pending` WOULD FABRICATE EVIDENCE. It has to
        pick one of S5's four outcomes, and Montoya reports nothing that
        distinguishes conn_refused from dns_error from tls_error -- which is
        exactly why `records.EXCHANGE_OUTCOME` has no `transport_error` entry
        and why the 599 sentinel needed an outcome of its own. It also has to
        pick a duration, and a long-poll, an SSE stream and a WebSocket
        upgrade all legitimately have no response for minutes: filing those as
        transport failures is a fabricated fact in the evidence store.
      - COUNTING IT AS A DROP instead needs the same duration, and gets the
        error in the direction `Capture` already warns about -- a response
        that arrives after the sweep is one loss reported and one exchange
        recorded, and `run.dropped_total` becomes "wrong in the direction of
        alarm".

    THE ONE FACILITY THAT MIGHT CLOSE IT, named so the next attempt starts
    from a measurement rather than a guess: `Proxy.history()` returns
    `ProxyHttpRequestResponse`, which has `hasResponse()`, `id()` and
    `listenerPort()`. It is a POLL and not a callback, and TWO THINGS ABOUT IT
    ARE UNMEASURED -- whether Burp enters a request that never connected into
    proxy history at all, and whether anything there separates "no response
    yet" from "no response ever". Both are `test_proxy_facts.py`-shaped
    questions; neither has been asked. See docs/burp-proxy-measurements.md Q5.

    IF THIS TEST GOES RED, the gap has closed by itself -- a Burp upgrade, or
    someone wiring a sweep -- and that is worth finding out about deliberately
    rather than discovering in a report.
    """
    assert rig.configure() == 1

    # A live request first, so the failure below is a fact about the DEAD
    # target rather than about a path that never worked in this fixture.
    assert status_of(browse(rig, "/api/orders")) == 200
    settle(rig, lambda: rows(rig, "SELECT id FROM exchange"), "the live row")
    live_rows = len(rows(rig, "SELECT id FROM exchange"))

    # The destination stays IN SCOPE -- the gate allows it, and the connection
    # is the thing that fails. Out of scope would be a `denial` row, which is
    # the case that already works.
    rig.target.stop()
    time.sleep(0.5)

    raw = browse(rig, "/api/orders?the-target-is-gone=1", timeout=20)
    assert status_of(raw) == DROP_LOOKS_LIKE, (
        "Burp answered a failed connection with something other than its own "
        f"200 error page: {raw[:120]!r}")
    assert b"Burp Suite" in raw

    # Long enough for a frame to have crossed the bridge and a row to have
    # been written. The live request above took well under this.
    time.sleep(SETTLE_S)

    assert len(rows(rig, "SELECT id FROM exchange")) == live_rows, (
        "an exchange row appeared for a request that never connected. If the "
        "outcome is one of S5's transport values this gap has been closed and "
        "this test should be rewritten as the check for the fix; if it is "
        "`ok` with Burp's own error page in the response blob, that is worse "
        "than the gap -- a report would read Burp's page as the target's")
    assert rows(rig, "SELECT kind, url FROM denial") == [], \
        "the request was ALLOWED; a denial row here would record a refusal " \
        "that did not happen"
    assert rows(rig, "SELECT COALESCE(SUM(dropped_total), 0) AS n FROM run"
                )[0]["n"] == 0, (
        "the loss is now counted as a drop. That is a real improvement over "
        "silence and it is NOT what this test pins -- rewrite it")
    assert rig.srv.exchange_errors == 0, (
        "this side's sink failed, so the empty table above measures a broken "
        "harness rather than the gap this test is about")
