"""The only writer of `via='send'` exchange rows.

WHY THIS MODULE EXISTS AT ALL is the first thing to know when reading these
tests. `src/hx/store/schema.sql` records that `Capture.java` delivers
`via: proxy` and nothing else, so until this module there was no send-path
exchange row in this build -- and `http.grep`, `http.body` and
`evidence.attach` are all defined as reads keyed on one. Every assertion below
about a row, a blob or a surface is an assertion about whether those three
tools have anything to read.
"""
import hashlib

import pytest

from hx import issue
from hx.bridge.server import BridgeError

from tests.test_probe import FakeBridge, sent_result


def test_a_send_writes_an_exchange_row_a_later_tool_can_read(tool_run):
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a")

    row = tool_run.conn.execute(
        "SELECT via, method, url, status, outcome, req_blob, resp_blob,"
        " surface_id FROM exchange WHERE id=?", (got.exchange_id,)).fetchone()
    via, method, url, status, outcome, req_blob, resp_blob, surface_id = row
    assert via == "send"
    assert (method, status, outcome) == ("GET", 200, "ok")
    assert url == "http://127.0.0.1:8080/a"
    # BOTH blobs, and the surface back-reference. A row with a NULL
    # `resp_blob` is a row `http.grep` cannot read, and a row with a NULL
    # `surface_id` is one `surface.detail` will never join to.
    assert req_blob and resp_blob and surface_id


def test_the_digest_is_section_8s_digest(tool_run):
    body = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{}"
    bridge = FakeBridge()
    bridge.replies([sent_result(body, status=201, ms=42)])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="POST", path="/a")
    assert got.status == 201
    assert got.ms == 42
    assert got.content_type == "application/json"
    assert got.first_line == "HTTP/1.1 201 Created"
    assert got.body_sha256.startswith("sha256:")
    # `bytes` counts the WHOLE redacted response; `body` and `body_sha256`
    # are the payload alone, split from the head. The two are different
    # spans on purpose -- see finding 2 below for what goes wrong if
    # `body_sha256` ever hashes `response` instead.
    assert got.bytes == len(body)
    assert got.body == b"{}"
    assert got.body_sha256 == "sha256:" + hashlib.sha256(b"{}").hexdigest()


def test_body_sha256_hashes_only_the_body_not_the_headers(tool_run):
    """Finding 2. Two responses whose PAYLOAD is identical and whose headers
    are not -- a fresh `Date`, a per-session `Set-Cookie` -- must produce the
    same `body_sha256`. If this hashed `response` (status line and headers
    included) instead, `http.replay_as` would report an authorisation
    difference between two replies that answered identically."""
    bridge = FakeBridge()
    bridge.replies([
        sent_result(b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2001 00:00:00 GMT"
                    b"\r\n\r\nsame payload"),
        sent_result(b"HTTP/1.1 200 OK\r\nDate: Tue, 02 Jan 2001 00:00:00 GMT"
                    b"\r\nSet-Cookie: sid=abc123\r\n\r\nsame payload"),
    ])
    kwargs = dict(
        bridge=bridge, conn=tool_run.conn, blobs=tool_run.blobs,
        config=tool_run.config, engagement_id=tool_run.engagement.id,
        run_id=tool_run.run_id, scheme="http", host="127.0.0.1", port=8080,
        method="GET")
    first = issue.issue(**kwargs, path="/a")
    second = issue.issue(**kwargs, path="/b")
    assert first.body == second.body == b"same payload"
    # The responses genuinely differ (in `bytes`, the whole-response count),
    # which is what makes an EQUAL body_sha256 the meaningful assertion here
    # rather than a coincidence of two identical replies.
    assert first.bytes != second.bytes
    assert first.body_sha256 == second.body_sha256


def test_the_surface_is_upserted_as_agent_discovered(tool_run):
    """`capture.DISCOVERED_BY` maps `send` to `agent`, and nothing has ever
    exercised that entry. A surface an agent found and a surface the operator
    browsed are different facts and a report distinguishes them."""
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a")
    discovered_by = tool_run.conn.execute(
        "SELECT s.discovered_by FROM surface s JOIN exchange x"
        " ON x.surface_id = s.id WHERE x.id=?", (got.exchange_id,)).fetchone()
    assert discovered_by[0] == "agent"


def test_requests_issued_counts_the_send(tool_run):
    """S5's coverage floor. The proxy writer bumps it and this one must too,
    or a run that sent a hundred requests reports having issued none."""
    before = tool_run.conn.execute(
        "SELECT requests_issued FROM run WHERE id=?",
        (tool_run.run_id,)).fetchone()[0]
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    issue.issue(bridge, tool_run.conn, tool_run.blobs,
                tool_run.config, engagement_id=tool_run.engagement.id,
                run_id=tool_run.run_id, scheme="http", host="127.0.0.1",
                port=8080, method="GET", path="/a")
    after = tool_run.conn.execute(
        "SELECT requests_issued FROM run WHERE id=?",
        (tool_run.run_id,)).fetchone()[0]
    assert after == before + 1


@pytest.mark.parametrize("cls", [
    "scope_denied", "method_denied", "dangerous_denied", "rate_limited",
    "budget_exhausted", "halted", "not_configured", "transport_error",
    "timeout", "bridge_lost",
])
def test_every_refusal_class_raises_rather_than_returning(tool_run, cls):
    """`BridgeServer.send` NEVER returns a refusal as a dict, and the whole
    of `hx.checks.probe`'s rule-one argument applies here with the same
    force: a refusal that came back as a value is one a caller can read as a
    response."""
    bridge = FakeBridge()
    bridge.replies([BridgeError(f"{cls}: no", error_class=cls)])
    with pytest.raises(issue.IssueRefused) as exc:
        issue.issue(bridge, tool_run.conn, tool_run.blobs, tool_run.config,
                    engagement_id=tool_run.engagement.id,
                    run_id=tool_run.run_id, scheme="http", host="127.0.0.1",
                    port=8080, method="GET", path="/a")
    assert exc.value.reason == cls
    # AND NO ROW. A refused send put no bytes on the wire for most of these
    # classes, and a row would make a denial indistinguishable from traffic.
    assert tool_run.conn.execute(
        "SELECT COUNT(*) FROM exchange").fetchone()[0] == 0


def test_a_send_under_an_identity_records_it_as_assumed(tool_run):
    """Never `proven`: a canary bracket proves a run, and one send has none."""
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a",
        identity=("staff", 3))
    row = tool_run.conn.execute(
        "SELECT identity, identity_generation, identity_state"
        " FROM exchange WHERE id=?", (got.exchange_id,)).fetchone()
    assert tuple(row) == ("staff", 3, "assumed")
    # And the frame carried the id, so the EXTENSION does the injection.
    assert bridge.requests[0]["identity_id"] == "staff"


def test_an_anonymous_send_sends_no_identity_key_at_all(tool_run):
    """An ABSENT key is anonymous; a null would leave the extension deciding
    what a null means. `Sender.decideAndIssue` reads the field as
    `instanceof String`, so a null happens to be anonymous there today -- and
    a key sent only when it means something cannot acquire a second meaning
    from a later reader."""
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    issue.issue(bridge, tool_run.conn, tool_run.blobs, tool_run.config,
                engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
                scheme="http", host="127.0.0.1", port=8080, method="GET",
                path="/a")
    assert "identity_id" not in bridge.requests[0]


@pytest.mark.parametrize("bad", [
    ("GE T", "/a"), ("GET", "/a b"), ("GET", "/a\r\nX: 1"),
    ("GET\n", "/a"), ("GET", "/a\x00"),
])
def test_a_request_that_could_be_split_is_refused_before_the_wire(bad):
    """Request smuggling starts at home. A method or path carrying CR, LF,
    NUL or a space would let an agent's ONE request become two, and the
    second would not have crossed the gate as itself. Refused here as a
    ValueError -- a caller's mistake, not a denial -- so it never lands in a
    journal row as an ordinary refusal."""
    method, path = bad
    with pytest.raises(ValueError):
        issue.request_bytes(method, path, "127.0.0.1", ())


def test_a_header_line_without_a_colon_is_refused():
    with pytest.raises(ValueError):
        issue.request_bytes("GET", "/a", "127.0.0.1", ("not a header",))


@pytest.mark.parametrize("line", [":evil", " X: 1"])
def test_a_header_with_an_empty_or_whitespace_led_name_is_refused(line):
    """Finding 3. `:evil` names no field at all; ` X: 1` is obs-fold, which
    some parsers reject and others fold into the PRECEDING header -- a
    parser-disagreement primitive reachable through http.send's headers
    array, even though neither shape can split a request by itself."""
    with pytest.raises(ValueError):
        issue.request_bytes("GET", "/a", "127.0.0.1", (line,))


def test_a_body_with_no_framing_header_gets_a_computed_content_length():
    """Finding 1. RFC 9112 S6.3: a request with neither Content-Length nor
    Transfer-Encoding has a ZERO-length body, so an unframed body sits in
    the connection buffer to be parsed as the head of the NEXT request on
    that keep-alive connection -- request splitting, produced by the exact
    function whose `FORBIDDEN` guard exists to prevent it."""
    raw = issue.request_bytes("POST", "/a", "h.test", (), b"x=1")
    assert b"\r\nContent-Length: 3\r\n" in raw
    assert raw.endswith(b"x=1")


def test_an_agreeing_content_length_is_left_alone():
    raw = issue.request_bytes(
        "POST", "/a", "h.test", ("Content-Length: 3",), b"x=1")
    assert raw.count(b"Content-Length:") == 1


def test_a_disagreeing_content_length_is_refused():
    """A CL that does not match the body is a request-smuggling primitive
    (CL.TE / TE.CL), not a typo -- refused rather than silently corrected,
    which would send a request different from the one the caller asked
    for."""
    with pytest.raises(ValueError, match="disagrees"):
        issue.request_bytes(
            "POST", "/a", "h.test", ("Content-Length: 99",), b"x=1")


def test_transfer_encoding_is_refused_outright():
    with pytest.raises(ValueError, match="Transfer-Encoding"):
        issue.request_bytes(
            "GET", "/a", "h.test", ("Transfer-Encoding: chunked",))


def test_an_empty_body_emits_no_content_length():
    raw = issue.request_bytes("GET", "/a", "h.test", ())
    assert b"Content-Length" not in raw


def test_the_host_header_is_not_duplicated():
    """The caller may spell `Host:` themselves -- a virtual-host test needs
    to -- and two Host headers is a request smuggling primitive, not a
    preference."""
    raw = issue.request_bytes("GET", "/a", "127.0.0.1", ("Host: other.test",))
    assert raw.count(b"Host:") == 1
    assert b"Host: other.test" in raw
