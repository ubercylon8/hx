"""What changed between a response and its surface's exemplar.

The digest exists because twelve payload variants against one endpoint return
twelve identical tuples without it. So the test that matters most here is the
one where a reflected token appears in `new_tokens` and nothing else does.
"""
from hx import delta, issue

from tests.test_probe import FakeBridge, sent_result


def test_a_reflected_payload_shows_up_as_a_new_token():
    """The whole point. An agent sends `hZq9xK` and wants to be told, in the
    digest, that `hZq9xK` came back -- without reading a 1.2 MB body."""
    base = b"<html><body>Hello visitor</body></html>"
    now = b"<html><body>Hello hZq9xK</body></html>"
    got = delta.against(200, base, 200, now)
    assert got["new_tokens"] == ["hZq9xK"]
    assert got["status_changed"] is False
    assert got["len_delta"] == len(now) - len(base)


def test_tokens_present_in_the_baseline_are_not_new():
    base = b"session=abcdef ; csrf=ghijkl"
    now = b"session=abcdef ; csrf=ghijkl ; extra=mnopqr"
    assert delta.against(200, base, 200, now)["new_tokens"] == ["mnopqr"]


def test_short_runs_are_not_tokens():
    """A six-character floor. Without it every `<div>`, `class` and `href`
    in a re-rendered page is a `new_token`, and the field an agent reads for
    signal becomes the field it learns to skip."""
    assert delta.against(200, b"a", 200, b"a bc def ghij")["new_tokens"] == []


def test_a_status_change_is_reported_even_when_the_body_is_identical():
    got = delta.against(200, b"same", 403, b"same")
    assert got["status_changed"] is True
    assert got["len_delta"] == 0
    assert got["new_tokens"] == []


def test_tokens_are_capped_and_the_cap_is_declared():
    """A silent cap reads as "that was all of them", which is section 12's
    failure in a single field."""
    now = b" ".join(b"tok%05d" % i for i in range(delta.MAX_TOKENS + 10))
    got = delta.against(200, b"", 200, now)
    assert len(got["new_tokens"]) == delta.MAX_TOKENS
    assert got["new_tokens_truncated"] is True


def test_an_oversized_body_reports_null_tokens_rather_than_scanning_it():
    """`new_tokens: null` is "not computed"; `[]` is "computed, none found".
    Collapsing the two would let an agent read a 40 MB download it never
    diffed as proof that nothing changed."""
    big = b"x" * (delta.MAX_DIFF_BYTES + 1)
    got = delta.against(200, b"", 200, big)
    assert got["new_tokens"] is None
    assert got["len_delta"] == len(big)
    assert got["status_changed"] is False


def test_a_surface_with_no_exemplar_has_no_baseline(tool_ctx):
    assert delta.baseline_for(tool_ctx.conn, tool_ctx.blobs, "no-such") is None


def test_baseline_for_returns_the_exemplars_body_not_its_whole_response(
        tool_run):
    """The row is built by `hx.issue.issue`, the one writer of `via='send'`
    exchange rows -- a fixture that wrote the surface/exchange rows itself
    would pass while the real writer wrote something else. The exemplar
    response here carries a `Date` header the body does not, so a
    `baseline_for` that returned the whole response rather than the body
    would fail the equality assertion below by leaking that header in.
    """
    bridge = FakeBridge()
    body = b"<html><body>Hello visitor</body></html>"
    resp = (b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2001 00:00:00 GMT\r\n"
            b"Content-Type: text/html\r\n\r\n" + body)
    bridge.replies([sent_result(resp, status=200)])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a")

    row = tool_run.conn.execute(
        "SELECT surface_id FROM exchange WHERE id=?",
        (got.exchange_id,)).fetchone()
    surface_id = row[0]

    baseline = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id)
    assert baseline == (200, body)
