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


def _two_exchanges_on_one_surface(tool_run):
    """Two `via='send'` exchanges against the same surface, through the real
    writer (`hx.issue.issue`) rather than hand-built rows -- the same reason
    `test_baseline_for_returns_the_exemplars_body_not_its_whole_response`
    goes through it above. `first` becomes the surface's exemplar (`hx.
    capture.Capture.upsert_surface`'s `INSERT ... ON CONFLICT DO UPDATE`
    writes `exemplar_exchange_id` only on the INSERT branch); `second` does
    not. Returns `(first, second, surface_id, first_payload)`.
    """
    bridge = FakeBridge()
    first_payload = b"Hello visitor"
    second_payload = b"Hello again"
    bridge.replies([
        sent_result(b"HTTP/1.1 200 OK\r\n\r\n" + first_payload),
        sent_result(b"HTTP/1.1 200 OK\r\n\r\n" + second_payload),
    ])
    kw = dict(engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
              scheme="http", host="127.0.0.1", port=8080, method="GET",
              path="/x")
    first = issue.issue(bridge, tool_run.conn, tool_run.blobs,
                        tool_run.config, **kw)
    second = issue.issue(bridge, tool_run.conn, tool_run.blobs,
                         tool_run.config, **kw)
    surface_id = tool_run.conn.execute(
        "SELECT surface_id FROM exchange WHERE id=?",
        (first.exchange_id,)).fetchone()[0]
    return first, second, surface_id, first_payload


# --- `exclude_exchange_id`, fix round 1's finding 4 -------------------------
#
# The NULL-safety contract lived only in a comment on `baseline_for`: `x.id
# IS NOT ?` against a NULL parameter, not `!=`, which SQLite evaluates to
# NULL -- neither true nor false -- and which would silently match NO row for
# every caller that passes nothing. These four cases are the ones the
# reviewer probed by hand.


def test_no_exclusion_returns_the_baseline(tool_run):
    first, _second, surface_id, payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id)
    assert got == (first.status, payload)


def test_excluding_the_exemplar_itself_returns_no_baseline(tool_run):
    """The guard `hx.tools.impl.http._digest` relies on: `hx.issue.issue`
    makes a brand-new surface's exemplar the very exchange that just created
    it, so a caller diffing THAT exchange's response against "the baseline"
    must not diff it against itself -- a zero delta reporting a comparison
    that was never made."""
    first, _second, surface_id, _payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id,
                             exclude_exchange_id=first.exchange_id)
    assert got is None


def test_excluding_a_different_exchange_leaves_the_baseline_intact(tool_run):
    """Only an exclusion naming the EXEMPLAR itself may suppress the
    baseline. Excluding the second exchange -- which is not the exemplar --
    must change nothing."""
    first, second, surface_id, payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id,
                             exclude_exchange_id=second.exchange_id)
    assert got == (first.status, payload)


def test_exclude_exchange_id_of_none_leaves_the_baseline_intact(tool_run):
    """`None` PASSED EXPLICITLY, not merely omitted -- pinning the same
    NULL-safety contract as `test_no_exclusion_returns_the_baseline` against
    the keyword itself rather than against its default."""
    first, _second, surface_id, payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id,
                             exclude_exchange_id=None)
    assert got == (first.status, payload)


def test_a_corrupt_exemplar_blob_is_no_baseline_rather_than_a_raise(tool_run):
    """RULING 18. The third read site of this blob and the only one that did
    not guard it -- `hx.tools.impl.http._blobs_for` and `replay_as`'s read of
    the original response both catch `CorruptBlob` by explicit ruling.

    None is the answer this function already gives for a missing surface, a
    missing exemplar and an unstored response. All four are "there is nothing
    to compare against", and a caller that told them apart would be reporting
    on hx's bookkeeping rather than on the application."""
    from hx.store.blobs import CorruptBlob

    _first, _second, surface_id, _payload = _two_exchanges_on_one_surface(
        tool_run)
    real_get = tool_run.blobs.get

    def _corrupt(digest, expected_len=None):
        raise CorruptBlob(f"blob {digest} failed digest verification")

    tool_run.blobs.get = _corrupt
    try:
        got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id)
    finally:
        tool_run.blobs.get = real_get
    assert got is None
