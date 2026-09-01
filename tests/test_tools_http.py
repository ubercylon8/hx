"""The four http.* tools.

WHAT THESE TESTS ARE FOR, given that `tests/test_issue.py` already proves the
send path: the TOOL layer's own obligations. Does a refusal from the wire
arrive as `refused` with the wire's class as the reason, or as `error /
internal`? Does the digest an agent receives carry a payload, in defiance of
Principle 1? Does an argument the schema should have caught reach the handler?
Those are questions about this layer and not about `hx.issue`.
"""
import pytest

from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401 -- registers every tool
from hx.bridge.server import BridgeError

from tests.test_probe import FakeBridge, sent_result


def _with_session(ctx, replies=()):
    """A context whose session is a bridge and nothing else.

    The tools reach `ctx.session.bridge` and never anything else on the
    session, which is worth knowing when reading these: a `LiveSession`'s
    ports, workdir and `proc` belong to the bracket, not to a send.

    `replies` is the queue `FakeBridge.replies` consumes, one per send. The
    double is `tests/test_probe.py`'s -- the project has ONE, and a second
    would be a second idea of what `BridgeServer.send` does.
    """
    bridge = FakeBridge()
    bridge.replies(list(replies))
    ctx.session = type("S", (), {"bridge": bridge})()
    return ctx


def test_send_returns_the_digest_and_not_the_body(tool_run):
    """Principle 1, and the one assertion in this file that is about the
    product's shape rather than its plumbing. A body in the envelope would be
    journalled into `agent_action.result_summary` and would put a client's
    response bytes in a table that is read by whoever asks what the run did."""
    body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>secret</h1>"
    ctx = _with_session(tool_run, [sent_result(body)])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="probe the index")
    assert env.outcome == "ok"
    assert set(env.result) >= {"exchange_id", "status", "bytes", "ms",
                               "content_type", "body_sha256", "first_line",
                               "outcome", "delta_vs_baseline"}
    assert b"secret" not in repr(env.result).encode()


def test_a_scope_denial_is_refused_with_the_wires_own_class(tool_run):
    """Principle 6: the safety profile is enforced in the extension and the
    tool layer merely REPORTS what was refused. `error / internal` here would
    tell the agent hx is broken when in fact hx worked exactly as designed."""
    ctx = _with_session(tool_run,
                        [BridgeError("scope_denied: not in scope",
                                     error_class="scope_denied")])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "evil.test", "port": 80,
                                 "method": "GET", "path": "/a"},
                                why="try an out-of-scope host")
    assert env.outcome == "refused"
    assert env.reason == "scope_denied"


def test_without_a_session_it_is_unavailable_not_an_error(tool_run):
    """The dispatcher's own `needs_egress` guard, which Plan A shipped and
    nothing has ever reached until now: `http.send` is the first registered
    tool with the bit set."""
    tool_run.session = None
    env = dispatch_mod.dispatch(tool_run, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="no session on purpose")
    assert env.outcome == "unavailable"
    assert env.reason == "no_session"


def test_send_without_a_why_is_refused(tool_run):
    """Principle 5. `http.send` mutates -- it puts bytes on a client's
    network -- so `missing_why` fires before anything reaches the wire."""
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"})
    assert env.outcome == "refused"
    assert env.reason == "missing_why"
    assert ctx.session.bridge.requests == [], "a why-less send reached the wire"


def test_send_is_refused_while_the_engagement_is_halted(tool_run):
    """An operator has hit STOP. `http.send` mutates and is not in
    HALT_EXEMPT, so the dispatcher refuses before the handler runs."""
    tool_run.halt.halt("operator stopped the run")
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="should never reach the wire")
    assert env.outcome == "refused"
    assert env.reason == "halted"
    assert ctx.session.bridge.requests == []


@pytest.mark.parametrize("args", [
    {"host": "127.0.0.1", "method": "GET"},                     # no path
    {"host": "127.0.0.1", "method": "GET", "path": "a"},        # not origin-form
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "port": 0},                                                # port floor
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "port": 70000},                                            # port ceiling
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "scheme": "gopher"},                                       # scheme enum
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "headers": "X: 1"},                                        # headers is a list
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "nonsense": 1},                                            # additionalProperties
])
def test_bad_arguments_never_reach_the_wire(tool_run, args):
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send", args, why="malformed")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert ctx.session.bridge.requests == []


def test_a_path_carrying_crlf_is_refused_as_bad_args(tool_run):
    """`issue.request_bytes` raises ValueError for this, and the handler must
    turn it into `bad_args` rather than letting it become `error / internal`.
    An agent told hx is broken retries; one told its path is malformed fixes
    the path."""
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a\r\nX: 1"},
                                why="attempt a split")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert ctx.session.bridge.requests == []


def test_an_undeclared_identity_is_refused_and_names_the_declared_ones(
        tool_run):
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a",
                                 "identity": "ghost"},
                                why="use an identity that does not exist")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert "ghost" in (env.detail or "")
    assert ctx.session.bridge.requests == []


def test_an_identity_registration_refused_by_the_wire_carries_its_class(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 13, fix round 1's finding 1. `hx.tools.live.ensure_identity`
    can raise `BridgeError` -- the extension's own liveness canary already
    having answered `identity_dead` for this identity, say -- and not only
    `ValueError`. That must reach the agent as the wire's own class, exactly
    like a send refusal, rather than `error / internal`: told hx is broken,
    an agent would retry the identical send forever instead of re-opening
    its session."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ctx = _with_session(tool_run, [sent_result()])
    ctx.session.bridge.refuse_identity("identity_dead", "canary failed")
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a",
                                 "identity": "staff"},
                                why="identity registration is refused")
    assert env.outcome == "unavailable"
    assert env.reason == "identity_dead"
    assert ctx.session.bridge.requests == [], "send reached the wire anyway"


def test_a_declared_identity_whose_credential_will_not_resolve_is_unavailable(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 13, fix round 1's finding 2. `identity: "staff"` is a perfectly
    valid argument -- the operator's environment is what is missing, and no
    argument the agent can write would fix it, so this is NOT `bad_args`
    (that stays reserved for an UNDECLARED identity name, which the agent
    does control). The detail names the environment variable and must never
    carry its value -- moot here since none was set, but `hx.identity`'s own
    messages are value-free by construction."""
    monkeypatch.delenv("HX_STAFF_TOKEN", raising=False)
    tool_run.config = staff_identity_config
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a",
                                 "identity": "staff"},
                                why="the credential is not in the environment")
    assert env.outcome == "unavailable"
    assert env.reason == "identity_unresolved"
    assert "HX_STAFF_TOKEN" in (env.detail or "")
    assert ctx.session.bridge.requests == [], "send reached the wire anyway"


def test_the_delta_is_null_when_the_surface_has_no_exemplar_yet(tool_run):
    """`null` and not a zero delta: nothing was compared, and a zero delta
    would read as 'identical to normal' about a comparison never made."""
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/brand-new"},
                                why="first ever request to this path")
    assert env.result["delta_vs_baseline"] is None


def test_a_second_send_to_the_same_surface_gets_a_delta(tool_run):
    """The first send becomes the surface's exemplar; the second is compared
    against it. This is the shape an agent actually uses: baseline, then
    payload."""
    first = b"HTTP/1.1 200 OK\r\n\r\nHello visitor"
    second = b"HTTP/1.1 200 OK\r\n\r\nHello hZq9xK"
    ctx = _with_session(tool_run,
                        [sent_result(first), sent_result(second)])
    args = {"host": "127.0.0.1", "port": 8080, "method": "GET", "path": "/x"}
    dispatch_mod.dispatch(ctx, "http.send", args, why="baseline")
    env = dispatch_mod.dispatch(ctx, "http.send", args, why="payload")
    got = env.result["delta_vs_baseline"]
    assert got is not None
    assert got["new_tokens"] == ["hZq9xK"]


def test_a_corrupt_exemplar_blob_still_answers_with_the_exchange_id(tool_run):
    """RULING 18, end to end and on the send path, which is where it bites.

    The request has ALREADY GONE OUT by the time the digest is composed: the
    exchange row is written and `requests_issued` is incremented. Before the
    fix, `delta.baseline_for`'s unguarded `blobs.get` raised `CorruptBlob`
    from there and the whole call answered `error / internal` -- so the agent
    never learned the `exchange_id` of a request the client's application had
    already served, could not read the response it had just paid for, and its
    natural next move was to send the same request again.

    `delta_vs_baseline: null` is the honest answer: nothing was compared. The
    `exchange_id` assertion is the load-bearing one -- an `outcome == "ok"`
    on its own would pass for a digest that carried no handle."""
    from hx.store.blobs import CorruptBlob

    first = b"HTTP/1.1 200 OK\r\n\r\nHello visitor"
    second = b"HTTP/1.1 200 OK\r\n\r\nHello hZq9xK"
    ctx = _with_session(tool_run, [sent_result(first), sent_result(second)])
    args = {"host": "127.0.0.1", "port": 8080, "method": "GET", "path": "/x"}
    dispatch_mod.dispatch(ctx, "http.send", args, why="baseline")

    real_get = ctx.blobs.get

    def _corrupt(digest, expected_len=None):
        raise CorruptBlob(f"blob {digest} failed digest verification")

    ctx.blobs.get = _corrupt
    try:
        env = dispatch_mod.dispatch(ctx, "http.send", args, why="payload")
    finally:
        ctx.blobs.get = real_get
    assert env.outcome == "ok"
    assert env.result["exchange_id"]
    assert env.result["delta_vs_baseline"] is None


def _refusing(cls: str):
    """One `BridgeError` of a class no `REASON_FOR_CLASS` entry names."""
    return [BridgeError(f"{cls}: mystery", error_class=cls)]


def test_an_unknown_wire_class_does_not_escape_dispatch(tool_run):
    """`dispatch` NEVER RAISES, and an unmapped reason is the one way left
    to make it. MEASURED: `Envelope.__post_init__` raises ValueError for a
    reason outside the closed set, and that raise lands inside `except
    ToolError` where the `except Exception` beside it cannot catch it."""
    ctx = _with_session(tool_run, _refusing("nova_class_from_2027"))
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="unknown class")
    assert env.outcome in ("refused", "unavailable")
    assert "nova_class_from_2027" in (env.detail or "")


def _one_exchange_on(ctx, body, *, path):
    """One stored exchange at `path`, sent through a fake bridge; its id.

    THE SESSION IS THE CALLER'S WHEN THERE IS ONE, and that is the whole of
    what this adds over `_one_exchange` below. A replay test queues the
    baseline's reply and its replays' replies in ONE `_with_session` call --
    the ORDER of that queue is the fact under test, since the whole point of
    `http.replay_as` is that the answers DIFFER -- so opening a second
    session here would throw the queue away and leave the replay sending into
    a bridge with nothing left to say.
    """
    if ctx.session is None:
        ctx = _with_session(ctx, [sent_result(body)])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": path},
                                why="set up a body to read")
    return env.result["exchange_id"]


def _one_exchange(ctx, body=b"HTTP/1.1 200 OK\r\n\r\nneedle in a haystack"):
    """Send one request through a fake bridge and return its exchange id."""
    return _one_exchange_on(ctx, body, path="/hay")


def test_grep_finds_a_literal_and_reports_its_offset(tool_run):
    """The offset is the whole point: `http.body(range)` is the escape hatch
    used AFTER a match yields one."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "needle"})
    assert env.outcome == "ok"
    row = env.result["rows"][0]
    assert row["exchange_id"] == xid
    assert row["part"] == "response"
    assert isinstance(row["offset"], int)
    assert "needle" in row["match"]


def test_grep_that_matches_nothing_is_empty_not_ok(tool_run):
    """Principle 4. `empty` says the search ran and found nothing; `ok` with
    zero rows would be indistinguishable from a search that never ran."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "absent"})
    assert env.outcome == "empty"


def test_grep_searches_the_request_when_asked(tool_run):
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "/hay",
                                 "part": "request"})
    assert env.outcome == "ok"
    assert env.result["rows"][0]["part"] == "request"


def test_grep_needs_no_session(tool_run):
    """It reads the blob store, which is on this side. An agent that has
    finished its run can still read what it captured -- and a tool marked
    needs_egress would have refused that."""
    xid = _one_exchange(tool_run)
    tool_run.session = None
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "needle"})
    assert env.outcome == "ok"


def test_grep_reports_which_exchanges_it_could_not_read(tool_run):
    """Section 12 inside one envelope, AND Ruling 14's partial case.

    One exchange is readable and one is not, so the search RAN -- `ok`, not
    `unavailable` -- and both halves must be true at once: the readable
    exchange's match still surfaces in `rows`, and the unreadable one is
    named in the facet rather than silently folded into "no matches". A
    facet that said `0 matches` about both would be the report that cannot
    distinguish tested from unreached, and a test that checked only the
    facet -- as this one used to -- would not catch a regression that
    dropped the real match while still populating `unreadable`."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid, "x-nonexistent"],
                                 "pattern": "needle"})
    assert env.outcome == "ok"
    assert env.result["rows"][0]["exchange_id"] == xid
    assert env.result["rows"][0]["match"] == "needle"
    assert env.result["facets"]["unreadable"] == ["x-nonexistent"]


def test_grep_over_only_unreadable_exchanges_is_unavailable_not_empty(
        tool_run):
    """Ruling 14. `empty` is `envelope.answered`'s reading of a zero-row
    page and means "I searched and found nothing" -- an agent told `empty`
    moves on, which is exactly wrong when nothing was searchable at all.
    `unavailable` is the outcome whose job is to say the tool could not run,
    and that is precisely what happened when every requested exchange is
    unreadable. The `unreadable` facet alone is not enough: it is not the
    field an agent branches on."""
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": ["x-nope1", "x-nope2"],
                                 "pattern": "needle"})
    assert env.outcome == "unavailable"
    assert env.reason == "unreadable"


def test_body_returns_a_bounded_range_and_the_total(tool_run):
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 0, "length": 8})
    assert env.outcome == "ok"
    assert len(env.result["bytes"]) == 8
    # THE TOTAL IS ALWAYS THERE, so an agent knows whether it has the whole
    # thing. A range with no total is a window with no idea how far the room
    # extends.
    assert env.result["total"] > 8


def test_body_past_the_end_answers_ok_with_zero_length_and_the_real_total(
        tool_run):
    """Reading past the end is a legitimate way to discover the end, so it is
    not an error -- and it is not `empty` either.

    `empty` IS PRINCIPLE 3's LIST VOCABULARY and `http.body` returns no list.
    `envelope.answered` reads `empty` off a page envelope's `total == 0`, so
    spelling this `empty` would mean reporting `total: 0` for a body that is
    5 KB long -- a lie about the one number an agent needs in order to know
    it has read the whole thing. `ok` with `length: 0` and the true `total`
    says exactly what happened and where the end is."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 99999,
                                 "length": 10})
    assert env.outcome == "ok"
    assert env.result["length"] == 0
    assert env.result["total"] > 0


def test_body_of_an_unknown_exchange_is_refused(tool_run):
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": "x-nope", "start": 0,
                                 "length": 8})
    assert env.outcome == "refused"
    assert env.reason == "bad_args"


def test_a_binary_body_round_trips_rather_than_becoming_question_marks(
        tool_run):
    """Latin-1 is chosen for exactly this: every byte maps to one character
    and back. A UTF-8 decode with `errors='replace'` would turn a binary
    body into a string of U+FFFD an agent then greps for a payload it can
    never find."""
    raw = b"HTTP/1.1 200 OK\r\n\r\n\x00\x80\xff\xfe"
    xid = _one_exchange(tool_run, raw)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 0,
                                 "length": 64, "part": "response"})
    assert env.result["bytes"].encode("latin-1") == raw


def test_grep_reports_a_corrupt_blob_as_unavailable_not_internal_error(
        tool_run):
    """`_blobs_for`'s own docstring says a blob the store cannot return is
    covered by the same None it returns for a missing row -- so a corrupt
    blob must land the exchange in `unreadable`, not blow up as
    `error / internal`. `error / internal` here would tell an agent hx is
    broken when in fact one stored blob failed its digest check.

    The one exchange requested is the one that is corrupt, so by Ruling 14
    this is the all-unreadable case: `unavailable / unreadable`, not
    `empty` -- the tool could not run, which is a different fact from
    running and finding nothing."""
    from hx.store.blobs import CorruptBlob

    xid = _one_exchange(tool_run)
    real_get = tool_run.blobs.get

    def _corrupt(digest, expected_len=None):
        raise CorruptBlob(f"blob {digest} failed digest verification")

    tool_run.blobs.get = _corrupt
    try:
        env = dispatch_mod.dispatch(tool_run, "http.grep",
                                    {"exchange_ids": [xid],
                                     "pattern": "needle"})
    finally:
        tool_run.blobs.get = real_get
    assert env.outcome == "unavailable"
    assert env.reason == "unreadable"


def _also(config, name, header):
    """`config` with a SECOND declared identity, so that a two-identity
    replay is two identities and not one identity twice.

    `staff_identity_config` declares one, which is all Tasks 3 and 4 needed.
    Section 12's rule inside one result -- "two identities, one answer and
    one rate limit" must stay distinguishable from "two identities, one
    answer" -- is a claim about a row that is NOT the first, and a fixture
    with one identity cannot make it.
    """
    import dataclasses

    from hx import config as config_mod

    ident = config_mod.Identity(
        id=name, strategy="static",
        inject=config_mod.Inject(header=header,
                                 value_from_env=f"HX_{name.upper()}_TOKEN"),
        liveness=config_mod.Liveness(path="/account", expect_body="Sign out",
                                     expect_absent="Sign in"),
        origins=("https://app.test/",))
    return dataclasses.replace(
        config, identities={**config.identities, name: ident})


def test_replay_as_returns_one_row_per_identity_plus_the_baseline(
        tool_run, staff_identity_config, monkeypatch):
    """The shape an authz finding is written from: same request, several
    sessions, one column of differences."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    denied = b"HTTP/1.1 403 Forbidden\r\n\r\nno"
    ctx = _with_session(tool_run,
                        [sent_result(ok), sent_result(denied, status=403)])
    xid = _one_exchange_on(ctx, ok, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"]},
        why="check whether /admin is reachable as staff")
    assert env.outcome == "ok"
    rows = env.result["rows"]
    assert [r["identity"] for r in rows] == ["staff"]
    assert rows[0]["digest"]["status"] == 403
    assert rows[0]["differs"] is True


def test_the_replayed_path_comes_from_the_request_line_not_the_redacted_url(
        tool_run, staff_identity_config, monkeypatch):
    """The trap `_parts_of` exists for. `records.redact_url` runs on EVERY
    write to `exchange.url`, so the stored url for a request carrying
    `?token=` holds `{{observed:param}}` where the credential was. Replaying
    THAT path would put a placeholder on the wire -- a different request from
    the one under investigation, answered differently, and the difference
    reported as an authorisation finding. The stored request BLOB is not
    rewritten by that rule, so its own request line is the one to re-issue.

    The origin still comes from the url, because an origin-form request line
    carries none -- which is the half that looks like an inconsistency."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin/users?token=abc123")
    stored_url, = ctx.conn.execute(
        "SELECT url FROM exchange WHERE id=?", (xid,)).fetchone()
    assert "abc123" not in stored_url, \
        "the url was never redacted, so this test proves nothing"

    dispatch_mod.dispatch(ctx, "http.replay_as",
                          {"exchange_id": xid, "identities": ["staff"]},
                          why="replay the admin listing as staff")
    replayed = ctx.session.bridge.bodies[-1]
    assert replayed.startswith(b"GET /admin/users?token=abc123 HTTP/1.1\r\n")
    assert b"observed:param" not in replayed
    # And to the same origin, taken from the url rather than from the
    # origin-form request line, which carries none.
    sent = ctx.session.bridge.requests[-1]
    assert (sent["target_host"], sent["target_port"]) == ("127.0.0.1", 8080)


def test_an_identity_header_in_the_stored_request_is_never_replayed(
        tool_run, staff_identity_config, monkeypatch):
    """THE LOAD-BEARING RULE OF THIS TOOL. `staff` injects `Cookie` and the
    stored request already carries one. Replayed verbatim, the original
    session's cookie would go out under staff's name: the application would
    answer both replays as the SAME session, every row would come back
    identical, and the tool would report "no difference" for two sessions
    that were never two. An authorisation finding gets written from these
    rows.

    The `X-Trace` half is the other direction and is not decoration: a
    replay that dropped every header would be equally wrong, and would send
    a request the agent never captured."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    env = dispatch_mod.dispatch(
        ctx, "http.send",
        {"host": "127.0.0.1", "port": 8080, "method": "GET", "path": "/admin",
         "headers": ["Cookie: session=alice", "X-Trace: 7"]},
        why="capture a request that carries a session cookie")
    xid = env.result["exchange_id"]
    assert b"Cookie: session=alice" in ctx.session.bridge.bodies[0], \
        "the fixture never put the cookie on the wire, so nothing is proven"

    dispatch_mod.dispatch(ctx, "http.replay_as",
                          {"exchange_id": xid, "identities": ["staff"]},
                          why="replay /admin as staff")
    replayed = ctx.session.bridge.bodies[-1]
    assert b"session=alice" not in replayed
    assert b"Cookie" not in replayed
    assert b"X-Trace: 7" in replayed, \
        "a replay that drops a header no identity injects sends a request " \
        "the agent never captured"


def test_include_anonymous_adds_an_unauthenticated_row(
        tool_run, staff_identity_config, monkeypatch):
    """Its own boolean, not a magic identity name. The unauthenticated
    comparison is the single most valuable row in an authz table, and a
    reserved string could collide with a name an operator declared."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    away = b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok),
                                   sent_result(away, status=302)])
    xid = _one_exchange_on(ctx, ok, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"],
         "include_anonymous": True},
        why="compare staff against anonymous")
    assert [r["identity"] for r in env.result["rows"]] == ["staff", None]
    # UNAUTHENTICATED ON THE WIRE, not merely labelled so. `hx.issue` omits
    # `identity_id` entirely rather than sending a null, because an absent
    # key is what the extension reads as anonymous.
    staff_send, anon_send = ctx.session.bridge.requests[-2:]
    assert staff_send["identity_id"] == "staff"
    assert "identity_id" not in anon_send


def test_replay_of_an_unknown_exchange_is_refused_before_any_send(tool_run):
    ctx = _with_session(tool_run, [])
    env = dispatch_mod.dispatch(ctx, "http.replay_as",
                                {"exchange_id": "x-nope",
                                 "identities": ["staff"]},
                                why="replay something that is not there")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert ctx.session.bridge.requests == []


def test_an_undeclared_identity_is_refused_before_any_identity_registers(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 16. Every name is CHECKED before any name is RESOLVED, and both
    happen before anything sends.

    `bridge.identities` is the half that `bridge.requests` cannot see:
    `ensure_identity` registers with the extension, whose liveness canary is
    itself traffic against the client's application, so a typo in the second
    name found after the first had been registered is still a typo found
    after the client had been touched. An empty `requests` alone would let
    that regression through."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    sent_before = len(ctx.session.bridge.requests)

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff", "ghost"]},
        why="one good name and one typo")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert "ghost" in (env.detail or "")
    assert len(ctx.session.bridge.requests) == sent_before, \
        "staff's replay reached the wire before the typo was found"
    assert ctx.session.bridge.identities == [], \
        "staff was registered -- and its canary fired -- before the typo " \
        "in the second name was found"


def test_one_identitys_refusal_does_not_lose_the_others(
        tool_run, staff_identity_config, monkeypatch):
    """A rate limit on the second identity must not discard the first
    identity's answer. Section 12 again: 'two identities, one answer, one
    refusal' and 'two identities, one answer' are different facts."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    monkeypatch.setenv("HX_AUDITOR_TOKEN", "an0ther")
    tool_run.config = _also(staff_identity_config, "auditor", "Authorization")
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [
        sent_result(ok), sent_result(ok),
        BridgeError("rate_limited: slow down", error_class="rate_limited")])
    xid = _one_exchange_on(ctx, ok, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff", "auditor"]},
        why="compare staff against auditor")
    assert env.outcome == "ok"
    rows = env.result["rows"]
    assert [r["identity"] for r in rows] == ["staff", "auditor"]
    assert rows[0]["digest"] is not None
    assert rows[1]["digest"] is None
    assert rows[1]["refused"] == "rate_limited"


def test_an_original_with_no_stored_response_compares_against_nothing(
        tool_run, staff_identity_config, monkeypatch):
    """`resp_blob` is NULL for an exchange whose body was shed and for one
    whose transport failed before a response existed. Diffing against `b""`
    there would report a length delta and `differs: true` on EVERY row -- an
    authorisation difference on every single call, which is the one claim
    this tool must never make wrongly. `null` says the comparison was not
    made, exactly as `delta.new_tokens` is null rather than `[]` when the
    bodies were too large to diff, and the facet names the reason."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    ctx.conn.execute(
        "UPDATE exchange SET resp_blob=NULL, resp_len=NULL WHERE id=?", (xid,))

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as", {"exchange_id": xid, "identities": ["staff"]},
        why="replay an exchange whose response was never stored")
    assert env.outcome == "ok"
    row = env.result["rows"][0]
    # The replay still happened and its digest is still worth having.
    assert row["digest"]["status"] == 200
    assert row["differs"] is None
    assert row["diff_vs_original"] is None
    assert env.result["facets"]["original_body_stored"] is False


def test_a_corrupt_request_blob_is_unavailable_and_reaches_no_wire(
        tool_run, staff_identity_config, monkeypatch):
    """A blob that fails its own digest check is not a bad argument and it is
    not a defect in hx: `unavailable / unreadable`, the same answer
    `http.grep` gives for the same failure. And nothing may reach a client's
    application on the way to finding out."""
    from hx.store.blobs import CorruptBlob

    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    sent_before = len(ctx.session.bridge.requests)
    real_get = ctx.blobs.get

    def _corrupt(digest, expected_len=None):
        raise CorruptBlob(f"blob {digest} failed digest verification")

    ctx.blobs.get = _corrupt
    try:
        env = dispatch_mod.dispatch(
            ctx, "http.replay_as",
            {"exchange_id": xid, "identities": ["staff"]},
            why="replay an exchange whose request blob is corrupt")
    finally:
        ctx.blobs.get = real_get
    assert env.outcome == "unavailable"
    assert env.reason == "unreadable"
    assert len(ctx.session.bridge.requests) == sent_before


def test_replay_needs_a_why_and_a_session(tool_run):
    """It mutates -- it puts N more requests on a client's network -- and it
    needs egress."""
    ctx = _with_session(tool_run, [])
    args = {"exchange_id": "x-nope", "identities": ["staff"]}
    env = dispatch_mod.dispatch(ctx, "http.replay_as", args)
    assert env.outcome == "refused"
    assert env.reason == "missing_why"
    assert ctx.session.bridge.requests == []

    bridge = ctx.session.bridge
    ctx.session = None
    env = dispatch_mod.dispatch(ctx, "http.replay_as", args,
                                why="no session on purpose")
    assert env.outcome == "unavailable"
    assert env.reason == "no_session"
    assert bridge.requests == []


def test_a_stale_content_length_is_recomputed_rather_than_replayed(
        tool_run, staff_identity_config, monkeypatch):
    """A stored request whose `Content-Length` disagrees with its stored body
    -- a proxy observation whose body was shed, say -- is exactly what
    `issue.request_bytes` REFUSES: a Content-Length that does not match its
    body is a request-smuggling primitive, not a typo to correct silently.
    So the header is dropped and recomputed from the body actually being
    sent, and the replay happens. Replayed verbatim it would refuse instead,
    and an authz question would go unanswered over a header nobody read."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    stale = (b"POST /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n"
             b"Content-Length: 99\r\n\r\nx=1")
    digest, _len = ctx.blobs.put(stale)
    ctx.conn.execute(
        "UPDATE exchange SET req_blob=?, method='POST' WHERE id=?",
        (digest, xid))

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as", {"exchange_id": xid, "identities": ["staff"]},
        why="replay a request whose stored Content-Length is stale")
    assert env.outcome == "ok"
    replayed = ctx.session.bridge.bodies[-1]
    assert b"Content-Length: 3\r\n" in replayed
    assert b"Content-Length: 99" not in replayed
    assert replayed.endswith(b"\r\n\r\nx=1")


def _dated(body, *, date, cookie):
    """One response whose HEAD is unique and whose BODY is not.

    `Date:` and a per-session `Set-Cookie` are the two headers that differ
    between any two replies to one request, which is exactly what makes
    comparing whole responses report a difference every time.
    """
    return (b"HTTP/1.1 200 OK\r\nDate: " + date + b"\r\nSet-Cookie: s="
            + cookie + b"\r\nContent-Type: text/html\r\n\r\n" + body)


def test_replies_differing_only_in_date_and_cookie_do_not_differ(
        tool_run, staff_identity_config, monkeypatch):
    """TRAP 4, and `replay_as`'s own comment calls it the one answer this
    tool must never give wrongly. Two replays of one request differ in their
    `Date:` and their per-session `Set-Cookie` even when the application
    returned byte-identical content, so a comparison over WHOLE responses
    reports an authorisation difference on EVERY single call -- and an
    authz finding gets written from these rows.

    `differs is False` is the assertion, not `not differs`: null is "not
    computed" and would satisfy a falsiness check while meaning the
    opposite."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    page = b"admin panel, unchanged"
    ctx = _with_session(tool_run, [
        sent_result(_dated(page, date=b"Mon, 01 Sep 2026 00:00:00 GMT",
                           cookie=b"aaaaaa")),
        sent_result(_dated(page, date=b"Mon, 01 Sep 2026 00:00:07 GMT",
                           cookie=b"bbbbbb")),
        sent_result(_dated(page, date=b"Mon, 01 Sep 2026 00:00:09 GMT",
                           cookie=b"cccccc"))])
    xid = _one_exchange_on(ctx, page, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"],
         "include_anonymous": True},
        why="two sessions that are shown the same page")
    rows = env.result["rows"]
    assert [r["identity"] for r in rows] == ["staff", None]
    assert rows[0]["differs"] is False
    assert rows[1]["differs"] is False
    assert rows[0]["diff_vs_original"]["len_delta"] == 0
    assert rows[1]["diff_vs_original"]["len_delta"] == 0


def test_a_credential_header_no_identity_declares_is_never_replayed(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 15, and the half the declared set cannot reach. `staff` injects
    `Cookie`, so an `Authorization` in the stored request is named by NO
    declared identity -- and it is exactly what a request lifted from Burp's
    history carries, which `Sender.java` itself names as the natural agent
    action.

    Replayed verbatim, the extension refuses it as `unmanaged_credential`
    before the Gate, so every row comes back refused and no authz table can
    be built at all. `FakeBridge` implements no such check, which is why the
    SENT BYTES are what this asserts on rather than the envelope."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    env = dispatch_mod.dispatch(
        ctx, "http.send",
        {"host": "127.0.0.1", "port": 8080, "method": "GET", "path": "/admin",
         "headers": ["Authorization: Bearer alices-token", "X-Trace: 7"]},
        why="capture a request lifted from history, bearer and all")
    xid = env.result["exchange_id"]
    assert b"alices-token" in ctx.session.bridge.bodies[0], \
        "the fixture never put the bearer on the wire, so nothing is proven"

    dispatch_mod.dispatch(ctx, "http.replay_as",
                          {"exchange_id": xid, "identities": ["staff"]},
                          why="replay /admin as staff")
    replayed = ctx.session.bridge.bodies[-1]
    assert b"alices-token" not in replayed
    assert b"Authorization" not in replayed
    assert b"X-Trace: 7" in replayed, \
        "a replay that drops a header carrying no credential sends a " \
        "request the agent never captured"


def test_more_identities_than_the_bound_is_refused_not_silently_truncated(
        tool_run, staff_identity_config, monkeypatch):
    """The schema's `maxItems` already holds this, so the handler's own guard
    is unreachable through `dispatch` -- which is why it is asserted against
    the handler directly. A SLICE is the wrong shape for a bound whose whole
    subject is blast radius: it would drop the identities past the eighth and
    return a complete-looking table that never asked about them."""
    from hx.tools.errors import ToolRefused
    from hx.tools.impl import http as http_mod

    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    sent_before = len(ctx.session.bridge.requests)

    with pytest.raises(ToolRefused) as caught:
        http_mod.replay_as(
            ctx, exchange_id=xid,
            identities=["staff"] * (http_mod.MAX_IDENTITIES + 1))
    assert caught.value.reason == "bad_args"
    assert len(ctx.session.bridge.requests) == sent_before
