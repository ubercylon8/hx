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
