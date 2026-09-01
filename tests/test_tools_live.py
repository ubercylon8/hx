"""The session bracket.

FIVE OUTCOMES, AND FOUR OF THEM ARE "NO SESSION". That is the shape worth
holding in mind while reading: a run opens either way, and what varies is the
reason it has no Burp. An agent that is told `not_needed` knows its browse run
never wanted one; one told `no_host` knows it is running under `hx tool` and
should move to `hx mcp`; one told `launch_failed` has an operator problem; one
told `session_held` knows which run to finish. A single `live: false` would
collapse four different next actions into one shrug.

NOTHING HERE LAUNCHES A JVM. `session.session` is monkeypatched in every test
that gets past the first two branches, which is right for a suite about
bookkeeping -- and `tests/integration/test_tool_session.py` proves the one
claim a fake cannot, that a real Burp comes up configured and goes away again.
"""
import contextlib

import pytest

from hx import identity as identity_mod
from hx import session as session_mod
from hx.tools import live
from tests.test_probe import FakeBridge


class FakeLive:
    """What `session.session()` yields, minus the JVM."""

    operator_port = 18080
    crawler_port = 18081
    epoch = 3
    bridge = object()

    def gone(self):
        return None


@contextlib.contextmanager
def _fake_session(eng, **kw):
    yield FakeLive()


def test_a_browse_run_is_told_it_never_needed_one(tool_ctx):
    got = live.open_for(tool_ctx, "run-1", "browse")
    assert got["live"] is False
    assert got["reason"] == "not_needed"


def test_without_a_host_stack_it_names_the_adapter_and_the_fix(tool_ctx):
    """`hx tool` is one process per call. A session launched there would be
    torn down microseconds later by `session()`'s own unconditional
    teardown, so the honest answer is that this ADAPTER cannot hold one."""
    tool_ctx.stack = None
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "no_host"
    assert "hx mcp" in got["detail"]


def test_a_launch_failure_is_reported_not_raised(tool_ctx, monkeypatch):
    """`run.start` must still open the run: refusing outright would leave no
    run row and no agent_action row -- no trace that the instrument failed."""
    def boom(eng, **kw):
        raise session_mod.SessionError("no burp jar under ~/F0RT1KA/burp-lab")

    monkeypatch.setattr(session_mod, "session", boom)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "launch_failed"
    assert "burp-lab" in got["detail"]


def test_a_successful_launch_binds_the_session_and_reports_its_ports(
        tool_ctx, monkeypatch):
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is True
    assert got["operator_port"] == 18080
    assert got["crawler_port"] == 18081
    assert got["epoch"] == 3
    assert tool_ctx.session is not None


def test_a_scan_run_gets_one_too(tool_ctx, monkeypatch):
    """EGRESS_KINDS is two kinds, not one. `manual` alone would leave the
    agent's own check pass -- the one thing in section 8 that certainly
    sends -- reporting `not_needed` for a run that needs it most."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    assert live.open_for(tool_ctx, "run-1", "scan")["live"] is True


def test_a_second_egress_run_is_told_who_holds_the_session(
        tool_ctx, monkeypatch):
    """One Burp at a time, owned by the run that launched it. The second run
    OPENS -- it can still record findings and query surfaces -- and is told
    exactly which run to finish."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    got = live.open_for(tool_ctx, "run-2", "scan")
    assert got["live"] is False
    assert got["reason"] == "session_held"
    assert "run-1" in got["detail"]


def test_only_the_owning_run_can_close_the_session(tool_ctx, monkeypatch):
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    assert live.close_for(tool_ctx, "run-2") is False
    assert tool_ctx.session is not None
    assert live.close_for(tool_ctx, "run-1") is True
    assert tool_ctx.session is None


def test_closing_with_no_session_at_all_is_false_not_a_raise(tool_ctx):
    """`run.finish` calls this on every run it closes, egress or not: a
    browse run, or a manual run whose launch failed, has no session and must
    still be closeable."""
    tool_ctx.stack = contextlib.ExitStack()
    assert live.close_for(tool_ctx, "run-1") is False


def test_the_stack_is_reusable_so_a_second_run_can_open_its_own(
        tool_ctx, monkeypatch):
    """One `hx mcp` conversation opens and closes many runs on ONE stack.
    `ExitStack.close()` unwinds and leaves the stack usable, which is what
    makes that true -- a stack that could only be closed once would give the
    second egress run of a conversation `launch_failed` for ever."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    live.close_for(tool_ctx, "run-1")
    assert live.open_for(tool_ctx, "run-2", "manual")["live"] is True
    assert tool_ctx._session_run_id == "run-2"


def test_a_dead_session_is_not_handed_out_as_live(tool_ctx, monkeypatch):
    """`LiveSession.gone()` has two ways to be true and neither is 'the
    process exited': a JVM that is up while its extension dropped the bridge
    reconnects at DENY-ALL -- alive, proxying nothing, recording nothing."""
    class Dead(FakeLive):
        def gone(self):
            return "Burp's extension dropped the bridge connection"

    @contextlib.contextmanager
    def dead_session(eng, **kw):
        yield Dead()

    monkeypatch.setattr(session_mod, "session", dead_session)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "launch_failed"
    assert tool_ctx.session is None


def test_a_dead_session_is_torn_down_rather_than_left_running(
        tool_ctx, monkeypatch):
    """A Burp at DENY-ALL is a Burp that is UP. Reporting `launch_failed` and
    leaving the context manager on the stack would leave a 900 MB JVM running
    for a session nobody holds -- section 8's orphaned JVM, arrived at by the
    one branch that knows the session is no good."""
    torn_down = []

    @contextlib.contextmanager
    def dead_session(eng, **kw):
        class Dead(FakeLive):
            def gone(self):
                return "Burp exited (status 1) while the session was live"
        try:
            yield Dead()
        finally:
            torn_down.append(True)

    monkeypatch.setattr(session_mod, "session", dead_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    assert torn_down == [True], "the dead session was left on the stack"


def test_an_identity_is_registered_once_per_generation(
        tool_ctx, monkeypatch, staff_identity_config):
    """A second registration of the same generation would be refused
    `stale_generation` by the extension, so a tool that re-registered on
    every send would fail on its second one."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()

    first = live.ensure_identity(tool_ctx, "staff")
    second = live.ensure_identity(tool_ctx, "staff")
    assert first == second == ("staff", 1)
    assert len(tool_ctx.session.bridge.identities) == 1


def test_the_credential_never_leaves_this_function(
        tool_ctx, monkeypatch, staff_identity_config):
    """Principle 5. What comes back is a name and a number -- an exchange
    row's worth -- and never a `Resolved`, which a journalled return value
    would put the secret into."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    got = live.ensure_identity(tool_ctx, "staff")
    assert got == ("staff", 1)
    assert "s3cret" not in repr(got)


def test_the_declared_origins_bound_the_credential(
        tool_ctx, monkeypatch, staff_identity_config):
    """`origins` is what the extension applies the credential within, and an
    empty tuple is 'the operator did not widen it' rather than 'everywhere'.
    Dropping it here would send a client's live session to every host in
    scope, which is the widening `Identity.origins` exists to prevent."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    live.ensure_identity(tool_ctx, "staff")
    assert tool_ctx.session.bridge.identities == [
        ("staff", 1, ("https://app.test/",))]


def test_a_credential_that_is_not_in_the_environment_is_not_registered(
        tool_ctx, monkeypatch, staff_identity_config):
    """`resolve` refuses rather than issuing anonymously, and the refusal
    must not leave a half-registration behind: an identity recorded here that
    the extension never heard of would make the NEXT call believe it had
    already registered and send unauthenticated under its name."""
    monkeypatch.delenv("HX_STAFF_TOKEN", raising=False)
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    with pytest.raises(identity_mod.IdentityError, match="HX_STAFF_TOKEN"):
        live.ensure_identity(tool_ctx, "staff")
    assert tool_ctx._registered == set()
    assert tool_ctx.session.bridge.identities == []


def test_an_undeclared_identity_names_what_is_declared(
        tool_ctx, staff_identity_config):
    tool_ctx.config = staff_identity_config
    with pytest.raises(ValueError, match="staff"):
        live.ensure_identity(tool_ctx, "nope")
