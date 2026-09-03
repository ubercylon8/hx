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


#: A string no real `SessionError` can carry. The obvious message for the
#: test below -- "no burp jar under ~/F0RT1KA/burp-lab" -- is very close to
#: what `find_burp_jar` really says on a machine with no Burp, so the test
#: would have passed against an UNPATCHED `session()` and proved nothing
#: about the seam it names. The sentinel makes only the patched function able
#: to satisfy it.
LAUNCH_SENTINEL = "hx-test-sentinel-4f21a9"


def test_a_launch_failure_is_reported_not_raised(tool_ctx, monkeypatch):
    """`run.start` must still open the run: refusing outright would leave no
    run row and no agent_action row -- no trace that the instrument failed."""
    def boom(eng, **kw):
        raise session_mod.SessionError(
            f"no burp jar under ~/F0RT1KA/burp-lab [{LAUNCH_SENTINEL}]")

    monkeypatch.setattr(session_mod, "session", boom)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "launch_failed"
    # The operator's own sentence, intact -- and the sentinel, which says the
    # sentence came from the patched `session()` and not from a real one.
    assert "burp-lab" in got["detail"]
    assert LAUNCH_SENTINEL in got["detail"]


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
    """EGRESS_KINDS is three kinds, not one. `manual` alone would leave the
    agent's own check pass -- the one thing in section 8 that certainly
    sends -- reporting `not_needed` for a run that needs it most."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    assert live.open_for(tool_ctx, "run-1", "scan")["live"] is True


def test_a_crawl_run_gets_one_too(tool_ctx, monkeypatch):
    """Ruling 21: `crawl` belongs in `EGRESS_KINDS`. Left out, `run.start
    (kind="crawl")` would answer `not_needed`, no Burp would launch, and
    `crawl.run` would have no `crawler_port` to dial -- a crawl that found
    nothing presenting as a crawl that reached nothing, with no error
    anywhere to say so.

    MUTATION: drop `crawl` back out of `EGRESS_KINDS`. Must go red -- the
    only other way `open_for` answers `live: True` is `ctx.session is not
    None` already (`_held`, tested above), and this test's `tool_ctx` fixture
    starts with `session=None`, so that path cannot produce this result
    either.
    """
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "crawl")
    assert got["live"] is True
    assert got["crawler_port"] == 18081


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
    assert got["owner_alive"] is True
    assert "run-1" in got["detail"]


def test_a_session_held_by_a_corpse_says_so_and_names_the_fix(
        tool_ctx, monkeypatch):
    """Section 12 once more: "blocked by a live session" and "blocked by a
    corpse" are different facts, and only one of them means wait. A JVM that
    died mid-run leaves `ctx.session` set, so every later egress run is
    refused -- and an agent told only `session_held` would go on waiting for
    a run that will never give the instrument back on its own.

    OWNERSHIP IS NOT TAKEN HERE. The dead session is not torn down and not
    stolen: `run.finish` on the owning run is the fix, and the detail says
    so, because a run helping itself to another run's teardown is how two
    runs come to share one instrument.
    """
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    held = tool_ctx.session
    tool_ctx.session = type(
        "Corpse", (), {"gone": lambda self: "Burp exited (status 137)"})()

    got = live.open_for(tool_ctx, "run-2", "scan")
    assert got["reason"] == "session_held"
    assert got["owner_alive"] is False
    assert "run.finish" in got["detail"] and "run-1" in got["detail"]
    assert "status 137" in got["detail"]
    # Not stolen and not torn down: the owner still holds what it held.
    assert tool_ctx._session_run_id == "run-1"
    assert held is not None


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
    would put the secret into.

    THE EQUALITY IS THE WHOLE CLAIM. This test used to add
    `assert "s3cret" not in repr(got)` under it, which the line above had
    already settled -- a pair that IS `("staff", 1)` cannot contain anything
    else -- so it read as credential-containment coverage that was not there.
    Containment on the OTHER side of the call, where the credential really
    does travel, is `test_the_declared_origins_bound_the_credential`: it
    reads what reached the bridge and pins it to the id, the generation and
    the declared origins.
    """
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    assert live.ensure_identity(tool_ctx, "staff") == ("staff", 1)


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


def test_close_for_tears_down_the_session_and_nothing_else_on_the_stack(
        tool_ctx, monkeypatch):
    """WHAT THE NESTING BUYS. Task 8 hands `hx mcp`'s own long-lived
    ExitStack straight to `build_context`, so anything that adapter registers
    on it must survive an ordinary `run.finish`. The session goes onto an
    INNER stack for exactly that reason; closing the outer one still unwinds
    the inner, so a crash kills the JVM either way."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    adapters_own = []
    with contextlib.ExitStack() as stack:
        stack.callback(adapters_own.append, "the adapter's own clean-up")
        tool_ctx.stack = stack
        live.open_for(tool_ctx, "run-1", "manual")
        assert live.close_for(tool_ctx, "run-1") is True
        assert adapters_own == [], (
            "run.finish tore down the adapter's own stack entries")
    assert adapters_own == ["the adapter's own clean-up"]


def test_the_inner_stack_is_made_once_and_reused(tool_ctx, monkeypatch):
    """A fresh inner stack per session would leave one spent `__exit__`
    callback on the adapter's stack per session -- a no-op each, and unbounded
    growth across an `hx mcp` conversation that opens and closes runs all
    day."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    first = tool_ctx._session_stack
    live.close_for(tool_ctx, "run-1")
    live.open_for(tool_ctx, "run-2", "manual")
    assert tool_ctx._session_stack is first


def test_a_teardown_that_raises_still_clears_the_bookkeeping(
        tool_ctx, monkeypatch):
    """The failure mode this guards is a tool layer that can never open a
    session again. With `ctx.session` left set for a session that is gone,
    every later egress run is told `session_held` naming a run that is
    already closed -- recoverable only by restarting `hx mcp`. The raise is
    still allowed out; what it may not do is take the context with it."""
    @contextlib.contextmanager
    def brittle_session(eng, **kw):
        yield FakeLive()
        raise RuntimeError("the JVM would not die")

    monkeypatch.setattr(session_mod, "session", brittle_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    with pytest.raises(RuntimeError, match="would not die"):
        live.close_for(tool_ctx, "run-1")
    assert tool_ctx.session is None
    assert tool_ctx._session_run_id is None
    assert tool_ctx._registered == set()

    # And the proof that it matters: the next egress run gets a session
    # rather than being told `session_held` by a run that is already closed.
    monkeypatch.setattr(session_mod, "session", _fake_session)
    assert live.open_for(tool_ctx, "run-2", "manual")["live"] is True


def test_a_gone_that_cannot_answer_is_not_read_as_a_live_session(
        tool_ctx, monkeypatch):
    """`open_for` NEVER RAISES, and the liveness read is inside that promise.
    A `gone()` that throws is not evidence that the holder is alive, so it is
    reported as `owner_alive: False` with the reason in the detail."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")

    def explode(self):
        raise OSError("no such process")

    tool_ctx.session = type("Broken", (), {"gone": explode})()
    got = live.open_for(tool_ctx, "run-2", "manual")
    assert got["reason"] == "session_held"
    assert got["owner_alive"] is False
    assert "no such process" in got["detail"]


def test_a_launch_that_arrives_dead_reports_rather_than_raising_from_gone(
        tool_ctx, monkeypatch):
    """The dead-session check is guarded, because "NEVER RAISES" is stated
    without qualification and a reader will rely on it -- not on an argument
    that `gone()` happens not to raise.

    AND THE JVM STILL GOES. By the time `gone()` is called the session is
    already on the inner stack, so a guard that only turned the raise into a
    `launch_failed` would leave a live Burp held by a stack nothing closes
    until the adapter exits, with the next `open_for` entering a SECOND
    session beside it.
    """
    torn_down = []

    @contextlib.contextmanager
    def unreadable_session(eng, **kw):
        class Unreadable(FakeLive):
            def gone(self):
                raise OSError("proc table went away")
        try:
            yield Unreadable()
        finally:
            torn_down.append(True)

    monkeypatch.setattr(session_mod, "session", unreadable_session)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "launch_failed"
    assert "proc table went away" in got["detail"]
    assert tool_ctx.session is None
    assert torn_down == [True], "a session whose liveness is unreadable was left"
