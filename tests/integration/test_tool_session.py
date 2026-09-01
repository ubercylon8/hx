"""The bracket against a real Burp.

Everything else about the bracket is proved with a monkeypatched
`session.session`, which is right -- the branches are about bookkeeping. This
file proves the one thing a fake cannot: that `run.start` on a manual run
brings up a JVM whose extension is CONFIGURED, and that `run.finish` takes it
away again.

THE EXITSTACK IS THE TEST'S OWN SAFETY NET AS WELL AS THE PRODUCT'S. It is
the same object `hx mcp` will hand `build_context`, and it is what section 8's
"a crash must not orphan a JVM" rests on first: an assertion that fails
between `run.start` and `run.finish` unwinds it on the way out, which is why
the JVM here cannot outlive a red test. `tests/integration/conftest.py`
records what happens without that discipline -- "a 900 MB JVM per debugging
attempt".

THE SEED HOME IS NOT THE OPERATOR'S. `hx.tools.live.open_for` calls
`session()` with no `seed`, deliberately: a tool layer has no business
choosing which Burp home a consultant's licence lives in. So this test says so
the way an operator would, through `$HX_BURP_SEED_HOME` -- the same override
`tests/integration/test_cli_session.py` gives the `hx capture start`
subprocess, and for the same reason. Without it `make_home` would copy the
developer's real `$HOME`, which on a consultant's machine is live client
project state.
"""
from __future__ import annotations

import contextlib

import pytest

from hx import halt as halt_mod
from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401 -- registers every tool
from tests.integration import burp_fixture as bf

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _prerequisites(monkeypatch):
    """The rig's order: an unbuilt jar FAILS, a missing Burp SKIPS.

    Asking the skip question first would turn a forgotten `extension/build.sh`
    into a silently skipped suite, which is how this project's tests have
    twice gone dark while reporting green.
    """
    if bf.unbuilt():
        pytest.fail("unbuilt: " + ", ".join(bf.unbuilt()))
    if bf.missing():
        pytest.skip("missing: " + ", ".join(bf.missing()))
    monkeypatch.setenv("HX_BURP_SEED_HOME", str(bf.SEED_HOME))


def test_run_start_brings_up_a_configured_burp_and_run_finish_stops_it(
        engagement):
    with contextlib.ExitStack() as stack:
        ctx = dispatch_mod.ToolContext(
            engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
            config=engagement.config,
            halt=halt_mod.OperatorHalt(engagement.root, engagement.db),
            stack=stack)
        env = dispatch_mod.dispatch(ctx, "run.start", {"kind": "manual"},
                                    why="prove the bracket brings up a JVM")
        assert env.outcome == "ok"
        sess = env.result["session"]
        assert sess["live"] is True, sess
        # EPOCH IS NEVER 0 HERE. 0 is what the extension reports at DENY-ALL,
        # and a session that reached this object got a `configure` the
        # extension accepted. An assertion on the ports alone would pass
        # against a Burp that refuses everything.
        assert sess["epoch"] != 0
        assert ctx.session is not None
        proc = ctx.session.proc
        assert proc.poll() is None, "run.start reported a JVM that is not there"

        env = dispatch_mod.dispatch(ctx, "run.finish", {"status": "completed"},
                                    why="close the bracket")
        assert env.outcome == "ok"
        assert env.result["session_closed"] is True
        assert ctx.session is None
        assert proc.poll() is not None, "run.finish left the JVM running"
