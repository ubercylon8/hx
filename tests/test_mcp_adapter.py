"""hx mcp: JSON-RPC 2.0 over stdio, hand-rolled.

WHY HAND-ROLLED is a decision the spec left open and this task settles: MCP
stdio is newline-delimited JSON-RPC 2.0 and a server needs `initialize`,
`tools/list` and `tools/call`. That is what this module is. This project runs
on two Python dependencies and a Java extension with none, and a security
tool's dependency footprint is part of its argument -- an SDK here would be a
third dependency, plus its transitive closure, inside the process that holds
the client's credentials and the operator's halt path.

THE TESTS DRIVE `handle` RATHER THAN THE LOOP wherever they can. The loop is
four lines of framing; the protocol is the part that can be wrong.
"""
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from hx.tools import registry
from hx.tools.adapters import mcp


def test_initialize_answers_with_a_protocol_version_and_tool_capability():
    got = mcp.handle(None, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {}})
    assert got["id"] == 1
    assert got["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert "tools" in got["result"]["capabilities"]


def test_a_notification_gets_no_reply_at_all():
    """JSON-RPC: a message with no `id` is a notification and answering one
    is a protocol violation. `notifications/initialized` is the one every
    client sends immediately after `initialize`, so a server that replied
    would break on its first real conversation."""
    assert mcp.handle(None, {"jsonrpc": "2.0",
                             "method": "notifications/initialized"}) is None


def test_tools_list_publishes_every_registered_tool(tool_ctx):
    got = mcp.handle(tool_ctx, {"jsonrpc": "2.0", "id": 2,
                                "method": "tools/list"})
    names = {t["name"] for t in got["result"]["tools"]}
    assert names == set(registry.TOOLS)
    assert len(names) == 17


def test_a_mutating_tools_published_schema_carries_why(tool_ctx):
    """MCP hands a tool ONE arguments object, so `why` has to travel inside
    it -- there is nowhere else for Principle 5's reason to go. The adapter
    pops it back out before `dispatch` validates, because `ToolSpec.params`
    sets `additionalProperties: false` and would otherwise refuse it."""
    got = mcp.handle(tool_ctx, {"jsonrpc": "2.0", "id": 2,
                                "method": "tools/list"})
    by_name = {t["name"]: t for t in got["result"]["tools"]}
    assert "why" in by_name["run.start"]["inputSchema"]["properties"]
    assert "why" in by_name["run.start"]["inputSchema"]["required"]
    # And NOT on a read-only tool, where it would be noise an agent fills in.
    assert "why" not in by_name["surface.query"]["inputSchema"]["properties"]


def test_tools_call_dispatches_and_why_never_reaches_the_handler(tool_ctx):
    got = mcp.handle(tool_ctx, {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "run.start",
                   "arguments": {"kind": "manual", "why": "start probing"}}})
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["outcome"] == "ok"
    assert payload["result"]["kind"] == "manual"
    # `why` reached agent_action and not the handler: had it been passed
    # through as an argument, the schema's additionalProperties: false would
    # have refused the call as bad_args.
    row = tool_ctx.conn.execute(
        "SELECT why FROM agent_action ORDER BY rowid DESC LIMIT 1").fetchone()
    assert row[0] == "start probing"


def test_a_refused_tool_is_isError_but_still_a_jsonrpc_result(tool_ctx):
    """A refusal is the tool answering, not the transport failing. A
    JSON-RPC `error` here would make `scope_denied` look like a broken server
    and would lose the envelope an agent needs to read."""
    got = mcp.handle(tool_ctx, {
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "run.start", "arguments": {"kind": "manual"}}})
    assert "error" not in got
    assert got["result"]["isError"] is True
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["reason"] == "missing_why"


def _rows(ctx):
    return ctx.conn.execute("SELECT COUNT(*) FROM agent_action").fetchone()[0]


# `[["a","b"]]` is here because the ruling names it, not because it
# discriminates: `dict()` coerces it to `{"a": "b"}`, which `surface.query`
# refuses as bad_args anyway, so this row stays green under the coercing
# version. The coercion itself is owned by
# test_a_nested_arguments_list_is_not_coerced_into_an_object below, where the
# coerced object is one the tool ACCEPTS. Measured, not assumed.
@pytest.mark.parametrize("arguments", ["oops", 5, ["a", "b"], [["a", "b"]]])
def test_malformed_arguments_are_refused_and_journalled(tool_ctx, arguments):
    """RULING 20. `dispatch`'s own docstring names THIS adapter as the reason
    its untrusted-argument guards exist -- "an `args` that is a string...
    Each is a `bad_args` refusal, journalled like any other" -- and
    `dict(params.get("arguments") or {})` made every one of them unreachable.

    MEASURED before the fix: "oops", 5 and ["a","b"] each raised inside
    `handle`, surfaced as JSON-RPC -32603, and wrote ZERO journal rows. The
    -32603 is what this file's own docstring says must never be how a bad
    call is rendered: it says the SERVER failed. `[["a","b"]]` was worse
    still -- `dict()` coerced it into `{"a": "b"}` and the tool was called
    with an arguments object the client never sent.

    THE JOURNAL ROW IS THE ASSERTION THAT MATTERS. An agent looping on a
    malformed call is exactly what `agent_action` exists to make visible, and
    a crash erases it."""
    before = _rows(tool_ctx)
    got = mcp.handle(tool_ctx, {
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "surface.query", "arguments": arguments}})
    assert "error" not in got, "a bad call was rendered as a server failure"
    assert got["result"]["isError"] is True
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["outcome"] == "refused"
    assert payload["reason"] == "bad_args"
    assert _rows(tool_ctx) == before + 1, "the malformed call was not recorded"
    tool, = tool_ctx.conn.execute(
        "SELECT tool FROM agent_action ORDER BY rowid DESC LIMIT 1").fetchone()
    assert tool == "surface.query"


@pytest.mark.parametrize("params", ["oops", 5, ["name", "surface.query"]])
def test_a_malformed_params_is_refused_and_journalled_too(tool_ctx, params):
    """The same guard one level out. `msg.get("params") or {}` answered a
    non-dict truthy `params` with an `AttributeError` two lines later --
    -32603 again, and again no row."""
    before = _rows(tool_ctx)
    got = mcp.handle(tool_ctx, {"jsonrpc": "2.0", "id": 10,
                                "method": "tools/call", "params": params})
    assert "error" not in got
    assert got["result"]["isError"] is True
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["outcome"] == "refused"
    assert payload["reason"] == "bad_args"
    assert _rows(tool_ctx) == before + 1, "the malformed call was not recorded"


def test_a_nested_arguments_list_is_not_coerced_into_an_object(tool_ctx):
    """The silent half of Ruling 20, and the one no outcome assertion would
    have caught on its own: `dict([["kind", "manual"]])` is `{"kind":
    "manual"}`, so `run.start` would have RUN -- opening a real run -- on an
    arguments object the client never sent. `ok` was the answer, which is why
    this needs its own test rather than a row in the table above."""
    before = _rows(tool_ctx)
    got = mcp.handle(tool_ctx, {
        "jsonrpc": "2.0", "id": 11, "method": "tools/call",
        "params": {"name": "run.start",
                   "arguments": [["kind", "manual"], ["why", "coerced"]]}})
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["outcome"] == "refused"
    assert payload["reason"] == "bad_args"
    assert _rows(tool_ctx) == before + 1
    assert tool_ctx.conn.execute(
        "SELECT COUNT(*) FROM run").fetchone()[0] == 0, \
        "a coerced arguments list opened a run"


def test_a_malformed_call_through_the_loop_is_not_a_transport_error(tool_ctx):
    """RULING 20 through `serve_streams`, which is where the -32603 actually
    appeared: `handle` raised, the loop's `except Exception` rendered it as
    INTERNAL_ERROR, and the client was told the SERVER failed for a message
    IT had malformed. MEASURED before the fix, byte for byte:

        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message":
         "ValueError: dictionary update sequence element #0 has length 1;
          2 is required"}}

    with `SELECT COUNT(*) FROM agent_action` still 0."""
    before = _rows(tool_ctx)
    out = io.StringIO()
    mcp.serve_streams(tool_ctx, io.StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
        '{"name":"surface.query","arguments":"oops"}}\n'), out)
    reply = json.loads(out.getvalue())
    assert "error" not in reply, (
        "a malformed call came back as a JSON-RPC error, which says the "
        "SERVER failed")
    assert reply["result"]["isError"] is True
    assert json.loads(reply["result"]["content"][0]["text"])["reason"] \
        == "bad_args"
    assert _rows(tool_ctx) == before + 1


def test_an_unknown_method_is_a_jsonrpc_error(tool_ctx):
    got = mcp.handle(tool_ctx, {"jsonrpc": "2.0", "id": 5,
                                "method": "resources/list"})
    assert got["error"]["code"] == -32601


def test_a_malformed_line_does_not_kill_the_server(tool_ctx):
    """The one property the loop must have. An agent that emits one bad line
    -- a truncated write, a stray log -- must not take the session, the run
    and the operator's halt path down with it."""
    out = io.StringIO()
    mcp.serve_streams(tool_ctx, io.StringIO(
        "not json\n"
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700     # parse error
    assert lines[1]["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION


def test_nothing_but_json_rpc_reaches_stdout(tool_ctx):
    """stdout IS the protocol. A print, a warning, a library's banner --
    anything else on this stream desynchronises the client for the rest of
    the conversation, and there is no resynchronising a newline-delimited
    protocol."""
    out = io.StringIO()
    mcp.serve_streams(tool_ctx, io.StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'), out)
    for line in out.getvalue().splitlines():
        assert json.loads(line)["jsonrpc"] == "2.0"


def test_every_published_schema_is_one_this_validator_can_enforce():
    """`tool_schema` adds `why` to a schema `check_schema` already passed,
    and a publisher that emitted something the validator ignores would be
    promising a constraint nothing applies -- which is the exact defect
    `check_schema` exists to refuse."""
    from hx.tools import schema
    for tool in registry.TOOLS.values():
        schema.check_schema(mcp.tool_schema(tool)["inputSchema"],
                            where=tool.name)


def test_hx_mcp_subprocess_writes_only_two_json_rpc_lines_to_real_stdout(
        tmp_path):
    """THE ONE TEST THAT INSPECTS THE REAL OS-LEVEL FILE DESCRIPTOR.

    Every test above drives `handle`/`serve_streams` with an injected
    `io.StringIO`, which proves `serve_streams` writes only valid JSON-RPC
    into the stream IT IS GIVEN. That cannot see a stray `print`, a library's
    deprecation warning, or any other write that lands on file descriptor 1
    directly -- and it does not: a mutation that put `print("noise")` at the
    top of `serve_streams` left `test_nothing_but_json_rpc_reaches_stdout`
    green, because that test's `stdout` was never real. Deleting this test as
    "redundant with" that one is exactly the mistake that lets a stray line
    back in -- a newline-delimited protocol has no resynchronisation point,
    so ONE such line desynchronises the client for the rest of the
    conversation, which is the single highest-value property in this file.

    A REAL SUBPROCESS rather than `capfd` around an in-process `mcp.serve`,
    per Ruling 17: the two catch the same fd-1 writes, but the subprocess
    also exercises the actual `hx mcp` Click command -- the lines added to
    `cli.py`, which nothing else in the suite drives. One test proving two
    things beats one test plus an untested command.

    stderr is read but INTENTIONALLY NOT ASSERTED ON: diagnostics belong
    there by design, and pinning its shape would make this test brittle
    against any future logging line.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod

    cfg = config_mod.Config(name="t", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng = eng_mod.create(tmp_path / "e", cfg, author="test")
    eng.db.close()

    # The console script `pyproject.toml` installs, not `python -m` or an
    # import -- `hx mcp` is the command an operator's MCP client actually
    # spawns, matching `tests/integration/test_cli_session.py`'s own `HX`.
    hx_bin = Path(sys.executable).with_name("hx")
    assert hx_bin.is_file(), (
        f"{hx_bin} is not there -- the console script `pyproject.toml` "
        "installs. `pip install -e .`")

    messages = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')

    # `input=` writes the three messages and then closes stdin, giving
    # `serve_streams`'s `for line in stdin` its EOF -- without that the loop
    # blocks on a read that never returns and the timeout below is what
    # fails the suite instead of wedging it.
    proc = subprocess.run(
        [str(hx_bin), "mcp", "--root", str(eng.root)],
        input=messages, capture_output=True, text=True, timeout=20)

    lines = proc.stdout.splitlines()
    assert len(lines) == 2, (
        f"expected exactly two JSON-RPC lines, got {len(lines)}:\n"
        f"{proc.stdout!r}\nstderr: {proc.stderr!r}")
    first, second = (json.loads(line) for line in lines)
    assert first["jsonrpc"] == "2.0" and first["id"] == 1
    assert first["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert second["jsonrpc"] == "2.0" and second["id"] == 2
    assert len(second["result"]["tools"]) == 17


def test_hx_mcp_installs_the_sigterm_handler_before_it_serves(tmp_path,
                                                              monkeypatch):
    """S7: a Burp process is never orphaned -- and `hx mcp` is the command
    most exposed to the signal that orphans one.

    `serve` holds the session on an `ExitStack`, which unwinds on a return, an
    exception, or the agent closing the pipe. SIGTERM runs none of those: its
    default disposition ends the process without a single `__exit__`. This is
    the one command built to hold a Burp open for a whole conversation, so it
    is the one most likely to be under a service manager and the one most
    likely to be stopped by `docker stop` or a redeploy.

    `run.reap_stale` does not cover it -- it marks run rows stale and never
    kills a process. `capture_start` has carried the wrapper since S7 was
    written; this asserts `mcp` does too, by observing the handler that is
    installed AT THE MOMENT `serve` runs rather than by reading the source.
    """
    import signal
    from click.testing import CliRunner

    from hx import cli
    from hx.tools.adapters import mcp as mcp_adapter

    seen = {}

    def fake_serve(engagement):
        seen["handler"] = signal.getsignal(signal.SIGTERM)

    monkeypatch.setattr(mcp_adapter, "serve", fake_serve)
    made = CliRunner().invoke(cli.main, [
        "new", "acme-2026-09", "--client", "Acme Corp",
        "--scope", "https://app.acme.com/*", "--root", str(tmp_path)])
    assert made.exit_code == 0, made.output
    result = CliRunner().invoke(
        cli.main, ["mcp", "--root", str(tmp_path / "acme-2026-09")])
    assert result.exit_code == 0, result.output

    installed = seen.get("handler")
    assert installed is not None, "serve was never reached"
    # NOT the default, and not "ignore" either: something of this process's own
    # must be standing between a SIGTERM and an orphaned JVM.
    assert installed not in (signal.SIG_DFL, signal.SIG_IGN), installed
    assert callable(installed)


def test_a_real_sigterm_unwinds_what_serve_was_holding(tmp_path, monkeypatch):
    """THE TEST ABOVE PROVES A HANDLER IS INSTALLED; THIS ONE PROVES IT WORKS.

    A review made the distinction and it is a fair one: installation is not
    teardown, and a regression that broke propagation -- a bare `except
    BaseException` swallowing the KeyboardInterrupt inside the loop, say --
    would leave the first test green and a JVM running.

    So this fires an actual SIGTERM at this process from inside the wrapped
    call, out of a stand-in shaped like `serve`'s own body: an `ExitStack`
    holding a cleanup, exactly where `serve` holds the Burp session. The
    assertion is that the cleanup RAN. What is under test is the chain --
    signal -> KeyboardInterrupt -> `with` unwinds -- rather than any part of
    it in isolation.
    """
    import os
    import contextlib
    import signal
    from click.testing import CliRunner

    from hx import cli
    from hx.tools.adapters import mcp as mcp_adapter

    torn_down = []

    def fake_serve(engagement):
        # `serve`'s shape: a stack holding what must not outlive this call.
        with contextlib.ExitStack() as stack:
            stack.callback(torn_down.append, "the session")
            os.kill(os.getpid(), signal.SIGTERM)
            # Reached only if the signal did NOT become an exception, which
            # is the regression this test exists to catch.
            torn_down.append("SIGTERM DID NOT INTERRUPT")

    monkeypatch.setattr(mcp_adapter, "serve", fake_serve)
    made = CliRunner().invoke(cli.main, [
        "new", "acme-2026-09", "--client", "Acme Corp",
        "--scope", "https://app.acme.com/*", "--root", str(tmp_path)])
    assert made.exit_code == 0, made.output

    before = signal.getsignal(signal.SIGTERM)
    CliRunner().invoke(cli.main, ["mcp", "--root", str(tmp_path / "acme-2026-09")])

    assert "SIGTERM DID NOT INTERRUPT" not in torn_down, torn_down
    assert torn_down == ["the session"], torn_down
    # AND THE HANDLER IS RESTORED, asserted against the one that was there
    # BEFORE rather than against a shape. `callable(getsignal(...))` was the
    # first spelling and proves nothing -- almost anything satisfies it,
    # including the handler this command installed and failed to remove.
    assert signal.getsignal(signal.SIGTERM) is before, (
        "hx mcp left its own SIGTERM handler installed; a later signal is the "
        "operator's to handle, not this command's")
