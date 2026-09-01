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
