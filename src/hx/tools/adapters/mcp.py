"""`hx mcp` -- the seventeen tools over stdio, spoken as JSON-RPC 2.0.

HAND-ROLLED, AND THAT WAS THE SPEC'S ONE OPEN QUESTION FOR THIS PLAN. MCP's
stdio transport is newline-delimited JSON-RPC 2.0, and a server needs three
methods: `initialize`, `tools/list` and `tools/call`. That is this file. The
alternative was the `mcp` Python SDK -- a third dependency plus its transitive
closure, inside the one process that holds this engagement's credentials, its
Burp and the operator's halt path. This project runs on two Python
dependencies and a Java extension with none, and a security tool's dependency
footprint is part of its argument. Revisit if MCP's transport requirements
grow past three methods and a line of JSON.

THIS ADAPTER IS ONE PROCESS FOR A WHOLE CONVERSATION, which is the only reason
egress works at all. `hx.session.session()` tears Burp down on every exit, so
`hx tool` -- one process per call -- has nothing for a session to outlive and
reports `no_host`. Here there is an `ExitStack` around the serve loop:
`run.start` pushes a session onto it, `run.finish` pops it, and ANY exit from
`serve` -- return, exception, the agent closing the pipe -- unwinds it. That
is spec section 8's "a crash must not orphan a JVM", first of its three
layers.

`why` TRAVELS INSIDE THE ARGUMENTS AND IS TAKEN BACK OUT. MCP hands a tool one
arguments object and has nowhere else to put Principle 5's reason, so
`tools/list` publishes `why` as a required property of every mutating tool and
`tools/call` pops it before `dispatch` validates -- `ToolSpec.params` sets
`additionalProperties: false` and would refuse it otherwise. The published
schema and the enforced schema are therefore NOT the same object, which is
worth saying out loud: `tool_schema` builds the published one from the
enforced one, and a test runs `check_schema` over the result so the extra
property cannot become a constraint nothing applies.

A MALFORMED CALL IS `dispatch`'s TO REFUSE, NOT THIS FILE'S TO CRASH ON.
Everything here arrives over a pipe from another process: `params` may be a
string, `arguments` may be a list, a number or absent. `dispatch` has guards
for every one of those shapes and its docstring names this adapter as the
reason they exist -- so `tools/call` passes both through as they arrived
rather than coercing them into the shapes it prefers. The one adapter that
speaks JSON-RPC must not be the one that makes those guards unreachable: a
coercion here costs a journal row, and a journal row is how an agent looping
on a malformed call becomes visible at all.

STDOUT IS THE PROTOCOL. Nothing else may be written to it -- not a print, not
a warning, not a traceback. A newline-delimited protocol has no
resynchronisation point, so one stray line desynchronises the client for the
rest of the conversation. Diagnostics go to stderr.
"""
from __future__ import annotations

import contextlib
import json
import sys

from .. import dispatch as dispatch_mod
from .. import impl  # noqa: F401 -- registers every tool
from .. import registry
from . import cli as cli_adapter

#: The MCP revision this server speaks. A client that asks for another is
#: answered with this one, which is what the specification says to do: the
#: server states what it supports and the client decides.
PROTOCOL_VERSION = "2025-06-18"

SERVER_INFO = {"name": "hx", "version": "0.1.0"}

#: JSON-RPC 2.0 s5.1.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603

WHY_DESCRIPTION = (
    "Why you are doing this, in a sentence. It is written to agent_action "
    "and read by whoever asks what this run did.")


def tool_schema(tool) -> dict:
    """One `tools/list` entry: the enforced schema, plus `why` when it needs
    one.

    A COPY, never the registered object. `ToolSpec` is frozen and its
    `params` is the dict `dispatch` validates against; adding a key to it in
    place would publish a property the validator then refuses.
    """
    params = json.loads(json.dumps(tool.params))
    if tool.requires_why:
        params.setdefault("properties", {})["why"] = {
            "type": "string", "minLength": 1, "maxLength": 500,
            "description": WHY_DESCRIPTION}
        params["required"] = sorted(set(params.get("required", [])) | {"why"})
    return {"name": tool.name, "description": tool.summary,
            "inputSchema": params}


def _ok(msg_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def handle(ctx, msg) -> dict | None:
    """One message in, one reply out -- or None for a notification.

    A NOTIFICATION IS A MESSAGE WITH NO `id`, and answering one is a protocol
    violation. `notifications/initialized` is the message every client sends
    the moment `initialize` returns, so a server that replied to it would
    break on its first real conversation rather than in some corner.
    """
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _err(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
    msg_id = msg.get("id")
    method = msg.get("method")
    if msg_id is None:
        return None
    if method == "initialize":
        return _ok(msg_id, {"protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {"tools": {}},
                            "serverInfo": SERVER_INFO})
    if method == "tools/list":
        return _ok(msg_id, {"tools": [tool_schema(registry.TOOLS[n])
                                      for n in sorted(registry.TOOLS)]})
    if method == "tools/call":
        params = msg.get("params")
        if not isinstance(params, dict):
            # A `params` that is a string, a number or a list. `{}` here
            # hands `dispatch` a `name` of None, which it refuses as
            # `bad_args` and journals -- the same treatment every other
            # malformed call gets, and the reason this is not `.get` on
            # whatever arrived is that `.get` on a string raises.
            params = {}
        args = params.get("arguments")
        why = None
        if isinstance(args, dict):
            # POPPED, not passed through, and only from a real object.
            # `ToolSpec.params` is additionalProperties: false, so a `why`
            # left in here would be refused as bad_args -- and Principle 5's
            # reason belongs in agent_action, which is where `dispatch`'s
            # keyword puts it. The copy is so a caller's message is not
            # mutated by being answered.
            args = dict(args)
            why = args.pop("why", None)
        # RULING 20 -- `arguments` GOES TO `dispatch` UNCHANGED. This line
        # was `dict(params.get("arguments") or {})`, and `dispatch`'s own
        # docstring names THIS adapter as the reason its untrusted-argument
        # guards exist: "an `args` that is a string... Each is a `bad_args`
        # refusal, journalled like any other -- a malformed call is exactly
        # what `agent_action` exists to make visible, not a crash that erases
        # it." The `dict()` made those guards unreachable. MEASURED: an
        # `arguments` of "oops", of 5, or of ["a","b"] raised inside `handle`
        # and came back as JSON-RPC -32603 -- which this module's own
        # docstring says must never be how a bad call is rendered -- with
        # ZERO journal rows; and `[["a","b"]]` was silently coerced into
        # `{"a": "b"}`, an arguments object the client never sent.
        env = dispatch_mod.dispatch(ctx, params.get("name"), args, why=why)
        # A REFUSAL IS A RESULT, NOT A TRANSPORT ERROR. `isError` is MCP's
        # way of saying the tool answered badly; a JSON-RPC `error` would say
        # the SERVER failed, would lose the envelope, and would make
        # `scope_denied` -- the extension working exactly as designed -- look
        # like a broken server.
        return _ok(msg_id, {
            "content": [{"type": "text",
                         "text": json.dumps(env.as_dict(), sort_keys=True)}],
            "isError": not env.ran})
    return _err(msg_id, METHOD_NOT_FOUND, f"unknown method {method!r}")


def serve_streams(ctx, stdin, stdout) -> None:
    """The loop. Takes streams so a test can drive it without a subprocess.

    ONE BAD LINE MUST NOT END THE CONVERSATION. A truncated write or a stray
    log line from the agent's side is a parse error for that message and
    nothing more -- ending the loop would take the session, the run and the
    operator's halt path with it, over one malformed line.
    """
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            reply = _err(None, PARSE_ERROR, f"could not parse: {exc}")
        else:
            try:
                reply = handle(ctx, msg)
            except Exception as exc:            # noqa: BLE001
                # `dispatch` never raises, so reaching this is a defect in
                # THIS file. Named in the reply rather than swallowed, and
                # the loop continues: a broken `tools/list` should not cost
                # an operator their live session.
                reply = _err(msg.get("id") if isinstance(msg, dict) else None,
                             INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def serve(engagement) -> None:
    """`hx mcp`, wired to the real stdio.

    THE EXITSTACK IS THE POINT OF THIS FUNCTION. It is what `run.start`
    pushes a Burp onto, and every way out of here -- the agent closing the
    pipe, a raise, a signal that unwinds -- tears that Burp down.
    """
    with contextlib.ExitStack() as stack:
        ctx = cli_adapter.build_context(engagement, stack=stack)
        serve_streams(ctx, sys.stdin, sys.stdout)
