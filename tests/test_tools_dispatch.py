"""One order, published, that every layer and every test agrees on -- the same
device that made the send path's gate reviewable."""
from __future__ import annotations

import pytest

import json

from hx.tools import dispatch, registry, spec

EMPTY = {"type": "object", "additionalProperties": False, "properties": {}}
ONE = {"type": "object", "additionalProperties": False,
       "properties": {"n": {"type": "integer"}}, "required": ["n"]}


@pytest.fixture
def a_tool(monkeypatch):
    """Install stubs under real v1 names, in a registry of our own.

    `hx.tools.impl` has already registered `run.start`, `checks.list` and the
    rest by the time this file runs -- pytest imports every test module before
    running any test -- so registering by name against the real registry would
    raise "already registered". Rebinding the module attribute sidesteps that
    without teardown bookkeeping.
    """
    monkeypatch.setattr(registry, "TOOLS", {})

    def make(name, handler, **kw):
        return registry.register(spec.ToolSpec(
            name=name, summary="x", params=kw.pop("params", EMPTY),
            handler=handler, **kw))

    return make


def _actions(conn):
    return conn.execute(
        "SELECT tool, result_summary FROM agent_action WHERE actor='agent'"
        " ORDER BY ts_us, rowid").fetchall()


def test_the_order_is_the_published_one():
    assert dispatch.DECISION_ORDER == (
        "not_registered", "halted", "missing_why", "bad_args", "no_session")


def test_an_unregistered_name_is_refused_and_still_journalled(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "nothing.at.all", {})
    assert (env.outcome, env.reason) == ("refused", "not_registered")
    rows = _actions(tool_ctx.conn)
    # The row names the tool that does NOT exist -- that is how an agent
    # looping on a name it invented becomes visible.
    #
    # The summary is asserted by PARTS rather than as one string. It used to
    # be `== "refused: not_registered"`, and Task 4's fix round made
    # `journal.summarise` append a refusal's detail -- because a bare
    # `bad_args` sends an agent round the same loop, which is what this table
    # exists to break. Both changes are right and the exact-string assertion
    # was what stood between them. The detail reaching the journal is now
    # itself worth asserting, so it is.
    assert len(rows) == 1 and rows[0][0] == "nothing.at.all"
    assert rows[0][1].startswith("refused: not_registered")
    # `checks.list` lists security checks, not tools -- an agent told to "ask
    # checks.list" for a tool list learns nothing and asks again. The message
    # now points at the thing that actually lists tools, `hx tool --list`,
    # and no longer tells the agent to ask checks.list for one.
    assert "hx tool --list" in rows[0][1]
    assert "Ask checks.list" not in rows[0][1]


def test_a_halt_stops_a_mutating_tool(tool_ctx, a_tool):
    # `run.start`, not `run.finish` -- the latter is the one member of
    # `HALT_EXEMPT` (item 6 of the final whole-branch review, tested below),
    # and would make this test say the opposite of what it means to show.
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    tool_ctx.halt.halt("stop now")
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why="because")
    assert (env.outcome, env.reason) == ("refused", "halted")


def test_a_halt_does_not_stop_a_read(tool_ctx, a_tool):
    # Deliberate: an operator who has just hit STOP wants the agent able to
    # explain what it was doing. Reads change nothing.
    a_tool("run.journal", lambda c: ["an action"])
    tool_ctx.halt.halt("stop now")
    assert dispatch.dispatch(tool_ctx, "run.journal", {}).outcome == "ok"


def test_the_halt_exemption_is_exactly_run_finish():
    # Item 6 of the final whole-branch review: closing an open run does LESS,
    # not more, so a halt must not block it -- and in Plan B, `run.finish` is
    # what stops the Burp JVM, so refusing it under a halt would leave one
    # running with nothing holding it. A named set, asserted exactly, so a
    # future tool cannot join it quietly.
    assert dispatch.HALT_EXEMPT == frozenset({"run.finish"})


def test_a_halt_does_not_stop_the_exempt_tool(tool_ctx, a_tool):
    a_tool("run.finish", lambda c: {"id": "r-1"}, mutates=True)
    tool_ctx.halt.halt("stop now")
    env = dispatch.dispatch(tool_ctx, "run.finish", {}, why="closing up")
    assert env.outcome == "ok"


def test_a_halt_still_stops_every_other_mutating_tool(tool_ctx, a_tool):
    # The exemption is `run.finish` alone -- every other mutating tool must
    # still be refused under a halt, or the set is not doing its job.
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    tool_ctx.halt.halt("stop now")
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why="mapping")
    assert (env.outcome, env.reason) == ("refused", "halted")


def test_a_mutating_tool_without_a_why_is_refused(tool_ctx, a_tool):
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    for why in (None, "", "   "):
        env = dispatch.dispatch(tool_ctx, "run.start", {}, why=why)
        assert (env.outcome, env.reason) == ("refused", "missing_why")


def test_bad_arguments_are_refused_with_every_problem_at_once(tool_ctx, a_tool):
    a_tool("surface.query", lambda c, n: n, params=ONE)
    env = dispatch.dispatch(tool_ctx, "surface.query", {"nope": 1})
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "n is required" in env.detail and "nope is not an argument" in env.detail


def test_an_egress_tool_without_a_session_is_unavailable_not_refused(tool_ctx, a_tool):
    # It could not run; nothing said no. Section 12 lives on this difference.
    a_tool("http.send", lambda c: None, needs_egress=True, mutates=True)
    env = dispatch.dispatch(tool_ctx, "http.send", {}, why="probing")
    assert (env.outcome, env.reason) == ("unavailable", "no_session")


def test_halt_beats_missing_why_which_beats_bad_args(tool_ctx, a_tool):
    # Trip three rules at once; the earliest must win, or the order is only
    # a comment. Same test shape the send path's order already has.
    a_tool("scan.run", lambda c, n: n, params=ONE, mutates=True,
           needs_egress=True)
    tool_ctx.halt.halt("stop")
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1}).reason == "halted"
    # The two LENGTH guards are `bad_args` refusals too, and used to sit above
    # `lookup` and the halt check -- so a halted engagement plus a `why` too
    # long to accept used to answer `bad_args` here instead of `halted`. Still
    # halted, on the earliest-matching-rule rule.
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1},
                             why="x" * 501).reason == "halted"
    tool_ctx.halt.resume()
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1}).reason == "missing_why"
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1}, why="w").reason == "bad_args"
    assert dispatch.dispatch(tool_ctx, "scan.run", {"n": 1}, why="w").reason == "no_session"


def test_not_registered_beats_an_over_long_name(tool_ctx):
    # The other length guard, same shape: a name over 64 characters that is
    # ALSO unregistered used to answer `bad_args` -- the length guard sat
    # above `lookup` -- when the order says `not_registered` should win,
    # since a name that long was never going to be found anyway.
    env = dispatch.dispatch(tool_ctx, "x" * 70, {})
    assert (env.outcome, env.reason) == ("refused", "not_registered")


def test_a_handler_raising_ToolUnavailable_keeps_its_outcome(tool_ctx, a_tool):
    from hx.tools.errors import ToolUnavailable

    def dead(c):
        raise ToolUnavailable("not_implemented", "no crawler exists")

    a_tool("crawl.run", dead)
    env = dispatch.dispatch(tool_ctx, "crawl.run", {})
    assert (env.outcome, env.reason) == ("unavailable", "not_implemented")


def test_a_handler_raising_anything_else_becomes_an_error_not_a_traceback(tool_ctx, a_tool):
    def broken(c):
        raise ZeroDivisionError("division by zero")

    a_tool("checks.list", broken)
    env = dispatch.dispatch(tool_ctx, "checks.list", {})
    assert (env.outcome, env.reason) == ("error", "internal")
    assert "ZeroDivisionError" in env.detail


def _last_args(conn):
    return conn.execute("SELECT args_blob FROM agent_action"
                        " ORDER BY ts_us DESC, rowid DESC LIMIT 1").fetchone()[0]


def test_an_unvalidated_call_journals_key_names_and_never_values(tool_ctx):
    # Principle 5 makes `args_blob` safe to store verbatim, and that argument
    # covers calls a schema ACCEPTED. Every refusal at or before validation
    # carries a dict nobody checked -- and `additionalProperties: false` means
    # {"password": ...} sent to a REAL tool is exactly a bad_args refusal.
    dispatch.dispatch(tool_ctx, "nothing.at.all", {"password": "hunter2"})
    blob = _last_args(tool_ctx.conn)
    assert "hunter2" not in blob
    assert json.loads(blob) == {"unvalidated_argument_names": ["password"]}


def test_bad_args_is_unvalidated_too_because_validation_is_what_failed(
        tool_ctx, a_tool):
    a_tool("surface.query", lambda c, n: n, params=ONE)
    dispatch.dispatch(tool_ctx, "surface.query", {"password": "hunter2"})
    blob = _last_args(tool_ctx.conn)
    assert "hunter2" not in blob


def test_a_validated_call_journals_its_argument_values(tool_ctx, a_tool):
    a_tool("surface.query", lambda c, n: n, params=ONE)
    dispatch.dispatch(tool_ctx, "surface.query", {"n": 7})
    assert json.loads(_last_args(tool_ctx.conn)) == {"n": 7}


def test_every_call_writes_exactly_one_action_row(tool_ctx, a_tool):
    a_tool("checks.list", lambda c: ["passive"])
    for _ in range(3):
        dispatch.dispatch(tool_ctx, "checks.list", {})
    dispatch.dispatch(tool_ctx, "not.a.tool", {})
    assert len(_actions(tool_ctx.conn)) == 4


# `name`, `args` and `why` arrive over MCP or JSON-RPC, where nothing stops
# the wrong JSON type reaching any of them. Before the guards at the top of
# `dispatch`, each of the four below raised before a single row was written --
# breaking both "never raises" and "exactly one row" at once, and reaching no
# test, because nothing here had passed a non-string name/why or a non-dict
# args.

def test_a_non_string_name_is_refused_and_still_journalled(tool_ctx):
    env = dispatch.dispatch(tool_ctx, ["nope"], {})
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    rows = _actions(tool_ctx.conn)
    # `agent_action.tool` is NOT NULL TEXT, so the row still names something --
    # rendered, not dropped.
    assert len(rows) == 1 and rows[0][0] == "<list>"


def test_non_dict_arguments_are_refused_and_still_journalled(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "surface.query", "not a dict")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert len(_actions(tool_ctx.conn)) == 1


def test_non_string_argument_keys_are_refused_and_still_journalled(tool_ctx):
    # A JSON object's keys are always strings, so a non-string key here did
    # not come from JSON at all -- and `schema.validate`'s own
    # `sorted(set(value) - set(props))` cannot sort a set of mixed types
    # either, which is the second raise this same guard closes.
    env = dispatch.dispatch(tool_ctx, "surface.query", {1: "x", "z": "y"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert len(_actions(tool_ctx.conn)) == 1


def test_a_non_string_why_is_refused_not_coerced(tool_ctx, a_tool):
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why=123)
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    row = tool_ctx.conn.execute(
        "SELECT why FROM agent_action WHERE actor='agent'"
        " ORDER BY ts_us DESC, rowid DESC LIMIT 1").fetchone()
    # Refused, not coerced: `str(123)` in `agent_action.why` would read as an
    # operator's reason for a state change nobody gave.
    assert row[0] is None
    assert len(_actions(tool_ctx.conn)) == 1


def test_a_why_longer_than_500_characters_is_refused_and_journalled(tool_ctx, a_tool):
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    long_why = "x" * 501
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why=long_why)
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert len(_actions(tool_ctx.conn)) == 1


def test_a_name_longer_than_64_characters_on_an_unregistered_name_is_not_registered(
        tool_ctx):
    # A name this long cannot be registered -- nothing in V1_TOOL_NAMES is
    # anywhere near 64 characters -- so `lookup` already answers None for it,
    # and the published order gives `not_registered` before the length guard
    # ever gets a turn. This used to answer `bad_args` instead, which is
    # exactly the inversion the whole-branch review's item 1 named.
    long_name = "x" * 65
    env = dispatch.dispatch(tool_ctx, long_name, {})
    assert (env.outcome, env.reason) == ("refused", "not_registered")
    assert len(_actions(tool_ctx.conn)) == 1
