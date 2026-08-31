"""Section 8's bracket. `run.start` and `run.finish` are what a run IS to the
tool layer, and in Plan B they are also what a live Burp is bracketed by."""
from __future__ import annotations

from hx.tools import dispatch, registry
from hx.tools.impl import run as run_tools  # noqa: F401  (registers)


def test_the_three_tools_are_registered_and_only_two_mutate():
    assert registry.lookup("run.start").mutates is True
    assert registry.lookup("run.finish").mutates is True
    assert registry.lookup("run.journal").mutates is False


def test_start_opens_a_run_and_binds_it_to_the_context(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="mapping")
    assert env.outcome == "ok"
    assert env.result["id"].startswith("r-")
    assert tool_ctx.run_id == env.result["id"]
    row = tool_ctx.conn.execute("SELECT kind, status FROM run WHERE id=?",
                           (env.result["id"],)).fetchone()
    assert row == ("manual", "running")


def test_an_unknown_kind_is_a_schema_refusal_not_a_valueerror(tool_ctx):
    # hx.run.open_run raises ValueError on a bad kind. Reaching it would turn
    # an ordinary agent mistake into `error / internal`, which reads as a
    # defect in hx rather than as a wrong argument.
    env = dispatch.dispatch(tool_ctx, "run.start", {"kind": "audit"}, why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_finish_closes_the_run_and_unbinds_it(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="mapping")
    run_id = tool_ctx.run_id
    env = dispatch.dispatch(tool_ctx, "run.finish",
                            {"status": "completed", "note": "done"}, why="done")
    assert env.outcome == "ok" and tool_ctx.run_id is None
    assert tool_ctx.conn.execute("SELECT status, stop_reason FROM run WHERE id=?",
                            (run_id,)).fetchone() == ("completed", "done")


def test_finish_without_a_run_is_unavailable_not_an_error(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "run.finish", {"status": "completed"}, why="w")
    assert (env.outcome, env.reason) == ("unavailable", "no_run")


def test_killed_is_not_a_status_the_agent_may_write(tool_ctx):
    # `killed` is the operator's word for what they did to a run. An agent
    # writing it would put a human act in the run table.
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="w")
    env = dispatch.dispatch(tool_ctx, "run.finish", {"status": "killed"}, why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_the_journal_shows_what_was_already_tried_newest_first(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="one")
    dispatch.dispatch(tool_ctx, "run.finish", {"status": "completed"}, why="two")
    env = dispatch.dispatch(tool_ctx, "run.journal", {})
    tools = [r["tool"] for r in env.result["rows"]]
    assert tools[0] == "run.finish" and "run.start" in tools


def test_the_journal_can_be_filtered_by_tool(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="one")
    dispatch.dispatch(tool_ctx, "run.journal", {})
    env = dispatch.dispatch(tool_ctx, "run.journal", {"tool": "run.start"})
    assert {r["tool"] for r in env.result["rows"]} == {"run.start"}


def test_the_journal_page_is_capped_and_says_when_there_is_more(tool_ctx):
    for _ in range(4):
        dispatch.dispatch(tool_ctx, "run.journal", {})
    env = dispatch.dispatch(tool_ctx, "run.journal", {"last_n": 2})
    assert env.result["returned"] == 2 and env.result["truncated"] is True
