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


def test_starting_twice_on_the_same_context_is_refused(tool_ctx):
    env1 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="first")
    run_id_1 = env1.result["id"]
    env2 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="second")
    assert (env2.outcome, env2.reason) == ("refused", "run_open")
    # Exactly one running row exists
    rows = tool_ctx.conn.execute(
        "SELECT id, status FROM run WHERE engagement_id=?",
        (tool_ctx.engagement.id,)).fetchall()
    running = [r for r in rows if r[1] == "running"]
    assert len(running) == 1 and running[0][0] == run_id_1


def test_a_different_kind_can_start_while_one_is_running(tool_ctx):
    env1 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="first")
    run_id_1 = env1.result["id"]
    env2 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "browse"}, why="second")
    assert env2.outcome == "ok" and env2.result["id"].startswith("r-")
    run_id_2 = env2.result["id"]
    assert run_id_1 != run_id_2
    # Both running rows exist
    rows = tool_ctx.conn.execute(
        "SELECT id, kind, status FROM run WHERE engagement_id=?",
        (tool_ctx.engagement.id,)).fetchall()
    running = [(r[0], r[1]) for r in rows if r[2] == "running"]
    assert len(running) == 2
    assert {r[1] for r in running} == {"manual", "browse"}


def test_starting_the_same_kind_from_a_new_context_is_refused(tool_ctx, engagement):
    from hx import halt as halt_mod
    from hx.tools import dispatch as dispatch_mod
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="first")
    # Create a new context for the same engagement
    new_ctx = dispatch_mod.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db))
    env2 = dispatch.dispatch(new_ctx, "run.start", {"kind": "manual"}, why="second")
    assert (env2.outcome, env2.reason) == ("refused", "run_open")


def test_resume_answers_the_four_questions_a_compacted_agent_has(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="mapping")
    env = dispatch.dispatch(tool_ctx, "run.resume", {})
    brief = env.result
    assert set(brief) == {"engagement", "halt", "run", "open_runs",
                          "surfaces", "findings", "recent"}
    assert brief["run"]["id"] == tool_ctx.run_id
    assert brief["open_runs"] == [{"id": tool_ctx.run_id, "kind": "manual"}]
    assert brief["halt"]["armed"] is False


def test_resume_reports_a_halt_because_that_is_why_nothing_is_working(tool_ctx):
    tool_ctx.halt.halt("client asked us to stop")
    brief = dispatch.dispatch(tool_ctx, "run.resume", {}).result
    assert brief["halt"] == {"armed": True, "reason": "client asked us to stop"}


def test_resume_says_there_is_no_run_rather_than_omitting_the_key(tool_ctx):
    assert dispatch.dispatch(tool_ctx, "run.resume", {}).result["run"] is None


def test_the_brief_is_bounded(tool_ctx):
    # Make calls distinguishable with different why values
    for i in range(run_tools.RECENT_LIMIT + 5):
        dispatch.dispatch(tool_ctx, "run.journal", {}, why=f"call-{i:02d}")
    brief = dispatch.dispatch(tool_ctx, "run.resume", {}).result
    assert len(brief["recent"]) == run_tools.RECENT_LIMIT
    # Verify order: recent[0] should be the LAST call (call-24), and
    # recent[-1] should be the 20th-from-last (call-05)
    assert brief["recent"][0]["why"] == "call-24"
    assert brief["recent"][-1]["why"] == "call-05"


def test_the_brief_size_is_bounded_even_with_maximum_length_values(tool_ctx):
    import json
    # Create a brief with maximum-length agent-supplied why values
    max_why = "x" * 500
    for _ in range(run_tools.RECENT_LIMIT):
        dispatch.dispatch(tool_ctx, "run.journal", {}, why=max_why)
    brief = dispatch.dispatch(tool_ctx, "run.resume", {}).result
    # Serialize the brief and check its size is reasonable
    serialized = json.dumps(brief)
    # With RECENT_LIMIT=20, max_why=500, and other fields, the brief should
    # be much less than 1MB even with maximum values
    assert len(serialized) < 1_000_000


def test_resume_is_a_read_and_survives_a_halt(tool_ctx):
    tool_ctx.halt.halt("stop")
    assert dispatch.dispatch(tool_ctx, "run.resume", {}).outcome == "ok"


def test_operator_fields_in_the_brief_are_truncated_but_the_stored_values_are_not(
        tmp_path):
    """Item 3 of the final whole-branch review.

    `test_the_brief_is_bounded` drives the brief off the `engagement` fixture,
    whose `config.name == 't'`, `config.client == 'T'` and whose halt reason in
    that older test was 24 characters -- every one of them already shorter
    than `OPERATOR_FIELD_LIMIT`, so the truncated and untruncated brief were
    byte-identical and the assertion (`< 1_000_000`) held at roughly 15 KB
    either way. Deleting all three `OPERATOR_FIELD_LIMIT` slices in `resume()`
    left the whole suite green -- they were the only survivors of 49 seeded
    mutations. This test gives the engagement a name, a client and a halt
    reason each longer than the limit, so a removed slice changes the
    assertion instead of leaving it vacuously true.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod
    from hx import halt as halt_mod
    from hx.tools import dispatch as dispatch_mod

    limit = run_tools.OPERATOR_FIELD_LIMIT
    long_name = "N" * (limit + 50)
    long_client = "C" * (limit + 50)
    long_reason = "R" * (limit + 50)

    cfg = config_mod.Config(name=long_name, client=long_client,
                            safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng = eng_mod.create(tmp_path / "e", cfg, author="test")
    try:
        eng.db.row_factory = None
        ctx = dispatch_mod.ToolContext(
            engagement=eng, conn=eng.db, blobs=eng.blobs, config=eng.config,
            halt=halt_mod.OperatorHalt(eng.root, eng.db))
        ctx.halt.halt(long_reason)

        brief = dispatch.dispatch(ctx, "run.resume", {}).result

        # Each of the three fields comes back at EXACTLY the limit.
        assert len(brief["engagement"]["name"]) == limit
        assert len(brief["engagement"]["client"]) == limit
        assert len(brief["halt"]["reason"]) == limit
        assert brief["engagement"]["name"] == long_name[:limit]
        assert brief["engagement"]["client"] == long_client[:limit]
        assert brief["halt"]["reason"] == long_reason[:limit]

        # The STORED values are untouched -- truncation is a display-boundary
        # choice the brief makes, not a rewrite of the config or the halt
        # sentinel underneath it.
        assert eng.config.name == long_name
        assert eng.config.client == long_client
        assert ctx.halt.reason == long_reason
    finally:
        eng.db.close()


def test_a_halted_engagement_can_still_close_its_run(tool_ctx):
    # Item 6 of the final whole-branch review: `run.finish` is exempt from
    # the halt gate. Closing an open run does LESS, not more, and in Plan B
    # it is what stops the Burp JVM -- a halt refusing it would leave one
    # running with nothing holding it, exactly what section 8's bracket
    # exists to prevent.
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="mapping")
    run_id = tool_ctx.run_id
    tool_ctx.halt.halt("client asked us to stop")

    env = dispatch.dispatch(tool_ctx, "run.finish",
                            {"status": "aborted", "note": "halted"}, why="closing up")
    assert env.outcome == "ok" and env.result["id"] == run_id
    assert tool_ctx.run_id is None
    assert tool_ctx.conn.execute("SELECT status FROM run WHERE id=?",
                            (run_id,)).fetchone() == ("aborted",)

    # Every OTHER mutating tool stays refused while the halt is armed.
    env = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="again")
    assert (env.outcome, env.reason) == ("refused", "halted")


# ---- Finding 1 of the final whole-branch review: the CLI adapter builds a
# fresh `ToolContext` per `hx tool` invocation, and before this fix
# `ctx.run_id` was a plain field that only ever held what THAT process set --
# so `run.finish` and every run-scoped tool were permanently unreachable
# through it. The tests below drive the reported sequence exactly: a fresh
# context per step, never one carried between them, the way separate `hx
# tool` processes actually are. ---------------------------------------------


def _fresh_ctx(engagement):
    """A brand-new `ToolContext` -- nothing bound -- the way
    `adapters.cli.build_context` makes one for every `hx tool` invocation."""
    from hx import halt as halt_mod
    from hx.tools import dispatch as dispatch_mod
    return dispatch_mod.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db))


def test_start_resume_finish_start_round_trips_across_fresh_contexts(engagement):
    env = dispatch.dispatch(_fresh_ctx(engagement), "run.start",
                            {"kind": "scan"}, why="mapping")
    assert env.outcome == "ok"
    run_id = env.result["id"]

    env = dispatch.dispatch(_fresh_ctx(engagement), "run.resume", {})
    assert env.outcome == "ok"
    assert env.result["run"]["id"] == run_id
    assert env.result["run"]["kind"] == "scan"
    assert env.result["open_runs"] == [{"id": run_id, "kind": "scan"}]

    env = dispatch.dispatch(_fresh_ctx(engagement), "run.finish",
                            {"status": "completed"}, why="done")
    assert env.outcome == "ok"
    assert env.result["id"] == run_id

    # `no_run` now, not the same run again: a fresh context resolves the
    # store, and the store says nothing is open.
    env = dispatch.dispatch(_fresh_ctx(engagement), "run.finish",
                            {"status": "completed"}, why="done again")
    assert (env.outcome, env.reason) == ("unavailable", "no_run")

    env = dispatch.dispatch(_fresh_ctx(engagement), "run.start",
                            {"kind": "scan"}, why="mapping again")
    assert env.outcome == "ok"
    assert env.result["id"] != run_id


def test_finish_with_two_kinds_open_is_ambiguous_without_kind(engagement):
    # Two runs of different kinds, opened by two different (fresh) contexts,
    # exactly as `run.start`'s own docstring says is legitimate: "a crawl
    # running while you browse is two runs".
    manual_id = dispatch.dispatch(_fresh_ctx(engagement), "run.start",
                                  {"kind": "manual"}, why="w").result["id"]
    browse_id = dispatch.dispatch(_fresh_ctx(engagement), "run.start",
                                  {"kind": "browse"}, why="w").result["id"]

    resumed = dispatch.dispatch(_fresh_ctx(engagement), "run.resume", {}).result
    assert resumed["run"] is None  # ambiguous -- never guessed
    assert sorted(resumed["open_runs"], key=lambda r: r["kind"]) == [
        {"id": browse_id, "kind": "browse"}, {"id": manual_id, "kind": "manual"}]

    env = dispatch.dispatch(_fresh_ctx(engagement), "run.finish",
                            {"status": "completed"}, why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "browse" in env.detail and "manual" in env.detail

    # Both runs are still open -- the refusal above closed neither.
    still_open = dispatch.dispatch(_fresh_ctx(engagement), "run.resume", {}).result
    assert len(still_open["open_runs"]) == 2

    # `kind` picks one; the other is untouched.
    env = dispatch.dispatch(_fresh_ctx(engagement), "run.finish",
                            {"status": "completed", "kind": "manual"}, why="w")
    assert env.outcome == "ok" and env.result["id"] == manual_id

    after = dispatch.dispatch(_fresh_ctx(engagement), "run.resume", {}).result
    assert after["run"] == {"id": browse_id, "kind": "browse",
                            "status": "running",
                            "started_us": after["run"]["started_us"],
                            "requests_issued": 0}
    assert after["open_runs"] == [{"id": browse_id, "kind": "browse"}]
