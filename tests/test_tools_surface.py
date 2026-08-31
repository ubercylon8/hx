"""Principle 3: a tool that can return 3,400 rows must never do so by default."""
from __future__ import annotations

from hx.tools import dispatch, envelope
from hx.tools.impl import surface as surface_tools  # noqa: F401  (registers)


def _surface(conn, engagement_id, *, sid, method="GET", host="app.test",
             path="/x", kind="idempotent_read"):
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by, normaliser_version)"
        " VALUES(?,?,?,'https',?,443,?,'',?,'proxy',2)",
        (sid, engagement_id, method, host, path, kind))


def test_an_empty_engagement_answers_empty_not_unavailable(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "surface.query", {})
    assert env.outcome == "empty" and env.result["total"] == 0


def test_state_changing_surfaces_sort_first(tool_ctx):
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1", path="/read")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-2", path="/write",
             method="POST", kind="state_changing")
    rows = dispatch.dispatch(tool_ctx, "surface.query", {}).result["rows"]
    assert rows[0]["id"] == "s-2"


def test_filters_narrow_and_facets_count_the_filtered_set(tool_ctx):
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1", host="a.test")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-2", host="b.test")
    env = dispatch.dispatch(tool_ctx, "surface.query", {"host": "a.test"})
    assert env.result["total"] == 1
    assert env.result["facets"]["host"] == {"a.test": 1}


def test_the_default_limit_is_fifty_and_the_cursor_walks(tool_ctx):
    for i in range(60):
        _surface(tool_ctx.conn, tool_ctx.engagement.id, sid=f"s-{i:03d}", path=f"/p{i:03d}")
    first = dispatch.dispatch(tool_ctx, "surface.query", {}).result
    assert first["returned"] == envelope.DEFAULT_LIMIT
    assert first["truncated"] is True and first["next_cursor"] == "o-50"
    second = dispatch.dispatch(tool_ctx, "surface.query",
                               {"cursor": first["next_cursor"]}).result
    assert second["returned"] == 10 and second["truncated"] is False
    assert not {r["id"] for r in first["rows"]} & {r["id"] for r in second["rows"]}


def test_a_malformed_cursor_is_a_refusal_not_a_crash(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "surface.query", {"cursor": "nonsense"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_untested_is_the_filter_that_makes_coverage_actionable(tool_ctx):
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-2")
    tool_ctx.conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r-1',?,'scan','staging',1,'running')",
        (tool_ctx.engagement.id,))
    tool_ctx.conn.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id, check_version,"
        " verdict) VALUES('c-1','r-1','s-1','x','1','clean')")
    env = dispatch.dispatch(tool_ctx, "surface.query", {"untested": True})
    assert [r["id"] for r in env.result["rows"]] == ["s-2"]


def test_detail_says_what_was_tested_as_well_as_what_the_surface_is(tool_ctx):
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1")
    env = dispatch.dispatch(tool_ctx, "surface.detail", {"surface_id": "s-1"})
    assert env.result["id"] == "s-1"
    assert env.result["checks"] == [] and env.result["exchanges"] == 0


def test_detail_of_an_unknown_surface_is_empty_not_an_error(tool_ctx):
    # It ran and matched nothing. `unavailable` would say the tool could not
    # look, which is false and would send an agent chasing a broken tool.
    env = dispatch.dispatch(tool_ctx, "surface.detail", {"surface_id": "s-nope"})
    assert env.outcome == "empty"
