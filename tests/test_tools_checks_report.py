"""What can be run, and what the client will read."""
from __future__ import annotations

from hx.tools import dispatch
from hx.tools.impl import checks as checks_tools  # noqa: F401  (registers)
from hx.tools.impl import report as report_tools  # noqa: F401  (registers)


def test_the_corpus_lists_disabled_checks_too_and_says_so(tool_ctx):
    rows = dispatch.dispatch(tool_ctx, "checks.list", {}).result["rows"]
    assert rows, "the corpus is not empty"
    assert {"id", "version", "class", "enabled", "needs_egress",
            "insertion_kinds"} <= set(rows[0])
    assert all(r["enabled"] for r in rows), "the fixture enables every class"
    whole_corpus = {r["id"] for r in rows}

    # THE PROPERTY, and the first version of this test did not test it. It
    # asserted `any(r["enabled"] for r in rows)` -- which passes while every
    # class is enabled, and would go on passing if `checks.list` returned
    # ONLY the enabled ones. It asserted the opposite of what its own comment
    # claimed.
    #
    # What matters is that disabling a class changes a FLAG and not
    # MEMBERSHIP: an agent that cannot see `active_safe` in the corpus
    # concludes the class does not apply to this application, where one that
    # sees it listed `enabled: false` knows an operator turned it off. Those
    # are different facts and only one of them belongs in a report.
    tool_ctx.config.checks["active_safe"] = False
    rows = dispatch.dispatch(tool_ctx, "checks.list", {}).result["rows"]
    assert {r["id"] for r in rows} == whole_corpus, "a disabled class vanished"
    off = [r for r in rows if not r["enabled"]]
    assert off and {r["class"] for r in off} == {"active_safe"}


def test_a_class_filter_narrows(tool_ctx):
    rows = dispatch.dispatch(tool_ctx, "checks.list",
                             {"class": "passive"}).result["rows"]
    assert rows and {r["class"] for r in rows} == {"passive"}


def test_an_unknown_class_is_a_schema_refusal(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "checks.list", {"class": "telepathy"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_the_report_renders_markdown_and_reports_its_size(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "report.render", {})
    assert env.outcome == "ok"
    assert env.result["markdown"].lstrip().startswith("#")
    assert env.result["bytes"] == len(env.result["markdown"].encode("utf-8"))


def test_the_report_is_a_read_and_survives_a_halt(tool_ctx):
    # A halted engagement is exactly when someone wants the report.
    tool_ctx.halt.halt("stop")
    assert dispatch.dispatch(tool_ctx, "report.render", {}).outcome == "ok"


def test_the_report_is_rendered_with_the_blob_store_not_without_it(tool_ctx):
    """`report.render` passes `ctx.blobs` through, proved rather than assumed.

    The insertion-points section is derived at render time from the captured
    request bytes -- `report._insertion_coverage` reads `blobs.get(req_blob)`
    -- so it is the one part of the document that vanishes if the blob store
    does not arrive. On the empty fixture the other tests use,
    `render(blobs=...)` and `render(blobs=None)` are byte-identical: writing
    `blobs=None` in the handler would silently drop insertion coverage from
    every real engagement and change nothing they assert.

    `_insertion_coverage`'s own docstring records this exact defect landing
    once already -- a bare `except Exception` swallowed `blobs.get`'s
    `AttributeError` for a `blobs=None` caller, and fourteen tests went on
    passing.
    """
    digest, _ = tool_ctx.blobs.put(
        b"GET /search?q=hello&page=2 HTTP/1.1\r\nHost: app.test\r\n\r\n")
    tool_ctx.conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r-1',?,'browse','staging',1,'completed')",
        (tool_ctx.engagement.id,))
    tool_ctx.conn.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, req_blob) VALUES('x-1','r-1','proxy','ok',1,'GET',"
        "'https://app.test/search?q=hello&page=2',200,?)", (digest,))
    tool_ctx.conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by,"
        " normaliser_version, exemplar_exchange_id)"
        " VALUES('s-1',?,'GET','https','app.test',443,'/search','page,q',"
        "'idempotent_read','proxy',2,'x-1')", (tool_ctx.engagement.id,))

    out = dispatch.dispatch(tool_ctx, "report.render", {}).result["markdown"]
    assert "### Insertion points" in out
    assert "`query`" in out
