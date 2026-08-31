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
