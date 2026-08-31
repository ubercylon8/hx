"""Design section 11: the five properties asserted about the layer itself,
rather than about any one tool."""
from __future__ import annotations

import pytest

from hx.tools import dispatch, registry, spec
from hx.tools import impl  # noqa: F401  (registers every tool)

#: The eleven Plan A builds. The other six carry `needs_egress` and arrive
#: with the session bracket in Plan B.
PLAN_A = {
    "run.start", "run.finish", "run.journal", "run.resume",
    "surface.query", "surface.detail",
    "finding.record", "finding.query", "evidence.attach",
    "checks.list", "report.render",
}

PLAN_B = {"http.send", "http.grep", "http.body", "http.replay_as",
          "scan.run", "crawl.run"}


def test_the_registry_is_exactly_plan_as_eleven():
    # Property 1, half of it. Adding a tool without spec'ing it fails here,
    # and so does spec'ing one without building it. Plan B flips this to the
    # full seventeen.
    assert set(registry.TOOLS) == PLAN_A


def test_plan_a_and_plan_b_together_are_section_eights_seventeen():
    assert PLAN_A | PLAN_B == spec.V1_TOOL_NAMES
    assert not (PLAN_A & PLAN_B)


def test_the_three_human_acts_have_no_entry():
    # Property 2. The absence IS the rule -- there is no code path to forget.
    for name in ("engagement.create", "surface.add", "finding.set_status"):
        assert registry.lookup(name) is None


def test_every_registered_tool_has_an_enforceable_schema_and_a_summary():
    from hx.tools import schema
    for name, tool in registry.TOOLS.items():
        schema.check_schema(tool.params, where=name)
        assert tool.summary.strip(), f"{name} has no summary"
        assert tool.params.get("type") == "object", f"{name} takes an object"


def test_mutating_tools_are_exactly_the_ones_that_write():
    writes = {"run.start", "run.finish", "finding.record", "evidence.attach"}
    assert {n for n, t in registry.TOOLS.items() if t.mutates} == writes


def test_no_plan_a_tool_needs_egress():
    assert not any(t.needs_egress for t in registry.TOOLS.values())


def test_every_tool_schema_matches_its_handlers_signature():
    """A schema property the handler has no parameter for is a `TypeError` at
    call time, which `dispatch` reports as `error / internal` -- an hx defect
    surfaced to the agent mid-engagement, for what is really a wrong tool
    definition.

    Task 5's review proposed catching it inside `registry.register` with
    `inspect`. It lives here instead: the registry should not need to
    introspect a callable to do its job, and a test covers tools added after
    this plan exactly as well -- Plan B's six included.
    """
    import inspect

    for name, tool in registry.TOOLS.items():
        params = inspect.signature(tool.handler).parameters
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            # `checks.list` takes **kw because its argument is spelled `class`
            # on the wire, which is a Python keyword. Nothing to check.
            continue
        declared = set(tool.params.get("properties") or {})
        missing = declared - (set(params) - {"ctx"})
        assert not missing, (
            f"{name}: the schema declares {sorted(missing)} and the handler "
            "takes no such parameter; dispatch would raise TypeError")
        for optional in declared - set(tool.params.get("required") or ()):
            assert params[optional].default is not inspect.Parameter.empty, (
                f"{name}: {optional} is optional in the schema but the handler "
                "gives it no default, so omitting it raises")


def test_the_agent_cannot_confirm_its_own_finding_two_ways_over(engagement):
    # Property 4. The registry has no finding.set_status, so there is no path;
    # and the trigger is what survives someone adding the tool back.
    assert registry.lookup("finding.set_status") is None
    with pytest.raises(Exception, match="agent may not set status"):
        engagement.db.execute(
            "INSERT INTO finding_status_event(id, finding_id, ts_us, actor,"
            " from_status, to_status) VALUES('e-1','f-1',1,'agent',"
            "'new','confirmed')")


def test_every_mutating_tool_is_refused_while_a_halt_is_armed(tool_ctx):
    tool_ctx.halt.halt("stop")
    for name, tool in registry.TOOLS.items():
        if not tool.mutates:
            continue
        env = dispatch.dispatch(tool_ctx, name, {}, why="trying anyway")
        assert env.reason == "halted", f"{name} ran while halted"
