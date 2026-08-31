"""The registry is the allowlist, so its refusals are the security story."""
from __future__ import annotations

import pytest

from hx.tools import registry, schema, spec

EMPTY = {"type": "object", "additionalProperties": False, "properties": {}}


def _spec(name: str, **kw) -> spec.ToolSpec:
    return spec.ToolSpec(name=name, summary="x", params=EMPTY,
                         handler=lambda ctx: None, **kw)


@pytest.fixture
def clean_registry(monkeypatch):
    """A registry of our own.

    `hx.tools.impl` registers the real tools at import, and pytest imports
    every test module before running any test -- so by the time this file runs,
    `checks.list` and `surface.query` are already taken. Rebinding the module
    attribute gives these tests an empty one; `register` and `lookup` both
    resolve the global at call time, so they follow it.
    """
    monkeypatch.setattr(registry, "TOOLS", {})
    return registry.TOOLS


def test_the_two_name_sets_are_disjoint():
    # If a name were in both, `register` would refuse it twice with two
    # different explanations and one of them would be wrong.
    assert not (spec.V1_TOOL_NAMES & spec.NEVER_AGENT_FACING)


def test_there_are_seventeen_v1_names():
    assert len(spec.V1_TOOL_NAMES) == 17


def test_a_name_outside_the_v1_set_cannot_be_registered():
    with pytest.raises(registry.RegistryError, match="not one of the seventeen"):
        registry.register(_spec("surface.delete_everything"))


def test_a_human_act_is_refused_by_name_and_says_so():
    # Refused by the v1-set rule too, but the message an operator reads has to
    # be the one that explains WHY, not merely that the name is unknown.
    for name in sorted(spec.NEVER_AGENT_FACING):
        with pytest.raises(registry.RegistryError, match="human act"):
            registry.register(_spec(name))


def test_registering_twice_is_refused(clean_registry):
    registry.register(_spec("checks.list"))
    with pytest.raises(registry.RegistryError, match="already registered"):
        registry.register(_spec("checks.list"))


def test_a_schema_the_validator_cannot_enforce_is_refused_here(clean_registry):
    # The point of check_schema being called at REGISTRATION: an unenforceable
    # schema fails a test run, never an agent's call.
    bad = {"type": "object", "additionalProperties": False,
           "properties": {"q": {"type": "string", "pattern": "^x"}}}
    with pytest.raises(schema.SchemaError, match="not implemented"):
        registry.register(spec.ToolSpec(name="surface.query", summary="x",
                                        params=bad, handler=lambda ctx: None))
    assert "surface.query" not in registry.TOOLS


def test_lookup_of_an_unregistered_name_is_none_not_an_error():
    # The dispatcher turns this into `refused / not_registered`; raising here
    # would make an ordinary agent mistake look like a defect in hx.
    assert registry.lookup("nothing.at.all") is None


def test_requires_why_is_derived_from_mutates():
    assert _spec("run.start", mutates=True).requires_why is True
    assert _spec("run.journal").requires_why is False


def test_a_toolspec_may_not_be_subclassed():
    """The third door into `requires_why`, found by the Task 2 review.

    `frozen=True` already refuses `dataclasses.replace` and
    `object.__setattr__`. A subclass overriding the property was open, and it
    registered cleanly: a mutating tool reporting `requires_why False` is one
    the dispatcher never asks a `why` for.
    """
    with pytest.raises(TypeError, match="may not be subclassed"):
        class Evil(spec.ToolSpec):
            requires_why = property(lambda self: False)
