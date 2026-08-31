"""The allowlist.

WHAT IS NOT HERE HAS NO CODE PATH. Section 8's "not agent-facing" list is
enforced by those three names having no entry, so a future refactor cannot
forget a check that was never written as a check. This is the same move
section 4 makes inside the JVM -- two enforcement points, both unavoidable --
and the same one `IdentityRegistry.register` makes by keeping the three-name
header allowlist at the one door rather than at each caller.

`TOOLS` is module state, which is the one thing here worth arguing about: it
makes registration an import side effect, and a test that registers must clean
up after itself. The alternative -- a registry instance threaded through every
adapter -- buys an isolation nothing needs, because the set of tools is fixed
at build time and identical in every process.
"""
from __future__ import annotations

from . import schema
from .spec import NEVER_AGENT_FACING, V1_TOOL_NAMES, ToolSpec


class RegistryError(Exception):
    """A tool that may not be registered, refused at registration."""


#: name -> spec. Populated by `hx.tools.impl` at import.
TOOLS: dict[str, ToolSpec] = {}


def register(tool: ToolSpec) -> ToolSpec:
    """Add `tool`, or refuse.

    Order matters only for the first two rules: the human-act refusal comes
    FIRST so its message is the one an author of `finding.set_status` reads.
    The v1-set rule would also catch those three names, and would explain
    nothing.

    The schema check runs before insertion, so a tool whose schema this
    validator cannot enforce is absent rather than half-registered.
    """
    if tool.name in NEVER_AGENT_FACING:
        raise RegistryError(
            f"{tool.name} is a human act, not a tool: spec section 8 keeps "
            "creating an engagement and confirming a finding in the CLI and "
            "the web app. There is no agent-facing form of it."
        )
    if tool.name not in V1_TOOL_NAMES:
        raise RegistryError(
            f"{tool.name} is not one of the seventeen tools spec section 8 "
            "names. Add it to the spec before adding it here."
        )
    if tool.name in TOOLS:
        raise RegistryError(f"{tool.name} is already registered")
    schema.check_schema(tool.params, where=f"{tool.name}.params")
    TOOLS[tool.name] = tool
    return tool


def lookup(name: str) -> ToolSpec | None:
    """The spec, or None.

    None rather than a raise: an agent naming a tool that does not exist is an
    ordinary mistake the dispatcher answers with `refused / not_registered`,
    and an exception here would make it look like a defect in hx.
    """
    return TOOLS.get(name)
