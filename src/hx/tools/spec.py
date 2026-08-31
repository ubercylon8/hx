"""What a tool IS, before any transport knows about it.

A `ToolSpec` is what the registry holds, what the dispatcher reads and what an
adapter projects. `params` is JSON Schema because MCP's `tools/list` must
publish it verbatim -- so the schema is the interface, not a convenience.

THE TWO NAME SETS BELOW ARE ENFORCEMENT, NOT DOCUMENTATION. Section 8 names
seventeen tools and three that are deliberately not agent-facing; both lists
live here as data that `hx.tools.registry` refuses against, so neither can
drift into being a comment nobody checks.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Callable

#: Spec section 8's seventeen. A name outside this set cannot be registered.
#: Plan A of the tool layer builds eleven of them; the other six carry the
#: `needs_egress` bit and arrive with the session bracket in Plan B. The full
#: seventeen are listed from the start so what is missing is visible.
V1_TOOL_NAMES = frozenset({
    "run.start", "run.finish", "run.journal", "run.resume",
    "surface.query", "surface.detail",
    "http.send", "http.grep", "http.body", "http.replay_as",
    "crawl.run",
    "checks.list", "scan.run",
    "finding.record", "finding.query",
    "evidence.attach",
    "report.render",
})

#: Section 8: "Not agent-facing: `engagement.create`, `surface.add`,
#: `finding.set_status`. Creating an engagement and confirming a finding are
#: human acts; they live in the CLI and the web app."
#:
#: DISJOINT FROM THE SET ABOVE, asserted by a test. The registry refuses both
#: sets separately even though the first refusal already covers these three,
#: because the two messages say different things to whoever hits them -- "that
#: is not a v1 tool" and "that is a human act" -- and the day `V1_TOOL_NAMES`
#: grows is the day the second stops being implied by the first.
NEVER_AGENT_FACING = frozenset({
    "engagement.create", "surface.add", "finding.set_status",
})


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    """One tool: its name, its arguments, and what it is allowed to do.

    `needs_egress` and `mutates` are the only two capability bits, and the
    DISPATCHER reads them, never the handler. A handler that decided for itself
    whether it needed a session, or whether a `why` was required, would be a
    second place the rule lives and a first place it can be forgotten.
    """

    name: str
    summary: str
    params: dict[str, Any]
    handler: Callable[..., Any]
    needs_egress: bool = False
    mutates: bool = False

    @property
    def requires_why(self) -> bool:
        """Principle 5: "state-changing tools require `why`".

        DERIVED, never stored. A separate field could be set False on a
        mutating tool, and then the rule would hold everywhere except the one
        place someone typed it wrong.
        """
        return self.mutates
