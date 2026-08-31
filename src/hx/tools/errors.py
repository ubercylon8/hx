"""The two ways a handler may decline, and the vocabulary it declines in.

A HANDLER RAISES; THE DISPATCHER BUILDS THE ENVELOPE. That split is what makes
design section 4 a claim about every tool rather than about the ones that
remembered: there is exactly one place the outer shape is written, and a
handler cannot answer in a shape of its own.
"""
from __future__ import annotations

from .envelope import REASONS


class ToolError(Exception):
    """A handler declining, with a reason from the closed vocabulary."""

    outcome = "error"

    def __init__(self, reason: str, detail: str | None = None) -> None:
        if reason not in REASONS:
            raise ValueError(
                f"{reason!r} is not in the closed vocabulary {sorted(REASONS)}")
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


class ToolRefused(ToolError):
    """A gate said no. The tool could have run; it was not allowed to."""

    outcome = "refused"


class ToolUnavailable(ToolError):
    """The tool COULD NOT RUN, which is not the same as finding nothing.

    Section 12's governing rule lives on this distinction.
    """

    outcome = "unavailable"
