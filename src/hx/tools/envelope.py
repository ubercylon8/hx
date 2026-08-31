"""The one shape every tool answers in, and the five things it can say.

PRINCIPLE 4 SAYS THE TRI-STATE HOLDS AT EVERY LAYER, and section 12 says why:
a report that cannot distinguish "tested, clean" from "never reached" is worse
than no report. `check_run.verdict` already carries that distinction for
checks. Without it HERE, an agent whose `surface.query` returned nothing
because the engagement is empty writes the same sentence as one whose query
returned nothing because the tool could not run -- and section 12's failure
arrives one layer above the layer that was hardened against it.

So `empty` and `unavailable` are separate outcomes, and `answered` decides
between `ok` and `empty` from the RESULT rather than leaving each handler to
spell it. Two handlers spelling "nothing matched" two ways is the same defect
one layer down.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Callable, Sequence

#: Design section 4. `ok` and `empty` both mean the tool RAN; `unavailable`
#: means it could not; `refused` means a gate said no; `error` is a defect.
OUTCOMES = ("ok", "empty", "unavailable", "refused", "error")

#: Closed, because the report counts refusals and free text cannot be counted.
#: Grouped by the outcome each belongs to.
REASONS = frozenset({
    "not_registered", "halted", "missing_why", "bad_args",   # refused
    "no_session", "no_run", "not_implemented",               # unavailable
    "internal",                                              # error
})

#: Principle 3: "a tool that can return 3,400 rows must never do so by
#: default."
DEFAULT_LIMIT = 50
MAX_LIMIT = 500


@dataclasses.dataclass(frozen=True)
class Envelope:
    """What every tool returns, list tool or not."""

    tool: str
    outcome: str
    result: Any = None
    reason: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(
                f"{self.outcome!r} is not an outcome; the design names {OUTCOMES}")
        if self.ran:
            if self.reason is not None:
                # A tool that ran has nothing to excuse. Allowing a reason here
                # would let `ok / halted` exist, and something downstream would
                # eventually read the reason and believe it.
                raise ValueError(
                    f"{self.outcome!r} means the tool ran; it may not carry a reason")
        elif self.reason not in REASONS:
            raise ValueError(
                f"{self.reason!r} is not in the closed vocabulary "
                f"{sorted(REASONS)}; the report counts refusals by reason")

    @property
    def ran(self) -> bool:
        """Whether the tool executed. `empty` did; `unavailable` did not."""
        return self.outcome in ("ok", "empty")

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "outcome": self.outcome,
                "reason": self.reason, "detail": self.detail,
                "result": self.result}


def answered(tool: str, result: Any) -> Envelope:
    """`ok`, or `empty` when the tool ran and matched nothing.

    A PAGE ENVELOPE ANSWERS BY ITS `total`, not by its `returned`. A cursor
    past the end returns zero rows out of a non-zero total: the query matched
    things and this page did not, which is `ok`. Answering `empty` there would
    tell an agent the surface set is bare when it is merely finished.
    """
    if isinstance(result, dict) and "returned" in result and "total" in result:
        empty = result["total"] == 0
    else:
        empty = result is None or (
            isinstance(result, (list, tuple, dict, str)) and not result)
    return Envelope(tool=tool, outcome="empty" if empty else "ok", result=result)


def refused(tool: str, reason: str, detail: str | None = None) -> Envelope:
    return Envelope(tool=tool, outcome="refused", reason=reason, detail=detail)


def unavailable(tool: str, reason: str, detail: str | None = None) -> Envelope:
    return Envelope(tool=tool, outcome="unavailable", reason=reason, detail=detail)


def failed(tool: str, detail: str) -> Envelope:
    """A defect in hx, not a decision about the request."""
    return Envelope(tool=tool, outcome="error", reason="internal", detail=detail)


def page(rows: Sequence[Any], *, total: int, limit: int,
         cursor_of: Callable[[Any], str] | None = None,
         facets: dict[str, Any] | None = None) -> dict[str, Any]:
    """Principle 3's uniform list envelope.

    `rows` MUST hold up to `limit + 1` rows: the extra one is how "there is
    more" is known. The obvious alternative -- `truncated = returned < total`
    -- calls every cursored page truncated, the last one included, so an agent
    following cursors never learns it has finished.
    """
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}, got {limit}")
    kept = list(rows[:limit])
    truncated = len(rows) > limit
    return {
        "rows": kept,
        "returned": len(kept),
        "total": total,
        "truncated": truncated,
        "next_cursor": cursor_of(kept[-1]) if truncated and cursor_of and kept
                       else None,
        "facets": facets or {},
    }
