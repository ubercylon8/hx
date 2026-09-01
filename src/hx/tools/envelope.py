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
import re
from typing import Any, Callable, Sequence

#: Design section 4. `ok` and `empty` both mean the tool RAN; `unavailable`
#: means it could not; `refused` means a gate said no; `error` is a defect.
OUTCOMES = ("ok", "empty", "unavailable", "refused", "error")

#: Closed, because the report counts refusals and free text cannot be counted.
#: Each outcome has its own set of reasons; nothing that crosses a boundary
#: can construct. Before the review, REASONS was a flat frozenset with comment
#: groups, and reasons from neighbouring outcomes constructed cleanly:
#: `ToolRefused("no_session")` built, though "no_session" is unavailable's.
#: The report counts refusals by reason -- a cross-partition reason corrupts a
#: client-facing number. Twelve tests passed with this open because only one
#: tried a reason outside REASONS entirely; none crossed between groups.
REASONS_FOR = {
    "refused": frozenset({"not_registered", "halted", "missing_why", "bad_args", "run_open"}),
    "unavailable": frozenset({"no_session", "no_run", "not_implemented"}),
    "error": frozenset({"internal"}),
}

#: Union of all reason sets, used by `answered` and other generic code that
#: does not know the outcome in advance.
REASONS = frozenset().union(*REASONS_FOR.values())

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

    def __init_subclass__(cls, **kwargs) -> None:
        """An Envelope has no subclasses, and that is load-bearing.

        The `ran` property decides whether a `reason` is permitted. A subclass
        overriding `ran` produces a `refused` envelope that exits 0, and a
        shell or CI job reads a refusal as success. `adapters/cli.py` sets the
        process exit status from `ran`, so the fix is not a rule but a closing.
        """
        raise TypeError(
            "Envelope may not be subclassed; ran is derived from outcome and "
            "an override would un-derive it")

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
        else:
            # Non-ran outcomes: unavailable, refused, error
            if self.reason not in REASONS_FOR.get(self.outcome, frozenset()):
                raise ValueError(
                    f"{self.reason!r} is not in the closed vocabulary "
                    f"{sorted(REASONS_FOR.get(self.outcome, frozenset()))}; "
                    f"the report counts refusals by reason")
            if self.result is not None:
                raise ValueError(
                    f"{self.outcome!r} means the tool did not run; "
                    f"it may not carry a result")

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


#: Every list tool that pages by offset uses this cursor shape, `o-<n>`. One
#: constant so `surface.query` and `finding.query` cannot drift into two
#: prefixes for the same idea -- which is exactly what their two `_offset`
#: functions had started to do before this fix.
CURSOR_PREFIX = "o-"

#: SQLite binds an offset as a signed 64-bit C integer and raises
#: `OverflowError` past that range. Uncaught, that lands in `dispatch`'s
#: generic `except Exception` and answers `error / internal` -- telling the
#: agent hx is broken when its cursor was merely implausible. No real
#: engagement's row count comes close to this, so a cursor naming more is
#: refused as `bad_args` before it ever reaches a query.
MAX_OFFSET = 1_000_000_000

#: What `int(s, 10)` actually parses. `str.isdigit()` is NOT this: it answers
#: True for `"²"` (superscript two) -- a digit BY UNICODE, not one base
#: 10 accepts -- so a cursor built from it passed the old digit check and
#: `int()` then raised `ValueError` two lines later. Anchored, so this never
#: matches a substring of something longer.
_CURSOR_DIGITS = re.compile(r"[0-9]+")


def parse_offset(cursor: str | None) -> int:
    """The offset an `o-<n>` cursor encodes, or 0 for none.

    THE ONE COPY. `surface.query` and `finding.query` each carried their own
    `_offset`, with divergent refusal messages, and neither bounded the
    result nor restricted the digit check to ASCII -- the final whole-branch
    review's item 2. Both defects were shared by construction: any cursor
    parser built this way would have had them, so the fix is one function
    both import, not two patches that could drift apart again.

    RAISES `ToolRefused`, imported inside the function rather than at module
    level: `hx.tools.errors` imports `REASONS_FOR` from this module, so a
    top-level import back here would be a cycle. By the time anything CALLS
    this function both modules have finished importing, so the deferred
    import inside it is safe where one at the top would not be.
    """
    from .errors import ToolRefused

    if cursor is None:
        return 0
    digits = cursor[len(CURSOR_PREFIX):]
    if not cursor.startswith(CURSOR_PREFIX) or not _CURSOR_DIGITS.fullmatch(digits):
        raise ToolRefused(
            "bad_args",
            f"{cursor!r} is not a cursor from this tool; pass back the "
            "next_cursor you were given, or omit it to start over")
    offset = int(digits)
    if offset > MAX_OFFSET:
        raise ToolRefused(
            "bad_args",
            f"{cursor!r} names an offset further than any real engagement "
            "reaches; pass back the next_cursor you were given, or omit it "
            "to start over")
    return offset
