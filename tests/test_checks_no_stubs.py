"""No check may still be the stub Task 2 left behind.

Task 2 seeded each of the five files under `passive/` with a placeholder body
that returns `Verdict.inconclusive("not implemented yet")`, and nothing
pinned that placeholder against ever leaving the tree: no marker, no test on
the literal. A stub that survives a task boundary renders in a report exactly
like a check that ran and found nothing conclusive -- "could not test"
forever -- which is the failure S12 exists to prevent (see hx/checks/base.py
on the `inconclusive`/`clean` distinction). This file is the guard Task 4
owes for retiring those five stubs.

Two angles, because a comment can lie about which one a change satisfies:
`test_the_placeholder_string_is_gone_from_the_tree` greps the actual source
tree, so a stub hiding in a check nobody bothered to register (and so never
gets driven by the second test) still gets caught; `test_no_registered_check
_returns_the_stub_reason` drives every check the registry actually lists and
asserts none of them hands the literal back at runtime, so a stub that got
its string edited (and so slips past a grep, e.g. wrapped in an f-string or
built by concatenation) is still caught by behaviour.

THE MUTATION THAT SEPARATES THIS FROM NOT EXISTING: reverting any one of
`cookie_flags.py`, `security_headers.py`, `secret_in_response.py` or
`stack_trace.py` to Task 2's one-line stub --
`return base.Verdict.inconclusive("not implemented yet")` -- reddens both
tests below. Measured by hand during Task 4: restoring `cookie_flags.py` to
its Task-2 stub failed both, restoring it to the real implementation
returned both to green.
"""
from __future__ import annotations

from pathlib import Path

from hx.checks import base, registry

_STUB_REASON = "not implemented yet"

_CHECKS_DIR = Path(__file__).resolve().parent.parent / "src" / "hx" / "checks"


def test_the_placeholder_string_is_gone_from_the_tree():
    """Task 2's exact literal, grepped across every `.py` file the checks
    package ships -- including ones the registry never imports, which the
    behavioural test below cannot see."""
    hits = [str(path) for path in _CHECKS_DIR.rglob("*.py")
            if _STUB_REASON in path.read_text()]
    assert not hits, f"stub placeholder still present in: {hits}"


class _UnreadableBlobs:
    """Every real passive check turns an unreadable blob into its OWN
    `inconclusive` reason (see `passive/_http.py`), never Task 2's literal --
    so this drives every check without needing a real capture to exist."""

    def get(self, digest, expected_len=None):
        raise KeyError(digest)


def test_no_registered_check_returns_the_stub_reason():
    ctx = base.CheckContext(config=None, blobs=_UnreadableBlobs(), run_id="r-1",
                             log=lambda s: None)
    row = base.ExchangeRow(id="x-1", method="GET", url="https://app.test/",
                            status=200, req_blob=None, resp_blob="missing")
    for check in registry.CHECKS:
        on_surface = getattr(check, "on_surface", None)
        if not callable(on_surface):
            continue
        v = on_surface(ctx, None, (row,))
        assert v.reason != _STUB_REASON, (
            f"{check.id} still returns the Task 2 stub verdict")
