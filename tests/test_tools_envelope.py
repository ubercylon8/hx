"""Design section 4: `empty` and `unavailable` are different facts, and the
tool layer is where an agent first has the chance to confuse them."""
from __future__ import annotations

import pytest

from hx.tools import envelope, errors


def test_the_five_outcomes_are_exactly_the_designs_five():
    assert envelope.OUTCOMES == ("ok", "empty", "unavailable", "refused", "error")


def test_a_ran_outcome_may_not_carry_a_reason():
    with pytest.raises(ValueError, match="ran"):
        envelope.Envelope(tool="t", outcome="ok", reason="halted")


def test_a_non_ran_outcome_must_carry_a_reason_from_the_closed_set():
    with pytest.raises(ValueError, match="closed vocabulary"):
        envelope.Envelope(tool="t", outcome="refused", reason="because I said so")


def test_empty_is_decided_from_the_result_not_by_the_handler():
    assert envelope.answered("t", []).outcome == "empty"
    assert envelope.answered("t", None).outcome == "empty"
    assert envelope.answered("t", ["a"]).outcome == "ok"
    assert envelope.answered("t", {"id": "s-1"}).outcome == "ok"


def test_a_page_with_no_total_is_empty_and_one_with_a_total_is_not():
    # A cursor past the end returns zero rows out of a non-zero total. The
    # QUERY matched things; this page did not. That is `ok`, not `empty` --
    # answering `empty` there would tell an agent the surface set is bare.
    page = envelope.page([], total=0, limit=50)
    assert envelope.answered("t", page).outcome == "empty"
    page = envelope.page([], total=12, limit=50)
    assert envelope.answered("t", page).outcome == "ok"


def test_the_page_envelope_has_principle_threes_six_keys():
    page = envelope.page(["a", "b"], total=2, limit=50)
    assert set(page) == {"rows", "returned", "total", "truncated",
                         "next_cursor", "facets"}
    assert page["returned"] == 2 and page["truncated"] is False


def test_truncation_is_known_from_one_extra_row_not_from_the_total():
    # The caller fetches limit+1. Comparing `returned < total` instead would
    # call every cursored page truncated, including the last one.
    page = envelope.page(["a", "b", "c"], total=99, limit=2,
                         cursor_of=lambda row: f"c-{row}")
    assert page["returned"] == 2
    assert page["rows"] == ["a", "b"]
    assert page["truncated"] is True
    assert page["next_cursor"] == "c-b"


def test_the_last_page_has_no_cursor():
    page = envelope.page(["a"], total=1, limit=2, cursor_of=lambda row: "never")
    assert page["truncated"] is False and page["next_cursor"] is None


def test_a_limit_above_the_ceiling_is_refused():
    with pytest.raises(ValueError, match="500"):
        envelope.page([], total=0, limit=501)


def test_as_dict_is_the_wire_shape():
    got = envelope.unavailable("crawl.run", "not_implemented", "no crawler").as_dict()
    assert got == {"tool": "crawl.run", "outcome": "unavailable",
                   "reason": "not_implemented", "detail": "no crawler",
                   "result": None}


def test_a_tool_error_refuses_a_reason_outside_the_vocabulary():
    with pytest.raises(ValueError, match="closed vocabulary"):
        errors.ToolRefused("whatever")


def test_the_two_handler_exceptions_carry_their_outcomes():
    assert errors.ToolRefused("halted").outcome == "refused"
    assert errors.ToolUnavailable("no_session").outcome == "unavailable"
