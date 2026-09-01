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


def test_cross_partition_reasons_are_refused_in_envelope():
    # "no_session" belongs to unavailable, not refused
    with pytest.raises(ValueError, match="closed vocabulary"):
        envelope.Envelope(tool="t", outcome="refused", reason="no_session")
    # "halted" belongs to refused, not unavailable
    with pytest.raises(ValueError, match="closed vocabulary"):
        envelope.Envelope(tool="t", outcome="unavailable", reason="halted")


def test_cross_partition_reasons_are_refused_in_exceptions():
    # "no_session" belongs to unavailable, not refused
    with pytest.raises(ValueError, match="closed vocabulary"):
        errors.ToolRefused("no_session")
    # "halted" belongs to refused, not unavailable
    with pytest.raises(ValueError, match="closed vocabulary"):
        errors.ToolUnavailable("halted")


def test_every_reason_belongs_to_exactly_one_outcome():
    # Each reason appears in exactly one outcome's set
    all_reasons = set()
    for outcome, reasons in envelope.REASONS_FOR.items():
        overlap = all_reasons & reasons
        assert not overlap, f"Reason(s) {overlap} appear in multiple outcomes"
        all_reasons.update(reasons)
    # REASONS is exactly the union of all reason sets
    assert envelope.REASONS == all_reasons


def test_envelope_may_not_be_subclassed():
    with pytest.raises(TypeError, match="Envelope may not be subclassed"):
        class Evil(envelope.Envelope):
            pass


def test_parse_offset_is_none_for_no_cursor():
    assert envelope.parse_offset(None) == 0


def test_parse_offset_reads_back_what_it_was_given():
    assert envelope.parse_offset("o-50") == 50
    assert envelope.parse_offset("o-0") == 0


def test_parse_offset_refuses_a_cursor_from_nowhere():
    with pytest.raises(errors.ToolRefused) as exc:
        envelope.parse_offset("nonsense")
    assert exc.value.reason == "bad_args"


def test_parse_offset_refuses_an_overflowing_offset_before_sqlite_ever_sees_it():
    # `int("9" * 20)` succeeds -- Python ints have no ceiling -- but SQLite
    # binds an offset as a signed 64-bit C integer and raises `OverflowError`
    # the moment the query runs. Uncaught, that lands in dispatch's generic
    # `except Exception` and answers `error / internal`, telling the agent hx
    # is broken when its cursor was merely implausible. `parse_offset` catches
    # it here instead, as an ordinary `bad_args` refusal.
    with pytest.raises(errors.ToolRefused) as exc:
        envelope.parse_offset(f"{envelope.CURSOR_PREFIX}{'9' * 20}")
    assert exc.value.reason == "bad_args"
    # Comfortably inside the bound is still fine.
    assert envelope.parse_offset(
        f"{envelope.CURSOR_PREFIX}{envelope.MAX_OFFSET}") == envelope.MAX_OFFSET
    with pytest.raises(errors.ToolRefused):
        envelope.parse_offset(f"{envelope.CURSOR_PREFIX}{envelope.MAX_OFFSET + 1}")


def test_parse_offset_refuses_a_unicode_digit_that_isdigit_would_have_missed():
    # "²" (superscript two) answers True to `str.isdigit()` -- it IS a
    # digit, by Unicode, just not one `int()` accepts in base 10 -- so a
    # cursor built from it used to pass the digit check and then raise
    # `ValueError` two lines later, inside `int()`.
    assert "²".isdigit()
    with pytest.raises(errors.ToolRefused) as exc:
        envelope.parse_offset(f"{envelope.CURSOR_PREFIX}²")
    assert exc.value.reason == "bad_args"


def test_a_non_ran_envelope_may_not_carry_a_result():
    # Non-ran outcomes cannot carry results
    with pytest.raises(ValueError, match="did not run"):
        envelope.Envelope(tool="t", outcome="refused", reason="halted",
                         result={"leaked": "data"})
    with pytest.raises(ValueError, match="did not run"):
        envelope.Envelope(tool="t", outcome="unavailable", reason="no_session",
                         result=[])
    with pytest.raises(ValueError, match="did not run"):
        envelope.Envelope(tool="t", outcome="error", reason="internal",
                         result="error details")
    # But result=None is allowed and will be the default
    e = envelope.Envelope(tool="t", outcome="error", reason="internal")
    assert e.result is None
