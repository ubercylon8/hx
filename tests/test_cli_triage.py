"""`hx triage` -- the terminal half of S8's human act."""
from __future__ import annotations

from click.testing import CliRunner

from hx import cli


def _finding(conn, fid="f-1", status="new"):
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES(?,?,?,'Missing HSTS','Low','Firm','check',?,'surface')",
        (fid, conn.execute("SELECT id FROM engagement").fetchone()[0],
         f"k-{fid}", status))


def test_confirming_from_the_cli_moves_the_status(engagement):
    _finding(engagement.db)
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "confirmed",
                   "--root", str(engagement.root)])

    assert result.exit_code == 0, result.output
    assert "new -> confirmed" in result.output


def test_dismissing_without_a_note_is_refused_at_the_terminal(engagement):
    _finding(engagement.db)
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "false_positive",
                   "--root", str(engagement.root)])

    assert result.exit_code != 0
    assert "note is required" in result.output


def test_an_unknown_status_is_refused_by_click_before_the_store_is_opened(
        engagement):
    """`click.Choice` over `triage.TARGETS`, so the two vocabularies cannot
    drift and the operator gets the list rather than a traceback."""
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "reported",
                   "--root", str(engagement.root)])

    assert result.exit_code != 0
    assert "false_positive" in result.output


def test_repeating_a_decision_says_nothing_was_recorded(engagement):
    _finding(engagement.db, status="confirmed")
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "confirmed",
                   "--root", str(engagement.root)])

    assert result.exit_code == 0, result.output
    assert "nothing recorded" in result.output
