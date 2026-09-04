"""`hx amend` -- the sanctioned way to make an edited config take effect.

WHY IT EXISTS. `engagement.open_` refuses an engagement whose `config.yaml`
no longer matches its recorded `scope_version` row, and its message tells the
reader to "re-record the change through record_scope_version()". Nothing
could: that function takes an `Engagement`, and `open_` was the only way to
obtain one. The documented recovery path could not be walked, and every
caller who hit the guard was told to do something impossible.

Found 2026-09-04 while trying to declare a `rate_burst` on an existing
engagement -- which is the legitimate case exactly: an operator who learns
mid-engagement that a limit is wrong.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from hx import cli
from hx import config as config_mod
from hx import engagement as eng_mod


@pytest.fixture
def engagement(tmp_path):
    cfg = config_mod.Config(name="amend", client="C", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    return eng_mod.create(tmp_path / "amend", cfg, author="t")


def _edit(root: Path, old: str, new: str) -> None:
    p = root / "config.yaml"
    text = p.read_text()
    assert old in text, f"fixture assumes {old!r} is in the config"
    p.write_text(text.replace(old, new, 1))


def test_a_diverged_config_cannot_be_opened_until_it_is_amended(engagement):
    """THE GUARD THIS COMMAND SERVES, pinned here so the two are read
    together. A limit somebody widened between two runs -- with every request
    still stamped with the OLD scope_version_id -- is a deliberate act
    wearing an accident's clothes.

    MUTATION: delete the divergence check from `engagement.open_`. Must go
    red -- and `hx` would silently honour hand-edits.
    """
    _edit(engagement.root, "rate_limit_rps: 5", "rate_limit_rps: 500")
    engagement.db.close()

    with pytest.raises(eng_mod.EngagementError, match="diverges"):
        eng_mod.open_(engagement.root)


def test_amend_records_the_edit_and_reopens(engagement):
    """MUTATION: have `amend` skip `record_scope_version`. Must go red -- the
    engagement would still refuse to open afterwards.
    """
    _edit(engagement.root, "rate_limit_rps: 5", "rate_limit_rps: 3")
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["amend", "--root", str(engagement.root),
                   "--reason", "target is fragile"])
    assert result.exit_code == 0, result.output

    reopened = eng_mod.open_(engagement.root)
    try:
        assert reopened.config.rate_limit_rps == 3
    finally:
        reopened.db.close()


def test_amend_shows_what_it_is_about_to_record(engagement):
    """An operator who mistyped a limit finds out HERE, not from a report
    three days later.

    Asserted on the changed values rather than on the word "diff": the
    surrounding output contains plenty of other text.

    MUTATION: drop the `click.echo` of the diff. Must go red.
    """
    _edit(engagement.root, "rate_limit_rps: 5", "rate_limit_rps: 3")
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["amend", "--root", str(engagement.root), "--reason", "why"])

    assert "-rate_limit_rps: 5" in result.output
    assert "+rate_limit_rps: 3" in result.output


def test_amend_refuses_when_nothing_changed(engagement):
    """THE SEPARATING CASE. Recording an identical version would grow the
    audit trail with rows that say nothing, and make a real amendment harder
    to find among them.

    MUTATION: drop the `on_disk == recorded` guard. Must go red.
    """
    root = engagement.root
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["amend", "--root", str(root), "--reason", "no change"])

    assert result.exit_code != 0
    assert "nothing to amend" in result.output


def test_amend_requires_a_reason(engagement):
    """A limit that moved without a stated reason is the thing this command
    exists to prevent. `--reason` is `required=True`, so click refuses.

    MUTATION: make `--reason` optional. Must go red.
    """
    _edit(engagement.root, "rate_limit_rps: 5", "rate_limit_rps: 3")
    engagement.db.close()

    result = CliRunner().invoke(cli.main, ["amend", "--root", str(engagement.root)])

    assert result.exit_code != 0
    assert "reason" in result.output.lower()


def test_the_old_version_is_kept_not_updated(engagement):
    """Runs stamped with the old scope_version_id keep meaning what they
    meant. `record_scope_version` appends; it never updates.

    MUTATION: have `_record_scope` UPDATE the latest row instead of
    inserting. Must go red.
    """
    root = engagement.root
    _edit(root, "rate_limit_rps: 5", "rate_limit_rps: 3")
    engagement.db.close()

    CliRunner().invoke(cli.main, ["amend", "--root", str(root),
                                  "--reason", "slower"])

    reopened = eng_mod.open_(root)
    try:
        rows = reopened.db.execute(
            "SELECT reason FROM scope_version ORDER BY rowid").fetchall()
    finally:
        reopened.db.close()
    assert len(rows) == 2, [r["reason"] for r in rows]
    assert rows[-1]["reason"] == "slower"


# --- the guards `open_diverged` must re-derive, not inherit ----------------
#
# It exists to skip ONE of `open_`'s checks -- divergence. Skipping the others
# came free with copying less code, and shipped for one review round. A store
# written by an incompatible schema, or holding two engagement rows, is
# exactly as unfit to be AMENDED as it is to be opened.
#
# None of the tests above catch any of this: they all ask whether `amend`
# behaves, never whether the door it opens still refuses what the front door
# refuses.

def test_amend_refuses_a_store_from_a_different_schema_version(engagement):
    """`record_scope_version` would otherwise INSERT against a schema nobody
    validated.

    MUTATION: drop the `PRAGMA user_version` check from `open_diverged`.
    Must go red.
    """
    from hx.store import db as db_mod
    root = engagement.root
    _edit(root, "rate_limit_rps: 5", "rate_limit_rps: 3")
    engagement.db.execute(f"PRAGMA user_version={db_mod.SCHEMA_VERSION + 1}")
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["amend", "--root", str(root), "--reason", "why"])

    assert result.exit_code != 0
    assert "different version of hx" in result.output


def test_amend_refuses_a_store_with_two_engagement_rows(engagement):
    """`engagement` is the unit of isolation. With two rows, the new scope
    version would be stamped against whichever one SQLite returned first.

    MUTATION: replace the `len(rows) != 1` check with `fetchone()`. Must go
    red.
    """
    root = engagement.root
    _edit(root, "rate_limit_rps: 5", "rate_limit_rps: 3")
    # THE TRIGGER IS DROPPED ON PURPOSE. `trg_engagement_singleton` refuses a
    # second row, so this guard is defence in depth against a store that got
    # into that state some other way -- a restore, a merge, a hand-edited
    # database. Simulating the corruption is the only way to exercise the code
    # that defends against it; a test that could not create the state would be
    # asserting nothing.
    engagement.db.execute("DROP TRIGGER trg_engagement_singleton")
    engagement.db.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-second','other','other',1,'active')")
    engagement.db.commit()
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["amend", "--root", str(root), "--reason", "why"])

    assert result.exit_code != 0
    assert "exactly one engagement row" in result.output


def test_a_malformed_hand_edit_gets_a_message_not_a_traceback(engagement):
    """THE SECOND MOST LIKELY THING TO HAPPEN after a hand-edit succeeding.
    `hx amend` is the sanctioned path for hand-edited configs, so a YAML
    syntax error in that edit is ordinary -- and reached the operator as a
    raw traceback out of `config_mod.load` on the one command they run when
    something is already wrong.

    MUTATION: call `eng_mod.open_diverged` directly from `amend` instead of
    `_diverged_engagement`. Must go red.
    """
    root = engagement.root
    (root / "config.yaml").write_text("this: [is not: valid yaml\n")
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["amend", "--root", str(root), "--reason", "why"])

    assert result.exit_code != 0
    assert "invalid config at" in result.output
    assert "Traceback" not in result.output
