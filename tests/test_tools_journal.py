"""Principle 5's record. It is also the loop-prevention hole: an agent that
cannot see what it already tried repeats it."""
from __future__ import annotations

import json

import pytest

from hx.tools import envelope, journal


def _row(conn, engagement_id):
    return conn.execute(
        "SELECT actor, tool, args_blob, result_summary, why FROM agent_action"
        " WHERE engagement_id=? ORDER BY ts_us DESC, rowid DESC LIMIT 1",
        (engagement_id,)).fetchone()


def test_small_arguments_are_stored_inline_and_read_back_as_json(engagement):
    args = {"host": "app.example.com", "limit": 10}
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="surface.query", args=args, why=None,
                   env=envelope.answered("surface.query", ["a"]),
                   blobs=engagement.blobs)
    actor, tool, args_blob, summary, why = _row(engagement.db, engagement.id)
    assert actor == "agent" and tool == "surface.query" and why is None
    assert json.loads(args_blob) == args


def test_large_arguments_spill_to_the_blob_store_and_are_retrievable(engagement):
    args = {"request": "A" * (journal.ARGS_INLINE_MAX + 1)}
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="surface.query", args=args, why=None,
                   env=envelope.answered("surface.query", []),
                   blobs=engagement.blobs)
    args_blob = _row(engagement.db, engagement.id)[2]
    assert args_blob.startswith(journal.SPILL_PREFIX)
    digest = args_blob[len(journal.SPILL_PREFIX):]
    assert json.loads(engagement.blobs.get(digest)) == args


def test_a_refusal_is_journalled_too(engagement):
    # The rows that make the report's refusal counts real. A layer that
    # recorded only successes would answer "what did the agent try" with
    # "everything that worked".
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="run.start", args={}, why=None,
                   env=envelope.refused("run.start", "missing_why"),
                   blobs=engagement.blobs)
    assert _row(engagement.db, engagement.id)[3] == "refused: missing_why"


def test_a_page_result_summarises_as_counts_not_as_rows(engagement):
    page = envelope.page(["a", "b"], total=97, limit=2)
    env = envelope.answered("surface.query", page)
    assert journal.summarise(env) == "ok: 2 of 97 rows"


def test_a_summary_is_capped(engagement):
    # The "id" branch produces a summary; exercise truncation there.
    env = envelope.answered("report.render", {"id": "x" * 5000})
    summary = journal.summarise(env)
    assert len(summary) == journal.SUMMARY_MAX
    assert summary.startswith("ok: ")


def test_the_why_is_stored_verbatim(engagement):
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="run.start", args={}, why="mapping the checkout flow",
                   env=envelope.answered("run.start", {"run_id": "r-1"}),
                   blobs=engagement.blobs)
    assert _row(engagement.db, engagement.id)[4] == "mapping the checkout flow"


@pytest.mark.parametrize("raw,expect_absent", [
    ("/callback?access_token=SEKRIT&state=x", "SEKRIT"),
    ("/cb?token=SEKRIT", "SEKRIT"),
    ("http://alice:SEKRIT@app.test/a", "SEKRIT"),
])
def test_a_credential_in_a_url_argument_is_redacted_too(raw, expect_absent):
    """THE HEADER GUARD DID NOT COVER THIS, and the store disagreed with
    itself about the same string. MEASURED before the fix: `exchange.url`
    held `access_token={{observed:param}}` while `agent_action.args_blob`
    held the token verbatim -- one table redacting what the other kept.

    `http.send`'s `path` is agent-supplied and required, and replaying an
    OAuth callback is ordinary work during an assessment, so this is
    reachable by typing rather than by contriving."""
    got = journal._redacted(raw)
    assert expect_absent not in got
    # The KEY survives: "the agent sent an access_token" is the fact
    # run.journal exists to report.
    assert "{{observed:" in got


def test_redaction_leaves_ordinary_strings_alone():
    """The redactor runs over EVERY string argument, so it has to be inert on
    the ones that carry nothing. A guard that mangled `pattern` or `path`
    would corrupt the journal's account of what was tried."""
    for benign in ["needle", "/a?b=c", "GET", "", "not a url, just prose"]:
        assert journal._redacted(benign) == benign


@pytest.mark.parametrize("raw,secret", [
    ("field=1\r\nCookie: session=SEKRIT\r\nother=3", "SEKRIT"),
    ("a=1\nAuthorization: Bearer SEKRIT", "SEKRIT"),
    ("x=1\r\nProxy-Authorization: Basic SEKRIT\r\ny=2", "SEKRIT"),
])
def test_a_credential_on_a_later_line_is_redacted(raw, secret):
    """THE ANCHORED VERSION MISSED THE SHAPE `http.send` ALREADY SHIPS.
    `headers` arrives as separate array items, so line one was always the
    whole string and `.match` sufficed. A `body` is one free string, and an
    agent replaying a captured request by hand puts a whole request in it --
    credential on line two, nothing looking past line one.

    This was recorded in DECISIONS.md as debt against a hypothetical FUTURE
    tool taking a raw request string. The tool exists; it is `http.send`."""
    got = journal._redacted(raw)
    assert secret not in got
    assert "{{observed:" in got


def test_redaction_keeps_the_lines_around_a_credential():
    """Only the matched LINES go. A journal that dropped the rest of a body
    would answer "what did I already try" with a request that was never
    made."""
    got = journal._redacted("field=1\r\nCookie: session=SEKRIT\r\nother=3")
    assert "field=1" in got and "other=3" in got
    # And no stray CR left inside the value that replaced the line: MULTILINE's
    # `$` matches before the `\n` but not before the `\r`.
    assert "\r\r" not in got
    assert got.count("\r\n") == 2
