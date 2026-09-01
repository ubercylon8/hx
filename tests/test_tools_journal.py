"""Principle 5's record. It is also the loop-prevention hole: an agent that
cannot see what it already tried repeats it."""
from __future__ import annotations

import json

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
