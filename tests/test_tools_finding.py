"""An agent finding must cite traffic. `Candidate` already required that of
checks; it is a better rule for an agent."""
from __future__ import annotations

import pytest

from hx.tools import dispatch
from hx.tools.impl import finding as finding_tools  # noqa: F401  (registers)
from hx.tools.impl import run as run_tools  # noqa: F401  (registers)


@pytest.fixture
def ready(tool_ctx):
    """A run, a surface and an exchange -- the least a finding can hang off."""
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="setup")
    tool_ctx.conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by,"
        " normaliser_version) VALUES('s-1',?,'GET','https','app.test',443,"
        "'/login','','idempotent_read','proxy',2)", (tool_ctx.engagement.id,))
    tool_ctx.conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url, status) VALUES('x-1',?, 's-1','proxy','ok',1,'GET',"
        "'https://app.test/login',200)", (tool_ctx.run_id,))
    return tool_ctx


BASE = {"title": "Login form over plaintext", "issue_type_id": "cleartext-login",
        "severity": "Medium", "confidence": "Firm", "surface_id": "s-1",
        "exchange_ids": ["x-1"]}


def test_a_recorded_finding_is_created_by_the_agent_and_starts_new(ready):
    env = dispatch.dispatch(ready, "finding.record", BASE, why="saw it")
    assert env.outcome == "ok"
    row = ready.conn.execute(
        "SELECT created_by, status, check_id, severity FROM finding WHERE id=?",
        (env.result["id"],)).fetchone()
    assert row == ("agent", "new", None, "Medium")


def test_the_agent_does_not_get_to_spell_its_own_dedupe_key(ready):
    env = dispatch.dispatch(ready, "finding.record", BASE, why="w")
    key = ready.conn.execute("SELECT dedupe_key FROM finding WHERE id=?",
                             (env.result["id"],)).fetchone()[0]
    # Nine parts, and the first says an agent found it -- so an agent finding
    # can never collide with a check's finding of the same issue type on the
    # same surface, and a re-record of the same thing collapses onto one row.
    assert key.split("|")[0] == "agent"
    assert len(key.split("|")) == 9
    again = dispatch.dispatch(ready, "finding.record", BASE, why="w")
    assert again.result["id"] == env.result["id"]


def test_a_finding_with_no_exchanges_is_refused(ready):
    # `exchange_ids` now carries `minItems: 1` in the schema (final
    # whole-branch review's item 2), so this is caught at validation, before
    # the handler's own "a finding must cite the exchanges" check ever runs
    # -- `dispatch` validates before it calls. The handler's own check stays
    # in place as defence in depth for a caller that reaches `record()`
    # directly, bypassing the schema (as `tests/test_records_findings.py`
    # and this module's own fixtures do elsewhere).
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, exchange_ids=[]), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "exchange_ids" in env.detail and "fewer than 1" in env.detail


def test_exchange_ids_past_the_ceiling_is_refused_not_too_many_sql_variables(ready):
    # MEASURED, before this fix: 60,000 exchange ids reached `record`'s own
    # `IN (...)` lookup and raised `OperationalError: too many SQL
    # variables` -- `error / internal`, telling the agent hx was broken when
    # its argument was simply too large. `exchange_ids` now carries
    # `maxItems` (final whole-branch review's item 2), so an over-long list
    # is `bad_args` at validation and the handler never builds the query.
    from hx.tools.impl import finding as finding_mod
    too_many = [f"x-{i}" for i in range(finding_mod.MAX_EXCHANGE_IDS + 1)]
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, exchange_ids=too_many), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "exchange_ids" in env.detail and "more than" in env.detail


def test_finding_query_cursor_rejects_an_overflowing_offset(ready):
    env = dispatch.dispatch(ready, "finding.query", {"cursor": "o-" + "9" * 20})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_finding_query_cursor_rejects_a_unicode_digit(ready):
    env = dispatch.dispatch(ready, "finding.query", {"cursor": "o-²"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_recording_without_a_run_is_unavailable(tool_ctx):
    tool_ctx.conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by,"
        " normaliser_version) VALUES('s-1',?,'GET','https','app.test',443,"
        "'/login','','idempotent_read','proxy',2)", (tool_ctx.engagement.id,))
    env = dispatch.dispatch(tool_ctx, "finding.record", BASE, why="w")
    assert (env.outcome, env.reason) == ("unavailable", "no_run")


def test_an_unknown_surface_is_refused_rather_than_written(ready):
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, surface_id="s-nope"), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_the_agent_cannot_write_a_status_at_all(ready):
    # Not "cannot write confirmed" -- cannot write ANY status. Status is a
    # human act (section 8) and `finding.set_status` has no registry entry.
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, status="confirmed"), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_finding_query_filters_and_pages(ready):
    dispatch.dispatch(ready, "finding.record", BASE, why="w")
    dispatch.dispatch(ready, "finding.record",
                      dict(BASE, issue_type_id="other", severity="Low",
                           title="Something else"), why="w")
    env = dispatch.dispatch(ready, "finding.query", {"severity": "Medium"})
    assert env.result["total"] == 1
    assert env.result["rows"][0]["issue_type_id"] == "cleartext-login"


def test_evidence_attaches_with_a_role_and_a_note(ready):
    fid = dispatch.dispatch(ready, "finding.record", BASE, why="w").result["id"]
    env = dispatch.dispatch(ready, "evidence.attach",
                            {"finding_id": fid, "exchange_id": "x-1",
                             "role": "baseline", "note": "control request"},
                            why="showing the difference")
    assert env.outcome == "ok"
    rows = ready.conn.execute(
        "SELECT role, note FROM evidence WHERE finding_id=? ORDER BY seq",
        (fid,)).fetchall()
    assert ("baseline", "control request") in rows


def test_an_evidence_role_outside_the_set_is_refused(ready):
    fid = dispatch.dispatch(ready, "finding.record", BASE, why="w").result["id"]
    env = dispatch.dispatch(ready, "evidence.attach",
                            {"finding_id": fid, "exchange_id": "x-1",
                             "role": "smoking-gun"}, why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


# ---- The scoped re-review's finding in Finding 1's own fix: `ctx.run_id`
# used to re-query the store on EVERY read, and `record()` above reads it
# three times (the guard, and once in each of two writes). `ready` binds its
# context via `run.start` on the SAME `tool_ctx` it hands back, which makes
# `ctx.run_id` a fixed, already-bound answer for the rest of that context's
# life -- exactly the case the memoisation fix does not need to touch. Both
# tests below build fresh, UNBOUND contexts instead, the shape that actually
# resolves `run_id` from the store and the only shape the bug could reach. --


def _fresh_ctx(engagement):
    """A brand-new `ToolContext` -- nothing bound -- the way
    `adapters.cli.build_context` makes one for every `hx tool` invocation."""
    from hx import halt as halt_mod
    from hx.tools import dispatch as dispatch_mod
    return dispatch_mod.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db))


def test_a_run_opening_between_the_guard_and_the_writes_cannot_corrupt_the_write(
        engagement, monkeypatch):
    """MEASURED, before this fix: one `manual` run open, the guard passes on
    an unbound context; a `browse` run opens (a different, now-discarded
    context, the way an operator's `hx scan` or a second agent's `run.start`
    would) between the guard and the writes; the now-ambiguous `ctx.run_id`
    turns `None` for the second and third reads, `finding_observation.
    run_id` (`NOT NULL`) raises `IntegrityError`, and the transaction rolls
    back -- `error/internal`, the agent's finding and evidence lost, for
    ordinary concurrent use.

    `ctx.open_runs()` is memoised per `dispatch()` call, so this must now
    complete exactly as if the concurrent `run.start` never happened: every
    read inside this one `finding.record` invocation agrees with the guard.
    """
    conn = engagement.db
    started = dispatch.dispatch(_fresh_ctx(engagement), "run.start",
                                {"kind": "manual"}, why="setup")
    assert started.outcome == "ok"
    run_id = started.result["id"]
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by,"
        " normaliser_version) VALUES('s-1',?,'GET','https','app.test',443,"
        "'/login','','idempotent_read','proxy',2)", (engagement.id,))
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url, status) VALUES('x-1',?, 's-1','proxy','ok',1,'GET',"
        "'https://app.test/login',200)", (run_id,))

    opened = {}

    def hook():
        # Fires once `record()` has already passed its `ctx.run_id is None`
        # guard and finished everything but the write -- the exact gap the
        # review's repro used. Opened via a THIRD, separate context: the
        # concurrent actor is not this call's own context either.
        if not opened:
            opened["id"] = dispatch.dispatch(
                _fresh_ctx(engagement), "run.start", {"kind": "browse"},
                why="concurrent").result["id"]
        return real_now_us()

    real_now_us = finding_tools.now_us
    monkeypatch.setattr(finding_tools, "now_us", hook)

    env = dispatch.dispatch(_fresh_ctx(engagement), "finding.record", BASE,
                            why="saw it")

    assert opened, "the hook never fired -- this test proves nothing"
    assert env.outcome != "error", f"a defect leaked to the agent: {env.detail}"
    assert env.outcome == "ok"
    fid = env.result["id"]
    # Attributed to the run the guard actually saw, never the one opened
    # underneath it, and no partial chain: the finding, its observation and
    # its evidence all landed together.
    assert conn.execute("SELECT run_id FROM finding_observation WHERE"
                        " finding_id=?", (fid,)).fetchone()[0] == run_id
    assert conn.execute("SELECT COUNT(*) FROM finding WHERE id=?",
                        (fid,)).fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM evidence WHERE finding_id=?",
                        (fid,)).fetchone()[0] == 1


def test_recording_with_two_kinds_open_names_them_rather_than_saying_no_run(
        engagement):
    """§12's distinction, given to `finding.record` the way `run.finish`
    already has it: "nothing is open" and "I cannot tell which of two" are
    different facts, and only one of them means `run.start` is the fix."""
    dispatch.dispatch(_fresh_ctx(engagement), "run.start", {"kind": "manual"},
                      why="w")
    dispatch.dispatch(_fresh_ctx(engagement), "run.start", {"kind": "browse"},
                      why="w")

    env = dispatch.dispatch(_fresh_ctx(engagement), "finding.record", BASE,
                            why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "browse" in env.detail and "manual" in env.detail
