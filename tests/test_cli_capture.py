"""`hx capture start` brings Burp up (Task 7).

Before this task the command wrote a `run` row and printed one line -- it
never called `session.session`, so a consultant who ran it and browsed
recorded nothing (the extension defaults to DENY-ALL). This file pins the
rewired command: it opens a session, prints the operator's proxy port, opens
the run only once the session is live, and closes the run on the way out
however the session ended.

NO JVM IS STARTED HERE AND NO SOCKET IS OPENED. `cli.session_mod.session` is
replaced in every test below with `_fake_session`/`_raising_session`, the
same way `tests/test_session.py` replaces `launch_burp` rather than run a
real Burp -- the real thing is exercised under `pytest -m integration`.

THIS IS ALSO WHERE THE OLD `tests/test_cli.py` "Task 8" capture tests moved
to, and why: those tests called `capture start` through `CliRunner` with
nothing stubbed, which was safe back when the command wrote a row and
returned immediately. It no longer does -- unstubbed, it now calls the real
`session.session`, and this machine has exactly one jar under the default
`$HX_BURP_LAB` (`find_burp_jar` would happily find it), so those tests would
have started launching a real Burp on every default `pytest` run. Moved here
and adjusted:

- Tests that only exercise `capture stop` no longer route through `capture
  start` to set up their runs -- they open the running row directly through
  `run.open_run`, the same way `engagement_with_drops` in the old file
  already did. `capture stop` itself is untouched by this task.
- `test_capture_start_is_idempotent` could not survive unchanged: it invoked
  `start` twice in a row expecting the first run to still be open when the
  second call is made, which held when `start` returned immediately. Now
  `start` blocks for the life of the session and only closes the run on the
  way out, so two SEQUENTIAL `CliRunner` invocations never observe a run
  that is simultaneously live from both -- there would need to be two
  concurrent processes for that, which is what "typing start twice" actually
  describes. `run.current_run`'s own idempotency is already pinned directly
  in `tests/test_run.py`; what belongs here is only that the CLI is WIRED to
  `current_run` and not `open_run`, which
  `test_capture_start_resumes_rather_than_opens_a_second_run` checks by
  planting the running row out of band (as a previous `capture start`
  process would have left it) and asserting `start` does not add a second
  one.
"""
from __future__ import annotations

import contextlib
from pathlib import Path

import pytest
from click.testing import CliRunner

from hx import cli
from hx import config as config_mod
from hx import engagement as eng_mod
from hx import run as run_mod
from hx import session as session_mod


# --- fakes for `cli.session_mod.session` ----------------------------------
#
# THE BRIEF FOR THIS TASK CALLS `_fake_session(...)` AND `_raising_session(...)`
# IN ITS STEP-1 TEST CODE BUT DEFINES NEITHER -- not here, not in the tree.
# Written from what the call sites need: `_fake_session` stands in for
# `session.session` itself (a `@contextlib.contextmanager` factory taking
# `(eng, *, instance, jar=None, workdir=None)` and yielding something with at
# least `.operator_port`), and `_raising_session` stands in for a
# `session.session` whose body raises before the first `yield` -- the shape a
# real `SessionError` takes, surfacing from the `with` statement's `__enter__`
# rather than from the call that builds the context manager.


class _FakeLiveSession:
    """The handful of `session.LiveSession` fields `capture_start` reads."""

    def __init__(self, operator_port: int = 0):
        self.operator_port = operator_port
        self.crawler_port = 0
        self.epoch = 1
        self.bridge = None
        self.workdir = None


def _fake_session(operator_port: int = 0, calls: list | None = None):
    """A stand-in for `session.session` that launches nothing and yields a
    fake `LiveSession` with the given `operator_port`.

    `calls`, when given, gets one dict appended per invocation recording the
    keyword arguments `capture_start` actually passed through -- in
    particular `jar`, which nothing asserted on before this fix round:
    mutating `jar=burp_jar` to `jar=None` in the command reddened nothing."""

    @contextlib.contextmanager
    def factory(eng, *, instance, jar=None, workdir=None):
        if calls is not None:
            calls.append({"instance": instance, "jar": jar, "workdir": workdir})
        yield _FakeLiveSession(operator_port=operator_port)

    return factory


def _raising_session(exc: Exception):
    """A stand-in for `session.session` whose body never reaches a `yield` --
    the exception surfaces from `with session_mod.session(...) as live:`
    itself, matching how a real `SessionError` (raised inside `session()`
    before its first `yield`) actually reaches a caller."""

    @contextlib.contextmanager
    def factory(eng, *, instance, jar=None, workdir=None):
        raise exc
        yield  # pragma: no cover -- unreachable; keeps this a generator function

    return factory


# --- engagements -----------------------------------------------------------


@pytest.fixture
def engagement(tmp_path: Path) -> Path:
    """A real engagement, made the way an operator makes one. Returns the
    engagement directory itself, matching `tests/test_cli.py`'s fixture of
    the same name (moved-here tests keep referring to it by this name)."""
    result = CliRunner().invoke(cli.main, [
        "new", "acme-2026-09", "--client", "Acme Corp",
        "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    return tmp_path / "acme-2026-09"


@pytest.fixture
def an_engagement(tmp_path):
    """A real, on-disk engagement, returned as the `Engagement` object
    itself (`.root`, `.db`, `.id`, `.config`) -- what the brief's own Step-1
    tests read directly. Same shape as `tests/test_session.py`'s fixture of
    the same name, for the same reason: `OperatorHalt` and
    `stored_scope_sha256` both need a real `scope_version` row, which only
    `engagement.create()` writes."""
    cfg = config_mod.Config(
        name="acme-2026-09", client="Acme Corp",
        scope_include=["https://a.test/*"])
    eng = eng_mod.create(tmp_path / "acme", cfg, author="jimx")
    yield eng
    eng.db.close()


# --- Step 1: the brief's own tests, verbatim except for the two helpers
# above, which it calls but never defines. -----------------------------


def test_capture_start_reports_the_port_to_browse_through(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session",
                        _fake_session(operator_port=18080))
    monkeypatch.setattr(cli, "_block_until_interrupt", lambda: None)
    result = CliRunner().invoke(cli.main, ["capture", "start",
                                           "--root", str(an_engagement.root)])
    assert result.exit_code == 0, result.output
    assert "18080" in result.output, (
        "the operator cannot browse through a proxy whose port they were "
        "never told")


def test_ctrl_c_closes_the_run(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())
    def interrupt():
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "_block_until_interrupt", interrupt)
    CliRunner().invoke(cli.main, ["capture", "start",
                                  "--root", str(an_engagement.root)])
    row = an_engagement.db.execute(
        "SELECT status, stop_reason FROM run ORDER BY started_us DESC LIMIT 1").fetchone()
    # `status != 'running'` alone is satisfied by `aborted`, `killed` or
    # `error` too -- those mean the harness or S4's auto-halt ended the run,
    # not the operator. Verbatim the argument the moved F1 test already made
    # for `capture stop`; `capture_start`'s own close path had been left
    # with the weaker assertion. Mutating the close to
    # `status="error", stop_reason="harness fell over"` reddens only this.
    assert row["status"] == "completed", "Ctrl-C left the run open"
    assert row["stop_reason"] == "operator"


def test_a_session_error_exits_non_zero_and_says_why(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session",
                        _raising_session(session_mod.SessionError("no Burp jar found")))
    result = CliRunner().invoke(cli.main, ["capture", "start",
                                           "--root", str(an_engagement.root)])
    assert result.exit_code != 0
    assert "no Burp jar found" in result.output
    # The property this task exists for: the session opens BEFORE the run.
    # Moving `current_run` above the `with` in `capture_start` reddens
    # nothing else in the suite -- only this assertion and the byte-identity
    # check in test_plan_matches_repo (which reddens on any edit and proves
    # nothing about behaviour) catch it.
    assert an_engagement.db.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0, \
        "a run row was opened in front of a session that never started"


def test_burp_jar_flag_reaches_session(monkeypatch, an_engagement, tmp_path):
    """`--burp-jar` is documented as how an operator with two jars in
    `$HX_BURP_LAB` (or one they want to override) says which Burp this
    engagement runs against -- `find_burp_jar`'s docstring calls silently
    guessing between two "not a choice hx may make for you". Silently
    dropping the flag would give that operator the "two jars is an error"
    refusal from the very flag meant to resolve it, or -- with one jar --
    would assess against a Burp other than the one they named while the
    report records the wrong version. Mutating `jar=burp_jar` to `jar=None`
    in `capture_start` reddens only this test."""
    calls: list = []
    monkeypatch.setattr(cli.session_mod, "session", _fake_session(calls=calls))
    monkeypatch.setattr(cli, "_block_until_interrupt", lambda: None)
    jar = tmp_path / "burpsuite_desktop_v0.0.0.jar"
    jar.write_bytes(b"not a jar; session.session is faked in this test")
    result = CliRunner().invoke(cli.main, [
        "capture", "start", "--root", str(an_engagement.root),
        "--burp-jar", str(jar)])
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0]["jar"] == jar


# --- moved from tests/test_cli.py, adjusted not to touch a real Burp ------


def test_capture_start_opens_a_named_run(monkeypatch, engagement):
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())
    monkeypatch.setattr(cli, "_block_until_interrupt", lambda: None)
    result = CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "browse" in result.output


def test_capture_start_refuses_a_kind_the_schema_will_not_take(engagement):
    """The vocabulary lives in run.RUN_KINDS and in a CHECK. A bad --kind
    must be refused by the CLI with a readable message, not by SQLite with
    `CHECK constraint failed: run`. Click's `Choice` rejects it while
    parsing options, before the command body -- and therefore before
    `session.session` -- ever runs, so no session needs to be stubbed here."""
    result = CliRunner().invoke(cli.main,
        ["capture", "start", "--kind", "scheduled", "--root", str(engagement)])
    assert result.exit_code != 0
    assert "scheduled" in result.output


def test_capture_start_resumes_rather_than_opens_a_second_run(monkeypatch, engagement):
    """`start` calls `current_run`, not `open_run`: a run of this kind
    already live -- as a previous, still-running `capture start` process
    would have left it -- must be resumed, not duplicated. The running row is
    planted directly through `run.open_run` rather than through a second
    `capture start` invocation: `start` now blocks for the life of the
    session, so two sequential `CliRunner` calls can no longer both observe
    a run that is live at once -- that would take two concurrent processes,
    which is what "typing start twice" actually means. `current_run`'s own
    resume behaviour is pinned directly in tests/test_run.py; this test pins
    only that the CLI is wired to it."""
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())
    monkeypatch.setattr(cli, "_block_until_interrupt", lambda: None)
    eng = eng_mod.open_(engagement)
    try:
        existing_id = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="browse",
            safety_profile=eng.config.safety_profile)
    finally:
        eng.db.close()

    CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])

    eng = eng_mod.open_(engagement)
    try:
        rows = eng.db.execute(
            "SELECT id FROM run WHERE kind='browse'").fetchall()
    finally:
        eng.db.close()
    assert len(rows) == 1, (
        "a second browse row means start called open_run, not current_run")
    assert rows[0]["id"] == existing_id


def _open_running(path: Path, kind: str) -> None:
    """Plant a `status='running'` row the way a live `capture start` process
    would have left it -- without going through the CLI, which now blocks
    for the life of the session and would hang the test on a real
    `signal.pause()` with nothing stubbed."""
    eng = eng_mod.open_(path)
    try:
        run_mod.open_run(eng.db, engagement_id=eng.id, kind=kind,
                         safety_profile=eng.config.safety_profile)
    finally:
        eng.db.close()


def test_capture_stop_closes_it(engagement):
    _open_running(engagement, "browse")
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output


def test_capture_stop_closes_every_live_run(engagement):
    """Two kinds live at once is the normal case, not the exotic one: a crawl
    runs while a human browses. An operator typing `stop` means both."""
    for kind in ("browse", "crawl"):
        _open_running(engagement, kind)
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "2" in result.output
    # ...and assert against the STORE, not the wording: no run of this
    # engagement is left with status='running'.
    eng = eng_mod.open_(engagement)
    try:
        still_running = eng.db.execute(
            "SELECT COUNT(*) AS n FROM run WHERE status='running'").fetchone()["n"]
        assert still_running == 0
    finally:
        eng.db.close()


def test_capture_stop_with_no_run_says_so_rather_than_failing(engagement):
    """An operator typing stop twice has made no mistake worth an error."""
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "no" in result.output.lower()


def test_capture_stop_writes_completed_status_and_operator_reason(engagement):
    """F1 (carried over from the old file): the close is
    `status='completed'`, `stop_reason='operator'`. `status != 'running'`
    alone is satisfied by `aborted`, `killed` or `error` too, and those mean
    the harness or the auto-halt ended the run, not an operator. Assert
    against the STORE."""
    _open_running(engagement, "browse")
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    eng = eng_mod.open_(engagement)
    try:
        row = eng.db.execute(
            "SELECT status, stop_reason FROM run WHERE kind='browse'"
        ).fetchone()
        assert row["status"] == "completed"
        assert row["stop_reason"] == "operator"
    finally:
        eng.db.close()


def test_capture_stop_with_kind_only_closes_that_kind(engagement):
    """The mirror of test_capture_stop_closes_every_live_run. Two kinds live
    at once, `stop --kind crawl` must close only the crawl run and leave the
    browse run untouched."""
    for kind in ("browse", "crawl"):
        _open_running(engagement, kind)
    result = CliRunner().invoke(cli.main,
        ["capture", "stop", "--kind", "crawl", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    eng = eng_mod.open_(engagement)
    try:
        browse_status = eng.db.execute(
            "SELECT status FROM run WHERE kind='browse'").fetchone()["status"]
        crawl_status = eng.db.execute(
            "SELECT status FROM run WHERE kind='crawl'").fetchone()["status"]
        assert browse_status == "running"
        assert crawl_status == "completed"
    finally:
        eng.db.close()
