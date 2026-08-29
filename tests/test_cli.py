import contextlib
import dataclasses
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from hx import cli
from hx import engagement as eng_mod
from hx import halt as halt_mod
from hx import run as run_mod
from hx import scan as scan_mod
from hx import session as session_mod
from hx.checks import base as checks_base
from hx.checks import registry as registry_mod
from hx.store import records as records_mod


@pytest.fixture(autouse=True)
def no_unit_test_in_this_file_launches_a_jvm(monkeypatch):
    """NO TEST IN THIS FILE MAY REACH THE REAL `hx.session.session`.

    THE HAZARD THIS FILE ALREADY DOCUMENTS IN PROSE, NOW ENFORCED. The
    comment above `test_info_reports_drops_loudly_when_there_are_any` records
    why the `capture start` tests were moved out to `tests/test_cli_capture.py`
    -- unstubbed, they reached `session.session`, and this machine has exactly
    one jar under the default `$HX_BURP_LAB` (a 714 MB
    `burpsuite_desktop_v2026.7.3.jar`, which `find_burp_jar`'s glob matches
    exactly once), so a plain `pytest` run would have launched real Burps.
    A comment cannot stop that happening again, and it did not: Plan 6 Task 7
    gave `hx scan` a session too, and five `scan`/`report` tests here (the
    ones invoking `scan` and `report` through `CliRunner` with nothing
    stubbed) sat one registered active check away from launching five JVMs on
    every default run. Reviewer-measured, and nothing was red -- the trap
    arms itself the day `hx.active.cors` joins `registry.CHECKS`, not today.

    OPTING IN IS REPLACING IT. A test that legitimately drives the session
    path monkeypatches `cli.session_mod.session` with its own double in the
    test body, which runs after this fixture and therefore wins; `refuse`
    below is then never called and this fixture passes silently. There is no
    marker to remember, because the thing a safe test must do -- stub the
    session -- IS the opt-in.

    IT RAISES `SessionError` AND FAILS IN TEARDOWN, which is two mechanisms
    for one job and both are needed. `pytest.fail` inside the call would be
    swallowed: `CliRunner.invoke` catches every exception by default and
    files it under `result.exception`, so the guard would surface as a
    puzzling non-zero exit rather than as itself. Raising `SessionError`
    keeps the command's own error path intact (the CLI turns it into a
    `ClickException`, as it would for any session failure), and the
    post-yield `pytest.fail` then reports the real cause somewhere
    `CliRunner` cannot reach.
    """
    reached: list[str] = []

    def refuse(eng, *, instance, **kwargs):
        reached.append(instance)
        raise session_mod.SessionError(
            "tests/test_cli.py's no-JVM guard refused to launch Burp")

    monkeypatch.setattr(cli.session_mod, "session", refuse)
    yield
    if reached:
        pytest.fail(
            "this test reached the real hx.session.session (instance="
            f"{reached[0]!r}), which launches a real Burp: ~10 s and a 900 MB "
            "JVM inside the default `pytest` run. Stub "
            "`cli.session_mod.session` in the test, or move the test to "
            "tests/test_cli_capture.py, which stubs it throughout.")


def test_new_creates_engagement(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "acme-2026-09",
            "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*",
            "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme-2026-09" / "hx.db").exists()
    assert "acme-2026-09" in result.output


def test_new_requires_a_scope(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "Acme", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert "scope" in result.output.lower()


def test_new_refuses_to_clobber(tmp_path: Path):
    runner = CliRunner()
    args = [
        "new", "acme", "--client", "Acme",
        "--scope", "https://a/*", "--root", str(tmp_path),
    ]
    assert runner.invoke(cli.main, args).exit_code == 0
    second = runner.invoke(cli.main, args)
    assert second.exit_code != 0
    assert "exists" in second.output.lower()


def test_info_reports_engagement(tmp_path: Path):
    runner = CliRunner()
    runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code == 0, result.output
    assert "Acme Corp" in result.output
    assert "production" in result.output
    assert "https://app.acme.com/*" in result.output


def test_default_root_honours_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HX_HOME", str(tmp_path / "custom"))
    assert cli.default_root() == tmp_path / "custom"


def test_new_rejects_empty_name(tmp_path: Path):
    """Test that hx new rejects empty NAME and creates no directory."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "", "--client", "Acme", "--scope", "https://a/*", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    # Ensure no directory was created at all
    assert len(list(tmp_path.iterdir())) == 0


def test_new_rejects_empty_client(tmp_path: Path):
    """Test that hx new rejects empty --client and creates no directory."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "", "--scope", "https://a/*", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    # Ensure no directory was created at all
    assert len(list(tmp_path.iterdir())) == 0


@pytest.mark.parametrize("option", ["--scope", "--exclude"])
def test_new_rejects_a_blank_scope_entry(tmp_path: Path, option):
    """A blank pattern is refused at `hx new`, not at the next `load()`.

    config.load() has refused a blank entry since the guard landed, but `hx new`
    does not go through load(): it builds a Config from its options and dumps()
    it. So `hx new --exclude ''` wrote `exclude: ['']` into config.yaml and into
    the scope_version row, and the operator learned about it on the next open --
    which is the one thing the guard was added to prevent. The extension still
    fails closed on an empty pattern, so this was never a bypass; it was the
    guard firing one step too late to be the guard.
    """
    runner = CliRunner()
    args = ["new", "acme", "--client", "Acme", "--scope", "https://a/*",
            "--root", str(tmp_path)]
    if option == "--scope":
        args = ["new", "acme", "--client", "Acme", "--scope", "",
                "--root", str(tmp_path)]
    else:
        args += ["--exclude", ""]
    result = runner.invoke(cli.main, args)
    assert result.exit_code != 0, result.output
    assert "blank" in result.output.lower(), result.output
    # And nothing was created: the refusal comes before any directory is made.
    assert list(tmp_path.iterdir()) == []


def test_new_still_accepts_no_exclude_at_all(tmp_path: Path):
    """The control. The guard refuses a blank ENTRY, never an empty LIST --
    `exclude: []` has to stay writable, and an operator who passes no
    `--exclude` at all is writing exactly that."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "Acme", "--scope", "https://a/*",
         "--root", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    text = (tmp_path / "acme" / "config.yaml").read_text(encoding="utf-8")
    assert "exclude: []" in text


def test_info_missing_config_yaml(tmp_path: Path):
    """Test that info handles missing config.yaml gracefully."""
    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Delete config.yaml
    config_path = tmp_path / "acme" / "config.yaml"
    config_path.unlink()

    # Try to run info - should show an error, not a traceback
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert str(tmp_path / "acme") in result.output


def test_info_malformed_config_yaml(tmp_path: Path):
    """Test that info handles malformed config.yaml gracefully."""
    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Write malformed YAML
    config_path = tmp_path / "acme" / "config.yaml"
    config_path.write_text("{ invalid yaml: [")

    # Try to run info - should show an error, not a traceback
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert str(tmp_path / "acme") in result.output


def test_info_damaged_database(tmp_path: Path):
    """Test that info handles inaccessible database gracefully."""
    import os as os_module

    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Make the database inaccessible
    db_path = tmp_path / "acme" / "hx.db"
    os_module.chmod(db_path, 0o000)

    try:
        # Try to run info - should show an error, not a traceback
        result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
    finally:
        # Restore permissions so pytest can clean up
        os_module.chmod(db_path, 0o600)


# --- I3: `hx new` accepts a path, not a name ---


@pytest.mark.parametrize("bad_name", [".", "..", "../escaped", "a/b"])
def test_new_rejects_path_like_names_within_root(tmp_path: Path, bad_name):
    """`.` breaks the destruction guarantee outright (the engagements root
    itself becomes an engagement, so `rm -rf` of it destroys every sibling
    client), and any other traversal walks the created directory outside
    the engagements root. Nothing must be created at all."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", bad_name, "--client", "Acme", "--scope", "https://a/*", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert list(tmp_path.iterdir()) == [], f"NAME={bad_name!r} created something under root"


def test_new_rejects_an_absolute_path_as_name(tmp_path: Path):
    """pathlib's `/` operator discards the left operand when the right one
    is absolute, so NAME='/tmp/hx-i3-abs-escape-test' used to make --root
    silently ignored and create the engagement at that literal absolute
    path."""
    target = Path("/tmp/hx-i3-abs-escape-test")
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)

    runner = CliRunner()
    try:
        result = runner.invoke(
            cli.main,
            [
                "new", str(target), "--client", "Acme",
                "--scope", "https://a/*", "--root", str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert not target.exists(), "NAME as an absolute path escaped --root entirely"
        assert list(tmp_path.iterdir()) == []
    finally:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)


def test_new_accepts_a_normal_name(tmp_path: Path):
    """The validation must not be so strict it rejects ordinary names."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "acme-2026-09.retest_1", "--client", "Acme",
            "--scope", "https://a/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme-2026-09.retest_1" / "hx.db").exists()


# --- M3: `hx new` must degrade like `hx info` does, not traceback ---


def test_new_reports_a_clean_error_when_root_is_not_a_directory(tmp_path: Path):
    """`hx new acme --root /etc/hostname` used to dump a NotADirectoryError
    traceback -- `new` needs the same guard shape `info` already has."""
    not_a_dir = tmp_path / "im-a-file"
    not_a_dir.write_text("not a directory")

    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "x", "--client", "Acme",
            "--scope", "https://a/*", "--root", str(not_a_dir),
        ],
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output


# --- Task 8: `hx capture start/stop`, and `hx info` that admits its gaps ---


@pytest.fixture
def engagement(tmp_path: Path) -> Path:
    """A real engagement, made the way an operator makes one.

    Returns the ENGAGEMENT directory itself (`tmp_path / name`), not the
    engagements root `new --root` takes. `info` and `capture` both open a
    single engagement directly (`eng_mod.open_` checks for `hx.db` right at
    the path it is given), the same way `test_info_reports_engagement` above
    passes `tmp_path / "acme"` -- the child directory, never `tmp_path`
    itself -- to `info --root`.
    """
    result = CliRunner().invoke(cli.main, [
        "new", "acme-2026-09", "--client", "Acme Corp",
        "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    return tmp_path / "acme-2026-09"


@pytest.fixture
def engagement_with_drops(engagement: Path) -> Path:
    """A run recorded 4 dropped exchanges, through `hx.run`, not raw SQL."""
    eng = eng_mod.open_(engagement)
    try:
        run_id = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="browse",
            safety_profile=eng.config.safety_profile)
        run_mod.count_drop(eng.db, run_id=run_id, n=4)
    finally:
        eng.db.close()
    return engagement


@pytest.fixture
def engagement_with_stale_run(engagement: Path) -> Path:
    """A run whose heartbeat is old enough for `reap_stale` to find it.

    `reap_stale`'s own default window is `IDLE_CLOSE_US * 2`, not
    `IDLE_CLOSE_US` -- the two windows are deliberately different (idle vs.
    dead-harness), per `run.reap_stale`'s docstring. Backdating by a single
    `IDLE_CLOSE_US` would not clear reap_stale's own default threshold, so
    this backdates well past it.
    """
    eng = eng_mod.open_(engagement)
    try:
        run_id = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="browse",
            safety_profile=eng.config.safety_profile)
        stale_at = eng_mod.now_us() - (run_mod.IDLE_CLOSE_US * 3)
        run_mod.heartbeat(eng.db, run_id=run_id, now_us=stale_at)
    finally:
        eng.db.close()
    return engagement


# Task 7 rewired `hx capture start` so it actually launches Burp (through
# `session.session`), which means it now blocks for the life of the session
# and a plain unstubbed `CliRunner` invocation is no longer safe in the
# default suite -- this machine has exactly one jar under the default
# `$HX_BURP_LAB`, so `find_burp_jar` would find it and launch a real Burp.
# The `capture start`/`capture stop` tests that used to live here moved to
# tests/test_cli_capture.py, which stubs `session.session` throughout; the
# fixtures below (`engagement` and its variants) stay because the `info` and
# `scan`/`report` tests further down still use them.
#
# THAT MOVE IS NO LONGER THE ONLY THING HOLDING THE LINE. Task 7 of Plan 6
# gave `hx scan` a session as well, and this comment did not stop five tests
# below from re-arming the same trap. `no_unit_test_in_this_file_launches_a_jvm`
# at the top of the file is the autouse guard that now enforces the rule for
# every test here, whatever command it invokes.


def test_info_reports_drops_loudly_when_there_are_any(engagement_with_drops):
    """S5: a run with drops has coverage numbers that are a FLOOR, not a
    count. An operator who does not know that reads the surface count as
    complete."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement_with_drops)])
    assert "floor" in result.output.lower()
    # The COUNT, in its own context. A bare `"4" in output` passes on any
    # unrelated 4 -- four surfaces, a timestamp digit -- which is the shape of
    # a test that reads green for the wrong reason.
    assert "4 dropped" in result.output


def test_info_says_nothing_alarming_when_there_are_no_drops(engagement):
    """The separating case. A warning that is always present is not a
    warning."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert "floor" not in result.output.lower()


def test_info_reaps_stale_runs_before_reporting(engagement_with_stale_run):
    """Otherwise the first thing an operator sees after a crash is a run that
    claims to be running."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement_with_stale_run)])
    assert "error" in result.output.lower()


# `test_capture_start_is_idempotent`, F1
# (`test_capture_stop_writes_completed_status_and_operator_reason`) and F2
# (`test_capture_stop_with_kind_only_closes_that_kind`) moved to
# tests/test_cli_capture.py along with the rest of the `capture`
# start/stop family -- see the note above `test_info_reports_drops_loudly...`.


@pytest.fixture
def engagement_with_drops_on_two_runs(engagement: Path) -> Path:
    """Two DIFFERENT runs, each with its own nonzero drop count, so the
    printed total can be told apart from a single run's count, a MAX, or a
    last-value written -- none of which `engagement_with_drops` (one run)
    can separate from a correct SUM."""
    eng = eng_mod.open_(engagement)
    try:
        r1 = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="browse",
            safety_profile=eng.config.safety_profile)
        run_mod.count_drop(eng.db, run_id=r1, n=4)
        r2 = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="crawl",
            safety_profile=eng.config.safety_profile)
        run_mod.count_drop(eng.db, run_id=r2, n=7)
    finally:
        eng.db.close()
    return engagement


def test_info_floor_count_sums_drops_across_every_run(engagement_with_drops_on_two_runs):
    """F3: Q1 in the review asks exactly this -- is the printed total a SUM
    across runs, or could it be one run's count? `engagement_with_drops`
    only ever makes one run, so it cannot tell a sum (11) from a max (7) or
    a last-value (whichever ran last). This fixture makes two, 4 and 7, and
    the only correct total is their sum, 11."""
    result = CliRunner().invoke(
        cli.main, ["info", "--root", str(engagement_with_drops_on_two_runs)])
    assert result.exit_code == 0, result.output
    assert "floor" in result.output.lower()
    assert "11 dropped" in result.output


def test_info_breakdown_lines_report_their_own_table(engagement):
    """F4: each of the three breakdown lines must carry ITS OWN table's
    counts under its own heading. A row is planted in each of surface,
    exchange and denial with a value unique to that table (no vocabulary
    overlaps another table's), so a swapped table argument -- e.g. printing
    denial counts under 'surfaces' -- is caught by checking each heading's
    OWN line, not by a bare substring search of the whole page (which would
    pass even with the values filed under the wrong heading)."""
    eng = eng_mod.open_(engagement)
    try:
        eng.db.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host,"
            " port, path_template, kind, discovered_by, normaliser_version)"
            " VALUES('s1', ?, 'GET', 'https', 'app.acme.com', 443,"
            " '/api/widgets', 'state_changing', 'proxy', 1)",
            (eng.id,))
        records_mod.record_exchange(
            eng.db, run_id=None, method="GET", url="https://app.acme.com/x",
            status=None, req_blob=None, resp_blob=None, ms=0,
            at_us=eng_mod.now_us(), outcome="timeout")
        records_mod.record_denial(
            eng.db, run_id=None, kind="rate", method="GET",
            url="https://app.acme.com/y", detail="over budget",
            at_us=eng_mod.now_us())
    finally:
        eng.db.close()

    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    surfaces_line = next(ln for ln in lines if ln.strip().startswith("surfaces"))
    exchanges_line = next(ln for ln in lines if ln.strip().startswith("exchanges"))
    denials_line = next(ln for ln in lines if ln.strip().startswith("denials"))

    assert "state_changing=1" in surfaces_line
    assert "rate=1" not in surfaces_line
    assert "timeout=1" not in surfaces_line

    assert "timeout=1" in exchanges_line
    assert "state_changing=1" not in exchanges_line
    assert "rate=1" not in exchanges_line

    assert "rate=1" in denials_line
    assert "state_changing=1" not in denials_line
    assert "timeout=1" not in denials_line


# --- B5: `hx halt` / `hx resume`, S4's kill switch reachable by a human -----


def _halt_state(engagement: Path):
    """Read the halt back through a FRESH OperatorHalt, the way the harness
    and the next process do. Reading the CLI's own object would only prove it
    remembered its own call; the whole point of a durable halt is that another
    process sees it."""
    eng = eng_mod.open_(engagement)
    try:
        oh = halt_mod.OperatorHalt(eng.root, eng.db)
        return oh.halted, oh.reason, oh.sentinel_path
    finally:
        eng.db.close()


def test_halt_stops_issuance_and_writes_the_file_the_extension_polls(engagement):
    """S4's third kill path, reachable by a person for the first time.

    Two of the three §4 promises had no way in: `BridgeServer.halt()` and
    `resume()` are correct and durable and had no CLI and no production
    driver, and the suite-tab STOP button is unbuilt. Only "create the
    sentinel by hand" was something an operator could do -- and §4's whole
    argument is the redundancy, not any one path.

    THE FILE IS THE ASSERTION. `-Dhx.halt_sentinel` is what the extension
    polls, and `burp_fixture.launch_burp` passes `OperatorHalt.sentinel_path`
    for it -- so a CLI that stopped issuance by some other means would report
    success while the extension kept sending.
    """
    result = CliRunner().invoke(cli.main, [
        "halt", "--reason", "the client asked us to stop",
        "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    halted, reason, sentinel = _halt_state(engagement)
    assert halted is True
    assert reason == "the client asked us to stop"
    assert sentinel == engagement / "HALTED"
    assert sentinel.exists()
    assert "the client asked us to stop" in result.output
    assert str(sentinel) in result.output


def test_halt_writes_the_audit_row_as_well_as_the_file(engagement):
    """Durable is the row AND the file: the file is what stops the extension,
    the row is what explains the stop afterwards. A halt nobody can account
    for at the end of an engagement is the half `agent_action` exists for."""
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "target wobbling", "--root", str(engagement)])
    eng = eng_mod.open_(engagement)
    try:
        rows = eng.db.execute(
            "SELECT actor, tool, why FROM agent_action ORDER BY ts_us"
        ).fetchall()
    finally:
        eng.db.close()
    assert [(r["actor"], r["tool"]) for r in rows] == [("operator", "halt")]
    assert rows[0]["why"] == "target wobbling"


def test_halt_needs_no_reason_because_it_is_a_kill_switch(engagement):
    """`--reason` is OPTIONAL on purpose, and this pins the decision. The
    moment this command is used is the moment something is going wrong on a
    client's production system; a required argument is friction in front of a
    stop. What is NOT optional is that the recorded reason still says who
    stopped it and how, which is the part nobody can reconstruct later."""
    result = CliRunner().invoke(cli.main, ["halt", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    halted, reason, _ = _halt_state(engagement)
    assert halted is True
    assert "command line" in reason


def test_resume_is_the_only_thing_that_lifts_it(engagement):
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "stop", "--root", str(engagement)])
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    halted, reason, sentinel = _halt_state(engagement)
    assert halted is False
    assert reason is None
    assert not sentinel.exists()
    assert "stop" in result.output


def test_resume_clears_a_sentinel_nobody_recorded(engagement):
    """§4 names the by-hand path explicitly -- an operator can `touch` the
    sentinel from a shell when the socket is dead -- and such a halt has no
    row behind it. `OperatorHalt.halted` is a UNION for that reason, and this
    is the case that would strand an engagement halted forever if `resume`
    consulted the row instead."""
    (engagement / "HALTED").write_text("stopped by hand at 02:00\n")
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert not (engagement / "HALTED").exists()
    assert _halt_state(engagement)[0] is False


def test_resume_on_an_un_halted_engagement_writes_nothing(engagement):
    """An audit trail whose entries do not correspond to events is worse than
    a short one, and `resume()` would append a resume row for a stop that
    never happened. Refusing is safe here rather than pedantic: the direction
    that matters is that nothing accidentally re-arms issuance."""
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "nothing to resume" in result.output
    eng = eng_mod.open_(engagement)
    try:
        assert eng.db.execute(
            "SELECT COUNT(*) AS n FROM agent_action").fetchone()["n"] == 0
    finally:
        eng.db.close()


def test_halting_an_already_halted_engagement_says_so_and_still_halts(engagement):
    """Idempotent, and it SAYS what it found. An operator typing `halt` twice
    during an incident must not be told nothing happened, and must not be left
    wondering whether the second reason replaced the first."""
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "first reason", "--root", str(engagement)])
    result = CliRunner().invoke(cli.main, [
        "halt", "--reason", "second reason", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "already halted: first reason" in result.output
    halted, reason, _ = _halt_state(engagement)
    assert halted is True
    assert reason == "second reason"


def test_info_says_so_when_issuance_is_halted(engagement):
    """Where an operator looks first. §4 makes the sentinel something a
    DIFFERENT person can create from a shell with no harness running, so an
    operator can arrive at a halted engagement they did not halt -- and until
    this line nothing in the CLI would tell them."""
    before = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert "HALTED" not in before.output, (
        "the halt line must appear only when there IS one, or it stops "
        "meaning anything")
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "the client asked us to stop",
        "--root", str(engagement)])
    after = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert after.exit_code == 0, after.output
    assert "HALTED" in after.output
    assert "the client asked us to stop" in after.output
    assert "hx resume" in after.output


@pytest.mark.parametrize("command", [["halt"], ["resume"]])
def test_both_refuse_cleanly_when_there_is_no_engagement(tmp_path, command):
    """`hx capture`'s shape: a missing engagement is a ClickException with a
    sentence in it, never a traceback. A kill switch that answers with a
    stack trace is one an operator does not trust the next time."""
    result = CliRunner().invoke(cli.main, command + ["--root", str(tmp_path)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "no engagement" in result.output.lower()


def test_deleting_the_sentinel_by_hand_leaves_the_two_sides_disagreeing(engagement):
    """THE CLAIM I HAD WRONG, as a check rather than a sentence.

    `hx resume`'s docstring said it was "the only thing that lifts a halt".
    It is not. The extension polls the sentinel FILE and nothing else -- which
    is exactly what S4 asks of it, "an operator can create it from a shell when
    the socket is dead" -- and a mechanism that can be created by hand can be
    removed by hand.

    What that loses is asserted here: no `agent_action` row says the halt was
    lifted, and a process that reads the store still believes issuance is
    stopped while the extension has already started again. The two sides
    disagree, and the disagreement is silent. `hx resume` is what leaves them
    agreeing and leaves a row behind.
    """
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "stop", "--root", str(engagement)])
    (engagement / "HALTED").unlink()

    halted, reason, _ = _halt_state(engagement)
    assert halted is True, (
        "the store no longer believes this engagement is halted, so the "
        "disagreement this test documents does not exist and `hx resume`'s "
        "docstring should say so")
    assert reason == "stop"

    eng = eng_mod.open_(engagement)
    try:
        tools = [r["tool"] for r in eng.db.execute(
            "SELECT tool FROM agent_action ORDER BY ts_us")]
    finally:
        eng.db.close()
    assert tools == ["halt"], (
        "removing the file by hand wrote a resume row, which would make it "
        "equivalent to `hx resume` and this whole test pointless")

    # And `hx resume` still works from here -- it is the way back to two sides
    # agreeing, and it does not require the file it is about to remove.
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert _halt_state(engagement)[0] is False


# --- Task 7: `hx scan` ---


@pytest.fixture
def engagement_with_surface(engagement: Path) -> Path:
    """One `surface` row and one `exchange` against it, so a passive check --
    or, since Task 8, `hx.active.cors` on its `probes` hook -- has something
    to read. Built on `engagement` the way `engagement_with_drops` and
    `engagement_with_stale_run` are, per P2: this fixture did not exist
    before Task 7."""
    eng = eng_mod.open_(engagement)
    try:
        eng.db.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host,"
            " port, path_template, discovered_by, normaliser_version)"
            " VALUES('s1', ?, 'GET', 'https', 'app.acme.com', 443,"
            " '/api/widgets', 'proxy', 1)",
            (eng.id,))
        records_mod.record_exchange(
            eng.db, run_id=None, method="GET",
            url="https://app.acme.com/api/widgets", status=200,
            req_blob=None, resp_blob=None, ms=0, at_us=eng_mod.now_us(),
            outcome="ok", surface_id="s1")
    finally:
        eng.db.close()
    return engagement


def _disable_checks(engagement_path: Path, **overrides: bool) -> None:
    """Overlay `overrides` onto an engagement's `checks` config, on disk.

    Not a raw rewrite of `config.yaml`: `eng_mod.open_`'s I2 guard refuses a
    file that has drifted from the latest `scope_version` row, so
    `record_scope_version` -- the sanctioned writer, which updates both -- is
    what a test needing a non-default `checks` map has to go through instead.
    """
    eng = eng_mod.open_(engagement_path)
    try:
        eng.config = dataclasses.replace(
            eng.config, checks={**eng.config.checks, **overrides})
        eng_mod.record_scope_version(
            eng, author="test", reason="test override of checks config")
    finally:
        eng.db.close()


def _stub_session(monkeypatch, bridge=None) -> None:
    """Stand in for `hx.session.session` with something that never launches
    a JVM, for a test whose point has nothing to do with the session itself.

    `hx.active.cors` shipping (Task 8) means `active_safe` -- on by default
    -- now has a check in it, so `hx scan` opens a session for any engagement
    with a surface (see `cli.scan`'s `sending` gate). `bridge` defaults to a
    bare `object()`: `Cors.probes` calling `.send()` on it raises
    `AttributeError`, which `scan.run`'s per-check `except Exception` turns
    into an `error` check_run row rather than a crash -- fine for every test
    below that is not itself asserting something about CORS's own outcome.
    """
    def fake(eng, *, instance, jar=None, workdir=None, seed=None):
        return contextlib.nullcontext(
            SimpleNamespace(operator_port=1, crawler_port=2, epoch=1,
                            bridge=bridge if bridge is not None else object(),
                            workdir=None, proc=None))
    monkeypatch.setattr(cli.session_mod, "session", fake)


def test_scan_reports_what_it_ran(engagement_with_surface, monkeypatch):
    _stub_session(monkeypatch)
    result = CliRunner().invoke(cli.main,
                                ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    assert "surfaces" in result.output.lower()


_FLAGLESS_COOKIE_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Set-Cookie: session=abc; Path=/\r\n"
    b"\r\n"
)


def test_scan_prints_the_number_of_findings_the_store_holds(engagement,
                                                             monkeypatch):
    """D3 of the fix-round-A re-review. Forty surfaces of ONE host, all
    setting one flagless cookie: `cookie_flags` is `scope_level='host'`, so
    F3 of the whole-branch review makes the forty candidates land on ONE
    finding row, and the line an operator reads has to say so.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED against the
    per-candidate counter: `findings  40` printed while `SELECT COUNT(*)
    FROM finding` was 1 -- the exact forty tickets F3 exists to prevent,
    removed from the report and left at the terminal. Forty rather than two
    because a number that is wrong by one is a number someone argues about.
    """
    eng = eng_mod.open_(engagement)
    try:
        digest, length = eng.blobs.put(_FLAGLESS_COOKIE_RESPONSE)
        for n in range(40):
            eng.db.execute(
                "INSERT INTO surface(id, engagement_id, method, scheme, host,"
                " port, path_template, discovered_by, normaliser_version)"
                " VALUES(?, ?, 'GET', 'https', 'app.acme.com', 443, ?,"
                " 'proxy', 1)",
                (f"s{n}", eng.id, f"/p{n}"))
            records_mod.record_exchange(
                eng.db, run_id=None, method="GET",
                url=f"https://app.acme.com/p{n}", status=200,
                req_blob=None, resp_blob=digest, resp_len=length, ms=0,
                at_us=eng_mod.now_us(), outcome="ok", surface_id=f"s{n}")
    finally:
        eng.db.close()

    _stub_session(monkeypatch)
    result = CliRunner().invoke(cli.main, ["scan", "--root", str(engagement)])

    assert result.exit_code == 0, result.output
    assert "findings  1" in result.output, result.output
    eng = eng_mod.open_(engagement)
    try:
        held = eng.db.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    finally:
        eng.db.close()
    assert held == 1, (
        "the line the operator reads and the rows the report renders "
        "disagreed")


def test_scan_names_a_class_that_is_enabled_but_ships_no_checks(
        engagement_with_surface, monkeypatch):
    """config.DEFAULT_CHECKS turns `active_timing` ON by default and this
    build ships no checks in it (`active_safe` -- since Task 8 -- and
    `active_timing` are two different classes). An operator reading
    `active_timing: enabled` and seeing no rows would reasonably conclude it
    ran and found nothing. The scan says so out loud instead."""
    _stub_session(monkeypatch)
    result = CliRunner().invoke(cli.main,
                                ["scan", "--root", str(engagement_with_surface)])
    assert "active_timing" in result.output
    assert "no checks" in result.output.lower()


def test_scan_with_no_surfaces_says_so_rather_than_reporting_success(engagement):
    """Nothing captured yet is not the same as nothing found. An operator who
    forgot to browse must not read `0 findings` as a clean bill."""
    result = CliRunner().invoke(cli.main, ["scan", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "no surfaces" in result.output.lower()


def test_scan_refuses_a_root_that_is_not_an_engagement(tmp_path):
    result = CliRunner().invoke(cli.main, ["scan", "--root", str(tmp_path)])
    assert result.exit_code != 0
    assert result.output.strip()


def test_scan_max_seconds_reaches_the_runner(engagement_with_surface, monkeypatch):
    """Row C of the sweep: none of the tests above ever pass `--max-seconds`,
    so a CLI that silently dropped it in favour of `max_seconds=None` on the
    call to `scan.run` would leave every test above green. A deadline already
    in the past is the input that separates 'wired through' from 'ignored' --
    it only truncates the scan if the CLI's own option actually reaches
    `scan.run`. `time.monotonic` is patched the same way
    `test_budget_exhaustion_writes_skipped_rows_for_the_remaining_surfaces`
    in `tests/test_scan.py` does it: one call to compute the deadline, one
    call for the single surface `engagement_with_surface` seeds."""
    _stub_session(monkeypatch)
    ticks = iter([0.0, 1.0])
    monkeypatch.setattr(scan_mod.time, "monotonic", lambda: next(ticks))
    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface), "--max-seconds", "0",
    ])
    assert result.exit_code == 0, result.output
    assert "surfaces  0" in result.output
    assert "skipped" in result.output.lower()


# --- Task 6: --max-requests -------------------------------------------------


def test_scan_max_requests_flag_overrides_the_configured_budget(
        engagement_with_surface, monkeypatch):
    """`--max-requests` overrides `eng.config.max_requests` for this
    invocation only -- the number `scan.run` is actually called with, not
    what `config.yaml` says on disk. A CLI that silently dropped the flag
    (or wrote it back to the file) would leave this test red."""
    real_run = scan_mod.run
    seen: list = []

    def fake_run(conn, *, engagement_id, blobs, config, checks=None,
                surface_filter=None, max_seconds=None, bridge=None):
        # `bridge=None` is not decoration: `hx scan` passes it the moment an
        # active check ships, and a double whose signature lags the function
        # it doubles fails with `unexpected keyword argument` rather than
        # with anything about budgets.
        seen.append(config.max_requests)
        return real_run(conn, engagement_id=engagement_id, blobs=blobs,
                        config=config, checks=checks,
                        surface_filter=surface_filter, max_seconds=max_seconds,
                        bridge=bridge)

    monkeypatch.setattr(scan_mod, "run", fake_run)
    _stub_session(monkeypatch)
    before = eng_mod.open_(engagement_with_surface)
    try:
        before_max_requests = before.config.max_requests
    finally:
        before.db.close()

    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface),
        "--max-requests", "17"])

    assert result.exit_code == 0, result.output
    assert seen == [17]
    after = eng_mod.open_(engagement_with_surface)
    try:
        assert after.config.max_requests == before_max_requests, (
            "the flag rewrote config.yaml; it must override this run only")
    finally:
        after.db.close()


def test_scan_max_requests_below_one_is_a_bad_parameter_not_a_silent_clamp(
        engagement_with_surface):
    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface),
        "--max-requests", "0"])
    assert result.exit_code != 0
    assert "max-requests" in result.output.lower()


# --- Plan 6 Task 7: `hx scan` opens the session, and only when it must -----
#
# NO REAL BURP IN THIS FILE. `session_mod.session` is replaced throughout;
# the real launch is `tests/integration/`'s, which is the only place in this
# repository allowed to cost a JVM.


class _CliActive:
    """A registerable `active_safe` check. `insertion_kinds` is empty for the
    same reason `hx.checks.active.cors`'s is -- it shapes its own request --
    which also means it runs against `engagement_with_surface`'s exchange,
    whose `req_blob` is NULL and yields no points to derive."""
    id, version, klass = "hx.test.cliactive", "1", "active_safe"
    insertion_kinds = frozenset()

    def probes(self, ctx, surface, insertions, send):
        return checks_base.Verdict.clean(considered=("probed",))


def _register_active(monkeypatch):
    """Put one active check in the shipped corpus for the length of a test.

    `registry.CHECKS` rather than a stub of `registry.enabled`: `cli.scan`
    and `scan.run` both call `enabled`, and patching the tuple they both
    read keeps the two answers the same. `validate` is called on it first --
    if this shape were not one the registry accepts, the test would be
    proving the CLI drives something that can never ship."""
    check = _CliActive()
    registry_mod.validate((check,))
    monkeypatch.setattr(registry_mod, "CHECKS", registry_mod.CHECKS + (check,))
    return check


def _fake_session(opened, bridge):
    @contextlib.contextmanager
    def fake(eng, *, instance, jar=None, workdir=None, seed=None):
        opened.append(instance)
        yield SimpleNamespace(operator_port=1, crawler_port=2, epoch=1,
                              bridge=bridge, workdir=None, proc=None)
    return fake


def test_scan_opens_no_session_when_the_corpus_is_passive_only(
        engagement_with_surface, monkeypatch):
    """A passive scan stays offline. Burp costs ~10 s to start, so an engine
    nothing will send through must not be paid for.

    `active_safe` is ON by default and, since Task 8, ships a check
    (`hx.active.cors`) -- so this scenario is no longer the shipped build's
    ambient state and has to be built by hand: everything active turned off,
    leaving a corpus that is passive-only BY CONSTRUCTION rather than by
    accident of what this build happened to ship."""
    _disable_checks(engagement_with_surface, active_safe=False,
                    active_timing=False)

    def refuse(*a, **k):
        pytest.fail("a passive-only scan launched Burp")

    monkeypatch.setattr(cli.session_mod, "session", refuse)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output


def test_scan_opens_a_session_when_an_active_check_is_enabled(
        engagement_with_surface, monkeypatch):
    """And hands `scan.run` that session's bridge. Opening a Burp and then
    scanning without its bridge would be the worst of both: the startup cost
    paid, and every active row still `skipped` for want of a route."""
    _register_active(monkeypatch)
    opened, bridge = [], object()
    monkeypatch.setattr(cli.session_mod, "session",
                        _fake_session(opened, bridge))

    seen = {}
    real_run = scan_mod.run

    def spy(conn, **kwargs):
        seen["bridge"] = kwargs.get("bridge")
        return real_run(conn, **kwargs)

    monkeypatch.setattr(scan_mod, "run", spy)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code == 0, result.output
    assert opened == ["scan"], "the session was not opened once, as `scan`"
    assert seen["bridge"] is bridge


def test_scan_does_not_open_a_session_for_an_active_class_that_ships_nothing(
        engagement_with_surface, monkeypatch):
    """THE SEPARATING CASE for the test above. `active_timing` is enabled by
    default and this build ships no check in it, so a CLI that tested
    `config.checks` instead of `registry.enabled` would launch a Burp for
    every scan, send nothing through it, and print the `ships no checks`
    note underneath.

    `active_safe` turned off here so `hx.active.cors` -- a class this build
    DOES ship a check in, since Task 8 -- cannot itself be the reason a
    session opens and mask what this test is actually pinning."""
    _disable_checks(engagement_with_surface, active_safe=False)

    def refuse(*a, **k):
        pytest.fail("a class with no checks in it launched Burp")

    monkeypatch.setattr(cli.session_mod, "session", refuse)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    assert "ships no checks" in result.output


def test_scan_does_not_open_a_session_for_a_non_passive_class_that_reads(
        engagement_with_surface, monkeypatch):
    """FIX ROUND 1 (LOW): the gate used to be `c.klass != "passive"`, and
    this is the disagreement nothing pinned.

    `_HOOKS` decides PER CLASS which hooks are legal, and nothing says a
    non-passive class must get `probes`. Simulated here by giving
    `active_timing` the passive pairing -- a decision a later plan could
    genuinely make for a class that reads timing off captured exchanges
    rather than issuing its own -- and registering a check that implements
    `on_surface`. `registry.validate` accepts it, `scan.run` dispatches it to
    `on_surface` and sends nothing, and the old class-string gate would have
    started a 10-second JVM per scan to hand it no traffic.

    THE ASSERTION IS THE AUTOUSE GUARD. `no_unit_test_in_this_file_launches_a_jvm`
    fails this test in teardown if the gate opens a session, which is the
    same mechanism protecting every other test in the file rather than a
    second one invented here.

    `active_safe` turned off so `hx.active.cors` -- which DOES send, since
    Task 8 -- is not itself the reason a session opens here; this test is
    about `active_timing`'s hook, not about `active_safe`'s content."""
    _disable_checks(engagement_with_surface, active_safe=False)
    monkeypatch.setitem(registry_mod._HOOKS, "active_timing",
                        ("on_surface", "on_corpus"))

    class ReadsOnly:
        id, version, klass = "hx.test.reads", "1", "active_timing"
        insertion_kinds = frozenset()

        def on_surface(self, ctx, surface, exchanges):
            return checks_base.Verdict.clean(considered=("read",))

    check = ReadsOnly()
    registry_mod.validate((check,))
    monkeypatch.setattr(registry_mod, "CHECKS", registry_mod.CHECKS + (check,))

    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output


def test_scan_turns_a_session_error_into_a_click_exception(
        engagement_with_surface, monkeypatch):
    """The message intact, as `capture start` does. Every `SessionError`
    already names the fix -- a stale socket to remove by hand, an extension
    jar that is unbuilt -- and an operator who gets `Error: SessionError`
    instead has been handed the exception's type in place of its advice."""
    _register_active(monkeypatch)

    def die(*a, **k):
        raise session_mod.SessionError(
            "the bridge could not start on /x/hx.sock: address in use")

    monkeypatch.setattr(cli.session_mod, "session", die)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code != 0
    assert "the bridge could not start on /x/hx.sock" in result.output


def test_scan_max_requests_still_reaches_an_active_session(
        engagement_with_surface, monkeypatch):
    """`--max-requests` predates the session and must survive it. The number
    goes into `eng.config` before the session is opened, so it is the budget
    `session.config_body` authorises the extension with -- not just the one
    `scan.run` is handed."""
    _register_active(monkeypatch)
    seen = {}

    @contextlib.contextmanager
    def fake(eng, *, instance, jar=None, workdir=None, seed=None):
        seen["max_requests"] = eng.config.max_requests
        yield SimpleNamespace(operator_port=1, crawler_port=2, epoch=1,
                              bridge=object(), workdir=None, proc=None)

    monkeypatch.setattr(cli.session_mod, "session", fake)
    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface),
        "--max-requests", "23"])
    assert result.exit_code == 0, result.output
    assert seen["max_requests"] == 23


# --- Task 8 fix round 1, F12/F2: `hx report` had no test at all, and F2 is ---
# --- what that gap already cost -----------------------------------------

def test_report_writes_a_file_and_says_where(engagement_with_surface):
    result = CliRunner().invoke(cli.main,
                                ["report", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    target = engagement_with_surface / "exports" / "acme-2026-09.md"
    assert target.exists()
    assert str(target) in result.output


def test_report_default_export_is_never_looser_than_0o600(engagement_with_surface):
    """§3, unconditional. F2: `write_text` then `chmod` used to leave the
    file at `0o644` for the window between them; there is no window left to
    measure from the outside once the file exists, so this pins the mode
    the file ends at -- the live end-to-end half of F2's fix, the write-time
    window itself is what `_write_export_secure`'s O_EXCL-at-final-mode
    shape (`cli.py`) exists to close."""
    CliRunner().invoke(cli.main,
                       ["report", "--root", str(engagement_with_surface)])
    target = engagement_with_surface / "exports" / "acme-2026-09.md"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_report_out_creates_new_directories_at_0o700_not_the_umask(engagement_with_surface, tmp_path):
    """F2's exact measured repro: `--out <somewhere>/nested/report.md`, where
    neither `nested` directory exists yet. The old
    `target.parent.mkdir(parents=True, exist_ok=True)` created both at the
    ambient umask (`755` under `022`, measured in the review) -- including
    when the path was inside the engagement root, which §3 governs
    unconditionally. `secure_mkdir` must leave every directory it creates at
    `0o700`, never looser, with no window.

    R3 (fix round 2): the umask is set explicitly here, LOOSE (`022`), and
    restored after. Without this the test's separating power depended on
    whatever umask the developer's or CI's shell happened to have: under a
    restrictive ambient umask (`077`), the OLD buggy `mkdir(parents=True)`
    creates directories at `0o777 & ~0o077 == 0o700` too -- the same result
    the fix produces -- so the mutation this test exists to catch would pass
    vacuously there. A guard whose discriminating power depends on the
    environment it happens to run in is one that will quietly stop testing.
    """
    old_umask = os.umask(0o022)
    try:
        target = tmp_path / "handoff" / "client" / "acme.md"
        result = CliRunner().invoke(cli.main, [
            "report", "--root", str(engagement_with_surface), "--out", str(target),
        ])
    finally:
        os.umask(old_umask)
    assert result.exit_code == 0, result.output
    assert target.exists()
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "handoff").stat().st_mode & 0o777) == "0o700"
    assert oct((tmp_path / "handoff" / "client").stat().st_mode & 0o777) == "0o700"


def test_report_redacts_a_credential_reaching_the_export(engagement_with_surface):
    """F1/F12: the export-side redaction the review found missing, exercised
    through the real CLI command rather than `report.render` directly --
    F2's own defect was found exactly this way, by driving the command
    end-to-end rather than trusting the unit-level render tests alone. The
    finding is hand-inserted rather than written through `records.py`'s own
    writers, the same way `records.record_exchange`/`record_denial` already
    redact at write time and would mask the gap this checks for."""
    eng = eng_mod.open_(engagement_with_surface)
    try:
        eng.db.execute(
            "INSERT INTO finding(id, engagement_id, dedupe_key, title,"
            " severity, confidence, created_by, status, scope_level)"
            " VALUES('f-1', ?, 'k1',"
            " 'Token leak: https://admin:hunter2@app.acme.com/x?access_token=SECRETTOKEN',"
            " 'Medium', 'Firm', 'check', 'new', 'surface')",
            (eng.id,))
    finally:
        eng.db.close()
    result = CliRunner().invoke(cli.main,
                                ["report", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    target = engagement_with_surface / "exports" / "acme-2026-09.md"
    text = target.read_text(encoding="utf-8")
    assert "SECRETTOKEN" not in text
    assert "hunter2" not in text
    assert "Token leak" in text
