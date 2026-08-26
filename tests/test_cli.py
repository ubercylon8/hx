import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from hx import cli
from hx import engagement as eng_mod
from hx import run as run_mod
from hx.store import records as records_mod


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


def test_capture_start_opens_a_named_run(engagement):
    result = CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "browse" in result.output


def test_capture_start_refuses_a_kind_the_schema_will_not_take(engagement):
    """The vocabulary lives in run.RUN_KINDS and in a CHECK. A bad --kind must
    be refused by the CLI with a readable message, not by SQLite with
    `CHECK constraint failed: run`."""
    result = CliRunner().invoke(cli.main,
        ["capture", "start", "--kind", "scheduled", "--root", str(engagement)])
    assert result.exit_code != 0
    assert "scheduled" in result.output


def test_capture_stop_closes_it(engagement):
    CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output


def test_capture_stop_closes_every_live_run(engagement):
    """Two kinds live at once is the normal case, not the exotic one: a crawl
    runs while a human browses. An operator typing `stop` means both."""
    for kind in ("browse", "crawl"):
        CliRunner().invoke(cli.main,
            ["capture", "start", "--kind", kind, "--root", str(engagement)])
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


def test_capture_start_is_idempotent(engagement):
    """`start` calls `current_run`, not `open_run`: typing `start` twice must
    resume the one live run of that kind, not open a second one. Row E of the
    Task 8 sabotage table -- if `start` called `open_run` instead, nothing
    else here would catch it."""
    CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
    CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
    eng = eng_mod.open_(engagement)
    try:
        running = eng.db.execute(
            "SELECT COUNT(*) AS n FROM run WHERE status='running' AND kind='browse'"
        ).fetchone()["n"]
        assert running == 1
    finally:
        eng.db.close()


# --- Fix round 1: four requirements the brief named, correctly implemented,
# pinned by no test until now. ---


def test_capture_stop_writes_completed_status_and_operator_reason(engagement):
    """F1: the brief is explicit -- 'the close is status=\'completed\',
    stop_reason=\'operator\''. `status != 'running'` (the existing
    assertion in test_capture_stop_closes_every_live_run) is satisfied by
    `aborted`, `killed` or `error` too, and those mean the harness or the
    auto-halt ended the run, not an operator. Assert against the STORE."""
    CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
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
    """F2: the mirror of test_capture_stop_closes_every_live_run. Two kinds
    live at once, `stop --kind crawl` must close only the crawl run and
    leave the browse run untouched -- `hx capture stop --kind crawl`
    closing a browse run must be visible to something."""
    for kind in ("browse", "crawl"):
        CliRunner().invoke(cli.main,
            ["capture", "start", "--kind", kind, "--root", str(engagement)])
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
