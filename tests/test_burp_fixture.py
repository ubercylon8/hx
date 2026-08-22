"""The integration fixture's prerequisite checks, checked themselves.

These live in the FAST suite deliberately. Every guard in `missing()` has two
failure directions and only one of them is visible: a guard that fails to fire
lets a run proceed on a broken prerequisite, but a guard that fires when it
should not silently skips the entire integration suite -- and a skipped suite
reads on a terminal almost exactly like a passing one. So each guard is checked
in both directions here, against a fake lab, with no JVM anywhere near it.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.integration import burp_fixture as bf

REPO = Path(__file__).resolve().parents[1]

ACCEPTED = b'<?xml version="1.0"?><map><entry key="burp.eula" value="true"/></map>'
# Invalid UTF-8: 0xff can never start a UTF-8 sequence. This is the shape of a
# 1.75 MB prefs.xml caught mid-rewrite by a Burp shutting down.
TORN = b'<?xml version="1.0"?><map><entry key="burp.proxy" value="\xff\xfe'


def _build_lab(root: Path) -> Path:
    """A lab directory in which every prerequisite is satisfied."""
    (root / "burphome" / ".java" / ".userPrefs" / "burp").mkdir(parents=True)
    (root / "burphome" / ".java" / ".userPrefs" / "burp" / "prefs.xml").write_bytes(ACCEPTED)
    (root / "burphome" / ".BurpSuite").mkdir()
    (root / "burpsuite_desktop.jar").write_bytes(b"not really a jar")
    return root


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Point the fixture module at a satisfied fake lab and hand back its paths."""
    root = _build_lab(tmp_path / "lab")
    src = tmp_path / "ext" / "src" / "hx"
    src.mkdir(parents=True)
    (src / "HxExtension.java").write_text("class HxExtension {}\n")
    jar = tmp_path / "ext" / "build" / "hx-bridge.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"not really a jar")
    os.utime(src / "HxExtension.java", (1_000_000, 1_000_000))
    os.utime(jar, (2_000_000, 2_000_000))          # built after its source

    monkeypatch.setattr(bf, "LAB", root)
    monkeypatch.setattr(bf, "BURP_JAR", root / "burpsuite_desktop.jar")
    monkeypatch.setattr(bf, "SEED_HOME", root / "burphome")
    monkeypatch.setattr(bf, "EXT_JAR", jar)
    monkeypatch.setattr(bf, "EXT_SRC", tmp_path / "ext" / "src")
    return tmp_path


def _prefs(lab_root: Path) -> Path:
    return lab_root / "lab" / "burphome" / ".java" / ".userPrefs" / "burp" / "prefs.xml"


def test_a_satisfied_lab_reports_nothing_missing(lab):
    """The direction that hides: a guard that over-reports skips the whole
    integration suite, and a skipped suite looks like a passing one."""
    assert bf.missing() == []
    assert bf.burp_available() is True


# ---- the EULA check ---------------------------------------------------

def test_a_torn_prefs_file_reports_the_eula_row_rather_than_raising(lab):
    """read_text() raised UnicodeDecodeError here -- not an OSError, so it
    escaped missing() at import time and reduced every pytest run in the repo
    to `Interrupted: 1 error during collection`, zero tests, fast suite
    included. Reproduced before the fix."""
    _prefs(lab).write_bytes(TORN)
    assert bf.missing() == [f"burp.eula not accepted in {bf.SEED_HOME / '.java'}"]


def test_a_torn_prefs_file_that_still_holds_the_key_stays_quiet(lab):
    """The byte search must find an accepted EULA in a file that cannot be
    decoded, or the fix trades a crash for a permanently skipped suite."""
    _prefs(lab).write_bytes(TORN + b'"/><entry key="burp.eula" value="true"/></map>')
    assert bf.missing() == []


def test_an_unreadable_prefs_file_is_still_an_unaccepted_eula(lab):
    _prefs(lab).unlink()
    assert bf.missing() == [f"burp.eula not accepted in {bf.SEED_HOME / '.java'}"]


def test_importing_the_integration_module_survives_a_torn_prefs_file(lab):
    """The blocker at the level it actually bit: importing the test module
    evaluates skipif's `bf.missing()` at collection time, so an exception
    there is a collection error, not a skip. A subprocess because this is
    about import-time state -- LAB is resolved from the environment once.
    """
    _prefs(lab).write_bytes(TORN)
    env = {**os.environ,
           "HX_BURP_LAB": str(lab / "lab"),
           "PYTHONPATH": f"{REPO}{os.pathsep}{REPO / 'src'}"}
    done = subprocess.run(
        [sys.executable, "-c",
         "import tests.integration.test_real_burp\n"
         "from tests.integration import burp_fixture as bf\n"
         "print(bf.missing())"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert "burp.eula" in done.stdout, done.stdout


# ---- the stale-jar check ----------------------------------------------

def test_a_source_newer_than_the_jar_reports_a_stale_jar(lab):
    """Without this row a task edits BridgeClient.java, forgets build.sh, and
    `-m integration` reports 2 passed against the previous jar."""
    os.utime(lab / "ext" / "src" / "hx" / "HxExtension.java", (3_000_000, 3_000_000))
    assert bf.missing() == [
        "extension jar is older than its sources (run extension/build.sh)"]


def test_a_source_in_a_subpackage_counts(lab):
    """The sources are nested (hx/bridge/*.java); a non-recursive glob would
    see none of the ones most likely to change."""
    nested = lab / "ext" / "src" / "hx" / "bridge"
    nested.mkdir()
    (nested / "BridgeClient.java").write_text("class BridgeClient {}\n")
    os.utime(nested / "BridgeClient.java", (3_000_000, 3_000_000))
    assert bf.missing() == [
        "extension jar is older than its sources (run extension/build.sh)"]


def test_a_jar_newer_than_every_source_stays_quiet(lab):
    """A freshly built jar must not skip the suite it exists to enable."""
    os.utime(bf.EXT_JAR, (4_000_000, 4_000_000))
    assert bf.missing() == []


def test_a_source_that_cannot_be_stat_ed_does_not_raise(lab):
    """A dangling symlink under extension/src -- a checkout or a rebuild
    running alongside the suite -- must not become a collection error. This
    is the blocker of round 1 in a second costume."""
    (lab / "ext" / "src" / "hx" / "Vanished.java").symlink_to(lab / "gone.java")
    assert bf.missing() == []


def test_an_absent_jar_reports_only_that(lab):
    """Absence is one problem, not two: staleness has nothing to compare."""
    bf.EXT_JAR.unlink()
    assert bf.missing() == [
        f"extension jar (run extension/build.sh): {bf.EXT_JAR}"]


# ---- the seed-home checks ---------------------------------------------

def test_a_seed_home_without_BurpSuite_is_named(lab):
    """make_home() iterates this tree. Checking only .java let
    burp_available() return True and the launch die on FileNotFoundError
    mid-copy -- the unnamed failure missing() exists to prevent."""
    (bf.SEED_HOME / ".BurpSuite").rmdir()
    assert bf.missing() == [f"seed burp home: {bf.SEED_HOME / '.BurpSuite'}"]


def test_a_seed_home_without_java_is_named_without_an_eula_row(lab):
    """No .java means no prefs to read; one row, naming the real problem."""
    _prefs(lab).unlink()
    for d in sorted((bf.SEED_HOME / ".java").rglob("*"), reverse=True):
        d.rmdir()
    (bf.SEED_HOME / ".java").rmdir()
    assert bf.missing() == [f"seed burp home: {bf.SEED_HOME / '.java'}"]


def test_every_row_can_be_reported_at_once(lab):
    """The rows are independent: one absent prerequisite must not mask another."""
    bf.BURP_JAR.unlink()
    bf.EXT_JAR.unlink()
    (bf.SEED_HOME / ".BurpSuite").rmdir()
    _prefs(lab).write_bytes(TORN)
    assert bf.missing() == [
        f"burp jar: {bf.BURP_JAR}",
        f"extension jar (run extension/build.sh): {bf.EXT_JAR}",
        f"burp.eula not accepted in {bf.SEED_HOME / '.java'}",
        f"seed burp home: {bf.SEED_HOME / '.BurpSuite'}",
    ]
