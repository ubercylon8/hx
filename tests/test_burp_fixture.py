"""The integration fixture's prerequisite checks, checked themselves.

These live in the FAST suite deliberately. Every guard in `missing()` has two
failure directions and only one of them is visible: a guard that fails to fire
lets a run proceed on a broken prerequisite, but a guard that fires when it
should not silently skips the entire integration suite -- and a skipped suite
reads on a terminal almost exactly like a passing one. So each guard is checked
in both directions here, against a fake lab, with no JVM anywhere near it.

The same argument covers the two guards at the bottom of this file, which are
not about prerequisites at all. `not_loopback_only()` is the check that
`listen_mode: loopback_only` is real rather than a comment, and its parser is
where it would silently rot -- an address form it does not recognise must read
as "not loopback", never as safe. `probe_source_missing()` is the one
prerequisite that may NOT skip.
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


# ---- nothing may raise out of missing() -------------------------------
#
# It runs at import time, so an exception is not a skipped test -- it is
# `Interrupted: 1 error during collection` for the whole repository. Twice now
# that has happened from code added to make missing() safer.


def test_an_unreadable_prerequisite_is_reported_not_raised(lab, monkeypatch):
    """Path.exists() swallows only ENOENT/ENOTDIR/EBADF/ELOOP, so EACCES,
    ESTALE and ENOTCONN still propagate. Reproduced with a chmod 000 lab:

        PermissionError [Errno 13] ... burpsuite_desktop_v2026.7.3.jar

    A CI runner under another uid or a stale NFS mount is enough.
    """
    def denied(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "exists", denied)

    reasons = bf.missing()                       # must not raise
    assert reasons, "an unreadable prerequisite must be reported as missing"
    assert "could not be checked" in reasons[0]
    assert "Permission denied" in reasons[0]
    assert bf.burp_available() is False


def test_a_stale_nfs_mount_is_reported_not_raised(lab, monkeypatch):
    def stale(*_args, **_kwargs):
        raise OSError(116, "Stale file handle")

    monkeypatch.setattr(Path, "is_dir", stale)
    reasons = bf.missing()
    assert reasons and "could not be checked" in reasons[0]


# ---- a future mtime is a broken clock, not a stale jar ----------------


def test_a_future_dated_source_is_named_as_such(lab):
    """Treating it as staleness disables the suite PERMANENTLY: no rebuild can
    stamp the jar later than a source dated years ahead. Reproduced -- two
    honest rebuilds, still reported stale both times."""
    import time

    src = lab / "ext" / "src" / "hx" / "HxExtension.java"
    future = time.time() + 10 * 365 * 86400
    os.utime(src, (future, future))

    reasons = bf.missing()
    assert len(reasons) == 1, reasons
    assert "dated in the future" in reasons[0]
    assert "run extension/build.sh" not in reasons[0], (
        "a broken clock must not be reported as a stale jar: rebuilding cannot fix it"
    )

    # And a rebuild does not clear it, which is the whole point.
    os.utime(bf.EXT_JAR, None)
    assert any("dated in the future" in r for r in bf.missing())

    os.utime(src, (1_000_000, 1_000_000))
    assert bf.missing() == []


def test_a_genuinely_stale_jar_still_fires(lab):
    """The guard must keep working after being taught about future dates."""
    src = lab / "ext" / "src" / "hx" / "HxExtension.java"
    os.utime(src, (3_000_000, 3_000_000))        # newer than the jar's 2_000_000
    reasons = bf.missing()
    assert reasons == ["extension jar is older than its sources (run extension/build.sh)"]


# ---- the probe's source is a shipped file, not an environment fact -----
#
# It used to be a row in probe_missing(), which made it a SKIP: renaming
# tests/integration/probe/ produced `3 skipped in 0.03s` with no error and no
# diagnostic, and the default run announces DESELECTED integration tests, not
# skipped ones. The three facts eight tasks rest on stopped being checked with
# nothing red anywhere.


def test_the_shipped_probe_source_is_present():
    """No fake lab: this asserts about the real repository, which is the point."""
    assert bf.PROBE_SRC.exists(), bf.PROBE_SRC
    assert bf.probe_source_missing() is None


def test_a_deleted_probe_source_is_reported_separately_from_the_environment(
        lab, monkeypatch, tmp_path):
    gone = tmp_path / "no" / "such" / "Probe.java"
    monkeypatch.setattr(bf, "PROBE_SRC", gone)

    reason = bf.probe_source_missing()
    assert reason is not None, "a deleted probe source must be reported"
    assert str(gone) in reason
    assert "git checkout" in reason, "the message must say how to restore it"

    # And it must NOT be an environment row, because those SKIP.
    assert not any("Probe.java" in row for row in bf.probe_missing()), (
        "a missing probe source in probe_missing() is a skip, and a skipped "
        "measurement is the silence this check exists to remove")


def test_a_present_probe_source_adds_no_environment_row(lab):
    assert not any("Probe.java" in row for row in bf.probe_missing())


# ---- loopback_only, checked rather than asserted in a comment ----------
#
# Flipping that one string to `all_interfaces` left test_proxy_facts.py at
# `3 passed in 38.03s` with `ss` reporting the two configured listeners on
# `*:34777` and `*:38399`. Reproduced on this machine before the fix.

# Every local-address form measured on this machine's `ss -ltnpH` output.
LOOPBACK_FORMS = ["127.0.0.1:8080", "[::1]:631", "[::ffff:127.0.0.1]:40421",
                  "127.0.0.53%lo:53"]
EXPOSED_FORMS = ["0.0.0.0:8443", "*:8444", "[::]:3389", "100.64.0.1:22",
                 "[fd00:1234:5678::1]:22"]


@pytest.mark.parametrize("local", LOOPBACK_FORMS)
def test_loopback_address_forms_are_recognised(local):
    """`[::ffff:127.0.0.1]` is the form EVERY Burp listener takes here, so a
    parser that read it as exposed would fail every honest run. Whether
    IPv6Address.is_loopback alone answers True for an IPv4-mapped address is
    interpreter-dependent, which is why not_loopback_only() does not rely on
    it; these rows pin the answer whichever way that goes."""
    assert bf._is_loopback(local) is True


@pytest.mark.parametrize("local", EXPOSED_FORMS)
def test_exposed_address_forms_are_not_mistaken_for_loopback(local):
    """The direction that matters: `*` is the wildcard bind the whole check
    exists to catch, and it does not parse as an address at all."""
    assert bf._is_loopback(local) is False


def _sockets(*addresses):
    return lambda _pid: list(addresses)


def test_two_loopback_listeners_and_the_configured_ports_pass(monkeypatch):
    monkeypatch.setattr(bf, "_listening_sockets",
                        _sockets("[::ffff:127.0.0.1]:40421",
                                 "[::ffff:127.0.0.1]:41543"))
    assert bf.not_loopback_only(1234, [40421, 41543]) is None


def test_burps_own_third_listener_does_not_fail_the_check(monkeypatch):
    """Burp opens a third listener nobody configured on an ephemeral loopback
    port every run. Measured: it answers `204 No Content` to an absolute-URI
    GET, `200 Connection established` to a CONNECT and `204` inside the tunnel,
    forwards nothing to the target and never reaches the extension's handler.
    It is not an enforcement hole and it must not turn every run red."""
    monkeypatch.setattr(bf, "_listening_sockets",
                        _sockets("[::ffff:127.0.0.1]:40421",
                                 "[::ffff:127.0.0.1]:41543",
                                 "[::ffff:127.0.0.1]:43719"))
    assert bf.not_loopback_only(1234, [40421, 41543]) is None


def test_a_wildcard_bound_listener_is_named(monkeypatch):
    """`all_interfaces` in the config file, which is what this reproduces."""
    monkeypatch.setattr(bf, "_listening_sockets",
                        _sockets("*:34777", "[::ffff:127.0.0.1]:38399"))
    reason = bf.not_loopback_only(1234, [34777, 38399])
    assert reason and "*:34777" in reason, reason
    assert "loopback_only" in reason, "say which setting to look at"


def test_a_routable_listener_is_named_too(monkeypatch):
    """Not only the wildcard: a listener bound to this laptop's tailnet address
    is on a network as surely as `0.0.0.0` is."""
    monkeypatch.setattr(bf, "_listening_sockets",
                        _sockets("100.64.0.1:34777"))
    reason = bf.not_loopback_only(1234, [34777])
    assert reason and "100.64.0.1:34777" in reason


def test_a_configured_port_that_is_not_listening_is_not_a_pass(monkeypatch):
    """Otherwise the check passes vacuously against a Burp that bound nothing:
    every socket found is loopback when no socket was found at all."""
    monkeypatch.setattr(bf, "_listening_sockets",
                        _sockets("[::ffff:127.0.0.1]:40421"))
    reason = bf.not_loopback_only(1234, [40421, 41543])
    assert reason and "41543" in reason, reason


def test_a_port_is_matched_whole_and_not_as_a_suffix(monkeypatch):
    """`endswith(":387")` against `...:46387` is the bug this rules out."""
    monkeypatch.setattr(bf, "_listening_sockets",
                        _sockets("[::ffff:127.0.0.1]:46387"))
    assert bf.not_loopback_only(1234, [387]) is not None
    assert bf.not_loopback_only(1234, [46387]) is None


def test_an_unreadable_ss_is_reported_rather_than_passed(monkeypatch):
    """A guard that evaporates when its tool is missing is the defect this
    function exists to fix, one level down."""
    def no_ss(*_a, **_k):
        raise FileNotFoundError(2, "No such file or directory: 'ss'")

    monkeypatch.setattr(bf.subprocess, "run", no_ss)
    reason = bf.not_loopback_only(1234, [40421])
    assert reason and "unverified" in reason, reason


def test_no_socket_attributed_to_the_pid_is_reported_rather_than_passed(monkeypatch):
    monkeypatch.setattr(bf, "_listening_sockets", _sockets())
    reason = bf.not_loopback_only(1234, [40421])
    assert reason and "no listening socket" in reason, reason


class TestTheSkipFailSplit:
    """`unbuilt()` and `_environment_missing()`, in both directions.

    Both were added in a commit that shipped zero tests for them, and its
    review found three defects that a single test would each have caught. The
    guards below are the three.
    """

    def test_a_future_dated_source_is_not_a_build_problem(self, tmp_path,
                                                          monkeypatch):
        """It is the clock's, and build.sh provably cannot fix it.

        No jar can be stamped later than a source dated years ahead, so
        routing this to a hard FAIL tells the operator to run a script that
        changes nothing -- permanently, for every run. Measured before the
        fix: two honest rebuilds, still reported unbuilt both times.
        """
        monkeypatch.setattr(bf, "_jar_problem", lambda: "future")
        monkeypatch.setattr(bf, "_environment_missing", lambda: [])
        assert bf.unbuilt() == []

    def test_but_a_stale_jar_is(self, monkeypatch):
        """The separating case: without it the test above passes on a function
        that always returns empty."""
        monkeypatch.setattr(bf, "_jar_problem", lambda: "stale")
        monkeypatch.setattr(bf, "_environment_missing", lambda: [])
        assert bf.unbuilt() and "build.sh" in bf.unbuilt()[0]

    def test_a_machine_that_cannot_build_is_not_told_to_build(self, monkeypatch):
        """build.sh needs the montoya jar from the same lab the environment
        check reports, and exits 1 without it. A build product is only
        independent of the machine when the machine can build it."""
        monkeypatch.setattr(bf, "_jar_problem", lambda: "missing")
        monkeypatch.setattr(bf, "_environment_missing",
                            lambda: ["burp jar: /nope"])
        assert bf.unbuilt() == []

    def test_neither_predicate_raises_on_an_unreadable_lab(self, monkeypatch):
        """Both run at IMPORT TIME through test_real_burp's skipif, so an
        exception here is not a skipped test -- it is `Interrupted: 1 error
        during collection` for the entire repository, 396 fast tests included.
        Measured against a lab at mode 000 before the fix: 0 of 396 ran.
        """
        def boom():
            raise PermissionError(13, "Permission denied")
        monkeypatch.setattr(bf, "_environment_missing_unguarded", boom)
        assert bf._environment_missing()          # reports, does not raise
        monkeypatch.setattr(bf, "_jar_problem", boom)
        assert bf.unbuilt() == []                 # same, and stays silent
