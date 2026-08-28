import os
import stat
from pathlib import Path

import pytest

from hx import session


@pytest.fixture
def seeded_home(monkeypatch, tmp_path):
    """A fake Burp home with an accepted licence, standing in for the
    operator's own via $HX_BURP_SEED_HOME -- never the real $HOME, which
    this suite must not touch.
    """
    seed = tmp_path / "seed"
    prefs_dir = seed / ".java" / ".userPrefs" / "burp"
    prefs_dir.mkdir(parents=True)
    (prefs_dir / "prefs.xml").write_bytes(
        b'<map><entry key="burp.eula" value="true"/></map>')
    # A lock file living where make_home()'s glob looks for one, so the test
    # that asserts its removal is exercising real behaviour and not a glob
    # that never had anything to find.
    (seed / ".java" / ".userPrefs" / ".userRootModFile.lock").write_text("lock")
    burpsuite = seed / ".BurpSuite"
    burpsuite.mkdir()
    (burpsuite / "burpbrowser").mkdir()
    (burpsuite / "burpbrowser" / "chrome").write_text("browser payload")
    (burpsuite / "UserConfigCommunity.json").write_text("{}")
    monkeypatch.setenv("HX_BURP_SEED_HOME", str(seed))
    return seed


def test_the_seed_is_the_operators_own_burp_home(monkeypatch, tmp_path):
    monkeypatch.delenv("HX_BURP_SEED_HOME", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert session.seed_home() == tmp_path


def test_the_seed_can_be_overridden(monkeypatch, tmp_path):
    monkeypatch.setenv("HX_BURP_SEED_HOME", str(tmp_path))
    assert session.seed_home() == tmp_path


def test_a_home_that_never_accepted_the_licence_says_so(monkeypatch, tmp_path):
    # The failure this replaces is a 90-second handshake timeout with no
    # diagnostic: Burp starts, waits at the licence prompt, and never dials.
    monkeypatch.setenv("HX_BURP_SEED_HOME", str(tmp_path))
    (tmp_path / ".BurpSuite").mkdir()
    with pytest.raises(session.SessionError) as exc:
        session.make_home(tmp_path / "work")
    assert "accept" in str(exc.value).lower()


def test_the_private_home_is_a_copy_and_the_seed_is_untouched(seeded_home, tmp_path):
    home = session.make_home(tmp_path / "work")
    assert home != seeded_home
    (home / ".BurpSuite" / "scratch").write_text("written by the run")
    assert not (seeded_home / ".BurpSuite" / "scratch").exists(), (
        "the run wrote into the operator's own Burp home")


def test_a_copied_preferences_lock_is_removed(seeded_home, tmp_path):
    # A lock file copied from the seed belongs to the seed's process, and
    # leaving it makes Java Preferences fight a Burp that is not running.
    home = session.make_home(tmp_path / "work")
    assert not list((home / ".java" / ".userPrefs").glob(".user*"))


def test_a_named_seed_beats_the_environment_and_the_home(monkeypatch, tmp_path):
    """A caller that knows which home to copy says so in code.

    `$HX_BURP_SEED_HOME` is the operator's override and `Path.home()` is the
    default, and neither can serve a caller that must not read the machine at
    all. Both are pointed somewhere fatal here: a `make_home` that consulted
    either would raise, since neither has accepted a licence.

    The gap this closes was measured. While the seed could ONLY be steered by
    the environment, `tests/integration/burp_fixture.py` set the variable from
    an autouse pytest fixture -- so `scripts/demo_capture.py` and
    `scripts/demo_gate.py`, which call the same launcher outside pytest,
    checked the lab's home in `missing()` and then copied the operator's live
    `~/.BurpSuite/sessions` into a temporary directory.
    """
    named = tmp_path / "named"
    prefs = named / ".java" / ".userPrefs" / "burp"
    prefs.mkdir(parents=True)
    (prefs / "prefs.xml").write_bytes(
        b'<map><entry key="burp.eula" value="true"/></map>')
    (named / ".BurpSuite").mkdir()
    (named / ".BurpSuite" / "UserConfigCommunity.json").write_text("{}")

    monkeypatch.setenv("HX_BURP_SEED_HOME", str(tmp_path / "env-seed-no-eula"))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))

    home = session.make_home(tmp_path / "work", seed=named)
    assert (home / ".BurpSuite" / "UserConfigCommunity.json").exists(), (
        "make_home copied something other than the seed it was handed")


def test_an_omitted_seed_still_means_the_operators_home(seeded_home, tmp_path):
    """The default is unchanged, and that matters: a consultant's accepted
    licence is the only one hx may use, so `seed=None` must keep resolving
    through `seed_home()` rather than becoming a required argument."""
    home = session.make_home(tmp_path / "work")
    assert (home / ".BurpSuite" / "UserConfigCommunity.json").exists()


def test_a_second_run_copies_a_fresh_home_over_the_previous_one(
        seeded_home, tmp_path):
    """F1, in the shape an operator meets it: `hx capture start`, twice.

    `session()` defaults its workdir to `<engagement>/session` and nothing
    removes it, so the second `make_home` on one engagement hit
    `mkdir(parents=True)` on an existing `.BurpSuite` and raised
    `FileExistsError` -- not a `SessionError`, so the CLI's handler missed it
    and click printed a traceback with EMPTY output. A session that died
    mid-flight left the same directory behind, so one handshake timeout
    bricked the command for that engagement until somebody deleted the tree
    by hand.

    The second half is the constraint that rules out the easy fix: the
    previous run's home must not be REUSED either. It holds that run's
    `.BurpSuite/sessions` and its Java Preferences, and the whole point of a
    private home is that a run does not inherit another's state -- so the
    marker written into the first copy must be gone from the second.
    """
    work = tmp_path / "work"
    first = session.make_home(work)
    (first / ".BurpSuite" / "left-by-the-previous-run").write_text("stale")

    second = session.make_home(work)

    assert second == first, "the home is per run, but its path is the workdir's"
    assert (second / ".BurpSuite" / "UserConfigCommunity.json").exists(), (
        "the second run did not get a copy of the seed at all")
    assert not (second / ".BurpSuite" / "left-by-the-previous-run").exists(), (
        "the second run adopted the first run's Burp state: a private home "
        "that is reused is not a private home")


def test_the_copy_is_0o700_from_creation_even_at_a_loose_umask(
        seeded_home, tmp_path):
    """The two directories `make_home` CREATES rather than copies.

    Everything else in the tree arrives through `copytree`/`copy2` and carries
    the seed's own modes. `burphome` and `burphome/.BurpSuite` are made here,
    and at a plain `mkdir` they landed at the umask -- measured at 0o755 on
    this machine against a seed whose `.BurpSuite` is 0o700. What they hold is
    the operator's licence prefs and Burp's CA key, inside the engagement
    directory a consultant archives; the branch rule is 0o700 and never
    widened. The umask is forced loose here so the assertion is about the
    creation mode rather than about this machine's default.
    """
    previous = os.umask(0o022)
    try:
        home = session.make_home(tmp_path / "work")
    finally:
        os.umask(previous)

    assert stat.S_IMODE(home.stat().st_mode) == 0o700, (
        f"burphome was created at {oct(stat.S_IMODE(home.stat().st_mode))}")
    inner = home / ".BurpSuite"
    assert stat.S_IMODE(inner.stat().st_mode) == 0o700, (
        f"burphome/.BurpSuite was created at "
        f"{oct(stat.S_IMODE(inner.stat().st_mode))}")


def test_a_symlink_where_the_home_goes_is_removed_and_never_walked_into(
        seeded_home, tmp_path):
    """`shutil.rmtree` refuses a symlinked root, and must never be given one.

    The elsewhere it points at is a real directory with a file in it. Clearing
    the previous home must unlink the LINK and leave that file alone -- a
    clear that followed it would delete whatever an operator had pointed the
    path at, and one that did not handle it at all would raise `OSError` out
    of a module whose contract is `SessionError`.
    """
    work = tmp_path / "work"
    work.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "precious").write_text("not ours to delete")
    (work / "burphome").symlink_to(elsewhere)

    home = session.make_home(work)

    assert not home.is_symlink()
    assert (home / ".BurpSuite" / "UserConfigCommunity.json").exists()
    assert (elsewhere / "precious").exists(), (
        "clearing the previous home followed a symlink out of the workdir")
