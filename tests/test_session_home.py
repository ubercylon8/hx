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
