# Bridge Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the product the bridge session it never had — `hx` launches Burp, verifies its listeners are loopback-only, configures the extension out of DENY-ALL, and holds the session while a consultant browses.

**Architecture:** One new module, `src/hx/session.py`, built by promoting proven code out of `tests/integration/burp_fixture.py`. Each command owns its own Burp; there is no daemon and no second IPC channel. `tests/integration/conftest.py` and `scripts/demo_capture.py` are then rewritten to import the product's session, so the code a consultant runs becomes the code under test.

**Tech Stack:** Python 3.12, `.venv/bin/pytest`, click CLI, `subprocess`, Unix domain sockets. Zero new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-08-28-bridge-session-design.md` (approved 2026-08-28)
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§4 enforcement invariant and the DENY-ALL default, §5 tables, §6 bridge `configure`/epoch, §13 v1 scope)

## Global Constraints

- **§4 enforcement invariant:** every byte that leaves this machine crosses one of two points inside the JVM. DENY-ALL is terminal. This plan starts a Burp and authorises it; it does not add an egress path.
- **The agent's rules never bind the operator's browser.** §4: the method allowlist, dangerous-path denylist, rate limit and budget "apply to the send path in full, and to crawler traffic in full. They do **not** apply to traffic from the operator's own browser." The two are told apart by **which proxy listener the request arrived on**, never by anything in the traffic — so **both listeners must always be configured and `-Dhx.crawler_port` must always be passed.**
- **No Java changes.** `extension/` is untouched. `./extension/test.sh` must still print `13 ALL PASS`, 2330 `ok`, ~2352 output lines, rc 0. Check the **line count**, not just rc — it has printed zero summary lines and exited 0 with a missing jar.
- **`hx` never bundles or redistributes Burp.** This plan only *locates* a jar the operator already has.
- **Never run Burp against the real `$HOME`.** A private home is built per run and the operator's home is a read-only seed.
- **All test targets are loopback only.** Nothing in this project has ever sent a request off this machine.
- Engagement directories `0o700`; blob and DB files `0o600`. Never looser, never widened.
- **Baselines to hold:** `.venv/bin/pytest` → `931 passed, 1 skipped, 30 deselected`; `.venv/bin/pytest -m integration` → `30 passed` (~200s, real headless Burp).
- Some functions are guarded by plan byte-compare tests. If one breaks, sync it with a trailing `chore(plans):` commit — see `13a029e` and `3fc0a41`.
- **Every code block below carries a `# path` marker and is compared against the repository** by `tests/test_plan_matches_repo.py`. A marker that is a bare path means the block is that WHOLE FILE; a marker with a ` -- ` note means it is an EXCERPT — a contiguous run of that file, byte for byte. The blocks were written without markers, so none of them was compared for the length of this plan and the `session()` block drifted six fixes behind the code, including an error message commit `4428462` had removed. They are the finished files now, synced with `scripts/sync_plan_block.py`; **never edit a block by hand.** A step that says "write the failing tests" therefore shows the tests as they ended up, fix rounds included, rather than as they were first typed.

---

## File Structure

**Created:**
- `src/hx/session.py` — the whole session: locating Burp, building a private home, writing the listener config, launching, waiting for the handshake, verifying loopback-only listeners, configuring, and tearing down. One module because these steps are one lifecycle and splitting them would put the teardown guarantee in a different file from the thing it guarantees.

**Modified:**
- `src/hx/cli.py` — `capture start` launches Burp and blocks.
- `tests/integration/burp_fixture.py` — keeps only what is genuinely test-only (`missing`, `unbuilt`, `burp_available`, the `Probe.java` helper and its compile/launch); everything else is re-exported from `hx.session` so existing imports keep working.
- `tests/integration/conftest.py` — the rig uses the product's session and its config body.
- `scripts/demo_capture.py` — the demo uses the product's session.

**Not in this plan:** `hx scan` does not open a session. Passive checks read the store offline; scan needs a bridge only once active checks exist, and that is the active-checks plan's task.

---

## Task 1: locating Burp

**Files:**
- Create: `src/hx/session.py`
- Test: `tests/test_session_jar.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `SessionError(Exception)`; `find_burp_jar(explicit: Path | None = None) -> Path`.

The fixture hardcodes `BURP_JAR = LAB / "burpsuite_desktop_v2026.7.3.jar"`. That is right for a pinned fixture and wrong for a product whose user upgrades Burp.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_session_jar.py
from pathlib import Path

import pytest

from hx import session


def test_an_explicit_jar_path_wins(tmp_path):
    jar = tmp_path / "burpsuite_desktop_v2026.7.3.jar"
    jar.write_bytes(b"x")
    assert session.find_burp_jar(jar) == jar


def test_a_named_jar_that_does_not_exist_is_a_clear_error(tmp_path):
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar(tmp_path / "nope.jar")
    assert "nope.jar" in str(exc.value)


def test_the_lab_is_searched_without_pinning_a_version(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    jar = tmp_path / "burpsuite_desktop_v2027.1.0.jar"
    jar.write_bytes(b"x")
    assert session.find_burp_jar() == jar


def test_two_matching_jars_is_an_error_naming_both(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    (tmp_path / "burpsuite_desktop_v2026.7.3.jar").write_bytes(b"x")
    (tmp_path / "burpsuite_desktop_v2027.1.0.jar").write_bytes(b"x")
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar()
    # Picking the newest silently would let a consultant run an assessment
    # against a different Burp from the one they believe, and the report
    # records the version.
    assert "2026.7.3" in str(exc.value) and "2027.1.0" in str(exc.value)
    assert "--burp-jar" in str(exc.value)


def test_no_jar_anywhere_names_all_three_places_it_looked(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    monkeypatch.delenv("HX_BURP_JAR", raising=False)
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar()
    msg = str(exc.value)
    assert "--burp-jar" in msg and "HX_BURP_JAR" in msg and str(tmp_path) in msg
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_jar.py -v`
Expected: FAIL — `No module named 'hx.session'`.

- [ ] **Step 3: Write the locator**

```python
# src/hx/session.py -- Task 1: the error class and the jar locator
class SessionError(Exception):
    """The session cannot be established. The message names the fix."""


def _lab() -> Path:
    return Path(os.environ.get("HX_BURP_LAB", DEFAULT_LAB))


def find_burp_jar(explicit: Path | None = None) -> Path:
    """`--burp-jar`, then `$HX_BURP_JAR`, then a search of `$HX_BURP_LAB`.

    AMBIGUITY IS AN ERROR, NOT A GUESS. Two jars in the lab means the operator
    has upgraded and kept the old one, and silently taking the newer would run
    an assessment against a different Burp from the one they believe they are
    running -- which the report then records as the version under test.
    """
    if explicit is not None:
        if not Path(explicit).is_file():
            raise SessionError(f"no Burp jar at {explicit}")
        return Path(explicit)

    from_env = os.environ.get("HX_BURP_JAR")
    if from_env:
        if not Path(from_env).is_file():
            raise SessionError(f"HX_BURP_JAR names {from_env}, which is not a file")
        return Path(from_env)

    lab = _lab()
    found = sorted(lab.glob(JAR_GLOB))
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        names = ", ".join(p.name for p in found)
        raise SessionError(
            f"{len(found)} Burp jars in {lab}: {names}. Pass --burp-jar to say "
            "which one this engagement runs against -- the report records the "
            "version, so this is not a choice hx may make for you")
    raise SessionError(
        f"no Burp jar found. Pass --burp-jar, set HX_BURP_JAR, or put one "
        f"matching {JAR_GLOB} in {lab} (override with HX_BURP_LAB). hx does "
        "not ship Burp")
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_jar.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/session.py tests/test_session_jar.py
git commit -m "feat(session): locate the operator's Burp jar, refusing to guess"
```

---

## Task 2: the extension jar, and a private Burp home seeded from the operator's

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_home.py`

**Interfaces:**
- Consumes: `SessionError` (Task 1).
- Produces: `EXT_JAR: Path`; `extension_problem() -> str | None`; `seed_home() -> Path`; `make_home(workdir: Path) -> Path`.

**The decision this task settles, which the spec left open.** `burp_fixture.make_home` copies from `SEED_HOME = LAB / "burphome"` — a lab directory that exists on a developer's machine and not on a consultant's. A wholly fresh Burp home sits at an unaccepted licence prompt and never completes the handshake, which would surface as a bare timeout.

**Ruling: the seed is the operator's own Burp home** — `$HX_BURP_SEED_HOME` if set, else `$HOME`. It is **copied, never run against**, exactly as the fixture treats its seed. An operator who has never run Burp gets told to run it once and accept the licence, rather than a 90-second timeout.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_session_home.py
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_home.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'seed_home'`.

- [ ] **Step 3: Move `make_home`, `_eula_accepted`, `_jar_is_stale`, `_jar_mtime`, `_newest_source_mtime` from `tests/integration/burp_fixture.py`**

Move these **unchanged except where named below**, keeping their docstrings — each one records a failure that was diagnosed once and must not be rediscovered:

- `make_home` (fixture line 274): change `SEED_HOME` to `seed_home()`, and raise `SessionError` when the seed has no accepted licence. Keep the symlink for `burpbrowser` — it is 650 MB and read-mostly — and keep the `.userPrefs` lock removal.
- `_eula_accepted` (line 254): take the seed as an argument. **Keep the byte search and its comment**: `read_text()` on Burp's 1.75 MB prefs file raised `UnicodeDecodeError` on a torn write, which is not an `OSError`, and turned every pytest run in the repo into a collection error with zero tests run.
- `_jar_problem` (line 75), `_jar_is_stale` (209), `_jar_mtime` (231) and `_newest_source_mtime` (235): these judge the **extension** jar against `extension/src`, not Burp's jar (`_jar_mtime` reads `EXT_JAR.stat()`). `_jar_problem`'s three-way judgement becomes `extension_problem()` below — keep all three outcomes.

Add, using the same `parents[2]` depth the fixture uses — `src/hx/session.py` and `tests/integration/burp_fixture.py` are both two levels below the repo root, so the expression is identical:

```python
# src/hx/session.py -- Task 2: the extension jar, and the private Burp home
def seed_home() -> Path:
    """The Burp home to COPY FROM. Never the home Burp runs against.

    The operator's own, because that is the one whose licence they accepted.
    hx has no way to accept it for them and must not try.
    """
    from_env = os.environ.get("HX_BURP_SEED_HOME")
    return Path(from_env) if from_env else Path.home()


def _jar_mtime() -> float:
    return EXT_JAR.stat().st_mtime


def _newest_source_mtime() -> float:
    """0.0 when there are no sources -- absence is not evidence of staleness.

    A source that cannot be stat'd is skipped rather than raised: a dangling
    symlink, or a file that vanishes between the glob and the stat because a
    checkout or a rebuild is running alongside the suite, is no evidence that
    the jar is stale. Disabling the integration suite over a transient race
    would be the wrong direction -- unlike an unreadable LAB, which really
    does mean the prerequisites are unknown.
    """
    newest = 0.0
    for src in EXT_SRC.rglob("*.java"):
        try:
            newest = max(newest, src.stat().st_mtime)
        except OSError:
            continue
    return newest


def extension_problem() -> str | None:
    """Why the bridge extension jar cannot be used, or None.

    Burp STARTS HAPPILY WITHOUT AN EXTENSION, so an unbuilt or stale jar does
    not fail the launch -- it fails the handshake ninety seconds later with
    nothing pointing at the cause. Judged before launching for that reason.

    THREE OUTCOMES, NOT TWO, and the third is why this is one function.
    `_jar_problem` in the fixture records the bug: a FUTURE-dated source
    cannot be cleared by rebuilding -- no jar can be stamped later than a
    source dated years ahead -- so routing it to "run build.sh" told the
    operator to run a script that provably cannot help, permanently
    ("two honest rebuilds, still reported stale both times"). Missing and
    stale are build.sh's; future is the clock's, and it says so.
    """
    if not EXT_JAR.is_file():
        return (f"the bridge extension is not built: {EXT_JAR} does not exist. "
                "Run ./extension/build.sh")
    newest = _newest_source_mtime()
    if newest > time.time() + 60:
        return (f"a source under {EXT_SRC} is dated in the future, so no "
                "rebuild can make the jar newer than it. Fix the file's "
                "timestamp or the clock -- ./extension/build.sh cannot help")
    if newest > _jar_mtime():
        return (f"{EXT_JAR} is older than {EXT_SRC}. Run ./extension/build.sh "
                "-- Burp would start with the previous extension and the "
                "difference would show up as a handshake timeout")
    return None


def _eula_accepted(seed: Path) -> bool:
    prefs = seed / ".java" / ".userPrefs" / "burp" / "prefs.xml"
    try:
        # Searched as bytes. Burp rewrites this 1.75 MB file on exit, and a
        # torn write that lands mid-multibyte-character makes read_text()
        # raise UnicodeDecodeError -- which is not an OSError, so it escaped
        # this function, escaped missing(), and turned every pytest run in
        # the repo into a collection error with zero tests run. Reproduced;
        # a byte search cannot raise it at all.
        # The key is "burp.eula", not "eula" -- a check for the short
        # name reports every accepted home as unaccepted.
        return b'key="burp.eula"' in prefs.read_bytes()
    except OSError:
        return False


def _clear_previous_home(home: Path) -> None:
    """Remove whatever a previous run left at `home`, whatever shape it is.

    A symlink is UNLINKED, never walked into: `shutil.rmtree` refuses a
    symlinked root outright, and a version that did not would delete the tree
    somebody pointed it at. The same for a plain file, which is not a home and
    cannot become one by being copied into.
    """
    if home.is_symlink() or (home.exists() and not home.is_dir()):
        home.unlink()
    elif home.exists():
        shutil.rmtree(home)


def make_home(workdir: Path, *, seed: Path | None = None) -> Path:
    """A private $HOME per run.

    Sharing one Burp home across runs means sharing a Java Preferences lock and
    a sessions directory with any other Burp on the machine -- including one a
    developer left running. The prefs are 3 MB and cheap to copy; the embedded
    browser is 650 MB, read-mostly, and gets a symlink instead.

    PER RUN MEANS PER RUN, so an existing `burphome` is REMOVED and copied
    again rather than reused or merged into. Until this call did that, the
    plain `mkdir(parents=True)` below raised `FileExistsError` the second time
    `hx capture start` ran against one engagement -- not a `SessionError`, so
    the CLI printed a traceback with no output at all, and any session that
    died mid-flight (a handshake timeout, a refused configure, a SIGKILL) left
    the directory behind and bricked the command for that engagement until the
    operator found and deleted it by hand.

    Reusing it instead was the other candidate and it is the worse one: the
    tree holds the PREVIOUS run's Burp state -- its `.BurpSuite/sessions`, its
    Java Preferences, whatever the last JVM wrote on the way down -- and a
    second run adopting that silently is the one thing the sentence above says
    this function exists to avoid. The workdir itself is kept (it is where the
    bridge socket lives, and a stale `hx.sock` is REPORTED rather than removed,
    which is how a still-running session is told from a dead one); only the
    copied home is discarded, because only the copied home is per-run state
    hx made and hx can replace.

    The seed is COPIED FROM, never run against -- see seed_home(). A seed
    that never accepted Burp's licence sits at the licence prompt and never
    dials in, which without this check surfaces as a bare 90-second handshake
    timeout; checked here, before the copy, so it is reported instead.

    `seed` NAMES THE HOME TO COPY, and omitting it means `seed_home()` -- the
    operator's own, which is the right default for a consultant because the
    licence they accepted is the only one hx may use. It is a PARAMETER, not
    only an environment variable, because a caller that already knows the
    answer must be able to say so in code:

      - `tests/integration/burp_fixture.py` copies the LAB's curated home. It
        checks that home in `missing()` and then launches, and while the seed
        could only be steered through `$HX_BURP_SEED_HOME` the check and the
        copy were two different homes for any caller outside pytest --
        `scripts/demo_capture.py` and `scripts/demo_gate.py` verified the lab
        and then copied the operator's live `~/.BurpSuite/sessions`, which on
        a consultant's machine is real client project state.
      - a unit test may not read `Path.home()` AT ALL. `tests/test_session_
        launch.py` faked only `Popen`, so three tests in the DEFAULT suite
        copied the developer's live Burp home into `tmp_path` and passed only
        because this machine's `$HOME` had accepted the EULA.
    """
    seed = Path(seed) if seed is not None else seed_home()
    if not _eula_accepted(seed):
        raise SessionError(
            f"{seed} has not accepted the Burp Suite licence. Run Burp by "
            "hand from that home once and accept it there -- hx copies this "
            "home, it does not run against it, and cannot accept the "
            "licence on your behalf")
    home = workdir / "burphome"
    try:
        _clear_previous_home(home)
    except OSError as exc:
        raise SessionError(
            f"the private Burp home a previous run left at {home} could not "
            f"be removed: {exc}. hx copies a fresh one per run and will not "
            "run against a stale one; remove that path by hand") from exc
    # secure_mkdir, not mkdir(parents=True): these are the only two directories
    # in the copy that this function CREATES rather than copies, and so the
    # only two that landed at the umask -- measured at 0o755 against a seed
    # whose own `.BurpSuite` is 0o700. Everything below is a copytree or a
    # copy2 and carries the seed's modes with it. What lands here is the
    # licence prefs and Burp's CA key, inside a client's engagement directory:
    # the branch rule is 0o700, never widened.
    secure_mkdir(home / ".BurpSuite")
    shutil.copytree(seed / ".java", home / ".java")
    for lock in (home / ".java" / ".userPrefs").glob(".user*"):
        lock.unlink()                 # a copied lock file belongs to the seed
    for entry in (seed / ".BurpSuite").iterdir():
        target = home / ".BurpSuite" / entry.name
        if entry.name == "burpbrowser":
            target.symlink_to(entry)
        elif entry.is_dir():
            shutil.copytree(entry, target)
        else:
            shutil.copy2(entry, target)
    return home
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_home.py -v`
Expected: all pass.

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: `941 passed, 1 skipped, 30 deselected` (931 + 5 from Task 1 + 5 here).

- [ ] **Step 6: Commit**

```bash
git add src/hx/session.py tests/test_session_home.py
git commit -m "feat(session): a private Burp home, seeded from the operator's own"
```

---

## Task 3: launching Burp

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_launch.py`

**Interfaces:**
- Consumes: `find_burp_jar`, `make_home`, `extension_problem`, `EXT_JAR` (Tasks 1-2).
- Produces: `PROXY_CONFIG: str`; `ADD_OPENS: list[str]`; `_free_port() -> int`; `write_listener_config(workdir: Path, second_port: int = 0) -> list[int]`; `launch_burp(socket_path, engagement_id, workdir, *, sentinel, jar, instance, crawler_port=0) -> subprocess.Popen`; `wait_for(predicate, timeout=90.0, interval=0.5) -> bool`.

**What changes in the promotion, and nothing else does.** `burp_fixture.launch_burp` hardcodes two things a product cannot:

1. `-Dhx.instance=integration` becomes the `instance` argument, so a capture session identifies itself as `capture`.
2. `-cp f"{BURP_JAR}:{EXT_JAR}"` takes the located `jar` rather than the pinned module constant, and `cwd=LAB` becomes `cwd=workdir`.

**Everything else moves verbatim, including every comment.** Three of them record failures that cost real debugging time and would otherwise be rediscovered:

- `-Dhx.halt_sentinel` is **required, not optional**: `HxExtension.initialize()` returns early ("extension idle") without it, so the extension never dials and the handshake never happens.
- `-Dhx.crawler_port` is **required and read back from the config file**, never from the argument, which may be the `0` meaning "choose one for me". Omitting it makes `Source.forListenerPort` answer OPERATOR for every request however many listeners run — so §4's operator/agent split silently stops working while everything appears fine.
- Output goes to `workdir/burp.log`, **never a pipe**: an unread `subprocess.PIPE` deadlocks once Burp fills the buffer, and a file lets a failure quote what Burp actually said.
- `proc.stdin.write(b"\n\n")` selects Community Edition.

- [ ] **Step 1: Write the failing tests**

These assert the command hx *builds*, without launching a JVM, so they run in the default suite. Define the stub once, at the top of the file — later tasks reuse it:

```python
# tests/test_session_launch.py -- the fakes a launch test needs
class _FakeProc:
    """A launched process that never was. `pid` is real enough to be passed
    to a monkeypatched `not_loopback_only`, and `on_kill` lets a test prove
    teardown happened."""

    def __init__(self, on_kill=None):
        self.pid = 4242
        self.stdin = io.BytesIO()
        self._on_kill = on_kill

    def kill(self):
        if self._on_kill is not None:
            self._on_kill(self.pid)

    def wait(self, timeout=None):
        return 0


@pytest.fixture
def seed(tmp_path):
    """A Burp home with an accepted licence, standing in for the operator's.

    The same shape `tests/test_session_home.py::seeded_home` builds, and the
    same reason: `make_home` refuses a seed that never accepted the EULA, and
    it copies `.java` wholesale and iterates `.BurpSuite`, so both have to be
    there or the copy dies half way through.
    """
    home = tmp_path / "seed"
    prefs = home / ".java" / ".userPrefs" / "burp"
    prefs.mkdir(parents=True)
    (prefs / "prefs.xml").write_bytes(
        b'<map><entry key="burp.eula" value="true"/></map>')
    (home / ".BurpSuite").mkdir()
    (home / ".BurpSuite" / "UserConfigCommunity.json").write_text("{}")
    return home


@pytest.fixture
def built_extension(tmp_path, monkeypatch):
    """A bridge jar newer than its sources, so `extension_problem()` passes.

    Pointed at `tmp_path` rather than stubbed out: the pre-flight still runs
    for real, it just stops depending on `extension/build/hx-bridge.jar`,
    which is gitignored and absent on any machine that has not run build.sh.
    An empty source tree makes `_newest_source_mtime()` 0.0, which is younger
    than anything.
    """
    jar = tmp_path / "ext" / "build" / "hx-bridge.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"not really a jar; nothing here launches a JVM")
    src = tmp_path / "ext" / "src"
    src.mkdir(parents=True)
    monkeypatch.setattr(session, "EXT_JAR", jar)
    monkeypatch.setattr(session, "EXT_SRC", src)
    return jar
```

```python
# tests/test_session_launch.py -- the tests themselves
def test_the_launch_command_carries_every_required_property(
        monkeypatch, tmp_path, seed, built_extension):
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return _FakeProc()

    monkeypatch.setattr(session.subprocess, "Popen", fake_popen)
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", seed=seed)
    joined = " ".join(seen["cmd"])
    assert "-Dhx.halt_sentinel=" in joined, (
        "without the sentinel HxExtension returns early and never dials, so "
        "the handshake times out with nothing naming the cause")
    assert "-Dhx.crawler_port=" in joined, (
        "without it Source.forListenerPort answers OPERATOR for every request "
        "and S4's operator/agent split stops working silently")
    assert "-Dhx.instance=capture" in joined
    assert "--developer-extension-class-name=hx.HxExtension" in joined
    assert "--disable-auto-update" in joined


def test_the_crawler_port_is_the_one_burp_was_actually_given(
        monkeypatch, tmp_path, seed, built_extension):
    # Read back out of the config file, never from the argument, which may be
    # the 0 that means "choose one for me". A launch that instead interpolates
    # the raw crawler_port argument still passes every other assertion here,
    # so this pins the exact substring rather than "-Dhx.crawler_port=" alone.
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(session.subprocess, "Popen", fake_popen)

    # A distinctive non-zero port: the command must carry exactly this value,
    # not a substring match that "-Dhx.crawler_port=0" would also satisfy.
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", crawler_port=54321, seed=seed)
    joined = " ".join(seen["cmd"])
    assert "-Dhx.crawler_port=54321" in joined

    # crawler_port=0 means "choose one for me" -- the command must carry
    # whatever write_listener_config actually bound, never the literal 0.
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w2",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", crawler_port=0, seed=seed)
    joined = " ".join(seen["cmd"])
    assert "-Dhx.crawler_port=0" not in joined, (
        "0 means choose one for me -- the raw argument must never reach the "
        "command line, or Source.forListenerPort answers OPERATOR for every "
        "request however many listeners are running")


def test_output_goes_to_a_file_not_a_pipe(
        monkeypatch, tmp_path, seed, built_extension):
    seen = {}
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: (seen.update(kw), _FakeProc())[1])
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", seed=seed)
    assert seen["stdout"] is not session.subprocess.PIPE, (
        "an unread PIPE deadlocks once Burp fills the buffer")
    assert (tmp_path / "w" / "burp.log").exists()


def test_the_seed_is_the_one_the_caller_named_not_the_operators(
        monkeypatch, tmp_path, seed, built_extension):
    """The regression this whole fixture pair exists for.

    `launch_burp` must copy the home it was HANDED. Proved by making
    `seed_home()` -- the default -- explode: a launch that still consulted it
    would raise instead of building a home, and the copy that lands in the
    workdir could then only have come from `seed`.
    """
    def never(*_a, **_k):
        raise AssertionError(
            "launch_burp read the operator's Burp home despite being handed "
            "a seed; every default pytest run would copy ~/.BurpSuite again")

    monkeypatch.setattr(session, "seed_home", never)
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: _FakeProc())
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", seed=seed)
    copied = tmp_path / "w" / "burphome" / ".BurpSuite" / "UserConfigCommunity.json"
    assert copied.exists(), "the named seed's contents are what should be copied"
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_launch.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'launch_burp'`.

- [ ] **Step 3: Move the launcher**

Move `ADD_OPENS` (fixture line 33), `PROXY_CONFIG` (308), `_free_port` (311), `write_listener_config` (339), `launch_burp` (366) and `wait_for` (426) into `src/hx/session.py`, applying only the two changes named above. Keep `write_listener_config`'s comment about `listen_mode: loopback_only` being written once and read back by `not_loopback_only`.

Call `extension_problem()` at the top of `launch_burp` and raise `SessionError` if it returns a message — before spending ninety seconds on a handshake that cannot happen.

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_launch.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/session.py tests/test_session_launch.py
git commit -m "feat(session): launch Burp with the bridge extension"
```

---

## Task 4: loopback-only listeners, enforced

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_loopback.py`

**Interfaces:**
- Consumes: `PROXY_CONFIG` (Task 3).
- Produces: `_listening_sockets(pid: int) -> list[str]`; `_is_loopback(local: str) -> bool`; `not_loopback_only(pid: int, ports: list[int]) -> str | None`; `listener_ports(workdir: Path) -> list[int]`; `proxy_port(workdir: Path) -> int`; `second_proxy_port(workdir: Path) -> int`.

In the fixture this is a check a test consults. **In the product it is a refusal.** A consultant running against a client network needs a proxy that cannot be reached from that network far more than a test does. `demo_capture.py` already treats it as a refusal (`refusing to continue`); this makes that the product's behaviour rather than the demo's.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_session_loopback.py
"""Loopback-only listeners, and the config that asks for them.

Two facts live here because they are one control. `write_listener_config`
WRITES the request -- `listen_mode: loopback_only`, on two listeners that must
not be the same listener -- and `not_loopback_only` MEASURES what Burp
actually bound. Neither is worth anything without the other: the string is not
self-enforcing (changing it to `all_interfaces` once left the whole suite
green with the proxy bound to `*`), and the check has nothing to check if the
config never asked.

No JVM starts here. `_free_port` really binds, to `127.0.0.1:0`, and closes
the socket before it returns.
"""
import json

import pytest

from hx import session


def test_a_loopback_only_listener_passes(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["127.0.0.1:8080", "[::1]:8081"])
    assert session.not_loopback_only(1, [8080, 8081]) is None


def test_a_listener_on_all_interfaces_is_named(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["0.0.0.0:8080"])
    why = session.not_loopback_only(1, [8080])
    assert why and "8080" in why


def test_a_listener_on_a_routable_address_is_named(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["192.168.1.10:8080"])
    assert session.not_loopback_only(1, [8080]) is not None


# --- the config the listeners come from ----------------------------------


def _listeners(workdir):
    cfg = json.loads((workdir / session.PROXY_CONFIG).read_text())
    return cfg["proxy"]["request_listeners"]


def test_every_listener_asks_for_loopback_only(tmp_path):
    """The one string that decides where Burp binds, pinned in the FAST suite.

    Mutating it to `all_interfaces` left `pytest -q` completely green: 973
    passed, with the only witness the 210-second integration suite, which
    catches it through `ss` against a real Burp. `tests/test_session.py` writes
    the string into a fake config the product never produced, and
    `tests/test_burp_fixture.py` only asserts the word appears in a failure
    MESSAGE -- so nothing here read what `write_listener_config` actually
    wrote. It is product code in `src/` now, and a proxy listener on `0.0.0.0`
    is an open forward relay on whatever network the laptop is attached to.
    """
    session.write_listener_config(tmp_path)
    listeners = _listeners(tmp_path)
    assert len(listeners) == 2, (
        "a config naming only the second listener leaves the first wherever "
        "Burp's defaults put it, which is the 8080 _free_port() exists to avoid")
    assert [l["listen_mode"] for l in listeners] == ["loopback_only"] * 2
    assert all(l["running"] for l in listeners)


def test_the_operator_and_the_crawler_never_get_one_port(monkeypatch, tmp_path):
    """F2: two ephemeral binds in a row can return the same number.

    Measured at this call site: 4 collisions in 20 000 calls. Forced here
    rather than waited for -- `_free_port` hands back one repeat and then two
    distinct numbers, which is exactly the draw that used to be written
    straight into the config. `Source.forListenerPort` is `port == crawlerPort
    ? CRAWLER : OPERATOR`, so one port for both would give the consultant's
    own browsing the agent's rule set, and nothing downstream compares them.
    """
    draws = iter([41001, 41001, 41002, 41003])
    monkeypatch.setattr(session, "_free_port", lambda: next(draws))

    ports = session.write_listener_config(tmp_path)

    assert ports[0] != ports[1], "the collision was written into the config"
    assert ports == [41002, 41003], (
        "the colliding pair must be redrawn as a PAIR: keeping the first and "
        "redrawing only the second would hand back a port the kernel has "
        "already offered once")
    assert [l["listener_port"] for l in _listeners(tmp_path)] == ports


def test_a_draw_that_cannot_separate_them_is_fatal_not_silent(
        monkeypatch, tmp_path):
    """Never silent. `_free_port` here is stuck, and the session must not
    start at all rather than start with one listener serving both roles."""
    monkeypatch.setattr(session, "_free_port", lambda: 41001)

    with pytest.raises(session.SessionError) as exc:
        session.write_listener_config(tmp_path)
    assert "41001" in str(exc.value)
    assert "crawler" in str(exc.value)


def test_a_named_crawler_port_is_honoured_and_still_separated(
        monkeypatch, tmp_path):
    """`second_port` is the rig's way of pinning the crawler's listener.

    It must survive the redraw -- a caller that named a port and got another
    one back would have its `-Dhx.crawler_port` and its listener disagree --
    and the FIRST port is the one that moves when the two collide.
    """
    draws = iter([41001, 41002])
    monkeypatch.setattr(session, "_free_port", lambda: next(draws))

    ports = session.write_listener_config(tmp_path, 41001)

    assert ports == [41002, 41001]
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_loopback.py -v`
Expected: FAIL — attribute does not exist.

- [ ] **Step 3: Move them unchanged**

Move `_listening_sockets` (fixture 515), `_is_loopback` (530), `not_loopback_only` (558), `listener_ports` (679), `proxy_port` (691), `second_proxy_port` (702) into `src/hx/session.py` **verbatim, with their docstrings**. They are correct; only their home changes. Do not "improve" the parsing — it reads `/proc` and its edge cases were established against a real Burp.

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_loopback.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/session.py tests/test_session_loopback.py
git commit -m "feat(session): loopback-only listeners move into the product"
```

---

## Task 5: the configure body, and the scope hash that must not be recomputed

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_configure.py`

**Interfaces:**
- Consumes: `hx.config.Config`, `hx.bridge.codec.CONFIG_KEYS`.
- Produces: `METHOD_ALLOW: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")`; `config_body(cfg) -> dict[str, list[str]]`; `stored_scope_sha256(conn, engagement_id: str) -> str`.

**The rule this task exists for.** `engagement.py:120` records `scope_version.sha256 = sha256(yaml_text)`. `scripts/demo_capture.py:226` instead **recomputes** `sha256(config.dumps(cfg))`. They agree today and would diverge on a hand-edited `config.yaml`, a different key order, or an added comment — and since Plan 5's F4 fix the report renders `scope_version.sha256` as provenance for contract disputes. **Read the stored value; never recompute one.**

`limit.max_requests` is deliberately absent. `Limits.arm()` falls back to a `defaultMaxRequests` that `Distress.java` documents as 2000 per run, and §4 is explicit that the budget never binds the operator's browser — so its absence costs a browsing consultant nothing, and the plan that spends the budget is the plan that should bound it.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_session_configure.py
"""The configure body, and the scope hash it is authorised against.

Two things live here because they are one authorisation: `config_body`
builds the wire body `hx capture start` will hand to `bridge.configure()`,
and `stored_scope_sha256` supplies the hash that authorises it -- READ from
`scope_version`, never recomputed from today's `config.yaml`. See
`session.stored_scope_sha256`'s own docstring for why recomputing is the
failure this module exists to design out.
"""
import sqlite3
from types import SimpleNamespace

import pytest

from hx import config as config_mod
from hx import engagement as engagement_mod
from hx import session
from hx.bridge import codec
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir


# --- fixtures ----------------------------------------------------------


@pytest.fixture
def a_config() -> config_mod.Config:
    """A `Config` with every relevant field distinct from every other, so a
    test that reads the wrong attribute into the wrong key fails loudly
    instead of by coincidence passing."""
    return config_mod.Config(
        name="acme-2026-09",
        client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
        scope_exclude=["https://app.acme.com/logout*"],
        dangerous_paths=["*/purge*"],
        render_allow=["https://app.acme.com/*"],
        rate_limit_rps=7,
        max_concurrency=3,
    )


@pytest.fixture
def engagement(tmp_path):
    """A real, on-disk engagement -- the way `hx.engagement.create()` makes
    one, the same call `tests/test_engagement.py` drives directly. Its
    initial `scope_version` row is written atomically by `create()` itself,
    which is exactly the row `stored_scope_sha256` must read back.

    Yields `(conn, eng)`: `conn` is `eng.db`, pulled out separately so the
    tests read the way `tests/test_halt.py`'s `engagement` fixture does.
    """
    cfg = config_mod.Config(
        name="acme-2026-09", client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
    )
    eng = engagement_mod.create(tmp_path / "acme", cfg, author="jimx")
    yield eng.db, eng
    eng.db.close()


@pytest.fixture
def empty_engagement(tmp_path):
    """An engagement row with NO `scope_version` row at all -- the state
    `stored_scope_sha256` must refuse rather than silently pass through.

    Built by hand from the store primitives, the way `tests/test_halt.py`'s
    `test_a_store_with_no_engagement_row_is_refused` builds its own empty
    store: `hx.engagement.create()` always writes the engagement row and its
    scope_version row in one transaction, so there is no way to reach this
    state through that API. The gap is the point.
    """
    root = tmp_path / "empty"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','Example','Example Ltd',1,'active')")
    yield conn, SimpleNamespace(id="e-1", root=root)
    conn.close()


# --- config_body ---------------------------------------------------------


def test_the_body_uses_only_keys_the_codec_permits(a_config):
    assert set(session.config_body(a_config)) <= codec.CONFIG_KEYS


def test_every_config_field_reaches_its_key(a_config):
    body = session.config_body(a_config)
    assert body["scope.include"] == a_config.scope_include
    assert body["scope.exclude"] == a_config.scope_exclude
    assert body["dangerous.path"] == a_config.dangerous_paths
    assert body["render.allow"] == a_config.render_allow
    assert body["limit.rate_rps"] == [str(a_config.rate_limit_rps)]
    assert body["limit.concurrency"] == [str(a_config.max_concurrency)]
    assert body["method.allow"] == ["GET", "HEAD", "OPTIONS"]


def test_the_budget_key_is_absent(a_config):
    # Java's Limits.arm() falls back to its documented default of 2000, and
    # S4 says the budget never binds the operator's browser. The plan that
    # spends it is the plan that bounds it.
    assert "limit.max_requests" not in session.config_body(a_config)


# --- stored_scope_sha256 --------------------------------------------------


def test_the_scope_hash_is_read_from_the_store(engagement):
    conn, eng = engagement
    stored = conn.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC LIMIT 1", (eng.id,)).fetchone()[0]
    assert session.stored_scope_sha256(conn, eng.id) == stored


def test_a_hand_edited_comment_does_not_change_the_authorised_hash(engagement):
    """A weak but cheap check: appending a comment does not disturb the
    stored hash.

    NOT the test that distinguishes "read from the store" from "recompute
    from the file". `config.dumps()` is a canonical re-serialisation of the
    parsed `Config` -- comments and key order are discarded before hashing,
    so `dumps(load(x + "# comment"))` is byte-identical to `dumps(load(x))`.
    A recompute-from-config implementation passes this test too. See
    `test_a_field_edit_that_survives_reserialisation_does_not_change_the_authorised_hash`
    below for the one that actually pins "read, never recompute".
    """
    conn, eng = engagement
    before = session.stored_scope_sha256(conn, eng.id)
    (eng.root / "config.yaml").write_text(
        (eng.root / "config.yaml").read_text() + "\n# a comment\n")
    assert session.stored_scope_sha256(conn, eng.id) == before


def test_a_field_edit_that_survives_reserialisation_does_not_change_the_authorised_hash(engagement):
    """The failure this rule prevents, proved by a mutation that a
    recompute-from-config implementation cannot pass.

    Unlike a bare comment, `rate_limit_rps: 5 -> 10` SURVIVES a
    `config.load()` / `config.dumps()` round trip: it is a real field on the
    parsed `Config`, not discarded formatting. A `stored_scope_sha256` that
    read `engagement.config_path`, reloaded it and re-hashed `dumps(cfg)`
    would return a DIFFERENT hash here -- only a read of the stored
    `scope_version` row returns the same one recorded at `create()` time.

    If the session recomputed the hash from today's config, the report would
    render one hash as the authorised scope while the extension had been
    authorised against another -- and nothing would notice.
    """
    conn, eng = engagement
    before = session.stored_scope_sha256(conn, eng.id)
    config_path = eng.root / "config.yaml"
    text = config_path.read_text()
    assert "rate_limit_rps: 5" in text, "fixture assumption changed; edit no longer applies"
    config_path.write_text(text.replace("rate_limit_rps: 5", "rate_limit_rps: 10"))
    assert session.stored_scope_sha256(conn, eng.id) == before


def test_an_engagement_with_no_scope_version_is_an_error(empty_engagement):
    conn, eng = empty_engagement
    with pytest.raises(session.SessionError):
        session.stored_scope_sha256(conn, eng.id)


def test_the_latest_of_several_scope_versions_wins(engagement):
    """`ORDER BY effective_from_us DESC LIMIT 1`, actually exercised against
    more than one row.

    Follows `tests/test_engagement.py`'s use of
    `engagement.record_scope_version()` to append a second, real row rather
    than hand-inserting one -- that call is the only legitimate way a second
    `scope_version` row comes to exist, and it stamps `effective_from_us`
    itself (`engagement.now_us()`), so a hand-inserted row would either have
    to guess that or risk two rows landing at the same microsecond.
    """
    conn, eng = engagement
    first = session.stored_scope_sha256(conn, eng.id)

    eng.config.scope_include.append("https://api.acme.com/*")
    engagement_mod.record_scope_version(
        eng, author="jimx", reason="client added API host")

    second = session.stored_scope_sha256(conn, eng.id)
    assert second != first
    assert session.stored_scope_sha256(conn, eng.id) == second


def test_two_rows_at_one_microsecond_break_the_tie_the_report_breaks_it(engagement):
    """The one fact S5 says must not become two facts.

    `stored_scope_sha256` authorises the extension; `report._scope_of_record`
    renders the boundary a contract dispute is read off. They ordered
    differently -- `effective_from_us DESC LIMIT 1` here against
    `effective_from_us, rowid` there, taking the last -- so two rows stamped
    in the same microsecond let the extension be authorised against one row
    while the deliverable rendered the other, with nothing to notice.

    `record_scope_version` stamps `engagement.now_us()`, so the tie is
    possible rather than impossible; it is hand-inserted here because
    producing it through that API means winning a race with the clock. The
    assertion is not a hard-coded row: it is the report's OWN ordering,
    executed here, so the two cannot drift apart again without this failing.
    """
    conn, eng = engagement
    when, = conn.execute(
        "SELECT effective_from_us FROM scope_version WHERE engagement_id=?",
        (eng.id,)).fetchone()
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256,"
        " effective_from_us, author, reason)"
        " VALUES('sv-same-us', ?, 'name: later', 'b' * 64, ?, 'jimx',"
        " 'stamped in the same microsecond as the row before it')",
        (eng.id, when))

    boundary_of_record = conn.execute(
        "SELECT sv.sha256 FROM scope_version sv WHERE sv.engagement_id=?"
        " ORDER BY sv.effective_from_us, sv.rowid", (eng.id,)).fetchall()[-1][0]

    assert session.stored_scope_sha256(conn, eng.id) == boundary_of_record, (
        "the extension would be authorised against one scope_version row "
        "while the report renders another as the boundary of record")
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_configure.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'config_body'`.

- [ ] **Step 3: Write both**

```python
# src/hx/session.py -- Task 5: the configure body, and the scope hash it is authorised against
METHOD_ALLOW: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
"""S4's method allowlist, stated rather than defaulted.

`Policy.DEFAULT_METHODS` is these same three verbs, so sending them
explicitly widens nothing and says what the engagement authorised. `Config`
has no `method` key and this plan does not add one: an active_safe check is
idempotent by S10's own definition, and GET is what idempotent means.
"""


def config_body(cfg) -> dict[str, list[str]]:
    """The authorisation, built from the engagement's config.

    `limit.max_requests` IS DELIBERATELY ABSENT. `Limits.arm()` falls back to
    a documented default of 2000 per run, and S4 is explicit that the method
    allowlist, dangerous-path denylist, rate limit and budget "apply to the
    send path in full, and to crawler traffic in full. They do NOT apply to
    traffic from the operator's own browser." Nothing this plan starts spends
    the budget, so bounding it here would be a number with no referent.
    """
    return {
        "scope.include": list(cfg.scope_include),
        "scope.exclude": list(cfg.scope_exclude),
        "dangerous.path": list(cfg.dangerous_paths),
        "render.allow": list(cfg.render_allow),
        "method.allow": list(METHOD_ALLOW),
        "limit.rate_rps": [str(cfg.rate_limit_rps)],
        "limit.concurrency": [str(cfg.max_concurrency)],
    }


def stored_scope_sha256(conn, engagement_id: str) -> str:
    """The hash of the scope IN FORCE, read from `scope_version`.

    NEVER RECOMPUTED FROM TODAY'S CONFIG. `scope_version` is append-only and
    tamper-evident precisely so a contract dispute has one answer, and since
    Plan 5's F4 fix the report renders this column as the engagement's
    provenance. Recomputing would let the report show one hash as the
    authorised boundary while the extension had been authorised against
    another -- two facts that usually agree, which is the failure mode worth
    designing out rather than testing for.

    `, rowid DESC` IS THE SAME ARGUMENT ONE CLAUSE FURTHER DOWN. Without it
    this query breaks a tie on `effective_from_us` however SQLite happens to
    walk the table, while `report._scope_of_record` orders by
    `effective_from_us, rowid` and renders the LAST row as the boundary of
    record -- so two rows at the same microsecond let the extension be
    authorised against one row while the deliverable renders the other.
    `record_scope_version` stamps `engagement.now_us()` and the schema has no
    uniqueness constraint on the column, so that is possible rather than
    impossible; `engagement.open_` has spelled the tie-break this way since
    Plan 2 and this was the one place that had not.
    """
    row = conn.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC, rowid DESC LIMIT 1",
        (engagement_id,)).fetchone()
    if row is None:
        raise SessionError(
            f"engagement {engagement_id} has no scope_version row, so there is "
            "no recorded boundary to authorise the extension against")
    return row[0]
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_configure.py -v`
Expected: all pass.

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: `953 passed, 1 skipped, 30 deselected`.

- [ ] **Step 6: Commit**

```bash
git add src/hx/session.py tests/test_session_configure.py
git commit -m "feat(session): authorise from the scope hash the store recorded"
```

---

## Task 6: the session itself

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session.py`

**Interfaces:**
- Consumes: everything from Tasks 1-5; `hx.halt.OperatorHalt`, `hx.capture.Capture`, `hx.bridge.server.BridgeServer`, `hx.store.db.connect`, `hx.store.blobs.BlobStore`.
- Produces:
  - `ExchangeSink(root, engagement_id, config)` — callable `(header, request, response)`
  - `LiveSession` dataclass: `.operator_port: int`, `.crawler_port: int`, `.epoch: int`, `.bridge`, `.workdir: Path`
  - `session(eng, *, instance: str, jar: Path | None = None, workdir: Path | None = None)` — a context manager yielding `LiveSession`

**The trap this task must not fall into, quoted from `scripts/demo_capture.py:85`:**

> The bridge calls its exchange sink **ON THE READ THREAD**, and a sqlite connection belongs to the thread that opened it — so a `Capture` built over the main thread's connection raises `ProgrammingError` on every frame. The bridge catches everything the sink throws, by design (§4: a lost record changes what hx KNOWS, never what it ALLOWS), so the observable would be **a live Burp, traffic flowing, and an empty database.**

The sink therefore opens its own connection **lazily, on first call**, which is already on the read thread. `ExchangeSink` moves into the product for that reason: it is not demo scaffolding, it is the only correct way to hold this connection.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_session.py -- the sink, and every way the session can fail
def test_the_sink_opens_its_connection_on_the_calling_thread(tmp_path, an_engagement):
    """The failure this guards is silent: a live Burp and an empty database.

    A Capture built over the main thread's connection raises ProgrammingError
    on every frame, the bridge swallows it by design, and nothing surfaces.
    """
    sink = session.ExchangeSink(an_engagement.root, an_engagement.id,
                                an_engagement.config)
    assert sink._capture is None, (
        "constructing the sink must not open anything: the constructor runs "
        "on the main thread and the connection belongs to whoever opens it")
    errors = []

    def on_other_thread():
        try:
            sink({"id": "x-1", "method": "GET", "url": "https://a.test/",
                  "status": 200, "outcome": "ok"}, b"GET / HTTP/1.1\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\n\r\n")
        except Exception as exc:            # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=on_other_thread)
    t.start(); t.join()
    assert not errors, f"the sink raised off the main thread: {errors}"
    conn = db_mod.connect(an_engagement.root / "hx.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 1
    finally:
        conn.close()

    # The positive half of the same claim, and the one that distinguishes
    # "lazy" from "lucky". A row landing proves the write worked; it does not
    # prove WHICH thread owns the connection that wrote it. sqlite3 answers
    # that directly -- the connection the sink opened is affine to the thread
    # that opened it, so touching it from HERE, the main thread, is the very
    # ProgrammingError the whole class exists to keep off the read thread.
    with pytest.raises(sqlite3.ProgrammingError):
        sink._capture.conn.execute("SELECT COUNT(*) FROM exchange")


def test_one_connection_serves_both_callbacks(monkeypatch, an_engagement):
    """`on_exchange` and `on_halted` are ONE object over ONE connection.

    The bridge calls both on its read thread, so a second sink for the second
    callback opens a second connection -- "as thread-affine as the first with
    nothing making that obvious", as the integration rig's own comment puts
    it. Both would even work, here and against a real Burp, which is why this
    is measured by COUNTING the connections rather than by checking that the
    rows landed.

    The halted frame goes FIRST, before anything has opened anything: if
    `on_halted` did not open the connection itself it would raise, and if it
    opened a private one the count below would be two. It is then sent AGAIN
    after the exchange, and that second call must abort the run the exchange
    opened -- a no-op `[]` would mean the two callbacks were not looking at
    the same store.
    """
    opened, built = [], []
    real_connect, real_capture = db_mod.connect, session.capture_mod.Capture

    def counting_connect(path, **kw):
        opened.append(threading.get_ident())
        return real_connect(path, **kw)

    def counting_capture(*a, **kw):
        built.append(threading.get_ident())
        return real_capture(*a, **kw)

    monkeypatch.setattr(session.db_mod, "connect", counting_connect)
    monkeypatch.setattr(session.capture_mod, "Capture", counting_capture)

    sink = session.ExchangeSink(an_engagement.root, an_engagement.id,
                                an_engagement.config)
    distress = {"t": "halted", "reason": "five 500s", "host": "a.test",
                "window": "10s"}
    errors, aborted = [], []

    def on_read_thread():
        try:
            aborted.append(sink.on_halted(distress))
            sink({"id": "x-1", "method": "GET", "url": "https://a.test/",
                  "status": 200, "outcome": "ok"}, b"GET / HTTP/1.1\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\n\r\n")
            aborted.append(sink.on_halted(distress))
        except Exception as exc:            # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=on_read_thread)
    t.start(); t.join()

    assert not errors, f"the sink raised off the main thread: {errors}"
    assert opened == [t.ident], (
        "both callbacks must share ONE connection, opened on the read thread "
        f"by whichever arrived first; connections were opened by {opened} and "
        f"this thread is {threading.get_ident()}")
    assert built == [t.ident], (
        f"one Capture, built on the read thread; got {len(built)}")

    first, second = aborted
    assert first == [], (
        "a halted frame arriving when nothing is recording aborts nothing")
    assert second, (
        "the second halted frame did not abort the run the exchange opened, "
        "so the two callbacks are not looking at the same store")

    conn = real_connect(an_engagement.root / "hx.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 1
        status, stop_reason = conn.execute(
            "SELECT status, stop_reason FROM run WHERE id=?", (second[0],)
        ).fetchone()
    finally:
        conn.close()
    assert status == "aborted"
    assert stop_reason == "five 500s on a.test (10s)"


# --- the context manager -------------------------------------------------


def test_a_failed_configure_leaves_no_burp_running(monkeypatch, an_engagement, a_jar):
    """A session that looks alive and is at DENY-ALL is worse than none."""
    killed = []
    monkeypatch.setattr(session, "launch_burp", _launcher(killed))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure",
                        lambda self, *a, **k: (_ for _ in ()).throw(
                            server.BridgeError("bad_config")))
    with pytest.raises(session.SessionError) as exc:
        with session.session(an_engagement, instance="capture", jar=a_jar):
            pass
    assert killed, "configure failed and Burp was left running"
    # The peer's own words survive the wrapping. `session()` cannot tell a
    # refusal from a dead bridge, so its own message says only that the
    # extension was never authorised -- the class the extension named is the
    # half that says WHICH, and swallowing it sends the next reader to the
    # wrong side of the socket.
    assert "bad_config" in str(exc.value)
    assert not (an_engagement.root / "session" / "hx.sock").exists(), (
        "the bridge was not stopped: its socket outlives the session, and the "
        "next `session()` on this engagement dies inside BridgeServer.start()")


def test_listeners_that_are_not_loopback_only_refuse_the_session(
        monkeypatch, an_engagement, a_jar):
    """A bind that will never become loopback still refuses -- and the wait
    is set to zero so this costs the fast suite nothing.

    `LISTENER_BIND_TIMEOUT` is the product's, not this test's: waiting cannot
    turn a wildcard bind into a loopback one, so the 15 seconds a real session
    would spend here are spent AFTER the check has already found something.
    Zeroing it asks the same question in one `ss` call.
    """
    killed = []
    monkeypatch.setattr(session, "launch_burp", _launcher(killed))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "LISTENER_BIND_TIMEOUT", 0.0)
    monkeypatch.setattr(session, "not_loopback_only",
                        lambda pid, ports: "8080 is bound to 0.0.0.0")
    with pytest.raises(session.SessionError) as exc:
        with session.session(an_engagement, instance="capture", jar=a_jar):
            pass
    assert "0.0.0.0" in str(exc.value)
    assert killed, "a session that refused to continue left Burp running"


def test_a_listener_burp_has_not_bound_yet_is_waited_for(
        monkeypatch, an_engagement, a_jar):
    """F4: the product checked once where the rig polls for 15 seconds.

    The handshake says the extension LOADED. It says nothing about when Burp
    bound its proxy listeners, and `tests/integration/conftest.py` and
    `tests/integration/test_proxy_facts.py` have both wrapped this exact call
    in `wait_for(..., 15)` since Plan 4, with that reason written beside them.
    `session()` asked once -- so a Burp a moment behind was refused and torn
    down, and the rig was more robust than the product it certifies.

    The fake reports the unbound-port answer twice and then the truth, which
    is the sequence a slow bind produces. What is asserted is that the session
    reached its body at all; the call count is asserted too, so a
    `not_loopback_only` that stopped being consulted after the first answer
    could not pass this by never looking again.
    """
    answers = ["burp pid 4242 was configured to listen on [31337] and is not",
               "burp pid 4242 was configured to listen on [31337] and is not",
               None]
    asked = []

    def slowly_binding(pid, ports):
        asked.append(ports)
        return answers[min(len(asked), len(answers)) - 1]

    monkeypatch.setattr(session, "launch_burp", _launcher())
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "LISTENER_BIND_INTERVAL", 0.0)
    monkeypatch.setattr(session, "not_loopback_only", slowly_binding)
    monkeypatch.setattr(session.BridgeServer, "configure", lambda self, *a, **k: 1)

    with session.session(an_engagement, instance="capture", jar=a_jar) as live:
        assert (live.operator_port, live.crawler_port) == (
            OPERATOR_PORT, CRAWLER_PORT)

    assert len(asked) == 3, (
        f"the check was made {len(asked)} time(s); a session that asks once "
        "refuses a healthy Burp that had not bound yet")
    assert asked == [[OPERATOR_PORT, CRAWLER_PORT]] * 3, (
        "every poll must ask about BOTH configured listeners")


def test_burp_is_torn_down_when_the_body_raises(monkeypatch, an_engagement, a_jar):
    killed = []
    seen = []
    monkeypatch.setattr(session, "launch_burp", _launcher(killed))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure", lambda self, *a, **k: 1)
    with pytest.raises(ZeroDivisionError):
        with session.session(an_engagement, instance="capture",
                             jar=a_jar) as live:
            seen.append(live)
            1 / 0
    assert killed, "an exception in the body orphaned a Burp process"

    # The only place a LiveSession is ever yielded, so it is the only place
    # its fields can be read. The ports are asserted to be the ones the CONFIG
    # named: S4 tells the operator and the crawler apart by which listener a
    # request arrived on, so a session that reported the wrong number for
    # either would misattribute every request downstream of it.
    live, = seen
    assert (live.operator_port, live.crawler_port) == (OPERATOR_PORT, CRAWLER_PORT)
    assert live.epoch == 1
    assert live.workdir == an_engagement.root / "session"
    assert live.bridge.engagement_id == an_engagement.id
    assert not (live.workdir / "hx.sock").exists(), (
        "the bridge was not stopped on the raising path")

    # WHAT THE SESSION HANDED THE BRIDGE, by identity. Everything else in this
    # file measures what `session()` raises and what it kills, and a
    # `BridgeServer` built with `on_exchange=None` fails none of it: its own
    # `_capture` reads Plan 4's exchange, denial and dropped frames off the
    # socket and DISCARDS them, so the observable is a live Burp, correctly
    # configured, traffic flowing, an empty database and no error anywhere --
    # this plan's own bug, one layer out from the one `ExchangeSink` fixes.
    assert isinstance(live.bridge.on_exchange, session.ExchangeSink), (
        "the bridge was constructed without a sink, so every frame Burp sends "
        "is read and thrown away")
    assert live.bridge.on_halted is not None, (
        "S4's auto-halt frame has no writer again: `records.abort_run` is "
        "never called and an aborted run renders as a clean one")
    assert live.bridge.on_halted.__self__ is live.bridge.on_exchange, (
        "one object must serve both callbacks -- two would open two "
        "connections on the read thread, and both would work")
    assert live.bridge.on_exchange._root == an_engagement.root
    assert live.bridge.on_exchange._id == an_engagement.id


def test_a_handshake_that_never_completes_points_at_burps_log(
        monkeypatch, an_engagement, a_jar):
    killed = []
    monkeypatch.setattr(session, "launch_burp", _launcher(killed))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: False)
    with pytest.raises(session.SessionError) as exc:
        with session.session(an_engagement, instance="capture", jar=a_jar):
            pass
    assert "burp.log" in str(exc.value)
    assert killed, "a Burp that never dialled in was left running anyway"
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'ExchangeSink'`.

- [ ] **Step 3: Write the sink and the context manager**

```python
# src/hx/session.py -- Task 6: the session itself
@dataclass(frozen=True)
class LiveSession:
    """A Burp that is up, verified loopback-only, and authorised.

    `operator_port` and `crawler_port` are S4's two listeners and are NOT
    interchangeable: the operator's browsing and an agent's crawl are told
    apart by WHICH ONE a request arrived on and by nothing in the traffic, so
    a caller that dials the wrong one has silently swapped the two rule sets.
    Both are read back out of the config file Burp was handed.

    `epoch` is the config epoch the extension answered with. It is never 0
    here: 0 is what the extension reports at DENY-ALL, and a session that
    reached this object got a `configure` the extension accepted.

    `proc` is the JVM, and it is here so that a caller HOLDING this session
    open can find out it has stopped being one -- see `gone()`. It is not
    handed out for killing: teardown is `session()`'s, unconditionally, and a
    caller that kills the process itself gets a `finally` that kills it again.
    """

    operator_port: int
    crawler_port: int
    epoch: int
    bridge: object
    workdir: Path
    proc: subprocess.Popen

    def gone(self) -> str | None:
        """Why this is no longer a live session -- or None while it still is.

        S8 requires "Burp dies mid-session" to produce a distinct message and
        a non-zero exit, and nothing implemented it: `hx capture start` held
        the session open in `signal.pause()`, so a Burp that died left the
        command blocked forever, the browser getting connection-refused,
        nothing printed, and the run row `status='running'` until the operator
        gave up and pressed Ctrl-C -- at which point the exit code said
        "operator", because that is what Ctrl-C means everywhere else.

        TWO WAYS TO STOP BEING LIVE, and the second is not the first. A dead
        JVM is the obvious one. The other is a JVM that is still up while its
        extension has dropped the bridge: `BridgeServer._reset` puts the state
        back to `waiting` and the config epoch back to 0 when the peer goes
        away, so a reconnect lands at DENY-ALL -- a Burp that looks alive,
        proxies nothing, and records nothing. `configured` and `halted` are
        the two states a session in this object's hands is allowed to be in;
        `halted` is an operator halt, which is a live session that has stopped
        issuing, not a dead one.
        """
        code = self.proc.poll()
        if code is not None:
            return (f"Burp exited (status {code}) while the session was live, "
                    f"so nothing has been captured since. Its log is "
                    f"{self.workdir / 'burp.log'}")
        state = getattr(self.bridge, "state", None)
        if state not in ("configured", "halted"):
            return ("Burp's extension dropped the bridge connection (state is "
                    f"{state!r}); it reconnects at DENY-ALL, which refuses "
                    "everything, so this session is no longer capturing")
        return None


class ExchangeSink:
    """`hx.capture.Capture` on a connection owned by the thread that uses it.

    THE BRIDGE CALLS ITS SINK ON THE READ THREAD, and a sqlite connection
    belongs to the thread that opened it -- so a `Capture` built over the main
    thread's connection raises `ProgrammingError` on every frame. The bridge
    catches everything the sink throws, BY DESIGN (S4: a lost record changes
    what hx KNOWS, never what it ALLOWS), so the observable is not an error:
    it is a live Burp, traffic flowing, and an empty database.

    The connection is therefore opened LAZILY, on the first call, which is
    already on the read thread.

    ONE OBJECT SERVES BOTH CALLBACKS, and that is why this is a class and not
    two functions. `BridgeServer` calls `on_exchange` AND `on_halted` on that
    same read thread, and S4's auto-halt writer is `Capture.on_halted` -- so a
    separate sink for the second callback would open a SECOND connection,
    which would be (quoting `tests/integration/conftest.py`, which has wired
    it this way against a real Burp since Plan 4) "as thread-affine as the
    first with nothing making that obvious". Whichever callback arrives first
    opens the connection through `_lazy()`; both then share it, and a third
    callback added later belongs on this object for the same reason.

    ONE READ THREAD is what makes that safe, and it is `BridgeServer`'s
    guarantee rather than this class's: `_accept_loop` runs on a single thread
    and every callback comes from it. A second caller thread would get the
    ProgrammingError this class exists to avoid, which is why nothing but a
    bridge should hold one of these.

    IT IS NEVER CLOSED, and that is not an oversight. `Connection.close()` is
    thread-affine too, so closing it from the thread that BUILT the sink
    raises the very error the laziness exists to prevent, during teardown,
    where it would replace whatever actually went wrong. `srv.stop()` joins
    the read thread first, so nothing is still writing; the connection is
    released with the sink.
    """

    def __init__(self, root: Path, engagement_id: str, cfg) -> None:
        self._root, self._id, self._cfg = Path(root), engagement_id, cfg
        self._capture = None

    def _lazy(self) -> capture_mod.Capture:
        """The `Capture`, built once, on whichever thread calls first."""
        if self._capture is None:
            self._capture = capture_mod.Capture(
                db_mod.connect(self._root / "hx.db"),
                blobs_mod.BlobStore(self._root / "blobs"),
                engagement_id=self._id, config=self._cfg)
        return self._capture

    def __call__(self, header: dict, request: bytes, response: bytes) -> None:
        # `on_exchange`, not a call on the Capture itself: `hx.capture.Capture`
        # is a dataclass with no `__call__`, so calling it raises TypeError --
        # which the bridge would catch and count like any other sink failure,
        # leaving exactly the live-Burp-and-empty-database this class was
        # written to prevent, one layer further out.
        self._lazy().on_exchange(header, request, response)

    def on_halted(self, header: dict) -> list[str]:
        """S4's auto-halt, on the same connection and the same thread.

        Returns the run ids this frame aborted -- `[]` when nothing was
        recording -- and does not swallow them. `BridgeServer` ignores the
        value, but `records.abort_run` is the writer S5 reads when it refuses
        to render an aborted run as a clean one, and a wrapper that dropped
        the answer would make this the one place in the tree that cannot tell
        an abort from a no-op.
        """
        return self._lazy().on_halted(header)


@contextlib.contextmanager
def session(eng, *, instance: str, jar: Path | None = None,
            workdir: Path | None = None, seed: Path | None = None):
    """A live, configured Burp -- or nothing at all.

    EVERY EXIT TEARS BURP DOWN, including a refused `configure` and a raise
    from the body. The alternative to tearing down after a failed configure is
    a running Burp whose extension is at DENY-ALL: it looks like a working
    session and captures nothing.

    THE ORDER OF THE FIRST FOUR LINES IS THE CHEAPEST REFUSAL FIRST. Locating
    the jar and reading the authorised scope hash both fail against facts that
    are already true before anything is started, so they are settled before a
    socket is bound or a JVM is launched -- an engagement with no
    `scope_version` row can never be authorised, and starting a Burp to find
    that out leaves one to kill.

    `seed` IS FORWARDED TO `launch_burp` AND MEANS THE SAME THING THERE:
    omitted, the operator's own Burp home is the one copied, which is right
    for `hx capture start` and is why the CLI passes nothing. It exists here
    for the same reason `launch_burp` and `make_home` carry it -- "a caller
    that already knows the answer must be able to say so in code" -- and it
    is not hypothetical at this level. Task 9 gave `scripts/demo_capture.py`
    this context manager in place of its own assembly, and the demo GUARDS on
    `burp_fixture.missing()`, which reports on the LAB's curated home. Without
    a seed to pass, the demo would check one home and copy another: the
    operator's live `~/.BurpSuite/sessions`, real client project state on a
    consultant's machine. That is the exact disagreement Task 8 removed one
    layer down, and an environment variable set beside the call would be a
    second answer to a question this parameter already answers.
    """
    jar = find_burp_jar(jar)
    work = Path(workdir) if workdir else eng.root / "session"
    # secure_mkdir, not mkdir: this directory holds the private Burp home
    # (copied from the operator's own, licence key included), Burp's log, and
    # the bridge socket. It is created at 0o700 rather than created at the
    # umask and tightened afterwards -- `BridgeServer.start()` does chmod its
    # socket's parent, but only once it gets there.
    secure_mkdir(work)

    halt = halt_mod.OperatorHalt(eng.root, eng.db)
    # READ, never recomputed, and read HERE -- on the thread that owns
    # `eng.db`, before the bridge exists. See stored_scope_sha256.
    scope_sha256 = stored_scope_sha256(eng.db, eng.id)

    # ONE sink object for BOTH callbacks, so both run on one connection opened
    # on the read thread -- the shape `tests/integration/conftest.py` has used
    # against a real Burp since Plan 4, and the reason `ExchangeSink` owns
    # `on_halted` rather than leaving S4's auto-halt writer without a caller.
    sink = ExchangeSink(eng.root, eng.id, eng.config)
    sock = work / "hx.sock"
    srv = BridgeServer(sock, engagement_id=eng.id, operator_halt=halt,
                       on_exchange=sink, on_halted=sink.on_halted)
    try:
        srv.start()
    except Exception as exc:            # noqa: BLE001
        # INSIDE THE CONTRACT. `srv.start()` is the one step of this function
        # that a caller can reach without a `SessionError`, and its commonest
        # failure is one a killed session leaves behind: a stale `hx.sock`,
        # which `BridgeServer.start()` refuses "rather than adopt a path
        # another process may own". Raw, that is a `BridgeError` escaping a
        # module whose whole exception contract is `SessionError` with a
        # message naming the fix -- and the next caller is the CLI, which
        # would have to learn about bridge internals to print it, spreading
        # that knowledge outward to compensate for a promise made here.
        #
        # REPORTED, NEVER REMEDIATED. hx does not unlink the path: a socket
        # that is still live belongs to a session that is still RUNNING, and
        # silently removing another process's rendezvous is worse than any
        # error message. Nothing is cleaned up here either -- `srv.stop()`
        # would be the obvious reflex and it is exactly wrong, because it
        # unlinks `socket_path`, which in the case that brings us here is a
        # file this call did not create.
        raise SessionError(
            f"the bridge could not start on {sock}: {exc}. If no other hx "
            "session is running against this engagement, a previous one did "
            "not shut down cleanly -- remove that path by hand and try "
            "again. hx will not remove it for you: a live socket belongs to "
            "a session that is still running") from exc
    proc = None
    try:
        proc = launch_burp(sock, eng.id, work,
                           sentinel=halt.sentinel_path, jar=jar,
                           instance=instance, seed=seed)
        if not wait_for(lambda: srv.state == "connected"):
            raise SessionError(
                f"Burp never completed the bridge handshake. See "
                f"{work / 'burp.log'} -- the usual cause is an extension jar "
                "that is unbuilt or stale, and Burp starts happily without one")

        operator, crawler = proxy_port(work), second_proxy_port(work)
        why = _wait_until_loopback_only(proc.pid, [operator, crawler])
        if why:
            raise SessionError(f"refusing to continue: {why}")

        try:
            epoch = srv.configure(config_body(eng.config),
                                  scope_sha256=scope_sha256,
                                  profile=eng.config.safety_profile)
        except Exception as exc:            # noqa: BLE001
            # "configure failed and the extension was never authorised", NOT
            # "the extension refused the scope". Everything reaches here: a
            # peer that refused the body, a bridge that died mid-request, a
            # socket error. Naming the refusal sends an operator to the
            # client's boundary -- the one document a consultant cannot change
            # on their own -- when the truth may be that Burp went away. The
            # peer's own words are appended, so a genuine refusal still says
            # `peer refused configure: bad_config: ...`, and the half of the
            # message that IS true whatever happened is the state Burp is left
            # in: this is always the first configure of the session, so a
            # failure here means the extension is still at DENY-ALL.
            raise SessionError(
                f"configure failed and the extension was never "
                f"authorised: {exc}") from exc

        yield LiveSession(operator, crawler, epoch, srv, work, proc)
    finally:
        # Nested, so that `srv.stop()` runs even if killing Burp raises. The
        # guarantee this function makes is that nothing is left running, and a
        # teardown where one half can cancel the other does not make it.
        try:
            if proc is not None:
                proc.kill()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=15)
        finally:
            try:
                srv.stop()
            finally:
                # THE COPIED HOME DOES NOT OUTLIVE THE SESSION. It holds the
                # operator's licence prefs and everything in their
                # `~/.BurpSuite` bar the browser -- real client project state
                # on a consultant's machine -- and `work` is inside the
                # engagement directory, which is the thing a consultant
                # archives or hands to a client. Burp's log stays: it is the
                # evidence a failed session is diagnosed from, and it is this
                # side's, not the previous client's.
                #
                # ignore_errors, and only here: a directory that will not
                # delete must not replace whatever actually went wrong on the
                # way out, and `make_home` removes it before the next copy
                # anyway -- so the failure mode is a stale tree until the next
                # run, not a session that cannot start.
                shutil.rmtree(work / "burphome", ignore_errors=True)
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session.py -v`
Expected: all pass.

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: `958 passed, 1 skipped, 30 deselected`.

- [ ] **Step 6: Commit**

```bash
git add src/hx/session.py tests/test_session.py
git commit -m "feat(session): one context manager that always tears Burp down"
```

---

## Task 7: `hx capture start` brings Burp up

**Files:**
- Modify: `src/hx/cli.py:214-238`
- Test: `tests/test_cli_capture.py`

**Interfaces:**
- Consumes: `session.session`, `session.SessionError`, `session.LiveSession`.
- Produces: `hx capture start [--kind] [--root] [--burp-jar]`, which launches Burp, prints the operator proxy port, opens the run, and blocks until interrupted.

Today this command opens a `run` row and prints one line. It never starts Burp, so a consultant who runs it and browses records nothing.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli_capture.py -- Task 7's own tests
def test_capture_start_reports_the_port_to_browse_through(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session",
                        _fake_session(operator_port=18080))
    monkeypatch.setattr(cli, "_block_until_interrupt", lambda live: None)
    result = CliRunner().invoke(cli.main, ["capture", "start",
                                           "--root", str(an_engagement.root)])
    assert result.exit_code == 0, result.output
    assert "18080" in result.output, (
        "the operator cannot browse through a proxy whose port they were "
        "never told")


def test_ctrl_c_closes_the_run(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())
    def interrupt(live):
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_cli_capture.py -v`
Expected: FAIL — the command never opens a session.

- [ ] **Step 3: Rewrite the command**

Keep `current_run` and its "typing start twice resumes the one live run" behaviour. Wrap it in a session, print the operator port, block, and close the run on exit. Add `--burp-jar` (a `click.Path`) passed through to `session.session`.

```python
# src/hx/cli.py -- capture start's wait, and the SIGTERM that must not orphan Burp
# How often `capture start` asks whether the session it is holding open is
# still a session. A second is far below anything a human notices and far
# above anything the check costs: `Popen.poll()` is a non-blocking waitpid and
# the bridge state is an attribute read.
_HEALTH_POLL_S = 1.0


def _block_until_interrupt(live) -> str | None:
    """Hold the session open until the operator interrupts -- or Burp dies.

    Returns None when the wait ended the way it usually does (Ctrl-C, which
    arrives as a KeyboardInterrupt out of `time.sleep`), or the reason the
    session stopped being one.

    NOT `signal.pause()` ANY MORE, and that is S8's "Burp dies mid-session"
    path. Paused, a command whose Burp had died blocked forever: the browser
    got connection-refused, nothing was printed, and the run row stayed
    `status='running'` until the operator gave up and pressed Ctrl-C, which
    then closed the run as though they had ended it on purpose. Nothing polled
    `proc.poll()` or re-read the bridge state, so the only witness was the
    consultant noticing their proxy had stopped answering.

    Separate so a test can drive the command without a real signal.
    """
    while True:
        why = live.gone()
        if why is not None:
            return why
        time.sleep(_HEALTH_POLL_S)


@contextlib.contextmanager
def _sigterm_ends_the_session():
    """SIGTERM tears Burp down instead of orphaning it.

    S7: "A Burp process is never orphaned." `capture_start` covered Ctrl-C and
    exceptions, and SIGTERM -- a `kill`, a terminal closing, a service manager
    stopping the unit -- killed the command where it stood, leaving a 900 MB
    JVM and a bridge socket behind. The next run then got the (good) stale
    socket refusal naming the path to remove.

    Raised as KeyboardInterrupt deliberately: a SIGTERM is somebody stopping
    this command, which is what Ctrl-C is, and giving the two paths one
    meaning keeps one teardown and one `stop_reason` rather than two that have
    to agree. The previous handler is restored on the way out, and a
    non-main-thread caller (where `signal.signal` raises) simply does not get
    the handler -- an inability to install one must not stop the session.
    """
    def handler(signum, frame):
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except ValueError:
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)
```

The command body: open the session first, then the run — a run row opened before a session that fails to start is a run that never captured anything. `SessionError` becomes `click.ClickException`. On exit, close the run with `run_mod.close_run`, inside a `finally`.

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_cli_capture.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/cli.py tests/test_cli_capture.py
git commit -m "feat(cli): capture start brings Burp up and holds it"
```

---

## Task 8: the rig uses the product's session

**Files:**
- Modify: `tests/integration/burp_fixture.py`, `tests/integration/conftest.py`
- Test: the existing 30 integration tests are the test.

**Interfaces:**
- Consumes: everything in `hx.session`.
- Produces: no new interface. `burp_fixture` re-exports the promoted names from `hx.session` so existing imports keep working.

**This is the highest-risk task in the plan and the one that gives it its point.** Thirty integration tests depend on this fixture. Until now the code a consultant runs and the code under test were different code; after this they are the same. `conftest.py`'s own comment already names the hazard: *"a config body spelled anywhere else is a second spelling free to drift from this one."* There have been three spellings and none of them shipped.

- [ ] **Step 1: Record the baseline before touching anything**

Run: `.venv/bin/pytest -m integration -q`
Expected: `30 passed`. Write the exact line into your report — it is what "no regression" means here.

- [ ] **Step 2: Re-export from the product instead of defining**

In `tests/integration/burp_fixture.py`, delete the promoted definitions and import them:

```python
# tests/integration/burp_fixture.py -- what the rig re-exports from the product
from hx import session
from hx.session import (          # noqa: F401  -- re-exported for the rig
    ADD_OPENS,
    EXT_JAR,
    EXT_SRC,
    PROXY_CONFIG,
    SessionError,
    _free_port,
    _is_loopback,
    _jar_mtime,
    _listening_sockets,
    _newest_source_mtime,
    extension_problem,
    find_burp_jar,
    listener_ports,
    make_home,
    not_loopback_only,
    proxy_port,
    second_proxy_port,
    seed_home,
    wait_for,
    write_listener_config,
)
```

**Keep in the fixture**, because they are genuinely test-only: `missing`, `unbuilt`, `_environment_missing`, `_environment_missing_unguarded`, `_missing`, `burp_available`, and the whole `Probe.java` section (`PROBE_SRC`, `PROBE_CLASS`, `probe_missing`, `probe_source_missing`, `_compile_probe`, `launch_probe`).

`launch_burp` now requires `jar` and `instance`. The fixture supplies `jar=find_burp_jar()` and `instance="integration"`, so the rig keeps identifying itself as the rig.

`BURP_JAR` was a module constant several call sites read. Replace it with a module-level `BURP_JAR = find_burp_jar()` **inside a try/except that leaves it `None`** — `missing()` must still be able to report a missing jar rather than raising at import and turning the whole run into a collection error. That exact failure mode has happened here before, via `_eula_accepted` raising `UnicodeDecodeError` at import time.

- [ ] **Step 3: Run the integration suite**

Run: `.venv/bin/pytest -m integration -q`
Expected: `30 passed`.

If a test fails, read it before changing it. A test that broke because the product's session differs from the rig's is telling you the product is wrong, not the test.

- [ ] **Step 4: Point the rig's config body at the product's**

`conftest.py`'s `build_config_body` becomes a thin wrapper over `session.config_body(cfg)`, adding only what the rig genuinely needs beyond it: `limit.max_requests` (the rig tests budget exhaustion, which the product omits) and the `rate_rps` override that exists for one test — the one pushing a second `configure` with a different rate and expecting `bad_config`. Keep both docstrings explaining why they are overrides rather than the default.

- [ ] **Step 5: Run both suites**

Run: `.venv/bin/pytest -q && .venv/bin/pytest -m integration -q`
Expected: `961 passed, 1 skipped, 30 deselected` and `30 passed`.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/burp_fixture.py tests/integration/conftest.py
git commit -m "refactor(tests): the rig drives the product's session"
```

---

## Task 9: the demo uses the product's session, and the whole thing is verified end to end

**Files:**
- Modify: `scripts/demo_capture.py`
- Test: `tests/integration/test_cli_session.py` (create)

**Interfaces:**
- Consumes: `hx.session.session`, `hx.session.ExchangeSink`.
- Produces: nothing new.

- [ ] **Step 1: Replace the demo's hand-rolled session**

Delete the demo's `Sink` class (line 85) and its inline assembly (lines ~195-236): the `OperatorHalt`, `BridgeServer`, `launch_burp`, `wait_for`, `not_loopback_only` and `configure` block all become one `with session.session(eng, instance="demo") as live:`.

**Keep the demo's narration** — the `did(...)` and `saw(...)` lines are the point of the script. Keep its deliberately-broken-sink demonstration (step 6 flips `failing`), which now subclasses `ExchangeSink` rather than reimplementing it: the demonstration is that the bridge keeps the exception and the browser does not notice, and that is worth keeping.

**The demo's hand-computed `scope_sha256` goes.** It recomputed `sha256(config.dumps(cfg))` where the session now reads the stored value — the exact divergence Task 5 exists to prevent.

- [ ] **Step 2: Run the demo against a real Burp**

Run: `.venv/bin/python scripts/demo_capture.py`
Expected: it completes with the same narration as before, and the config epoch line still prints.

- [ ] **Step 3: Write the end-to-end integration test**

```python
# tests/integration/test_cli_session.py -- Task 9: the command an operator types
def test_capture_start_records_what_the_operator_browses(tmp_path):
    """The whole point of this plan, in one test.

    Before it, `hx capture start` opened a database row and nothing else: a
    consultant could run it, browse, and record nothing, because the
    extension defaults to DENY-ALL and nothing in the product ever
    configured it. Every assertion below is about the OPERATOR's path --
    the command they type, the port it prints, the browser they point at it,
    the row they get -- and none of it touches the rig.
    """
    with contextlib.ExitStack() as stack:
        target = TargetServer("127.0.0.1")
        stack.callback(target.stop)
        target.start()
        eng = _engagement(stack, tmp_path, scope=f"{target.origin}/*")

        assert HX.is_file(), (
            f"{HX} is not there. It is the console script `pyproject.toml` "
            "installs and the thing an operator runs; this test drives the "
            "command, not the function behind it. `pip install -e .`")

        # Output to a FILE, never a pipe, for the reason `launch_burp` gives
        # about Burp's own: an unread pipe deadlocks the writer once its
        # buffer fills, and a file is also what a failing assertion below can
        # quote back.
        out = tmp_path / "capture-start.out"
        log = out.open("wb")
        stack.callback(log.close)
        # TWO ENTRIES, AND THE SECOND IS THE GUARD ON THE FIRST.
        # `HX_BURP_SEED_HOME` is what makes the subprocess copy the LAB's home
        # rather than the operator's -- `hx capture start` has no seed option
        # and must not grow one for a test. On its own it was the only thing
        # between a real Burp and a consultant's real `$HOME`, and DELETING IT
        # WAS SILENTLY GREEN: this machine's `$HOME` has an accepted EULA, so
        # the run succeeds, copies `~/.java` and `~/.BurpSuite` -- real client
        # project state -- into `tmp_path`, and reports 32 passed.
        #
        # `HOME` pointed at a directory that does not exist turns that silence
        # into a refusal: without the seed variable, `make_home` falls back to
        # `Path.home()` and `_eula_accepted` says no, so the command exits
        # before launching anything and this test fails naming the fake home.
        # Nothing else in `hx capture start` reads `HOME` -- `--root` and
        # `--burp-jar` are both explicit above, so `default_root()` is bypassed
        # and `DEFAULT_LAB` is unused.
        env = dict(os.environ, HX_BURP_SEED_HOME=str(bf.SEED_HOME),
                   HOME=str(tmp_path / "not-a-home"))
        proc = subprocess.Popen(
            [str(HX), "capture", "start", "--kind", "browse",
             "--root", str(eng.root),
             # Explicit, so this test never depends on how many jars are in
             # the operator's lab: `find_burp_jar` treats two as an error
             # rather than a guess, and that error would surface here as a
             # command that exits before printing anything.
             "--burp-jar", str(bf.BURP_JAR)],
            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            env=env, start_new_session=True)
        # READ, not assumed to be `proc.pid`. It is that today --
        # `start_new_session=True` makes the command a group leader -- and
        # reading it means the teardown and the survivor check below are
        # asking the kernel which group this command is actually in.
        pgid = os.getpgid(proc.pid)
        stack.callback(_terminate, proc, pgid)

        def said(pattern):
            found = pattern.search(out.read_text(errors="replace"))
            return found.group(1) if found else None

        # ~15 s on this machine: a private Burp home is copied, a JVM starts,
        # the extension dials in and the configure is answered before the
        # command prints a thing.
        #
        # THE EXIT IS PART OF THE PREDICATE. Polling stdout alone made every
        # way this command can die IMMEDIATELY -- a jar it cannot find, a
        # stale bridge socket, a seed home with no accepted EULA, all of
        # which `session()` reports and exits on in under a second -- cost the
        # full two minutes before failing, when `proc.poll()` already knew.
        assert bf.wait_for(
            lambda: said(RUN_LINE) is not None or proc.poll() is not None,
            120), (
            "`hx capture start` neither reported a live run nor exited within "
            "120s. It printed:\n" + out.read_text(errors="replace"))
        if said(RUN_LINE) is None:
            pytest.fail(
                f"`hx capture start` exited {proc.returncode} before reporting "
                "a live run. It printed:\n"
                + out.read_text(errors="replace"))
        port = int(said(PORT_LINE))
        run_id = said(RUN_LINE)

        # THE BROWSE. A forward-proxy request through the port the command
        # printed -- the one thing this plan added to that command, and the
        # one an operator's browser would send.
        raw = browse_through(port, "GET", f"{target.origin}/api/orders",
                             host=f"{target.host}:{target.port}")
        assert raw.startswith(b"HTTP/"), (
            f"nothing came back through the operator listener :{port}; got "
            f"{raw[:80]!r}")

        def rows():
            return eng.db.execute(
                "SELECT method, url, via, run_id, status FROM exchange"
            ).fetchall()

        _settle(lambda: len(rows()) >= 1, "the exchange row",
                evidence=lambda: (
                    f"`hx capture start` said:\n{out.read_text(errors='replace')}\n"
                    f"Burp's log: {eng.root / 'session' / 'burp.log'}\n"
                    f"the target received "
                    f"{[(h.method, h.path) for h in target.hits]}"))

        # The TARGET's own log, which is the one witness nothing on this side
        # can fake: the request was delivered, not merely answered by Burp.
        assert [(h.method, h.path) for h in target.hits] == [("GET", "/api/orders")]

        got = rows()
        assert len(got) == 1, got
        method, url, via, row_run, status = got[0]
        assert (method, url) == ("GET", f"{target.origin}/api/orders")
        assert via == "proxy", "the operator's browsing arrives on the proxy path"
        assert status == 200
        # ONE SESSION, NOT TWO THINGS RUNNING. The run row `capture start`
        # opened and printed is the row the captured exchange is attributed
        # to -- `Capture` resolves an operator frame through the same
        # `run.current_run(kind='browse')` the command used, so a session
        # whose capture opened a run of its own would show up here as a
        # different id rather than as a missing row.
        assert row_run == run_id

        # Ctrl-C, which is how an operator ends it. The run must be closed by
        # the command's own `finally`: a row left `status='running'` after the
        # operator's Burp is gone reads as a live capture forever.
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=90)
        status, stop_reason = eng.db.execute(
            "SELECT status, stop_reason FROM run WHERE id=?", (run_id,)).fetchone()
        assert (status, stop_reason) == ("completed", "operator")

        # HOW IT EXITED. 1 is Ctrl-C reaching a click command: the
        # KeyboardInterrupt raised out of the health-poll's `time.sleep`
        # unwinds the run-closing `finally`, click turns it into `Abort`, and
        # `Abort` is `sys.exit(1)`.
        # Pinned because the row above is written on the way out of a command
        # that could also have DIED -- and a crash after `close_run` leaves
        # exactly the row this test just read.
        assert proc.returncode == 1, (
            f"`hx capture start` exited {proc.returncode} on Ctrl-C, not 1. It "
            "printed:\n" + out.read_text(errors="replace"))

        # AND NOTHING IT STARTED OUTLIVED IT. Every assertion above is
        # satisfied BEFORE `session()` tears Burp down, so a regression in
        # that teardown -- anything raising between `close_run` and
        # `proc.kill()` / `srv.stop()` -- would orphan a 900 MB JVM while this
        # test reported green. `session()`'s whole contract is that every exit
        # tears Burp down; this is the only place in the repository that
        # measures it against a real JVM rather than a fake `kill()`.
        survivors = _group_survivors(pgid)
        assert not survivors, (
            "`hx capture start` exited and left these processes behind:\n  "
            + "\n  ".join(survivors)
            + f"\nIt printed:\n{out.read_text(errors='replace')}")
```

- [ ] **Step 4: Run everything**

```bash
.venv/bin/pytest -q
.venv/bin/pytest -m integration -q
./extension/test.sh 2>&1 | tail -3
```

Expected: `961 passed, 1 skipped, 30 deselected`; `32 passed`; and for Java `13 ALL PASS` with **2352 output lines and 2330 `ok`** — check the line count, not just rc.

- [ ] **Step 5: Commit**

```bash
git add scripts/demo_capture.py tests/integration/test_cli_session.py
git commit -m "refactor(demo): the demo drives the product's session"
```
