"""Standing up a live, configured Burp — and taking it down again.

hx NEVER BUNDLES OR REDISTRIBUTES BURP. This module locates a jar the
operator already has, launches it with the bridge extension, and authorises
it. Nothing here ships Burp and nothing here may.

WHY THIS MODULE EXISTS AT ALL: until it did, nothing in `src/` called
`bridge.configure()`. `hx capture start` opened a database row and stopped
there, while `scripts/demo_capture.py` and `tests/integration/` each stood up
their own session -- so capture worked in a demo and not from the CLI, and an
active check had nowhere to send. The extension defaults to DENY-ALL, so an
unconfigured extension refuses everything.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

JAR_GLOB = "burpsuite_desktop_v*.jar"
DEFAULT_LAB = Path.home() / "F0RT1KA" / "burp-lab"
EXT_JAR = Path(__file__).resolve().parents[2] / "extension" / "build" / "hx-bridge.jar"
EXT_SRC = Path(__file__).resolve().parents[2] / "extension" / "src"


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


def _jar_is_stale() -> bool:
    """True when any extension source is newer than the jar built from it.

    Nothing in the suite runs build.sh and the jar is gitignored, so an edit
    to BridgeClient.java without a rebuild leaves `-m integration` reporting
    2 passed while certifying this plan's central claim against an artifact
    that no longer matches the code. mtime is a coarse signal, and it errs in
    the safe direction: a touched but unchanged source skips the run with a
    reason that names the fix, rather than passing it silently.
    """
    try:
        return _newest_source_mtime() > _jar_mtime()
    except OSError:
        # A missing jar is the caller's row, not ours. The broader catch is
        # the lesson from _eula_accepted() above: anything raised out of
        # missing() is not a skip, it is a collection error for the entire
        # repository. A source that vanishes between the glob and the stat --
        # a rebuild or a checkout running alongside the suite -- is no
        # evidence that the jar is stale, so say nothing and let the run go.
        return False


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


def make_home(workdir: Path) -> Path:
    """A private $HOME per run.

    Sharing one Burp home across runs means sharing a Java Preferences lock and
    a sessions directory with any other Burp on the machine -- including one a
    developer left running. The prefs are 3 MB and cheap to copy; the embedded
    browser is 650 MB, read-mostly, and gets a symlink instead.

    The seed is COPIED FROM, never run against -- see seed_home(). A seed
    that never accepted Burp's licence sits at the licence prompt and never
    dials in, which without this check surfaces as a bare 90-second handshake
    timeout; checked here, before the copy, so it is reported instead.
    """
    seed = seed_home()
    if not _eula_accepted(seed):
        raise SessionError(
            f"{seed} has not accepted the Burp Suite licence. Run Burp by "
            "hand from that home once and accept it there -- hx copies this "
            "home, it does not run against it, and cannot accept the "
            "licence on your behalf")
    home = workdir / "burphome"
    (home / ".BurpSuite").mkdir(parents=True)
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
