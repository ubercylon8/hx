"""Launch a real headless Burp Suite Community with the hx extension loaded.

Everything here was established empirically, most of it the hard way:
  - Burp asks for a licence key on stdin; a bare newline selects Community.
  - The EULA gate is a single Java Preferences key, burp.eula.
  - Launching with -cp instead of -jar means the jar manifest's Add-Opens is
    ignored, so every --add-opens must be repeated on the command line.
  - Burp throws `java.lang.Error: no ComponentUI class` twice while building a
    Swing UI it cannot have under -Djava.awt.headless=true. This is NOISE. A
    known-good instance logs it identically and runs for hours. Do not chase it.
  - api.logging().logToOutput() does NOT reach the process stdout. You cannot
    detect that the extension loaded by reading the log -- observe the bridge
    instead. `hello` arriving IS the readiness signal.
  - Startup to hello measured at ~5s, not the ~40s originally assumed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

LAB = Path(os.environ.get("HX_BURP_LAB", Path.home() / "F0RT1KA" / "burp-lab"))
BURP_JAR = LAB / "burpsuite_desktop_v2026.7.3.jar"
SEED_HOME = LAB / "burphome"          # copied from, never run against
EXT_JAR = Path(__file__).resolve().parents[2] / "extension" / "build" / "hx-bridge.jar"
EXT_SRC = Path(__file__).resolve().parents[2] / "extension" / "src"

ADD_OPENS = [
    "--add-opens", "java.base/java.lang=ALL-UNNAMED",
    "--add-opens", "java.desktop/javax.swing=ALL-UNNAMED",
    "--add-opens", "java.desktop/java.awt=ALL-UNNAMED",
    "--add-opens", "java.desktop/java.awt.color=ALL-UNNAMED",
    "--add-opens", "java.base/javax.crypto=ALL-UNNAMED",
    "--add-opens", "jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
]


def missing() -> list[str]:
    """Which prerequisites are absent, for a skip reason that names them.

    A bare False here once sent a debugger into a Burp stack trace when the
    real problem was an unbuilt extension jar: Burp starts happily with a
    classpath entry that does not exist, loads no extension, and never dials
    in. Say which path is missing.

    NOTHING may raise out of this function. It runs at import time, so an
    exception here is not a skipped test -- it is `Interrupted: 1 error during
    collection` for the entire repository, fast suite included. That has now
    happened twice, both times from code added to make this function safer:
    once from a UnicodeDecodeError reading a torn prefs.xml, once from a
    dangling symlink under the source tree.

    The individual checks are not enough on their own. Path.exists() and
    Path.is_dir() swallow only a narrow errno whitelist -- ENOENT, ENOTDIR,
    EBADF, ELOOP -- so EACCES, ESTALE and ENOTCONN still propagate. A
    permission-tightened lab directory, a CI runner under another uid, or a
    stale NFS mount is enough. Reproduced directly:

        PermissionError [Errno 13] ... burpsuite_desktop_v2026.7.3.jar

    So the whole body is wrapped, and an unreadable prerequisite is reported
    as a missing one.
    """
    try:
        return _missing()
    except OSError as exc:
        return [f"prerequisites under {LAB} could not be checked: {exc}"]


def _missing() -> list[str]:
    absent = []
    if not BURP_JAR.exists():
        absent.append(f"burp jar: {BURP_JAR}")
    if not EXT_JAR.exists():
        absent.append(f"extension jar (run extension/build.sh): {EXT_JAR}")
    elif (newest := _newest_source_mtime()) > time.time() + 60:
        # A future timestamp is a broken clock, not a stale jar, and treating
        # it as staleness disables the integration suite PERMANENTLY: no
        # rebuild can stamp the jar later than a source dated years ahead.
        # Reproduced -- two honest rebuilds, still reported stale both times.
        absent.append(
            f"a source under {EXT_SRC} is dated in the future "
            f"({newest - time.time():.0f}s ahead); fix the clock or re-touch it"
        )
    elif newest > _jar_mtime():
        absent.append("extension jar is older than its sources (run extension/build.sh)")
    if not (SEED_HOME / ".java").is_dir():
        absent.append(f"seed burp home: {SEED_HOME / '.java'}")
    elif not _eula_accepted():
        # Checked because the failure mode is silence: Burp waits at the EULA
        # gate forever and the test times out with nothing in the log to say
        # why. The pref lives in the seed home, so a cleared or regenerated
        # home takes it with it.
        absent.append(f"burp.eula not accepted in {SEED_HOME / '.java'}")
    if not (SEED_HOME / ".BurpSuite").is_dir():
        # make_home() copies this tree as well as .java. Checking only .java
        # let burp_available() return True and the launch then die on a
        # FileNotFoundError halfway through the copy -- reproduced -- which is
        # precisely the unnamed failure this function exists to prevent.
        absent.append(f"seed burp home: {SEED_HOME / '.BurpSuite'}")
    return absent


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


def _eula_accepted() -> bool:
    prefs = SEED_HOME / ".java" / ".userPrefs" / "burp" / "prefs.xml"
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


def burp_available() -> bool:
    return not missing()


def make_home(workdir: Path) -> Path:
    """A private $HOME per run.

    Sharing one Burp home across runs means sharing a Java Preferences lock and
    a sessions directory with any other Burp on the machine -- including one a
    developer left running. The prefs are 3 MB and cheap to copy; the embedded
    browser is 650 MB, read-mostly, and gets a symlink instead.
    """
    home = workdir / "burphome"
    (home / ".BurpSuite").mkdir(parents=True)
    shutil.copytree(SEED_HOME / ".java", home / ".java")
    for lock in (home / ".java" / ".userPrefs").glob(".user*"):
        lock.unlink()                 # a copied lock file belongs to the seed
    for entry in (SEED_HOME / ".BurpSuite").iterdir():
        target = home / ".BurpSuite" / entry.name
        if entry.name == "burpbrowser":
            target.symlink_to(entry)
        elif entry.is_dir():
            shutil.copytree(entry, target)
        else:
            shutil.copy2(entry, target)
    return home


def launch_burp(socket_path: Path, engagement_id: str, workdir: Path,
                sentinel: Path) -> subprocess.Popen:
    """Burp's output goes to workdir/burp.log, never to a pipe.

    An unread subprocess.PIPE is a latent deadlock -- Burp blocks once the pipe
    buffer fills and the test hangs with no diagnostic. A file also means a
    failing test can quote what Burp actually said.
    """
    home = make_home(workdir)
    log = (workdir / "burp.log").open("wb")
    cmd = [
        "java",
        "-Djava.awt.headless=true",
        f"-Duser.home={home}",
        f"-Dhx.socket={socket_path}",
        f"-Dhx.engagement={engagement_id}",
        "-Dhx.instance=integration",
        # Required, not optional: HxExtension.initialize() returns early
        # ("extension idle") without it, so the extension never dials and the
        # handshake never happens. Task 6 made it mandatory and this fixture
        # was not updated -- the integration tests are deselected from the
        # default run, so nothing said so for a day.
        f"-Dhx.halt_sentinel={sentinel}",
        *ADD_OPENS,
        "-cp", f"{BURP_JAR}:{EXT_JAR}",
        "burp.StartBurp",
        "--developer-extension-class-name=hx.HxExtension",
        "--disable-auto-update",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, cwd=LAB)
    proc.stdin.write(b"\n\n")     # bare newline selects Community Edition
    proc.stdin.flush()
    return proc


def wait_for(predicate, timeout: float = 90.0, interval: float = 0.5) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(interval)
    return False
