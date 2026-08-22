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
    """
    absent = []
    if not BURP_JAR.exists():
        absent.append(f"burp jar: {BURP_JAR}")
    if not EXT_JAR.exists():
        absent.append(f"extension jar (run extension/build.sh): {EXT_JAR}")
    if not (SEED_HOME / ".java").is_dir():
        absent.append(f"seed burp home: {SEED_HOME / '.java'}")
    elif not _eula_accepted():
        # Checked because the failure mode is silence: Burp waits at the EULA
        # gate forever and the test times out with nothing in the log to say
        # why. The pref lives in the seed home, so a cleared or regenerated
        # home takes it with it.
        absent.append(f"burp.eula not accepted in {SEED_HOME / '.java'}")
    return absent


def _eula_accepted() -> bool:
    prefs = SEED_HOME / ".java" / ".userPrefs" / "burp" / "prefs.xml"
    try:
        # The key is "burp.eula", not "eula" -- a check for the short
        # name reports every accepted home as unaccepted.
        return 'key="burp.eula"' in prefs.read_text()
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


def launch_burp(socket_path: Path, engagement_id: str, workdir: Path) -> subprocess.Popen:
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
