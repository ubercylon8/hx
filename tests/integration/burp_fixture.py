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

import ipaddress
import json
import os
import shutil
import socket
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


# ---------------------------------------------------------------------------
# The probe launcher, for docs/burp-proxy-measurements.md and the tests that
# keep it true. Everything below is about one question: which proxy listener
# did this request arrive on?
#
# WHY THE PROBE'S SOURCE IS UNDER tests/ AND NOT UNDER extension/src.
# It is a second BurpExtension, and it registers a second proxy request
# handler. Two structural checks forbid that in the shipped tree, both
# rightly: ChokepointTest asserts burp.* is imported by HxExtension.java and
# nothing else, and Plan 4's Task 7 asserts there is exactly one
# registerRequestHandler. It was written under extension/src to take the
# measurements and deleted from there in the same task.
#
# Deleting it outright would have left test_proxy_facts.py skipping forever,
# and a test that can only skip is not the "goes red when Burp changes" half
# of that deliverable -- it is the silence this repository keeps removing. So
# the source lives beside the test that needs it and is compiled into a
# throwaway directory per run, against the Burp jar itself: Burp ships the
# whole Montoya API inside burpsuite_desktop_v2026.7.3.jar (997 entries under
# burp/api/montoya/), so this adds no prerequisite that -m integration did not
# already have.
# ---------------------------------------------------------------------------

PROXY_CONFIG = "proxy-listeners.json"
PROBE_SRC = Path(__file__).resolve().parent / "probe" / "hx" / "proxy" / "Probe.java"
PROBE_CLASS = "hx.proxy.Probe"


def probe_missing() -> list[str]:
    """What the probe needs FROM THIS MACHINE beyond what missing() covers.

    Environment facts only, and the split is not tidiness. PROBE_SRC used to
    be in this list, which made an absent probe a SKIP: renaming
    tests/integration/probe/ produced `3 skipped in 0.03s` -- no error, no
    diagnostic -- and the default run's summary line announces DESELECTED
    integration tests, not skipped ones. So the three facts eight tasks rest
    on stopped being checked with nothing red anywhere.

    A Burp jar and a JDK are things a machine may legitimately not have. A
    file this repository ships is not one of those. See probe_source_missing().

    Kept out of missing() deliberately. That function runs at import time for
    the whole repository and its contract is that nothing escapes it; this one
    is called by a single fixture and may be as ordinary as it likes.
    """
    absent = missing()
    if shutil.which("javac") is None:
        absent.append("javac (a JDK, not just a JRE) to compile the probe")
    return absent


def probe_source_missing() -> str | None:
    """Why the probe cannot be compiled at all -- or None when its source is here.

    Separate from probe_missing() so the caller can treat it differently, and
    the caller must: this is a FAILURE, not a skip. The scenario is specific
    enough to answer in the message -- somebody reads Task 1's brief, sees
    "Step 8: Delete the probe", and deletes the wrong copy.
    """
    if PROBE_SRC.exists():
        return None
    return (
        f"the probe's source is gone: {PROBE_SRC}. This is not a missing "
        "environment prerequisite, it is a file this repository ships, and "
        "without it the three measurements in test_proxy_facts.py -- the only "
        "check that Burp's proxy still behaves the way Plan 4 was designed "
        "around -- cannot run at all. If it was deleted because Task 1's brief "
        "says Step 8 deletes the probe: that step removed it from "
        "extension/src, where a second registerRequestHandler breaks "
        "ChokepointTest and Task 7. It belongs here. Restore it with "
        "`git checkout tests/integration/probe/`."
    )


# --- F1: loopback_only, checked ------------------------------------------

def _listening_sockets(pid: int) -> list[str]:
    """Every local `address:port` this pid holds a LISTENING socket on.

    `ss -ltnpH`: -l listening, -t tcp, -n numeric (a resolved `localhost`
    would defeat the address parsing below), -p with the owning process, -H
    without the header row. The process column reads
    `users:(("java",pid=123,fd=8))`, so the pid is matched with its trailing
    comma -- a bare `pid=123` also matches pid 1234.
    """
    out = subprocess.run(["ss", "-ltnpH"], capture_output=True, text=True,
                         check=True).stdout
    return [line.split()[3] for line in out.splitlines()
            if f"pid={pid}," in line]


def _is_loopback(local: str) -> bool:
    """Is this `ss` local-address field on 127.0.0.0/8 or ::1?

    The forms that actually turn up here, all measured on this machine:
    `127.0.0.1:8080`, `[::1]:631`, `[::ffff:127.0.0.1]:40421` (what Burp's own
    listeners look like), `0.0.0.0:8443`, `*:8444` and `127.0.0.53%lo:53`.

    Anything unparseable -- `*` above all -- is NOT loopback. That direction
    matters: `*` is the wildcard bind this whole check exists to catch, and a
    parser that fell through to True for what it did not understand would
    report an open relay as safe.
    """
    host = local.rsplit(":", 1)[0].strip("[]").split("%")[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    # Both halves, and the second is not redundant belt-and-braces. Whether
    # IPv6Address.is_loopback answers True for an IPv4-MAPPED address is a
    # property of the interpreter: the 3.12.13 running this suite says True
    # (measured), and CPython has not always. `::ffff:127.0.0.1` is the form
    # EVERY Burp listener takes here, so an interpreter that answered False
    # would fail every honest run. The explicit test costs nothing and does
    # not depend on which CPython this is.
    return bool(addr.is_loopback or (mapped is not None and mapped.is_loopback))


def not_loopback_only(pid: int, ports: list[int]) -> str | None:
    """Why this Burp is not listening on loopback alone -- or None when it is.

    `listen_mode: loopback_only` is written into every listener launch_probe
    configures, three places in this tree call it non-optional, and until this
    function existed NOTHING checked it. Changing that one string to
    `all_interfaces` left `test_proxy_facts.py` reporting `3 passed in 38.03s`
    while `ss` showed the two configured listeners bound to `*:34777` and
    `*:38399` -- a forward proxy open to whatever network this laptop is
    attached to, for the 38 s those three tests take. Reproduced here.

    Two claims, because either one alone passes while the other is false:

      - every port the config named is LISTENING for this pid, so the check
        cannot pass vacuously against a Burp that bound nothing at all;
      - every socket this pid listens on is on a loopback address, INCLUDING
        the ones the config did not ask for. Burp opens a third listener of
        its own on an ephemeral loopback port every run -- measured: it
        answers `HTTP/1.1 204 No Content` to an absolute-URI GET, `200
        Connection established` to a CONNECT and `204` again inside the
        tunnel, forwards nothing to the target, and never reaches the
        extension's handler. Harmless, and it must not fail this check; but a
        check written only against the configured ports would also miss a
        future listener that is not harmless.
    """
    try:
        sockets = _listening_sockets(pid)
    except (OSError, subprocess.SubprocessError) as exc:
        # NOT a pass. A guard that evaporates when its tool is missing is the
        # defect this function was written to fix, one level down.
        return (f"the listening sockets of burp pid {pid} could not be read, so "
                f"`listen_mode: loopback_only` is unverified: {exc}")
    if not sockets:
        return (f"`ss -ltnpH` attributes no listening socket to burp pid {pid}, "
                "so nothing here can say whether its proxy is on loopback. Burp "
                "is running and its extension has loaded -- `PROBE READY` is on "
                "disk -- so read this as a broken check before reading it as a "
                "Burp that bound nothing.")
    unbound = [port for port in ports
               if not any(sock.endswith(f":{port}") for sock in sockets)]
    if unbound:
        return (f"burp pid {pid} was configured to listen on {unbound} and is "
                f"not: it holds {sockets}. A check for `loopback_only` against "
                "a port nothing bound would pass without measuring anything.")
    off = [sock for sock in sockets if not _is_loopback(sock)]
    if off:
        return (f"burp pid {pid} is listening on {off}, which is not loopback. "
                "A proxy listener on a wildcard or routable address is an open "
                "forward relay on whatever network this machine is attached to, "
                "for as long as the run lasts. Check `listen_mode` in "
                f"{PROXY_CONFIG}: it must be loopback_only.")
    return None


def _compile_probe(workdir: Path) -> Path:
    """The probe's classes, built fresh per run into a directory nothing keeps.

    Compiled against BURP_JAR rather than montoya-api.jar so that the only
    prerequisite is the one the integration suite already has. --release 21
    matches extension/build.sh: Burp loads this class into the same JVM.
    """
    classes = workdir / "probe-classes"
    classes.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["javac", "--release", "21", "-nowarn", "-Xlint:-options",
         "-cp", str(BURP_JAR), "-d", str(classes), str(PROBE_SRC)],
        check=True, capture_output=True, text=True)
    return classes


def _free_port() -> int:
    """A port nothing holds right now, for a listener Burp is about to bind.

    Necessary rather than tidy, and measured the hard way. A first draft of
    this fixture picked its ports by hand, and every one of them was already
    taken on this machine: 8080 by a llama.cpp router, 18080 by a node service,
    18081 by an agent. A taken port does not fail, it SUCCEEDS against the
    wrong process -- that run got a clean `421` from one and a clean `200` from
    another, with Burp never involved and the probe file holding nothing but
    `PROBE READY`. (8080 answers a proxy-style absolute-URI GET with a
    `404 {"error":...}` and a `Server: llama.cpp` header.)

    The window between this close() and Burp's bind() is a real race and
    nothing here can close it. The far end is what settles it: a test believes
    the port is Burp's only once a request through it has reached the probe's
    own handler, which nothing but Burp's proxy can arrange.
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def launch_probe(workdir: Path, out: Path,
                 extra_listener_port: int = 0) -> subprocess.Popen:
    """Burp running hx.proxy.Probe, with a SECOND proxy listener.

    The second listener is the whole point of Q1: one Burp, two ports, and the
    question is whether the extension can tell which one a request came in on.
    `extra_listener_port=0` means the caller does not care which port it gets;
    read the real ones back with proxy_port() and second_proxy_port().

    Burp Community has no API for creating a listener -- `burp.api.montoya.
    proxy.Proxy` offers registerRequestHandler, registerResponseHandler,
    registerWebSocketCreationHandler, history and intercept, and nothing that
    opens a port. So the second listener comes from a PROJECT CONFIG FILE via
    `--config-file`, which Community does accept. Both listeners are written
    explicitly, including the first: a config that named only the second would
    leave the first wherever Burp's defaults put it, which is the 8080 that
    _free_port() exists to avoid.

    `loopback_only` is not decoration. Nothing in this project has ever sent a
    request off this machine, and a proxy listener on 0.0.0.0 is an open relay
    on whatever network the laptop is attached to. It is also not self-
    enforcing: this string was the whole of the protection until
    not_loopback_only() was written, and changing it to `all_interfaces` left
    the suite green with the proxy bound to `*`. Callers must run that check
    once the listeners are up -- test_proxy_facts.py's fixture does.
    """
    home = make_home(workdir)
    classes = _compile_probe(workdir)
    ports = [_free_port(), extra_listener_port or _free_port()]
    (workdir / PROXY_CONFIG).write_text(json.dumps({"proxy": {
        "request_listeners": [
            {"certificate_mode": "per_host", "listen_mode": "loopback_only",
             "listener_port": port, "running": True}
            for port in ports
        ]}}))
    log = (workdir / "burp.log").open("wb")
    cmd = [
        "java", "-Djava.awt.headless=true", f"-Duser.home={home}",
        f"-Dhx.probe.out={out}",
        # The probe's classes in place of the shipped extension jar. Burp
        # loads exactly the one class named below, so EXT_JAR on the classpath
        # would not load HxExtension -- it is left off because the probe does
        # not need it, and because a jar on the path of a measurement run is a
        # thing a later reader has to rule out.
        *ADD_OPENS, "-cp", f"{BURP_JAR}:{classes}",
        "burp.StartBurp",
        f"--developer-extension-class-name={PROBE_CLASS}",
        f"--config-file={workdir / PROXY_CONFIG}",
        "--disable-auto-update",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, cwd=LAB)
    proc.stdin.write(b"\n\n")
    proc.stdin.flush()
    return proc


def listener_ports(workdir: Path) -> list[int]:
    """The ports this run's Burp was TOLD to listen on, read back from its config.

    Discovered rather than hard-coded, and from the file Burp itself was handed
    rather than from a variable this module kept -- so the number a test dials
    is the number Burp was asked for, with nothing in between that could drift.
    """
    cfg = json.loads((workdir / PROXY_CONFIG).read_text())
    return [listener["listener_port"]
            for listener in cfg["proxy"]["request_listeners"]]


def proxy_port(workdir: Path) -> int:
    """Burp's first proxy listener for this run.

    NOT 8080. Burp Community does default to 8080, but a default is where a
    listener goes when nobody says otherwise, and this fixture says otherwise
    precisely because 8080 on a developer's machine is whatever else claimed it
    first -- here, the local LLM router. See _free_port().
    """
    return listener_ports(workdir)[0]


def second_proxy_port(workdir: Path) -> int:
    """Burp's second proxy listener -- the other side of Q1's question."""
    return listener_ports(workdir)[1]
