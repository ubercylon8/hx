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

import contextlib
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from hx import capture as capture_mod
from hx import halt as halt_mod
from hx.bridge.server import BridgeServer
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir

JAR_GLOB = "burpsuite_desktop_v*.jar"
DEFAULT_LAB = Path.home() / "F0RT1KA" / "burp-lab"
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


# The project config both launchers hand Burp, and the ports inside it.
#
# These three live ABOVE launch_burp because BOTH launchers need them and a
# second copy is a second set of listener settings free to drift from this one
# -- `listen_mode: loopback_only` above all, which is written once here and
# read back by not_loopback_only() for whichever Burp is running. The probe
# section below is where the mechanism is EXPLAINED (see launch_probe): Burp
# Community has no API for creating a listener, so a listener comes from a
# project config file or it does not exist.

PROXY_CONFIG = "proxy-listeners.json"

# How many times write_listener_config() may redraw before giving up. The
# first draw collides about once in 5000; eight is far past the point where a
# ninth would mean something other than luck -- an exhausted ephemeral range,
# or a `second_port` the caller named that _free_port() keeps handing back.
_PORT_DRAWS = 8


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
    own handler -- or, for launch_burp, once an exchange the extension observed
    on that port has arrived over the bridge -- which nothing but Burp's proxy
    can arrange.
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def write_listener_config(workdir: Path, second_port: int = 0) -> list[int]:
    """Two loopback-only proxy listeners, written where `--config-file` wants
    them. Returns the ports, first then second.

    BOTH listeners are written, including the first, and that is not
    redundancy: a config naming only the second leaves the first wherever
    Burp's defaults put it, which is the 8080 `_free_port()` exists to avoid.

    `loopback_only` is not decoration and it is not self-enforcing. Nothing in
    this project has ever sent a request off this machine, and a proxy listener
    on 0.0.0.0 is an open forward relay on whatever network the laptop is
    attached to. This string was the whole of the protection until
    not_loopback_only() was written, and changing it to `all_interfaces` left
    the suite green with the proxy bound to `*`. Every caller must run that
    check once the listeners are up.

    THE TWO PORTS MUST DIFFER, AND A DRAW THAT CANNOT MAKE THEM DIFFER IS
    FATAL. Two consecutive ephemeral binds can return the same number --
    measured at this call site on this machine, 4 collisions in 20 000 calls --
    and a collision is silent all the way down. `Source.java` is `port ==
    crawlerPort ? CRAWLER : OPERATOR`, so one port for both listeners
    attributes THE CONSULTANT'S OWN BROWSING to the crawler and applies the
    agent's rules to it: their POSTs dropped by the method allowlist, the
    dangerous-path denylist, the rate limit and the request budget, none of
    which S4 applies "to traffic from the operator's own browser". Every guard
    downstream passes -- not_loopback_only() sees one listening port and asks
    for one, the handshake completes, configure completes -- so the consultant
    gets Burp's drop page on a form submission with nothing in the output
    explaining it. Redrawn here, and raised rather than returned if the redraw
    cannot separate them, because there is no later place that can tell.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    for _ in range(_PORT_DRAWS):
        ports = [_free_port(), second_port or _free_port()]
        if ports[0] != ports[1]:
            break
    else:
        raise SessionError(
            f"could not draw two different proxy ports in {_PORT_DRAWS} tries: "
            f"the operator's listener and the crawler's both came back as "
            f"{ports[0]}. S4 tells the operator and the crawler apart by which "
            "listener a request arrived on and by nothing else, so one port "
            "for both would silently give the consultant's own browser the "
            "agent's rules"
            + (f". Try again without --crawler port {second_port}"
               if second_port else ""))
    (workdir / PROXY_CONFIG).write_text(json.dumps({"proxy": {
        "request_listeners": [
            {"certificate_mode": "per_host", "listen_mode": "loopback_only",
             "listener_port": port, "running": True}
            for port in ports
        ]}}))
    return ports


def launch_burp(socket_path: Path, engagement_id: str, workdir: Path, *,
                sentinel: Path, jar: Path, instance: str,
                crawler_port: int = 0,
                seed: Path | None = None) -> subprocess.Popen:
    """Burp's output goes to workdir/burp.log, never to a pipe.

    An unread subprocess.PIPE is a latent deadlock -- Burp blocks once the pipe
    buffer fills and the test hangs with no diagnostic. A file also means a
    failing test can quote what Burp actually said.

    TWO PROXY LISTENERS, and the SECOND one is the crawler's. S4 tells the
    operator and the crawler apart by WHICH LISTENER a request arrived on and
    by nothing in the traffic itself, so a rig with one listener cannot
    exercise the split at all -- `Source.forListenerPort` would answer OPERATOR
    for every request and the two rule sets would never be told apart.

    `-Dhx.crawler_port` IS THE OTHER HALF OF THAT AND IT IS NOT OPTIONAL.
    `HxExtension` reads it with a default of 0, and `Source.forListenerPort`
    reads 0 as "no crawler configured" -- so a launch that omits it attributes
    EVERY request to the operator however many listeners are running, and a
    test of the split passes while measuring nothing. This is the
    `-Dhx.halt_sentinel` incident that this function's own comment below
    records, one plan later; the property is passed from the config file Burp
    was actually handed, never from the argument, so the number the extension
    compares against and the number Burp bound cannot drift.

    `crawler_port=0` means "any free port"; read the real ones back with
    proxy_port() and second_proxy_port().

    `seed` is handed straight to make_home() and means the same thing there:
    omitted, the operator's own Burp home is copied. A caller that knows
    better -- the integration rig, which verified a different home before
    calling -- says so rather than checking one home and copying another.
    """
    problem = extension_problem()
    if problem is not None:
        raise SessionError(problem)
    # `seed` FORWARDED, not resolved here: make_home owns the default so that
    # there is one answer to "which home is copied" rather than two that agree.
    home = make_home(workdir, seed=seed)
    ports = write_listener_config(workdir, crawler_port)
    log = (workdir / "burp.log").open("wb")
    cmd = [
        "java",
        "-Djava.awt.headless=true",
        f"-Duser.home={home}",
        f"-Dhx.socket={socket_path}",
        f"-Dhx.engagement={engagement_id}",
        f"-Dhx.instance={instance}",
        # Required, not optional: HxExtension.initialize() returns early
        # ("extension idle") without it, so the extension never dials and the
        # handshake never happens. Task 6 made it mandatory and this fixture
        # was not updated -- the integration tests are deselected from the
        # default run, so nothing said so for a day.
        f"-Dhx.halt_sentinel={sentinel}",
        # Read back out of the config above rather than from `crawler_port`,
        # which may be the 0 that means "choose one for me".
        f"-Dhx.crawler_port={ports[1]}",
        *ADD_OPENS,
        "-cp", f"{jar}:{EXT_JAR}",
        "burp.StartBurp",
        "--developer-extension-class-name=hx.HxExtension",
        f"--config-file={workdir / PROXY_CONFIG}",
        "--disable-auto-update",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, cwd=workdir)
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


# --- Task 5: the configure body, and the scope hash it is authorised against

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
    """
    row = conn.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC LIMIT 1", (engagement_id,)).fetchone()
    if row is None:
        raise SessionError(
            f"engagement {engagement_id} has no scope_version row, so there is "
            "no recorded boundary to authorise the extension against")
    return row[0]


# --- Task 6: the session itself ------------------------------------------

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
    """

    operator_port: int
    crawler_port: int
    epoch: int
    bridge: object
    workdir: Path


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
        why = not_loopback_only(proc.pid, [operator, crawler])
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

        yield LiveSession(operator, crawler, epoch, srv, work)
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
