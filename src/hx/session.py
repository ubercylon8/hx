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

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

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
    """
    workdir.mkdir(parents=True, exist_ok=True)
    ports = [_free_port(), second_port or _free_port()]
    (workdir / PROXY_CONFIG).write_text(json.dumps({"proxy": {
        "request_listeners": [
            {"certificate_mode": "per_host", "listen_mode": "loopback_only",
             "listener_port": port, "running": True}
            for port in ports
        ]}}))
    return ports


def launch_burp(socket_path: Path, engagement_id: str, workdir: Path, *,
                sentinel: Path, jar: Path, instance: str,
                crawler_port: int = 0) -> subprocess.Popen:
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
    """
    problem = extension_problem()
    if problem is not None:
        raise SessionError(problem)
    home = make_home(workdir)
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
