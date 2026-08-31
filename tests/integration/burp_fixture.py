"""What the RIG adds to `hx.session`, and nothing that `hx.session` already is.

The launcher, the private home, the listener config, the port readback and the
loopback check all USED to live here, and the demo script imported them from
the test tree. They are `hx.session`'s now, and this module re-exports them so
that the code a consultant runs and the code these thirty tests certify are one
body of code rather than two that agree today.

What is left is genuinely test-only: the prerequisite checks that decide
whether this MACHINE can run a real Burp at all (a skip) as against whether
somebody forgot to run `extension/build.sh` (a failure), and the second
BurpExtension the proxy measurements need.

Everything below was established empirically, most of it the hard way:
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

LAB = Path(os.environ.get("HX_BURP_LAB", session.DEFAULT_LAB))
SEED_HOME = LAB / "burphome"          # copied from, never run against

# The rig's seed is the lab's curated home rather than the operator's own,
# which is what `hx.session.seed_home()` returns by default. Both launchers
# below say so with `seed=SEED_HOME`, in code, on every call -- NOT through
# `$HX_BURP_SEED_HOME`, which only an autouse pytest fixture could set and
# which therefore left this module's two non-pytest callers, the demo scripts,
# checking this home and copying the operator's.

try:
    BURP_JAR: Path | None = find_burp_jar()
    _NO_BURP_JAR: str | None = None
except (SessionError, OSError) as exc:
    # NOTHING MAY RAISE AT IMPORT. `find_burp_jar()` raises when the lab holds
    # no jar -- or two, which is an error rather than a guess -- and this
    # module is imported during COLLECTION for the whole repository. An escape
    # here is not a skipped suite, it is `Interrupted: 1 error during
    # collection` with zero tests run, fast suite included. That exact shape
    # has bitten twice already, once from `_eula_accepted` raising
    # UnicodeDecodeError on a torn prefs.xml. So the reason is HELD and
    # reported by missing(), which is the function whose whole contract is
    # that it names what is absent instead of raising.
    BURP_JAR = None
    _NO_BURP_JAR = str(exc)


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


def _burp_jar_row() -> str | None:
    """The Burp jar's absence, however it was discovered -- or None.

    Two ways to have no jar and one row for both: `find_burp_jar()` failed at
    import (no jar in the lab, or two, or an unreadable one) and left its own
    message, or it named a path that has since gone. The first message is the
    product's own and names all three places it looked; the second names the
    path, which is what the rows below do.
    """
    if BURP_JAR is None:
        return _NO_BURP_JAR
    if not BURP_JAR.exists():
        return f"burp jar: {BURP_JAR}"
    return None


def _jar_problem() -> str | None:
    """The ONE place the jar's state is judged: "missing", "stale", "future", None.

    One function because the first version of this split had two, and they had
    already diverged in the commit that created them: `_missing()` special-
    cased a future-dated source and `unbuilt()` did not. That is not a
    cosmetic drift. A future mtime cannot be cleared by rebuilding -- no jar
    can be stamped later than a source dated years ahead -- and `_missing()`'s
    own comment records it being reproduced ("two honest rebuilds, still
    reported stale both times"). Routing it to a hard FAIL told the operator
    to run a script that provably cannot help, permanently.

    So the three outcomes are distinguished HERE, once, and routed by who can
    fix them: "missing" and "stale" are build.sh's, "future" is the clock's.

    `hx.session.extension_problem()` makes the same three-way judgement for
    the product and phrases it as a sentence for an operator. This one stays
    because the rig routes the three outcomes to three DIFFERENT verdicts --
    fail, skip, silence -- where the product has only one, and a caller cannot
    recover the distinction from prose.
    """
    if not EXT_JAR.exists():
        return "missing"
    newest = _newest_source_mtime()
    if newest > time.time() + 60:
        return "future"
    if newest > _jar_mtime():
        return "stale"
    return None


def unbuilt() -> list[str]:
    """Build products of THIS repo that are absent or stale. These must FAIL.

    `missing()` answers "can this machine run Burp at all" -- a question whose
    honest answer on someone else's laptop is no, and a skip. This one answers
    "did you run build.sh", whose answer is always yes-or-you-forgot, and a
    skip there is the failure mode this project keeps finding: a missing
    artefact turns into a silent green.

    It is not hypothetical. Task 1's fix round inherited a tree whose jar was
    stale, `-m integration` reported all 17 tests SKIPPED, and the baseline
    recorded one commit earlier as "integration 17 passed" was not
    reproducible as committed. The same shape had just been fixed one level
    down for the probe source; it was still open here.

    Kept separate from `missing()` rather than merged into it because the two
    have opposite correct behaviours, and a single list forces one of them to
    be wrong.

    Returns EMPTY when the machine cannot build at all. `build.sh` needs the
    montoya jar from the same lab `_environment_missing()` reports and exits 1
    without it, so telling a contributor with no lab to "run extension/build.sh"
    sends them to a script that cannot succeed. A build product is only
    independent of the machine when the machine can build it.

    Wrapped for the same reason `missing()` is: this runs at IMPORT TIME
    through test_real_burp's skipif, and an exception here is not a skipped
    test, it is `Interrupted: 1 error during collection` for the entire
    repository -- 396 fast tests reporting nothing. That was measured against
    a lab directory at mode 000, and `missing()`'s docstring already records
    the same hazard biting twice before.
    """
    try:
        if _environment_missing():
            return []
        problem = _jar_problem()
        if problem == "missing":
            return [f"extension jar is missing (run extension/build.sh): {EXT_JAR}"]
        if problem == "stale":
            return ["extension jar is older than its sources (run extension/build.sh)"]
        return []
    except OSError:
        return []


def _environment_missing() -> list[str]:
    """Prerequisites this MACHINE may legitimately not have. Never the jar.

    Split out so a caller can take the subset it actually depends on.
    `probe_missing()` is the reason: the probe compiles its own class and
    launches with `--developer-extension-class-name=hx.proxy.Probe`, so it
    never loads the extension jar -- yet it inherited the jar's rows through
    missing() and a STALE JAR silenced all three of Task 1's measurements.
    A prerequisite that is not one is still a skip, and a skip still reports
    green.
    """
    try:
        return _environment_missing_unguarded()
    except OSError as exc:
        return [f"prerequisites under {LAB} could not be checked: {exc}"]


def _environment_missing_unguarded() -> list[str]:
    absent = []
    if (row := _burp_jar_row()) is not None:
        absent.append(row)
    if not (SEED_HOME / ".java").is_dir():
        absent.append(f"seed burp home: {SEED_HOME / '.java'}")
    elif not _eula_accepted():
        absent.append(f"burp.eula not accepted in {SEED_HOME / '.java'}")
    if not (SEED_HOME / ".BurpSuite").is_dir():
        absent.append(f"seed burp home: {SEED_HOME / '.BurpSuite'}")
    return absent


def _missing() -> list[str]:
    absent = []
    if (row := _burp_jar_row()) is not None:
        absent.append(row)
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


def _eula_accepted() -> bool:
    """The rig's seed home, judged by the product's reader.

    The byte search and the lesson behind it (a torn 1.75 MB prefs.xml makes
    read_text() raise UnicodeDecodeError, which is not an OSError, so it
    escaped this function, escaped missing(), and turned every pytest run in
    the repo into a collection error) live in `hx.session._eula_accepted`.
    Only WHICH home is the rig's business.
    """
    return session._eula_accepted(SEED_HOME)


def burp_available() -> bool:
    return not missing()


def launch_burp(socket_path: Path, engagement_id: str, workdir: Path,
                sentinel: Path, crawler_port: int = 0) -> subprocess.Popen:
    """`hx.session.launch_burp`, with the two facts that are the RIG's to say.

    The launcher itself is the product's, which is the whole point: the
    `--add-opens` list, the `-Dhx.*` properties, the two loopback-only
    listeners and the log-to-a-file-never-a-pipe rule are now certified by
    these thirty tests as the code a consultant's `hx capture start` runs,
    rather than as a copy of it that agreed on the day it was written.

    Three arguments are still this side's. `jar` is the one this lab holds --
    resolved once at import, so a test's failure names the same jar
    `missing()` does. `instance` is "integration" because the rig identifies
    itself as the rig: `test_real_burp` asserts on `hello["instance_id"]`, and
    an operator reading a bridge log should be able to tell a test run from a
    session they started.

    `seed=SEED_HOME` IS THE ONE `missing()` CHECKED, and passing it is not
    tidiness. `session.make_home` copies `seed_home()` by default -- the
    operator's own `$HOME` -- which is right for a consultant and wrong for
    every caller here, and for one round of this task it was steered by an
    autouse fixture setting `$HX_BURP_SEED_HOME`. A fixture only runs under
    pytest. `scripts/demo_capture.py` and `scripts/demo_gate.py` call this
    function too: they guarded on `missing()`, which reports on `SEED_HOME`,
    and then copied the operator's live `~/.BurpSuite/sessions` -- real client
    project state on a consultant's machine -- into a temporary directory.
    Checking one home and copying another is the exact disagreement this
    argument removes, for every caller rather than for the ones pytest owns.
    """
    return session.launch_burp(
        socket_path, engagement_id, workdir,
        sentinel=sentinel,
        # Not `BURP_JAR` outright: when the import-time search failed this is
        # None, and calling through raises find_burp_jar's own message, which
        # names all three places it looked.
        jar=BURP_JAR if BURP_JAR is not None else find_burp_jar(),
        instance="integration",
        crawler_port=crawler_port,
        seed=SEED_HOME)


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

# PROXY_CONFIG, _free_port and write_listener_config used to live here, then
# moved above launch_burp so the two launchers shared ONE spelling of
# `listen_mode: loopback_only`. They are `hx.session`'s now and imported at
# the top of this file, which makes that one spelling the product's. The
# explanation of WHY a listener has to come from a config file at all stays in
# launch_probe's docstring below, where it was measured.
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
    absent = _environment_missing()
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
    # seed=SEED_HOME for the same reason bf.launch_burp passes it: make_home's
    # default is the operator's own home, and this is the one missing() checked.
    home = make_home(workdir, seed=SEED_HOME)
    classes = _compile_probe(workdir)
    write_listener_config(workdir, extra_listener_port)
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
