"""The bridge session, end to end: the product's own, against a real Burp.

WHAT THIS FILE IS FOR, and why the thirty tests beside it do not already
cover it. Every other integration test builds its session in
`conftest.py`: the rig makes the `OperatorHalt`, constructs the
`BridgeServer`, launches Burp, waits for the handshake, checks the
listeners and pushes a configure. That rig now uses the product's pieces --
`session.config_body`, `session.stored_scope_sha256`, `session.ExchangeSink`
and `session.launch_burp` -- but it is still the RIG assembling them, and an
assembly that agrees with `hx.session.session()` today is free to stop
agreeing tomorrow. Nothing in this repository had ever driven the product's
own context manager against a real JVM, and nothing had ever driven the
command a consultant actually types.

That is the gap this plan was written to close. Before it, `hx capture
start` opened a database row and stopped: it never called `bridge.configure`,
the extension defaults to DENY-ALL, and a consultant could run the command,
browse all afternoon and record nothing -- with no error anywhere, because
DENY-ALL is a working extension refusing everything it was never authorised
to see.

SO THE FIRST TEST RUNS THE COMMAND. Not `session()` with a test's arguments:
`hx capture start` in its own process, the way an operator runs it, with a
browser pointed at the port it printed. What comes back is measured in the
store the command opened -- and the run row it opened is the one the exchange
is attributed to, which is the half that says the two are one session rather
than two things that happen to be running.

THE SEED HOME IS NOT THE OPERATOR'S. `make_home` copies `seed_home()` unless
told otherwise -- `$HX_BURP_SEED_HOME`, then `Path.home()` -- and the product
is right to default there, since the licence a consultant accepted is the only
one hx may use. It is wrong for every test: copying the real `$HOME` would
take a developer's live `~/.BurpSuite/sessions` (real client project state)
into `tmp_path`, and the run would be against a home nothing here checked.
The in-process test says `seed=bf.SEED_HOME` in code, the way every other
launcher in this directory does. The SUBPROCESS cannot: `hx capture start`
has no such option, and it should not grow one for a test -- so it gets
`$HX_BURP_SEED_HOME` in its environment, which is the operator-facing
override the product documents for exactly this.
"""
from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hx import config, engagement, report
from hx import session as session_mod
from hx.bridge import server
from tests.integration import burp_fixture as bf
from tests.integration.conftest import Rig, browse_through
from tests.integration.target_server import TargetServer

pytestmark = pytest.mark.integration

# What `capture start` prints, and the two facts a test needs off it. The
# port is the one an operator points a browser at; the run id is the row the
# command opened. Both are parsed rather than looked up, because reading them
# out of the command's own output is what proves the command reported them.
PORT_LINE = re.compile(r"operator proxy listening on 127\.0\.0\.1:(\d+)")
RUN_LINE = re.compile(r"browse run (\S+) is live")

# The console script, which is what an operator types. Not `python -m` or an
# import: `hx` is what `pyproject.toml` installs and what a consultant has on
# their PATH, and the point of this file is the command rather than the
# function behind it.
HX = Path(sys.executable).with_name("hx")


@pytest.fixture(autouse=True)
def _prerequisites():
    """Order matters, and it is the rig's order.

    An unbuilt or stale extension jar is a FAILURE -- somebody forgot
    `extension/build.sh`, and a skip there is how this project's tests have
    twice gone dark while reporting green. A machine with no Burp at all is a
    skip, and asking that question first turns the former into the latter.
    """
    if bf.unbuilt():
        pytest.fail("unbuilt: " + ", ".join(bf.unbuilt()))
    if bf.missing():
        pytest.skip("missing: " + ", ".join(bf.missing()))


def _engagement(stack: contextlib.ExitStack, root: Path, *, scope: str):
    """One engagement on disk, made the way `hx new` makes one.

    `engagement.create` is what writes the `scope_version` row both tests
    below depend on -- the session refuses to authorise an extension without
    one, and the report renders it as the boundary of record.
    """
    cfg = config.Config(name="cli-session", client="loopback",
                        scope_include=[scope])
    eng = engagement.create(root / "engagement", cfg, author="integration")
    stack.callback(eng.db.close)
    return eng


def _settle(predicate, what: str, *, evidence, timeout: float = Rig.SETTLE_S):
    """Wait for a row to arrive, and say what to read when it never does.

    THE RECORD ARRIVES AFTER THE RESPONSE. Measured in
    `test_proxy_capture.py`: browsing five times and reading the table the
    instant each client response completed gave 1, 1, 2, 3, 4 rows, because
    the capture frame crosses the bridge on its own thread, behind the
    browser. A test that read once would flake in the direction of "nothing
    was recorded", which is the direction that reads as this plan failing.

    NOT `Rig.settle`, and the difference is what can be said on timeout.
    That one reports `srv.exchange_errors` -- the count that separates "the
    extension sent nothing" from "the sink threw and the bridge swallowed
    it", which are the same empty table with opposite fixes. HERE THE SINK
    IS IN ANOTHER PROCESS: there is no bridge object on this side to ask, so
    the evidence is that process's own output and the session's Burp log,
    named by the caller.
    """
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return
        time.sleep(0.1)
    pytest.fail(f"{what} never arrived within {timeout}s.\n{evidence()}")


def _group_survivors(pgid: int) -> list[str]:
    """Every process still in the command's process group: `pid cmdline`.

    THE COMMAND'S BURP IS ITS CHILD, and `start_new_session=True` made the
    command a group leader, so the JVM inherits that pgid and this is the one
    question that covers both: did anything the command started outlive it?

    Read out of `/proc` rather than through `pgrep`, which is one more tool to
    be missing at the moment a guard needs it -- and a guard that evaporates
    when its tool is absent is the defect `not_loopback_only`'s docstring is
    about. `/proc/<pid>/stat` is `pid (comm) state ppid pgrp ...`, and `comm`
    can contain spaces and parentheses, so the fields are taken after the LAST
    `)`. A process that vanishes mid-scan is skipped: it is not a survivor.
    """
    alive = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            fields = stat[stat.rindex(")") + 1:].split()
            if int(fields[2]) != pgid:
                continue
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
        except (OSError, ValueError, IndexError):
            continue
        alive.append(f"{entry.name} {cmdline.decode(errors='replace')[:120]}")
    return alive


def _terminate(proc: subprocess.Popen, pgid: int) -> None:
    """Leave nothing running, however this test ended.

    Registered on the ExitStack BEFORE the command is waited on, for the
    reason `conftest.py` records at the top: on this branch a kill that lived
    at the end of a try block was jumped over by a failing assertion twice,
    leaving a 900 MB JVM behind per debugging attempt.

    TWO KILLS, and the second is not redundant. The first is the command
    never having got to its own teardown -- a failed assertion above, a
    timeout -- and the JVM is then its live child. The second covers the case
    the test now ASSERTS against: the command exited and something it started
    did not. That assertion has already failed by the time this runs, which is
    the point (the test must report the orphan, not tidy it away), but a
    failing test that leaks 900 MB per debugging attempt is exactly what this
    file's clean-up discipline exists to prevent. Guarded on a survivor
    actually being there, so a `killpg` is never sent to a group id that
    nothing in this test owns any more.
    """
    if proc.poll() is None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=30)
    if _group_survivors(pgid):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)


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
        env = dict(os.environ, HX_BURP_SEED_HOME=str(bf.SEED_HOME))
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
        # KeyboardInterrupt raised in `signal.pause()` unwinds the run-closing
        # `finally`, click turns it into `Abort`, and `Abort` is `sys.exit(1)`.
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


def test_the_authorised_hash_is_the_one_the_report_renders(tmp_path, monkeypatch):
    """Task 5's rule, proved against a real extension rather than a fake.

    The extension is authorised against the hash the STORE recorded, read
    from `scope_version`, and the report renders that same hash as the
    boundary of record. Recomputing it from today's config would let a
    deliverable show one boundary while the extension enforced another --
    two facts that agree today, which is why the rule is designed in rather
    than tested for.

    WHAT IS PINNED HERE AND NOT IN `tests/test_session_configure.py`. That
    file separates "read" from "recompute" with a config edit no recompute
    can survive, against no Burp at all. This one adds the two ends that only
    a real JVM has: the hash CROSSED THE SOCKET and a real extension accepted
    the frame carrying it (epoch 1, where 0 is DENY-ALL), and the body it
    accepted is `config_body`'s exactly -- no test additions, since every
    other integration test pushes the rig's `build_config_body`, which is
    that body plus two keys the product does not send.

    `configure` is WRAPPED rather than replaced: the recorded call is the one
    that actually went to the JVM, and the epoch below is the JVM's answer.
    """
    with contextlib.ExitStack() as stack:
        target = TargetServer("127.0.0.1")
        stack.callback(target.stop)
        target.start()
        eng = _engagement(stack, tmp_path, scope=f"{target.origin}/*")

        sent = []
        real_configure = server.BridgeServer.configure

        def recording_configure(self, pairs, scope_sha256, profile):
            sent.append((pairs, scope_sha256, profile))
            return real_configure(self, pairs, scope_sha256, profile)

        monkeypatch.setattr(server.BridgeServer, "configure",
                            recording_configure)

        with session_mod.session(eng, instance="test",
                                 seed=bf.SEED_HOME) as live:
            assert live.epoch == 1, (
                "0 is what the extension reports at DENY-ALL, and a fresh "
                "extension numbers its first accepted scope 1")

        assert len(sent) == 1, "the session must authorise exactly once"
        pairs, scope_sha256, profile = sent[0]
        assert pairs == session_mod.config_body(eng.config)
        assert profile == eng.config.safety_profile

        stored = eng.db.execute(
            "SELECT sha256 FROM scope_version WHERE engagement_id=?"
            " ORDER BY effective_from_us DESC LIMIT 1", (eng.id,)).fetchone()[0]
        assert scope_sha256 == stored, (
            "the extension was authorised against a hash that is not the one "
            "`scope_version` recorded")

        rendered = report.render(eng.db, engagement_id=eng.id,
                                 config=eng.config)
        assert f"`{stored}`" in rendered, (
            "the report does not render the boundary the extension was "
            "authorised against")
        # The report does not merely CONTAIN the string: it says it checked.
        # `_scope_of_record` hashes the config it rendered from and compares
        # it to every recorded version, so this sentence firing is the report
        # agreeing that the newest recorded row is the one it is describing.
        assert f"`{stored}` — verified, not assumed" in rendered
