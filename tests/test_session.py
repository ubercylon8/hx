"""The session itself: a live, configured Burp -- or nothing at all.

Two things are pinned here and they fail in opposite directions.

`ExchangeSink` fails SILENTLY. The bridge calls its exchange sink on the read
thread, a sqlite connection belongs to the thread that opened it, and the
bridge catches everything the sink throws by design -- so a sink built over
the wrong connection produces a live Burp, traffic flowing, and an empty
database. Nothing raises, nothing logs, and the run reads as complete.

`session()` fails LOUDLY and must still tear down. A refused `configure`
leaves a Burp whose extension is at DENY-ALL: it looks like a working session
and captures nothing, which is worse than no session at all.

NO JVM IS STARTED HERE. `launch_burp`, `wait_for` and `not_loopback_only` are
replaced in most tests here; the last two sections replace `subprocess.Popen`
instead, one level lower, so that `make_home` and `write_listener_config` are
the PRODUCT's on the paths where their composition is the thing being pinned.
Nothing in either case starts a JVM. The real thing is exercised under
`pytest -m integration`, against a real Burp, at about 200 seconds.

The only socket any test in this file creates is the bridge's own AF_UNIX
rendezvous inside `tmp_path`, which `BridgeServer.start()` makes and `stop()`
unlinks -- plus, in the one test that draws its ports for real, `_free_port`'s
bind to `127.0.0.1:0`, which is closed before it returns and never listened on.
"""
from __future__ import annotations

import io
import json
import sqlite3
import stat
import threading
from pathlib import Path

import pytest

from hx import config as config_mod
from hx import engagement as engagement_mod
from hx import session
from hx.bridge import server
from hx.store import db as db_mod

# Distinctive and fixed. `_free_port()` is what the product uses and it BINDS
# to find one; nothing in this file may, so the fake launch below writes these
# two straight into the config file instead. They are never connected to.
OPERATOR_PORT = 31337
CRAWLER_PORT = 31338


class _FakeProc:
    """A launched process that never was.

    The twin of `tests/test_session_launch.py`'s, redeclared rather than
    imported across test modules: `pid` is real enough to hand to a
    monkeypatched `not_loopback_only`, and `on_kill` is how a test proves the
    teardown actually ran.
    """

    def __init__(self, on_kill=None):
        self.pid = 4242
        self.stdin = io.BytesIO()
        self._on_kill = on_kill

    def kill(self):
        if self._on_kill is not None:
            self._on_kill(self.pid)

    def wait(self, timeout=None):
        return 0


def _write_listener_config(workdir: Path, ports=(OPERATOR_PORT, CRAWLER_PORT)):
    """What the real `launch_burp` would have left behind.

    `session()` reads its two ports back out of `PROXY_CONFIG` -- out of the
    file Burp was actually handed, never out of a variable this module kept --
    so a fake launch that writes nothing makes `proxy_port()` raise
    `FileNotFoundError` before any behaviour under test is reached, and every
    assertion below would be measuring that instead.

    Written directly rather than through `write_listener_config()`, which
    calls `_free_port()` and therefore binds.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / session.PROXY_CONFIG).write_text(json.dumps({"proxy": {
        "request_listeners": [
            {"certificate_mode": "per_host", "listen_mode": "loopback_only",
             "listener_port": port, "running": True}
            for port in ports]}}))


def _launcher(killed=None, ports=(OPERATOR_PORT, CRAWLER_PORT)):
    """A stand-in for `launch_burp` with the real one's side effect on disk."""

    def launch(socket_path, engagement_id, workdir, **kw):
        _write_listener_config(workdir, ports)
        return _FakeProc(on_kill=None if killed is None else killed.append)

    return launch


@pytest.fixture
def an_engagement(tmp_path):
    """A real, on-disk engagement -- `hx.engagement.create()`'s own shape.

    Real because three separate things read it: `OperatorHalt` needs exactly
    one `engagement` row, `stored_scope_sha256` needs the `scope_version` row
    `create()` writes in the same transaction, and `ExchangeSink` needs a
    database its `Capture` can actually insert into.
    """
    cfg = config_mod.Config(
        name="acme-2026-09", client="Acme Corp",
        scope_include=["https://a.test/*"])
    eng = engagement_mod.create(tmp_path / "acme", cfg, author="jimx")
    yield eng
    eng.db.close()


@pytest.fixture
def a_jar(tmp_path):
    """An explicit `--burp-jar`, so no test here reads the operator's lab.

    NOT optional, and not tidiness. `session()` calls `find_burp_jar(jar)`
    before anything else; with `jar=None` that searches `$HX_BURP_LAB`
    (default `~/F0RT1KA/burp-lab`), so on a machine with no jar -- or with
    two -- it raises `SessionError` first and the three tests below that
    expect a `SessionError` would PASS while measuring nothing at all. It is
    never opened: `launch_burp` is replaced in every test that gets this far.
    """
    jar = tmp_path / "burpsuite_desktop_v0.0.0.jar"
    jar.write_bytes(b"not a jar; launch_burp is faked in every test here")
    return jar


# --- the sink ------------------------------------------------------------


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
    t.start()
    t.join()
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
    t.start()
    t.join()

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
    assert not (an_engagement.root / "session" / "capture" / "hx.sock").exists(), (
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
    assert live.workdir == an_engagement.root / "session" / "capture"
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


def test_a_clean_exit_authorises_the_extension_and_stops_the_bridge(
        monkeypatch, an_engagement, a_jar):
    """The only test that runs `session()` to a CLEAN close.

    Two things nothing else here reaches. S4's authorisation point -- the one
    place in `src/` that calls `bridge.configure()` -- is proved to carry the
    ENGAGEMENT's own scope: Task 5 proved `config_body` and
    `stored_scope_sha256` in isolation, and nothing proved `session()` passes
    those particular values, so a call authorising an empty body against a
    made-up hash under a made-up profile was invisible. And the teardown is
    proved to run on the path where nothing went wrong, where a `finally` is
    not what carries it.

    `configure` is replaced by a function with the REAL signature rather than
    `*a, **k`, so the assertions below bind the same way whether `session()`
    passes them positionally or by keyword.
    """
    killed, configured = [], []

    def record_configure(self, pairs, scope_sha256, profile):
        configured.append((pairs, scope_sha256, profile))
        return 3

    monkeypatch.setattr(session, "launch_burp", _launcher(killed))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure", record_configure)

    with session.session(an_engagement, instance="capture", jar=a_jar) as live:
        work = live.workdir
        assert live.epoch == 3, "the epoch is the extension's answer, not a constant"
        assert (work / "hx.sock").exists(), "the bridge is not listening"

    assert len(configured) == 1
    pairs, scope_sha256, profile = configured[0]
    assert pairs == session.config_body(an_engagement.config)
    assert scope_sha256 == session.stored_scope_sha256(
        an_engagement.db, an_engagement.id), (
        "the extension must be authorised against the hash the store RECORDED, "
        "never one recomputed from today's config")
    assert profile == an_engagement.config.safety_profile

    assert killed, "a clean exit left Burp running"
    assert not (work / "hx.sock").exists(), (
        "the bridge was not stopped on the clean path: the socket survives, "
        "the accept thread leaks, and the next `session()` on this engagement "
        "dies inside BridgeServer.start()")


def test_the_workdir_is_0o700_before_anything_else_tightens_it(
        monkeypatch, an_engagement, a_jar):
    """0o700 from creation, not 0o700 by the time anyone looks.

    MEASURING AFTER THE SESSION PROVES NOTHING, and that is the whole reason
    this test is shaped like a spy. `BridgeServer.start()` chmods its socket's
    parent -- which is this directory -- to 0o700 itself, so a session built
    with a plain `mkdir` at the umask (measured on this machine: 0o755) ends
    at 0o700 too and an assertion made afterwards passes either way.

    So the mode is read at the moment `start()` is ENTERED, before its own
    chmod. What that pins is that the directory never exists at a looser mode
    than 0o700 even for an instant, that its permissions do not depend on a
    side effect of an unrelated class, and that it is still 0o700 on the path
    where `start()` itself raises. The directory goes on to hold the private
    Burp home copied from the operator's own -- licence key included -- plus
    Burp's log and the bridge socket.
    """
    seen = {}
    real_start = session.BridgeServer.start

    def spying_start(self):
        seen["mode"] = stat.S_IMODE(self.socket_path.parent.stat().st_mode)
        return real_start(self)

    monkeypatch.setattr(session, "launch_burp", _launcher())
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure", lambda self, *a, **k: 1)
    monkeypatch.setattr(session.BridgeServer, "start", spying_start)

    with session.session(an_engagement, instance="capture", jar=a_jar):
        pass

    assert seen["mode"] == 0o700, (
        f"the session workdir was created at {oct(seen.get('mode', 0))}; it "
        "holds the Burp home copied from the operator's own")


def test_a_stale_bridge_socket_is_reported_and_never_removed(
        monkeypatch, an_engagement, a_jar):
    """`srv.start()` is inside the module's error contract, and only reports.

    A killed session leaves `hx.sock` behind and `BridgeServer.start()`
    refuses it "rather than adopt a path another process may own". That is a
    `BridgeError`, and it is raised OUTSIDE the `try` that turns everything
    else here into a `SessionError` -- so without the wrap it escapes a module
    whose entire exception contract is `SessionError` with a message naming
    the fix, and Task 7's CLI shows a traceback or learns about bridge
    internals to avoid one.

    The stale socket is left EXACTLY WHERE IT WAS. A socket that is still live
    belongs to a session that is still running, and unlinking another
    process's rendezvous to make an error go away is worse than the error.

    No monkeypatch stands in for the failure: the file is really there and
    `BridgeServer.start()` really refuses it. `launch_burp` is replaced only
    to make sure no JVM starts if the refusal ever stops happening.
    """
    launched = []

    def never_launched(*a, **k):
        launched.append(a)
        raise AssertionError("Burp was launched after the bridge failed to start")

    monkeypatch.setattr(session, "launch_burp", never_launched)

    work = an_engagement.root / "session" / "capture"
    work.mkdir(mode=0o700, parents=True)
    stale = work / "hx.sock"
    stale.write_bytes(b"")

    with pytest.raises(session.SessionError) as exc:
        with session.session(an_engagement, instance="capture", jar=a_jar):
            pass

    assert str(stale) in str(exc.value), "the message must name the path to remove"
    assert "did not shut down cleanly" in str(exc.value)
    assert stale.exists(), (
        "hx removed the socket. It must not: a live socket belongs to a "
        "session that is still running, and unlinking another process's "
        "rendezvous is worse than an error message")
    assert not launched


def test_the_seed_the_caller_names_reaches_the_launch(
        monkeypatch, an_engagement, a_jar, tmp_path):
    """Which Burp home gets copied travels IN THE CALL, and omitting it still
    means the operator's own.

    `make_home` copies `seed_home()` by default -- `$HX_BURP_SEED_HOME`, then
    `Path.home()` -- which is right for a consultant and wrong for a caller
    that has already checked a different home. `launch_burp` grew the
    parameter for that in Task 8; `session()` did not forward it, so its
    callers had only the environment variable, and an environment variable is
    a second answer to a question the parameter already answers.

    It is not hypothetical: `scripts/demo_capture.py` now runs through
    `session()` and GUARDS on `burp_fixture.missing()`, which reports on the
    lab's curated home. Unforwarded, the demo would check that home and copy
    the operator's live `~/.BurpSuite/sessions` -- real client project state.

    Both halves are here because either alone passes while the other is
    false: a `session()` that ignored `seed` outright, and one that resolved
    a default of its own instead of leaving `make_home` to own it.
    """
    seen: list[dict] = []

    def launch(socket_path, engagement_id, workdir, **kw):
        seen.append(kw)
        _write_listener_config(workdir)
        return _FakeProc()

    monkeypatch.setattr(session, "launch_burp", launch)
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure", lambda self, *a, **k: 1)

    lab_home = tmp_path / "lab" / "burphome"
    with session.session(an_engagement, instance="demo", jar=a_jar,
                         seed=lab_home):
        pass
    with session.session(an_engagement, instance="capture", jar=a_jar):
        pass

    named, omitted = seen
    assert named["seed"] == lab_home
    assert omitted["seed"] is None, (
        "an omitted seed must reach `make_home` as None so IT applies the "
        "operator's own home; a default resolved here would be a second "
        "answer to which home is copied")


# --- the composition: two sessions, one engagement ------------------------


def test_two_commands_hold_two_sessions_on_one_engagement(
        monkeypatch, an_engagement, a_jar):
    """F6 of the whole-branch review, and the workflow it broke.

    Both callers defaulted their workdir to `eng.root / "session"`, so `hx
    scan` run while `hx capture start` held a session open found the capture
    session's LIVE `hx.sock` and died inside `BridgeServer.start()`, which
    refuses to adopt a path another process may own. The message says "a
    previous one did not shut down cleanly", which is the wrong diagnosis
    for two commands each correctly owning their own Burp -- Plan 6's
    governing decision, and now the directory layout too.

    It was a deferred minor while `hx scan` stayed offline. `active_safe` is
    on by default and five active checks ship, so every default `hx scan`
    opens a session and this was the common path, not a corner of it.

    The bridge sockets here are REAL -- `BridgeServer.start()` binds them,
    and the collision this test is about happens in that bind. Only Burp is
    faked.
    """
    monkeypatch.setattr(session, "launch_burp", _launcher())
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure",
                        lambda self, *a, **k: 1)

    with session.session(an_engagement, instance="capture", jar=a_jar) as cap:
        with session.session(an_engagement, instance="scan", jar=a_jar) as scn:
            assert cap.workdir != scn.workdir
            assert (cap.workdir / "hx.sock").exists()
            assert (scn.workdir / "hx.sock").exists()
            # The engagement root's own rule is not relaxed to make room for
            # the extra level: S3 is unconditional.
            for d in (cap.workdir, scn.workdir, cap.workdir.parent):
                assert d.stat().st_mode & 0o777 == 0o700, d


def test_an_instance_that_is_not_one_path_segment_is_refused(
        monkeypatch, an_engagement, a_jar):
    """`instance` names a directory under the engagement root now, and that
    root is 0o700 and holds the private Burp home (licence key included) and
    the client's captured traffic. Refused rather than sanitised: rewriting
    the caller's string would make the directory and the `-Dhx.instance` the
    extension reports two different things.

    No JVM: the check is ahead of every side effect, which the launcher
    below proves by failing if it is ever reached.
    """
    monkeypatch.setattr(
        session, "launch_burp",
        lambda *a, **k: pytest.fail("Burp launched for a refused instance"))
    for bad in ("../elsewhere", "a/b", "", ".", ".."):
        with pytest.raises(session.SessionError) as exc:
            with session.session(an_engagement, instance=bad, jar=a_jar):
                pass
        assert "single path segment" in str(exc.value)



@pytest.fixture
def a_seed(tmp_path):
    """A Burp home with an accepted licence, standing in for the operator's.

    The twin of `tests/test_session_launch.py`'s and
    `tests/test_session_home.py`'s, for the same reason both of those exist:
    `make_home` runs FOR REAL in the test below, and a seed it was not handed
    is the operator's own `$HOME`.
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

    `launch_burp` runs its pre-flight for real below; `extension/build/` is
    gitignored, so without this the test would fail on a missing build product
    it is not about.
    """
    jar = tmp_path / "ext" / "build" / "hx-bridge.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"not really a jar; nothing here launches a JVM")
    src = tmp_path / "ext" / "src"
    src.mkdir(parents=True)
    monkeypatch.setattr(session, "EXT_JAR", jar)
    monkeypatch.setattr(session, "EXT_SRC", src)
    return jar


def test_two_sessions_in_a_row_on_one_engagement_both_start(
        monkeypatch, an_engagement, a_jar, a_seed, built_extension):
    """F1's composition, which nine task reviews and this file both missed.

    EVERY OTHER TEST HERE REPLACES `launch_burp`, so `make_home` never runs
    and the second call never meets the directory the first one left. This one
    replaces `subprocess.Popen` instead: `make_home` and
    `write_listener_config` are the product's, and the only thing that never
    happens is the JVM. Run twice, `hx capture start` exited 1 with EMPTY
    output and a bare `FileExistsError` -- not a `SessionError`, so
    `capture_start`'s handler missed it and click printed a traceback.

    `_free_port` is replaced rather than allowed to bind, so this file's
    promise that it opens no TCP socket still holds; it hands back the same
    two distinctive numbers the fake launcher above writes.

    The last assertion is the other half of F3. The copied home holds the
    operator's licence prefs and their whole `~/.BurpSuite` bar the browser,
    and `work` is inside the engagement directory a consultant archives or
    hands to a client -- so it must not outlive the session that needed it.
    """
    ports = iter([OPERATOR_PORT, CRAWLER_PORT] * 2)
    monkeypatch.setattr(session, "_free_port", lambda: next(ports))
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: _FakeProc())
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure", lambda self, *a, **k: 1)

    # WHAT A SIGKILL LEAVES. `session()`'s teardown never ran, so the previous
    # run's private home is still on disk -- and it is that state, not the
    # clean one, that bricked the command: one handshake timeout and every
    # later run on this engagement died on FileExistsError with no message.
    # Planted rather than produced, because producing it means killing a
    # session, and a test that kills a session is testing the killing.
    stale = an_engagement.root / "session" / "capture" / "burphome" / ".BurpSuite"
    stale.mkdir(parents=True)
    (stale / "left-by-a-killed-run").write_text("stale")

    homes = []
    for attempt in (1, 2):
        with session.session(an_engagement, instance="capture", jar=a_jar,
                             seed=a_seed) as live:
            home = live.workdir / "burphome"
            assert (home / ".BurpSuite" / "UserConfigCommunity.json").exists(), (
                f"session {attempt} did not get a private Burp home")
            assert not (home / ".BurpSuite" / "left-by-a-killed-run").exists(), (
                f"session {attempt} adopted the home a killed run left behind, "
                "including its .BurpSuite/sessions and its Java Preferences")
            assert (live.operator_port, live.crawler_port) == (
                OPERATOR_PORT, CRAWLER_PORT)
            homes.append(home)

    assert homes[0] == homes[1]
    assert not homes[1].exists(), (
        "the private Burp home outlived the session: the operator's licence "
        "prefs and Burp state are left inside the client's engagement "
        "directory, which is the thing a consultant archives")



def test_the_two_listeners_are_never_the_same_port(
        monkeypatch, an_engagement, a_jar, a_seed, built_extension):
    """F2, at the level that matters: what the session REPORTS.

    `Source.forListenerPort` is `port == crawlerPort ? CRAWLER : OPERATOR`, so
    a session that yielded one number for both would hand the consultant's own
    browser the agent's rule set -- POSTs dropped, dangerous paths denied, the
    rate limit and the budget applied -- none of which S4 applies to "traffic
    from the operator's own browser". Nothing downstream compares the two, and
    every guard in between passes on one port: `not_loopback_only` is asked
    about one listening port and finds it, the handshake completes, configure
    completes. So this is the comparison.

    `_free_port` is the REAL one here -- the only test in this file that binds
    anything -- because the draw is the thing under test. The ports are read
    back out of the config file the launch was handed, never out of the return
    value, so a `write_listener_config` that returned one pair and wrote
    another would fail here too.
    """
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: _FakeProc())
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure", lambda self, *a, **k: 1)

    with session.session(an_engagement, instance="capture", jar=a_jar,
                         seed=a_seed) as live:
        assert live.operator_port != live.crawler_port, (
            f"both listeners are :{live.operator_port}, so the extension reads "
            "the operator's own browsing as the crawler's")
        assert session.listener_ports(live.workdir) == [
            live.operator_port, live.crawler_port]


# --- S8: the session knows when it has stopped being one ------------------


class _Bridge:
    def __init__(self, state):
        self.state = state


class _Proc:
    def __init__(self, code=None):
        self.pid = 4242
        self._code = code

    def poll(self):
        return self._code


def _live(proc, bridge, tmp_path):
    return session.LiveSession(OPERATOR_PORT, CRAWLER_PORT, 1, bridge,
                               tmp_path, proc)


def test_a_live_session_is_live_while_burp_runs_and_the_extension_is_configured(
        tmp_path):
    assert _live(_Proc(), _Bridge("configured"), tmp_path).gone() is None
    # An operator halt is a LIVE session that has stopped issuing. Reading it
    # as a dead one would end the capture every time somebody touched the
    # sentinel, which S4 makes a path an operator can take from any shell.
    assert _live(_Proc(), _Bridge("halted"), tmp_path).gone() is None


def test_a_dead_burp_is_named_with_its_status_and_its_log(tmp_path):
    why = _live(_Proc(143), _Bridge("configured"), tmp_path).gone()
    assert why and "143" in why
    assert str(tmp_path / "burp.log") in why, (
        "the one thing an operator can act on is Burp's own log")


def test_an_extension_that_dropped_the_bridge_is_not_a_live_session(tmp_path):
    """A JVM that is still up while its extension has gone is NOT healthy.

    `BridgeServer._reset` puts the state back to `waiting` and the epoch back
    to 0 when the peer disconnects, so a reconnect lands at DENY-ALL: a Burp
    that looks alive, proxies nothing and records nothing -- the exact
    live-Burp-and-empty-database this module keeps designing out.
    """
    why = _live(_Proc(), _Bridge("waiting"), tmp_path).gone()
    assert why and "DENY-ALL" in why
