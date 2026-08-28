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

NO JVM IS STARTED HERE and no port is bound. `launch_burp`, `wait_for` and
`not_loopback_only` are all replaced; the only socket any test in this file
creates is the bridge's own AF_UNIX rendezvous inside `tmp_path`, which
`BridgeServer.start()` makes and `stop()` unlinks. The real thing is exercised
under `pytest -m integration`, against a real Burp, at about 200 seconds.
"""
from __future__ import annotations

import io
import json
import sqlite3
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
    with pytest.raises(session.SessionError):
        with session.session(an_engagement, instance="capture", jar=a_jar):
            pass
    assert killed, "configure failed and Burp was left running"


def test_listeners_that_are_not_loopback_only_refuse_the_session(
        monkeypatch, an_engagement, a_jar):
    killed = []
    monkeypatch.setattr(session, "launch_burp", _launcher(killed))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only",
                        lambda pid, ports: "8080 is bound to 0.0.0.0")
    with pytest.raises(session.SessionError) as exc:
        with session.session(an_engagement, instance="capture", jar=a_jar):
            pass
    assert "0.0.0.0" in str(exc.value)
    assert killed, "a session that refused to continue left Burp running"


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
