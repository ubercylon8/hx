import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path

import pytest

from hx import halt as halt_mod
from hx.bridge import codec, server
from hx.store import db as db_mod
from hx.store import records
from hx.store.paths import secure_mkdir


@pytest.fixture
def srv(tmp_path):
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1")
    s.start()
    yield s
    s.stop()


def _client(path):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(path))
    # Every blocking read in this file -- thirteen of them, bare c.recv() and
    # codec.FrameReader(c).read() alike -- goes through this helper. Without a
    # timeout, a server that never answers HANGS the run rather than failing
    # it: deleting the SO_PEERCRED uid check was measured wedging pytest
    # indefinitely. Sabotage is this project's review method, so a defect that
    # cannot report itself is a real cost.
    c.settimeout(5)
    return c


def _connected(srv):
    """Drive srv to state 'connected' and return the live client socket."""
    c = _client(srv.socket_path)
    c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                            "pid": 1, "burp_version": "x",
                            "instance_id": "i-1", "engagement_id": "e-1"}))
    deadline = time.time() + 5
    while srv.state != "connected" and time.time() < deadline:
        time.sleep(0.005)
    assert srv.state == "connected"
    return c


def test_socket_and_directory_permissions(tmp_path):
    s = server.BridgeServer(tmp_path / "sub" / "b.sock", engagement_id="e-1")
    s.start()
    try:
        assert stat.S_IMODE(s.socket_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(s.socket_path.parent.stat().st_mode) == 0o700
    finally:
        s.stop()


def test_stop_unlinks_the_socket(tmp_path):
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1")
    s.start()
    path = s.socket_path
    assert path.exists()
    s.stop()
    assert not path.exists()


def test_refuses_to_start_if_the_path_already_exists(tmp_path):
    p = tmp_path / "b.sock"
    p.write_text("squatter")
    s = server.BridgeServer(p, engagement_id="e-1")
    with pytest.raises(server.BridgeError, match="exists"):
        s.start()


def test_socket_path_for_uses_a_fresh_random_basename():
    a = server.socket_path_for("e-1")
    b = server.socket_path_for("e-1")
    assert a != b
    assert "e-1" in a.name and a.name.endswith(".sock")


def test_hello_moves_state_to_connected(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                "pid": os.getpid(), "burp_version": "2026.7.3",
                                "instance_id": "i-1", "engagement_id": "e-1"}))
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"
    finally:
        c.close()


def test_engagement_id_mismatch_is_fatal(srv):
    """Client A's traffic must never land in client B's store."""
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                "pid": os.getpid(), "burp_version": "x",
                                "instance_id": "i-1", "engagement_id": "SOMEONE-ELSE"}))
        assert c.recv(4096) == b"", "server should close the connection"
        assert srv.state == "waiting"
        assert srv.rejected_hellos == 1
    finally:
        c.close()


def test_protocol_version_mismatch_is_fatal(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 99, "t": "hello", "engagement_id": "e-1",
                                "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1"}))
        assert c.recv(4096) == b""
        assert srv.state == "waiting"
    finally:
        c.close()


def test_configure_round_trip_returns_an_epoch(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1",
                                "engagement_id": "e-1"}))
        # configure() must not race the accept-loop thread's processing of
        # the hello: without this wait, a thread scheduled early enough sees
        # state == "waiting", raises BridgeError internally (silently, since
        # nothing joins it before the assertion), and the main thread then
        # blocks forever below waiting for a request frame that was never
        # sent. Reproduced: roughly 1 run in 10 hung indefinitely.
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"
        result = {}

        def do_configure():
            result["epoch"] = srv.configure(
                {"scope.include": ["https://a/*"], "limit.rate_rps": ["5"]},
                scope_sha256="deadbeef", profile="production",
            )

        t = threading.Thread(target=do_configure)
        t.start()

        header, body = codec.FrameReader(c).read()
        assert header["t"] == "configure"
        assert header["engagement_id"] == "e-1"
        assert header["scope_sha256"] == "deadbeef"
        assert codec.parse_config_body(body)["scope.include"] == ["https://a/*"]

        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert result["epoch"] == 1
        assert srv.state == "configured"
    finally:
        c.close()


def test_configure_carries_id_and_deadline(srv):
    """Both are required on every request frame by the protocol document."""
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1",
                                "engagement_id": "e-1"}))
        # See test_configure_round_trip_returns_an_epoch: without waiting for
        # the hello to land, this races the accept-loop thread and can hang.
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"
        result = {}

        def do_configure():
            # The test never sends a "configured" ack, and closes the
            # connection in its finally below. _reset()'s wake-on-disconnect
            # (round 1) now surfaces that immediately as BridgeError, where
            # it previously just blocked for the full 10s timeout unnoticed --
            # that is the desired prompt-wakeup behaviour, not a bug. Catch it
            # here rather than let it become an unhandled thread exception.
            try:
                srv.configure({"scope.include": ["https://a/*"]},
                              scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                result["error"] = exc

        t = threading.Thread(target=do_configure)
        t.start()
        header, _ = codec.FrameReader(c).read()
        assert isinstance(header["id"], int) and header["id"] > 0
        assert isinstance(header["deadline_us"], int)
        assert header["deadline_us"] > time.time_ns() // 1000
    finally:
        c.close()
        t.join(timeout=5)
        assert not t.is_alive(), "do_configure thread never finished"
        assert "error" in result, "closing without an ack must raise BridgeError"


def test_configure_before_hello_is_refused(srv):
    """What the precondition holds back is real, not hypothetical: _serve()
    assigns self._conn BEFORE the hello is read, so an un-helloed peer is a
    perfectly good socket to write to. Driven directly, it received the
    engagement id, the scope_sha256 and every scope pattern.

    `match=` therefore names the WHOLE message. "not connected" on its own is
    also what _send() raises when self._conn is None, so with the precondition
    deleted this test still passed -- on the wrong raise, from two frames
    further down, after the scope had already gone out. The peer-receives-
    nothing assertion is the one that cannot be satisfied by the wrong raise
    at all.
    """
    c = _client(srv.socket_path)
    try:
        # Wait for the server to have accepted and stored the socket: that is
        # precisely the window in which only the precondition stands between a
        # caller and a scope on the wire.
        deadline = time.time() + 5
        while srv._conn is None and time.time() < deadline:
            time.sleep(0.005)
        assert srv._conn is not None, "the server should have accepted the connection"
        assert srv.state == "waiting", "no hello has been sent"

        with pytest.raises(server.BridgeError, match="cannot configure before hello"):
            srv.configure({"scope.include": ["https://SECRET/*"]},
                          scope_sha256="deadbeef", profile="production")

        # Nothing at all may have reached the peer. A short timeout, not the
        # helper's 5s: this asserts an absence, so the wait is pure cost.
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def test_reconnect_resets_to_deny_all(srv):
    """extensionData does not survive a Burp restart, so a reconnected
    extension is unconfigured no matter what the previous one knew."""
    c = _client(srv.socket_path)
    c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                            "burp_version": "x", "instance_id": "i-1",
                            "engagement_id": "e-1"}))
    deadline = time.time() + 5
    while srv.state != "connected" and time.time() < deadline:
        time.sleep(0.01)
    # Without this, the test passes even when hello handling is completely
    # broken: state never leaves "waiting", so the second poll's precondition
    # is already true. Verified by sabotage -- it passed in 5.22s with hello
    # handling entirely disabled.
    assert srv.state == "connected"
    c.close()

    deadline = time.time() + 5
    while srv.state != "waiting" and time.time() < deadline:
        time.sleep(0.01)
    assert srv.state == "waiting", "a dropped connection must return to DENY-ALL"
    assert srv.config_epoch == 0


def test_oversized_frame_from_the_peer_closes_the_connection(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall((codec.MAX_FRAME + 1).to_bytes(4, "big") + b"{}")
        assert c.recv(4096) == b""
    finally:
        c.close()


def test_peer_credentials_are_recorded(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                "pid": os.getpid(), "burp_version": "x",
                                "instance_id": "i-1", "engagement_id": "e-1"}))
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.peer_uid == os.getuid()
        assert srv.peer_pid > 0
    finally:
        c.close()


def test_configure_ack_then_immediate_disconnect_ends_in_deny_all(srv):
    """Critical, fix round 1: configure() wrote self.state = "configured" and
    self.config_epoch from the caller's thread with no ordering against
    _reset() on the accept thread. A peer that acks configure and immediately
    disconnects could leave state="configured" with no peer attached at all --
    falsifying DENY-ALL as the terminal state. Reproduced 59/60 runs before
    the generation-token fix, so this loops enough times to be meaningful.
    """
    for _ in range(60):
        c = _client(srv.socket_path)
        try:
            c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                    "pid": 1, "burp_version": "x",
                                    "instance_id": "i-1", "engagement_id": "e-1"}))
            deadline = time.time() + 5
            while srv.state != "connected" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "connected"

            result = {}

            def do_configure():
                try:
                    result["epoch"] = srv.configure(
                        {"scope.include": ["https://a/*"]},
                        scope_sha256="x", profile="production",
                    )
                except server.BridgeError as exc:
                    result["error"] = exc

            t = threading.Thread(target=do_configure)
            t.start()

            header, _ = codec.FrameReader(c).read()
            c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                    "config_epoch": 1}))
            c.close()
            t.join(timeout=5)
            assert not t.is_alive(), "do_configure thread never finished"

            deadline = time.time() + 5
            while srv.state != "waiting" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "waiting", (
                "a peer that acked configure and vanished must not leave the "
                f"bridge looking configured (result={result!r})"
            )
            assert srv.config_epoch == 0
        finally:
            try:
                c.close()
            except OSError:
                pass


def test_late_reply_after_timeout_does_not_leak_into_replies(srv):
    """Important, fix round 1: _deliver used to record a reply before checking
    whether anyone was waiting for it. A reply that arrives after its caller
    gave up left an entry nothing ever collects -- unbounded growth on a
    bridge meant to run for a whole engagement."""
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1",
                                "engagement_id": "e-1"}))
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"

        with pytest.raises(server.BridgeError, match="no reply"):
            srv._request({"v": 1, "t": "configure", "engagement_id": "e-1"},
                         timeout=0.1)

        # Only now does the peer read and ack the request the server already
        # gave up waiting on.
        header, _ = codec.FrameReader(c).read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        time.sleep(0.3)  # give the late reply a chance to be (mis)handled
        assert srv._replies == {}, "a reply nobody awaits must not be recorded"
    finally:
        c.close()


def test_so_peercred_rejects_a_foreign_uid(srv, monkeypatch):
    """The one security-critical branch in the file, previously uncovered.
    Cannot actually connect as another uid in a test, so fake the credential
    lookup SO_PEERCRED reports."""
    real_getsockopt = socket.socket.getsockopt

    def fake_getsockopt(self, level, optname, buflen=0):
        if optname == socket.SO_PEERCRED:
            return struct.pack("3i", 12345, os.getuid() + 1, os.getgid())
        return real_getsockopt(self, level, optname, buflen)

    monkeypatch.setattr(socket.socket, "getsockopt", fake_getsockopt)

    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                "pid": os.getpid(), "burp_version": "x",
                                "instance_id": "i-1", "engagement_id": "e-1"}))
        # The server closes without ever reading the hello it left unread in
        # its receive buffer, so Linux resets the connection (RST) rather
        # than closing it cleanly (FIN) -- both mean "never served".
        try:
            data = c.recv(4096)
        except ConnectionResetError:
            data = b""
        assert data == b"", "a foreign uid must never be served"
        time.sleep(0.2)
        assert srv.state == "waiting"
    finally:
        c.close()


def test_configure_refuses_to_commit_when_a_reset_ran_in_the_gap(srv):
    """The whole point of the guard, deterministically: no threads, no sleeps.
    The stub performs the disconnect inside the window between _request()
    returning and configure()'s commit."""
    c = _connected(srv)
    try:
        def stub_request(header, body=b""):
            srv._reset(srv._generation)
            return {"v": 1, "t": "configured", "id": 1, "config_epoch": 7}
        srv._request = stub_request

        with pytest.raises(server.BridgeError,
                           match="peer disconnected before configure completed"):
            srv.configure({"scope.include": ["https://a/*"]},
                          scope_sha256="x", profile="production")
        assert srv.state == "waiting"
        assert srv.config_epoch == 0
    finally:
        c.close()


def test_configure_refuses_to_commit_when_the_socket_slot_was_refilled(srv):
    """Deliberately white-box, and the only test that isolates the generation
    token. It refills self._conn without going through accept(), so the
    `_conn is None` clause cannot fire and only `gen != self._generation`
    is left to catch the stale commit. Delete `self._generation += 1` from
    _reset() and this test fails; that is what it exists for."""
    c = _connected(srv)
    successor, other = socket.socketpair()
    try:
        def stub_request(header, body=b""):
            srv._reset(srv._generation)
            srv._conn = successor          # slot refilled: _conn is NOT None
            return {"v": 1, "t": "configured", "id": 1, "config_epoch": 7}
        srv._request = stub_request

        with pytest.raises(server.BridgeError,
                           match="peer disconnected before configure completed"):
            srv.configure({"scope.include": ["https://a/*"]},
                          scope_sha256="x", profile="production")
        assert srv.state == "waiting"
        assert srv.config_epoch == 0
    finally:
        srv._conn = None
        successor.close()
        other.close()
        c.close()


def test_reset_advances_the_generation_it_guards_on(srv):
    """The invariant is internal, so test it internally rather than pretend a
    black-box test can see it."""
    g0 = srv._generation
    srv._reset(g0)
    assert srv._generation > g0, "a real reset must advance the generation"

    g1 = srv._generation
    srv.state = "configured"
    srv.config_epoch = 9
    srv._reset(g0)                          # stale token: must be a no-op
    assert srv._generation == g1
    assert srv.state == "configured" and srv.config_epoch == 9


def test_halt_and_resume_refuse_to_commit_after_a_reset_in_the_gap(srv):
    """halt()/resume() have the same send-then-mutate shape as configure(),
    so they get the same test. Without this, the guard on them is unexercised
    by the whole suite."""
    for method, message in (
        (lambda: srv.halt("operator"), "peer disconnected before halt completed"),
        (lambda: srv.resume(), "peer disconnected before resume completed"),
    ):
        c = _connected(srv)
        try:
            def stub_send(header, body=b""):
                srv._reset(srv._generation)
            srv._send = stub_send

            with pytest.raises(server.BridgeError, match=message):
                method()
            assert srv.state == "waiting"
        finally:
            del srv._send          # fall back to the real bound method
            c.close()


def test_halt_and_resume_commit_on_the_happy_path(srv):
    c = _connected(srv)
    try:
        srv.halt("operator asked")
        assert srv.state == "halted"
        reader = codec.FrameReader(c)
        header, _ = reader.read()
        assert header["t"] == "halt" and header["reason"] == "operator asked"

        srv.resume()
        assert srv.state == "connected"     # no config_epoch yet
        header, _ = reader.read()
        assert header["t"] == "resume"
    finally:
        c.close()


def test_configure_never_leaves_a_lying_state_under_stress(srv, monkeypatch):
    """Round 2: the generation token read _generation as a guard but never
    advanced it, so it only detected "a NEW connection superseded an old
    one". It could not detect THIS connection resetting between _request()
    returning and configure()'s commit -- the caller still saw
    gen == self._generation and clobbered the "waiting" _reset() had just
    written. The natural-timing test above measured 0/60 for this because the
    accept thread happens to win that inner race on this machine -- favourable
    scheduling, not a closed gap. This closes the window instead of relying
    on timing: it delays configure()'s resumption after
    _request() returns, giving the accept thread's _reset() every chance to
    run to completion first, and asserts configure() detects it rather than
    silently committing over it.
    """
    real_request = server.BridgeServer._request

    def delayed_request(self, *args, **kwargs):
        reply = real_request(self, *args, **kwargs)
        time.sleep(0.08)  # matches the ~80ms window the reviewer used
        return reply

    monkeypatch.setattr(server.BridgeServer, "_request", delayed_request)

    for _ in range(20):
        c = _client(srv.socket_path)
        try:
            c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                    "pid": 1, "burp_version": "x",
                                    "instance_id": "i-1", "engagement_id": "e-1"}))
            deadline = time.time() + 5
            while srv.state != "connected" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "connected"

            result = {}

            def do_configure():
                try:
                    result["epoch"] = srv.configure(
                        {"scope.include": ["https://a/*"]},
                        scope_sha256="x", profile="production",
                    )
                except server.BridgeError as exc:
                    result["error"] = exc

            t = threading.Thread(target=do_configure)
            t.start()

            header, _ = codec.FrameReader(c).read()
            c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                    "config_epoch": 1}))
            # Close now, while do_configure is still asleep inside the
            # widened window: the accept thread's _reset() must run and
            # complete (including advancing the generation) well before
            # do_configure wakes up to commit.
            c.close()
            t.join(timeout=5)
            assert not t.is_alive(), "do_configure thread never finished"

            assert "error" in result, (
                "configure() must detect a disconnect that happened during "
                f"its widened commit window, not silently succeed (result={result!r})"
            )
            # Whichever mechanism fires, the forbidden outcome is the same:
            # state that claims a peer the server no longer has.
            assert not (srv.state == "configured" and srv._conn is None), (
                f"lying state after a disconnect mid-configure (result={result!r})"
            )

            deadline = time.time() + 5
            while srv.state != "waiting" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "waiting", (
                f"a disconnect during configure()'s commit window must not "
                f"leave the bridge looking configured (result={result!r})"
            )
            assert srv.config_epoch == 0
        finally:
            try:
                c.close()
            except OSError:
                pass


def test_an_error_reply_to_configure_reports_what_the_peer_said(srv):
    c = _connected(srv)
    try:
        out = {}

        def go():
            try:
                srv.configure({"scope.include": ["https://a/*"]},
                              scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out["err"] = str(exc)

        t = threading.Thread(target=go)
        t.start()
        header, _ = codec.FrameReader(c).read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "engagement_mismatch",
                                "detail": "e-1 != SOMEONE-ELSE"}))
        t.join(timeout=5)
        assert not t.is_alive()

        assert "engagement_mismatch" in out["err"], out
        assert "SOMEONE-ELSE" in out["err"], out
        assert "without a config_epoch" not in out["err"], out
    finally:
        c.close()


def test_a_refused_reconfigure_returns_this_side_to_deny_all(srv):
    """The extension answers a refused configure by dropping to DENY-ALL at
    epoch 0 -- it discards the scope it was already holding. If this side went
    on reporting state='configured' epoch=1 the two ends of the bridge would
    disagree about whether anything may be sent, and this is the end operators
    and the CLI read."""
    c = _connected(srv)
    reader = codec.FrameReader(c)
    out = {}

    def configure_into(key):
        def run():
            try:
                out[key] = srv.configure({"scope.include": ["https://a/*"]},
                                         scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out[key] = exc
        return run

    try:
        # A first configure that IS acknowledged: epoch 1, state 'configured'.
        t = threading.Thread(target=configure_into("first"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["first"] == 1, out
        assert srv.state == "configured"
        assert srv.config_epoch == 1

        # The second is refused. An operator NARROWING scope with a key the
        # installed extension predates is the likeliest way to land here, so
        # the wider epoch-1 scope is exactly what must not survive.
        t = threading.Thread(target=configure_into("second"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "bad_config",
                                "detail": "unknown key scope.exclude_ports"}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert isinstance(out["second"], server.BridgeError), out
        assert "bad_config" in str(out["second"]), out

        assert srv.state == "connected", (
            "the peer is at DENY-ALL after refusing the configure; this side "
            f"must not go on claiming {srv.state!r}"
        )
        assert srv.config_epoch == 0, srv.config_epoch
    finally:
        c.close()


def test_send_serialises_concurrent_writers(srv):
    """_send() wrote the socket with no mutex at all, while its Java
    counterpart is a deliberate `private synchronized void send`. Two threads
    inside one sendall() splice two frames together on the wire and the peer
    then decodes neither -- and every write on this side is a control frame:
    halt, resume, configure.

    Deterministic rather than scheduler-dependent. The stand-in socket parks
    halfway through each write, which is exactly what a real sendall() does
    when the socket buffer fills mid-frame, and both writers meet at a barrier
    IF the code lets them be inside at once. Serialised, the first writer
    breaks the barrier on its timeout and the second sails straight through.
    """
    chunks: list[bytes] = []
    gate = threading.Barrier(2, timeout=0.5)
    state_lock_was_free = []

    class SplittingConn:
        def sendall(self, data):
            half = len(data) // 2
            chunks.append(data[:half])
            # Parked mid-frame. The state mutex must NOT be held here: this
            # lock has to be a separate one, or a blocking send stalls the
            # _deliver() that wakes the _request() waiting on this very frame.
            free = srv._lock.acquire(blocking=False)
            if free:
                srv._lock.release()
            state_lock_was_free.append(free)
            try:
                gate.wait()
            except threading.BrokenBarrierError:
                pass
            chunks.append(data[half:])

    srv._conn = SplittingConn()
    try:
        # Two frames of DIFFERENT lengths, so a spliced wire cannot decode by
        # luck: frame one's length prefix would then span frame two's bytes.
        writers = [
            threading.Thread(target=srv._send, args=(
                {"v": 1, "t": "halt", "reason": "a" * 200},)),
            threading.Thread(target=srv._send, args=(
                {"v": 1, "t": "resume"},)),
        ]
        for w in writers:
            w.start()
        for w in writers:
            w.join(timeout=10)
            assert not w.is_alive()

        assert all(state_lock_was_free), (
            "the send mutex must be separate from self._lock: holding the state "
            "mutex across a blocking sendall() stalls _deliver()"
        )

        wire = b"".join(chunks)
        first, _, consumed = codec.decode(wire)
        second, _, _ = codec.decode(wire[consumed:])
        assert {first["t"], second["t"]} == {"halt", "resume"}, (
            f"two writers spliced their frames together on the wire: {wire!r}"
        )
    finally:
        srv._conn = None


def test_a_configure_does_not_lift_a_halt(srv):
    """An operator halts BECAUSE the scope went wrong, then pushes the
    corrected scope -- the most likely next action there is. Writing
    state="configured" over "halted" here re-armed issuance with no `resume`
    on the wire, no log line, and both consoles reading "configured". Only
    resume() may lift a halt.

    The other half is just as load-bearing: the scope and the epoch must still
    commit. Narrowing scope during an emergency stop is exactly what an
    operator should be able to do, which is why "halted" stays in configure()'s
    accepted-state tuple rather than being refused outright. A configure
    re-authorises SCOPE, not ISSUANCE. The extension half of this lives in
    BridgeClientTest.aConfigureDoesNotLiftAHalt().
    """
    c = _connected(srv)
    reader = codec.FrameReader(c)
    out = {}

    def configure_into(key, pattern):
        def run():
            try:
                out[key] = srv.configure({"scope.include": [pattern]},
                                         scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out[key] = exc
        return run

    try:
        t = threading.Thread(target=configure_into("first", "https://WIDE/*"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["first"] == 1, out
        assert srv.state == "configured"

        srv.halt("scope was wrong")
        header, _ = reader.read()
        assert header["t"] == "halt"
        assert srv.state == "halted"

        # The corrected, NARROWER scope, pushed while halted.
        t = threading.Thread(target=configure_into("second", "https://NARROW/*"))
        t.start()
        header, body = reader.read()
        assert header["t"] == "configure"
        assert codec.parse_config_body(body)["scope.include"] == ["https://NARROW/*"]
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 2}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["second"] == 2, out

        assert srv.state == "halted", (
            "a configure frame must not lift an operator halt; only resume() may"
        )
        assert srv.config_epoch == 2, (
            "the corrected scope must still commit -- narrowing scope during an "
            "emergency stop is exactly what an operator should be able to do"
        )

        # resume() is the frame that IS allowed to re-arm issuance, and it
        # returns to "configured" under the epoch-2 scope.
        srv.resume()
        header, _ = reader.read()
        assert header["t"] == "resume"
        assert srv.state == "configured"
        assert srv.config_epoch == 2
    finally:
        c.close()


def test_a_non_denying_configure_error_leaves_state_alone(srv):
    """engagement_mismatch and bad_frame answer error but leave the extension
    configured and live -- unlike bad_config and protocol_mismatch, which
    call denyAll() before answering. Resetting THIS side for those two would
    make it report state='connected', config_epoch=0 while the extension is
    still configured and sending: the reverse of the disagreement the reset
    exists to fix, and the more dangerous direction, since the operator's
    console would then say nothing may be sent while it can.

    Unreachable through a real client today -- a mismatched engagement_id is
    rejected at hello, and _request() always stamps deadline_us -- so this
    needs a version-skewed jar, the same scenario the plan names for
    bad_config. Reached here directly, the same way
    test_an_error_reply_to_configure_reports_what_the_peer_said reaches its
    own class string."""
    c = _connected(srv)
    reader = codec.FrameReader(c)
    out = {}

    def configure_into(key):
        def run():
            try:
                out[key] = srv.configure({"scope.include": ["https://a/*"]},
                                         scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out[key] = exc
        return run

    try:
        # A first configure that IS acknowledged: epoch 1, state 'configured'.
        t = threading.Thread(target=configure_into("first"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["first"] == 1, out
        assert srv.state == "configured"
        assert srv.config_epoch == 1

        # A second configure is refused, but with a class the extension does
        # NOT deny for.
        t = threading.Thread(target=configure_into("second"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "engagement_mismatch",
                                "detail": "e-1 != e-2"}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert isinstance(out["second"], server.BridgeError), out
        assert "engagement_mismatch" in str(out["second"]), out

        assert srv.state == "configured", (
            "the extension is still configured and live after this class of "
            f"refusal; this side must not go on claiming {srv.state!r}"
        )
        assert srv.config_epoch == 1, srv.config_epoch
    finally:
        c.close()


# ---- the send path, the halted frame, and the durable halt ----------------
#
# Everything below drives a REAL OperatorHalt against a real engagement
# database. A stub would hide the guarantee these tests exist for: the bridge
# reads `halted` and `reason` from its read thread, and the store connection
# they would otherwise touch belongs to another thread entirely.


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "engagement"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES('e-1','Example','Example Ltd',1,'active')")
    conn.execute("INSERT INTO run(id, engagement_id, kind, safety_profile,"
                 " started_us, status)"
                 " VALUES('r-1','e-1','manual','production',1700000000000000,"
                 "'running')")
    yield root, conn
    conn.close()


@pytest.fixture
def srv_with_halt(tmp_path, store):
    root, conn = store
    oh = halt_mod.OperatorHalt(root, conn)
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1",
                            operator_halt=oh)
    s.start()
    yield s, oh, conn
    s.stop()


def _hello(c, engagement_id="e-1"):
    c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                            "pid": os.getpid(), "burp_version": "2026.7.3",
                            "instance_id": "i-1",
                            "engagement_id": engagement_id}))


def _await(predicate, message, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError(message)


def _configured(s, c):
    """hello plus one acknowledged configure. Returns the peer's reader."""
    reader = codec.FrameReader(c)
    _hello(c)
    _await(lambda: s.state == "connected", "the hello never landed")
    out = {}

    def go():
        try:
            out["epoch"] = s.configure(
                {"scope.include": ["https://app.example.test/*"]},
                scope_sha256="a" * 64, profile="production")
        except server.BridgeError as exc:
            out["err"] = exc

    t = threading.Thread(target=go)
    t.start()
    header, _ = reader.read()
    c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                            "config_epoch": 1}))
    t.join(timeout=5)
    assert out.get("epoch") == 1, out
    return reader


# Real bytes, loopback-shaped hostname, real header names. Nothing in this
# project has ever sent a request off the machine and these tests do not
# either: the peer is a socket in tmp_path.
REQ = b"GET /api/orders?page=2 HTTP/1.1\r\nHost: app.example.test\r\n\r\n"
RESP = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Set-Cookie: session={{observed:set-cookie}}; HttpOnly\r\n\r\n"
        b'{"orders":[]}')


def test_send_returns_the_result_frame_and_its_body(srv_with_halt):
    """The body is the point. A result frame's bytes are the redacted response
    -- the evidence about to be hashed into the blob store -- and _deliver()
    used to hand back the header alone and drop them."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}
        t = threading.Thread(target=lambda: out.update(reply=s.send(
            {"target_host": "app.example.test", "target_port": 443,
             "tls": True, "identity_id": None}, REQ)))
        t.start()

        header, body = reader.read()
        assert header["t"] == "send"
        assert header["engagement_id"] == "e-1", (
            "S6: every send carries the engagement id and the extension "
            "refuses a mismatch"
        )
        assert header["target_host"] == "app.example.test"
        assert isinstance(header["id"], int) and header["id"] > 0
        assert header["deadline_us"] > time.time_ns() // 1000
        assert body == REQ, "the request bytes travel verbatim in the body"

        c.sendall(codec.encode({"v": 1, "t": "result", "id": header["id"],
                                "status": 200, "bytes": len(RESP), "ms": 42,
                                "outcome": "ok", "config_epoch": 1}, RESP))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["reply"]["status"] == 200
        assert out["reply"]["config_epoch"] == 1
        assert out["reply"][server.BridgeServer.BODY_KEY] == RESP
    finally:
        c.close()


def test_a_status_unreadable_result_reaches_the_store_unchanged(srv_with_halt):
    """The first consumer of a wire value added one commit before this task.

    S6 keeps `status` at the conservative sentinel 599 so S4's auto-halt
    counts it as an error, and moves the distinction to `outcome`. The wire
    value and exchange.outcome's value are deliberately the SAME STRING, so
    what this asserts is that no mapping layer appeared between them -- the
    frame's own outcome goes into the row, and the row can still be told
    apart from a peer that genuinely answered 599.

    The body on that frame says `HTTP/1.1 200 OK`, because that is the case
    that made the field necessary: eight interim heads then a 200.
    """
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}
        t = threading.Thread(target=lambda: out.update(reply=s.send(
            {"target_host": "app.example.test"}, REQ)))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "result", "id": header["id"],
                                "status": 599, "bytes": len(RESP), "ms": 42,
                                "outcome": "status_unreadable",
                                "config_epoch": 1}, RESP))
        t.join(timeout=5)
        reply = out["reply"]
        assert reply["status"] == 599
        assert reply["outcome"] == "status_unreadable"

        row_id = records.record_exchange(
            conn, run_id="r-1", method="GET",
            url="https://app.example.test/api/orders?page=2",
            status=reply["status"], outcome=reply["outcome"],
            req_blob="a" * 64, resp_blob="b" * 64, ms=reply["ms"],
            at_us=1700000000000000,
            resp_len=len(reply[server.BridgeServer.BODY_KEY]))
        row = conn.execute("SELECT status, outcome FROM exchange WHERE id=?",
                           (row_id,)).fetchone()
        assert (row["status"], row["outcome"]) == (599, "status_unreadable")
        assert b"HTTP/1.1 200 OK" in reply[server.BridgeServer.BODY_KEY], (
            "the exchange this outcome exists for is one whose own evidence "
            "contradicts its status"
        )
    finally:
        c.close()


def test_send_raises_the_peers_class_and_its_retry_hint(srv_with_halt):
    """S6 makes the class load-bearing for the agent: rate_limited means slow
    down and retry, the three *_denied classes mean the answer will not
    change, budget_exhausted means the run is over. A caller that only got a
    message string would have to parse English to tell them apart."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}

        def go():
            try:
                s.send({"target_host": "app.example.test"}, REQ)
            except server.BridgeError as exc:
                out["err"] = exc

        t = threading.Thread(target=go)
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "rate_limited",
                                "detail": "5 rps, 200000us to the next slot",
                                "retry_after_us": 200_000}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["err"].error_class == "rate_limited"
        assert out["err"].retry_after_us == 200_000
        assert "5 rps" in str(out["err"])
        # And it is a class the store can actually record, which is the other
        # half of "denials are never silent".
        assert records.DENIAL_KIND[out["err"].error_class] == "rate"
    finally:
        c.close()


def test_send_never_retries(srv_with_halt):
    """S6: a replayed state-changing request is worse than a failed one. One
    call, one frame on the wire, whatever the answer was."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}

        def go():
            try:
                s.send({"target_host": "app.example.test"}, REQ)
            except server.BridgeError as exc:
                out["err"] = exc

        t = threading.Thread(target=go)
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "transport_error",
                                "detail": "connection reset"}))
        t.join(timeout=5)
        assert out["err"].error_class == "transport_error"

        # Nothing else may arrive. A short timeout, not the helper's 5s: this
        # asserts an absence, so the wait is pure cost.
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            reader.read()
    finally:
        c.close()


def test_an_in_flight_send_fails_with_bridge_lost(srv_with_halt):
    """S6 names bridge_lost as distinct from timeout: the peer went away, the
    request may or may not have been issued, and nothing may replay it."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    reader = _configured(s, c)
    out = {}

    def go():
        try:
            s.send({"target_host": "app.example.test"}, REQ)
        except server.BridgeError as exc:
            out["err"] = exc

    t = threading.Thread(target=go)
    t.start()
    reader.read()          # the send frame is on the wire and unanswered
    c.close()
    t.join(timeout=5)
    assert not t.is_alive(), "the caller was left blocked on a dead peer"
    assert out["err"].error_class == "bridge_lost"


def test_a_send_nobody_answers_fails_with_timeout(srv_with_halt):
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.2)
        assert exc.value.error_class == "timeout", (
            "a peer that is alive and slow is not a peer that vanished"
        )
        assert exc.value.retry_after_us is None
    finally:
        c.close()


def test_send_before_configure_never_reaches_the_wire(srv_with_halt):
    """DENY-ALL is the initial state on both sides. The extension would refuse
    this too -- but a request that was never framed cannot be issued by a
    version-skewed jar either."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _hello(c)
        _await(lambda: s.state == "connected", "the hello never landed")
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ)
        assert exc.value.error_class == "not_configured"

        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def test_send_refuses_a_caller_supplied_engagement_id(srv_with_halt):
    """Client A's traffic must never land in client B's store, and the id on
    the frame is what the extension checks. A caller able to overwrite it
    would be addressing whichever extension answered."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        with pytest.raises(server.BridgeError, match="engagement_id"):
            s.send({"target_host": "app.example.test",
                    "engagement_id": "SOMEONE-ELSE"}, REQ)
    finally:
        c.close()


@pytest.mark.parametrize("key,value", [
    ("v", 99), ("t", "halt"), ("id", 1), ("deadline_us", 1),
    ("engagement_id", "SOMEONE-ELSE"),
])
def test_send_refuses_every_key_it_stamps_itself(srv_with_halt, key, value):
    """`**req` is spliced over the frame this method builds, so a caller's key
    WINS. Without the guard, `t` alone turns a send into a halt frame the
    extension acts on and nobody correlates, `v` gets answered
    protocol_mismatch and drops the channel, and `id` collides with a live
    correlation id so one of the two callers collects the other's reply.

    Refused rather than silently overwritten: a caller who set one of these
    believed something would happen, and quietly doing something else is how
    a scan ends up addressing an extension nobody meant to address.
    """
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test", key: value}, REQ)
        assert exc.value.error_class is None, (
            "a malformed call is a harness bug, not a denial the store should "
            "file a row for"
        )
        assert key in str(exc.value)
        # And nothing reached the wire: the guard runs before _request().
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def test_a_halted_frame_stops_issuance_and_aborts_the_run(srv_with_halt):
    """S6's unsolicited `halted` frame, {reason, host, window}, no id. Without
    it an auto-halt is invisible until the next send fails and
    `run.status = aborted` has no stop_reason to record.

    THIS TEST IS THE REFERENCE HARNESS. Plan 4's tool layer copies the shape
    of the `on_halted` handling below, so the shape has to be the safe one.

    It used to call `abort_run` and stop there, and `abort_run` alone does not
    survive the connection the frame arrived on. Measured against a live
    bridge with only that call:

        after the halted frame:  state='halted'   operator_halt.halted=False
        after _reset():          state='waiting'  operator_halt.halted=False
        next send refused as 'not_configured' -- DENY-ALL, not the halt
        run.status='aborted'  <- the only survivor, and nothing on the send
                                 path consults it

    So a reconnect and a fresh configure re-armed issuance after an auto-halt.
    That the `halted` arm does not make the stop durable by itself is
    defensible and is NOT changed here -- S4 scopes durability to an OPERATOR
    halt, and the arm's own comment defers it. What is fixed is the pattern
    this test hands to Plan 4: the harness calls `oh.halt()` beside
    `abort_run`, and the assertions below fail if that line is ever dropped.
    """
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        seen = []
        # The callback runs on the READ THREAD, so it may not touch this
        # store's connection: it belongs to this thread. Hand the frame over
        # and do the writing here -- which is what a harness must do too.
        s.on_halted = seen.append

        c.sendall(codec.encode({"v": 1, "t": "halted",
                                "reason": "5xx rate 0.40",
                                "host": "app.example.test",
                                "window": "50 requests / 37s"}))
        _await(lambda: s.state == "halted", "the halted frame was ignored")
        _await(lambda: seen, "on_halted never fired")

        frame = seen[0]
        assert s.last_halted == frame, (
            "a harness with no callback installed still has to be able to see "
            "why issuance stopped"
        )
        stop_reason = (f"{frame['reason']} on {frame['host']} "
                       f"({frame['window']})")
        assert records.abort_run(conn, run_id="r-1", at_us=1700000000900000,
                                 stop_reason=stop_reason) is True
        row = conn.execute("SELECT status, stop_reason FROM run WHERE id='r-1'"
                           ).fetchone()
        assert row["status"] == "aborted"
        assert row["stop_reason"] == ("5xx rate 0.40 on app.example.test "
                                      "(50 requests / 37s)")
        # The line that makes the stop outlive this connection. `abort_run`
        # writes the run's epitaph; only this writes the sentinel and the row
        # the next Burp start reads. Both, or the auto-halt lasts exactly as
        # long as the socket it arrived on.

        oh.halt(f"target distress: {stop_reason}")

        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted"

        # And the same refusal after the connection goes away, which is what
        # made the missing line matter: `state` is back to DENY-ALL and a
        # configure would lift that, but the sentinel is what send() consults
        # first. Without oh.halt() above this is 'not_configured' -- a refusal
        # the next configure clears.
        s._reset()
        assert s.state == "waiting"
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted", (
            "an auto-halt the harness recorded must still refuse after the "
            f"connection it arrived on is gone; this was {exc.value.error_class!r}"
        )
        assert oh.sentinel_path.exists()
        assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True, (
            "the next Burp start reads the store and the file; run.status="
            "'aborted' is not something the send path consults"
        )
    finally:
        c.close()


def test_a_halted_callback_that_throws_drops_to_deny_all(srv_with_halt):
    """The callback is what makes an auto-halt durable. If it threw, nothing
    was recorded, and carrying on beside a peer whose stop nobody wrote down
    is the one thing DENY-ALL exists to prevent."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)

        def boom(header):
            raise RuntimeError("the store is gone")

        s.on_halted = boom
        c.sendall(codec.encode({"v": 1, "t": "halted", "reason": "5xx rate 0.40",
                                "host": "app.example.test",
                                "window": "50 requests / 37s"}))
        _await(lambda: s.state == "waiting",
               "a throwing on_halted must close the connection")
        assert isinstance(s.halted_callback_error, RuntimeError)
    finally:
        c.close()


def test_a_durable_halt_is_reasserted_before_any_configure(srv_with_halt):
    """The task this whole module exists for.

    Two findings from the Plan 2 review meet here: a second `hello` erased the
    halt, and a halt did not survive a Burp restart -- precisely when someone
    has already hit stop. The assertion is about ORDER ON THE WIRE, not about
    state afterwards: a harness pushes scope from on_hello, so a re-assert
    that happened after that callback would leave the extension configured and
    armed for the length of a round trip.

    The second half is just as load-bearing. The configure still commits its
    scope and its epoch -- narrowing scope during an emergency stop is exactly
    what an operator should be able to do -- and it does NOT re-arm issuance.
    """
    s, oh, conn = srv_with_halt
    oh.halt("client called: stop everything")

    threads = []
    out = {}

    def push_scope():
        try:
            out["epoch"] = s.configure(
                {"scope.include": ["https://app.example.test/*"]},
                scope_sha256="b" * 64, profile="production")
        except server.BridgeError as exc:
            out["err"] = exc

    def on_hello(header):
        # Appended BEFORE start(): t.start() can be preempted the instant the
        # new thread runs, and the main thread below is fast enough to reach
        # threads[0] first. Measured as an IndexError under a full-suite run.
        t = threading.Thread(target=push_scope)
        threads.append(t)
        t.start()

    s.on_hello = on_hello

    c = _client(s.socket_path)
    try:
        reader = codec.FrameReader(c)
        _hello(c)

        first, _ = reader.read()
        assert first["t"] == "halt", (
            "a reconnecting extension must be told it is still halted BEFORE "
            f"it is handed a scope; the first frame it received was {first!r}"
        )
        assert first["reason"] == "client called: stop everything"

        second, body = reader.read()
        assert second["t"] == "configure"
        assert codec.parse_config_body(body)["scope.include"] == \
            ["https://app.example.test/*"]
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": second["id"],
                                "config_epoch": 4}))
        threads[0].join(timeout=5)
        assert out.get("epoch") == 4, out

        assert s.state == "halted", (
            "a configure re-authorises scope, never issuance; only resume does"
        )
        assert s.config_epoch == 4, "the corrected scope must still commit"
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted"
    finally:
        c.close()


def test_a_reset_never_clears_the_durable_halt(srv_with_halt):
    """_reset() returns this side to DENY-ALL, which is right, and it has no
    business touching the halt: the halt is not part of a connection's
    lifetime. It lives in OperatorHalt, on disk."""
    s, oh, conn = srv_with_halt
    oh.halt("operator pressed stop")
    s._reset()
    assert s.state == "waiting"
    assert oh.halted is True
    assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True


def test_a_shell_created_sentinel_stops_send(srv_with_halt):
    """S4: the sentinel file exists to work when the bridge does not. Nothing
    told this bridge anything -- no frame, no halt() call -- and the next send
    must still be refused."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        assert s.state == "configured"

        oh.sentinel_path.write_text("socket was dead, stopped by hand\n")

        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted", (
            "a sentinel file is a halt even when no frame ever said so; this "
            f"send was refused as {exc.value.error_class!r} instead"
        )
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def test_halt_arms_the_durable_record_and_only_resume_clears_it(srv_with_halt):
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)

        s.halt("operator pressed stop")
        header, _ = reader.read()
        assert header["t"] == "halt"
        assert oh.halted is True
        assert oh.sentinel_path.exists()
        assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True

        s.resume()
        header, _ = reader.read()
        assert header["t"] == "resume"
        assert oh.halted is False
        assert not oh.sentinel_path.exists()
        assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is False
    finally:
        c.close()


def test_halt_arms_the_durable_record_before_the_frame_it_cannot_send(srv_with_halt):
    """halt() arms the durable record FIRST, and a dead socket proves it.

    S4 names the dead socket as the reason the sentinel exists at all, and a
    dead socket is the likeliest thing to be wrong at the moment someone hits
    stop. Arming after the send makes exactly that case the one path that
    loses the halt: the operator gets an exception and NOTHING anywhere is
    halted -- no frame, no sentinel, no row, and the next Burp start finds no
    standing halt to re-assert.

    The mirror ordering inside OperatorHalt.halt (sentinel before row) has
    test_the_sentinel_is_written_before_the_row behind it. This ordering, on
    the bridge, had nothing but a comment: reversing the two statements passed
    the entire suite except the plan's byte-compare, which a re-sync would
    have carried the reversal straight into.
    """
    s, oh, conn = srv_with_halt
    assert s._conn is None, "this test is only about the socket being dead"

    with pytest.raises(server.BridgeError, match="not connected") as exc:
        s.halt("operator pressed stop, socket already dead")
    assert exc.value.error_class == "bridge_lost"

    assert oh.halted is True, (
        "the operator pressed stop and was told it failed; if nothing is "
        "halted, the stop button did nothing at all"
    )
    assert oh.sentinel_path.exists(), (
        "the sentinel is the path that works when the bridge does not -- it "
        "is the one that must exist after a send that could not happen"
    )
    assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True, (
        "the next Burp start reads the store and the file, not this object"
    )
    assert conn.execute("SELECT COUNT(*) FROM agent_action WHERE tool=?",
                        (halt_mod.HALT_TOOL,)).fetchone()[0] == 1, (
        "the audit trail must say who stopped the run even when the frame "
        "never reached anyone"
    )
    assert s.state == "waiting", (
        "the bridge state is the connection's, and there is no connection; "
        "the halt that outlives it is the one in OperatorHalt"
    )


def test_resume_leaves_the_durable_halt_armed_when_the_frame_cannot_be_sent(srv_with_halt):
    """resume() disarms LAST, and the same dead socket proves it.

    A resume the peer never received must not lift a standing halt. Reversed,
    the operator is told the resume failed while issuance has been silently
    re-armed for the next Burp start -- a lifted halt nobody asked for,
    reported as a failure. S4's direction is the other one: unknown state is
    stop, so every failure before the frame reaches the wire leaves the halt
    standing.
    """
    s, oh, conn = srv_with_halt
    oh.halt("operator pressed stop")
    assert s._conn is None, "this test is only about the socket being dead"

    with pytest.raises(server.BridgeError, match="not connected"):
        s.resume()

    assert oh.halted is True, (
        "a resume nobody received lifted the halt anyway"
    )
    assert oh.sentinel_path.exists()
    assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True, (
        "and the next Burp start would have come up armed"
    )
    assert conn.execute("SELECT COUNT(*) FROM agent_action WHERE tool=?",
                        (halt_mod.RESUME_TOOL,)).fetchone()[0] == 0, (
        "nothing was resumed, so nothing should say it was"
    )


def test_a_reassert_that_cannot_be_sent_closes_the_connection(srv_with_halt):
    """`_reassert_halt` returns False and the caller drops the connection.

    Nothing else in this file exercises that arm: the send it guards only
    fails when the socket dies inside the hello handler, so the failure is
    injected rather than raced for. Carrying on would leave a peer that never
    received the halt believing it may issue -- and this side, having set
    state='halted', would show an operator a stop that is not in force
    anywhere.
    """
    s, oh, conn = srv_with_halt
    oh.halt("client called: stop everything")

    real_send = s._send

    def refuse(header, body=b""):
        if header.get("t") == "halt":
            raise server.BridgeError("send failed: [Errno 32] Broken pipe",
                                     error_class="bridge_lost")
        return real_send(header, body)

    s._send = refuse

    c = _client(s.socket_path)
    try:
        _hello(c)
        # _serve's finally runs _reset(), which is the observable consequence.
        _await(lambda: s.state == "waiting",
               f"the connection was kept after a failed re-assert: {s.state!r}")
        c.settimeout(0.5)
        assert c.recv(4096) == b"", "the peer socket was left open"
    finally:
        c.close()


def test_send_refuses_a_reply_that_is_not_a_result_or_an_error(srv_with_halt):
    """_deliver routes `configured` by correlation id like anything else, so a
    peer that answers a send with one gets that frame handed straight back.
    Returning it as a result would put `status=None` into an evidence row and
    call it an exchange that happened."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}

        def go():
            try:
                s.send({"target_host": "app.example.test"}, REQ)
            except server.BridgeError as exc:
                out["err"] = exc

        t = threading.Thread(target=go)
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 2}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert "configured" in str(out["err"])
        assert out["err"].error_class is None
    finally:
        c.close()
