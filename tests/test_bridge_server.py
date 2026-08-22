import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path

import pytest

from hx.bridge import codec, server


@pytest.fixture
def srv(tmp_path):
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1")
    s.start()
    yield s
    s.stop()


def _client(path):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(path))
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
    with pytest.raises(server.BridgeError, match="not connected"):
        srv.configure({"scope.include": ["https://a/*"]}, scope_sha256="x", profile="production")


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
