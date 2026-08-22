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
        threading.Thread(
            target=lambda: srv.configure({"scope.include": ["https://a/*"]},
                                         scope_sha256="x", profile="production"),
            daemon=True,
        ).start()
        header, _ = codec.FrameReader(c).read()
        assert isinstance(header["id"], int) and header["id"] > 0
        assert isinstance(header["deadline_us"], int)
        assert header["deadline_us"] > time.time_ns() // 1000
    finally:
        c.close()


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
