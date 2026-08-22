"""The harness end of the bridge.

Python listens and Burp dials in, inverted from the obvious arrangement: the
harness holds the engagement state and outlives Burp, which we measured losing
everything on restart. A Burp restart is therefore a reconnect, not an outage.

DENY-ALL is the initial and terminal state. A freshly connected extension knows
nothing -- extensionData does not survive a Burp restart -- so it stays
unconfigured until a configure frame is acknowledged.
"""
from __future__ import annotations

import os
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

from hx.bridge import codec


class BridgeError(Exception):
    """The bridge cannot start, or was asked to do something out of order."""


def socket_path_for(engagement_id: str) -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / "hx" / f"{engagement_id}-{secrets.token_hex(4)}.sock"


class BridgeServer:
    # Error classes under which BridgeClient.handle() actually drops to
    # DENY-ALL: `bad_config` calls denyAll() before answering, and
    # `protocol_mismatch` returns false out of handle(), which trips
    # readLoop()'s finally block. `engagement_mismatch` and `bad_frame`
    # answer error and carry on configured -- resetting THIS side for those
    # would make it report state="connected", config_epoch=0 while the
    # extension is still configured and live, the reverse of the bug this
    # reset exists to fix, and the more dangerous direction: the operator's
    # console says nothing may be sent while it can. See the `case` arms in
    # extension/src/hx/bridge/BridgeClient.java's handle() for the exact
    # strings.
    _DENYING_CONFIGURE_ERRORS = frozenset({"bad_config", "protocol_mismatch"})

    def __init__(self, socket_path: Path, engagement_id: str, on_hello=None):
        self.socket_path = Path(socket_path)
        self.engagement_id = engagement_id
        self.on_hello = on_hello

        self.state = "waiting"
        self.config_epoch = 0
        self.peer_uid: int | None = None
        self.peer_pid: int | None = None
        self.hello: dict | None = None
        self.rejected_hellos = 0

        self._srv: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._pending: dict[int, threading.Event] = {}
        self._replies: dict[int, dict] = {}
        self._next_id = 0
        self._generation = 0     # bumped per accepted connection; see _reset
        self._lock = threading.Lock()
        # A SEPARATE mutex from self._lock, deliberately. Reusing the state
        # mutex would hold it across a blocking sendall() and stall the
        # _deliver() that wakes the _request() waiting on the very frame being
        # written.
        self._send_lock = threading.Lock()

    # ---- lifecycle ---------------------------------------------------

    def start(self) -> None:
        if self.socket_path.exists():
            raise BridgeError(
                f"socket path already exists: {self.socket_path}. Refusing to "
                "start rather than adopt a path another process may own."
            )
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.socket_path.parent, 0o700)

        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self._srv.listen(1)
        self._srv.settimeout(0.2)

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        if self._conn is not None:
            try:
                # shutdown(), not just close(): the accept-loop thread may be
                # blocked in conn.recv() with no timeout set on that socket.
                # A bare close() from this thread does not reliably unblock a
                # concurrent recv() on the same fd on Linux -- verified by
                # reproduction, stop() hung for the full join timeout with the
                # accept thread left permanently blocked. shutdown(SHUT_RDWR)
                # forces that pending recv() to return 0 immediately.
                self._conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for s in (self._conn, self._srv):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    # ---- accept / read loop -------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                conn, _ = self._srv.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            try:
                self._serve(conn)
            except Exception:
                # The accept loop is a daemon thread. If it dies the server
                # looks alive and silently never accepts again, so no
                # exception may escape here.
                try:
                    conn.close()
                except OSError:
                    pass

    def _serve(self, conn: socket.socket) -> None:
        with self._lock:
            self._generation += 1
            gen = self._generation
            self._conn = conn
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", creds)
            if uid != os.getuid():
                # The socket authenticates a uid, not a program; a different
                # uid has no business here at all.
                return
            self.peer_pid, self.peer_uid = pid, uid

            reader = codec.FrameReader(conn)
            while not self._stopping.is_set():
                header, body = reader.read()
                if not self._handle(header, body):
                    return
        except (codec.PeerClosed, codec.Incomplete, codec.FrameError, OSError):
            return
        finally:
            self._reset(gen)
            try:
                conn.close()
            except OSError:
                pass

    def _reset(self, gen: int | None = None) -> None:
        """Return to DENY-ALL. `gen` guards against a slow teardown of an old
        connection wiping the state of a newer one."""
        with self._lock:
            if gen is not None and gen != self._generation:
                return
            # Advance the generation as well as guarding on it. Without this,
            # the token only detects "a NEW connection superseded an old one" --
            # it cannot detect this same connection resetting between a caller's
            # _request() returning and its commit, so the caller still sees
            # gen == self._generation and clobbers the waiting state.
            self._generation += 1
            self.state = "waiting"
            self.config_epoch = 0
            self._conn = None
            # A waiter blocked on a reply that will now never arrive must not
            # outlive the connection, and a stale reply must not be collected
            # by a future request.
            for ev in self._pending.values():
                ev.set()
            self._pending.clear()
            self._replies.clear()

    def _handle(self, header: dict, body: bytes) -> bool:
        """Return False to close the connection."""
        if header.get("v") != codec.PROTOCOL_VERSION:
            return False

        t = header.get("t")
        if t == "hello":
            if header.get("engagement_id") != self.engagement_id:
                # Client A's traffic must never land in client B's store.
                self.rejected_hellos += 1
                return False
            self.hello = header
            with self._lock:
                self.state = "connected"
                self.config_epoch = 0   # a fresh hello is a fresh session
            if self.on_hello:
                self.on_hello(header)
            return True

        if t == "configured":
            self._deliver(header)
            return True

        if t in ("result", "error", "exchange"):
            self._deliver(header)          # consumed by a later plan
            return True

        return False

    def _deliver(self, header: dict) -> None:
        rid = header.get("id")
        with self._lock:
            ev = self._pending.get(rid)
            if ev is None:
                # Nobody is waiting: the caller timed out, or this is an
                # unsolicited frame. Recording it would leak an entry that
                # nothing ever collects, forever, on a long-lived bridge.
                return
            self._replies[rid] = header
        ev.set()

    # ---- outbound ------------------------------------------------------

    def _send(self, header: dict, body: bytes = b"") -> None:
        conn = self._conn          # snapshot: the accept thread may null it
        if conn is None:
            raise BridgeError("not connected")
        # Encoded OUTSIDE the mutex: it touches nothing shared, and holding a
        # send mutex across it would serialise work that needs no serialising.
        frame = codec.encode(header, body)
        try:
            # sendall() is not atomic -- it loops over send() and a large frame
            # parks mid-write once the socket buffer fills -- so two callers
            # inside it splice their frames together and the peer decodes
            # neither. Every write on this side is a control frame: halt,
            # resume, configure. The Java counterpart is a deliberate
            # `private synchronized void send` for exactly this reason.
            with self._send_lock:
                conn.sendall(frame)
        except OSError as exc:
            raise BridgeError(f"send failed: {exc}") from exc

    def _request(self, header: dict, body: bytes = b"", timeout: float = 10.0) -> dict:
        with self._lock:
            self._next_id += 1
            rid = self._next_id
            ev = threading.Event()
            self._pending[rid] = ev
        # deadline_us is set on every request frame from the start so the frame
        # shape never changes later. Acting on it -- abandoning work past the
        # deadline -- belongs to the send path in Plan 3; here it is carried and
        # validated, not enforced.
        header = {**header, "id": rid,
                  "deadline_us": (time.time_ns() // 1000) + int(timeout * 1_000_000)}
        self._send(header, body)
        if not ev.wait(timeout):
            with self._lock:
                self._pending.pop(rid, None)
            raise BridgeError(f"no reply to {header['t']} within {timeout}s")
        with self._lock:
            self._pending.pop(rid, None)
            # _reset() also sets every pending event, on disconnect, so that a
            # waiter does not outlive its connection -- that wakeup carries no
            # reply. Without this check, .pop(rid) raises a bare KeyError
            # instead of the documented BridgeError. Reproduced directly:
            # a peer that closes without ever replying woke this waiter via
            # _reset(), with no entry in _replies for it to collect.
            if rid not in self._replies:
                raise BridgeError(
                    f"peer disconnected before replying to {header['t']}"
                )
            return self._replies.pop(rid)

    def configure(self, pairs: dict[str, list[str]], scope_sha256: str,
                  profile: str) -> int:
        if self.state not in ("connected", "configured", "halted"):
            raise BridgeError("not connected: cannot configure before hello")
        gen = self._generation
        reply = self._request(
            {
                "v": codec.PROTOCOL_VERSION,
                "t": "configure",
                "engagement_id": self.engagement_id,
                "scope_sha256": scope_sha256,
                "profile": profile,
            },
            codec.build_config_body(pairs),
        )
        if reply.get("t") == "error":
            # The extension answers SOME refused configures by dropping to
            # DENY-ALL at epoch 0 -- including a refused RE-configure, which
            # discards the scope it was already holding -- but not all of
            # them. Only reset this side for the classes that actually deny;
            # see _DENYING_CONFIGURE_ERRORS. Resetting for the others would
            # make this side report state='connected', config_epoch=0 while
            # the extension is still configured and sending -- the opposite
            # disagreement from the one this reset was added to fix, and it
            # is this side that operators and Plan 5 read. Verified against a
            # live extension before the reset was added.
            #
            # Same gen/_conn guard as the success path: a newer connection's
            # state is not ours to clobber.
            if reply.get("class") in self._DENYING_CONFIGURE_ERRORS:
                with self._lock:
                    if gen == self._generation and self._conn is not None:
                        self.state = "connected"
                        self.config_epoch = 0
            # Surface what the peer actually said. Falling through to the
            # generic message below turns "engagement_mismatch: e-1 != e-2"
            # into "acknowledged configure without a config_epoch", which
            # sends the next debugger looking in the wrong place entirely.
            raise BridgeError(
                "peer refused configure: "
                f"{reply.get('class', 'unspecified')}: {reply.get('detail', '')}".rstrip(": ")
            )
        if "config_epoch" not in reply:
            raise BridgeError("peer acknowledged configure without a config_epoch")
        with self._lock:
            # Commit only if this is still the same connection. Without the
            # guard, a peer that acks and immediately disconnects leaves
            # state="configured" with no peer attached -- reproduced 59/60.
            # The generation check alone caught a NEW connection superseding
            # this one; it missed THIS connection resetting in the window
            # between _request() returning and this commit (reproduced 10/10
            # once that window was widened), because _reset() did not used to
            # advance the generation it guards on. The _conn check is belt
            # and braces: the generation check is the structural fix, this
            # makes the invariant obvious to the next reader.
            if gen != self._generation or self._conn is None:
                raise BridgeError("peer disconnected before configure completed")
            self.config_epoch = int(reply["config_epoch"])
            # A configure re-authorises SCOPE, not ISSUANCE. An operator who
            # halted because the scope went wrong, and is now pushing the
            # corrected scope, has not asked for issuance back -- only resume()
            # does that. Writing "configured" over "halted" here re-armed the
            # bridge with no `resume` on the wire and no log line, and the
            # extension's commit used to clear its own `halted` flag to match.
            # "halted" is still an accepted state on the way in (see the
            # precondition above): narrowing scope during an emergency stop is
            # exactly what an operator should be able to do.
            self.state = "halted" if self.state == "halted" else "configured"
        return self.config_epoch

    def halt(self, reason: str) -> None:
        # Same send-then-mutate shape as configure(), so the same guard: a
        # peer that disconnects between the send and this commit must not
        # leave state looking like anything other than what _reset() wrote.
        gen = self._generation
        self._send({"v": codec.PROTOCOL_VERSION, "t": "halt", "reason": reason})
        with self._lock:
            if gen != self._generation or self._conn is None:
                raise BridgeError("peer disconnected before halt completed")
            self.state = "halted"

    def resume(self) -> None:
        gen = self._generation
        self._send({"v": codec.PROTOCOL_VERSION, "t": "resume"})
        with self._lock:
            if gen != self._generation or self._conn is None:
                raise BridgeError("peer disconnected before resume completed")
            self.state = "configured" if self.config_epoch else "connected"
