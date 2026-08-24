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
    """The bridge cannot start, or was asked to do something out of order.

    `error_class` is the send path's vocabulary (spec S6): the class the peer
    put on an `error` frame, or the class this side refused under before the
    frame ever reached the wire. It is None when the failure is not a send-path
    failure at all -- a malformed call, a configure the peer refused -- so a
    caller mapping classes onto `denial` rows through `records.DENIAL_KIND`
    must check for None rather than index blindly.

    `retry_after_us` is set only for `rate_limited`, the one class that carries
    a retry hint. NOTHING IN THIS FILE RETRIES: S6 is explicit that a replayed
    state-changing request is worse than a failed one, so retry is a decision
    the caller makes explicitly, and records.
    """

    def __init__(self, message: str, *, error_class: str | None = None,
                 retry_after_us: int | None = None):
        super().__init__(message)
        self.error_class = error_class
        self.retry_after_us = retry_after_us


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

    # The key a delivered frame's body arrives under. It mirrors
    # BridgeClient.BODY_KEY on the Java side, and codec._check_header refuses a
    # bytes value, so a reply dict that ever got re-encoded as a frame with the
    # body still attached fails loudly instead of putting evidence in a header.
    BODY_KEY = "@body"

    # Keys send() stamps itself. `**req` is spliced OVER the frame send()
    # builds, so a caller's key wins: `t` alone would turn a send into a halt
    # frame nobody correlates, `engagement_id` would address whichever
    # extension answered, and `id` would collide with a live correlation id.
    # They are refused rather than silently overwritten, which would leave the
    # caller believing something else happened.
    _RESERVED_SEND_KEYS = frozenset({"v", "t", "id", "deadline_us",
                                     "engagement_id"})

    def __init__(self, socket_path: Path, engagement_id: str, operator_halt,
                 on_hello=None, on_halted=None):
        """
        `operator_halt` is an `hx.halt.OperatorHalt` -- duck-typed, so this
        module keeps no dependency on the store, and tests can attach anything
        with `.halted`, `.reason`, `.halt()` and `.resume()`. `.halted` and
        `.reason` are read on the read thread, which is why OperatorHalt
        answers them from memory and a stat() rather than from the database.

        IT IS REQUIRED, and the Java side made the same call for the same
        field: HxExtension.initialize() refuses to come up without
        `-Dhx.halt_sentinel` because "an extension that went live without one
        would have two of the three paths spec s4 promises, silently". The
        same is true here. Optional, it made the whole durable halt opt-in: a
        HALTED file placed by hand -- S4's named "the socket is dead, stop by
        hand" path -- did not stop send(), and halt() wrote neither sentinel
        nor audit row. Measured with the argument omitted:

            sentinel on disk: True   operator_halt attr: None
            SEND REACHED THE WIRE with a HALTED sentinel present
            after server.halt(): agent_action rows = 0

        The extension still refused via its own poller, so S4's enforcement
        invariant held; what was lost was durability and the harness-side
        refusal. S4 promises three paths, and an opt-in third path is not a
        promise. A caller with no engagement -- a test harness -- supplies a
        sentinel in a directory of its own, which is exactly the discipline
        the Java side imposes on itself.

        `on_hello` and `on_halted` are both called ON THE READ THREAD, so
        neither may touch a sqlite3 connection opened elsewhere: it belongs to
        the thread that created it and raises ProgrammingError anywhere else
        (tests/test_halt.py demonstrates it). Hand the work to the thread that
        owns the store instead.
        """
        if operator_halt is None:
            # The signature already refuses an OMITTED argument. This refuses
            # an explicit None, which is the same fail-open with a keystroke
            # in front of it, and refuses it at construction rather than at
            # the first send -- the Java side's `extension idle` shape.
            raise BridgeError(
                "operator_halt is required and may not be None. It is S4's "
                "third kill path: the sentinel file that works when the "
                "bridge does not. A caller with no engagement supplies an "
                "hx.halt.OperatorHalt over a directory of its own, the same "
                "way HxExtension refuses to initialise without "
                "-Dhx.halt_sentinel."
            )
        self.socket_path = Path(socket_path)
        self.engagement_id = engagement_id
        self.on_hello = on_hello
        self.on_halted = on_halted
        self.operator_halt = operator_halt
        # The last unsolicited `halted` frame, kept so a harness with no
        # on_halted callback installed can still see why issuance stopped.
        self.last_halted: dict | None = None
        self.halted_callback_error: BaseException | None = None

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
            # A durable halt is re-asserted HERE, before on_hello runs and so
            # before any configure: on_hello is where a harness pushes scope,
            # and configure() cannot be called before a hello at all. That
            # ordering IS the guarantee -- a peer that learned its scope first
            # would be armed for the length of a round trip.
            if not self._reassert_halt():
                return False
            if self.on_hello:
                self.on_hello(header)
            return True

        if t == "halted":
            # Unsolicited, no id: auto-halt is extension-initiated, so there is
            # no outstanding request to answer. Without this frame an auto-halt
            # is invisible until the next send fails, and `run.status =
            # aborted` has no stop_reason to record. The frame is
            # {reason, host, window}.
            self.last_halted = header
            with self._lock:
                self.state = "halted"
            if self.on_halted:
                try:
                    self.on_halted(header)
                except Exception as exc:
                    # The callback is what makes this durable -- it is where
                    # the run is marked aborted and, if the harness wants the
                    # stop to survive a Burp restart, where OperatorHalt.halt
                    # is called. A callback that threw recorded nothing, so
                    # drop to DENY-ALL rather than carry on beside a peer whose
                    # stop nothing has written down.
                    self.halted_callback_error = exc
                    return False
            return True

        if t == "configured":
            self._deliver(header, body)
            return True

        if t in ("result", "error", "exchange"):
            self._deliver(header, body)
            return True

        return False

    def _reassert_halt(self) -> bool:
        """Tell a freshly connected peer it is still halted. False to close.

        Two findings from the Plan 2 review meet on this method: a second
        `hello` erased the halt (the epoch reset above is right -- a fresh
        hello IS a fresh session -- but the halt is not part of that session),
        and a halt did not survive a Burp restart, which is precisely when
        someone has already hit stop. `_reset()` cannot clear it either: the
        state lives in OperatorHalt, on disk, not in this object.
        """
        if not self.operator_halt.halted:
            return True
        reason = self.operator_halt.reason or "halted, no reason recorded"
        try:
            self._send({"v": codec.PROTOCOL_VERSION, "t": "halt",
                        "reason": reason})
        except BridgeError:
            # The connection is the thing that just failed, so it is the thing
            # to give up on: a peer that never received the halt must not be
            # left believing it may issue. Returning False closes it, and
            # _serve's finally puts this side back to DENY-ALL.
            return False
        with self._lock:
            self.state = "halted"
        return True

    def _deliver(self, header: dict, body: bytes = b"") -> None:
        rid = header.get("id")
        # A `result` frame's body is the redacted response bytes -- the
        # evidence the caller is about to hash into the blob store. Delivering
        # the header alone dropped it silently.
        header = {**header, self.BODY_KEY: body}
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
            raise BridgeError("not connected", error_class="bridge_lost")
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
            raise BridgeError(f"send failed: {exc}",
                              error_class="bridge_lost") from exc

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
            # S6 distinguishes timeout from bridge_lost and from
            # conn_refused, and the agent acts differently on each: this one
            # means the peer is alive and did not answer in time.
            raise BridgeError(f"no reply to {header['t']} within {timeout}s",
                              error_class="timeout")
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
                    f"peer disconnected before replying to {header['t']}",
                    # S6: every outstanding send fails with bridge_lost when
                    # the peer goes away, distinct from timeout, and NEVER
                    # auto-retried across the reconnect.
                    error_class="bridge_lost",
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

    def send(self, req: dict, body: bytes = b"", timeout: float = 30.0,
             *, enforce_locally: bool = True) -> dict:
        """Issue one request through the extension; return the `result` header.

        `req` carries the destination and the identity the extension applies --
        `target_host`, `target_port`, `tls`, `identity_id` -- and `body` is the
        raw HTTP request bytes. The returned dict is the result header plus the
        redacted response bytes under BODY_KEY.

        Enforcement is the extension's (S4: every byte that leaves this machine
        crosses one of two points inside the JVM). Everything refused here is
        refused a second time there; nothing allowed here is thereby allowed.

        `enforce_locally=False` drops THIS side's three duplicate refusals --
        the durable halt, `state == "halted"`, and anything short of
        `configured` -- and nothing else. It exists for one caller, the
        integration rig, and for one reason: those refusals are answered
        BEFORE the wire, so a test of the extension's gate written the obvious
        way writes ZERO frames to the socket, is satisfied by this side's own
        bookkeeping, and goes on passing with the extension wide open. It
        weakens nothing in production -- the extension refuses each of these a
        second time, which is the half that actually stands between the agent
        and the network -- and a caller passing it is asking to be answered by
        the JVM rather than by this dict of state.

        It is a KEYWORD on this method rather than a second code path in the
        rig because the rig used to own a copy of the error translation below,
        and a copy is what drifts: a new frame type or a renamed hint field
        would have been handled here and not there, silently, with every test
        that uses it still asserting the old shape.

        The reserved-key guard above is NOT part of it. That one catches a
        malformed call -- a bug, not a denial -- and there is no test worth
        writing that needs it off.

        Raises BridgeError. `.error_class` is the peer's class for an `error`
        frame; `timeout` when no reply arrives in time; `bridge_lost` when the
        peer disconnects with this send in flight; `not_configured` or `halted`
        when this side refuses before the wire; and None when the call itself
        was malformed, which is a bug rather than a denial.

        NOTHING RETRIES.
        """
        bad = self._RESERVED_SEND_KEYS.intersection(req)
        if bad:
            raise BridgeError(
                f"send() stamps {sorted(bad)} itself; a caller may not set "
                "them. An engagement_id from the caller in particular would "
                "address whichever extension answers, not this engagement's."
            )
        if enforce_locally:
            # The durable halt is consulted on EVERY send, not only at hello.
            # An operator can create the sentinel file from a shell while the
            # socket is dead or the agent has stopped responding -- S4 names
            # that as the reason the file exists -- and that halt has to work
            # with no frame ever arriving.
            if self.operator_halt.halted:
                raise BridgeError(f"halted: {self.operator_halt.reason}",
                                  error_class="halted")
            state = self.state
            if state == "halted":
                raise BridgeError("halted", error_class="halted")
            if state != "configured":
                # DENY-ALL is the initial and terminal state. "connected" is
                # not configured: no configure frame has been acknowledged, so
                # the extension would refuse this anyway, with not_configured.
                raise BridgeError(f"not configured: bridge state is {state!r}",
                                  error_class="not_configured")

        reply = self._request({"v": codec.PROTOCOL_VERSION, "t": "send",
                               "engagement_id": self.engagement_id, **req},
                              body, timeout=timeout)
        t = reply.get("t")
        if t == "result":
            return reply
        if t == "error":
            raise BridgeError(
                f"{reply.get('class', 'unspecified')}: "
                f"{reply.get('detail', '')}".rstrip(": "),
                error_class=reply.get("class"),
                retry_after_us=reply.get("retry_after_us"),
            )
        raise BridgeError(f"peer answered a send with a {t!r} frame")

    def halt(self, reason: str) -> None:
        # The durable record is armed BEFORE the frame goes out. If the send
        # fails, or the peer vanishes between the send and the commit below,
        # the halt still stands and the next hello re-asserts it. Arming
        # afterwards would make a dead socket -- the likeliest thing to be
        # wrong when someone hits stop -- the one path that loses the halt.
        self.operator_halt.halt(reason)
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
        # Disarmed only after the frame reached the wire AND the commit above
        # stood. Every failure before this point leaves the durable halt armed,
        # which is the direction S4 asks for: unknown state is stop. Only
        # resume re-arms issuance, and only a resume that actually got there.
        self.operator_halt.resume()
