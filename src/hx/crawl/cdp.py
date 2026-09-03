"""Chrome DevTools Protocol over two file descriptors.

NOT OVER A WEBSOCKET, and the reason is `pyproject.toml`'s own note about
`httpx2`: an HTTP client in the runtime closure "is the kind of thing that
quietly stops being true" about S4's invariant that every byte leaving this
machine crosses the JVM. A WebSocket client aimed at loopback today is a
WebSocket client. Over pipes there is no port, no client and no address to
repoint -- the transport is two descriptors on a child process.

WIRE FORMAT, measured 2026-09-02 against Chromium 150.0.7871.186: UTF-8
JSON objects separated by one NUL byte. We write to the child's fd 3 and
read what it writes to fd 4.
"""
from __future__ import annotations

import json
import os
import selectors
import time


class CdpError(Exception):
    """The peer answered, and the answer was a protocol error."""


class CdpTimeout(CdpError):
    """The peer did not answer inside the deadline."""


class CdpClosed(CdpError):
    """The peer closed its pipe or died."""


class Connection:
    """One CDP session over a pair of descriptors.

    NOT THREAD-SAFE and deliberately synchronous. A crawl visits one page at
    a time under a budget; concurrency here would buy nothing and would make
    the id correlation below a lock instead of a dict.
    """

    def __init__(self, read_fd: int, write_fd: int) -> None:
        self._read_fd = read_fd
        self._write_fd = write_fd
        self._next_id = 0
        self._buf = b""
        self._replies: dict[int, dict] = {}
        self.events: list[dict] = []
        self._sel = selectors.DefaultSelector()
        self._sel.register(read_fd, selectors.EVENT_READ)
        self._closed = False

    def call(self, method: str, params: dict | None = None, *,
             session_id: str | None = None, timeout: float = 30.0) -> dict:
        """Send one command and return its `result`."""
        self._next_id += 1
        msg_id = self._next_id
        msg: dict = {"id": msg_id, "method": method, "params": params or {}}
        if session_id is not None:
            msg["sessionId"] = session_id
        self._write(msg)

        deadline = time.monotonic() + timeout
        while True:
            if msg_id in self._replies:
                reply = self._replies.pop(msg_id)
                if "error" in reply:
                    err = reply["error"]
                    raise CdpError(
                        f"{method}: {err.get('message', err)}")
                return reply.get("result", {})
            self._pump(deadline)

    def drain(self, timeout: float) -> list[dict]:
        """Every event received up to now, plus any arriving within `timeout`.

        Returns and CLEARS. A caller reading events twice would count one
        request twice, and the page classifier of `page.py` counts requests.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._pump(deadline)
            except (CdpTimeout, CdpClosed):
                break
        out, self.events = self.events, []
        return out

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._sel.close()
        for fd in (self._read_fd, self._write_fd):
            try:
                os.close(fd)
            except OSError:
                pass

    # --- internals ---------------------------------------------------------

    def _write(self, msg: dict) -> None:
        raw = json.dumps(msg).encode("utf-8") + b"\0"
        try:
            while raw:
                raw = raw[os.write(self._write_fd, raw):]
        except OSError as e:
            raise CdpClosed(f"write failed: {e}") from e

    def _pump(self, deadline: float) -> None:
        """Read once, decode whatever completed, and file it.

        A message with an `id` is somebody's reply and goes to `_replies`; a
        message without one is an event and goes to `self.events`. DISCARDING
        the second kind is the mutation `test_events_arriving_during_a_call_
        are_buffered_not_discarded` exists to catch: events and replies share
        one pipe, so an event that lands while a call is outstanding is read
        by that call's loop and by nothing else.
        """
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CdpTimeout("no reply before the deadline")
        if not self._sel.select(timeout=remaining):
            raise CdpTimeout("no reply before the deadline")
        try:
            chunk = os.read(self._read_fd, 1 << 16)
        except OSError as e:
            raise CdpClosed(f"read failed: {e}") from e
        if not chunk:
            raise CdpClosed("the peer closed its pipe")
        self._buf += chunk
        while b"\0" in self._buf:
            raw, self._buf = self._buf.split(b"\0", 1)
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                # A frame we cannot parse is not a frame we may guess at.
                # Dropping it loses one message; treating it as a reply would
                # answer a caller with garbage.
                continue
            if "id" in msg:
                self._replies[msg["id"]] = msg
            else:
                self.events.append(msg)
