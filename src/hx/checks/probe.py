"""The one route from a check to the wire.

A check does not own a socket and cannot construct one. It is handed a
`ProbeSender` already bound to its surface, and every request goes through
`hx.bridge.server.BridgeServer.send` into the extension -- so S4 holds
unchanged: every byte that leaves this machine still crosses one of two
points inside the JVM, and this module adds neither.

TWO RULES, BOTH STRUCTURAL RATHER THAN DOCUMENTED.

A REFUSAL RAISES. S10 says a check that cannot run returns `inconclusive`,
never `clean`. A sender that RETURNED a refusal would leave a check free to
read it as a response and carry on to a clean answer; `budget_exhausted`
would then render as `tested, clean`, which is exactly the confusion S12
calls worse than no report. Raising takes the choice away.

THE SENDER HOLDS NO DATABASE CONNECTION. It counts in memory and the runner
writes `check_run.requests_sent` when it closes the row, so
`hx.checks.base.CheckContext`'s guarantee -- "a check that can write is a
check that can write the wrong thing" -- stays literally true of everything a
check can reach.

`BridgeServer.send` DOES NOT RETURN A REFUSAL AS A DICT. It raises
`hx.bridge.server.BridgeError` -- with the wire's class on `.error_class` --
for every one of them: this side's own local enforcement (`halted`,
`not_configured`), a timed-out or disconnected peer (`timeout`,
`bridge_lost`), and every `error` frame the extension answers with
(`scope_denied`, `method_denied`, `dangerous_denied`, `rate_limited`,
`budget_exhausted`, `transport_error`, ...). `get()` below is what turns that
raised `BridgeError` into a raised `ProbeRefused`, so rule one above holds
against the bridge as it actually behaves, not against a dict shape it never
produces.

A SUCCESSFUL SEND CAN STILL NOT BE A WHOLE ANSWER. The result frame carries
its own `outcome` (`ok`, or `status_unreadable` when the peer's status line
could not be read -- see `Sender.java`), the same field
`hx.checks.passive._http` reads off a stored `exchange` row and treats as a
gap rather than proof of absence. `get()` applies the identical rule at the
wire: only `outcome == "ok"` is handed back as a `ProbeResponse`, and
anything else raises `ProbeRefused` too, for the same reason -- a check must
not be able to read an incomplete response as a clean one.
"""
from __future__ import annotations

from dataclasses import dataclass

from hx.bridge.server import BridgeError, BridgeServer
from hx.checks.passive import _http


class ProbeRefused(Exception):
    """The request did not produce an answer. `reason` is the wire's class."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ProbeResponse:
    status: int | None
    head: bytes
    body: bytes
    outcome: str


class ProbeSender:
    """Bound to one surface for the life of one `check_run`."""

    def __init__(self, bridge, *, scheme: str, host: str, port: int,
                 path_template: str) -> None:
        self._bridge = bridge
        self._scheme = scheme
        self._host = host
        self._port = port
        self._path_template = path_template
        self._sent = 0

    @property
    def sent(self) -> int:
        return self._sent

    def get(self, path: str, *, headers: dict[str, str] | None = None,
            timeout: float = 30.0) -> ProbeResponse:
        if not path.startswith("/"):
            raise ValueError(
                f"path must be origin-form and start with '/', got {path!r}; "
                "a sender is bound to one surface and cannot be pointed "
                "somewhere else")
        raw = self._request_bytes(path, headers or {})
        self._sent += 1          # BEFORE the call: a refused attempt still
                                 # spent the budget and still touched the
                                 # target, and a count that omitted refusals
                                 # would understate the traffic hx generated.
        try:
            result = self._bridge.send(
                {"target_host": self._host, "target_port": self._port,
                 "tls": self._scheme == "https"},
                raw, timeout=timeout)
        except BridgeError as exc:
            # BridgeServer.send() never returns a refusal -- it raises this,
            # with the wire's class on .error_class (None only for a
            # malformed call, which a correctly bound sender never makes).
            # Translating it here is what makes rule one hold in practice.
            raise ProbeRefused(exc.error_class or "transport_error",
                               str(exc)) from exc
        outcome = result.get("outcome", "ok")
        if outcome != "ok":
            raise ProbeRefused(
                outcome, "the response did not come back whole, so nothing "
                         "found in it separates tested from unreachable")
        head, body = _http._split_head_body(
            result.get(BridgeServer.BODY_KEY, b""))
        return ProbeResponse(result.get("status"), head, body, outcome)

    def _request_bytes(self, path: str, headers: dict[str, str]) -> bytes:
        lines = [f"GET {path} HTTP/1.1", f"Host: {self._host}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
