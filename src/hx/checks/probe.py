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

ONE REFUSAL CLASS IS A REQUEST TO WAIT, AND THIS IS THE SEAM THAT OBEYS IT.
`hx.policy.Limiter` REFUSES an over-rate request rather than queueing it, and
puts the exact moment the window frees on the refusal --
`Decision.rateLimited(WINDOW_US - elapsed, ...)`, which `BridgeServer.send`
carries out to Python on `BridgeError.retry_after_us`. That hint is computed
exactly, plumbed through four layers and pinned end to end
(`tests/integration/test_send_path.py::test_the_rate_limit_trips_and_its_
retry_hint_is_true`, whose own docstring states the contract: "the agent
obeys `retry_after_us`"). Nothing on this side consumed it until the probe
pass became the first thing in the product to issue requests in a loop, and
an unpaced probe pass at a production rate is not a slow scan, it is a scan
that reports `inconclusive` for every probe after the `rate_rps`'th and finds
almost nothing. MEASURED against a real Burp at the integration rig's 3/s: of
the sixteen probes one scan of five surfaces issues, three were answered and
thirteen were refused.

`rate_limited` ONLY, AS AN ALLOWLIST AND NEVER AS A DENYLIST. Every other
class is terminal, and a new class arriving from a future extension is
terminal by default rather than accidentally retried: `scope_denied`,
`method_denied` and `dangerous_denied` are deterministic policy and answer
the same way for ever; `budget_exhausted` is monotonic by construction
(`Limiter`: "a budget that is spent stays spent", with no way to refill it);
`halted` and `not_configured` are session state that a wait does not change;
and `transport_error`, `timeout` and `bridge_lost` may have already reached
the target, so replaying them blindly is the one thing a safe sender may not
do.

THE WAIT IS HERE AND NOT IN `BridgeServer`. That module's "NOTHING IN THIS
FILE RETRIES" stays literally true, and it should: S6's objection is that a
replayed STATE-CHANGING request is worse than a failed one, and only a caller
knows whether its request was one. This sender is a caller that does know.
`_request_bytes` can build nothing but a GET, and `Limiter.check` increments
`issued` on the ALLOW path only -- "Refusals are not issuances and do not
appear here" -- so a request refused for rate never left the JVM and a
bounded retry cannot double-spend `limit.max_requests`. The published
decision order is `not_configured, halted, scope, method, dangerous, rate,
budget`, so a `rate_limited` answer also means scope, method and dangerous
ALREADY PASSED: waiting cannot turn a denial into an allow.

THE HINT CROSSES A TRUST BOUNDARY, SO IT IS BOUNDED IN BOTH DIRECTIONS. A
missing or non-positive hint is terminal -- inventing a wait for a refusal
that did not ask for one is how a scan spins -- and an over-large one is
CLAMPED to `_RETRY_CEILING_S` rather than obeyed, so a peer cannot stall a
scan by answering with a huge number. The clamp costs nothing real:
`retryAfterUs` is `WINDOW_US - elapsed` with `0 < elapsed < WINDOW_US`, so a
`Limiter` cannot legitimately ask for more than one second. Attempts are
bounded at `_RATE_LIMIT_ATTEMPTS`, which puts a ceiling of roughly two
seconds on what any one probe can add; the run as a whole is bounded by
`hx.scan.run`'s `max_seconds`, so no deadline is threaded through here.

THE COUNT IS OF ISSUANCES, NOT ATTEMPTS. `check_run.requests_sent` reaches a
client's report as the traffic hx generated, so it has to be true of the
requests that were actually made. `Limiter` decides `scope_denied`,
`method_denied`, `dangerous_denied`, `rate_limited` and `budget_exhausted`
BEFORE issuing and never increments `issued` for them, and `halted` /
`not_configured` are refused on this side before a frame is written at all --
so none of the seven is a request the target saw, and counting them would
overstate the traffic AND make every retry above double-count. Everything
else counts, by default and including a class this build has never seen:
`transport_error`, `timeout` and `bridge_lost` may already have reached the
target, and a `status_unreadable` outcome certainly did. Overstating traffic
is the safe direction; understating what hx put on a client's system is not.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from hx.bridge.server import BridgeError, BridgeServer
from hx.checks.passive import _http

# ATTEMPTS, not retries: 3 is one issue and at most two waits, so the worst
# case a single probe can add to a scan is two clamped waits (~2 s).
_RATE_LIMIT_ATTEMPTS = 3

# The most a `Limiter` can legitimately ask for is one window, and the window
# is one second (`Limiter.WINDOW_US`). A larger hint is a peer that is wrong
# or hostile, and either way it does not get to decide how long hx waits.
_RETRY_CEILING_S = 1.0

# The same slack `tests/integration/test_send_path.py` already waits with:
# the hint is exact about when the window frees, and two clocks that are
# exactly equal are two clocks that race.
_RETRY_SLACK_S = 0.02

# The refusal classes the gate decides BEFORE issuing, so none of them is a
# request the target saw. Named as an EXCLUSION set on purpose -- see the
# module docstring's last paragraph: anything not listed here counts.
_NOT_ISSUED = frozenset({
    "scope_denied", "method_denied", "dangerous_denied", "rate_limited",
    "budget_exhausted", "halted", "not_configured",
})


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


def _rate_limit_wait(exc: BridgeError) -> float | None:
    """Seconds to wait out a `rate_limited` refusal, or None if it is terminal.

    None for a hint that is absent, non-numeric or non-positive: `Limiter`
    always sends a positive one when it refuses for rate, so its absence means
    something other than that limiter answered and there is nothing to wait
    for. Waiting anyway -- a default, a backoff -- is what makes a scan spin
    against a peer that will never let it through.
    """
    hint = exc.retry_after_us
    if not isinstance(hint, (int, float)) or isinstance(hint, bool) or hint <= 0:
        return None
    return min(hint / 1_000_000, _RETRY_CEILING_S) + _RETRY_SLACK_S


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
        attempts_left = _RATE_LIMIT_ATTEMPTS
        while True:
            attempts_left -= 1
            try:
                result = self._bridge.send(
                    {"target_host": self._host, "target_port": self._port,
                     "tls": self._scheme == "https"},
                    raw, timeout=timeout)
            except BridgeError as exc:
                # BridgeServer.send() never returns a refusal -- it raises
                # this, with the wire's class on .error_class (None only for a
                # malformed call or a peer answering a send with the wrong
                # frame, the second of which HAS already put bytes on the
                # wire). Translating it here is what makes rule one hold in
                # practice.
                cls = exc.error_class or "transport_error"
                if cls not in _NOT_ISSUED:
                    # Counted before the raise and before the retry decision:
                    # this attempt may have reached the target, and a class
                    # this build has never seen counts too.
                    self._sent += 1
                wait = _rate_limit_wait(exc) if cls == "rate_limited" else None
                if wait is not None and attempts_left > 0:
                    time.sleep(wait)
                    continue
                # `BridgeError`'s own message already opens with the class
                # ("rate_limited: rate limit 3/s: ..."), and `ProbeRefused`
                # puts the reason in front of the detail again -- which
                # `hx.scan.run` then prefixes a third time on its way into
                # `check_run.reason` and the report's coverage rows.
                detail = str(exc).removeprefix(f"{cls}: ")
                raise ProbeRefused(cls, "" if detail == cls else detail) from exc
            # The send returned a `result` frame, so a request was issued --
            # whatever the frame then says about how much of the answer came
            # back.
            self._sent += 1
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
