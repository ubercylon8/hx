"""The one route from a check to the wire.

A check does not own a socket and cannot construct one. It is handed a
`ProbeSender` already bound to its surface, and every request goes through
`hx.bridge.server.BridgeServer.send` into the extension -- so S4 holds
unchanged: every byte that leaves this machine still crosses one of two
points inside the JVM, and this module adds neither.

THREE RULES, ALL STRUCTURAL RATHER THAN DOCUMENTED.

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

A PROBE GOES TO A CONCRETE PATH, NEVER TO A TEMPLATE. A surface's identity
is `path_template` -- `hx.surface` normalises `/user/12345/profile` into
`/user/{id}/profile`, and S5 says that merge is the point -- but a template
is an identity and not an address: `GET /user/{id}/profile` reaches a URL
that cannot exist, and the 404 that comes back carries none of the headers,
reflections or signatures a check is looking for. Every active check in this
build answered `clean` from exactly that request, with `considered`
populated, so `hx.scan._mark_unobserved` retired live findings on the
strength of a probe that tested nothing. The sender is therefore bound at
construction to the CONCRETE path of the surface's exemplar request
(`hx.insertion.request_path`, resolved by `hx.scan.run`, which skips the
check outright when it cannot be read), exposes it as `path`, and `get()`
REFUSES a path still carrying a placeholder. That refusal is a `ValueError`
and not a `ProbeRefused`, like the origin-form guard beside it and for the
same reason: nothing on the wire said no, a caller made a mistake, and a
`ProbeRefused` would land it in `check_run` as an ordinary `inconclusive`
row indistinguishable from a rate limit. A future check cannot reintroduce
the defect by reading `surface[5]`, because the seam will not send it.

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
seconds on what any one probe can add. `hx.scan.run` does NOT bound the run
by `max_seconds` -- it consults its deadline only at the top of the surface
loop (`scan.py:144`), so `max_seconds` bounds when the next surface starts,
not when the run ends: once a surface is in flight every check on it runs
to completion, and this retry can add its ceiling to each probe issued
there. That overshoot is accepted, not fixed: it is bounded (one surface's
probes, worst case tens of seconds), the safety envelope is
`limit.max_requests` and the rate limit rather than `max_seconds`, and
`_skip_rest(..., "budget", ...)` already records a skipped row for every
check a deadline miss does cut off. No deadline is threaded through here.

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

from hx import insertion as insertion_mod
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


def _placeholder_in(path: str) -> str | None:
    """The first template placeholder segment in `path`, or None.

    `hx.insertion.is_placeholder` decides the shape, because that module is
    already the one that turns a placeholder into an insertion point and two
    spellings of the test could disagree. The query string is not examined:
    every check percent-encodes what it puts there (`quote(safe="")` escapes
    `{` to `%7B`), so a brace can only reach the request line's PATH.

    A target that genuinely serves a `{...}` path segment is refused here
    too, which is a false positive with no better answer available: the
    segment is indistinguishable from an unsubstituted template, and the
    refusal is an `error` row -- visible, and retiring nothing -- while
    guessing the other way is F1 again. `hx.surface._kept_segment`
    percent-encodes such a segment when it templates it, so that surface's
    own `path_template` does not carry braces either.
    """
    for segment in path.partition("?")[0].split("/"):
        if insertion_mod.is_placeholder(segment):
            return segment
    return None


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
                 path: str) -> None:
        self._bridge = bridge
        self._scheme = scheme
        self._host = host
        self._port = port
        self._path = path
        self._sent = 0

    @property
    def sent(self) -> int:
        return self._sent

    @property
    def path(self) -> str:
        """The concrete path this surface's exemplar request asked for.

        WHAT A CHECK BUILDS ITS PROBE FROM, in place of `surface[5]`. The
        surface row carries the TEMPLATE, which is an identity rather than an
        address -- see the module docstring's third rule -- and this is the
        address the capture that proved this surface exists actually used.
        Read-only: a sender is bound to one surface for the life of one
        `check_run`, and a check that could move it could point it somewhere
        the operator never authorised.
        """
        return self._path

    def get(self, path: str, *, headers: dict[str, str] | None = None,
            timeout: float = 30.0) -> ProbeResponse:
        if not path.startswith("/"):
            raise ValueError(
                f"path must be origin-form and start with '/', got {path!r}; "
                "a sender is bound to one surface and cannot be pointed "
                "somewhere else")
        placeholder = _placeholder_in(path)
        if placeholder is not None:
            # STRUCTURAL, NOT DOCUMENTED. A check that reaches for
            # `surface[5]` -- or substitutes one placeholder of two -- is
            # asking to send a request to an address that cannot exist and
            # then to read the 404 as an answer. The one thing that makes
            # that unrepeatable is a seam that will not carry it.
            raise ValueError(
                f"path still holds the template placeholder {placeholder!r}: "
                f"{path!r}. A surface's `path_template` is its identity, not "
                "an address; build the probe from `sender.path` -- the "
                "exemplar's own concrete path -- and substitute into that")
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
