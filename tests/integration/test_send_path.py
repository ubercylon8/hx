"""The gate, proved rather than asserted.

Everything below crosses the whole stack: Python `send()`, the Unix socket,
the real extension inside a real headless Burp, out to a loopback HTTP server,
and back. Fakes prove the logic and they already do, exhaustively, in
extension/test; what only this file can prove is that the gate is in the path
that actually issues requests.

Two rules run through it:

  * A denial is asserted on the TARGET SERVER'S OWN LOG, not on the error
    class. "An error came back" and "the request was never issued" are
    different claims and only the second one is S4's invariant. The
    out-of-scope destination is a second live loopback server for exactly
    this reason -- an escaped request would be delivered and recorded there.

  * Nothing here sleeps to approach a boundary except where a real clock or
    a real poller makes waiting the only honest option, and each of those
    waits is bounded, named and derived rather than guessed. The rate-limit
    test is the one that sleeps on purpose: part way into the window, so a
    limiter answering a flat one second whatever it is asked cannot pass, and
    then for exactly the wait its refusal named. The budget test sleeps for
    nothing at all, because the budget has no clock in its decision.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from hx import engagement
from hx.bridge import codec, server
from hx.store import records
from tests.integration import burp_fixture as bf
from tests.integration import target_server

pytestmark = pytest.mark.integration

# HxExtension builds its HaltSwitch with HaltSwitch.DEFAULT_POLL_MS, which is
# 500 ms, so the extension needs at most two polls -- one second -- to notice
# a sentinel that has just appeared. The loop that spends this budget is paced
# by its own 0.2 s sleep and almost nothing else: a send against a target that
# closes its connections costs 0.59 ms p50 of it (see
# target_server._Handler.protocol_version), and a send the extension has
# already halted never leaves the JVM at all. So 5 s buys roughly 25 probes
# for a wait that needs about five.
#
# The one thing that can eat into it is the rate limit -- probing at 5/s
# against a configured rate_rps of 3 trips it -- which the loop sleeps out
# rather than counting as an answer. The window is a second and the halt
# lands inside one, so there is at most one such sleep and it is a partial
# window.
#
# This budget was also 5 s when a send cost ~1.003 s and bought four probes
# against the two polls needed. The Burp half of a send is now ~3,700x
# cheaper and the number has not moved, because 5 s is the honest answer to
# "how long may issuance continue after the operator pressed stop" -- which is
# what the failure message says -- rather than an estimate of how long the
# loop takes.
SENTINEL_POLL_S = 0.5
SENTINEL_HALT_BUDGET_S = 5.0

# Limiter's window is one second. Written out rather than derived from the
# extension's own constant, which is private for exactly this reason: a test
# that computes its expectation from the number it is checking agrees with
# itself whatever that number says. LimiterTest takes the same line.
RATE_WINDOW_US = 1_000_000
RATE_WINDOW_S = RATE_WINDOW_US / 1_000_000

# How far into the window the rate-limit test waits before spending the send
# that must be refused. Any value strictly inside the window works; 0.4 s is
# picked so the only correct retry hint (~0.6 s) is nowhere near a full
# second, which is what a limiter that answers a flat window whatever it is
# asked would return.
RATE_PROBE_OFFSET_S = 0.4

# What the retry-hint arithmetic allows for the two clocks involved running at
# slightly different rates. The extension times its window with Instant.now();
# this side brackets the same interval with time.monotonic(). 5 ms is 12,000
# ppm over the ~0.4 s the two marks span -- orders of magnitude more than any
# host drifts -- and it is a small widening of a band that the first send's
# own latency already makes ~37 ms wide (measured against this Burp: hint
# 573,050 us inside a band of [564,678, 601,754]). What matters is that both
# stay an order of magnitude short of the ~427 ms between a computed hint and
# a flat one-second answer -- the sabotage that answers WINDOW_US was
# measured at 1,000,000 against a band whose top was 598,971 -- so this slack
# cannot hide the failure it exists to tolerate around.
CLOCK_SKEW_SLACK_US = 5_000

# Error class -> `denial.kind` is records.DENIAL_KIND, imported rather than
# restated. A second copy here would be the copy nothing tests, and the two
# would agree right up until Plan 1's CHECK constraint grew a value.
# unmanaged_credential is in neither: see records.UNRECORDABLE, and the
# assertion that pins the gap in test_the_gate_refuses_four_ways.


def _blobs_containing(eng, needle: bytes) -> list[Path]:
    """Every blob whose bytes contain `needle`. Empty is the only good answer.

    Content-addressed storage is the reason this is a tree walk rather than a
    query: once raw bytes are hashed in, they are in every backup taken since,
    and no row has to reference them for that to be true.
    """
    return [p for p in sorted(eng.blobs.root.rglob("*"))
            if p.is_file() and needle in p.read_bytes()]


def _span_us(began: float, ended: float) -> int:
    """A time.monotonic() interval in microseconds, rounded outward.

    Used only to BRACKET an interval the extension timed on its own clock, so
    the rounding direction matters: int() would truncate toward zero and could
    make a bracket one microsecond too narrow, which is a flake rather than a
    finding.
    """
    return int((ended - began) * 1_000_000) + 1


def _issue_until(rig, target_path: str, *, want: str, attempts: int = 40) -> list:
    """Send `target_path` until the gate answers with error class `want`.

    A rate limit is slept out rather than treated as the answer. S6 says
    nothing retries automatically; this is a caller deciding to, explicitly,
    which is precisely the distinction that class exists to support. Every
    other error class is returned to the test rather than swallowed.

    That branch is live, not defensive: the only caller wants eleven answered
    samples from a host that replies in 40 ms, which is well above the 3/s
    this rig configures, so it is refused several times on the way and each
    refusal costs one attempt out of `attempts`. The COUNT is not fixed --
    it depends on where the sends fall inside each window, and a run measured
    here was refused three times where an earlier one was refused five -- so
    `attempts` is 40 rather than a number derived from either. 15 would be
    within reach of an unlucky run; 40 is not.

    The sends go out UNGUARDED, and that is not a stylistic choice. The
    auto-halt this loop waits for is announced by an unsolicited `halted`
    frame, which moves BridgeServer's own state to "halted" -- so a guarded
    send after that point is refused by this side's bookkeeping. MEASURED
    against a real Burp, with rig.get(): the eleventh refusal arrives with
    `srv.state == "halted"` and ZERO frames written to the socket, so the
    class this loop would end on is the harness agreeing with itself and the
    extension is never asked. The assertion still passes with the extension
    wide open, which is exactly the shape send_unguarded exists to avoid.
    """
    seen: list = []
    for _ in range(attempts):
        try:
            seen.append(rig.send_unguarded("GET", target_path)["status"])
        except server.BridgeError as exc:
            # A BridgeError this side raised before the wire -- a malformed
            # call -- has error_class None rather than a send-path class, so
            # None is a real answer here and not a missing attribute.
            error_class = exc.error_class
            if error_class == "rate_limited":
                time.sleep(exc.retry_after_us / 1_000_000 + 0.02)
                continue
            seen.append(error_class)
            if error_class == want:
                return seen
            raise AssertionError(
                f"waiting for {want}, got {error_class}: {exc} (so far: {seen})"
            ) from exc
    raise AssertionError(f"{attempts} attempts and no {want}: {seen}")


def test_deny_all_holds_then_an_in_scope_get_becomes_an_exchange_row(rig):
    """The happy path, and the state it starts from.

    DENY-ALL first: a live extension that has not been configured refuses
    everything. That is the 02:00 Burp-restart window in S4, and this is the
    only place it is exercised against a real JVM rather than a fake.

    Which is why the first send goes out UNGUARDED. BridgeServer.send refuses
    an unconfigured bridge on this side, before the wire -- rightly, two gates
    are better than one -- and a guarded send here is answered by that
    bookkeeping alone. MEASURED against a real Burp: guarded, ZERO frames
    reach the socket; unguarded, one does and comes back carrying the
    extension's own words, "no configure frame acknowledged yet". Only the
    second of those is evidence about the JVM. The guarded refusal is
    asserted too, immediately after, because both gates are meant to be there.
    """
    with pytest.raises(server.BridgeError) as unconfigured:
        rig.send_unguarded("GET", "/api/orders")
    assert unconfigured.value.error_class == "not_configured"
    assert rig.target.hits == [], \
        f"an unconfigured extension issued {rig.target.hits}"

    with pytest.raises(server.BridgeError) as locally:
        rig.get("/api/orders")
    assert locally.value.error_class == "not_configured"

    assert rig.configure() == 1

    reply = rig.get("/api/orders")
    assert reply["t"] == "result"
    assert reply["status"] == 200
    assert reply["outcome"] == "ok"
    assert reply["config_epoch"] == 1, \
        "the result must carry the epoch that authorised the scope it was decided under"
    # BODY_KEY carries the redacted raw HTTP response -- status line and
    # headers included, exactly what Sender put there -- not the parsed
    # entity body, so split them before handing anything to json.loads.
    raw = reply[server.BridgeServer.BODY_KEY]
    _head, _, body = raw.partition(b"\r\n\r\n")
    assert json.loads(body)["orders"][0]["id"] == 1

    hits = rig.target.hits_for("/api/orders")
    assert [hit.method for hit in hits] == ["GET"]

    # The harness's half: what came back becomes evidence. Plan 4 owns the
    # loop that does this for real; here it is one call, against a reply that
    # crossed a real socket from a real Burp. The blob holds the raw response
    # -- record_exchange's own docstring: "digests of the REDACTED bytes" --
    # not the entity body split out of it above, so a reader of the row later
    # gets back what actually crossed the wire, headers included.
    req_blob, _req_len = rig.eng.blobs.put(rig.last_request)
    resp_blob, resp_len = rig.eng.blobs.put(raw)
    # The row id, not a bare truthiness check: record_exchange returns the id
    # of the row it wrote, `x-` and twelve hex. A plain `assert` on the return
    # would be just as satisfied by True, by a rowcount, or by the run_id it
    # was handed back unchanged.
    assert records.record_exchange(
        rig.eng.db, run_id=rig.run_id, method="GET",
        url=f"{rig.target.origin}/api/orders", status=reply["status"],
        req_blob=req_blob, resp_blob=resp_blob, ms=reply["ms"],
        at_us=engagement.now_us()).startswith("x-")

    row = rig.eng.db.execute(
        "SELECT method, url, status, via, req_blob, resp_blob FROM exchange"
        " WHERE run_id=?", (rig.run_id,)).fetchone()
    assert row["method"] == "GET"
    assert row["url"] == f"{rig.target.origin}/api/orders"
    assert row["status"] == 200
    assert row["via"] == "send"
    assert row["req_blob"] == req_blob
    assert rig.eng.blobs.get(row["resp_blob"], resp_len) == raw


def test_the_gate_refuses_four_ways_and_no_target_sees_any_of_them(rig):
    rig.configure()

    # A successful send FIRST. Without it, every "the log is empty" assertion
    # below is also satisfied by a target server that never worked at all.
    assert rig.get("/health")["status"] == 200

    refusals: dict[str, server.BridgeError | None] = {}

    def attempt(name, method, target_path, **kwargs):
        """Send, and record the refusal -- or record that there was none.

        NOT `with pytest.raises(...)`. MEASURED, by deleting Sender's
        unmanaged-credential check and re-running: the credential send then
        SUCCEEDS and pytest.raises fails the test on the spot with a bare
        "DID NOT RAISE BridgeError", so the three assertions below -- the
        ones this test exists for, including the live cookie now sitting in
        the in-scope target's request log -- are never reached at all. A
        guard that cannot report what it caught is half a guard.
        """
        try:
            rig.send(method, target_path, **kwargs)
        except server.BridgeError as exc:
            refusals[name] = exc
        else:
            refusals[name] = None

    # Scope. 127.0.0.2 is a live server on a second loopback address, so a
    # request that escaped the gate would be DELIVERED there -- not refused
    # by a closed port, which would look identical to the gate working.
    attempt("scope", "GET", "/api/orders", to=rig.offside)

    # Method: the allowlist is GET/HEAD/OPTIONS.
    attempt("method", "POST", "/api/orders", body=b'{"total":"1.00"}')

    # Dangerous path: in scope, allowed method, still refused. "In scope" and
    # "safe to touch automatically" are different questions (S4).
    attempt("dangerous", "GET", "/account/logout")

    # A credential this extension did not inject (S7). Refused, and never
    # persisted -- there is nothing to persist, because it was never issued.
    cookie = f"session={target_server.SESSION_COOKIE_VALUE}"
    attempt("credential", "GET", "/api/orders",
            headers=[("Cookie", cookie)])

    # The assertions this test exists for, on what the SERVERS saw, and they
    # come FIRST: "an error came back" and "the request was never issued" are
    # different claims, and only the second one is S4's invariant.
    assert rig.offside.hits == [], \
        f"the out-of-scope target received {[(h.method, h.path) for h in rig.offside.hits]}"
    assert [hit.path for hit in rig.target.hits] == ["/health"], \
        f"the in-scope target received {[(h.method, h.path) for h in rig.target.hits]}"
    assert _blobs_containing(rig.eng, target_server.SESSION_COOKIE_VALUE.encode()) == []

    # "ALLOWED" rather than an AttributeError on None: a send that was not
    # refused at all has to name itself in the diff, not crash the assertion
    # that is trying to describe it.
    assert {name: (e.error_class if e else "ALLOWED")
            for name, e in refusals.items()} == {
        "scope": "scope_denied",
        "method": "method_denied",
        "dangerous": "dangerous_denied",
        "credential": "unmanaged_credential",
    }

    # Denials are never silent (S4): each one becomes a row.
    for name in ("scope", "method", "dangerous"):
        assert records.record_denial(
            rig.eng.db, run_id=rig.run_id,
            kind=records.DENIAL_KIND[refusals[name].error_class],
            method="POST" if name == "method" else "GET",
            url=f"{rig.target.origin}/api/orders",
            detail=str(refusals[name]), at_us=engagement.now_us())
    kinds = [r["kind"] for r in rig.eng.db.execute(
        "SELECT kind FROM denial WHERE run_id=? ORDER BY ts_us, rowid",
        (rig.run_id,))]
    assert kinds == ["scope", "method", "dangerous"]

    # A gap, pinned rather than papered over: Plan 1's denial.kind CHECK
    # lists scope, method, dangerous, rate, budget and not_configured. There
    # is no kind for unmanaged_credential -- nor for halted, transport_error,
    # timeout or bridge_lost -- so S6's error classes are wider than the
    # table that is supposed to record them. records.UNRECORDABLE is where
    # that is written down; this is where it is demonstrated, and when the
    # schema grows a kind these two assertions are what will say so.
    assert "unmanaged_credential" in records.UNRECORDABLE
    with pytest.raises((sqlite3.IntegrityError, ValueError)):
        records.record_denial(
            rig.eng.db, run_id=rig.run_id, kind="unmanaged_credential",
            method="GET", url=f"{rig.target.origin}/api/orders",
            detail="a Cookie header this extension did not inject",
            at_us=engagement.now_us())


def test_a_set_cookie_is_redacted_before_anything_can_hash_it(rig):
    """S7's one item that cannot be retrofitted.

    The application hands back a live session cookie the extension never
    injected, so the injected-range mechanism cannot reach it; response
    Set-Cookie VALUES are replaced by header name instead, before the bytes
    cross the bridge, because the blob store on this side is content-addressed
    and hashing raw bytes means the raw bytes are already on disk.
    """
    rig.configure()
    reply = rig.get("/login")
    assert reply["status"] == 200

    raw = reply[server.BridgeServer.BODY_KEY]
    assert b"Set-Cookie: session={{observed:set-cookie}}" in raw, raw
    # The name and the attributes stay, so session-fixation and cookie-flag
    # checks still have something to look at.
    assert b"Path=/" in raw and b"HttpOnly" in raw and b"SameSite=Lax" in raw
    assert target_server.SESSION_COOKIE_VALUE.encode() not in raw

    # And it stays gone through the store. Read the blob BACK, rather than
    # asserting on the bytes still in memory.
    req_blob, _req_len = rig.eng.blobs.put(rig.last_request)
    digest, size = rig.eng.blobs.put(raw)
    records.record_exchange(
        rig.eng.db, run_id=rig.run_id, method="GET",
        url=f"{rig.target.origin}/login", status=reply["status"],
        req_blob=req_blob, resp_blob=digest, ms=reply["ms"],
        at_us=engagement.now_us())
    stored = rig.eng.blobs.get(digest, size)
    assert target_server.SESSION_COOKIE_VALUE.encode() not in stored
    assert b"{{observed:set-cookie}}" in stored

    # Not "not in the blob we just wrote" -- not anywhere in the tree.
    assert _blobs_containing(rig.eng, target_server.SESSION_COOKIE_VALUE.encode()) == []

    # The server really did send it, so the absence above is redaction and
    # not a route that quietly stopped setting a cookie.
    assert rig.target.hits_for("/login")


def test_the_rate_limit_trips_and_its_retry_hint_is_true(rig):
    """S6's first limit, and the promise the refusal carries.

    A limiter that denies but lies about when to retry is worse than one that
    just denies: the agent obeys `retry_after_us`, so a hint that is short
    spins and a hint that is long stalls a run for no reason. The arithmetic
    is proved exactly in Task 2 against a clock the test moves by hand. What
    only this file can show is that the decision sits in the path that issues
    requests and that the number survives all the way out -- Limiter, the
    Decision, the `error` frame's optional field, BridgeError -- and is still
    true when a real caller waits it out against a real Burp.

    This test can exist at all only because the target server closes its
    connections. Burp's send call returns when the SOCKET closes, so a
    keep-alive target costs ~1.003 s a send, the bridge's one read loop cannot
    then place two sends inside one second, and no configured rate is
    reachable. See target_server._Handler.protocol_version, which says the
    same thing from the other end.
    """
    rps = rig.eng.config.rate_limit_rps
    rig.configure()

    # The burst. It shares one window with room to spare -- three sends
    # measured at 28 ms in total, against a window of a second -- so the
    # FIRST of them is the one whose departure the retry hint has to be
    # about. Nearly all of those 28 ms are the first send alone, 25 ms of
    # them, against 0.57 ms p50 for a warm one (measured back to back,
    # n=300, min 0.33, p90 1.25). That is why first_start and first_done are
    # separate marks rather than one: the bracket around the first issuance
    # has to be wide enough to hold whatever the first send costs, and a
    # single mark would make it a guess.
    first_start = time.monotonic()
    assert rig.get("/health")["status"] == 200
    first_done = time.monotonic()
    for n in range(2, rps + 1):
        assert rig.get("/health")["status"] == 200, \
            f"issuance {n} of {rps} was refused inside its own window"

    # Part way in, deliberately: a limiter that answers a flat one second
    # whatever it is asked passes a hint checked at the top of the window and
    # fails one checked here.
    time.sleep(RATE_PROBE_OFFSET_S)

    hits_before = len(rig.target.hits_for("/health"))
    refusal_start = time.monotonic()
    refusal = None
    try:
        rig.get("/health")
    except server.BridgeError as exc:
        refusal = exc
    refusal_done = time.monotonic()

    assert refusal is not None, (
        f"send {rps + 1} was allowed {refusal_done - first_start:.3f}s after "
        f"send 1, against a configured limit.rate_rps of {rps}. Either the "
        "extension is not reading limit.rate_rps out of the configure body "
        f"(its own fallback is 5, which {rps + 1} sends would not exceed), or "
        "the target is holding its connections open and each send is costing "
        "~1.003s -- see target_server._Handler.protocol_version.")
    assert refusal.error_class == "rate_limited", refusal
    assert f"{rps}/s" in str(refusal), (
        f"the refusal names a rate other than the {rps}/s configured: {refusal}")

    assert refusal_done - first_start < RATE_WINDOW_S, (
        f"the burst and the refusal spanned {refusal_done - first_start:.3f}s, "
        f"longer than the {RATE_WINDOW_S}s window, so the first issuance had "
        "already left it and nothing below can be concluded")

    # The arithmetic, bracketed rather than approximated. The extension put
    # the first issuance on its window at some instant A with
    # first_start <= A <= first_done, and decided this refusal at some B with
    # refusal_start <= B <= refusal_done. The hint it must carry is exactly
    # A + RATE_WINDOW_US - B, so widening each end to the interval that
    # brackets it gives two inequalities that hold for every A and B in range.
    hint = refusal.retry_after_us
    assert isinstance(hint, int), f"retry_after_us is {hint!r}, not an integer"
    assert 0 < hint <= RATE_WINDOW_US, (
        f"a {RATE_WINDOW_S}s window cannot produce a wait of {hint}us")
    lowest = RATE_WINDOW_US - _span_us(first_start, refusal_done) - CLOCK_SKEW_SLACK_US
    highest = RATE_WINDOW_US - _span_us(first_done, refusal_start) + CLOCK_SKEW_SLACK_US
    assert lowest <= hint <= highest, (
        f"retry_after_us is {hint}us; the oldest issuance in the window leaves "
        f"it between {lowest}us and {highest}us from when this refusal was "
        f"decided. {RATE_WINDOW_US}us would be the answer for a limiter that "
        "returns the whole window instead of the wait for its oldest entry")

    # Still limited, and the target's own request log -- the one witness this
    # side cannot fake -- says so.
    for _ in range(3):
        with pytest.raises(server.BridgeError) as again:
            rig.get("/health")
        assert again.value.error_class == "rate_limited"
    assert len(rig.target.hits_for("/health")) == hits_before, \
        "a rate-limited extension issued a request anyway"

    # The promise itself. Waiting exactly what the refusal asked for -- plus
    # whatever the three refusals above cost, which can only overshoot -- and
    # the gate opens. "Not a microsecond more" is Task 2's half of this: a
    # wall clock cannot place a send a microsecond early.
    time.sleep(hint / 1_000_000)
    assert rig.get("/health")["status"] == 200, (
        "the gate refused, named a wait, and was still refusing after it")
    assert len(rig.target.hits_for("/health")) == hits_before + 1

    # Denials are never silent (S4). rate_limited has a kind of its own,
    # unlike unmanaged_credential.
    assert records.record_denial(
        rig.eng.db, run_id=rig.run_id,
        kind=records.DENIAL_KIND["rate_limited"],
        method="GET", url=f"{rig.target.origin}/health",
        detail=str(refusal), at_us=engagement.now_us()).startswith("d-")
    row = rig.eng.db.execute(
        "SELECT kind FROM denial WHERE run_id=? ORDER BY ts_us, rowid",
        (rig.run_id,)).fetchone()
    assert row["kind"] == "rate"


def test_the_run_budget_is_exhausted_and_stays_exhausted(rig):
    """S6's other limit, and the one that depends on nothing at all.

    The rate-limit test next door needs the target server to close its
    connections before a sub-second limit is even reachable. This one needs
    nothing: `Limiter.check` only counts, with no clock in the decision, so
    the budget is exhausted by a slow harness exactly as surely as by a fast
    one and this test would pass unchanged against a keep-alive target at a
    second a send. That is why it is the limit to reach for when a timing
    question is in doubt.

    max_requests is 2 here against the rig's default of 2000, so it also says
    that the number in the configure body is the number enforced -- and 2000
    happens to be HxExtension.DEFAULT_MAX_REQUESTS, the fallback, which is
    exactly why the test may not use the default.
    """
    # max_requests=2, not the rig's default of 2000: Limits.arm only ever
    # arms once per run, so this has to be the FIRST configure this test
    # issues (see Rig.configure's docstring).
    rig.configure(max_requests=2)

    assert rig.get("/health")["status"] == 200
    assert rig.get("/health")["status"] == 200

    with pytest.raises(server.BridgeError) as exc:
        rig.get("/health")
    assert exc.value.error_class == "budget_exhausted"
    assert str(exc.value) == \
        "budget_exhausted: run budget spent: 2 of 2 requests issued"

    # The refusal never reached the target -- the budget is enforced before
    # issuance, not after -- and the target's own request log is the witness
    # this side cannot fake.
    assert len(rig.target.hits_for("/health")) == 2

    # Monotonic by construction, and there is deliberately no way to refill it
    # (Limiter.check's own comment): a further attempt spends nothing and is
    # refused exactly the same way, for ever. A `configure` re-authorises
    # scope, not issuance.
    with pytest.raises(server.BridgeError) as again:
        rig.get("/health")
    assert again.value.error_class == "budget_exhausted"
    assert len(rig.target.hits_for("/health")) == 2

    # Denials are never silent (S4), same as the four-ways test above.
    assert records.record_denial(
        rig.eng.db, run_id=rig.run_id,
        kind=records.DENIAL_KIND["budget_exhausted"],
        method="GET", url=f"{rig.target.origin}/health",
        detail=str(exc.value), at_us=engagement.now_us()).startswith("d-")
    row = rig.eng.db.execute(
        "SELECT kind FROM denial WHERE run_id=? ORDER BY ts_us, rowid",
        (rig.run_id,)).fetchone()
    assert row["kind"] == "budget"


def test_the_sentinel_halts_issuance_and_a_frame_outlives_its_removal(rig):
    """Two of S4's three kill paths, and the rule that they are independent.

    Both halves are arranged so the `send` frame actually leaves this process,
    which is the whole difficulty of testing a kill switch from a harness that
    holds one of the buttons. BridgeServer.send refuses locally whenever the
    durable halt is armed or its own state says halted; written the obvious
    way, every assertion below is satisfied by that bookkeeping alone and goes
    on passing with the extension wide open.

    So the sentinel half goes out through rig.send_unguarded(), and the frame
    half puts the halt frame on the wire itself so rig.srv.state never leaves
    "configured". Each refusal is also checked against rig.target.hits: the
    target server's own request log is the one witness this side cannot fake.
    """
    rig.configure()
    assert rig.get("/api/orders")["status"] == 200

    rig.halt.halt("operator pressed stop during the integration run")
    assert rig.halt.halted is True
    assert rig.halt.reason == "operator pressed stop during the integration run"
    assert rig.sentinel.exists()

    deadline = time.monotonic() + SENTINEL_HALT_BUDGET_S
    halted_class = None
    while time.monotonic() < deadline and halted_class is None:
        try:
            # Unguarded: this side would otherwise refuse the send itself, on
            # the strength of the sentinel it just wrote, and never ask the
            # extension anything.
            rig.send_unguarded("GET", "/health")
        except server.BridgeError as exc:
            if exc.error_class == "rate_limited":
                # Not an answer to the question this loop is asking. Probing
                # at 5/s against a configured 3/s trips the limit before the
                # extension has necessarily noticed the sentinel, and the
                # decision order answers `halted` before `rate_limited`, so a
                # rate limit here means the halt has NOT landed yet. Sleep
                # what the refusal asked for and ask again -- S6's own
                # prescription, and the sentinel budget above allows for one
                # of these.
                time.sleep(exc.retry_after_us / 1_000_000 + 0.02)
                continue
            halted_class = exc.error_class
            assert halted_class == "halted", exc
        time.sleep(0.2)
    assert halted_class == "halted", (
        f"issuance continued {SENTINEL_HALT_BUDGET_S}s after the sentinel "
        f"appeared at {rig.sentinel}")

    # The refusal, and the evidence that it WAS a refusal. `halted` arrived
    # over the wire from a JVM that read the sentinel file, and the target's
    # log did not move.
    before = len(rig.target.hits)
    with pytest.raises(server.BridgeError) as exc:
        rig.send_unguarded("GET", "/api/orders")
    assert exc.value.error_class == "halted"
    assert len(rig.target.hits) == before, \
        "a halted extension issued a request anyway"

    # Now a halt FRAME joins the sentinel. Two paths, one state.
    #
    # The frame goes out directly rather than through rig.srv.halt(), which
    # would also arm the durable halt and move this side's state to "halted" --
    # and then every send below is refused here, without the extension being
    # asked. The frame is what is under test, so the frame is all that is sent.
    rig.srv._send({"v": codec.PROTOCOL_VERSION, "t": "halt",
                   "reason": "operator pressed stop"})

    # Removing the sentinel must NOT re-arm: the frame is still in force, and
    # a kill switch that any one of its three paths can cancel is not three
    # independent paths, it is one with three buttons.
    rig.halt.resume()
    assert not rig.sentinel.exists()
    assert rig.halt.halted is False
    assert rig.srv.state == "configured", \
        "this side must still believe it may issue, or what follows is a " \
        "test of the harness and not of the extension"
    time.sleep(SENTINEL_POLL_S * 3)          # three chances to notice

    # NOT `with pytest.raises(...)` around the send. MEASURED, by collapsing
    # HaltSwitch's two inputs into one and re-running: the send then SUCCEEDS,
    # and pytest.raises fails the test with a bare "DID NOT RAISE
    # BridgeError" before either of the two sentences below is ever reached.
    # The diagnostic a guard prints is part of the guard, and this file's own
    # rule is that the target server's log is the claim -- so the log is
    # asserted FIRST, and the error class after it.
    before = len(rig.target.hits)
    refusal = None
    try:
        rig.get("/api/orders")
    except server.BridgeError as exc:
        refusal = exc
    assert len(rig.target.hits) == before, \
        "removing the sentinel re-armed issuance: the request reached the target"
    assert refusal is not None and refusal.error_class == "halted", \
        ("removing the sentinel re-armed issuance while a halt frame was in "
         f"force; the send answered {refusal if refusal else 'successfully'}")

    # Only resume re-arms, and the target's log is what says the request was
    # issued this time rather than merely permitted.
    rig.srv.resume()
    assert rig.get("/api/orders")["status"] == 200
    assert len(rig.target.hits) == before + 1


def test_five_hundreds_from_the_slow_route_abort_the_whole_run(rig):
    """S4's auto-halt, and the frame that makes it visible.

    The 5xx rule needs ten answered samples on a host before it may trip, so
    ten 500s is the earliest it can fire and the eleventh send is the first
    one refused.
    """
    rig.configure()

    frames: list[dict] = []
    # Appended, not acted on. This callback runs on the bridge's read-loop
    # thread, and sqlite3 connections are single-thread by default, so the
    # store write below belongs to the thread that owns the run.
    rig.srv.on_halted = frames.append

    seen = _issue_until(rig, "/slow?ms=40&status=500", want="halted")
    assert seen.count(500) >= 10, \
        f"the 5xx rule needs ten answered samples before it may trip; got {seen}"
    assert seen[-1] == "halted"

    assert bf.wait_for(lambda: bool(frames), timeout=10), (
        "auto-halt is extension-initiated, so there is no outstanding id to "
        "answer: without an unsolicited `halted` frame it is invisible until "
        "the next send fails and run.status has no stop_reason to record")
    frame = frames[0]
    assert frame["t"] == "halted"
    assert "5xx rate" in frame["reason"], frame
    assert frame["host"] == rig.target.host, frame
    assert frame["window"], frame

    assert records.abort_run(
        rig.eng.db, run_id=rig.run_id,
        stop_reason=f"{frame['reason']} on {frame['host']}",
        at_us=engagement.now_us()) is True
    row = rig.eng.db.execute(
        "SELECT status, stop_reason, ended_us FROM run WHERE id=?",
        (rig.run_id,)).fetchone()
    assert row["status"] == "aborted"
    assert "5xx rate" in row["stop_reason"]
    assert row["ended_us"] is not None

    # One distressed host aborts the WHOLE run, and a human decides when it
    # restarts. `resume` lifts an operator halt; it does not undo distress.
    rig.srv.resume()
    with pytest.raises(server.BridgeError) as exc:
        rig.get("/health")
    assert exc.value.error_class == "halted", \
        "a resume frame un-did an auto-halt; distress has no reset by design"
