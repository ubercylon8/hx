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
# closes its connections costs 0.57 ms p50 of it (see
# target_server._Handler.protocol_version, which is the source this number is
# quoted FROM and which it disagreed with -- 0.59 against 0.57 -- for the life
# of Task 8), and a send the extension has already halted never leaves the JVM
# at all. So 5 s buys roughly 25 probes for a wait that needs about five.
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
# unmanaged_credential was in neither until SCHEMA_VERSION 6 gave it the
# `credential` kind; the assertions in test_the_gate_refuses_four_ways are
# where that closure is demonstrated rather than asserted.


def _blobs_containing(eng, needle: bytes) -> list[Path]:
    """Every blob whose bytes contain `needle`. Empty is the only good answer.

    Content-addressed storage is the reason this is a tree walk rather than a
    query: once raw bytes are hashed in, they are in every backup taken since,
    and no row has to reference them for that to be true.
    """
    return [p for p in sorted(eng.blobs.root.rglob("*"))
            if p.is_file() and needle in p.read_bytes()]


def _refusal_from(call, *args, **kwargs) -> server.BridgeError | None:
    """Run `call`; hand back the BridgeError it raised, or None if it did not.

    THE REPLACEMENT FOR `with pytest.raises(server.BridgeError):` EVERYWHERE
    IN THIS FILE, and the reason is this file's own first rule: a denial is
    asserted on the TARGET SERVER'S OWN LOG, not on the error class.

    `pytest.raises` inverts that. When a guard is deleted the send SUCCEEDS,
    the context manager fails the test at the `with` block with a bare
    "DID NOT RAISE BridgeError", and every assertion after it -- including
    the one saying a request reached a live server -- is never reached.
    "No error came back" and "a request was issued" are different claims and
    only the second is what S4 forbids; a report that makes only the first
    sends whoever reads it to the wrong end of the stack.

    It is also what keeps ONE broken guard from hiding the others: a refusal
    checked this way does not abort the refusals after it, so a loop of three
    reports three answers rather than the first.

    MEASURED both ways, real Burp, one sabotage (Limiter's per-run budget
    guard deleted), the two shapes run back to back:

        before   E  Failed: DID NOT RAISE BridgeError
        after    E  AssertionError: a spent run budget issued anyway: the
                    target served 3 against max_requests=2

    Quoted here rather than referenced, because the report it came from is
    not in this repository and a comment pointing somewhere a reader cannot
    follow is the thing this branch keeps finding. The two comments below
    record their own sabotages the same way.
    """
    try:
        call(*args, **kwargs)
    except server.BridgeError as exc:
        return exc
    return None


def _classes(refusals) -> list | dict:
    """Error classes, with "ALLOWED" standing in for a send nobody refused.

    Never an AttributeError on None: a send that was not refused at all has to
    NAME ITSELF in the assertion diff, not crash the assertion that is trying
    to describe it.
    """
    if isinstance(refusals, dict):
        return {name: (e.error_class if e else "ALLOWED")
                for name, e in refusals.items()}
    return [e.error_class if e else "ALLOWED" for e in refusals]


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
    # NOT `with pytest.raises(...)`, and this is the site where that matters
    # most in the file. Delete the unconfigured guard from Sender and this
    # send SUCCEEDS: an extension that has been told nothing at all delivers a
    # request to a live server. pytest.raises reports that as
    # "DID NOT RAISE BridgeError" -- true, and it never mentions the delivery.
    # So the target's own log is asserted FIRST and the class second.
    unconfigured = _refusal_from(rig.send_unguarded, "GET", "/api/orders")
    assert rig.target.hits == [], (
        "DENY-ALL was not held: an unconfigured extension issued "
        f"{[(h.method, h.path) for h in rig.target.hits]} to a live server")
    assert unconfigured is not None and \
        unconfigured.error_class == "not_configured", \
        f"the JVM answered {_classes([unconfigured])[0]!r}"

    # The guarded refusal, which this side owns. No target assertion belongs
    # here: BridgeServer.send refuses before the wire, so there is no send to
    # have been issued and "DID NOT RAISE" is the whole of the diagnosis.
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

        Four attempts, and each one is answered whatever the ones before it
        did. Under pytest.raises the FIRST failing guard would abort the
        other three, so one sabotage would be reported as one broken guard
        when it is the only one that got to speak.
        """
        refusals[name] = _refusal_from(rig.send, method, target_path, **kwargs)

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

    # ...and the SAME credential on a request that also leaves scope. This
    # shape had never been driven: every case above sends its credential to
    # an in-scope path, so the two guards were never made to compete.
    #
    # Until the whole-branch review it answered `unmanaged_credential`, which
    # was then in records.UNRECORDABLE -- so a scope violation carrying a
    # Cookie produced no row anywhere and named the credential rather than the
    # boundary crossed. The class has a row of its own now, and the ordering
    # still matters: the scope boundary is the fact worth recording, and a
    # `credential` row would name the wrong reason for the refusal. It is not
    # an exotic input either: until Plan 5 ships
    # identity injection, the natural agent action is replaying a request
    # lifted from Burp's history, and those carry a Cookie.
    attempt("scope_with_credential", "GET", "/api/orders", to=rig.offside,
            headers=[("Cookie", cookie)])

    # The assertions this test exists for, on what the SERVERS saw, and they
    # come FIRST: "an error came back" and "the request was never issued" are
    # different claims, and only the second one is S4's invariant.
    assert rig.offside.hits == [], \
        f"the out-of-scope target received {[(h.method, h.path) for h in rig.offside.hits]}"
    assert [hit.path for hit in rig.target.hits] == ["/health"], \
        f"the in-scope target received {[(h.method, h.path) for h in rig.target.hits]}"
    assert _blobs_containing(rig.eng, target_server.SESSION_COOKIE_VALUE.encode()) == []

    assert _classes(refusals) == {
        "scope": "scope_denied",
        "method": "method_denied",
        "dangerous": "dangerous_denied",
        "credential": "unmanaged_credential",
        # The boundary, not the credential -- and so a class with a row.
        "scope_with_credential": "scope_denied",
    }

    # Denials are never silent (S4): each one becomes a row. The fifth case is
    # in this loop and not merely in the dict above, because "it reported
    # scope_denied" and "it produced a denial row" are different claims and
    # only the second is S4's.
    for name in ("scope", "method", "dangerous", "scope_with_credential"):
        assert records.record_denial(
            rig.eng.db, run_id=rig.run_id,
            kind=records.DENIAL_KIND[refusals[name].error_class],
            method="POST" if name == "method" else "GET",
            url=f"{rig.target.origin}/api/orders",
            detail=str(refusals[name]), at_us=engagement.now_us())
    kinds = [r["kind"] for r in rig.eng.db.execute(
        "SELECT kind FROM denial WHERE run_id=? ORDER BY ts_us, rowid",
        (rig.run_id,))]
    assert kinds == ["scope", "method", "dangerous", "scope"]

    # The gap this block used to pin is CLOSED, and these assertions are what
    # said so. Plan 1's denial.kind CHECK listed scope, method, dangerous,
    # rate, budget and not_configured, and there was no kind for
    # unmanaged_credential -- so S4's "denials are never silent" did not hold
    # for the one class here that IS a denial about a request the extension
    # agreed to look at. SCHEMA_VERSION 6 added 'credential'.
    #
    # The classes still wider than the tables are halted, transport_error,
    # timeout and bridge_lost, and none of those is a denial: a run-wide stop,
    # a transport failure, and two that name a request the caller gave up on.
    # records.UNRECORDABLE carries each with its reason.
    assert "unmanaged_credential" not in records.UNRECORDABLE
    assert records.record_denial(
        rig.eng.db, run_id=rig.run_id,
        kind=records.DENIAL_KIND["unmanaged_credential"],
        method="GET", url=f"{rig.target.origin}/api/orders",
        detail="a Cookie header this extension did not inject",
        at_us=engagement.now_us()).startswith("d-")
    assert rig.eng.db.execute(
        "SELECT kind FROM denial WHERE run_id=? ORDER BY ts_us DESC, rowid DESC",
        (rig.run_id,)).fetchone()["kind"] == "credential"
    # ...and the class is still not a KIND. Passing the wire name where a
    # schema value belongs is the mistake this refusal exists for, and closing
    # the gap did not make the two words interchangeable.
    with pytest.raises(ValueError, match="not a denial kind"):
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
    refusal = _refusal_from(rig.get, "/health")
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
    #
    # All three are ISSUED before any of them is judged. Under
    # `with pytest.raises(...)` the first one that came back allowed would end
    # the test inside the loop: the other two would never be attempted, and
    # the log assertion below -- the one that says requests REACHED the target
    # -- would never run. One sabotage would then be reported as one broken
    # guard, having silenced the two after it.
    still_limited = [_refusal_from(rig.get, "/health") for _ in range(3)]
    assert len(rig.target.hits_for("/health")) == hits_before, (
        "a rate-limited extension issued a request anyway: "
        f"{len(rig.target.hits_for('/health')) - hits_before} of the three "
        "reached the target")
    assert _classes(still_limited) == ["rate_limited"] * 3, still_limited

    # The promise itself. Waiting exactly what the refusal asked for -- plus
    # whatever the three refusals above cost, which can only overshoot -- and
    # the gate opens. "Not a microsecond more" is Task 2's half of this: a
    # wall clock cannot place a send a microsecond early.
    time.sleep(hint / 1_000_000)
    assert rig.get("/health")["status"] == 200, (
        "the gate refused, named a wait, and was still refusing after it")
    assert len(rig.target.hits_for("/health")) == hits_before + 1

    # Denials are never silent (S4), and rate_limited has a kind of its own.
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

    exhausted = _refusal_from(rig.get, "/health")

    # The refusal never reached the target -- the budget is enforced before
    # issuance, not after -- and the target's own request log is the witness
    # this side cannot fake. Asserted FIRST: a budget that has stopped
    # counting spends a third request against a limit of two, and "the target
    # served 3" is the finding, not "no exception was raised".
    assert len(rig.target.hits_for("/health")) == 2, (
        "a spent run budget issued anyway: the target served "
        f"{len(rig.target.hits_for('/health'))} against max_requests=2")
    assert exhausted is not None and \
        exhausted.error_class == "budget_exhausted", \
        f"the JVM answered {_classes([exhausted])[0]!r}"
    assert str(exhausted) == \
        "budget_exhausted: run budget spent: 2 of 2 requests issued"

    # Monotonic by construction, and there is deliberately no way to refill it
    # (Limiter.check's own comment): a further attempt spends nothing and is
    # refused exactly the same way, for ever. A `configure` re-authorises
    # scope, not issuance.
    again = _refusal_from(rig.get, "/health")
    assert len(rig.target.hits_for("/health")) == 2, (
        "the budget refilled: a later send past an exhausted budget reached "
        f"the target, which has now served {len(rig.target.hits_for('/health'))}")
    assert again is not None and again.error_class == "budget_exhausted", \
        f"the JVM answered {_classes([again])[0]!r}"

    # Denials are never silent (S4), same as the four-ways test above.
    assert records.record_denial(
        rig.eng.db, run_id=rig.run_id,
        kind=records.DENIAL_KIND["budget_exhausted"],
        method="GET", url=f"{rig.target.origin}/health",
        detail=str(exhausted), at_us=engagement.now_us()).startswith("d-")
    row = rig.eng.db.execute(
        "SELECT kind FROM denial WHERE run_id=? ORDER BY ts_us, rowid",
        (rig.run_id,)).fetchone()
    assert row["kind"] == "budget"


def test_a_mid_run_configure_that_moves_the_rate_is_refused_by_the_jvm(rig):
    """F8, driven end to end for the first time.

    S4: the rate and the budget are armed ONCE and held for the run. A later
    `configure` naming a different one must be REFUSED, not silently ignored --
    an operator who believes they slowed a run down and did not is the failure
    that rule exists to prevent, and it is silent by construction: the second
    configure returns a fresh `config_epoch` and the old rate keeps running.

    UNTIL THIS TEST, NOTHING DROVE IT AGAINST THE REAL EXTENSION. The Java
    test installs `Limits.refuseIfLimitsMoved` directly, so it never exercised
    `HxExtension`'s `c.setConfigGuard(...)` line -- and `ConfigGuard` FAILS
    OPEN when uninstalled (BridgeClient.refuseConfigure returns null for a null
    guard, deliberately: an unwired guard restores a silent-ignore and breaches
    no scope, where an unwired HaltSource would leave a run unstoppable). So
    the wire was held by one raw-text needle in ChokepointTest that a `//`
    could satisfy, and by nothing else in the repository.

    THE REFUSAL IS PROVED TO HAVE COME FROM THE JVM, twice over, because this
    side has its own bookkeeping and a test satisfied by that would pass with
    the guard gone:

      * the detail text. `limit.rate_rps cannot change mid-run: this run armed
        at N and this configure asks for M` is written in `Limits.movedFrom`
        and exists nowhere on the Python side to be fabricated.
      * the consequence. `bad_config` calls `denyAll()` in the extension BEFORE
        answering, so the next send is refused from inside the JVM and the
        target server records nothing -- which is the claim S4 actually makes,
        and the only one asserted on the target's own log.

    THE CLASS OF THAT SECOND REFUSAL IS `not_configured`, NOT `scope_denied`,
    and it was measured rather than assumed -- this test asserted
    `scope_denied` first and the JVM answered `not_configured`. `denyAll()`
    does not narrow the scope to nothing; it puts the extension back to having
    no acknowledged configure at all, at epoch 0, which is the first half of
    what the protocol doc says that class means. The doc also says the class is
    OVERLOADED -- the send path throwing or never being installed lands there
    too, prefixed `extension fault: ` -- so the absence of that prefix is
    asserted as well. "The operator has not authorised this run" and "this jar
    is broken" are opposite instructions, and a test that accepted either would
    be green against a send path that had crashed.

    The second configure is built by `rig.configure(rate_rps=...)` rather than
    in this test, so the body that is refused is the body the rig would really
    send.
    """
    armed = rig.eng.config.rate_limit_rps
    rig.configure()

    # The limits arm on the first SEND, not on the configure: `Limits.arm` runs
    # inside the send handler. A test that pushed the second configure straight
    # after the first would find `limiter == null`, be answered null by
    # `refuseIfLimitsMoved`, and pass with the guard wired or not.
    first = rig.get("/api/orders")
    assert first["status"] == 200, first
    assert len(rig.target.hits_for("/api/orders")) == 1

    moved = armed + 1
    refusal = _refusal_from(rig.configure, rate_rps=moved)
    assert refusal is not None, (
        f"a mid-run configure moving limit.rate_rps from {armed} to {moved} "
        "was ACCEPTED. It returns a fresh config_epoch and goes on issuing at "
        f"{armed}/s, which is S4's silent-ignore -- the operator believes the "
        "run was slowed and it was not")
    detail = str(refusal)
    assert "bad_config" in detail, detail
    # The extension's own words. Nothing on this side can write these.
    assert "limit.rate_rps cannot change mid-run" in detail, detail
    assert f"armed at {armed}" in detail, detail
    assert f"asks for {moved}" in detail, detail

    # THE CONSEQUENCE, on the target server's own log: `bad_config` denies all
    # first, so the next send is refused inside the JVM and nothing is issued.
    after = _refusal_from(rig.send_unguarded, "GET", "/api/orders")
    assert _classes([after]) == ["not_configured"], _classes([after])
    assert "extension fault: " not in str(after), (
        "the send after the refused configure was refused because the send "
        f"path itself broke, not because DENY-ALL held: {after}")
    assert len(rig.target.hits_for("/api/orders")) == 1, (
        "a send was issued after a refused configure dropped the extension to "
        f"DENY-ALL: the target served "
        f"{len(rig.target.hits_for('/api/orders'))}")
    # ...and no epoch was left behind for it. An operator told `bad_config`
    # must not find a fresh config_epoch on the next result frame.
    assert rig.srv.config_epoch == 0, rig.srv.config_epoch


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
    halted = _refusal_from(rig.send_unguarded, "GET", "/api/orders")
    assert len(rig.target.hits) == before, (
        "a halted extension issued a request anyway; the target received "
        f"{[(h.method, h.path) for h in rig.target.hits[before:]]} after the "
        "sentinel was written")
    assert halted is not None and halted.error_class == "halted", \
        f"the JVM answered {_classes([halted])[0]!r}"

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
    refusal = _refusal_from(rig.get, "/api/orders")
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
    #
    # The consequence of getting this wrong is not an exception that failed to
    # arrive -- it is a run that an auto-halt stopped and a resume frame
    # started again. So the target's log is what says so, and it is asserted
    # first: `/health` has been untouched for the whole test, so any hit at
    # all on it is issuance that distress was supposed to have ended.
    before = len(rig.target.hits_for("/health"))
    rig.srv.resume()
    after_resume = _refusal_from(rig.get, "/health")
    assert len(rig.target.hits_for("/health")) == before, (
        "a resume frame un-did an auto-halt: the request was ISSUED and "
        "reached the target. Distress has no reset by design")
    assert after_resume is not None and after_resume.error_class == "halted", (
        "a resume frame un-did an auto-halt; distress has no reset by design. "
        f"The send answered {_classes([after_resume])[0]!r}")


def test_early_hints_do_not_hide_a_failing_origin_from_the_auto_halt(rig):
    """The two spec amendments, against a real Burp rather than a fake.

    `dfc2080` (finalStatus) and `a188d0d` (the `status_unreadable`
    discriminator) were both written from a MEASUREMENT of Montoya's
    behaviour: on a 103-then-200 exchange `response().statusCode()` answers
    103 while `toByteArray()` carries BOTH heads. Everything downstream of
    that measurement was proved against fakes in SenderTest. This is the one
    place the measurement itself is re-confirmed, and it matters because the
    exchange it describes is not exotic -- it is a CDN in front of a failing
    origin, and the failure mode is that spec S4's 20% rule NEVER FIRES
    because every sample it counted was a 103.

    Three claims, in the order they have to hold:

      1. one interim head, then a 500: the frame says 500 and `outcome: ok`,
         and the bytes attached to it carry both heads. The status was read
         out of the RESPONSE, not off the transport.
      2. nine interim heads -- one past Sender.MAX_INTERIM_HEADS: 599 with
         `outcome: status_unreadable`. The scan ran out of budget rather than
         out of bytes, and it says which, because 599 is not reserved and a
         peer may send it for itself.
      3. the consequence. Distress counts the CORRECTED 500, so a run against
         this host aborts. That is the whole reason (1) is not merely
         cosmetic.
    """
    rig.configure()

    frames: list[dict] = []
    # Appended, not acted on -- same reason as the /slow test next door: this
    # callback runs on the bridge's read-loop thread and the store connection
    # belongs to the thread that owns the run.
    rig.srv.on_halted = frames.append

    # 1. The transport reports the interim head; the frame reports the origin.
    reply = rig.get("/hints?n=1&status=500")
    assert (reply["status"], reply["outcome"]) == (500, "ok"), (
        "the status on the evidence line came off the TRANSPORT, which parsed "
        f"the 103 as the response: {reply['status']} / {reply['outcome']!r}")
    raw = reply[server.BridgeServer.BODY_KEY]
    assert raw.startswith(b"HTTP/1.1 103 Early Hints"), raw[:64]
    assert b"HTTP/1.0 500 " in raw, raw[:256]

    # 2. Past the budget, and the discriminator that keeps this 599 apart
    #    from a peer's own. `status` stays 599 in both, by design -- the
    #    conservative-for-auto-halt property must not come to depend on
    #    anyone reading a second field -- so `outcome` is what carries it.
    reply = rig.get("/hints?n=9&status=500")
    assert (reply["status"], reply["outcome"]) == (599, "status_unreadable"), (
        "a scan that ran out of BUDGET must not report the peer's chosen 1xx, "
        "and must say that is what happened: "
        f"{reply['status']} / {reply['outcome']!r}")
    assert records.STATUS_UNREADABLE == reply["status"], (
        "the harness and the extension disagree about the sentinel status")
    # It is still recordable, which is the other half of the amendment: this
    # pair is the ONE that record_exchange cross-checks.
    req_blob, _ = rig.eng.blobs.put(rig.last_request)
    resp_blob, _ = rig.eng.blobs.put(reply[server.BridgeServer.BODY_KEY])
    assert records.record_exchange(
        rig.eng.db, run_id=rig.run_id, method="GET",
        url=f"{rig.target.origin}/hints", status=reply["status"],
        outcome=reply["outcome"], req_blob=req_blob, resp_blob=resp_blob,
        ms=reply["ms"], at_us=engagement.now_us()).startswith("x-")

    # 3. The consequence, and the reason any of this is worth a test. Every
    #    sample below is a 103 on the wire; Distress counts them as the 500s
    #    they really are, and the run is aborted.
    seen = _issue_until(rig, "/hints?n=1&status=500", want="halted")
    assert seen[-1] == "halted", seen
    assert set(seen[:-1]) == {500}, (
        "a sample that was not the origin's 500 reached Distress: "
        f"{sorted(set(seen[:-1]), key=str)}")
    # Ten ANSWERED samples on the host is the earliest the 5xx rule may fire,
    # and the two probes above are two of them, so the count is taken from
    # the target's own log rather than from this loop's length.
    answered = len(rig.target.hits_for("/hints"))
    assert answered >= 10, \
        f"the 5xx rule needs ten answered samples before it may trip; got {answered}"

    assert bf.wait_for(lambda: bool(frames), timeout=10), (
        "early hints in front of a failing origin did not trip the auto-halt "
        "-- which is the exact failure Sender.finalStatus exists to prevent")
    assert "5xx rate" in frames[0]["reason"], frames[0]
    assert frames[0]["host"] == rig.target.host, frames[0]


def test_an_early_hint_with_a_dead_origin_behind_it_still_trips_the_auto_halt(rig):
    """The other half of the same finding, and the half that was never driven.

    The test next door proves the BUDGET ending against a real Burp: nine
    interim heads, one past `Sender.MAX_INTERIM_HEADS`. The whole-branch
    review found a second ending open -- a peer that sends ONE interim head
    and then nothing at all -- and `Sender.scanStatus` reported that 1xx as
    the exchange's final status, on the reasoning that if the bytes ran out
    there was nothing behind them to have hidden anything. Nothing was
    hidden, and the 1xx is still not the final response.

    That ending is not exotic. It is a CDN that has already flushed its
    `103 Early Hints` when the origin behind it dies, which is why the route
    exists: `/hints?n=1&close=1` writes the interim head and closes.

    MEASURED HERE, against Burp Suite Community Edition and the same rig, with
    only `Sender.scanStatus` differing between the two runs:

        before:  {status: 103, outcome: 'ok',                bytes: 76}
        after:   {status: 599, outcome: 'status_unreadable', bytes: 76}

    So this answers the review's open question as well. Burp does NOT report
    an interim-then-close as a response-less exchange: `hasResponse()` is
    true, `statusCode()` is the interim `103`, and `toByteArray()` carries the
    76-byte interim head and nothing else. Every one of those exchanges was a
    healthy sample, the 5xx rate stayed at 0%, and the consecutive-error
    streak stayed at 0 because something did answer.
    """
    rig.configure()

    frames: list[dict] = []
    # Appended, not acted on: this callback runs on the bridge's read-loop
    # thread and the store connection belongs to the thread owning the run.
    rig.srv.on_halted = frames.append

    reply = rig.get("/hints?n=1&close=1")
    assert (reply["status"], reply["outcome"]) == (599, "status_unreadable"), (
        "an interim head with nothing behind it was reported as the "
        f"exchange's final status: {reply['status']} / {reply['outcome']!r}")
    raw = reply[server.BridgeServer.BODY_KEY]
    # The bytes are the evidence that this is the truncated ending and not the
    # budget one: one head, and no second status line anywhere in them.
    assert raw.startswith(b"HTTP/1.1 103 Early Hints"), raw[:64]
    assert raw.count(b"HTTP/") == 1, (
        "this is meant to be the TRUNCATED ending -- one interim head and no "
        f"final one -- and the bytes carry more than one head: {raw[:256]!r}")

    # THE CONSEQUENCE, which is the only reason the number above matters.
    seen = _issue_until(rig, "/hints?n=1&close=1", want="halted")
    assert seen[-1] == "halted", seen
    assert set(seen[:-1]) == {599}, (
        "a sample that was not the conservative sentinel reached Distress: "
        f"{sorted(set(seen[:-1]), key=str)}")
    answered = len(rig.target.hits_for("/hints"))
    assert answered >= 10, \
        f"the 5xx rule needs ten answered samples before it may trip; got {answered}"

    assert bf.wait_for(lambda: bool(frames), timeout=10), (
        "a dead origin behind a live CDN's early hints did not trip the "
        "auto-halt: every exchange it saw looked healthy")
    assert "5xx rate" in frames[0]["reason"], frames[0]
    assert frames[0]["host"] == rig.target.host, frames[0]


# The handshake headers a real WebSocket upgrade carries. The key is RFC 6455
# s1.3's worked example and `target_server.UPGRADE_HEAD` answers with the accept
# that belongs to it, so what goes out is a genuine handshake rather than a 101
# pasted in front of a plain GET -- which matters here, because how Burp treats
# a 101 is the thing being measured.
UPGRADE_REQUEST_HEADERS = (
    ("Connection", "Upgrade"),
    ("Upgrade", "websocket"),
    ("Sec-WebSocket-Version", "13"),
    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
)


def _issue_exactly(rig, target_path: str, *, n: int, attempts: int = 80) -> list:
    """Send `target_path` until `n` of them have been ANSWERED.

    The mirror of `_issue_until`, and it exists because the thing being proved
    here is an ABSENCE: no halt, no refusal, every send answered. `_issue_until`
    stops at the first refusal it was asked for, so it cannot express "none of
    them was refused" -- the loop that proves that has to keep going.

    Rate limits are slept out, exactly as they are there and for the same
    reason. Any OTHER refusal ends the test loudly, naming the class: a
    `halted` here is the failure this test was written to catch, not an
    inconvenience to retry through.
    """
    seen: list = []
    for _ in range(attempts):
        if len(seen) == n:
            return seen
        try:
            reply = rig.send_unguarded("GET", target_path,
                                       headers=UPGRADE_REQUEST_HEADERS)
        except server.BridgeError as exc:
            if exc.error_class == "rate_limited":
                time.sleep(exc.retry_after_us / 1_000_000 + 0.02)
                continue
            raise AssertionError(
                f"send {len(seen) + 1} of {n} was refused {exc.error_class!r}: "
                f"{exc} (answered so far: {seen})"
            ) from exc
        seen.append((reply["status"], reply["outcome"]))
    raise AssertionError(f"{attempts} attempts and only {len(seen)} of {n} "
                         f"answered: {seen}")


@pytest.mark.parametrize("route,shape", [
    ("/upgrade", "a WebSocket frame"),
    ("/upgrade?frame=0", "nothing at all"),
])
def test_a_successful_upgrade_reports_101_and_halts_nothing(rig, route, shape):
    """The MIRROR of the two tests above, against the same real Burp.

    Those two close "a peer can DISARM the auto-halt by putting an interim head
    in front of a dead origin". The fix for them classifies any 1xx head with
    nothing parseable behind it as unreadable -- and for `101 Switching
    Protocols` that is what a CORRECT, SUCCESSFUL response looks like (RFC 9110
    s15.2.2: the empty line after the 101 head ends HTTP on that connection and
    no further status line ever follows). So the fix for "a peer can stop the
    auto-halt firing" created "a healthy peer makes it fire": same rail, same
    severity, opposite direction, and a branch that shipped only the first half
    would file every WebSocket upgrade as false evidence about a client
    production system.

    hx places no restriction on `Upgrade` requests, so this is routine
    web-app work rather than an exotic input.

    MEASURED HERE, against Burp Suite Community Edition and this rig, with only
    `Sender.scanStatus` differing between the two runs -- and this is also the
    answer to what Burp itself does with a 101, which nothing before this
    measured:

        before:  the 1st answered send:  {status: 599,
                                          outcome: 'status_unreadable'}
                 the 11th answered send: refused `halted: target distress:
                                          5xx rate 100.0% over the last 10
                                          requests exceeds 20.0% on 127.0.0.1`
                 one halted frame, and the target had recorded 10 requests
                 when the loop stopped
        after:   {status: 101, outcome: 'ok'} thirteen times, no halted frame,
                 and the target recorded all thirteen

    Twelve is not arbitrary. S4's 5xx rule needs ten answered samples on a host
    before it may trip and trips ON the tenth, so a test that stopped at nine
    would pass with the bug still in place.

    Both shapes of the route are driven. With the WebSocket frame, a scan that
    keeps hunting for a final head reads `0x81` and calls it unreadable; with
    `frame=0` it runs out of bytes instead. They are different endings in
    `scanStatus` and a fix covering one need not cover the other.
    """
    rig.configure()

    frames: list[dict] = []
    # Appended, not acted on: this callback runs on the bridge's read-loop
    # thread. Same reason as the two tests above.
    rig.srv.on_halted = frames.append

    reply = rig.send_unguarded("GET", route, headers=UPGRADE_REQUEST_HEADERS)
    assert (reply["status"], reply["outcome"]) == (101, "ok"), (
        f"a completed protocol switch with {shape} behind the head was filed "
        f"as {reply['status']} / {reply['outcome']!r} -- 101 is FINAL "
        "(RFC 9110 s15.2.2), so there was never a later head to be missing")
    raw = reply[server.BridgeServer.BODY_KEY]
    assert raw.startswith(b"HTTP/1.1 101 Switching Protocols"), raw[:64]
    # The evidence that this really is the "nothing parseable behind it" shape
    # and not a 101 with a second head hiding behind it, which would be a
    # different case answered by a different arm of the scan.
    assert raw.count(b"HTTP/") == 1, raw[:256]

    # THE CONSEQUENCE, which is the only reason the number above matters: the
    # run is still running, and every request reached the target.
    answered = _issue_exactly(rig, route, n=12)
    assert set(answered) == {(101, "ok")}, answered
    assert len(rig.target.hits_for("/upgrade")) == 13, (
        "sends were refused before they reached the target: "
        f"{len(rig.target.hits_for('/upgrade'))} arrived, 13 were issued")
    assert rig.srv.state != "halted", rig.srv.state
    assert frames == [], (
        "thirteen SUCCESSFUL upgrades against a healthy host tripped the "
        f"auto-halt: {frames}")
