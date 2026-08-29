"""The rig: one engagement, one bridge, one real Burp, two loopback targets.

Everything is registered on an ExitStack as it is created, so a failure
part-way through construction unwinds whatever already exists, and a failing
TEST unwinds all of it. That is not defensiveness for its own sake: on this
branch a kill that lived at the end of a try block was jumped over by an
assertion twice, leaving a 900 MB JVM per debugging attempt.

The rig deliberately does NOT push a configure frame. DENY-ALL is the initial
state and a test that wants to prove it needs a live, unconfigured extension
to prove it against; every other test calls rig.configure() on its first line.

Everything expensive happens inside the fixture, never at import. A conftest
is imported during COLLECTION, including on a fast `pytest` run that then
deselects every test in this directory, so an exception at module level here
is not a skipped suite -- it is a collection error for the whole repository.
That has already happened twice on this branch from burp_fixture.missing().
"""
from __future__ import annotations

import contextlib
import socket
import subprocess
import time
import uuid
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import pytest

from hx import config, engagement, session
from hx.bridge import server
from hx.halt import OperatorHalt
from tests.integration import burp_fixture as bf
from tests.integration.target_server import TargetServer


def pytest_terminal_summary(terminalreporter) -> None:
    """Say out loud that the only real-Burp tests in this repo did not run.

    They stay deselected, and that is a decision rather than an oversight:
    they cost 53 s and a 900 MB JVM, so putting them in the default run makes
    every fast iteration five times slower.

    What is NOT acceptable is the way that decision reads. These two files
    were dark for a full day -- Task 6 made `-Dhx.halt_sentinel` mandatory
    without updating the launch fixture, both real-Burp tests timed out after
    90 s each, and every suite run in between reported green. The failure was
    never that they did not run; it was that `9 deselected` reads as somebody
    having scoped a run deliberately, and gives a reader no reason to suspect
    that the only tests in this repository which touch a real Burp, a real
    socket and a real target server are among them.

    So the default run says which ones, and how to run them. Cost if this is
    ever wrong: one line of output.

    This hook fires because a conftest is imported during COLLECTION even on a
    run that then deselects everything in its directory -- the same property
    the module docstring above warns about, used deliberately for once.
    """
    # Selected by MARKER, not by a substring of the node id. The drift check
    # is parametrised with plan-block markers, five of which are paths under
    # tests/integration/, so a node-id match counted seven of those as
    # real-Burp tests and announced them on a run that had just executed all
    # ten. A line that miscounts what is not running is the same defect this
    # line exists to fix, one level up.
    deselected = [
        item for item in terminalreporter.stats.get("deselected", [])
        if getattr(item, "get_closest_marker", None)
        and item.get_closest_marker("integration") is not None
    ]
    _announce_skipped(terminalreporter)
    if not deselected:
        return
    terminalreporter.write_line(
        f"NOT RUN: {len(deselected)} integration tests -- the only tests here "
        "that drive a real Burp. Run them with: pytest -m integration",
        yellow=True)


def _announce_skipped(terminalreporter) -> None:
    """Announce integration tests that RAN and SKIPPED, not only deselected ones.

    The hook above exists because `9 deselected` reads as somebody having
    scoped a run deliberately. `3 skipped` reads the same way and is worse: a
    deselected test was never asked to run, while a skipped one was asked,
    declined, and reported green.

    Both halves of that have now bitten this project. The real-Burp tests were
    dark for a day behind a deselect. Task 1's measurements were one renamed
    directory away from being dark behind a skip, and the extension jar going
    stale skipped all 17 integration tests while the commit that did it
    recorded them as passing.
    """
    # `stats["skipped"]` holds TestReport, NOT Item -- and a TestReport has no
    # get_closest_marker. The first version of this filter was copied from the
    # deselected path above, where the objects ARE Items, and the
    # `getattr(..., None)` guard turned the resulting AttributeError into
    # permanent silence: 17 skipped integration tests printed not one line.
    # Measured with HX_BURP_LAB=/nonexistent.
    #
    # That is worse than the hole it was written to close. A warning that is
    # never present is not a warning, which is the same reasoning the
    # deselected line's own docstring gives for not printing unconditionally.
    # `keywords` is what a TestReport carries, and it holds the marker names.
    skipped = [
        report for report in terminalreporter.stats.get("skipped", [])
        if "integration" in getattr(report, "keywords", ())
    ]
    if skipped:
        terminalreporter.write_line(
            f"SKIPPED: {len(skipped)} integration tests declined to run. A "
            "skipped test reported green; read the reason above before "
            "trusting this suite.", yellow=True)


def build_config_body(cfg: config.Config, *, max_requests: int,
                      rate_rps: int | None = None) -> dict[str, list[str]]:
    """`hx.session.config_body`, plus the two things only a TEST wants.

    The body itself is the product's now. It had been spelled here as well --
    a shorter body, with a two-entry `dangerous.path` where the engagement
    config carries nine and no `scope.exclude`, `render.allow` or
    `limit.concurrency` at all -- and this file's own comment already named
    that hazard: "a config body spelled anywhere else is a second spelling
    free to drift from this one". It had drifted. A test asserting a refusal
    against a body the product would never send proves nothing about the
    product.

    `limit.max_requests` is the first addition, and it is an addition rather
    than a defect in `config_body`: `Limits.arm()` falls back to a documented
    2000 per run and S4 says the budget binds the send path and the crawler,
    neither of which the product starts yet, so a number there would have no
    referent. The rig DOES exhaust a budget on purpose
    (`test_the_run_budget_is_exhausted_and_stays_exhausted`), which needs a
    number small enough to reach. It is a parameter rather than a constant
    because every OTHER test wants it far above anything it issues, so the
    per-run budget never trips first and quietly turns whatever is under test
    into a budget test. `Limits.arm` only ever arms once per run (its own
    docstring: "ARMED ONCE"), so a caller wanting a number other than the
    default must pass it on the FIRST configure of the test -- a later
    configure with a different value is silently ignored, by design, so that a
    scope push mid-run can never hand a run more requests than it started with.

    `rate_rps` is the second, and it overrides the rate for ONE configure for
    exactly one caller: the test that pushes a SECOND configure naming a
    different `limit.rate_rps` mid-run and expects `bad_config`. Default None
    means "the engagement's rate", which is what `config_body` reads from the
    config and what every other caller wants.

    The distress thresholds are deliberately in neither: Plan 2's config-key
    vocabulary (`codec.CONFIG_KEYS`) has no key for them and
    `codec.build_config_body` refuses an unrecognised key outright, so the
    auto-halt test is written against the S4 production defaults the extension
    carries -- a 5xx rate above 20%, over a window that needs ten answered
    samples on a host before it may trip.
    """
    body = session.config_body(cfg)
    body["limit.max_requests"] = [str(max_requests)]
    if rate_rps is not None:
        body["limit.rate_rps"] = [str(rate_rps)]
    return body


def _reap(proc: subprocess.Popen) -> None:
    proc.kill()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        # Warn rather than raise: this runs during unwind, and an exception
        # here would REPLACE the assertion that actually failed the test.
        warnings.warn(f"Burp pid {proc.pid} survived kill(); it may still be running")


def browse_through(port: int, method: str, url: str, *, host: str,
                   headers: Sequence[tuple[str, str]] = (), body: bytes = b"",
                   timeout: float = 30.0) -> bytes:
    """One request through a Burp proxy listener, and the whole response off
    the wire.

    THE FORWARD-PROXY form: the request line carries the ABSOLUTE URI, which
    is how a browser configured to use a proxy addresses one and how the
    destination reaches Burp at all. The `Host` line is set to match only so
    the target server sees a well-formed request.

    Raw sockets rather than `http.client` for the same reason
    `test_proxy_facts._Probe.raw_through_proxy` uses them: the byte count of
    the FULL response is half of what a drop is recognised by, and no
    http.client API exposes it. Reading to EOF is bounded twice over -- the
    socket timeout, and Burp closing the connection itself.

    A FUNCTION, NOT A METHOD, since Task 9: `Rig.browse` is the rig's caller
    and `tests/integration/test_cli_session.py` is a caller with NO RIG AT
    ALL -- it browses through a listener the product's own `session()` (or
    `hx capture start` in another process) opened, which is the whole point
    of that file. A second copy of these fifteen lines is a second place to
    get the absolute-URI form or the read-to-EOF wrong, and the wrong one
    looks like a drop.
    """
    lines = [f"{method} {url} HTTP/1.1",
             f"Host: {host}",
             "Connection: close"]
    lines += [f"{name}: {value}" for name, value in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    # ISO-8859-1 for the same reason Sender.parse reads it that way: HTTP
    # field values are octets, and one octet is one char here.
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + body
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(raw)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


@dataclass
class Rig:
    eng: engagement.Engagement
    srv: server.BridgeServer
    proc: subprocess.Popen
    target: TargetServer
    offside: TargetServer
    halt: OperatorHalt
    run_id: str
    workdir: Path
    # The two proxy listeners this run's Burp bound, read back from the config
    # file it was handed rather than kept as a second copy here. S4 tells the
    # operator and the crawler apart by WHICH of these a request arrived on and
    # by nothing in the traffic, so a test of that split needs both numbers.
    # `crawler_port` is also what `-Dhx.crawler_port` carries into the JVM; see
    # burp_fixture.launch_burp for why passing it is not optional.
    proxy_port: int
    crawler_port: int
    last_request: bytes = field(default=b"", init=False)

    @property
    def sentinel(self) -> Path:
        return self.halt.sentinel_path

    def configure(self, *, max_requests: int = 2000,
                  rate_rps: int | None = None) -> int:
        """The configure the PRODUCT sends, with the rig's two additions.

        Everything about the body is `build_config_body`'s; see it for why
        `max_requests` and `rate_rps` are the only two things this side adds.
        `limit.rate_rps` reaching the extension from the engagement config is
        what makes the number in the config, the number on the wire and the
        number a test computes its bounds from one number: the rig sets 3
        rather than hx.config's default of 5 at the Config() call, because 5
        is also what the extension falls back to when the key is absent, so a
        configured 5 and an ignored configure body would be the same
        observation.

        THE SCOPE HASH IS READ, NOT RECOMPUTED, through the product's
        `stored_scope_sha256`. This rig used to hash `config.dumps(cfg)` here.
        The two agree today -- `engagement.create` writes that same hash into
        `scope_version` -- and agreeing today is exactly the property Task 5
        says not to rely on: `scope_version` is append-only so that a contract
        dispute has one answer, and a rig that recomputes cannot notice a
        session authorising the extension against one boundary while the
        report renders another.
        """
        return self.srv.configure(
            build_config_body(self.eng.config, max_requests=max_requests,
                              rate_rps=rate_rps),
            scope_sha256=session.stored_scope_sha256(self.eng.db, self.eng.id),
            profile=self.eng.config.safety_profile)

    def send(self, method: str, target_path: str, *,
             to: TargetServer | None = None,
             headers: Sequence[tuple[str, str]] = (),
             body: bytes = b"", timeout: float = 15.0,
             guarded: bool = True) -> dict:
        """Issue one request through the whole stack.

        The DESTINATION travels in the frame header, not in the Host line:
        Burp connects to the service the header names, so that is what the
        scope decision has to be about. The Host line is set to match only so
        the target server sees a well-formed request.

        `guarded=False` skips this side's own refusals; see send_unguarded,
        which is its only caller and carries the reason.
        """
        dest = to or self.target
        lines = [f"{method} {target_path} HTTP/1.1",
                 f"Host: {dest.host}:{dest.port}",
                 "User-Agent: hx-integration/0.1",
                 "Accept: application/json"]
        lines += [f"{name}: {value}" for name, value in headers]
        if body:
            lines.append(f"Content-Length: {len(body)}")
        # ISO-8859-1 for the same reason Sender.parse reads it that way: HTTP
        # field values are octets, and one octet is one char here.
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + body
        self.last_request = raw
        req = {"identity_id": None, "target_host": dest.host,
               "target_port": dest.port, "tls": False}
        return self.srv.send(req, raw, timeout=timeout,
                             enforce_locally=guarded)

    def get(self, target_path: str, **kwargs) -> dict:
        return self.send("GET", target_path, **kwargs)

    def send_unguarded(self, method: str, target_path: str, **kwargs) -> dict:
        """Send with THIS side's refusals off, so the extension's are the only
        ones left.

        BridgeServer.send refuses locally whenever the durable halt is armed or
        its own state says halted. That is right in production -- two gates are
        better than one -- and fatal to a test of the kill switch: the frame
        never reaches the JVM, the assertion is satisfied by the harness's own
        bookkeeping, and it goes on passing with the extension wide open. This
        is that shape of vacuous guard, and it is the shape this project has
        already been bitten by seven times.

        So this goes through `BridgeServer.send(..., enforce_locally=False)`,
        which drops those three refusals and NOTHING else -- same frame, same
        deadline, same translation of the peer's `error` frame into a
        BridgeError. A refusal that comes back through it came back from the
        JVM. Every caller pairs it with an assertion on `target.hits`, because
        the target server's own log is the one witness no state on this side
        can fake.

        This rig USED to reach past `send()` into `srv._request` and translate
        the reply itself. That copy is gone: it was a second spelling of the
        five lines at the bottom of `send()`, free to drift from them, and
        every test reached through this method would have gone on asserting
        the old shape after any change to either.
        """
        return self.send(method, target_path, guarded=False, **kwargs)

    # Long enough for a frame that crosses a Unix socket in under a
    # millisecond once the response is complete (measured in
    # tests/integration/test_proxy_capture.py, where this constant and the
    # two methods below it lived until Task 9: the row was on disk 50 ms
    # after the client's response on every run taken there), short enough
    # that a wedged extension is a failure in seconds rather than a stalled
    # suite.
    SETTLE_S = 10.0

    def browse(self, method: str, path: str, *, port: int | None = None,
               to: "TargetServer | None" = None,
               headers: Sequence[tuple[str, str]] = (), body: bytes = b"",
               timeout: float = 30.0) -> bytes:
        """One request through Burp's PROXY LISTENER, and the whole response
        off the wire.

        THE OTHER ROUTE. `send` goes through the bridge -- Burp's send call,
        driven by an operator tool. This goes through the listener a real
        browser would be pointed at, which is the one path `ProxyGate`
        guards and the one a browsing session actually produces traffic on.
        Nothing that only calls `send` has ever driven this side of the
        extension.

        `port` defaults to the OPERATOR listener. The crawler's is
        `self.crawler_port` and the difference between them is the whole of
        S4's source attribution.

        The request itself is `browse_through`'s, because a test that has no
        rig needs the identical one -- see it for why the URI is absolute and
        why this is a raw socket.
        """
        dest = to or self.target
        return browse_through(port or self.proxy_port, method,
                              f"{dest.origin}{path}",
                              host=f"{dest.host}:{dest.port}",
                              headers=headers, body=body, timeout=timeout)

    def settle(self, predicate, what: str, timeout: float = SETTLE_S) -> None:
        """Wait for a row to arrive, and say WHY it did not if it never does.

        THE RECORD ARRIVES AFTER THE RESPONSE, so every row this waits for is
        POLLED rather than read once. Measured (test_proxy_capture.py):
        browsing five times and reading the table the instant each client
        response completed gave 1, 1, 2, 3, 4 rows -- the capture frame
        crosses the bridge on its own thread, behind the browser.

        THE MESSAGE IS THE POINT, carried over unchanged from where this
        lived before Task 9 moved it here. A sink that raises produces
        exactly the same observable as an extension that sent nothing -- an
        empty table -- and the two have opposite fixes. `exchange_errors`
        and `exchange_callback_error` are the only things on this side that
        can tell them apart, so they are in every timeout message rather
        than left for whoever is debugging to find.
        """
        end = time.time() + timeout
        while time.time() < end:
            if predicate():
                return
            time.sleep(0.1)
        pytest.fail(
            f"{what} never arrived within {timeout}s. This side's sink failed "
            f"{self.srv.exchange_errors} time(s), last: "
            f"{self.srv.exchange_callback_error!r}. A sink that throws is caught, "
            "counted and swallowed by BridgeServer._capture -- deliberately -- so "
            "an empty table is what a BROKEN HARNESS looks like as well as a "
            "silent extension. Read that number before reading Burp's log at "
            f"{self.workdir / 'burp' / 'burp.log'}. Target log: "
            f"{[(h.method, h.path) for h in self.target.hits]}")


# THERE IS NO SEED-HOME FIXTURE HERE, and its absence is deliberate. One round
# of this task set `$HX_BURP_SEED_HOME` from an AUTOUSE FIXTURE so that
# `hx.session.make_home` would copy the lab's home rather than the operator's.
# It worked for everything pytest runs and for nothing else: `bf.launch_burp`
# is also called by `scripts/demo_gate.py`, which guards on `bf.missing()` --
# a check against the LAB's home -- and then copied `~/.BurpSuite/sessions`,
# real client project state on a consultant's machine. (`demo_capture.py` was
# the second such caller until Task 9 moved it onto `hx.session.session()`,
# where it names the same seed in code.) `make_home(workdir, *, seed=None)`
# moved the answer into the call, so every launcher here says `seed=SEED_HOME`
# in code, for every caller rather than for the ones pytest owns.
#
# THE ENVIRONMENT VARIABLE IS NOT DEAD, AND ONE TEST DEPENDS ON IT. This
# paragraph used to end "nothing in this directory reaches `seed_home()` any
# more", and that sentence is now an invitation to a fixed defect.
# `tests/integration/test_cli_session.py` spawns the PRODUCT's own `hx capture
# start`, which has no seed option and must not grow one for a test, so it
# puts `HX_BURP_SEED_HOME=SEED_HOME` in that subprocess's environment. That
# line used to be the only thing between a real Burp and the operator's real
# `$HOME`, and deleting it did NOT go red -- a consultant's home has an
# accepted EULA and a live `~/.BurpSuite/sessions`, so the run succeeded,
# copied real client project state into a temporary directory, and reported
# green. It is a guard now rather than a warning: the same env dict also sets
# `HOME` to a directory that does not exist, so a seed variable that goes
# missing fails loudly, in that test, naming the fake home. What is true here
# is the narrow claim: no fixture in this directory sets that variable, and no
# launcher in this file needs it, because they say the seed in code.


@pytest.fixture
def rig(tmp_path):
    # Order matters: an unbuilt jar is a FAILURE and a missing Burp is a skip,
    # and asking the skip question first turns the former into the latter.
    if bf.unbuilt():
        pytest.fail("unbuilt: " + ", ".join(bf.unbuilt()))
    if bf.missing():
        pytest.skip("missing: " + ", ".join(bf.missing()))

    with contextlib.ExitStack() as stack:
        # stop() is registered BEFORE start() on both servers: a start() that
        # raises must still close the socket it already bound.
        target = TargetServer("127.0.0.1")
        stack.callback(target.stop)
        target.start()
        offside = TargetServer("127.0.0.2")
        stack.callback(offside.stop)
        offside.start()

        # rate_limit_rps is 3, and deliberately NOT hx.config's default of 5.
        # 5 is also HxExtension.DEFAULT_RATE_RPS -- the number Limits falls
        # back to when the configure body omits the key -- so a configured 5
        # and an ignored configure body are the same observation, and the
        # rate-limit test would agree with an extension that never read the
        # frame. 3 makes those two answers different.
        cfg = config.Config(name="integration", client="loopback",
                            scope_include=[f"{target.origin}/*"],
                            rate_limit_rps=3)
        eng = engagement.create(tmp_path / "engagement", cfg, author="integration")
        stack.callback(eng.db.close)

        # Plan 4 owns run lifecycle; this is the one row the exchange,
        # denial and abort assertions need to hang off.
        run_id = f"r-{uuid.uuid4().hex[:12]}"
        eng.db.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile,"
            " started_us, status) VALUES(?,?,?,?,?,?)",
            (run_id, eng.id, "manual", cfg.safety_profile,
             engagement.now_us(), "running"))

        operator_halt = OperatorHalt(eng.root, eng.db)
        # REQUIRED, not merely wired: BridgeServer refuses to be constructed
        # without one, the same call HxExtension makes about
        # -Dhx.halt_sentinel and for the same field. There is no such thing
        # as a rig that leaves it None any more, so the two behaviours Task 7
        # hangs off it -- the halt re-asserted after every hello, and the
        # sentinel consulted on every send -- are not optional extras this
        # fixture opted into. What IS this fixture's choice is WHICH sentinel:
        # the engagement's own, so the extension polls the same path this side
        # writes. The price is that this side now refuses a send of its own
        # accord while that file exists, which is why the halt test sends
        # through Rig.send_unguarded.
        #
        # `on_exchange` is Plan 4's proxy traffic arriving UNSOLICITED, and
        # without a sink installed BridgeServer reads those frames and DISCARDS
        # them -- its own `_capture` says so. This rig had no sink at all until
        # Task 9, which is right for the send-path tests (they assert on
        # `result` frames) and fatal to any assertion about a row: every
        # exchange, denial and dropped frame would be read off the socket,
        # thrown away, and the database would answer empty while Burp
        # cheerfully sent them.
        # ONE sink object for both callbacks, so both run on ONE connection
        # opened on the read thread. Two objects would open two, and the
        # second would be as thread-affine as the first with nothing making
        # that obvious. `ExchangeSink` IS this rig's sink, promoted: Task 6
        # gave it `on_halted` for exactly this wiring, and the lesson it
        # carries -- that a foreign connection's ProgrammingError is caught,
        # counted and swallowed, so getting it wrong looks like a green
        # handshake and an empty table -- was measured here first.
        sink = session.ExchangeSink(eng.root, eng.id, cfg)
        srv = server.BridgeServer(tmp_path / "hx.sock", engagement_id=eng.id,
                                  operator_halt=operator_halt,
                                  on_exchange=sink,
                                  on_halted=sink.on_halted)
        stack.callback(srv.stop)
        srv.start()

        burpdir = tmp_path / "burp"
        proc = bf.launch_burp(srv.socket_path, eng.id, burpdir,
                              sentinel=operator_halt.sentinel_path)
        stack.callback(_reap, proc)

        if not bf.wait_for(lambda: srv.state == "connected"):
            raise AssertionError(
                "Burp never completed the hello handshake; see "
                f"{burpdir / 'burp.log'}")

        # BEFORE any test touches a listener. `listen_mode: loopback_only` goes
        # into both listeners in `write_listener_config` and is not self-
        # enforcing: changing that one string to `all_interfaces` left
        # test_proxy_facts.py reporting `3 passed` with `ss` showing the
        # listeners bound to `*` -- an open forward proxy on whatever network
        # this laptop is attached to, for as long as the run lasts.
        #
        # Polled, not read once: the handshake says the extension loaded and
        # says nothing about when Burp bound its listeners. The wait is bounded
        # at 15 s and costs one `ss` call on the happy path -- waiting cannot
        # turn a wildcard bind into a loopback one, so the seconds only ever
        # get spent once the check has already found something.
        ports = bf.listener_ports(burpdir)
        violation: str | None = "the loopback check did not run"

        def on_loopback_only() -> bool:
            nonlocal violation
            violation = bf.not_loopback_only(proc.pid, ports)
            return violation is None

        if not bf.wait_for(on_loopback_only, 15):
            raise AssertionError(violation)

        yield Rig(eng=eng, srv=srv, proc=proc, target=target, offside=offside,
                  halt=operator_halt, run_id=run_id, workdir=tmp_path,
                  proxy_port=ports[0], crawler_port=ports[1])
