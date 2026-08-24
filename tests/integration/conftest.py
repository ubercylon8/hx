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
import hashlib
import subprocess
import uuid
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import pytest

from hx import config, engagement
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
    skipped = [
        item for item in terminalreporter.stats.get("skipped", [])
        if getattr(item, "get_closest_marker", None)
        and item.get_closest_marker("integration") is not None
    ]
    if skipped:
        terminalreporter.write_line(
            f"SKIPPED: {len(skipped)} integration tests declined to run. A "
            "skipped test reported green; read the reason above before "
            "trusting this suite.", yellow=True)


def _reap(proc: subprocess.Popen) -> None:
    proc.kill()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        # Warn rather than raise: this runs during unwind, and an exception
        # here would REPLACE the assertion that actually failed the test.
        warnings.warn(f"Burp pid {proc.pid} survived kill(); it may still be running")


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
    last_request: bytes = field(default=b"", init=False)

    @property
    def sentinel(self) -> Path:
        return self.halt.sentinel_path

    def configure(self, *, max_requests: int = 2000,
                  rate_rps: int | None = None) -> int:
        """Push the scope, the method allowlist and the limits this rig tests.

        `limit.rate_rps` is taken from the engagement config rather than
        written out here. S4 puts the limits inside the extension and the
        configure body is how they get there, so the number in the config, the
        number on the wire and the number a test computes its bounds from are
        one number. Two of them written separately is how a test ends up
        asserting against a rate nothing honours. The value the fixture picks
        is 3 rather than the config default of 5, and the reason is at the
        Config() call: 5 is what the extension falls back to on its own.

        `limit.max_requests` has no engagement-config field yet, so this is the
        rig's own choice, and it is a parameter rather than a second constant
        for exactly one reason: every test but the budget test wants it far
        above anything that test issues, so the per-run budget never trips
        first and quietly turns whatever it is testing into a budget test.
        `Limits.arm` only ever arms once per run (its own docstring: "ARMED
        ONCE"), so a caller wanting a number other than the default must pass
        it on the FIRST configure of the test -- a later configure with a
        different value is silently ignored, by design, so that a scope push
        mid-run can never hand a run more requests than it started with.

        `rate_rps` overrides the rate for ONE configure and exists for exactly
        one caller: the test that pushes a SECOND configure naming a different
        `limit.rate_rps` mid-run and expects `bad_config`. That body has to be
        built here rather than in the test -- a config body spelled anywhere
        else is a second spelling free to drift from this one, and a test
        asserting a refusal against a body the rig would never send proves
        nothing about the rig. Default None means "the engagement's rate",
        which is what every other caller wants and what the first configure of
        that test uses.

        The distress thresholds are deliberately NOT here. Plan 2's config-key
        vocabulary (`codec.CONFIG_KEYS`) has no key for them and
        `build_config_body` refuses an unrecognised key outright, so the
        auto-halt test is written against the S4 production defaults the
        extension carries: a 5xx rate above 20%, over a window that needs ten
        answered samples on a host before it may trip.
        """
        pairs = {
            "scope.include": [f"{self.target.origin}/*"],
            "method.allow": ["GET", "HEAD", "OPTIONS"],
            "dangerous.path": ["*/logout*", "*/password*"],
            "limit.rate_rps": [str(self.eng.config.rate_limit_rps
                                   if rate_rps is None else rate_rps)],
            "limit.max_requests": [str(max_requests)],
        }
        scope_sha256 = hashlib.sha256(
            config.dumps(self.eng.config).encode("utf-8")).hexdigest()
        return self.srv.configure(pairs, scope_sha256=scope_sha256,
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
        srv = server.BridgeServer(tmp_path / "hx.sock", engagement_id=eng.id,
                                  operator_halt=operator_halt)
        stack.callback(srv.stop)
        srv.start()

        proc = bf.launch_burp(srv.socket_path, eng.id, tmp_path / "burp",
                              sentinel=operator_halt.sentinel_path)
        stack.callback(_reap, proc)

        if not bf.wait_for(lambda: srv.state == "connected"):
            raise AssertionError(
                "Burp never completed the hello handshake; see "
                f"{tmp_path / 'burp' / 'burp.log'}")

        yield Rig(eng=eng, srv=srv, proc=proc, target=target, offside=offside,
                  halt=operator_halt, run_id=run_id, workdir=tmp_path)
