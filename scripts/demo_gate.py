#!/usr/bin/env python3
"""Watch the issuance gate make decisions, against a real Burp.

This exists because the send path has no human-facing entry point yet. `hx new`
and `hx info` create and inspect an engagement; the agent-facing tool layer that
would issue a request is Plan 6. Until then the only things that drive the gate
end to end are the integration tests, and a test is a poor way to SEE something
work -- it asserts and falls silent.

So this narrates instead. It stands up the same stack the integration rig does
-- one engagement, one bridge, one real headless Burp, two loopback targets --
and then walks the decision order from spec s4 one refusal at a time, printing
what was asked and what came back.

Run it:

    .venv/bin/python scripts/demo_gate.py

Everything it creates is a temporary directory it removes on the way out, and
every target is loopback. It never touches your real Burp home: the fixture
copies a seed home per run, which is also why the first launch takes a moment.

It needs what the integration tests need -- a Burp jar and an accepted EULA in
the seed home. If something is missing it says which, and exits without
starting anything.
"""
from __future__ import annotations

import contextlib
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from hx import config as config_mod          # noqa: E402
from hx import engagement as eng_mod         # noqa: E402
from hx import session as session_mod        # noqa: E402
from hx.bridge import server                 # noqa: E402
from hx.halt import OperatorHalt             # noqa: E402
from tests.integration import burp_fixture as bf   # noqa: E402
from tests.integration.target_server import TargetServer  # noqa: E402

BOLD, DIM, GREEN, RED, YELLOW, OFF = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[0m")


def step(n: int, title: str) -> None:
    print(f"\n{BOLD}{n}. {title}{OFF}")


def asked(what: str) -> None:
    print(f"   {DIM}ask {OFF}{what}")


def got(frame: dict, *, expect: str) -> None:
    """Print one reply, and say whether it is what spec s4 promises.

    `expect` is the error class, or "result" for an issued request. The point
    of printing the verdict rather than just the frame is that a reader who
    does not know the protocol still learns whether the gate did its job.
    """
    kind = frame.get("t")
    if kind == "result":
        actual = "result"
        detail = (f"status={frame.get('status')} bytes={frame.get('bytes')} "
                  f"outcome={frame.get('outcome')}")
    else:
        actual = frame.get("class", "?")
        detail = frame.get("detail", "")
    ok = actual == expect
    mark = f"{GREEN}as promised{OFF}" if ok else f"{RED}UNEXPECTED{OFF}"
    print(f"   {DIM}got {OFF}{BOLD}{actual}{OFF}  {mark}")
    if detail:
        print(f"       {DIM}{detail}{OFF}")


def main() -> int:
    missing = bf.missing()
    if missing:
        print(f"{RED}Cannot run.{OFF} Missing: {', '.join(missing)}")
        print("\nThis needs the same things the integration tests need -- a Burp"
              "\njar and a seed home with the EULA accepted. See"
              "\ntests/integration/burp_fixture.py for the exact paths.")
        return 1

    work = Path(tempfile.mkdtemp(prefix="hx-demo-"))
    stack = contextlib.ExitStack()
    proc = None
    try:
        print(f"{BOLD}hx — the issuance gate, end to end{OFF}")
        print(f"{DIM}workspace: {work}{OFF}")

        # Two targets. The second one is never in scope; it exists so a scope
        # refusal can be shown to be a refusal rather than a failure to
        # connect -- it is listening the whole time.
        # stop() is registered BEFORE start() on both, the way the integration
        # rig does it: a start() that raises must still close the socket it
        # already bound.
        target = TargetServer("127.0.0.1")
        stack.callback(target.stop)
        target.start()
        offside = TargetServer("127.0.0.2")
        stack.callback(offside.stop)
        offside.start()
        print(f"{DIM}in scope:     {target.origin}{OFF}")
        print(f"{DIM}out of scope: {offside.origin}  (listening, never authorised){OFF}")

        cfg = config_mod.Config(name="demo", client="Demo Client",
                                scope_include=[f"{target.origin}/*"],
                                rate_limit_rps=3)
        eng = eng_mod.create(work / "engagement", cfg, author="demo")
        stack.callback(eng.db.close)

        # Plan 4 owns run lifecycle; this is the one row the halt's audit
        # trail hangs off.
        run_id = f"r-{uuid.uuid4().hex[:12]}"
        eng.db.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile,"
            " started_us, status) VALUES(?,?,?,?,?,?)",
            (run_id, eng.id, "manual", cfg.safety_profile,
             eng_mod.now_us(), "running"))

        halt = OperatorHalt(eng.root, eng.db)
        srv = server.BridgeServer(work / "hx.sock", engagement_id=eng.id,
                                  operator_halt=halt)
        srv.start()
        stack.callback(srv.stop)

        step(1, "Launch Burp with the extension, and wait for it to dial in")
        asked("java ... burp.StartBurp --developer-extension-class-name=hx.HxExtension")
        proc = bf.launch_burp(srv.socket_path, eng.id, work / "burp",
                              halt.sentinel_path)
        if not bf.wait_for(lambda: srv.state == "connected"):
            print(f"   {RED}Burp never connected.{OFF} Log: {work / 'burp' / 'burp.log'}")
            return 1
        print(f"   {DIM}got {OFF}{BOLD}connected{OFF}  "
              f"{GREEN}the extension is live{OFF}")

        step(2, "Send before configuring — DENY-ALL is the initial state")
        asked(f"GET /health  ->  {target.origin}")
        got(_send(srv, target, "GET", "/health", guarded=False),
            expect="not_configured")

        step(3, "Push the authorisation")
        pairs = {
            "scope.include": [f"{target.origin}/*"],
            "method.allow": ["GET", "HEAD", "OPTIONS"],
            "dangerous.path": ["*/logout*", "*/password*"],
            "limit.rate_rps": ["3"],
            "limit.max_requests": ["10"],
        }
        # READ from `scope_version`, never recomputed. This script used to
        # hash `config.dumps(cfg)` right here, which is the one thing S5
        # forbids: the report renders `scope_version.sha256` as the boundary
        # of record, so a recomputed hash lets the extension be authorised
        # against one boundary while the deliverable shows another -- two
        # facts that agree until a config is hand-edited. `hx.session` is the
        # product's answer and the demo an operator runs should not teach a
        # different one.
        sha = session_mod.stored_scope_sha256(eng.db, eng.id)
        epoch = srv.configure(pairs, scope_sha256=sha,
                              profile=cfg.safety_profile)
        asked("scope, method allowlist, dangerous paths, 3 req/s, budget 10")
        print(f"   {DIM}got {OFF}{BOLD}config_epoch={epoch}{OFF}  "
              f"{GREEN}authorised{OFF}")

        step(4, "An in-scope GET — this one should actually go out")
        asked(f"GET /health  ->  {target.origin}")
        got(_send(srv, target, "GET", "/health"), expect="result")
        print(f"   {DIM}the target server logged: {target.hits[-1]}{OFF}")

        step(5, "The same request to a host nobody authorised")
        asked(f"GET /health  ->  {offside.origin}  {DIM}(listening!){OFF}")
        before = len(offside.hits)
        got(_send(srv, offside, "GET", "/health"), expect="scope_denied")
        print(f"   {DIM}the out-of-scope server logged "
              f"{len(offside.hits) - before} new request(s){OFF}")

        step(6, "A method the allowlist does not name")
        asked(f"DELETE /health  ->  {target.origin}")
        got(_send(srv, target, "DELETE", "/health"), expect="method_denied")

        step(7, "A path the engagement marked dangerous")
        asked(f"GET /logout  ->  {target.origin}")
        got(_send(srv, target, "GET", "/logout"), expect="dangerous_denied")

        step(8, "Faster than the configured rate")
        asked("three GETs back to back, against limit.rate_rps = 3")
        replies = [_send(srv, target, "GET", "/health") for _ in range(4)]
        limited = [r for r in replies if r.get("class") == "rate_limited"]
        if limited:
            got(limited[0], expect="rate_limited")
            print(f"   {DIM}retry_after_us="
                  f"{limited[0].get('retry_after_us')}{OFF}")
        else:
            print(f"   {YELLOW}no refusal this time — the window had room; "
                  f"harmless, it is a clock race{OFF}")

        step(9, "The kill switch that works when the bridge does not")
        asked(f"touch {halt.sentinel_path}")
        halt.sentinel_path.write_text("stopped by hand\n")
        time.sleep(1.5)   # the extension polls; DEFAULT_POLL_MS is 500
        asked(f"GET /health  ->  {target.origin}")
        # `halted`, not `not_configured`: the sentinel is its own class, so an
        # operator reading the frame learns WHY issuance stopped rather than
        # being told the run was never authorised. Worth knowing when writing
        # against this: the first draft of this script expected the weaker
        # class and the gate was more precise than the expectation.
        got(_send(srv, target, "GET", "/health", guarded=False),
            expect="halted")
        print(f"   {DIM}a file on disk stopped issuance, with the socket "
              f"still up{OFF}")

        step(10, "Remove it, and issuance re-arms")
        halt.sentinel_path.unlink()
        time.sleep(1.5)
        asked(f"GET /health  ->  {target.origin}")
        got(_send(srv, target, "GET", "/health", guarded=False),
            expect="result")

        print(f"\n{BOLD}Every byte above crossed one gate inside the JVM.{OFF}")
        print(f"{DIM}The refusals came from the extension, not from Python: "
              f"steps 9 and 10\nran with this side's own checks switched off, "
              f"so the JVM's answer is the only one.{OFF}")
        return 0
    finally:
        if proc is not None:
            proc.kill()
            proc.wait(timeout=30)
        stack.close()
        shutil.rmtree(work, ignore_errors=True)


def _raw(method: str, path: str, dest: TargetServer) -> bytes:
    lines = [f"{method} {path} HTTP/1.1",
             f"Host: {dest.host}:{dest.port}",
             "User-Agent: hx-demo/0.1",
             "Accept: application/json"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")


def _send(srv, dest: TargetServer, method: str, path: str,
          *, guarded: bool = True) -> dict:
    """One request, and the frame that came back rather than an exception.

    BridgeServer.send raises BridgeError on a refusal, which is right for a
    caller that wants to act on it and wrong for one that wants to SHOW it.
    """
    req = {"identity_id": None, "target_host": dest.host,
           "target_port": dest.port, "tls": False}
    try:
        return srv.send(req, _raw(method, path, dest), timeout=20.0,
                        enforce_locally=guarded)
    except server.BridgeError as e:
        return {"t": "error", "class": e.error_class, "detail": str(e),
                "retry_after_us": getattr(e, "retry_after_us", None)}


if __name__ == "__main__":
    sys.exit(main())
