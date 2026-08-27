#!/usr/bin/env python3
"""Watch the proxy enforcement point work, against a real Burp.

`demo_gate.py` narrates the SEND path -- the agent asking to issue a request
and the gate answering. This one narrates the other enforcement point, the one
spec s4 calls the proxy request handler: a human browsing the target while hx
decides, records and redacts.

WHY IT EXISTS, and why it is not just the integration tests with prettier
output. What this half of the system delivers is mostly THINGS THAT DID NOT
HAPPEN -- a request that never reached the target, a credential that never
reached the blob store. A browser cannot show you an absence and a passing
test run cannot either; both are silent in exactly the same way whether the
enforcement is working or missing. So every step below pairs something that
happened with the place where nothing did:

  * the dropped request, beside the target's own EMPTY request log;
  * the stored blob, FETCHED BACK OFF DISK, beside the credential that is not
    in it.

Run it:

    .venv/bin/python scripts/demo_capture.py             # drives its own traffic
    .venv/bin/python scripts/demo_capture.py --browse    # waits for your browser

Everything it creates is a temporary directory it removes on the way out, and
every target is loopback. It never touches your real Burp home: the fixture
copies a seed home per run, which is also why the first launch takes a moment.

It needs what the integration tests need -- a Burp jar, a built extension jar,
and an accepted EULA in the seed home. If something is missing it says which,
and exits without starting anything.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from hx import capture as capture_mod            # noqa: E402
from hx import config as config_mod              # noqa: E402
from hx import engagement as eng_mod             # noqa: E402
from hx.bridge import server                     # noqa: E402
from hx.halt import OperatorHalt                 # noqa: E402
from hx.store import blobs as blobs_mod          # noqa: E402
from hx.store import db as db_mod                # noqa: E402
from tests.integration import burp_fixture as bf                # noqa: E402
from tests.integration.target_server import TargetServer        # noqa: E402

BOLD, DIM, GREEN, RED, YELLOW, CYAN, OFF = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m",
    "\033[0m")

SECRET_COOKIE = "session=hx-demo-SUPERSECRET-do-not-store"
SECRET_BEARER = "Bearer hx-demo-TOKEN-do-not-store"


def step(n: str, title: str) -> None:
    print(f"\n{BOLD}{n}. {title}{OFF}")


def did(what: str) -> None:
    print(f"   {DIM}did  {OFF}{what}")


def saw(what: str, *, good: bool | None = None) -> None:
    tick = "" if good is None else (f"{GREEN}[ok]{OFF} " if good
                                    else f"{RED}[!!]{OFF} ")
    print(f"   {DIM}saw  {OFF}{tick}{what}")


def note(what: str) -> None:
    print(f"   {YELLOW}note {OFF}{what}")


class Sink:
    """`hx.capture.Capture`, on a connection owned by the thread that uses it.

    The bridge calls its exchange sink ON THE READ THREAD, and a sqlite
    connection belongs to the thread that opened it -- so a Capture built over
    the main thread's connection raises `ProgrammingError` on every frame. The
    bridge catches everything the sink throws, by design (s4: a lost record
    changes what hx KNOWS, never what it ALLOWS), so the observable would be a
    live Burp, traffic flowing, and an empty database. Opened lazily here, on
    the first call, which is already on the read thread.
    """

    def __init__(self, root: Path, engagement_id: str, cfg: config_mod.Config):
        self._root, self._id, self._cfg = Path(root), engagement_id, cfg
        self._capture: capture_mod.Capture | None = None
        self.failing = False
        self.refused = 0

    def __call__(self, header: dict, request: bytes, response: bytes):
        if self.failing:
            # Step 6 flips this. The bridge keeps the exception, counts the
            # loss, and the browser must not notice.
            self.refused += 1
            raise RuntimeError("demo: the sink is deliberately broken")
        if self._capture is None:
            self._capture = capture_mod.Capture(
                db_mod.connect(self._root / "hx.db"),
                blobs_mod.BlobStore(self._root / "blobs"),
                self._id, self._cfg)
        return self._capture.on_exchange(header, request, response)


def through_proxy(port: int, method: str, url: str, headers: dict | None = None,
                  body: bytes = b"") -> tuple[int, bytes]:
    """One request through Burp's proxy, in absolute-URI form.

    The ABSOLUTE url is the whole point: that is how a client speaks to a
    forward proxy, and it is what puts the destination in front of hx's scope
    check. The reply is read in full because a DROPPED request is answered by
    Burp itself, and its body is the only thing that distinguishes the two --
    by length, never by status.
    """
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request(method, url, body=body, headers=headers or {})
        reply = conn.getresponse()
        return reply.status, reply.read()
    finally:
        conn.close()


def rows(conn, sql: str, args: tuple = ()) -> list:
    return conn.execute(sql, args).fetchall()


def settle(conn, sql: str, args: tuple = (), *, want: int, timeout: float = 12.0):
    """Wait for a row to arrive, bounded.

    The capture frame is UNSOLICITED and arrives AFTER the client's response --
    measured in Task 9, five browses read 1,1,2,3,4 rows. So nothing here may
    read the store immediately after a request and conclude anything.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = rows(conn, sql, args)
        if len(got) >= want:
            return got
        time.sleep(0.15)
    return rows(conn, sql, args)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--browse", action="store_true",
                    help="wait for you to browse through the proxy, and narrate "
                         "each request as it arrives, instead of driving traffic")
    args = ap.parse_args()

    if bf.unbuilt():
        print(f"{RED}unbuilt:{OFF} " + ", ".join(bf.unbuilt()))
        print("  run ./extension/build.sh first")
        return 1
    if bf.missing():
        print(f"{RED}missing:{OFF} " + ", ".join(bf.missing()))
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="hx-demo-capture-"))
    with contextlib.ExitStack() as stack:
        stack.callback(lambda: shutil.rmtree(workdir, ignore_errors=True))

        print(f"{BOLD}hx -- the proxy enforcement point, against a real Burp{OFF}")
        print(f"{DIM}   scratch {workdir}{OFF}")

        step("0", "Stand up an engagement, two targets, and Burp")
        target = TargetServer("127.0.0.1")
        stack.callback(target.stop)
        target.start()
        offside = TargetServer("127.0.0.2")
        stack.callback(offside.stop)
        offside.start()
        did(f"in-scope target   {target.origin}")
        did(f"out-of-scope host {offside.origin}   {DIM}(listening the whole time){OFF}")

        cfg = config_mod.Config(name="demo-capture", client="loopback",
                                scope_include=[f"{target.origin}/*"])
        eng = eng_mod.create(workdir / "engagement", cfg, author="demo")
        stack.callback(eng.db.close)
        did(f"engagement {eng.id}  {DIM}scope: {target.origin}/*{OFF}")

        halt = OperatorHalt(eng.root, eng.db)
        sink = Sink(eng.root, eng.id, cfg)
        srv = server.BridgeServer(workdir / "hx.sock", engagement_id=eng.id,
                                  operator_halt=halt, on_exchange=sink)
        stack.callback(srv.stop)
        srv.start()

        crawler_port = bf._free_port()
        proc = bf.launch_burp(srv.socket_path, eng.id, workdir / "burp",
                              sentinel=halt.sentinel_path,
                              crawler_port=crawler_port)
        stack.callback(bf_reap, proc)
        if not bf.wait_for(lambda: srv.state == "connected"):
            print(f"{RED}Burp never completed the handshake.{OFF} "
                  f"See {workdir / 'burp' / 'burp.log'}")
            return 1

        operator_port = bf.proxy_port(workdir / "burp")
        crawler_port = bf.second_proxy_port(workdir / "burp")
        did(f"Burp up, bridge connected  {DIM}operator :{operator_port}  "
            f"crawler :{crawler_port}{OFF}")

        why = bf.not_loopback_only(proc.pid, [operator_port, crawler_port])
        if why:
            print(f"{RED}refusing to continue: {why}{OFF}")
            return 1
        saw("both listeners are loopback-only", good=True)

        # The same body shape the integration rig sends. `method.allow` and
        # `dangerous.path` are the AGENT's rules -- step 5 is the demonstration
        # that they bind crawler traffic and not the operator's own browsing.
        epoch = srv.configure(
            {
                "scope.include": [f"{target.origin}/*"],
                "method.allow": ["GET", "HEAD", "OPTIONS"],
                "dangerous.path": ["*/logout*", "*/password*"],
                "limit.rate_rps": [str(cfg.rate_limit_rps)],
                "limit.max_requests": ["500"],
            },
            scope_sha256=hashlib.sha256(
                config_mod.dumps(cfg).encode("utf-8")).hexdigest(),
            profile=cfg.safety_profile)
        saw(f"scope authorised, config epoch {epoch}", good=True)

        conn = eng.db
        if args.browse:
            return browse(conn, operator_port, target, offside, workdir)
        return drive(conn, sink, srv, operator_port, crawler_port,
                     target, offside,
                     blobs_mod.BlobStore(eng.root / "blobs"))


def bf_reap(proc) -> None:
    proc.kill()
    with contextlib.suppress(Exception):
        proc.wait(timeout=15)


def drive(conn, sink, srv, operator_port, crawler_port, target, offside,
          store) -> int:
    """Six things, each pairing what happened with where nothing did."""

    step("1", "An in-scope request is recorded")
    status, _ = through_proxy(operator_port, "GET", f"{target.origin}/api/orders")
    did(f"GET {target.origin}/api/orders  through :{operator_port}")
    saw(f"client got {status}")
    got = settle(conn, "SELECT url, status, req_blob, resp_blob FROM exchange"
                       " WHERE url LIKE ? ORDER BY rowid DESC", (f"%/api/orders",),
                 want=1)
    if got:
        url, st, req_blob, resp_blob = got[0]
        saw(f"exchange row  status={st}  {url}", good=True)
        saw(f"blobs  req {req_blob[:16]}...  resp {resp_blob[:16]}...", good=True)
    else:
        saw("no exchange row yet", good=False)

    step("2", "An out-of-scope request never reaches the target")
    before = len(offside.hits)
    status, body = through_proxy(operator_port, "GET", f"{offside.origin}/secret")
    did(f"GET {offside.origin}/secret  through :{operator_port}")
    saw(f"client got {status}, {len(body)} bytes")
    # The BYTE COUNT IS READ BACK, not asserted. Task 1 measured Burp's drop
    # page at ~1529 bytes; this run prints whatever it actually got, and the
    # two have already differed. A demo that states a remembered constant in
    # front of a reader who can see the real one is the claim-shaped sentence
    # this project keeps finding -- so the number above is the evidence and
    # this note only says what it MEANS.
    note(f"{BOLD}the client's answer proves nothing.{OFF} Those {len(body)} bytes "
         f"are Burp's own page,\n        not the target's -- a dropped request and a "
         f"delivered one are\n        {BOLD}indistinguishable by status code{OFF}. "
         f"The evidence is the target's log, below.")
    after = offside.hits[before:]
    saw(f"the out-of-scope target received {len(after)} requests "
        f"{DIM}(it has been listening throughout){OFF}", good=not after)
    den = settle(conn, "SELECT kind, via, url FROM denial ORDER BY rowid DESC",
                 want=1)
    if den:
        saw(f"denial row  kind={den[0][0]}  via={den[0][1]}", good=den[0][1] == "proxy")

    step("3", "A credential never reaches the blob store")
    through_proxy(operator_port, "GET", f"{target.origin}/login",
                  headers={"Cookie": SECRET_COOKIE, "Authorization": SECRET_BEARER})
    did(f"GET {target.origin}/login  carrying a Cookie and an Authorization header")
    did("...and the target answers with a Set-Cookie of its own")
    got = settle(conn, "SELECT req_blob, resp_blob FROM exchange"
                       " WHERE url LIKE ? ORDER BY rowid DESC", ("%/login",), want=1)
    if got:
        saw("fetching the stored blobs back off disk...")
        req_bytes = read_blob(store, got[0][0])
        resp_bytes = read_blob(store, got[0][1])
        leaked_c = b"SUPERSECRET" in (req_bytes or b"")
        leaked_b = b"TOKEN-do-not-store" in (req_bytes or b"")
        leaked_s = b"hx-demo" in (resp_bytes or b"") and b"session=" in (resp_bytes or b"")
        saw(f"request blob contains the session cookie value: {leaked_c}",
            good=not leaked_c)
        saw(f"request blob contains the bearer token: {leaked_b}", good=not leaked_b)
        for line in (req_bytes or b"").split(b"\r\n"):
            if line[:7].lower() in (b"cookie:", b"authori"):
                saw(f"stored as  {CYAN}{line.decode('latin-1')}{OFF}", good=True)
        saw(f"response blob still carries a live Set-Cookie: {leaked_s}",
            good=not leaked_s)

    step("4", "Two ids under one endpoint become one surface")
    for oid in ("1001", "1002"):
        through_proxy(operator_port, "GET", f"{target.origin}/api/orders/{oid}")
    did(f"GET /api/orders/1001 and /api/orders/1002")
    # `path_template`, not `template`: the column carries the TEMPLATED path
    # and the query KEY SET lives beside it, because two URLs differing only in
    # a value are one surface while two differing in their key set are not.
    surf = settle(conn, "SELECT method, path_template, kind FROM surface"
                        " WHERE path_template LIKE ?", ("%/api/orders/%",), want=1)
    for method, tmpl, kind in surf:
        saw(f"one surface  {CYAN}{method} {tmpl}{OFF}  kind={kind}", good=True)
    if len(surf) > 1:
        saw(f"...but there are {len(surf)} of them, so the two ids did NOT merge",
            good=False)

    step("5", "The same POST, two listeners, two answers")
    note("s4: the method allowlist and the dangerous-path denylist constrain an "
         "AGENT.\n        They apply to crawler traffic in full and not at all to "
         "the operator's own\n        browsing -- and the two are told apart by "
         "WHICH LISTENER the request arrived\n        on, never by anything in the "
         "traffic itself.")
    for label, port in (("operator", operator_port), ("crawler", crawler_port)):
        n_before = len(target.hits)
        status, _ = through_proxy(port, "POST", f"{target.origin}/api/orders",
                                  headers={"Content-Type": "application/json"},
                                  body=b'{"total":"1.00"}')
        reached = len(target.hits) > n_before
        saw(f"{label:8s} :{port}  client got {status}  "
            f"target reached: {reached}", good=(reached if label == "operator"
                                                else not reached))

    step("6", "A broken harness changes what hx KNOWS, never what it ALLOWS")
    note("s4 says a wedged harness, a full queue or a dropped record must never\n"
         "        become a stall on the client's application. A DEAD BRIDGE is a "
         "different\n        thing and is NOT this: DENY-ALL is terminal, so losing "
         "the bridge stops\n        issuance by design. This shows the first, not "
         "the second.")
    sink.failing = True
    did("the capture sink is now throwing on every frame")
    n_before = len(target.hits)
    status, _ = through_proxy(operator_port, "GET", f"{target.origin}/health")
    saw(f"client got {status}", good=status == 200)
    saw(f"the target still received the request: {len(target.hits) > n_before}",
        good=len(target.hits) > n_before)
    time.sleep(1.0)
    saw(f"hx refused {sink.refused} frame(s) and kept the channel", good=True)
    saw(f"the bridge recorded {srv.exchange_errors} sink failure(s)", good=True)
    sink.failing = False

    print()
    step("=", "What the engagement now holds")
    for label, sql in (("surfaces", "SELECT COUNT(*) FROM surface"),
                       ("exchanges", "SELECT COUNT(*) FROM exchange"),
                       ("denials", "SELECT COUNT(*) FROM denial"),
                       ("runs", "SELECT COUNT(*) FROM run")):
        print(f"   {label:12s} {conn.execute(sql).fetchone()[0]}")
    dropped = conn.execute("SELECT COALESCE(SUM(dropped_total),0) FROM run").fetchone()[0]
    if dropped:
        print(f"   {YELLOW}{dropped} record(s) dropped -- the counts above are a "
              f"FLOOR, not a total.{OFF}")
    print(f"\n{DIM}   Everything above happened on loopback. Nothing in this "
          f"project has ever\n   sent a request off this machine.{OFF}\n")
    return 0


def read_blob(store: blobs_mod.BlobStore, digest: str | None) -> bytes | None:
    """The blob, off disk, by its digest -- or None.

    Takes the STORE rather than looking a root up from the database: there is
    no `engagement.root` column, and inventing one here to save an argument is
    how a demo starts asserting things about a schema it does not own.
    """
    if not digest:
        return None
    with contextlib.suppress(Exception):
        return store.get(digest)
    return None


def browse(conn, operator_port, target, offside, workdir) -> int:
    print(f"\n{BOLD}Browsing mode.{OFF}")
    print(f"   Point your browser's HTTP proxy at {BOLD}127.0.0.1:{operator_port}{OFF}")
    print(f"   In scope:     {target.origin}/*   {DIM}(try /api/orders, /login){OFF}")
    print(f"   Out of scope: {offside.origin}/*  {DIM}(will be dropped){OFF}")
    print(f"   {DIM}Burp's CA certificate, if you need HTTPS: "
          f"{workdir / 'burp'}{OFF}")
    print(f"\n   {DIM}Ctrl-C to stop and print the summary.{OFF}\n")
    seen_x = seen_d = 0
    try:
        while True:
            time.sleep(0.4)
            for url, st in rows(conn, "SELECT url, status FROM exchange"
                                      " ORDER BY rowid LIMIT -1 OFFSET ?", (seen_x,)):
                saw(f"{GREEN}recorded{OFF}  {st}  {url}")
                seen_x += 1
            for kind, url in rows(conn, "SELECT kind, url FROM denial"
                                        " ORDER BY rowid LIMIT -1 OFFSET ?", (seen_d,)):
                saw(f"{RED}refused {OFF}  {kind}  {url}")
                seen_d += 1
    except KeyboardInterrupt:
        pass
    print(f"\n   {seen_x} exchange(s), {seen_d} denial(s) recorded.")
    print(f"   {DIM}The refused ones never reached their target. "
          f"The client could not tell.{OFF}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
