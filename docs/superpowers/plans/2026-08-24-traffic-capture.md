# Traffic Capture Implementation Plan

<!-- Remove the marker above in the commit that finishes this plan. Until then
     tests/test_plan_matches_repo.py skips this plan's blocks: every task here
     describes a file that does not exist yet, so its blocks describe the state
     AFTER the task rather than the state now. -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build §4's second enforcement point — the proxy request handler — and turn the store from a schema into something that gets written to, so that browsing the target through Burp produces an enforced, deduplicated, recorded attack surface.

**Architecture:** The extension gains a `ProxyGate` that decides (scope, from the same `Policy` the send path uses) and a `Capture` that records (redact, then push over a bounded queue that drops oldest and counts). Enforcement never waits on capture: scope is decided from the authorisation snapshot before anything is queued, so a wedged harness changes what `hx` knows and never what it allows. Python gains the consumer — blob, surface, exchange row — plus run lifecycle and two CLI verbs.

**Tech Stack:** Java 21 (`javac --release 21`, zero third-party dependencies, hand-rolled test runner), Python 3.12, SQLite, the Plan 2 bridge (`src/hx/bridge/`, `extension/src/hx/bridge/`), the Plan 1 store (`src/hx/store/`), Burp Suite Community 2026.7.3 via the Montoya API.

**Spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` — §4 (enforcement invariant, amended `b05a94a`), §5 (data model), §6 (bridge protocol), §7 (redaction), §9 (discovery).

## Global Constraints

- **Every byte that leaves this machine crosses exactly one of two enforcement points, both inside the JVM: the proxy request handler, or the send path.** Never add a third egress path (§4).
- **Scope is absolute at both points, for all traffic.** Out of scope is dropped and the drop is recorded (§4).
- **The agent's four rules — method allowlist, dangerous-path denylist, rate limit, budget — apply to the send path in full and to crawler traffic in full. They do NOT apply to traffic from the operator's own browser** (§4).
- **The two sources are told apart by which proxy listener the request arrived on, never by anything in the traffic itself** (§4).
- **Capture never gates enforcement.** A wedged harness, a full queue or a dropped record changes what `hx` KNOWS, never what it ALLOWS (§4).
- **Any denial produces a `denial` row and a distinct error class. Denials are never silent** (§4).
- **Redaction runs before hashing.** The blob store is content-addressed, so a credential that reaches the hashing step is already unrecoverable (§7).
- **Redaction is deterministic.** Two requests differing only in credential bytes must produce the same blob; a mask that varied would fragment the store and inflate every coverage number derived from it.
- **Engagement directories are `0o700`; blob and database files are `0o600`.** Never looser, never widened (§3).
- **The agent may never write finding status `confirmed` or `reported`** — a database trigger forbids it (§5).
- **`hx` must never bundle or redistribute Burp** (§2).
- **All test targets are loopback only.** Nothing in this project has ever sent a request off this machine. Real Burp runs against a private throwaway home directory, never the real `$HOME`.
- **Zero third-party dependencies in the extension.** Java 21, `javac --release 21`.

## Environment

- `pytest` is at `.venv/bin/pytest`, **not** on PATH. Integration tests are deselected by default: `-m integration`.
- `find` and `grep` are shadowed by broken shell functions in the interactive profile. Use `command find` / `command grep`.
- The Java suite is `extension/test.sh`. It prints **one summary line per class** and its output contains NUL bytes, so `grep` needs `-a` or it reports "binary file matches" and you see two lines instead of nine.
- The jar is built by `extension/build.sh`.
- **A healthy `burp.log` ENDS at `java.lang.Error: no ComponentUI class`** — 6423 bytes, twice, byte-identical to `~/F0RT1KA/burp-lab/harness-burp.log` from a known-good run. Burp catches the Swing failure and carries on.
- **`api.logging().logToError` writes to Burp's extension log, not stdout.** "No `hx` lines in `burp.log`" is not evidence the extension did not run.

## Baseline

Reproduce before starting any task and again when finishing it:

    java:        9 x ALL PASS / 1614 ok / 0 FAIL / 0 SKIP
    python:      376 passed, 14 deselected
    drift:       87 passed, 0 skipped
    integration: 14 passed (~95 s)
    jar builds

## The five rules this project bought, each with a fix round

1. **Judge every suite run by its summary lines**, never `grep -c FAIL`. A truncated run and a green run are indistinguishable by failure count.
2. **Name the expected sha256 to any sabotage harness** so it refuses to start on a polluted tree. Back up by file **copy**, restore by copy, verify the hash. `git checkout --` restores to HEAD, not to pre-edit, and eats uncommitted work.
3. **A guard is only tested by the input that separates it from its absence.** This fired on all eight tasks of Plan 3 without exception. Assume it applies to yours.
4. **A comment asserting an invariant is a claim.** Thirty-four on the previous branch turned out false. Measure before you assert, and **grep your own diff before you report** — the last four rounds did and found eighteen between them.
5. **Sync plan blocks ONLY with `scripts/sync_plan_block.py`**, passing an explicit allowlist. Six hand-rolled attempts corrupted something. The drift check compares 81 blocks and drops none, including excerpt blocks marked ` -- note` and `.sql` blocks.

---

## File Structure

**Java — create:**

| File | Responsibility |
|---|---|
| `extension/src/hx/proxy/Source.java` | The traffic source enum (`OPERATOR`, `CRAWLER`, `UNATTRIBUTED`) and how a request is attributed to one. One file because the attribution rule is the security boundary and must be readable on its own. **`UNATTRIBUTED` was added by Task 5's fix round 1**: a listener port that cannot be determined is its own answer, and `ProxyGate` refuses it, rather than falling into the permissive branch. |
| `extension/src/hx/proxy/ProxyGate.java` | §4's second enforcement point. Decides scope (operator) or the full order (crawler), returns drop-or-continue, and emits the denial. Owns no I/O. |
| `extension/src/hx/proxy/Observed.java` | The immutable record of one observed exchange: redacted request bytes, redacted response bytes, timing, source, status. |
| `extension/src/hx/proxy/Capture.java` | The bounded queue: accept an `Observed`, drop oldest when full, count drops, hand to the bridge on its own thread. Never blocks the caller. |

**Java — modify:**

| File | Change |
|---|---|
| `extension/src/hx/HxExtension.java` | Register the proxy handlers; construct `ProxyGate` and `Capture`; wire the drop counter. |
| `extension/src/hx/bridge/BridgeClient.java` | `exchangeSink()` — frames `{v, t:"exchange", ...}` with **two** bodies. |
| `extension/src/hx/bridge/Frame.java` | Two-body encode/decode. |
| `extension/test/hx/ChokepointTest.java` | Grow the structural egress test: `registerRequestHandler` exactly once, the scope check inside it, and a count over `java.net.Socket` / `HttpClient` / `URL.openConnection`. |

**Python — create:**

| File | Responsibility |
|---|---|
| `src/hx/surface.py` | The normaliser. URL → `path_template` + `query_key_set`. Pure functions, no database, no bridge. |
| `src/hx/run.py` | Run lifecycle: auto-open, heartbeat, idle-close, stale-heartbeat-to-error, `dropped_total`. |
| `src/hx/capture.py` | The exchange-frame consumer: blob put, surface upsert, `record_exchange`. The only place the three meet. |

**Python — modify:**

| File | Change |
|---|---|
| `src/hx/bridge/codec.py` | Two-body frame decode. |
| `src/hx/bridge/server.py` | `on_exchange` sink, called on the read thread. |
| `src/hx/store/records.py` | `record_exchange` gains `via`; `record_denial` gains `via`. |
| `src/hx/cli.py` | `hx capture start` / `hx capture stop`; `hx info` grows surfaces, exchanges, drops. |

**Tests — create:** `tests/test_surface.py`, `tests/test_run.py`, `tests/test_capture.py`, `extension/test/hx/proxy/ProxyGateTest.java`, `extension/test/hx/proxy/CaptureTest.java`, `tests/integration/test_proxy_capture.py`.

---

### Task 1: Measure what Burp's proxy actually does

Everything after this task rests on three facts nobody in this project has measured. The previous branch learned this the expensive way twice: `sendRequest` returning when the socket closes rather than when the response completes, and `toByteArray()` carrying interim `1xx` heads. Both were found by measuring, and both would have been designed around wrongly.

**This task builds no production code.** Its deliverable is a recorded answer to each question plus a test that goes red if Burp's behaviour changes under a future upgrade.

**Files:**
- Create: `docs/burp-proxy-measurements.md`
- Create: `tests/integration/test_proxy_facts.py`
- Create: `extension/src/hx/proxy/Probe.java` (temporary; deleted in Step 8)
- Test: `tests/integration/test_proxy_facts.py`

**Interfaces:**
- Consumes: `tests.integration.burp_fixture` — `missing()`, `launch_burp(socket_path, engagement_id, workdir, sentinel)`, `wait_for(predicate, timeout)`; `tests.integration.target_server.TargetServer` — `TargetServer(host)`, `.start()`, `.stop()`, `.origin`, `.host`, `.port`, `.hits`
- Produces: three recorded facts, and `Source.attribute` in Task 3 depends on **Q1**'s answer.

**The three questions:**

**Q1. Does `InterceptedRequest` expose which proxy listener it arrived on?** The operator/crawler split rests on it. If the answer is no, the fallback is a second `BridgeClient` on a second socket — heavier, but still a property of the connection rather than the content.

**Q2. Does `messageId()` correlate a request to its response?** Including when two requests are in flight and the responses come back out of order.

**Q3. Does `drop()` actually prevent egress?** Not "does Burp report a drop" — does the target receive **zero** bytes.

- [ ] **Step 1: Write the probe extension**

```java
// extension/src/hx/proxy/Probe.java
package hx.proxy;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * A throwaway extension that answers three questions and writes what it saw
 * to a file. Deleted in Step 8; nothing may depend on it.
 *
 * It writes to a FILE rather than logging, because api.logging().logToError
 * goes to Burp's own extension log and not to stdout -- a fact that cost a
 * day on the previous branch when "no hx lines in burp.log" was read as "the
 * extension never ran".
 */
public class Probe implements BurpExtension {
    private static Path out;

    public void initialize(MontoyaApi api) {
        out = Path.of(System.getProperty("hx.probe.out", "/tmp/hx-probe.txt"));
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest r) {
                // Q1: every accessor that might name the listener. Reflection
                // rather than a compile-time call, so a method that does not
                // exist is a recorded ABSENCE rather than a build failure.
                StringBuilder sb = new StringBuilder("REQ id=" + r.messageId()
                        + " path=" + r.path());
                for (String name : new String[]{
                        "listenerInterface", "listenerPort", "sourceIpAddress",
                        "destinationIpAddress", "httpService"}) {
                    sb.append(' ').append(name).append('=');
                    try {
                        sb.append(r.getClass().getMethod(name).invoke(r));
                    } catch (NoSuchMethodException e) {
                        sb.append("<absent>");
                    } catch (Throwable e) {
                        sb.append("<threw ").append(e.getClass().getSimpleName()).append('>');
                    }
                }
                write(sb.toString());

                // Q3: drop anything whose path says to, and record that we did.
                if (r.path().startsWith("/drop")) {
                    write("DROPPED id=" + r.messageId());
                    return ProxyRequestReceivedAction.drop();
                }
                return ProxyRequestReceivedAction.continueWith(r);
            }

            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest r) {
                return ProxyRequestToBeSentAction.continueWith(r);
            }
        });
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse r) {
                // Q2: does the id match the request's, and is it there at all?
                write("RESP id=" + r.messageId() + " status=" + r.statusCode()
                      + " reqpath=" + r.initiatingRequest().path());
                return ProxyResponseReceivedAction.continueWith(r);
            }

            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse r) {
                return ProxyResponseToBeSentAction.continueWith(r);
            }
        });
        write("PROBE READY");
    }

    private static synchronized void write(String line) {
        try {
            Files.writeString(out, line + "\n", StandardOpenOption.CREATE,
                              StandardOpenOption.APPEND);
        } catch (Exception e) {
            // A probe that cannot write has nothing to say; failing loudly
            // here would only obscure the run.
        }
    }
}
```

- [ ] **Step 2: Build the probe into the jar**

Run: `./extension/build.sh`
Expected: `built /path/to/hx/extension/build/hx-bridge.jar`

- [ ] **Step 3: Write the measurement harness**

```python
# tests/integration/test_proxy_facts.py
"""What Burp's proxy actually does, pinned so an upgrade cannot change it quietly.

These are MEASUREMENTS, not behaviour this project chose. Each one is a fact
about Burp 2026.7.3 that Plan 4's design rests on, and each test fails if a
future Burp answers differently -- which is the point. A design built on an
unmeasured assumption is how the previous branch shipped an auto-halt a peer
could disarm.

The prose record is `docs/burp-proxy-measurements.md`. These tests and that
document are one deliverable in two halves: the document says what Burp does
and the tests say it is still true. Q1's test reads the document back, so the
two cannot drift apart in silence.
"""
from __future__ import annotations

import re
import socket
import threading
import time
from pathlib import Path

import pytest

from tests.integration import burp_fixture as bf
from tests.integration.target_server import TargetServer

pytestmark = pytest.mark.integration

RECORD = Path(__file__).resolve().parents[2] / "docs" / "burp-proxy-measurements.md"

# The accessors on InterceptedRequest that might name the connection a request
# arrived on, in the order the probe writes them. `listenerPort` is in the list
# BECAUSE it does not exist: an accessor's absence is a measurement too, and one
# nobody would think to look for once the code is written around its absence.
ACCESSORS = ("listenerInterface", "listenerPort", "sourceIpAddress",
             "destinationIpAddress", "httpService")

# What Burp 2026.7.3 answered, classified. Three outcomes and not two: an
# accessor that EXISTS and THROWS is the trap here -- destinationIpAddress() is
# declared on the same InterceptedHttpMessage interface as listenerInterface(),
# compiles, and raises UnsupportedOperationException("Not yet implemented") the
# moment it is called. Code written against the interface's declared surface
# would reach for it as "a property of the connection" and find out at runtime.
MEASURED = {
    "listenerInterface": "present",
    "listenerPort": "absent",
    "sourceIpAddress": "present",
    "destinationIpAddress": "throws",
    "httpService": "present",
}

# What Burp answers the client whose request was DROPPED. Both halves are
# measured and each is load-bearing for a different reason.
#
# The STATUS is the finding: a delivered request returns 200 too, so a drop and
# a delivery are indistinguishable by status code and nothing may ever read the
# client's status as evidence that a request was blocked.
#
# The BYTE COUNT is what makes that finding checkable in the DOCUMENT. The
# document is the deliverable Task 5 acts from, and its whole Q3 client-response
# section could be deleted with this test still green -- reproduced -- because
# the document readback this file already had covered the accessor table and
# nothing else. A number this specific cannot survive in prose that no longer
# says what it is about. Burp's drop page is static: two drops of very different
# path lengths measured 1529 bytes each and it echoes nothing of the request, so
# this is a constant rather than a fingerprint of one URL.
DROPPED_STATUS = 200
DROPPED_BYTES = 1529

_FIELDS = ("id", "path", "status", "reqpath") + ACCESSORS
_SPLIT = re.compile(r" (?=(?:%s)=)" % "|".join(_FIELDS))


def fields(line: str) -> dict[str, str]:
    """The probe's `name=value` fields, split on the NAMES and not on whitespace.

    A value can contain spaces. `destinationIpAddress=<threw java.lang.
    UnsupportedOperationException: Not yet implemented>` is one field, and
    line.split() reads it as five -- losing the message, which is the only part
    of it that says anything about why the accessor cannot be used.
    """
    out: dict[str, str] = {}
    for chunk in _SPLIT.split(line):
        name, sep, value = chunk.partition("=")
        if sep and name in _FIELDS:
            out[name] = value
    return out


def classify(value: str) -> str:
    if value == "<absent>":
        return "absent"
    if value.startswith("<threw "):
        return "throws"
    return "present"


@pytest.fixture
def probe(tmp_path):
    """Real Burp running the probe extension, with a private home.

    Neither guard after `PROBE READY` is ceremony.

    The control request proves the peer is Burp. Burp is reached over a TCP
    port, and a port is whatever bound it first: an earlier draft of this
    fixture chose its ports by hand, and unrelated services on this machine
    answered `421` and a clean `200` while Burp was never involved and the
    probe file held nothing but `PROBE READY`. Nothing about a successful HTTP
    exchange proves the peer was Burp. A line in the probe file does, because
    only Burp's proxy can put one there.

    The loopback check proves the port is not open to the network. `listen_mode:
    loopback_only` goes into both listeners and was asserted in three places and
    checked by nothing: changing that one string to `all_interfaces` left this
    file reporting `3 passed in 38.03s` with `ss` showing the two listeners on
    `*:34777` and `*:38399` -- an open forward relay for as long as they run.

    A missing probe source FAILS rather than skips. It is a file this repository
    ships, not a prerequisite of this machine -- see bf.probe_source_missing().
    """
    gone = bf.probe_source_missing()
    if gone:
        pytest.fail(gone)
    if bf.probe_missing():
        pytest.skip(f"missing: {', '.join(bf.probe_missing())}")
    out = tmp_path / "probe.txt"
    target = TargetServer("127.0.0.1")
    target.start()
    proc = bf.launch_probe(tmp_path, out, extra_listener_port=0)
    try:
        assert bf.wait_for(lambda: out.exists() and "PROBE READY" in out.read_text()), \
            f"probe never started; burp.log: {tmp_path / 'burp.log'}"

        # Polled rather than read once: `PROBE READY` is written when the
        # extension loads and says nothing about when the listeners bound.
        # (Measured: all of them were already up at this point on every run
        # taken here, so the poll has never actually had to wait.)
        #
        # It costs one `ss` call on the happy path and the full 15 s on the
        # unhappy one -- waiting cannot turn a wildcard bind into a loopback
        # bind, so those seconds buy nothing there. Measured: these three
        # tests took 38.03 s before this check existed, 39.36 s with it, and
        # 81.28 s with the mutation in. That is the right way round for a
        # check that is only ever slow once it has already found something.
        violation: str | None = "the loopback check did not run"

        def on_loopback_only() -> bool:
            nonlocal violation
            violation = bf.not_loopback_only(proc.pid, bf.listener_ports(tmp_path))
            return violation is None

        assert bf.wait_for(on_loopback_only, 15), violation

        p = _Probe(out, target, bf.proxy_port(tmp_path),
                   bf.second_proxy_port(tmp_path))
        p.through_proxy("/health")
        assert bf.wait_for(lambda: any(line.startswith("REQ ") for line in p.lines()), 30), (
            f"a request to 127.0.0.1:{p.proxy_port} never reached the probe's "
            f"handler. Something answered on that port that is not this Burp -- "
            f"check `ss -tlnp | grep {p.proxy_port}`. burp.log: "
            f"{tmp_path / 'burp.log'}")
        yield p
    finally:
        proc.kill()
        proc.wait(timeout=30)
        target.stop()


class _Probe:
    def __init__(self, out: Path, target: TargetServer,
                 proxy_port: int, second_port: int):
        self.out, self.target = out, target
        self.proxy_port, self.second_port = proxy_port, second_port

    def lines(self) -> list[str]:
        return self.out.read_text().splitlines()

    def requests(self) -> list[dict[str, str]]:
        return [fields(line) for line in self.lines() if line.startswith("REQ ")]

    def responses(self) -> list[dict[str, str]]:
        return [fields(line) for line in self.lines() if line.startswith("RESP ")]

    def request_for(self, path: str) -> dict[str, str]:
        found = [r for r in self.requests() if r.get("path") == path]
        assert len(found) == 1, (
            f"expected exactly one request for {path}, got {len(found)}: "
            f"{self.lines()}")
        return found[0]

    def raw_through_proxy(self, path: str, port: int | None = None) -> bytes:
        """One proxied request, and the whole response as it came off the wire.

        `http.client` hands back a status and a decoded body. The byte count of
        the FULL response, head included, is the other half of what Q3 records,
        and no http.client API exposes it. Reading to EOF is safe for exactly
        one reason: the response this exists to measure carries
        `Connection: close`, which is Burp's own doing.
        """
        sock = socket.create_connection(("127.0.0.1", port or self.proxy_port),
                                        timeout=30)
        try:
            sock.sendall(f"GET {self.target.origin}{path} HTTP/1.1\r\n"
                         f"Host: {self.target.host}:{self.target.port}\r\n"
                         f"Connection: close\r\n\r\n".encode())
            chunks = []
            while chunk := sock.recv(65536):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            sock.close()

    def through_proxy(self, path: str, port: int | None = None) -> int | None:
        """One request through Burp's proxy. None means the connection died."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port or self.proxy_port,
                                          timeout=30)
        try:
            conn.request("GET", f"{self.target.origin}{path}")
            return conn.getresponse().status
        except (http.client.HTTPException, OSError):
            return None
        finally:
            conn.close()


def test_q1_whether_a_request_names_the_listener_it_arrived_on(probe):
    """Q1. Plan 4's operator/crawler split rests on this answer.

    Measured answer: YES. `listenerInterface()` returns `host:port` for the
    listener the request arrived on -- `127.0.0.1:42969` -- and two listeners in
    one Burp produce two different values for the same request. So the split can
    be a property of the CONNECTION, which is what spec s4 requires, and no
    second BridgeClient is needed.

    The two halves below are different claims and both are needed. The
    classification pins WHICH accessors Burp offers, so a future version that
    adds, removes or breaks one goes red here rather than in Task 5. The
    distinctness check pins that the value actually DISCRIMINATES: an accessor
    that existed and returned the same string for every listener would satisfy
    the first half completely and answer Q1 no.
    """
    assert probe.through_proxy("/api/orders") == 200
    assert probe.through_proxy("/account/logout", port=probe.second_port) == 200

    observed = {name: classify(probe.requests()[0][name]) for name in ACCESSORS}
    assert observed == MEASURED, (
        f"the accessors InterceptedRequest offers have changed: {observed} is "
        f"not the measured {MEASURED}. This is not necessarily a defect -- it is "
        "a new measurement. Update MEASURED and docs/burp-proxy-measurements.md "
        "together, and re-read Task 5's source attribution against the new set.")

    recorded = RECORD.read_text()
    for name, verdict in MEASURED.items():
        assert any(name in line and verdict in line
                   for line in recorded.splitlines()), (
            f"{name} is {verdict} on InterceptedRequest and no single line of "
            f"{RECORD.name} says so -- record what Burp offers before designing "
            "around what it does not")

    primary = probe.request_for("/api/orders")["listenerInterface"]
    second = probe.request_for("/account/logout")["listenerInterface"]
    assert primary != second, (
        f"both listeners report listenerInterface={primary!r}, so the accessor "
        "exists but tells the two apart from nothing. Q1's answer is NO and "
        "Task 5 needs the second-BridgeClient fallback.")
    assert primary.endswith(f":{probe.proxy_port}"), (primary, probe.proxy_port)
    assert second.endswith(f":{probe.second_port}"), (second, probe.second_port)


def test_q2_message_id_correlates_a_response_to_its_request(probe):
    """Q2. Capture pairs the two halves of an exchange by this id.

    Sequential requests would prove almost nothing: ids that merely count up
    match by accident when nothing overlaps. So two requests are put in flight
    at once against a target that answers the first one LAST, and the test
    requires the responses to arrive in the other order before it believes the
    pairing means anything.

    Measured answer: YES. Ids are assigned in request order and the response
    carries the id of ITS request, not of the exchange that finished first.
    """
    done: dict[str, int | None] = {}

    def go(name, path):
        done[name] = probe.through_proxy(path)

    slow = threading.Thread(target=go, args=("slow", "/slow?ms=2500"))
    fast = threading.Thread(target=go, args=("fast", "/api/orders"))
    slow.start()
    time.sleep(0.5)          # the slow exchange is already open
    fast.start()
    slow.join(60)
    fast.join(60)
    assert done == {"slow": 200, "fast": 200}, done

    reqs = {r["id"]: r for r in probe.requests()}
    resps = probe.responses()
    assert resps, "no response reached the handler"

    ids = {r["id"] for r in resps}
    assert ids <= set(reqs), (
        f"a response carried an id no request did: {ids - set(reqs)}. Capture "
        "cannot pair the halves of an exchange by messageId if this is false.")
    for resp in resps:
        assert resp["reqpath"] == reqs[resp["id"]]["path"], (
            f"messageId {resp['id']} is on a response whose initiating request "
            f"was {resp['reqpath']}, but the request with that id was "
            f"{reqs[resp['id']]['path']}. The id does not correlate.")

    order = [r["reqpath"] for r in resps]
    assert order.index("/api/orders") < order.index("/slow?ms=2500"), (
        f"the responses came back in request order ({order}), so nothing here "
        "was measured: the two exchanges never actually overlapped. Raise the "
        "/slow delay or check that the proxy is not serialising connections.")
    slow_id, fast_id = (probe.request_for("/slow?ms=2500")["id"],
                        probe.request_for("/api/orders")["id"])
    assert int(slow_id) < int(fast_id), (slow_id, fast_id)


def test_q3_drop_means_the_target_receives_nothing(probe):
    """Q3. The whole enforcement claim for this egress point.

    The target server is LISTENING throughout. A drop that merely fails to
    forward is indistinguishable from a connection error unless something on
    the far side can say it saw nothing -- which is why this asserts on the
    target's own log rather than on what the client got back.

    Measured answer: YES for egress, and the client-side half is a TRAP. Burp
    sends the dropping client `HTTP/1.1 200 OK` with its own HTML error page,
    so a dropped request is indistinguishable from a delivered one by status
    code alone. Nothing may ever read the client's status as evidence that a
    request was blocked.

    Three claims, and the third is about the DOCUMENT rather than about Burp.
    Egress is what the target's log settles. The status and byte count are what
    the client got. And `docs/burp-proxy-measurements.md` must still record
    both -- because that document, not this file, is what Task 5's implementer
    acts from, and the whole "client is told 200 OK" section could be deleted
    with every test here still green. Reading the two numbers back is the same
    mechanism Q1 uses for the accessor table, chosen over asserting them here
    alone for that reason: an assertion in this file keeps the FACT true, and
    only the readback keeps the DELIVERABLE true.
    """
    before = len(probe.target.hits)
    raw = probe.raw_through_proxy("/drop/secret")
    time.sleep(0.5)
    assert len(probe.target.hits) == before, (
        f"drop() did not prevent egress: the target received "
        f"{probe.target.hits[before:]}")
    assert any(line.startswith("DROPPED ") for line in probe.lines()), \
        "the handler never reached its drop branch; the test proved nothing"

    head = raw.split(b"\r\n", 1)[0]
    assert head.startswith(b"HTTP/"), (
        f"a dropped request no longer draws an HTTP response at all: {raw[:120]!r}")
    status = int(head.split()[1])
    assert (status, len(raw)) == (DROPPED_STATUS, DROPPED_BYTES), (
        f"a dropped request now draws {status} in {len(raw)} bytes from Burp, "
        f"not the measured {DROPPED_STATUS} in {DROPPED_BYTES}. If the status "
        "changed to something a client can tell apart from a delivery, that is a "
        "BETTER answer than the measured one and Plan 4 gets easier -- but it is "
        "a new measurement either way. Update DROPPED_STATUS/DROPPED_BYTES and "
        "docs/burp-proxy-measurements.md together. First line: "
        f"{head!r}")

    recorded = RECORD.read_text()
    assert any(str(DROPPED_BYTES) in line and str(DROPPED_STATUS) in line
               for line in recorded.splitlines()), (
        f"no single line of {RECORD.name} records that a dropped request draws "
        f"a {DROPPED_STATUS} of {DROPPED_BYTES} bytes. That is the most "
        "consequential finding in this task -- it is why a drop cannot be "
        "detected by status code -- and the document is what Task 5 is built "
        "from. Do not delete it from there to satisfy this assertion.")
    assert "indistinguishable" in recorded, (
        f"{RECORD.name} no longer says a dropped request is INDISTINGUISHABLE "
        "from a delivered one. The two numbers above can survive in a document "
        "that has stopped saying what they mean; this is the sentence that says "
        "it, and Task 5 reads the document rather than this test.")
```

- [ ] **Step 4: Add the probe launcher to the fixture**

```python
# tests/integration/burp_fixture.py -- probe launch and listener discovery
def launch_probe(workdir: Path, out: Path,
                 extra_listener_port: int = 0) -> subprocess.Popen:
    """Burp running hx.proxy.Probe, with a SECOND proxy listener.

    The second listener is the whole point of Q1: one Burp, two ports, and the
    question is whether the extension can tell which one a request came in on.
    `extra_listener_port=0` means the caller does not care which port it gets;
    read the real ones back with proxy_port() and second_proxy_port().

    Burp Community has no API for creating a listener -- `burp.api.montoya.
    proxy.Proxy` offers registerRequestHandler, registerResponseHandler,
    registerWebSocketCreationHandler, history and intercept, and nothing that
    opens a port. So the second listener comes from a PROJECT CONFIG FILE via
    `--config-file`, which Community does accept. Both listeners are written
    explicitly, including the first: a config that named only the second would
    leave the first wherever Burp's defaults put it, which is the 8080 that
    _free_port() exists to avoid.

    `loopback_only` is not decoration. Nothing in this project has ever sent a
    request off this machine, and a proxy listener on 0.0.0.0 is an open relay
    on whatever network the laptop is attached to. It is also not self-
    enforcing: this string was the whole of the protection until
    not_loopback_only() was written, and changing it to `all_interfaces` left
    the suite green with the proxy bound to `*`. Callers must run that check
    once the listeners are up -- test_proxy_facts.py's fixture does.
    """
    # seed=SEED_HOME for the same reason bf.launch_burp passes it: make_home's
    # default is the operator's own home, and this is the one missing() checked.
    home = make_home(workdir, seed=SEED_HOME)
    classes = _compile_probe(workdir)
    write_listener_config(workdir, extra_listener_port)
    log = (workdir / "burp.log").open("wb")
    cmd = [
        "java", "-Djava.awt.headless=true", f"-Duser.home={home}",
        f"-Dhx.probe.out={out}",
        # The probe's classes in place of the shipped extension jar. Burp
        # loads exactly the one class named below, so EXT_JAR on the classpath
        # would not load HxExtension -- it is left off because the probe does
        # not need it, and because a jar on the path of a measurement run is a
        # thing a later reader has to rule out.
        *ADD_OPENS, "-cp", f"{BURP_JAR}:{classes}",
        "burp.StartBurp",
        f"--developer-extension-class-name={PROBE_CLASS}",
        f"--config-file={workdir / PROXY_CONFIG}",
        "--disable-auto-update",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, cwd=LAB)
    proc.stdin.write(b"\n\n")
    proc.stdin.flush()
    return proc
```

- [ ] **Step 5: Write the three measurement tests**

```python
# tests/integration/test_proxy_facts.py -- the three questions
def test_q1_whether_a_request_names_the_listener_it_arrived_on(probe):
    """Q1. Plan 4's operator/crawler split rests on this answer.

    Measured answer: YES. `listenerInterface()` returns `host:port` for the
    listener the request arrived on -- `127.0.0.1:42969` -- and two listeners in
    one Burp produce two different values for the same request. So the split can
    be a property of the CONNECTION, which is what spec s4 requires, and no
    second BridgeClient is needed.

    The two halves below are different claims and both are needed. The
    classification pins WHICH accessors Burp offers, so a future version that
    adds, removes or breaks one goes red here rather than in Task 5. The
    distinctness check pins that the value actually DISCRIMINATES: an accessor
    that existed and returned the same string for every listener would satisfy
    the first half completely and answer Q1 no.
    """
    assert probe.through_proxy("/api/orders") == 200
    assert probe.through_proxy("/account/logout", port=probe.second_port) == 200

    observed = {name: classify(probe.requests()[0][name]) for name in ACCESSORS}
    assert observed == MEASURED, (
        f"the accessors InterceptedRequest offers have changed: {observed} is "
        f"not the measured {MEASURED}. This is not necessarily a defect -- it is "
        "a new measurement. Update MEASURED and docs/burp-proxy-measurements.md "
        "together, and re-read Task 5's source attribution against the new set.")

    recorded = RECORD.read_text()
    for name, verdict in MEASURED.items():
        assert any(name in line and verdict in line
                   for line in recorded.splitlines()), (
            f"{name} is {verdict} on InterceptedRequest and no single line of "
            f"{RECORD.name} says so -- record what Burp offers before designing "
            "around what it does not")

    primary = probe.request_for("/api/orders")["listenerInterface"]
    second = probe.request_for("/account/logout")["listenerInterface"]
    assert primary != second, (
        f"both listeners report listenerInterface={primary!r}, so the accessor "
        "exists but tells the two apart from nothing. Q1's answer is NO and "
        "Task 5 needs the second-BridgeClient fallback.")
    assert primary.endswith(f":{probe.proxy_port}"), (primary, probe.proxy_port)
    assert second.endswith(f":{probe.second_port}"), (second, probe.second_port)


def test_q2_message_id_correlates_a_response_to_its_request(probe):
    """Q2. Capture pairs the two halves of an exchange by this id.

    Sequential requests would prove almost nothing: ids that merely count up
    match by accident when nothing overlaps. So two requests are put in flight
    at once against a target that answers the first one LAST, and the test
    requires the responses to arrive in the other order before it believes the
    pairing means anything.

    Measured answer: YES. Ids are assigned in request order and the response
    carries the id of ITS request, not of the exchange that finished first.
    """
    done: dict[str, int | None] = {}

    def go(name, path):
        done[name] = probe.through_proxy(path)

    slow = threading.Thread(target=go, args=("slow", "/slow?ms=2500"))
    fast = threading.Thread(target=go, args=("fast", "/api/orders"))
    slow.start()
```

- [ ] **Step 6: Run the measurements**

Run: `.venv/bin/pytest tests/integration/test_proxy_facts.py -v -m integration`
Expected: `test_q1` FAILS first, naming the accessors Burp offers. That failure IS the measurement — it tells you what to write down.

- [ ] **Step 7: Record what was measured**

Create `docs/burp-proxy-measurements.md` with a section per question: the exact accessor names available on `InterceptedRequest`, whether `messageId()` correlated, whether the target received anything on a drop, and the Burp version measured. Then re-run Step 6; `test_q1` passes once the record matches.

- [ ] **Step 8: Delete the probe**

```bash
rm extension/src/hx/proxy/Probe.java
./extension/build.sh
```

The probe is throwaway by construction: it registers a second `registerRequestHandler`, and Task 7's structural test asserts there is exactly one. Leaving it in place would make that test fail — which is the correct outcome, and the reason to delete it now rather than discover it later.

- [ ] **Step 9: Commit**

```bash
git add docs/burp-proxy-measurements.md tests/integration/test_proxy_facts.py \
        tests/integration/burp_fixture.py
git commit -m "measure: what Burp's proxy does, before anything is built on it"
```

---

### Task 2: The normaliser

`/order/1`, `/order/2` … `/order/9999` are one attack surface, not nine thousand. §5 says so directly: *"Identity is the TEMPLATE, not the concrete URL."* This task is the pure function that decides which.

It has no database, no bridge and no Burp, which makes it the one component in this plan that can be tested exhaustively — so it is tested exhaustively.

**The two failure directions are not symmetric and both matter.** Over-templating merges distinct endpoints, and a merged surface is one the checks visit once and report on as though they had covered both. Under-templating explodes the count, and a surface table with 9,999 rows for one endpoint makes every coverage number meaningless. Neither is recoverable after the fact, because `normaliser_version` records which rules produced a row but cannot re-derive what the URL was.

**Files:**
- Create: `src/hx/surface.py`
- Test: `tests/test_surface.py`

**Interfaces:**
- Consumes: `hx.config.Config` — fields `preserve_segments: list[str]` (default `["api", "v1", "v2", "v3"]`) and `slug_threshold: int` (default `12`)
- Produces:
  - `NORMALISER_VERSION: int`
  - `path_template(path: str, *, preserve: frozenset[str], slug_threshold: int) -> str`
  - `query_key_set(query: str) -> str`
  - `kind_for(method: str) -> str` — returns `"idempotent_read"` | `"state_changing"` | `"unknown"`
  - `normalise(method: str, url: str, *, preserve: frozenset[str], slug_threshold: int) -> Normalised` where `Normalised` is a frozen dataclass with `method, scheme, host, port, path_template, query_key_set, kind, normaliser_version`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_surface.py
"""The normaliser, exhaustively.

Every test here separates one rule from its absence. That is not a style
preference on this project: on the previous branch, rule 3 -- a guard is only
tested by the input that separates it from its absence -- fired on all eight
tasks without exception, and the normaliser is the component where a missing
separation is least visible, because a wrong template still LOOKS like a
template.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from hx import surface

PRESERVE = frozenset({"api", "v1", "v2", "v3"})
KW = {"preserve": PRESERVE, "slug_threshold": 12}

POLICY_JAVA = Path(__file__).resolve().parents[1] / "extension/src/hx/policy/Policy.java"


def t(path: str) -> str:
    return surface.path_template(path, **KW)


class TestNumericSegments:
    def test_a_numeric_segment_becomes_a_placeholder(self):
        assert t("/order/1") == "/order/{id}"

    def test_and_every_numeric_segment_collapses_to_the_same_template(self):
        assert t("/order/1") == t("/order/9999") == t("/order/0")

    def test_a_word_segment_is_kept_verbatim(self):
        """The separating case: without this, everything templates to {id}."""
        assert t("/order/status") == "/order/status"

    def test_several_numeric_segments_each_template(self):
        assert t("/user/12/order/34") == "/user/{id}/order/{id}"


class TestPlaceholderSyntaxCannotBeForged:
    r"""A segment kept verbatim must not be able to spell a template.

    `{` and `}` are the placeholder syntax, and until NORMALISER_VERSION 2 a
    literal one was emitted unchanged: `/order/1`, `/order/{id}` and
    `/order/%7Bid%7D` all produced `/order/{id}`. Same `path_template` means
    the same row under `UNIQUE (engagement_id, method, scheme, host, port,
    path_template, query_key_set)`, so an un-interpolated `href="/order/{id}"`
    on a page -- or anyone sending `GET /order/%7Bid%7D` through the proxy --
    upserts onto the real `/order/N` row and moves its `last_seen_run` onto a
    request that never touched the endpoint. Seen FIRST, the forgery is that
    row's `exemplar_exchange_id` for good: Task 4's planned `DO UPDATE SET`
    touches only `last_seen_run`, so the exemplar is whatever inserted it.

    `Policy` does not stop it: `checkHostChars` is host-only, there is no path
    charset, and `{` decodes fully, so the request is allowed.
    """

    def test_a_literal_placeholder_segment_is_escaped_not_emitted(self):
        assert t("/order/{id}") == "/order/%7Bid%7D"

    def test_so_it_cannot_share_a_row_with_the_template_it_spells(self):
        """THE SEPARATING CASE. Both sides were `/order/{id}` before."""
        assert t("/order/1") == "/order/{id}"
        assert t("/order/{id}") != t("/order/1")

    def test_and_neither_can_its_encoded_spelling(self):
        """`%7Bid%7D` decodes to `{id}`, so escaping only the literal would
        leave the same forgery one percent-escape away."""
        assert t("/order/%7Bid%7D") == "/order/%7Bid%7D"
        assert t("/order/%7buuid%7d") == "/order/%7Buuid%7D"
        assert t("/order/%7buuid%7d") != t("/session/3f2504e0-4f89-11d3-9a0c-0305e82c3301")

    def test_a_segment_with_no_braces_is_untouched_by_the_escaping(self):
        """Separates the escaping from 'mangle every kept segment'."""
        assert t("/order/status") == "/order/status"


class TestPreservedSegments:
    r"""The preserve list, and the fact that the DEFAULT list does nothing.

    Deleting the preserve rule entirely reddens nothing that the SHIPPED
    defaults reach, and the reason is not a missing test -- it is that none of
    `api`, `v1`, `v2`, `v3` is matched by any shape rule anyway. `_DIGITS` is
    `\A[0-9]+\Z`, so `v1` never matched it; there is nothing for the list to
    protect them from. `v1`, `v2` and `v3` become reachable only below
    `slug_threshold` 3, which templates `/h2`, `/v9` and nearly every short
    digit-bearing segment -- a configuration that is legal and that nobody
    runs -- and `api` never becomes reachable at all, having no digit.
    `config.py` says so where an operator will read it.

    Three claims in the first version of this class asserted otherwise -- that
    `v1` "is digits-adjacent and must survive, this is why the list exists",
    that `/v2` would "otherwise match a rule", and that `/v9` "separates the
    preserve list" (it separates the digits rule). All three were false, and
    they are the reason the no-op went unnoticed: a class full of confident
    comments about a rule that was doing nothing.

    The rule is kept because it IS reachable under legal configurations, and
    the last two tests here are what separate it from its absence.
    """

    def test_a_preserved_segment_survives_alongside_templated_ones(self):
        """Not because the list protects it -- nothing threatens `v1` under the
        defaults -- but because the digits rule must not reach across it."""
        assert t("/api/v1/order/7") == "/api/v1/order/{id}"

    def test_a_default_preserved_segment_alone_is_unchanged(self):
        assert t("/v2") == "/v2"

    def test_a_segment_not_on_the_list_is_templated_by_the_digits_rule(self):
        """`/v9` is not on the list, but that is not what templates `7`."""
        assert t("/v9/order/7") == "/v9/order/{id}"

    def test_the_default_entries_are_protected_from_nothing(self):
        """The claim above, executable: with the list EMPTY and the shipped
        threshold, every default entry templates to itself anyway."""
        bare = {"preserve": frozenset(), "slug_threshold": 12}
        for seg in ("api", "v1", "v2", "v3"):
            assert surface.path_template("/" + seg, **bare) == "/" + seg

    def test_the_list_is_load_bearing_under_a_config_that_needs_it(self):
        """A separating case for the rule.

        A numeric path segment that is genuinely a route -- a year, a version,
        an API generation -- is exactly what an operator puts on this list, and
        without the rule it templates to `{id}` and merges with every other
        number in that position. Measured: `/2024/report` becomes
        `/{id}/report` when the rule is deleted.
        """
        kw = {"preserve": frozenset({"2024"}), "slug_threshold": 12}
        assert surface.path_template("/2024/report", **kw) == "/2024/report"
        assert surface.path_template("/2025/report", **kw) == "/{id}/report"

    def test_and_it_is_checked_after_decoding_so_one_escape_cannot_defeat_it(self):
        """THE OTHER SEPARATING CASE, and the ordering bug of version 1.

        `/%32024/report` and `/20%324/report` are the same request to the same
        server as `/2024/report`. Matched against the RAW spelling, the
        operator's explicit "this segment is a route" was bypassed by one
        escape AND the encoded spelling merged into the numeric-id family:
        both measured `/{id}/report`.
        """
        kw = {"preserve": frozenset({"2024"}), "slug_threshold": 12}
        assert surface.path_template("/%32024/report", **kw) == "/2024/report"
        assert surface.path_template("/20%324/report", **kw) == "/2024/report"


class TestIdentifierShapes:
    def test_a_uuid_becomes_a_placeholder(self):
        assert t("/session/3f2504e0-4f89-11d3-9a0c-0305e82c3301") == "/session/{uuid}"

    def test_a_uuid_is_matched_case_insensitively(self):
        assert t("/session/3F2504E0-4F89-11D3-9A0C-0305E82C3301") == "/session/{uuid}"

    def test_a_long_hex_string_becomes_a_placeholder(self):
        assert t("/blob/" + "a" * 40) == "/blob/{hex}"

    def test_but_a_short_hex_word_is_left_alone(self):
        """`face` is valid hex and is also an English word. The separating case."""
        assert t("/theme/face") == "/theme/face"

    def test_a_long_mixed_segment_with_a_digit_is_a_slug(self):
        assert t("/post/hello-world-2026-edition") == "/post/{slug}"

    def test_but_a_long_segment_with_no_digit_is_kept(self):
        """Separates slug_threshold from 'anything long'. `/documentation`
        is a route, not an identifier."""
        assert t("/documentation-index") == "/documentation-index"

    def test_a_short_segment_with_a_digit_is_kept(self):
        """Separates the threshold from 'anything containing a digit'."""
        assert t("/h2") == "/h2"


class TestPercentEncoding:
    def test_an_encoded_digit_templates_the_same_as_a_bare_one(self):
        """Otherwise `/order/%31` and `/order/1` are two surfaces for one
        endpoint, and the checks visit it twice while the report counts two."""
        assert t("/order/%31") == t("/order/1") == "/order/{id}"

    def test_an_encoded_separator_does_not_create_a_segment(self):
        """`%2f` is a slash the SERVER may or may not split on. Templating as
        though it did would merge two different endpoints, so it does not."""
        assert t("/a%2fb") == "/a%2fb"

    def test_malformed_encoding_is_left_verbatim_rather_than_guessed(self):
        assert t("/order/%zz") == "/order/%zz"

    def test_an_escape_that_is_not_utf8_is_left_verbatim_rather_than_folded(self):
        """`unquote`'s default `errors="replace"` folds all 128 invalid
        single-byte escapes to U+FFFD, so `/order/%80` .. `/order/%FF` all
        measured `/order/�`: byte-level fuzzing through the proxy would
        record 128 requests as one surface."""
        assert t("/order/%80") == "/order/%80"
        assert t("/order/%FF") == "/order/%FF"
        assert t("/order/%80") != t("/order/%FF")

    def test_but_a_valid_utf8_escape_still_decodes(self):
        """The separating case for the line above: strictness must not turn
        into 'never decode anything non-ASCII'."""
        assert t("/caf%C3%A9") == "/café"


class TestDecodingDepth:
    """Decoding runs to a fixed point, because `Policy` decides on one.

    `Policy.decodeToFixedPoint` unwraps nested escapes until nothing changes;
    version 1 decoded once. So `/order/%2531` was `/order/1` to the scope
    decision that authorised the request and `/order/%31` to the row recording
    it -- the evidence and the authorisation naming different endpoints -- and
    it split from `/order/1` into a second row besides.
    """

    def test_a_doubly_encoded_segment_reaches_the_same_template(self):
        """Measured before: `/order/%2531` -> `/order/%31`."""
        assert t("/order/%2531") == t("/order/%31") == t("/order/1") == "/order/{id}"

    def test_the_bound_is_the_one_Policy_enforces(self):
        """The mirror cannot share code across the language boundary, so it is
        pinned by reading Policy's constant rather than by a comment."""
        java = POLICY_JAVA.read_text(encoding="utf-8")
        m = re.search(r"MAX_DECODE_ROUNDS\s*=\s*(\d+)\s*;", java)
        assert m is not None, f"Policy.MAX_DECODE_ROUNDS not found in {POLICY_JAVA}"
        assert int(m.group(1)) == surface.MAX_DECODE_ROUNDS == 16

    def test_past_the_bound_the_partial_decode_is_what_is_recorded(self):
        """Exactly `decodeToFixedPoint`'s behaviour. Policy answers this shape
        with a DENIAL (`decodesFully`), so it does not reach here through the
        gate; the two still agree about everything the gate admits."""
        at_the_bound = "%" + "25" * 15 + "31"    # 16 rounds to reach "1"
        past_it = "%" + "25" * 16 + "31"         # 17
        assert t("/order/" + at_the_bound) == "/order/{id}"
        assert t("/order/" + past_it) == "/order/%31"

    def test_an_encoded_separator_is_refused_however_deeply_it_is_nested(self):
        """`%252f` decodes to `/` too, so the refusal has to survive the extra
        rounds or the fixed point would undo it."""
        assert t("/a%252fb") == "/a%252fb"


class TestShape:
    def test_the_root_path_survives(self):
        assert t("/") == "/"

    def test_a_trailing_slash_is_significant(self):
        """`/order/` and `/order` can be different routes. Merging them is a
        guess about someone else's router."""
        assert t("/order/") == "/order/"
        assert t("/order") == "/order"

    def test_an_empty_path_normalises_to_root(self):
        assert t("") == "/"

    def test_an_empty_interior_segment_survives_as_one(self):
        """`//` is two empty segments, not one collapsed slash: no rule matches
        the empty string, so it needs no special case to come back unchanged."""
        assert t("/a//b") == "/a//b"


class TestQueryKeySet:
    def test_values_are_dropped_and_keys_kept(self):
        assert surface.query_key_set("id=1&sort=asc") == "id,sort"

    def test_key_order_does_not_matter(self):
        assert surface.query_key_set("sort=asc&id=1") == surface.query_key_set("id=1&sort=asc")

    def test_a_repeated_key_appears_once(self):
        assert surface.query_key_set("id=1&id=2") == "id"

    def test_a_valueless_key_still_counts(self):
        assert surface.query_key_set("debug") == "debug"

    def test_an_empty_query_is_empty(self):
        assert surface.query_key_set("") == ""

    def test_a_key_containing_the_delimiter_is_escaped(self):
        """THE SEPARATING CASE for the escaping. `a%2Cb=1` is ONE parameter and
        `a=1&b=2` is two; both measured `a,b`, so a check enumerating inputs
        off the row would see a different count than the exchange carried."""
        assert surface.query_key_set("a%2Cb=1") == "a%2Cb"
        assert surface.query_key_set("a=1&b=2") == "a,b"
        assert surface.query_key_set("a%2Cb=1") != surface.query_key_set("a=1&b=2")

    def test_and_the_bare_spelling_of_that_key_is_the_same_key(self):
        """`?a,b` and `?a%2Cb` are one parameter under either spelling."""
        assert surface.query_key_set("a,b") == surface.query_key_set("a%2Cb=1")

    def test_a_two_key_set_renders_as_two_fields_not_three(self):
        """Measured before: `a=1&a%2Cb=2` -> `a,a,b`."""
        assert surface.query_key_set("a=1&a%2Cb=2") == "a,a%2Cb"

    def test_an_empty_key_is_distinguishable_from_no_query_at_all(self):
        """`GET /x` and `GET /x?=1` are different requests; both measured
        `""`, so they merged into one row."""
        assert surface.query_key_set("=1") == "(empty)"
        assert surface.query_key_set("=1") != surface.query_key_set("")

    def test_and_it_sorts_and_joins_like_any_other_key(self):
        assert surface.query_key_set("a=2&=1") == "(empty),a"

    def test_a_key_cannot_forge_the_empty_key_token(self):
        """`(` and `)` are outside what `quote(safe="")` emits, which is what
        makes `(empty)` unforgeable rather than merely unlikely."""
        assert surface.query_key_set("(empty)=1") == "%28empty%29"
        assert surface.query_key_set("(empty)=1") != surface.query_key_set("=1")


class TestKind:
    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    def test_safe_methods_are_idempotent_reads(self, method):
        assert surface.kind_for(method) == "idempotent_read"

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_the_rest_change_state(self, method):
        assert surface.kind_for(method) == "state_changing"

    def test_an_unrecognised_method_is_unknown_not_safe(self):
        """Fail-closed: an unknown verb is not assumed harmless."""
        assert surface.kind_for("PROPFIND") == "unknown"

    def test_method_matching_is_case_sensitive(self):
        """RFC 9110 s9.1: methods are case-sensitive. `get` is not GET, and
        treating it as one would let a lowercase verb inherit a safe kind."""
        assert surface.kind_for("get") == "unknown"


class TestNormalise:
    def test_it_pulls_a_url_apart_and_templates_the_path(self):
        n = surface.normalise("GET", "https://app.test:8443/order/7?id=1", **KW)
        assert (n.scheme, n.host, n.port) == ("https", "app.test", 8443)
        assert n.path_template == "/order/{id}"
        assert n.query_key_set == "id"
        assert n.kind == "idempotent_read"
        assert n.normaliser_version == surface.NORMALISER_VERSION

    def test_the_default_port_is_filled_in_from_the_scheme(self):
        assert surface.normalise("GET", "https://app.test/x", **KW).port == 443
        assert surface.normalise("GET", "http://app.test/x", **KW).port == 80

    def test_a_scheme_with_no_default_port_records_zero(self):
        """The fallback arm of `_DEFAULT_PORT.get`, which nothing reached: it
        could be any number at all and every test still passed."""
        assert surface.normalise("GET", "ftp://app.test/x", **KW).port == 0

    def test_an_explicit_port_zero_is_recorded_rather_than_replaced(self):
        """`parts.port or ...` made this 80 -- a row naming an endpoint nobody
        addressed. `port` is a UNIQUE-key field, so it is the row's identity."""
        assert surface.normalise("GET", "http://app.test:0/x", **KW).port == 0

    def test_the_host_is_lowercased_and_the_path_is_not(self):
        """Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not.
        Lowercasing a path would merge /Admin and /admin, which on some
        servers are two different places. The fold itself is `urlsplit`'s --
        this pins the output contract, not an implementation here."""
        n = surface.normalise("GET", "http://APP.Test/Admin", **KW)
        assert n.host == "app.test"
        assert n.path_template == "/Admin"

    def test_the_host_fold_is_urlsplit_s_and_stops_at_a_zone_id(self):
        """`hostname` lowercases up to the first `%` and leaves the rest,
        which it reads as an IPv6 zone id. A second `.lower()` here used to
        fold that tail too -- the only inputs it changed, and `Policy` refuses
        both (`checkHostChars` allows neither `%` nor a bracket). Recorded as
        `urlsplit` reports it rather than folded a second time."""
        n = surface.normalise("GET", "http://[fe80::1%tESt]/x", **KW)
        assert n.host == "fe80::1%tESt"

    def test_a_url_with_no_authority_has_an_empty_host_not_None(self):
        """`parts.hostname` is None for a relative url, and `host` feeds a NOT
        NULL column. The `or ""` is the only thing between the two."""
        assert surface.normalise("GET", "/order/1", **KW).host == ""

    @pytest.mark.parametrize("url", ["http://app.test:99999/x",
                                     "http://app.test:abc/x",
                                     "http://[fe80::/x"])
    def test_normalise_is_not_total_and_says_so(self, url):
        """A url this cannot parse is one the gate has already refused --
        `Policy.checkScope` turns exactly these into `scope_denied` -- so
        swallowing the error would record a surface for a request that had no
        authority behind it. A caller arriving by another route (`via='send'`,
        `via='crawl'`) owes the exception a handler."""
        with pytest.raises(ValueError):
            surface.normalise("GET", url, **KW)


def test_the_version_is_pinned_to_the_ruleset_in_this_file():
    """A rule change without a version bump silently reinterprets history:
    old rows claim a template the current rules would never produce.

    Pinned to the EXACT value. `>= 1` was the assertion here while the rules
    changed underneath it, which left the one field whose whole purpose is
    saying which ruleset produced a row unpinned by anything.
    """
    assert surface.NORMALISER_VERSION == 2


# --- the placeholder vocabulary, pinned in both directions -----------------
#
# `surface.PLACEHOLDERS` is read by `hx.checks.active.path_traversal` (can my
# name filter ever match one?) and, through it, by the Limits section of a
# client deliverable. A constant that drifted from what `_template_segment`
# actually mints would make that disclosure say something about a vocabulary
# the normaliser no longer has.


def _template(path):
    return surface.path_template(path, preserve=frozenset(),
                                 slug_threshold=12)


def test_every_placeholder_in_the_vocabulary_is_one_the_normaliser_mints():
    """Each entry, reached by a real path. An entry nothing can produce is a
    claim no input separates from its absence."""
    produced = {
        _template("/a/12345").rsplit("/", 1)[-1],
        _template("/a/3f2504e0-4f89-11d3-9a0c-0305e82c3301").rsplit("/", 1)[-1],
        _template("/a/" + "deadbeefcafe1234" * 2).rsplit("/", 1)[-1],
        _template("/a/hello-world-2026-edition").rsplit("/", 1)[-1],
    }
    assert produced == set(surface.PLACEHOLDERS)


def test_a_segment_the_normaliser_keeps_is_never_one_of_them():
    """The other direction: `_kept_segment` escapes a literal brace, so no
    captured segment can forge a placeholder and the tuple stays exhaustive
    of what a template can contain."""
    for path in ("/a/documentation-index", "/a/{id}", "/a/orders", "/a/v2"):
        segment = _template(path).rsplit("/", 1)[-1]
        assert segment not in surface.PLACEHOLDERS, path
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_surface.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.surface'`

- [ ] **Step 3: Write the normaliser**

```python
# src/hx/surface.py
"""URL to attack surface: the template, not the concrete address.

S5: "Identity is the TEMPLATE, not the concrete URL. /order/1..9999 is one
surface." Everything here serves that sentence.

The two failure directions are not symmetric, and neither is recoverable.
Over-templating MERGES distinct endpoints, and a merged surface is one the
checks visit once and the report covers as though it had visited both.
Under-templating EXPLODES the count, and a surface table with 9,999 rows for
one endpoint makes every coverage number meaningless. `normaliser_version`
records which rules produced a row, but it cannot re-derive the URL, so a
wrong rule is a permanent hole in the evidence rather than a re-runnable step.

So the rules below are deliberately conservative: a segment is templated only
when its SHAPE says identifier, never merely because it is unfamiliar.

WHERE THIS DIVERGES FROM `Policy` (extension/src/hx/policy/Policy.java), the
gate that decided the request was allowed at all. A difference between them is
a difference between what was AUTHORISED and what is RECORDED, so each one is
named here rather than left to be found in a report:

  - PATH CASE IS KEPT. Policy folds case before matching; merging `/Admin`
    with `/admin` would be a guess about someone else's router.
  - `%2f` DOES NOT SPLIT A SEGMENT. Policy reads a path several ways at once
    and one of them splits; a surface row is a single string and has to pick,
    and picking "the server split on it" merges two endpoints.
  - DECODING DEPTH IS MIRRORED -- see `_decode_segment`. This is the one that
    was a divergence and is now deliberately not one.
  - DECODING CHARSET DIFFERS. `Policy.decodeOnce` maps each escaped byte to
    one char with no transcoding; `unquote` here reads the escaped bytes as
    UTF-8 and leaves the whole segment verbatim when they are not UTF-8. The
    two agree on every ASCII escape, which is every escape a rule below can
    match on. They differ in how many CHARACTERS a non-ASCII segment has,
    which can move it across `slug_threshold`.
  - THE AUTHORITY IS RECORDED, NOT JUDGED. `Target.parse` and
    `checkHostChars` refuse userinfo, a leading or trailing dot, an empty
    label, a non-ASCII host, an IPv6 literal, an empty port and port 0.
    `normalise` refuses none of them: it says what happened, it does not
    decide whether it was allowed to. A request carrying one is `scope_denied`
    at the gate (`Policy.checkScope` turns the parse failure into a denial),
    so it reaches this module only from a caller that did not go through the
    gate.
  - HOST CASE FOLDING DIFFERS IN UNICODE'S CONDITIONAL CASES. Both sides fold
    U+212A KELVIN SIGN to `k`, so that one is not a divergence. `str.lower()`
    is Unicode's FULL mapping and `Policy.lower` is the SIMPLE one, so U+0130
    is two characters here and one there. Only a non-ASCII host can notice,
    and Policy refuses those.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote, urlsplit

# Bump this when any rule below changes. A rule change without a bump silently
# reinterprets history: rows written yesterday claim a template today's rules
# would never produce, and nothing can tell the two apart afterwards.
#
# 1 -> 2 (fix round 1): a kept segment now has `{` and `}` percent-encoded so
# it cannot spell a placeholder; `query_key_set` escapes its own delimiter and
# distinguishes an empty key from no query; `preserve` is matched AFTER
# decoding; decoding runs to a fixed point rather than once; a segment whose
# escapes are not UTF-8 is kept verbatim rather than folded to U+FFFD.
NORMALISER_VERSION = 2

# Mirrors Policy.MAX_DECODE_ROUNDS. See `_decode_segment`; a test reads the
# constant out of Policy.java so the two cannot drift apart in silence.
MAX_DECODE_ROUNDS = 16

_DIGITS = re.compile(r"\A[0-9]+\Z")
_UUID = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.I)
# 32 rather than something shorter because `deadbeef` and `face` are hex AND
# English. Below this length the false-merge risk outweighs the explosion risk.
_HEX = re.compile(r"\A[0-9a-f]{32,}\Z", re.I)
_HAS_DIGIT = re.compile(r"[0-9]")

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_DEFAULT_PORT = {"http": 80, "https": 443}

# What an empty query KEY is written as, so that `?=1` and no query at all are
# not the same row. Any other spelling of "nothing" would be a key some request
# could carry: `_encoded_key` emits only unreserved characters and `%XX`, and
# `(` is neither, so no key can forge this one.
_EMPTY_KEY = "(empty)"


@dataclass(frozen=True)
class Normalised:
    method: str
    scheme: str
    host: str
    port: int
    path_template: str
    query_key_set: str
    kind: str
    normaliser_version: int


def _decode_once(seg: str) -> str:
    """One round of percent-decoding, or the input when it cannot be read.

    `errors="strict"` and not the default `"replace"`: `unquote` folds every
    one of the 128 invalid single-byte escapes to U+FFFD, so `%80` through
    `%FF` would template to the same segment and 128 distinct requests would
    be recorded as one surface. Returning the input unchanged instead is the
    same policy this module already applies to `%zz` -- leave what it cannot
    read alone rather than invent a URL the client never sent -- and it makes
    the round a no-op, which stops the fixed-point loop below.
    """
    try:
        return unquote(seg, errors="strict")
    except UnicodeDecodeError:
        return seg


def _decode_segment(seg: str) -> str:
    """Percent-decode one segment to a fixed point, but never into a separator.

    `/order/%31` and `/order/1` are one endpoint and must template alike.

    TO A FIXED POINT, mirroring `Policy.decodeToFixedPoint`, under the same
    bound: `Policy` matches its rules against a SET of readings of the path,
    and one member of that set is the fully-decoded one, so `/order/%2531` is
    among other things `/order/1` to the gate that authorised it. Decoding
    once here would record it as `/order/%31` -- the row and the thing that
    was authorised naming different endpoints -- and would split it from
    `/order/1` besides.
    The two cannot share code across the language boundary, so the agreement
    is pinned by a test that reads Policy's constant.

    Past the bound the partially decoded string is returned, which is what
    `decodeToFixedPoint` does. Policy turns that case into a DENIAL
    (`decodesFully`), so a request that needs more than sixteen rounds does
    not reach this module through the gate.

    `/a%2fb` is NOT `/a/b`: whether the server splits on an encoded slash is
    the server's business, and assuming it does would merge two different
    endpoints into one surface. So a decode that would introduce a `/` is
    refused and the segment stays verbatim -- and it is refused however deeply
    the slash was nested, because `%252f` decodes to it too.
    """
    decoded = seg
    for _ in range(MAX_DECODE_ROUNDS):
        nxt = _decode_once(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    if "/" in decoded:
        return seg
    return decoded


def _kept_segment(seg: str) -> str:
    """A segment that survives templating, spelt so it cannot BE a template.

    `{` and `}` are this module's placeholder syntax, so a segment allowed to
    carry them literally can spell one: `/order/{id}` and `/order/%7Bid%7D`
    both template to `/order/{id}`, which is the row `/order/1` and
    `/order/9999` share. Task 4's upsert then moves that row's
    `last_seen_run` onto a request that never touched the endpoint, and if the
    forgery is the FIRST sighting it is the row's `exemplar_exchange_id` for
    good -- the exemplar is written on insert and the planned `DO UPDATE SET`
    does not touch it. A page shipping an un-interpolated `href="/order/{id}"`
    is enough.

    Escaping the braces instead of choosing a rarer delimiter is the fix,
    because a rarer delimiter is the same defect with a longer fuse. It is
    injective on a segment that REACHED its fixed point: such a segment holds
    no valid escape, so a `%7B` in the output came from a `{` and from nothing
    else. Two shapes sit outside that: a segment kept verbatim by the `/`
    refusal above, where `a{b%2fc` and `a%7Bb%2fc` both give `a%7Bb%2fc` --
    two spellings of one decoded segment, which is a merge this module makes
    everywhere else and not a merge of two endpoints -- and a segment still
    encoded past the round bound, which `Policy` answers with a denial.
    """
    return seg.replace("{", "%7B").replace("}", "%7D")


# EVERY STRING `_template_segment` CAN MINT, and nothing else in this module
# may return one that is not here. It is a vocabulary two other modules
# reason about -- `hx.insertion.is_placeholder` decides the SHAPE, which is
# a different question, and `hx.checks.active.path_traversal` asks whether
# its own name filter can ever match one of these (it cannot: none of them
# looks like a filename, so that check can never probe a templated segment,
# which `hx.report._limits` discloses). Pinned against the normaliser's real
# output by `tests/test_surface.py`, in both directions: nothing outside this
# tuple is minted, and every entry in it is reachable.
PLACEHOLDERS = ("{id}", "{uuid}", "{hex}", "{slug}")


def _template_segment(seg: str, preserve: frozenset[str],
                      slug_threshold: int) -> str:
    decoded = _decode_segment(seg)
    if decoded in preserve:
        # Checked AFTER decoding, and that ordering is the point: with
        # `preserve={"2024"}`, `/%32024/report` is the same request to the same
        # server as `/2024/report`, and matching the raw spelling let one
        # escape defeat the operator's explicit "this segment is a route" AND
        # merge the encoded spelling into the numeric-id family.
        return _kept_segment(decoded)
    if _DIGITS.match(decoded):
        return "{id}"
    if _UUID.match(decoded):
        return "{uuid}"
    if _HEX.match(decoded):
        return "{hex}"
    # A long segment carrying a digit is a slug: `hello-world-2026-edition`.
    # The digit requirement is what separates this from "anything long" --
    # `/documentation-index` is a route, not an identifier.
    if len(decoded) >= slug_threshold and _HAS_DIGIT.search(decoded):
        return "{slug}"
    return _kept_segment(decoded)


def path_template(path: str, *, preserve: frozenset[str],
                  slug_threshold: int) -> str:
    """The path with identifier-shaped segments replaced by placeholders."""
    if not path:
        return "/"
    # A trailing slash is significant: `/order/` and `/order` can be different
    # routes, and merging them is a guess about someone else's router. Split
    # keeps the empty final segment, and join puts it back. An empty segment
    # needs no special case here: `_template_segment("")` is `""` under every
    # configuration -- no shape rule matches the empty string, and the one
    # rule that can (`preserve={""}`) returns it unchanged.
    segments = path.split("/")
    out = [segments[0]]   # always "" for an absolute path
    for seg in segments[1:]:
        out.append(_template_segment(seg, preserve, slug_threshold))
    return "/".join(out)


def _encoded_key(key: str) -> str:
    """One query key, spelt so that the join below cannot be misread.

    `,` separates keys, so a key containing one has to be escaped or the field
    lies about how many inputs the request carried: `a%2Cb=1` is ONE parameter
    and `a=1&b=2` is two, and both used to render `a,b`. A parameter is an
    input and an input is where a flaw lives, so a check reading this field
    would enumerate the wrong ones. `quote(safe="")` escapes `%` as well as
    `,`, without which `a%2Cb` (the literal key) and `a,b` would collide in
    turn.
    """
    return quote(key, safe="") if key else _EMPTY_KEY


def query_key_set(query: str) -> str:
    """The comma-joined sorted set of query KEYS, values discarded.

    Two requests to the same endpoint differing only in a value are one
    surface. Two differing in which PARAMETERS they carry are not: a parameter
    is an input, and an input is where a flaw lives.

    No query at all is `""`. A query carrying the empty key -- `?=1` -- is
    `(empty)`, because `GET /x` and `GET /x?=1` are not the same request and a
    field that renders both as `""` merges them.
    """
    keys = {k for k, _ in parse_qsl(query, keep_blank_values=True)}
    return ",".join(_encoded_key(k) for k in sorted(keys))


def kind_for(method: str) -> str:
    """Idempotent read, state changing, or unknown -- and unknown is not safe.

    Case-sensitive, per RFC 9110 s9.1. `get` is not GET, and letting a
    lowercase verb inherit `idempotent_read` would hand a check permission to
    replay something the server may treat as a write.
    """
    if method in _SAFE_METHODS:
        return "idempotent_read"
    if method in _STATE_CHANGING:
        return "state_changing"
    return "unknown"


def normalise(method: str, url: str, *, preserve: frozenset[str],
              slug_threshold: int) -> Normalised:
    """One request as the surface row it belongs to.

    NOT TOTAL, and the caller owes it a url. `urlsplit` raises `ValueError` on
    an unterminated IPv6 literal (`http://[fe80::/x`), and `parts.port` raises
    on a port that is not a number or is out of range (`http://h:abc/x`,
    `http://h:99999/x`). Nothing here catches those: a url this cannot parse
    is one the enforcement gate has already refused -- `Policy.checkScope`
    turns exactly these into `scope_denied` -- so swallowing the error would
    record a surface for a request that had no authority behind it. A caller
    reaching this module by some other route (a `via='send'` or `via='crawl'`
    string that never went through `Policy.Target.parse`) must be prepared for
    the exception.
    """
    parts = urlsplit(url)
    # `urlsplit` has already lowercased the scheme, and `parts.hostname` the
    # host -- everything up to the first `%`, treating whatever follows as an
    # IPv6 zone id and deliberately leaving its case alone. A second `.lower()`
    # here was dead for every host that does not carry a `%`, which is the
    # only thing it could still change -- `[fe80::1%tESt]` and `EX%41MPLE.test`
    # are what that looks like -- and there it fought that deliberate choice.
    # `Policy` refuses a `%` and a bracket alike (`checkHostChars`), so it
    # asserted a normalisation this function does not perform, on inputs that
    # cannot reach it through the gate.
    scheme = parts.scheme
    # Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not. Lowercasing
    # a path would merge /Admin and /admin, which on some servers are two
    # different places and on others are one -- and we do not get to decide
    # which server we are talking to.
    host = parts.hostname or ""   # None for a url with no authority at all
    # `is not None` and not `or`: port 0 is falsy, and `or` recorded `http://
    # h:0/x` on port 80 -- a row naming an endpoint nobody addressed. 0 is
    # also the port an unknown scheme gets, and scheme is in the UNIQUE key,
    # so the two cannot collide.
    port = parts.port if parts.port is not None else _DEFAULT_PORT.get(scheme, 0)
    return Normalised(
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        path_template=path_template(parts.path, preserve=preserve,
                                    slug_threshold=slug_threshold),
        query_key_set=query_key_set(parts.query),
        kind=kind_for(method),
        normaliser_version=NORMALISER_VERSION,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_surface.py -q`
Expected: PASS, 30 tests.

- [ ] **Step 5: Prove each rule is load-bearing**

For each of the six rules — preserve, digits, uuid, hex, slug-threshold, slug-digit — delete it from `_template_segment`, run the suite, and record which named test goes red. A rule whose deletion changes nothing is either unreachable or untested, and both are findings. Restore by file copy, verifying the sha256; `git checkout --` restores to HEAD, not to pre-edit.

Expected: six deletions, six distinct failures.

- [ ] **Step 6: Run the full suite and commit**

```bash
.venv/bin/pytest -q
git add src/hx/surface.py tests/test_surface.py
git commit -m "feat(surface): the template, not the concrete URL"
```

Expected: `406 passed, 14 deselected` (376 + 30).

---

### Task 3: Run lifecycle

§5's `run` table has carried `heartbeat_us` and `dropped_total` since Plan 1 and nothing has ever written to either. This task makes them real.

**The rule that matters most is the one about a run nobody closed.** §5: *"an aborted run must never render as a clean one, and neither must one that merely STOPPED BEING UPDATED."* A run left `running` with a stale heartbeat is a run whose harness died — the machine slept, the process was killed. If that resolves to `completed`, a report is generated from a session that stopped halfway and nothing in the data says so.

**Files:**
- Create: `src/hx/run.py`
- Test: `tests/test_run.py`

**Interfaces:**
- Consumes: `hx.store.records.new_id(prefix)`, `hx.engagement.now_us()`, and the `run` table from `src/hx/store/schema.sql`
- Produces:
  - `IDLE_CLOSE_US: int` (15 minutes, in microseconds)
  - `open_run(conn, *, engagement_id, kind, safety_profile, now_us) -> str`
  - `current_run(conn, *, engagement_id, kind, safety_profile, now_us) -> str` — auto-opens if none is live
  - `heartbeat(conn, *, run_id, now_us) -> None`
  - `close_run(conn, *, run_id, now_us, status="completed") -> None`
  - `reap_stale(conn, *, now_us) -> list[str]` — resolves dead runs to `error`, returns their ids
  - `count_drop(conn, *, run_id, n=1) -> None`
  - `RUN_KINDS: frozenset[str]` — `{"browse", "crawl", "manual", "scan"}`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_run.py
"""Run lifecycle, and in particular the run nobody closed.

The interesting cases here are all about a run that STOPPED rather than
ended. S5 is explicit that such a run must not render as a clean one, and a
report generated from a half-finished session that claims to be complete is
the worst output this project could produce.
"""
from __future__ import annotations

import pytest

from hx import run as run_mod
from hx.store import db as db_mod

ENG = "e-test"
HOUR = 3_600_000_000


@pytest.fixture
def conn(tmp_path):
    c = db_mod.connect(tmp_path / "hx.db")
    db_mod.init_schema(c)
    c.execute("INSERT INTO engagement(id, name, client, created_us, status)"
              " VALUES(?,'T','T',1,'active')", (ENG,))
    yield c
    c.close()


def _status(conn, run_id: str) -> str:
    return conn.execute("SELECT status FROM run WHERE id=?", (run_id,)).fetchone()[0]


class TestOpening:
    def test_a_run_opens_running(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        assert _status(conn, rid) == "running"

    def test_and_its_heartbeat_starts_at_the_open_time(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        assert conn.execute("SELECT heartbeat_us FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 1000

    def test_an_unknown_kind_is_refused(self, conn):
        """The vocabulary is S5's and it is closed. A typo'd kind that reached
        the table would be invisible to every query that filters on it."""
        with pytest.raises(ValueError, match="kind"):
            run_mod.open_run(conn, engagement_id=ENG, kind="brwose",
                             safety_profile="production", now_us=1000)


class TestAutoOpen:
    def test_current_run_opens_one_when_there_is_none(self, conn):
        rid = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                  safety_profile="production", now_us=1000)
        assert _status(conn, rid) == "running"

    def test_and_returns_the_same_one_while_it_is_live(self, conn):
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=2000)
        assert a == b

    def test_but_a_second_kind_gets_its_own_run(self, conn):
        """A crawl running while you browse is two runs, not one. Merging them
        would attribute crawler traffic to a human and vice versa, and the
        enforcement rules differ by exactly that distinction."""
        browse = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                     safety_profile="production", now_us=1000)
        crawl = run_mod.current_run(conn, engagement_id=ENG, kind="crawl",
                                    safety_profile="production", now_us=1000)
        assert browse != crawl

    def test_an_idle_run_is_closed_and_a_fresh_one_opened(self, conn):
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production",
                                now_us=1000 + run_mod.IDLE_CLOSE_US + 1)
        assert b != a
        assert _status(conn, a) == "completed"

    def test_exactly_at_the_window_the_run_is_still_live(self, conn):
        """THE separating input, and the only one for `<=` versus `<`.

        Measured before this test existed: changing `<=` to `<` reddened
        NOTHING. Both other probes sit at +/-1 and agree under either operator,
        so the boundary looked tested from both sides and was tested from
        neither. The one input that tells them apart is exactly
        IDLE_CLOSE_US."""
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production",
                                now_us=1000 + run_mod.IDLE_CLOSE_US)
        assert b == a

    def test_a_closed_run_is_not_handed_back_as_the_current_one(self, conn):
        """Found by Task 3's mutation sweep, not by the brief: dropping
        `status='running'` from `current_run`'s lookup reddened NOTHING.

        Every close in the file as written happened inside `current_run` itself,
        so no test ever asked what `current_run` does when a run was closed
        deliberately and the idle window has not yet expired. Without the filter
        it hands the CLOSED run straight back, and every exchange recorded
        afterwards lands on a run whose `ended_us` is already in the past.
        """
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        run_mod.close_run(conn, run_id=a, now_us=2000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=3000)
        assert b != a
        assert _status(conn, a) == "completed"

    def test_one_microsecond_inside_the_window_is_still_the_same_run(self, conn):
        """Inside the window, well away from the boundary."""
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production",
                                now_us=1000 + run_mod.IDLE_CLOSE_US - 1)
        assert b == a

    def test_a_run_with_no_heartbeat_at_all_is_judged_on_when_it_started(self, conn):
        """`heartbeat_us` is NULLABLE, and without a COALESCE this RAISES.

        Found in Task 9's fix round, by measurement rather than by reading:
        a rig that inserts a `run` row by hand -- `INSERT INTO run(id,
        engagement_id, kind, safety_profile, started_us, status)`, which is a
        perfectly legal insert against schema.sql's plain `INTEGER` column --
        made this function raise

            TypeError: unsupported operand type(s) for -: 'int' and 'NoneType'

        `reap_stale` already had the COALESCE and a comment explaining exactly
        this, four lines further down the same module. `current_run` did not.

        WHY IT MATTERED MORE THAN A TypeError USUALLY DOES: the raise came out
        of `hx.capture.on_exchange`, which runs on the bridge's READ THREAD,
        where `BridgeServer._capture` catches everything, files the record as a
        drop and keeps the channel -- by design, because S4 says a lost record
        changes what hx KNOWS and never what it ALLOWS. So the whole of the
        observable was an empty table while Burp went on sending.

        BOTH SIDES OF THE WINDOW, because a COALESCE that fell back to `at`
        (or to 0) would satisfy one of them and not the other: inside, the run
        is handed back; outside, it is closed `idle` and a new one opens. That
        is the same behaviour a row WITH a heartbeat gets, which is the claim.
        """
        conn.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile,"
            " started_us, status) VALUES('r-nohb',?,'browse','production',"
            "1000,'running')", (ENG,))
        assert conn.execute("SELECT heartbeat_us FROM run WHERE id='r-nohb'"
                            ).fetchone()[0] is None, \
            "this test is about a NULL heartbeat; the column now has a default"

        inside = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                     safety_profile="production",
                                     now_us=1000 + run_mod.IDLE_CLOSE_US)
        assert inside == "r-nohb"
        assert _status(conn, "r-nohb") == "running"

        outside = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                      safety_profile="production",
                                      now_us=1000 + run_mod.IDLE_CLOSE_US + 1)
        assert outside != "r-nohb"
        assert _status(conn, "r-nohb") == "completed"
        assert conn.execute("SELECT stop_reason FROM run WHERE id='r-nohb'"
                            ).fetchone()[0] == "idle"


class TestStale:
    def test_a_run_left_running_past_the_window_resolves_to_error(self, conn):
        """NOT completed. This is the whole point of the heartbeat."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        reaped = run_mod.reap_stale(conn, now_us=1000 + HOUR)
        assert reaped == [rid]
        assert _status(conn, rid) == "error"

    def test_and_says_why_rather_than_leaving_an_empty_reason(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.reap_stale(conn, now_us=1000 + HOUR)
        reason = conn.execute("SELECT stop_reason FROM run WHERE id=?",
                              (rid,)).fetchone()[0]
        assert reason and "heartbeat" in reason

    def test_a_live_run_is_not_reaped(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.heartbeat(conn, run_id=rid, now_us=1000 + HOUR)
        assert run_mod.reap_stale(conn, now_us=1000 + HOUR + 1) == []
        assert _status(conn, rid) == "running"

    def test_an_already_closed_run_is_not_reopened_as_an_error(self, conn):
        """Separates 'stale' from 'old'. A completed run from last week is not
        a crash, and reaping it would rewrite history."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.close_run(conn, run_id=rid, now_us=2000)
        assert run_mod.reap_stale(conn, now_us=1000 + HOUR) == []
        assert _status(conn, rid) == "completed"

    def test_a_reaped_run_cannot_be_closed_clean_afterwards(self, conn):
        """S5's sentence in the other direction, and the sweep found it untested.

        `close_run` guards on `status='running'`. Deleting that guard reddened
        NOTHING: every close in the file as written ran on a live run. Without
        it, a late `close_run` -- the harness coming back after the reaper has
        already filed the run as dead -- rewrites `error` to `completed`, and
        the aborted run renders as a clean one. That is the exact outcome S5
        forbids, reached from the opposite direction to the reaper.
        """
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        assert run_mod.reap_stale(conn, now_us=1000 + HOUR) == [rid]
        run_mod.close_run(conn, run_id=rid, now_us=1000 + 2 * HOUR)
        assert _status(conn, rid) == "error"

    def test_a_run_idle_but_not_yet_stale_is_left_alone(self, conn):
        """The distinction the two windows exist for, and it had no test.

        An IDLE run is one nobody used; a STALE run is one whose process is
        gone. Reaping at the idle boundary would file every ordinary pause as a
        crash, and `reap_stale`'s window was free to collapse to IDLE_CLOSE_US
        with nothing red."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        just_idle = 1000 + run_mod.IDLE_CLOSE_US + 1
        assert run_mod.reap_stale(conn, now_us=just_idle) == []
        assert _status(conn, rid) == "running"

    def test_a_run_that_never_heartbeated_is_still_reaped(self, conn):
        """`NULL < x` is NULL and WHERE treats it as false, so a bare
        comparison never reaps a run that died before its first heartbeat --
        the exact case the mechanism is for."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        conn.execute("UPDATE run SET heartbeat_us=NULL WHERE id=?", (rid,))
        assert run_mod.reap_stale(conn, now_us=1000 + HOUR) == [rid]
        assert _status(conn, rid) == "error"


class TestDrops:
    def test_a_drop_is_counted(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.count_drop(conn, run_id=rid, n=3)
        assert conn.execute("SELECT dropped_total FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 3

    def test_and_drops_accumulate_rather_than_overwrite(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.count_drop(conn, run_id=rid, n=2)
        run_mod.count_drop(conn, run_id=rid, n=5)
        assert conn.execute("SELECT dropped_total FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 7

    def test_an_accumulator_cannot_be_made_to_run_backwards(self, conn):
        """The floor S5 spends this column on, and it was not a floor.

        `n` arrives off a wire frame -- `int(header["n"])` in `hx.capture` --
        and a negative one MEASURED `dropped_total = -5`. Two drop reports and
        one malformed frame could then leave a run whose coverage was
        incomplete reading as one with no gaps at all, which is the single
        direction this column exists to prevent. `n=0` goes with it: a drop
        report of nothing is not a drop report.
        """
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.count_drop(conn, run_id=rid, n=4)
        for bad in (-5, 0):
            with pytest.raises(ValueError, match="floor"):
                run_mod.count_drop(conn, run_id=rid, n=bad)
        assert conn.execute("SELECT dropped_total FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 4

    def test_a_fresh_run_has_no_drops_rather_than_null(self, conn):
        """NULL would make `dropped_total > 0` quietly false for every run,
        which is the reading a report would take as 'no gaps'."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        assert conn.execute("SELECT dropped_total FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_run.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.run'`

- [ ] **Step 3: Write the module**

```python
# src/hx/run.py
"""Run lifecycle: opening, keeping alive, closing, and reaping the dead.

S5 gives the `run` table `heartbeat_us` and `dropped_total`, and until this
module nothing wrote to either.

The rule worth stating out loud is the one about a run nobody closed. A run
left `running` with a stale heartbeat is a run whose harness DIED -- the
machine slept, the process was killed, the terminal closed. It resolves to
`error`, never to `completed`, because a report generated from a session that
stopped halfway and claims to be complete is the worst output this project
could produce. S5: "an aborted run must never render as a clean one, and
neither must one that merely STOPPED BEING UPDATED."
"""
from __future__ import annotations

import sqlite3

from hx.engagement import now_us as _now_us
from hx.store.records import new_id

# 15 minutes. Long enough that a coffee break does not split a browsing
# session into two runs; short enough that a crash is noticed the same
# afternoon rather than at report time.
IDLE_CLOSE_US = 15 * 60 * 1_000_000

# S5's vocabulary, and it is closed. A typo'd kind reaching the table would be
# invisible to every query that filters on one.
RUN_KINDS = frozenset({"browse", "crawl", "manual", "scan"})

# The identity design's section 6 vocabulary, and it is closed for the reason
# `RUN_KINDS` is: `run.identity_state` and `exchange.identity_state` both
# carry it as a CHECK constraint, and `hx.scan._retirable` gates a client-
# facing retirement on one of the three by name. A fourth spelling reaching
# the column would be refused by SQLite with a message naming neither the
# value nor the alternatives.
IDENTITY_STATES = frozenset({"proven", "assumed", "dead"})


def open_run(conn: sqlite3.Connection, *, engagement_id: str, kind: str,
             safety_profile: str, now_us: int | None = None) -> str:
    if kind not in RUN_KINDS:
        raise ValueError(f"unknown run kind {kind!r}; S5 names {sorted(RUN_KINDS)}")
    at = _now_us() if now_us is None else now_us
    run_id = new_id("r")
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, heartbeat_us, requests_issued, dropped_total)"
        " VALUES(?,?,?,?,?,'running',?,0,0)",
        (run_id, engagement_id, kind, safety_profile, at, at))
    return run_id


def heartbeat(conn: sqlite3.Connection, *, run_id: str,
              now_us: int | None = None) -> None:
    at = _now_us() if now_us is None else now_us
    conn.execute("UPDATE run SET heartbeat_us=? WHERE id=? AND status='running'",
                 (at, run_id))


def close_run(conn: sqlite3.Connection, *, run_id: str,
              now_us: int | None = None, status: str = "completed",
              stop_reason: str | None = None) -> None:
    at = _now_us() if now_us is None else now_us
    conn.execute(
        # Plain assignment, not COALESCE(?, stop_reason). The preserve form was
        # a provable no-op: this statement only touches status='running' rows,
        # and nothing writes stop_reason before a close, so there was never an
        # existing value to preserve. A no-op that looks like a rule is worse
        # than no rule -- it is the shape Task 2 spent a round on.
        "UPDATE run SET status=?, ended_us=?, stop_reason=?"
        " WHERE id=? AND status='running'",
        (status, at, stop_reason, run_id))


def record_identity(conn: sqlite3.Connection, *, run_id: str,
                    identity_id: str, generation: int, state: str) -> None:
    """Which identity a run issued under, and what its liveness settled at.

    NOT PART OF `close_run`, and the split is the same one `count_drop`
    makes. `close_run` is a lifecycle transition guarded on
    `status='running'`; this is a FACT ABOUT WHAT THE RUN DID, and it has to
    be recordable on the halt path -- where `hx.scan.run` writes it a line
    before closing the row `error` -- as readily as on the happy one. A
    version folded into `close_run` would also have to be threaded through
    `current_run`'s idle close and `reap_stale`, neither of which knows
    anything about an identity.

    THE STATE IS CHECKED HERE AS WELL AS BY THE COLUMN. `schema.sql`'s CHECK
    is the backstop and its message is SQLite's ("CHECK constraint failed"),
    which names neither the value nor the vocabulary. `hx.scan` composes this
    argument from three places -- `IdentityWindow.state_for_run()`, and two
    literals on the halt path -- and a fourth caller spelling `alive` would
    otherwise be diagnosed by a constraint rather than by a sentence.

    Deliberately no `WHERE status='running'`: a run whose identity is being
    recorded on the way out of a crash is one this statement must still
    reach, and there is no second writer for it to race.
    """
    if state not in IDENTITY_STATES:
        raise ValueError(
            f"{state!r} is not an identity state; the identity design's "
            f"section 6 names {sorted(IDENTITY_STATES)}, and `run."
            "identity_state` carries the same CHECK constraint `exchange."
            "identity_state` does")
    conn.execute(
        "UPDATE run SET identity=?, identity_generation=?, identity_state=?"
        " WHERE id=?", (identity_id, generation, state, run_id))


def open_runs(conn: sqlite3.Connection, *,
              engagement_id: str) -> list[tuple[str, str]]:
    """`(id, kind)` for every run of this engagement still `status='running'`.

    THE ONE PLACE THAT ANSWERS "WHAT IS OPEN". `dispatch.ToolContext.run_id`
    resolves an unbound context through this query rather than each of its
    callers running its own -- the tool layer's own review put it plainly:
    "do not make the tools query the store one at a time; the resolution
    belongs in one place." `run.finish`'s `kind` disambiguation and
    `run.resume`'s `open_runs` brief both read it too, so a run opened by one
    process and found by another (the CLI's `hx tool` is a fresh process per
    invocation) see the same list.

    Ordered by `started_us` so a caller that wants "the" open run when there
    is exactly one gets it without sorting, and a caller listing all of them
    lists them in the order they were opened.
    """
    return conn.execute(
        "SELECT id, kind FROM run WHERE engagement_id=? AND status='running'"
        " ORDER BY started_us", (engagement_id,)).fetchall()


def current_run(conn: sqlite3.Connection, *, engagement_id: str, kind: str,
                safety_profile: str, now_us: int | None = None) -> str:
    """The live run of this kind, opening one if there is none.

    Auto-open exists to avoid one specific afternoon: browsing an application
    for an hour and then discovering nothing was recorded because a command
    was forgotten. `hx capture start` will open a deliberately named run when
    Task 8 adds it -- the CLI registers only `new` and `info` today -- and this
    is the fallback rather than the only path.

    A run of a DIFFERENT kind does not satisfy this call. A crawl running
    while you browse is two runs, because the enforcement rules differ by
    exactly that distinction and attributing crawler traffic to a human would
    make the denial rows lie about who was driving.
    """
    at = _now_us() if now_us is None else now_us
    row = conn.execute(
        # COALESCE, exactly as `reap_stale` does below and for the same
        # reason: `heartbeat_us` is NULLABLE (schema.sql declares it plain
        # `INTEGER`, no DEFAULT), and `at - NULL` is not a comparison in
        # Python -- it is `TypeError: unsupported operand type(s) for -: 'int'
        # and 'NoneType'`, raised on whichever thread happened to call this.
        #
        # FOUND BY MEASUREMENT, in Task 9's fix round, from a rig that inserts
        # a `run` row by hand without the column. That raised out of
        # `hx.capture.on_exchange`, which runs on the bridge's READ THREAD,
        # where `BridgeServer._capture` catches it, files the record as a drop
        # and keeps the channel -- so the whole of the symptom was an empty
        # table. `reap_stale` had this COALESCE and a comment explaining it;
        # this function, four lines up in the same module, did not.
        #
        # `started_us` is the fallback and it is NOT NULL, so a run that never
        # heartbeated is judged on when it started -- which is the honest
        # reading: nothing has reported on it since it opened.
        "SELECT id, COALESCE(heartbeat_us, started_us) FROM run"
        " WHERE engagement_id=? AND kind=? AND status='running'"
        " ORDER BY started_us DESC LIMIT 1",
        (engagement_id, kind)).fetchone()
    if row is not None:
        # Strictly greater: at exactly the window the run is still live. The
        # boundary is tested from both sides because a test that only probes
        # the far side passes on an off-by-one.
        if at - row[1] <= IDLE_CLOSE_US:
            return row[0]
        close_run(conn, run_id=row[0], now_us=row[1], status="completed",
                  stop_reason="idle")
    return open_run(conn, engagement_id=engagement_id, kind=kind,
                    safety_profile=safety_profile, now_us=at)


def stale_before_us(*, now_us: int | None = None,
                    stale_after_us: int | None = None) -> int:
    """The heartbeat a `running` run must be newer than to count as alive.

    Deliberately a WIDER window than IDLE_CLOSE_US: an idle run is one nobody
    used, and a stale one is a run whose process is gone. Reaping at the idle
    boundary would file every ordinary pause as a crash.
    """
    at = _now_us() if now_us is None else now_us
    window = IDLE_CLOSE_US * 2 if stale_after_us is None else stale_after_us
    return at - window


def is_stale(status: str, heartbeat_us: int | None, started_us: int,
             *, before_us: int) -> bool:
    """Whether one run row is a run whose harness died.

    ONE DEFINITION, because there are now two callers and they must not be
    free to disagree. `reap_stale` below resolves such a run to `error` in
    the store; the web app's overview screen RENDERS it as `error` without
    writing anything, since its connections are read-only. A screen that
    showed `running` for a run the reaper would kill is the first thing an
    operator sees after a crash, and S5 is explicit: "an aborted run must
    never render as a clean one, and neither must one that merely STOPPED
    BEING UPDATED".

    The fallback to `started_us` is what `reap_stale`'s SQL spelled
    `COALESCE`, and it is load-bearing for the same reason: the column is
    NULLable, and a run that died BEFORE its first heartbeat is precisely
    what this mechanism is for. `started_us` is NOT NULL, so a run that
    started long ago and never reported is stale on its own evidence.

    `if heartbeat_us is None` AND NOT `heartbeat_us or started_us`: a
    heartbeat of 0 is a real timestamp at the epoch, and `or` would discard
    it for `started_us`. SQL's COALESCE tests for NULL, not falsiness, so
    the truthiness spelling would not have been the same rule.
    """
    if status != "running":
        return False
    last = started_us if heartbeat_us is None else heartbeat_us
    return last < before_us


def reap_stale(conn: sqlite3.Connection, *, now_us: int | None = None,
               stale_after_us: int | None = None) -> list[str]:
    """Resolve runs whose harness died to `error`. Returns their ids.

    THE PREDICATE MOVED OUT, to `is_stale` above, and the SQL got simpler
    rather than smarter: this selects every `running` run and filters in
    Python. The previous version asked SQLite
    `COALESCE(heartbeat_us, started_us) < ?`, which was correct and was also
    a SECOND copy of a rule the web app's read-only overview screen needs to
    apply without writing. Two spellings of "stale" in two languages is how
    a screen and a reaper end up disagreeing about the same run. The set
    being filtered is every run currently `running` in one engagement, which
    is nought or one in practice and never large.
    """
    at = _now_us() if now_us is None else now_us
    before = stale_before_us(now_us=at, stale_after_us=stale_after_us)
    rows = conn.execute(
        "SELECT id, heartbeat_us, started_us FROM run WHERE status='running'"
    ).fetchall()
    ids = [r[0] for r in rows if is_stale("running", r[1], r[2],
                                          before_us=before)]
    for run_id in ids:
        conn.execute(
            "UPDATE run SET status='error', ended_us=?, stop_reason=?"
            " WHERE id=? AND status='running'",
            (at, "heartbeat went stale: the harness stopped without closing "
                 "this run, so its coverage is incomplete", run_id))
    return ids


def count_drop(conn: sqlite3.Connection, *, run_id: str, n: int = 1) -> None:
    """Record exchanges the extension could not hand over.

    S5: a run with drops has coverage numbers that are a FLOOR, not a count.
    Accumulates rather than sets, because drops arrive in bursts as the queue
    fills and each burst is real.

    An accumulator only floors anything if it cannot go backwards. `n=-5`
    measured `dropped_total = -5` here, and a run's own drop reports could
    then erase the signal that its coverage is incomplete -- one malformed
    frame turning an incomplete run into a clean-looking one, which is the
    direction S5 spends this column to prevent. `n=0` is refused with it: a
    `dropped` frame reporting no drops is a frame that means nothing, and the
    caller's own `n` is malformed either way. `hx.capture` checks the same
    bound BEFORE it opens a run, so a stream of these cannot manufacture
    empty runs; this is the floor at the writer, where it also covers callers
    that do not exist yet.
    """
    if n < 1:
        raise ValueError(
            f"a drop report of {n!r} is not a drop report; dropped_total is "
            "an accumulator and S5 makes it the reason a run's coverage "
            "numbers are a floor, so it must never move backwards")
    conn.execute("UPDATE run SET dropped_total = dropped_total + ? WHERE id=?",
                 (n, run_id))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_run.py -q`
Expected: PASS, 16 tests.

- [ ] **Step 5: Prove the stale rule separates from its absence**

Change `reap_stale`'s `status='error'` to `status='completed'` and run the suite. Expected: `test_a_run_left_running_past_the_window_resolves_to_error` goes red and nothing else does. Restore by file copy and verify the sha256.

Then change `current_run`'s `<=` to `<` and confirm `test_one_microsecond_inside_the_window_is_still_the_same_run` goes red. A boundary tested from one side only is not tested.

- [ ] **Step 6: Run the full suite and commit**

```bash
.venv/bin/pytest -q
git add src/hx/run.py tests/test_run.py
git commit -m "feat(run): a run nobody closed is an error, not a clean one"
```

---

### Task 4: `via` on the rows, and the consumer that writes them

`record_exchange` hardcodes `via='send'` and its docstring says so: *"The other two values in that vocabulary belong to the proxy and the crawler, which are their own egress point."* This is that egress point. `record_denial` and `record_exchange` gain `via`, and `capture.py` becomes the first production caller either has ever had.

**Files:**
- Modify: `src/hx/store/records.py` — `record_exchange`, `record_denial`
- Create: `src/hx/capture.py`
- Test: `tests/test_capture.py`, and extend `tests/test_records.py`

**Interfaces:**
- Consumes: `hx.surface.normalise`, `hx.run.current_run`/`heartbeat`/`count_drop`, `hx.store.blobs.BlobStore.put`, `hx.store.records.record_exchange`/`record_denial`, `hx.config.Config`
- Produces:
  - `VIA_VALUES: frozenset[str]` in `records` — `{"proxy", "send", "crawl"}`
  - `record_exchange(..., via: str = "send")`, `record_denial(..., via: str = "send")`
  - `class Capture` in `hx.capture` with `on_exchange(header: dict, request: bytes, response: bytes) -> str | None`
  - `Capture.upsert_surface(normalised, *, exchange_id) -> str`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_capture.py
"""The consumer: one exchange frame in, one surface and one exchange row out.

This is where three components meet that were each tested alone, and the
previous branch's evidence is that boundaries are where the defects live --
every finding that survived eight task reviews was at a join.
"""
from __future__ import annotations

import hashlib
import socket
import sqlite3
import time
from pathlib import Path

import pytest

from hx import capture as cap_mod
from hx import config as config_mod
from hx import run as run_mod
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from hx.store import paths as paths_mod

ENG = "e-test"
REQ = (b"GET /order/7?id=1 HTTP/1.1\r\nHost: app.test\r\n"
       b"Cookie: session=[REDACTED]\r\n\r\n")
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"


@pytest.fixture
def cap_with(tmp_path):
    """Build a Capture over a config THE TEST chooses.

    `preserve_segments` and `slug_threshold` reach the normaliser through this
    call and through nothing else, so a fixture that fixes them leaves the
    threading unpinned: replacing both with constants reddened no test in the
    task's own set. A factory is what lets a test separate the operator's
    value from the default.
    """
    opened = []

    def make(**cfg_over):
        root = tmp_path / f"engagement{len(opened)}"
        paths_mod.secure_mkdir(root)
        conn = db_mod.connect(root / "hx.db")
        db_mod.init_schema(conn)
        conn.execute("INSERT INTO engagement(id, name, client, created_us,"
                     " status) VALUES(?,'T','T',1,'active')", (ENG,))
        opened.append(conn)
        cfg = config_mod.Config(name="t", client="t",
                                scope_include=["http://app.test/*"],
                                **cfg_over)
        return cap_mod.Capture(conn=conn,
                               blobs=blobs_mod.BlobStore(root / "blobs"),
                               engagement_id=ENG, config=cfg)

    yield make
    for conn in opened:
        conn.close()


@pytest.fixture
def cap(cap_with):
    return cap_with()


def _header(**over) -> dict:
    h = {"v": 1, "t": "exchange", "method": "GET",
         "url": "http://app.test/order/7?id=1", "status": 200, "ms": 12,
         "via": "proxy", "outcome": "ok", "source": "operator"}
    h.update(over)
    return h


class TestTheHappyPath:
    def test_one_frame_writes_one_exchange_row(self, cap):
        rid = cap.on_exchange(_header(), REQ, RESP)
        assert rid is not None
        row = cap.conn.execute("SELECT via, status, method FROM exchange"
                               " WHERE id=?", (rid,)).fetchone()
        assert tuple(row) == ("proxy", 200, "GET")

    def test_and_opens_a_browse_run_without_being_asked(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        kind = cap.conn.execute("SELECT kind FROM run").fetchone()[0]
        assert kind == "browse"

    def test_and_stores_both_halves_as_blobs(self, cap):
        rid = cap.on_exchange(_header(), REQ, RESP)
        req_blob, resp_blob = cap.conn.execute(
            "SELECT req_blob, resp_blob FROM exchange WHERE id=?", (rid,)).fetchone()
        assert cap.blobs.get(req_blob) == REQ
        assert cap.blobs.get(resp_blob) == RESP

    def test_and_creates_one_surface(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        row = cap.conn.execute("SELECT path_template, query_key_set, kind"
                               " FROM surface").fetchone()
        assert tuple(row) == ("/order/{id}", "id", "idempotent_read")

    def test_and_the_exchange_names_the_surface_it_belongs_to(self, cap):
        """The join the whole plan is for, and it was written by nothing.

        `exchange.surface_id` is a column, has its own index
        (`idx_exchange_surf`), and every coverage figure in a report is a join
        across it: "which surfaces has anything actually reached". The task
        brief's consumer computed the surface id and threw it away, which left
        the column NULL on every row this egress point will ever write -- and
        a NULL there is not recoverable later without re-deriving the template
        from the url under whatever the normaliser's rules have become by
        then, which is the one thing `normaliser_version` exists to say cannot
        be done.
        """
        rid = cap.on_exchange(_header(), REQ, RESP)
        surface_id, = cap.conn.execute(
            "SELECT surface_id FROM exchange WHERE id=?", (rid,)).fetchone()
        assert surface_id is not None
        assert surface_id == cap.conn.execute(
            "SELECT id FROM surface").fetchone()[0]


class TestWhatTheHeaderSays:
    """Every header field this module threads into a row, separated from its
    absence.

    MEASURED before these existed: `resp_len` -> always None, `ms` -> 0,
    `outcome` -> "ok", the `via` default -> "send", the `method` default ->
    "GET", and the whole `config` -> `normalise` threading replaced by
    constants -- six mutations, zero red tests between them. A field nothing
    checks is a field that can be dropped on the floor without anyone finding
    out, and the rows are the only evidence this plan produces.
    """

    def test_the_response_length_is_the_response_it_measured(self, cap):
        rid = cap.on_exchange(_header(), REQ, RESP)
        assert cap.conn.execute("SELECT resp_len FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == len(RESP)

    def test_the_elapsed_time_separates_the_two_timestamps(self, cap):
        """`ms` is the only thing that makes `recv_us` differ from `sent_us`,
        and hardcoding it to 0 made every exchange look instantaneous."""
        rid = cap.on_exchange(_header(ms=12), REQ, RESP)
        sent, recv = cap.conn.execute(
            "SELECT sent_us, recv_us FROM exchange WHERE id=?", (rid,)).fetchone()
        assert recv - sent == 12_000

    def test_the_outcome_is_the_frame_s_and_not_an_assumption_of_ok(self, cap):
        """`ok` is the guessing direction: it claims a response came back.

        `header.get("outcome") or "ok"` turns an absent outcome into that
        claim, so the value that separates the two is one the frame carries
        and `"ok"` is not.
        """
        rid = cap.on_exchange(_header(outcome="truncated"), REQ, RESP)
        assert cap.conn.execute("SELECT outcome FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == "truncated"

    def test_a_frame_that_names_no_via_is_proxy_traffic(self, cap):
        """The default this whole task exists to keep honest.

        `via` tells the two egress points apart -- it is the stated reason
        `denial` gained the column and SCHEMA_VERSION went to 5. Defaulting to
        `"send"` instead files proxy observations as send-path traffic, which
        is exactly the conflation being ended, and no test could see it.
        """
        h = _header()
        del h["via"]
        rid = cap.on_exchange(h, REQ, RESP)
        assert cap.conn.execute("SELECT via FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == "proxy"

    def test_a_frame_that_names_no_method_says_so_rather_than_guessing_GET(self, cap):
        """`""` and `"GET"` are not the same missing value.

        `surface.kind` is derived from the method, and `GET` earns
        `idempotent_read` -- a check reading that is being told it may replay
        the request. A method nobody sent must not buy that permission.
        """
        h = _header()
        del h["method"]
        rid = cap.on_exchange(h, REQ, RESP)
        assert cap.conn.execute("SELECT method FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == ""
        assert cap.conn.execute("SELECT kind FROM surface").fetchone()[0] == "unknown"

    def test_the_operator_s_preserve_list_reaches_the_normaliser(self, cap_with):
        """Task 2 spent a round establishing this rule; the call site can undo
        it silently. `2024` is digit-shaped, so it templates to `{id}` unless
        the operator's `preserve` list arrives here and says it is a route."""
        cap = cap_with(preserve_segments=["2024"])
        cap.on_exchange(_header(url="http://app.test/2024/report"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT path_template FROM surface").fetchone()[0] == "/2024/report"

    def test_and_so_does_the_operator_s_slug_threshold(self, cap_with):
        """`abc-123-xyz` is 11 characters: a slug at threshold 8, a route at
        the default 12. Only the config can move that line."""
        cap = cap_with(slug_threshold=8)
        cap.on_exchange(_header(url="http://app.test/abc-123-xyz"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT path_template FROM surface").fetchone()[0] == "/{slug}"

    def test_the_surface_records_which_egress_point_found_it(self, cap):
        """`surface.discovered_by`, which lost its DEFAULT in SCHEMA_VERSION
        6. S5 draws a coverage figure straight off it -- "crawl-discovered
        surfaces are recorded with discovered_by = 'crawl'" -- so the value a
        writer that never thought about it used to get was a wrong answer to a
        question a report asks."""
        cap.on_exchange(_header(via="proxy"), REQ, RESP)
        cap.on_exchange(_header(via="crawl", source="crawler",
                                url="http://app.test/other"), REQ, RESP)
        rows = dict(cap.conn.execute(
            "SELECT path_template, discovered_by FROM surface"))
        assert rows == {"/order/{id}": "proxy", "/other": "crawl"}

    def test_and_the_first_finder_keeps_the_credit(self, cap):
        """Same family as the exemplar, and the `DO UPDATE` must not touch it:
        the crawler walking into an endpoint the proxy already recorded does
        not make it a crawler discovery."""
        cap.on_exchange(_header(via="proxy"), REQ, RESP)
        cap.on_exchange(_header(via="crawl", source="crawler"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT discovered_by FROM surface").fetchone()[0] == "proxy"


class TestDeduplication:
    def test_two_ids_under_one_endpoint_are_one_surface(self, cap):
        """The sentence S5 exists for. Without this, /order/1..9999 is 9999
        rows and every coverage number derived from them is meaningless."""
        cap.on_exchange(_header(url="http://app.test/order/1"), REQ, RESP)
        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 1

    def test_but_a_different_query_key_set_is_a_different_surface(self, cap):
        """Separates dedup from 'merge everything on this path'. A parameter
        is an input, and an input is where a flaw lives."""
        cap.on_exchange(_header(url="http://app.test/order/1?id=1"), REQ, RESP)
        cap.on_exchange(_header(url="http://app.test/order/1?debug=1"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 2

    def test_and_a_different_method_is_a_different_surface(self, cap):
        cap.on_exchange(_header(method="GET"), REQ, RESP)
        cap.on_exchange(_header(method="POST"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 2

    def test_the_second_sighting_updates_last_seen_not_first_seen(self, cap):
        cap.on_exchange(_header(url="http://app.test/order/1"), REQ, RESP)
        first = cap.conn.execute("SELECT first_seen_run FROM surface").fetchone()[0]
        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        row = cap.conn.execute("SELECT first_seen_run, last_seen_run"
                               " FROM surface").fetchone()
        assert row[0] == first

    def test_a_sighting_in_a_LATER_run_moves_last_seen_and_not_first_seen(self, cap):
        """The input that separates `DO UPDATE` from `INSERT OR IGNORE`.

        The test above cannot: both its sightings land in ONE run, so
        `last_seen_run` holds the same value whether the conflicting insert
        updated it or was silently discarded, and it asserts only
        `first_seen_run` besides. Mutating the upsert to `INSERT OR IGNORE`
        left it green -- a rule invisible to the test named after it, which is
        the shape this plan has now found on every task.

        Two runs is what makes the two columns disagree, and both directions
        matter: `first_seen_run` is when this endpoint entered the assessment
        and `last_seen_run` is whether it is still there. The exemplar is
        checked in the same breath, because it is written on insert and the
        `DO UPDATE` deliberately does not touch it -- a surface's exemplar is
        the exchange that PROVED it exists, and rewriting it on every sighting
        would make "show me an example of this endpoint" answer with whatever
        happened most recently rather than with what was reviewed.
        """
        first_x = cap.on_exchange(_header(url="http://app.test/order/1"), REQ, RESP)
        first_run, exemplar = cap.conn.execute(
            "SELECT first_seen_run, exemplar_exchange_id FROM surface").fetchone()
        assert exemplar == first_x
        run_mod.close_run(cap.conn, run_id=first_run)

        second_x = cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        second_run, = cap.conn.execute(
            "SELECT run_id FROM exchange WHERE id=?", (second_x,)).fetchone()
        assert second_run != first_run

        row = cap.conn.execute(
            "SELECT first_seen_run, last_seen_run, exemplar_exchange_id"
            " FROM surface").fetchone()
        assert tuple(row) == (first_run, second_run, first_x)


class TestDenials:
    def test_a_dropped_request_writes_a_denial_and_no_exchange(self, cap):
        cap.on_exchange(_header(t="denial", error_class="scope_denied",
                                detail="matches no scope.include pattern"),
                        REQ, b"")
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        kind = cap.conn.execute("SELECT kind FROM denial").fetchone()[0]
        assert kind == "scope"

    def test_and_the_denial_records_which_egress_point_refused(self, cap):
        cap.on_exchange(_header(t="denial", error_class="scope_denied", detail="x"),
                        REQ, b"")
        assert cap.conn.execute("SELECT via FROM denial").fetchone()[0] == "proxy"

    def test_a_refused_request_is_not_counted_as_one_that_left(self, cap):
        """S5's `requests_issued` counts what LEFT.

        A denial is a request that never did, so the counter must not move for
        it -- counting refusals as issued inflates every coverage figure
        derived from the column, and a report claiming reach the run never had
        is the failure this store exists to avoid.

        MEASURED: with only the brief's own tests in the file, moving the bump
        above the `t == "denial"` branch reddened NOTHING -- the counter was
        written by the consumer and read by nobody. It now reddens this and
        `test_each_exchange_is_counted_against_the_run_that_issued_it`, which
        are the two halves of the rule: bumped there, and not bumped here.
        """
        cap.on_exchange(_header(t="denial", error_class="scope_denied", detail="x"),
                        REQ, b"")
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 0

    def test_a_denial_frame_says_the_request_never_left(self, cap):
        """`row_for(..., issued=False)`, and it was pinned by nothing.

        `timeout` and `bridge_lost` each name a request that left the JVM AND
        one that never did, so `row_for` refuses to route either from the
        class alone. A denial frame is the case where it never did -- that is
        what makes it a denial -- so this consumer answers False, and
        `row_for` then writes NO row at all: `denial.kind` has no value for
        "the caller gave up before we started", and a row filed under a reason
        that is not the reason is worse than no row.

        Flipping the argument to True was invisible to the whole suite. It is
        not invisible here: True routes the same frame to ("exchange",
        "timeout"), which is an exchange row for a request that was never
        sent -- the one direction every guard in `records` leans against,
        because it inflates `requests_issued` and every coverage figure drawn
        from it.
        """
        assert cap.on_exchange(
            _header(t="denial", error_class="timeout",
                    detail="deadline passed before this frame was decided"),
            REQ, b"") is None
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == 0

    def test_a_credential_refusal_is_a_denial_and_not_a_silence(self, cap):
        """S4 is unconditional and this was the class that escaped it.

        MEASURED at the previous commit: an `unmanaged_credential` denial
        reaching this egress point produced no row, no counter, no log and no
        exception, and `on_exchange` returned None -- indistinguishable from a
        recorded denial and from a drop report. `records.UNRECORDABLE` itself
        called it "a real denial ... the gap to close first", and the reason
        it had nowhere to go was that `denial.kind`'s CHECK had no value for
        it. SCHEMA_VERSION 6 adds one.

        S7's "refused and never persisted" is about the REQUEST BYTES: the row
        below carries the method, the url and a reason, and no credential.
        """
        assert cap.on_exchange(
            _header(t="denial", error_class="unmanaged_credential",
                    detail="Authorization header we did not inject"),
            REQ, b"") is None
        row = cap.conn.execute("SELECT kind, via, url, reason FROM denial").fetchone()
        assert tuple(row) == ("credential", "proxy",
                              "http://app.test/order/7?id=1",
                              "Authorization header we did not inject")
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0

    def test_an_unrecordable_class_writes_nothing_rather_than_guessing(self, cap):
        """`records.UNRECORDABLE`: a class with no row to file it under.

        `row_for` answers None, and None must mean no row -- not a row under a
        reason that is not the reason. `transport_error` is one of the seven
        left in that set: the request DID leave the JVM, so it belongs in
        `exchange`, and the extension reports one class for conn_refused,
        dns_error and tls_error alike, so picking one of the three would put a
        guess in the evidence store.

        No run either, since the routing decision is now settled above `_run`:
        a frame that produces nothing must not leave a run behind claiming
        zero coverage.
        """
        assert cap.on_exchange(
            _header(t="denial", error_class="transport_error",
                    detail="the connection did not complete"),
            REQ, b"") is None
        assert cap.conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0


class TestDrops:
    def test_a_drop_report_is_counted_against_the_run(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        cap.on_exchange(_header(t="dropped", n=4), b"", b"")
        assert cap.conn.execute("SELECT dropped_total FROM run").fetchone()[0] == 4

    def test_a_drop_report_before_any_exchange_still_lands(self, cap):
        """The queue can overflow before the first exchange gets through --
        that is precisely the case where the harness was slow to start. A
        counter that needed a run to exist first would lose exactly the drops
        that matter most."""
        cap.on_exchange(_header(t="dropped", n=2), b"", b"")
        assert cap.conn.execute("SELECT dropped_total FROM run").fetchone()[0] == 2

    def test_a_saturated_run_is_not_an_idle_one(self, cap):
        """A harness dropping everything is the opposite of an idle harness.

        MEASURED before the drop path heartbeated: a run receiving only
        `dropped` frames never moved `heartbeat_us`, so after IDLE_CLOSE_US
        the next drop report made `current_run` close it
        `status='completed', stop_reason='idle'` with `dropped_total=100` on
        it and open a fresh run for the rest. S5, quoted in `run.py`'s own
        docstring: "an aborted run must never render as a clean one, and
        neither must one that merely stopped being updated." A run that
        dropped a hundred exchanges is incomplete coverage by definition, and
        it read as clean -- while the total fragmented across a chain of runs
        where no single row showed the drops.

        Each frame here is followed by winding the heartbeat back two thirds
        of the window. Beating on every drop keeps the age at two thirds
        forever; not beating accumulates it, and the third frame arrives at
        four thirds of the window -- which is what makes this two runs rather
        than one.
        """
        for _ in range(3):
            cap.on_exchange(_header(t="dropped", n=50), b"", b"")
            cap.conn.execute(
                "UPDATE run SET heartbeat_us = heartbeat_us - ?"
                " WHERE status='running'", (run_mod.IDLE_CLOSE_US * 2 // 3,))
        rows = cap.conn.execute("SELECT status, dropped_total FROM run").fetchall()
        assert [tuple(r) for r in rows] == [("running", 150)]


class TestRefusals:
    def test_an_unknown_via_is_refused(self, cap):
        with pytest.raises(ValueError, match="via"):
            cap.on_exchange(_header(via="carrier-pigeon"), REQ, RESP)

    def test_a_frame_with_no_url_is_refused_rather_than_guessed(self, cap):
        with pytest.raises(ValueError):
            cap.on_exchange(_header(url=None), REQ, RESP)

    def test_a_frame_type_this_version_does_not_know_is_refused(self, cap):
        """S6 carries an `unknown_frame` class precisely for this.

        MEASURED with no else-arm on `t`: `{"t": "quarantine", ...}` returned
        a row id and wrote 1 exchange row, 1 surface, 2 blobs and
        `requests_issued = 1`. Plan 5's crawler, or any later extension build,
        adds one frame type this side does not know and every such frame
        becomes observed traffic that never existed -- inflating every
        coverage figure drawn from that column, in a store whose entire
        purpose is not to claim reach a run never had.
        """
        with pytest.raises(ValueError, match="unknown frame type"):
            cap.on_exchange(_header(t="quarantine"), REQ, RESP)
        for table in ("exchange", "surface", "run"):
            assert cap.conn.execute(
                f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        assert not cap.blobs.path_for(hashlib.sha256(REQ).hexdigest()).exists()

    def test_a_drop_report_that_would_run_the_counter_backwards_is_refused(self, cap):
        """`int(header.get("n", 1))` was unchecked and MEASURED
        `dropped_total = -5`. See `run.count_drop`, which refuses the same
        bound at the writer; this is the same refusal placed early enough that
        the malformed frame does not leave a run behind either."""
        cap.on_exchange(_header(t="dropped", n=3), b"", b"")
        with pytest.raises(ValueError, match="floor"):
            cap.on_exchange(_header(t="dropped", n=-5), b"", b"")
        assert cap.conn.execute(
            "SELECT dropped_total FROM run").fetchone()[0] == 3

    def test_a_refused_frame_opens_no_run(self, cap):
        """Each frame below is refused before `current_run` is reached, so a
        stream of malformed frames manufactures neither runs whose coverage is
        zero nor blob files nothing will ever name.

        THE LIST IS THE CLAIM; the module's comment deliberately no longer
        says it is complete. Five of the entries were added after being
        measured opening a run: the unparseable port (`normalise` is
        explicitly NOT TOTAL), the unrecognised `error_class` and the empty
        string `header.get("error_class") or ""` produces, and then `ms="abc"`
        and `outcome="bogus"`, which raised from INSIDE `record_exchange` --
        below the blob puts as well. Three frames of either measured 1 run, 0
        exchanges and 2 orphan blob files: six puts of two distinct bodies
        into a content-addressed store.

        The blob assertion is why the last two belong here rather than in a
        test of their own: a refusal that opens no run can still leave files
        behind, and that is strictly the worse leak of the two -- a run with
        no exchanges is visible in the store, an orphan blob is not.
        """
        bad_frames = (
            _header(via="carrier-pigeon"),
            _header(url=None),
            _header(t="quarantine"),
            _header(t="dropped", n=-5),
            _header(url="http://h:abc/x"),
            _header(t="denial", error_class="no-such-class"),
            _header(t="denial", error_class=""),
            _header(ms="abc"),
            _header(outcome="bogus"),
        )
        for bad in bad_frames:
            with pytest.raises(ValueError):
                cap.on_exchange(bad, REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0
        assert not cap.blobs.path_for(
            hashlib.sha256(REQ).hexdigest()).exists()

    def test_a_response_that_came_back_cannot_be_filed_without_a_status(self, cap):
        """An absent `status` is refused, not written as NULL.

        This module invents a default for nine header fields and for `status`
        it invents nothing -- so the frame with no `status` key at all had to
        land somewhere, and for `outcome='truncated'` it landed on disk:
        MEASURED `ACCEPTED rid=x-...  exchange 1  surface 1
        requests_issued 1  status NULL`. `record_exchange` guarded only 'ok'
        and 'status_unreadable'.

        A truncated response is a response that CAME BACK, so that row said a
        peer answered and declined to say what it answered -- while
        `status_unreadable` plus the 599 sentinel is the store's whole
        apparatus for saying exactly that. A NULL status now carries one
        reading and only one: nothing on the far side ever answered.
        """
        header = _header(outcome="truncated")
        del header["status"]
        with pytest.raises(ValueError, match="no status"):
            cap.on_exchange(header, REQ, RESP)
        assert cap.conn.execute(
            "SELECT COUNT(*) FROM exchange").fetchone()[0] == 0

    def test_the_one_refusal_that_does_leave_a_run_behind(self, cap):
        """The boundary of the sentence above, pinned from the other side.

        `record_exchange`'s coherence guards belong to the STORE, not to this
        module, and they fire on a frame whose shape was already accepted --
        `outcome='ok'` with no status is a frame that says two things which
        cannot both be true. By then the run exists and has been heartbeated.
        An empty run is the honest cost: something WAS captured here, and the
        refusal is about what the row would have claimed rather than about
        whether the frame could be read at all.
        """
        with pytest.raises(ValueError):
            cap.on_exchange(_header(status=None), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 0


class TestTheOrderThingsHappenIn:
    def test_a_row_that_cannot_be_written_leaves_its_blob_behind(self, cap):
        """The separating input for "blobs before the row that names them".

        The ordering guards a crash between two statements, and no unit test
        can crash the interpreter -- so the brief expected this invariant to be
        unpinned and it very nearly was. What CAN be observed is the same
        window reached by a different route: `record_exchange`'s own coherence
        guard refuses `outcome='ok'` with no status, and it refuses at exactly
        the point a crash would land. Blobs-first therefore leaves an ORPHAN
        BLOB and no row; blobs-after leaves a row-less store and no blob, which
        is the same state -- but with the two statements the other way round a
        successful put followed by a failed row is impossible to reach, so the
        assertion below is False.

        The asymmetry is the point and is worth saying plainly: an orphan blob
        is garbage a sweep can collect, and a row naming a blob that was never
        written is corruption a report reads as evidence.
        """
        with pytest.raises(ValueError):
            cap.on_exchange(_header(status=None), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.blobs.path_for(hashlib.sha256(REQ).hexdigest()).exists()

    def test_a_failure_partway_through_leaves_no_half_written_exchange(self, cap):
        """The four row writes are one unit, and they were four units.

        `db.connect` is autocommit and `records`'s own docstring says so --
        "a caller writing an exchange row and its blobs together should wrap
        the pair in `db.transaction` itself". Unwrapped, with `upsert_surface`
        raising `OperationalError("database is locked")` -- which WAL plus a
        concurrent writer past `busy_timeout=5000` is enough to produce --
        this MEASURED an exchange row COMMITTED with `surface_id` NULL, zero
        surface rows, and `requests_issued = 1`. That NULL is the precise
        state the back-reference was added to prevent and cannot be repaired
        afterwards, and the counter is then a phantom issued request.

        Ordering cannot fix this one: the back-reference has to come last
        because the surface's exemplar is the exchange. Atomicity is the
        mechanism, and it is a different mechanism from the blob ordering
        above -- which stays, because the blob store is not in the database
        and no ROLLBACK reaches it.
        """
        def explode(*_a, **_k):
            raise sqlite3.OperationalError("database is locked")

        cap.upsert_surface = explode
        with pytest.raises(sqlite3.OperationalError):
            cap.on_exchange(_header(), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 0
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 0


class TestTheRunTheFrameBelongsTo:
    def test_crawler_traffic_is_a_crawl_run_and_not_a_browse_one(self, cap):
        """`source` decides the kind, and nothing else did.

        MEASURED: collapsing the mapping to a constant `"browse"` reddened no
        test in the brief's own set. `test_and_opens_a_browse_run_without_
        being_asked` asserts the branch a constant already satisfies, and it
        was the only test that looked at `run.kind`. Attributing crawler
        traffic to a browse run would make the denial rows lie about who was
        driving, and the enforcement rules differ by exactly that distinction.
        """
        cap.on_exchange(_header(source="crawler"), REQ, RESP)
        assert cap.conn.execute("SELECT kind FROM run").fetchone()[0] == "crawl"
        cap.on_exchange(_header(source="operator"), REQ, RESP)
        assert set(r[0] for r in cap.conn.execute("SELECT kind FROM run")) == \
            {"crawl", "browse"}

    def test_each_exchange_is_counted_against_the_run_that_issued_it(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 2

    def test_a_frame_keeps_its_run_alive(self, cap):
        """The heartbeat, separated from its absence.

        `run.reap_stale` resolves a run whose heartbeat went stale to `error`
        -- "its coverage is incomplete" -- so a capture session that beats only
        when the run is OPENED is one that reports itself as a crash after
        half an hour of steady browsing. The window below is inside
        IDLE_CLOSE_US, so `current_run` returns the same run rather than
        closing it as idle, which is what makes the update observable.
        """
        cap.on_exchange(_header(), REQ, RESP)
        run_id, = cap.conn.execute("SELECT id FROM run").fetchone()
        stale = cap.conn.execute(
            "SELECT heartbeat_us FROM run").fetchone()[0] - run_mod.IDLE_CLOSE_US // 2
        cap.conn.execute("UPDATE run SET heartbeat_us=? WHERE id=?",
                         (stale, run_id))

        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
        assert cap.conn.execute(
            "SELECT heartbeat_us FROM run").fetchone()[0] > stale


class TestTheAutoHalt:
    """S4's `halted` frame, as rows.

    Until this class existed `records.abort_run` had zero callers outside
    tests, nothing in `src/` built a `BridgeServer` with an `on_halted`, and
    the integration rig wired only `on_hello` and `on_exchange`. So S5's "an
    aborted run must never render as a clean one" was unenforced BY
    CONSTRUCTION: the run always closed through one of the three writers that
    are individually correct and none of which is the truth about a run a
    target's distress ended.
    """

    def test_a_halted_frame_aborts_the_run_with_the_distress_as_its_epitaph(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        aborted = cap.on_halted({"t": "halted", "reason": "5xx rate 0.40",
                                 "host": "app.example.test",
                                 "window": "50 requests / 37s"})
        assert len(aborted) == 1
        row = cap.conn.execute(
            "SELECT status, stop_reason, ended_us FROM run").fetchone()
        assert row["status"] == "aborted"
        assert row["stop_reason"] == ("5xx rate 0.40 on app.example.test "
                                      "(50 requests / 37s)")
        assert row["ended_us"] is not None

    def test_one_distressed_host_aborts_every_live_run_and_not_just_its_own(self, cap):
        """S4, in as many words: "One distressed host aborts the WHOLE run
        ... not just that host. Distress on one host is often the first sign
        of something the whole test is causing." A crawl running beside a
        human browsing is two `run` rows of one test, and leaving the other
        one `running` is the half a report would read as clean.
        """
        cap.on_exchange(_header(source="operator"), REQ, RESP)
        cap.on_exchange(_header(source="crawler"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT COUNT(*) FROM run WHERE status='running'").fetchone()[0] == 2

        assert len(cap.on_halted({"reason": "5 consecutive connection errors",
                                  "host": "app.example.test",
                                  "window": "5 requests"})) == 2
        assert cap.conn.execute(
            "SELECT COUNT(*) FROM run WHERE status='running'").fetchone()[0] == 0
        assert set(r[0] for r in cap.conn.execute(
            "SELECT DISTINCT status FROM run")) == {"aborted"}

    def test_a_second_distressed_host_does_not_replace_the_diagnosis(self, cap):
        """`abort_run`'s `status='running'` guard, reached from here. Two
        distressed hosts inside one window is ordinary behaviour for a
        struggling target, and the FIRST stop_reason is the one that explains
        what happened -- a symptom arriving second must not overwrite it."""
        cap.on_exchange(_header(), REQ, RESP)
        assert len(cap.on_halted({"reason": "5xx rate 0.40",
                                  "host": "first.example.test"})) == 1
        assert cap.on_halted({"reason": "p50 latency 12x baseline",
                              "host": "second.example.test"}) == []
        assert cap.conn.execute("SELECT stop_reason FROM run").fetchone()[0] \
            == "5xx rate 0.40 on first.example.test"

    def test_a_halted_frame_with_nothing_recording_opens_no_run(self, cap):
        """A row for a session that never happened is the thing `FRAME_TYPES`
        refuses two hundred lines above, and it would be the same defect here:
        a `run` with no traffic, aborted, inflating nothing but confusing
        everything. Nothing to abort is an empty list, not an invented row."""
        assert cap.on_halted({"reason": "5xx rate 0.40",
                              "host": "app.example.test"}) == []
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0

    def test_a_frame_missing_its_fields_still_produces_a_readable_epitaph(self, cap):
        """S6 gives the frame `{reason, host, window}` and this side does not
        get to assume all three arrived. A KeyError here runs on the bridge's
        READ THREAD, where `BridgeServer._handle`'s halted arm turns a throw
        into a CLOSED CONNECTION -- so a frame one key short would take the
        operator's browsing down as well as failing to record the stop."""
        cap.on_exchange(_header(), REQ, RESP)
        assert len(cap.on_halted({"t": "halted"})) == 1
        assert cap.conn.execute("SELECT stop_reason FROM run").fetchone()[0] \
            == "target distress on an unnamed host"

    def test_an_aborted_run_is_not_reaped_into_something_that_reads_cleaner(self, cap):
        """The reading S5 asks for, end to end. `reap_stale` resolves a
        `running` run whose harness died to `error`; `current_run` closes an
        idle one `completed`. Both are guarded on `status='running'`, so an
        aborted run keeps its own status and its own reason -- and this is the
        assertion that would fail if the abort were ever written as a plain
        `close_run`."""
        cap.on_exchange(_header(), REQ, RESP)
        cap.on_halted({"reason": "5xx rate 0.40", "host": "app.example.test"})
        assert run_mod.reap_stale(cap.conn, now_us=10 ** 18) == []
        row = cap.conn.execute("SELECT status, stop_reason FROM run").fetchone()
        assert row["status"] == "aborted"
        assert row["stop_reason"].startswith("5xx rate 0.40")


def test_a_halted_frame_off_a_real_socket_reaches_the_store(tmp_path, cap):
    """THE WIRING, not the writer.

    Every check above calls `on_halted` directly, which is exactly the shape
    B2 found: a correct writer nothing calls. This one drives a real `halted`
    frame down a real `BridgeServer` and asserts the row at the far end, so
    that removing `on_halted=` from the constructor is a RED test rather than
    a silent return to a run that never gets its epitaph.

    The callback runs on the bridge's READ THREAD. `cap`'s connection was
    opened on this one, so this test would raise `sqlite3.ProgrammingError`
    inside `BridgeServer._handle`'s halted arm -- which closes the connection
    and records the throw rather than propagating it. The write therefore
    happens on the read thread's own connection, opened lazily, exactly as
    `tests/integration/conftest.py::ReadThreadCapture` does it for the same
    reason.
    """
    from hx import halt as halt_mod
    from hx.bridge import codec, server

    root = Path(cap.blobs.root).parent
    oh = halt_mod.OperatorHalt(root, cap.conn)
    read_thread_cap = _ReadThreadCapture(root, cap.engagement_id, cap.config)
    srv = server.BridgeServer(tmp_path / "halted.sock", engagement_id=ENG,
                              operator_halt=oh,
                              on_halted=read_thread_cap.on_halted)
    srv.start()
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(5)
    try:
        c.connect(str(srv.socket_path))
        cap.on_exchange(_header(), REQ, RESP)
        run_id, = cap.conn.execute("SELECT id FROM run").fetchone()

        c.sendall(codec.encode({"v": 1, "t": "halted",
                                "reason": "5xx rate 0.40",
                                "host": "app.example.test",
                                "window": "50 requests / 37s"}))

        deadline = time.time() + 5
        row = None
        while time.time() < deadline:
            row = cap.conn.execute(
                "SELECT status, stop_reason FROM run WHERE id=?",
                (run_id,)).fetchone()
            if row["status"] != "running":
                break
            time.sleep(0.005)
        assert srv.halted_callback_error is None, srv.halted_callback_error
        assert row["status"] == "aborted", (
            "the halted frame reached the bridge and no run was aborted; "
            f"state={srv.state!r} last_halted={srv.last_halted!r}")
        assert row["stop_reason"] == ("5xx rate 0.40 on app.example.test "
                                      "(50 requests / 37s)")
        assert srv.state == "halted"
    finally:
        c.close()
        srv.stop()
        read_thread_cap.close()


class _ReadThreadCapture:
    """`hx.capture.Capture` on a connection belonging to the thread that uses
    it -- the same shape `tests/integration/conftest.py` installs, and for the
    same measured reason: a sqlite3 connection raises `ProgrammingError`
    anywhere but the thread that created it, and `BridgeServer` catches that
    throw, so the observable would be a green handshake and an empty table."""

    def __init__(self, root, engagement_id, cfg):
        self._root = Path(root)
        self._engagement_id = engagement_id
        self._config = cfg
        self._capture = None

    def _lazy(self):
        if self._capture is None:
            self._capture = cap_mod.Capture(
                db_mod.connect(self._root / "hx.db"),
                blobs_mod.BlobStore(self._root / "blobs"),
                self._engagement_id, self._config)
        return self._capture

    def on_halted(self, header):
        return self._lazy().on_halted(header)

    def close(self):
        # Deliberately not closed: `Connection.close()` is thread-affine too,
        # so closing it from THIS thread raises during teardown and replaces
        # whatever failed the test. `srv.stop()` has already joined the read
        # thread, so nothing is still writing.
        pass
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_capture.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.capture'`

- [ ] **Step 3: Add `via` to the two record functions**

In `src/hx/store/records.py`, add near `EXCHANGE_OUTCOMES`:

```python
# src/hx/store/records.py -- the via vocabulary
# S5's `via` vocabulary, and the schema's CHECK enforces the same three.
# `send` was the only value either writer could produce until Plan 4:
# record_exchange hardcoded the literal and `denial` had no column to put one
# in. `proxy` and `crawl` are the two other egress points, and a fourth value
# would mean a fourth path -- which S4 forbids outright.
#
# Both `exchange.via` and `denial.via` carry it, and a test compares this
# constant against BOTH constraints rather than one: the column was added to
# `denial` in Plan 4 and two CHECKs spelling the same vocabulary are two
# places for it to drift.
VIA_VALUES = frozenset({"proxy", "send", "crawl"})
```

Then give both `record_exchange` and `record_denial` a keyword-only `via: str = "send"` parameter, validated at the top of each:

```python
    if via not in VIA_VALUES:
        raise ValueError(f"unknown via {via!r}; S5 names {sorted(VIA_VALUES)}")
```

and thread it into the INSERT in place of the literal `'send'`. The default keeps every existing caller working unchanged, which is what makes this a safe edit to a module with coherence guards already in it.

- [ ] **Step 4: Write the consumer**

```python
# src/hx/capture.py
"""One exchange frame in; one surface, one exchange row, two blobs out.

Three components tested alone meet here, and on the previous branch every
defect that survived eight task reviews lived at a join like this one. So the
module is deliberately thin: it validates, and it delegates.

IT IS NOT RULE-FREE, and saying so was a claim that did not survive its own
review. The rules it owns, each named where it is written:

  - the frame-type vocabulary (`FRAME_TYPES`), and the refusal of anything
    else;
  - `source` -> run KIND, in `_run`;
  - `via` -> `surface.discovered_by`, in `DISCOVERED_BY`;
  - what an ABSENT header field means, which is nine separate decisions:
    `t`, `n`, `source`, `via`, `method`, `error_class`, `detail`, `ms` and
    `outcome` all have a default here. `url` and `status` have none, and
    neither is INVENTED: an absent `url` is refused by this module, and an
    absent `status` is refused by `record_exchange`'s coherence guard for the
    outcomes that mean a response came back -- `ok`, `truncated` and
    `status_unreadable`. For the rest the row keeps a NULL, and that NULL is
    the reading: nothing on the far side ever answered, because the transport
    failed or the request was refused before it left. It never means a
    response came back whose status went unrecorded -- `status_unreadable`
    with its 599 sentinel is how that is said;
  - the `requests_issued` bump, and that the denial path does not do it;
  - the whole upsert/conflict policy in `upsert_surface`;
  - the `exchange.surface_id` back-reference.

TWO GUARANTEES, TWO MECHANISMS, and they are not the same one said twice:

  - ATOMICITY OF THE FOUR ROW WRITES comes from `db.transaction` and from
    nothing else. The connection is autocommit, so an unwrapped run of
    statements commits as far as it got -- measured, with `upsert_surface`
    raising: an exchange row committed with a NULL `surface_id`, no surface,
    and `requests_issued` bumped for it.
  - BLOB-BEFORE-ROW ORDERING is about the blob store, which is not in the
    database and cannot be rolled back with it. A blob written for a row that
    never commits is garbage a sweep can collect; a committed row naming a
    blob that was never written is corruption a report reads as evidence. So
    the puts stay OUTSIDE the transaction and ahead of it.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from hx import config as config_mod
from hx import run as run_mod
from hx import surface as surface_mod
from hx.engagement import now_us
from hx.store import db as db_mod
from hx.store import records
from hx.store.blobs import BlobStore

# The frame types this version knows. S6 carries an `unknown_frame` error
# class precisely because a `t` outside this set must be REFUSED: without the
# refusal, `t` fell through to the exchange arm and a `{"t": "quarantine"}`
# frame measured 1 exchange row, 1 surface, 2 blobs and `requests_issued=1` --
# traffic that never happened, inflating every coverage figure drawn from that
# column. The next frame type Plan 5 adds must be decided about here rather
# than fabricated into an exchange.
FRAME_TYPES = frozenset({"exchange", "denial", "dropped"})

# `via` (S5's egress point) -> `surface.discovered_by` (S5's discovery
# provenance). Two vocabularies, one fact, and they are spelt differently:
# S5 draws coverage off `discovered_by = 'crawl'`, and `discovered_by` has no
# 'send' -- an agent's own request is what 'agent' names. The column lost its
# DEFAULT in SCHEMA_VERSION 6, so this map is not an optimisation: an insert
# from here without it now fails.
DISCOVERED_BY = {"proxy": "proxy", "crawl": "crawl", "send": "agent"}


@dataclass
class Capture:
    conn: sqlite3.Connection
    blobs: BlobStore
    engagement_id: str
    config: config_mod.Config

    def _run(self, source: str) -> str:
        """The run this frame belongs to, opened if need be.

        `source` decides the KIND, and that mapping is the whole reason the
        two are told apart at the listener: attributing crawler traffic to a
        browse run would make the denial rows lie about who was driving, and
        the enforcement rules differ by exactly that distinction.
        """
        kind = "crawl" if source == "crawler" else "browse"
        return run_mod.current_run(
            self.conn, engagement_id=self.engagement_id, kind=kind,
            safety_profile=self.config.safety_profile)

    def on_halted(self, header: dict) -> list[str]:
        """S4's auto-halt, as rows. Returns the run ids this call aborted.

        THE FRAME HAD NO WRITER. `records.abort_run` had zero callers outside
        tests, nothing in `src/` built a `BridgeServer` with an `on_halted`,
        and the integration rig wired only `on_hello` and `on_exchange` -- so
        S4's "one distressed host aborts the WHOLE run" and S5's "an aborted
        run must never render as a clean one" were unenforced BY
        CONSTRUCTION. The run then closed through `cli.capture stop`
        (completed/operator), `run.current_run` (completed/idle) or
        `run.reap_stale` (error), each of which is individually correct and
        none of which is the truth about a run a target's distress ended.

        EVERY LIVE RUN OF THE ENGAGEMENT, not the one the distressed host
        belongs to. S4 is explicit -- "One distressed host aborts the whole
        run ... not just that host. Distress on one host is often the first
        sign of something the whole test is causing" -- and a crawl running
        beside a browse is two runs of one test. `cli.capture stop` takes the
        same reading for the same reason.

        ONE TRANSACTION, so a store that fails partway leaves no run marked
        aborted beside another still `running` on the same distress. The
        connection is autocommit; see this module's header.

        NO RUN IS OPENED. A `halted` frame arriving when nothing is recording
        aborts nothing and says so by returning `[]`. Manufacturing a run to
        hold the epitaph would put a row in the store for a session that never
        happened, which is what `FRAME_TYPES` above refuses for the same
        reason.

        WHAT THIS DOES NOT MAKE DURABLE, named because a reader will otherwise
        assume it: the run's epitaph survives, the STOP does not. Issuance is
        stopped by the extension's own `Distress` state, which lives in the
        JVM, and `BridgeServer._reset` puts this side back to DENY-ALL when
        the connection drops -- so a Burp restart plus a fresh `configure`
        re-arms issuance with nobody having looked. That is measured, in
        `tests/test_bridge_server.py::test_a_halted_frame_stops_issuance_and_aborts_the_run`,
        and it is deliberate rather than missed: S4 scopes DURABILITY to an
        OPERATOR halt, and an operator who has looked has `hx halt` to make it
        durable. Calling `OperatorHalt.halt()` from here is not available
        anyway -- it writes to the database and this method runs on the
        bridge's READ THREAD, where a connection opened elsewhere raises
        `sqlite3.ProgrammingError`.
        """
        reason = str(header.get("reason") or "target distress")
        host = str(header.get("host") or "an unnamed host")
        window = str(header.get("window") or "")
        stop_reason = f"{reason} on {host}"
        if window:
            stop_reason += f" ({window})"
        rows = self.conn.execute(
            "SELECT id FROM run WHERE engagement_id=? AND status='running'",
            (self.engagement_id,)).fetchall()
        aborted: list[str] = []
        with db_mod.transaction(self.conn):
            for row in rows:
                # True only when THIS call stopped it. A second `halted` frame
                # from another host inside one window is ordinary behaviour
                # for a struggling target, and the first stop_reason is the
                # one that explains what happened -- see `abort_run`.
                if records.abort_run(self.conn, run_id=row[0],
                                     stop_reason=stop_reason, at_us=now_us()):
                    aborted.append(row[0])
        return aborted

    def on_exchange(self, header: dict, request: bytes,
                    response: bytes) -> str | None:
        """Handle one frame. Returns the exchange row id, or None.

        Called on the bridge's READ THREAD, so it must not block for long and
        must not raise into the read loop for anything recoverable -- Plan 2's
        read loop drops to DENY-ALL on an unhandled throw, which would turn a
        bookkeeping bug into an outage. A malformed frame is a ValueError the
        caller logs; a database failure is not caught here, because a store
        that cannot be written to is not a condition to carry on through.
        """
        t = header.get("t", "exchange")
        if t not in FRAME_TYPES:
            raise ValueError(
                f"unknown frame type {t!r}; this version knows "
                f"{sorted(FRAME_TYPES)}. S6 answers one with the "
                "`unknown_frame` error class -- one frame refused, the channel "
                "kept -- and recording it as an exchange would file traffic "
                "that never happened")

        if t == "dropped":
            # Parsed and bounded BEFORE `_run`, so a malformed drop report
            # cannot manufacture a run whose coverage is zero. `count_drop`
            # refuses the same bound at the writer; see its docstring for why
            # a negative n is the one that matters.
            drops = int(header.get("n", 1))
            if drops < 1:
                raise ValueError(
                    f"a dropped frame reporting n={drops!r} is malformed; "
                    "run.dropped_total is an accumulator and S5 makes it the "
                    "reason a run's coverage numbers are a floor")
            run_id = self._run(header.get("source", "operator"))
            # The drop path heartbeats too, and that is not decoration. A
            # saturated harness may be dropping every exchange it sees while
            # reporting each drop faithfully; without this, `heartbeat_us`
            # never moved, and after IDLE_CLOSE_US the next drop report made
            # `current_run` close the run `completed`/`idle` and open another
            # -- MEASURED at status='completed', stop_reason='idle',
            # dropped_total=100, with the rest of the total on a second run.
            # A run that dropped 100 exchanges is the definition of incomplete
            # coverage and it read as a clean, idle one.
            #
            # `idle` STAYS the reason for a genuine idle close, drops or not:
            # the close is made by a LIVE harness observing a quiet window,
            # which is what separates it from `reap_stale`'s `error` close for
            # a harness that is gone. `completed` says the run ENDED cleanly,
            # never that its coverage is complete -- `dropped_total` on the
            # same row is what says otherwise, and the heartbeat above is what
            # keeps that number whole instead of fragmenting it across a chain
            # of runs where no single row shows the drops.
            run_mod.heartbeat(self.conn, run_id=run_id, now_us=now_us())
            run_mod.count_drop(self.conn, run_id=run_id, n=drops)
            return None

        via = header.get("via", "proxy")
        if via not in records.VIA_VALUES:
            raise ValueError(f"unknown via {via!r}")
        url = header.get("url")
        if not url:
            raise ValueError("exchange frame has no url")
        method = header.get("method") or ""

        # READING THE FRAME IS SETTLED ABOVE `_run`, and this paragraph names
        # what is BELOW rather than claiming the list above is complete:
        # three successive versions of it claimed completeness and a
        # counter-example was measured against each. The hoisted refusals so
        # far are the frame type, `via`, `url`, the drop count `n`, and --
        # further down this method -- `error_class` through `row_for`, the
        # template through `normalise`, `ms` through `int()` and `outcome`
        # against the store's vocabulary. Each of the last four was measured
        # firing BELOW the run -- one empty run per malformed frame -- and
        # `ms` and `outcome` fired below the BLOB PUTS as well, leaving the
        # files for a row that was never written. None of them touches the
        # database, so hoisting costs nothing and the run is opened once the
        # frame is known to be readable.
        #
        # BELOW `_run` sit `record_exchange`'s COHERENCE GUARDS, deliberately.
        # They are the STORE's; they fire on a frame this module has already
        # read successfully; and they are about what the ROW would claim --
        # the status/outcome pairing -- rather than about whether the frame
        # could be read at all. That case leaves an empty run and an orphan
        # blob behind, which is the honest cost of catching a row that would
        # have lied: `test_the_one_refusal_that_does_leave_a_run_behind` and
        # `test_a_row_that_cannot_be_written_leaves_its_blob_behind` pin the
        # boundary from that side, and the second needs this exact window to
        # exist at all.
        if t == "denial":
            error_class = header.get("error_class") or ""
            # row_for answers ("denial", kind) OR ("exchange", outcome) -- it
            # is the supported way in precisely because reading DENIAL_KIND
            # directly gets the precedence wrong for the two classes that
            # appear in both maps. So the table it names is checked, not
            # assumed: passing an OUTCOME where a KIND belongs is not a thing
            # to find out about downstream.
            #
            # MEASURED, because the two sentences the brief wrote here were
            # both claims and both are false. (1) The branch is UNREACHABLE
            # while `issued=False`, and no input can redden it: `row_for`'s
            # third arm is the only one that answers ("exchange", ...), and
            # every key of EXCHANGE_OUTCOME is caught by an earlier arm --
            # scope_denied and rate_limited by DENIAL_KIND, timeout and
            # bridge_lost by AMBIGUOUS_ISSUANCE, which answers None when the
            # request never left. The reachable answers here are
            # ("denial", kind), None, and ValueError. (2) It would NOT "fail
            # the denial table's CHECK": `record_denial` checks `kind` against
            # DENIAL_KINDS itself, so `kind='timeout'` raises ValueError in
            # Python and never reaches SQLite at all.
            #
            # It stays anyway, because (1) is a fact about TODAY'S maps rather
            # than about this call -- EXCHANGE_OUTCOME gaining one key that
            # neither DENIAL_KIND nor AMBIGUOUS_ISSUANCE names makes the
            # branch live -- and because it names the TABLE in its message,
            # which the check downstream cannot. `issued=False` is the load-
            # bearing half of the pair and IS pinned; see
            # test_a_denial_frame_says_the_request_never_left.
            row = records.row_for(error_class, issued=False)
            if row is None:
                return None
            table, value = row
            if table != "denial":
                raise ValueError(
                    f"{error_class!r} routes to {table!r}, not a denial; a "
                    "dropped request that produced no exchange cannot be "
                    "recorded as one")
            run_id = self._run(header.get("source", "operator"))
            at = now_us()
            run_mod.heartbeat(self.conn, run_id=run_id, now_us=at)
            records.record_denial(
                self.conn, run_id=run_id, kind=value, method=method, url=url,
                detail=header.get("detail") or "", at_us=at, via=via)
            return None

        # The two exchange-only header fields, read HERE and not at the
        # `record_exchange` call, which sits below `_run` AND below the blob
        # puts. Both were measured leaking there, three frames each:
        #
        #   ms="abc"          ValueError from int()     1 run, 0 exchanges,
        #                                               2 orphan blob files
        #   outcome="bogus"   ValueError from records   1 run, 0 exchanges,
        #                                               2 orphan blob files
        #
        # Six puts, two files: the store is content-addressed and the three
        # frames carried the same bodies. Distinct bodies would be six.
        #
        # A value the frame cannot be read with is the same family as the
        # unparseable port and the unplaceable error class -- nothing about
        # the row's claims, everything about the frame -- so it belongs with
        # them, above anything that opens or writes. `record_exchange` checks
        # the outcome again at the writer; this one is placed early rather
        # than instead.
        ms = int(header.get("ms") or 0)
        outcome = header.get("outcome") or "ok"
        if outcome not in records.EXCHANGE_OUTCOMES:
            raise ValueError(
                f"unknown outcome {outcome!r}; the exchange table's "
                f"vocabulary is {sorted(records.EXCHANGE_OUTCOMES)}. Map an "
                "error class through records.EXCHANGE_OUTCOME rather than "
                "inventing a value here")

        norm = surface_mod.normalise(
            method, url,
            preserve=frozenset(self.config.preserve_segments),
            slug_threshold=self.config.slug_threshold)
        run_id = self._run(header.get("source", "operator"))
        at = now_us()
        run_mod.heartbeat(self.conn, run_id=run_id, now_us=at)

        # Blobs before the transaction, deliberately: the blob store is not in
        # the database, so a ROLLBACK cannot take a file back. Writing them
        # first means a failed exchange leaves an orphan blob, which is
        # garbage a sweep can collect; writing them after a committed row that
        # names them would leave corruption a report reads as evidence. This
        # is an ordering argument only -- the four writes below are atomic
        # because of the transaction, not because of where they sit.
        req_blob, _ = self.blobs.put(request) if request else (None, None)
        resp_blob, resp_len = (self.blobs.put(response) if response
                               else (None, None))

        # One unit. `db.connect` is autocommit, so without this each statement
        # commits on its own: `upsert_surface` failing -- "database is locked"
        # under WAL past busy_timeout is enough -- MEASURED an exchange row
        # committed with `surface_id` NULL, no surface row, and
        # `requests_issued` bumped for it. That NULL is the exact state the
        # back-reference was added to prevent, and it is unrecoverable
        # afterwards.
        with db_mod.transaction(self.conn):
            exchange_id = records.record_exchange(
                self.conn, run_id=run_id, method=method, url=url,
                status=header.get("status"), req_blob=req_blob,
                resp_blob=resp_blob, resp_len=resp_len,
                ms=ms, at_us=at, outcome=outcome, via=via)

            # S5's run.requests_issued, which nothing has ever written to. It
            # counts what LEFT, so it is bumped here and not on the denial
            # path: a refused request is in `denial`, and counting it as
            # issued would inflate every coverage figure derived from this
            # column.
            self.conn.execute(
                "UPDATE run SET requests_issued = requests_issued + 1"
                " WHERE id=?", (run_id,))

            surface_id = self.upsert_surface(norm, exchange_id=exchange_id,
                                             run_id=run_id, via=via)
            # The back-reference, and it cannot be written any earlier: the
            # surface's exemplar is this exchange, so the exchange row has to
            # exist before the surface row can name it. `exchange.surface_id`
            # is what every coverage query joins on -- "which surfaces has
            # anything actually reached" -- and a NULL here is not recoverable
            # afterwards except by re-deriving the template under whatever the
            # normaliser's rules have become by then, which is the one thing
            # `normaliser_version` exists to say cannot be done.
            self.conn.execute("UPDATE exchange SET surface_id=? WHERE id=?",
                              (surface_id, exchange_id))
        return exchange_id

    def upsert_surface(self, n: surface_mod.Normalised, *, exchange_id: str,
                       run_id: str, via: str) -> str:
        """Insert or touch the surface this exchange belongs to.

        `first_seen_run` is written once and never updated; `last_seen_run`
        moves. The exemplar is likewise set only on insert -- a surface's
        exemplar is the first exchange that proved it exists, and rewriting it
        on every sighting would make "show me an example of this endpoint"
        return whatever happened most recently rather than what was reviewed.

        `discovered_by` is in the same family as the exemplar and is likewise
        untouched by the `DO UPDATE`: it answers WHICH EGRESS POINT FOUND
        this surface, and the crawler seeing an endpoint the proxy already
        recorded does not make it a crawler discovery. S5 draws a coverage
        figure straight off that distinction.
        """
        self.conn.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
            " path_template, query_key_set, kind, discovered_by,"
            " normaliser_version, first_seen_run, last_seen_run,"
            " exemplar_exchange_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, method, scheme, host, port,"
            "             path_template, query_key_set)"
            " DO UPDATE SET last_seen_run=excluded.last_seen_run",
            (records.new_id("s"), self.engagement_id, n.method, n.scheme,
             n.host, n.port, n.path_template, n.query_key_set, n.kind,
             DISCOVERED_BY[via],
             n.normaliser_version, run_id, run_id, exchange_id))
        return self.conn.execute(
            "SELECT id FROM surface WHERE engagement_id=? AND method=?"
            " AND scheme=? AND host=? AND port=? AND path_template=?"
            " AND query_key_set=?",
            (self.engagement_id, n.method, n.scheme, n.host, n.port,
             n.path_template, n.query_key_set)).fetchone()[0]
```

- [ ] **Step 5: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_capture.py tests/test_records.py -q`
Expected: PASS.

- [ ] **Step 6: Prove the ordering and the dedup separate from their absence**

Three mutations, each run against the full suite, each judged by the summary line:

1. Move the `blobs.put` calls *after* `record_exchange` — expect no test to fail, and **that is a finding to report**, not a pass. The ordering protects against a crash between two statements, which no unit test observes. Add a check that separates it: assert the blob exists on disk before the row is queried, or state plainly in the report that this invariant is unpinned and why.
2. Change `ON CONFLICT … DO UPDATE` to `INSERT OR IGNORE` — expect `test_the_second_sighting_updates_last_seen_not_first_seen` to go red.
3. Drop `query_key_set` from the conflict target — expect `test_but_a_different_query_key_set_is_a_different_surface` to go red.

- [ ] **Step 7: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/capture.py src/hx/store/records.py tests/test_capture.py tests/test_records.py
git commit -m "feat(capture): the rows get their first production caller"
```

---

### Task 5: `Source` and `ProxyGate` — §4's second enforcement point

The extension gains the point §4 has promised since the spec was written. `ProxyGate` decides; it does no I/O and holds no queue, so it can be tested exhaustively against fakes before real Burp is anywhere near it.

**`Source` is a security boundary and gets its own file** so the attribution rule can be read on its own. §4: *the two sources are told apart by which proxy listener the request arrived on, never by anything in the traffic itself.* A property of the connection cannot be forged by a hostile page; a header can.

**Files:**
- Create: `extension/src/hx/proxy/Source.java`, `extension/src/hx/proxy/ProxyGate.java`
- Create: `extension/test/hx/proxy/ProxyGateTest.java`
- Modify: `extension/src/hx/policy/Policy.java` — add `decideScopeOnly` (Step 5)
- Modify: `extension/test.sh` — add `hx.proxy.ProxyGateTest` to `CLASSES`

**Interfaces:**
- Consumes: `hx.policy.Policy.decide(HxRequest, BridgeClient.Authorisation)`, `hx.policy.Decision`, `hx.policy.HxRequest`, `hx.bridge.BridgeClient.Authorisation`, `hx.policy.Gate`
- Produces:
  - `enum Source { OPERATOR, CRAWLER, UNATTRIBUTED }` with `static Source forListenerPort(int port, int crawlerPort)` and `static final int NO_PORT = 0`
    - **Amended by fix round 1, and this is the contract Task 7 implements against.** `forListenerPort` answers `UNATTRIBUTED` for any `port` outside `1..65535` — `NO_PORT` is the spelling for "the caller could not read one" — and `ProxyGate.decide` REFUSES `UNATTRIBUTED` and `null` with class `not_configured` and a detail carrying `BridgeClient.EXTENSION_FAULT`. A port that parses and is not the crawler's is still `OPERATOR`. The code blocks below are Task 5's original text and predate the amendment; the files are the authority (this plan is `plan-drift: pending`, so its blocks are not compared).
  - `record ProxyGate.Verdict(boolean allow, String errorClass, String detail)`
  - `ProxyGate(Policy policy)` and `Verdict decide(HxRequest req, Authorisation auth, Source source)`

`ProxyGate` takes **one** `Policy` and no separate `Gate`: `Policy` already owns its `Gate` (`Policy(Gate)`, consulted last by `decide`), so handing this class a second one would mean two budgets spent for one request. `ProxyGateTest` injects its `CountingGate` through the `Policy`, which is where a real run's rate limit and budget live too.

- [ ] **Step 1: Write the failing test**

```java
// extension/test/hx/proxy/ProxyGateTest.java
package hx.proxy;

import hx.TestSupport;
import hx.bridge.BridgeClient;
import hx.policy.Decision;
import hx.policy.Gate;
import hx.policy.HxRequest;
import hx.policy.Policy;
import hx.policy.TickClock;
import hx.send.Limits;

import java.util.List;
import java.util.Map;

/**
 * The gate, against fakes.
 *
 * The two cases that matter most are the pair: the SAME request is allowed
 * for the operator and refused for the crawler. A test that only exercises
 * one source cannot tell a working split from a gate that ignores source
 * entirely -- which is rule 3 on this project. Rows B and C of this task's
 * sabotage table are that split turned off in each direction, and each
 * reddens only its own source's checks: neither is caught by the other's.
 *
 * Hand-rolled runner, like the other eleven classes: JUnit would be a
 * dependency, and this jar has none.
 */
public class ProxyGateTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  Load-bearing here rather than decoration: the input that separates this
     *  class's own DENY-ALL guard from its absence makes the method THROW, and
     *  without this guard that reads as a truncated run rather than a failure.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(ProxyGateTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("scope is absolute for the operator",
          ProxyGateTest::scopeIsAbsoluteForTheOperator);
        t("and absolute for the crawler",
          ProxyGateTest::scopeIsAbsoluteForTheCrawler);
        t("the operator's own browsing is not method-checked",
          ProxyGateTest::theOperatorIsNotMethodChecked);
        t("but the crawler is",
          ProxyGateTest::theCrawlerIsMethodChecked);
        t("the operator is not dangerous-path checked",
          ProxyGateTest::theOperatorIsNotDangerousPathChecked);
        t("but the crawler is (dangerous path)",
          ProxyGateTest::theCrawlerIsDangerousPathChecked);
        t("the operator does not spend the gate",
          ProxyGateTest::theOperatorDoesNotSpendTheGate);
        t("but the crawler does (the gate)",
          ProxyGateTest::theCrawlerSpendsTheGate);
        t("an unconfigured extension refuses every source",
          ProxyGateTest::unconfiguredRefusesBoth);
        t("a source that could not be attributed is refused, not defaulted",
          ProxyGateTest::anUnattributableSourceIsRefused);
        t("a crawler request that passes scope, method and dangerous.path "
          + "REACHES the gate, and an unarmed one refuses it",
          ProxyGateTest::theCrawlerReachesTheGateAndAnUnarmedOneRefusesIt);
        t("the listener port decides the source",
          ProxyGateTest::theListenerPortDecides);
        t("a listener interface is parsed or refused, never guessed at",
          ProxyGateTest::theListenerInterfaceIsParsedOrRefused);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures -------------------------------------------------------

    static BridgeClient.Authorisation authorised() {
        return new BridgeClient.Authorisation(7, Map.of(
            "scope.include", List.of("http://app.test/*"),
            "method.allow", List.of("GET", "HEAD"),
            "dangerous.path", List.of("*/logout*")));
    }

    /**
     * The host is taken FROM the url rather than fixed at "app.test".
     *
     * Policy refuses any request whose url authority is not the connection
     * host, with the same `scope_denied` class an unmatched include produces,
     * and it refuses it FIRST (Policy.checkScope). A fixture that hard-coded
     * the host to "app.test" would therefore have `http://evil.test/x`
     * refused by the host comparison rather than by the include patterns, and
     * the two scope checks below would say nothing about scope.
     *
     * Measured, row G of this task's sabotage table. Adding
     * "http://evil.test/*" to `scope.include` -- authorising the very request
     * those checks exist to see refused -- reddens three checks with the host
     * taken from the url, and the suite is back to 10 x ALL PASS with the same
     * widened include the moment the host is hard-coded again.
     */
    static HxRequest req(String method, String url) {
        java.net.URI u = java.net.URI.create(url);
        return new HxRequest(method, url, u.getHost(), u.getPath(), "",
                             Map.of(), new byte[0]);
    }

    /** A Gate that counts, so "did this spend budget" is observable. */
    static final class CountingGate implements Gate {
        int calls;
        public Decision check(HxRequest r) { calls++; return Decision.allow(); }
    }

    static ProxyGate gateOver(Gate gate) {
        // The Gate goes into the Policy, which is where the rate limit and the
        // budget live in production too: Policy owns its Gate and consults it
        // last. A call counted here is a call a real run spends a rate token
        // and a budget slot on.
        return new ProxyGate(new Policy(gate));
    }

    // ---- scope, which is absolute for everyone ---------------------------

    static void scopeIsAbsoluteForTheOperator() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://evil.test/x"), authorised(), Source.OPERATOR);
        check("out of scope is refused even for the operator", !v.allow());
        check("and the class names the boundary crossed (" + v.errorClass() + ")",
              "scope_denied".equals(v.errorClass()));
    }

    static void scopeIsAbsoluteForTheCrawler() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://evil.test/x"), authorised(), Source.CRAWLER);
        check("out of scope is refused for the crawler too", !v.allow());
    }

    // ---- the four rules that constrain an agent, in pairs ----------------

    static void theOperatorIsNotMethodChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("POST", "http://app.test/login"), authorised(), Source.OPERATOR);
        check("a POST the allowlist omits still goes out for a human ("
              + v.errorClass() + ")", v.allow());
    }

    static void theCrawlerIsMethodChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("POST", "http://app.test/login"), authorised(), Source.CRAWLER);
        check("the same POST is refused for the crawler", !v.allow());
        check("with method_denied (" + v.errorClass() + ")",
              "method_denied".equals(v.errorClass()));
    }

    static void theOperatorIsNotDangerousPathChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://app.test/logout"), authorised(), Source.OPERATOR);
        check("a deliberate click on a dangerous path is the operator's to make",
              v.allow());
    }

    static void theCrawlerIsDangerousPathChecked() {
        ProxyGate g = gateOver(new CountingGate());
        var v = g.decide(req("GET", "http://app.test/logout"), authorised(), Source.CRAWLER);
        check("a crawler that finds logout must not click it", !v.allow());
        check("with dangerous_denied (" + v.errorClass() + ")",
              "dangerous_denied".equals(v.errorClass()));
    }

    static void theOperatorDoesNotSpendTheGate() {
        CountingGate gate = new CountingGate();
        var v = gateOver(gate)
            .decide(req("GET", "http://app.test/x"), authorised(), Source.OPERATOR);
        // The allow is asserted alongside the count: a request refused before
        // the Gate would also leave `calls` at 0, so the count on its own does
        // not separate "the operator skips the Gate" from "the operator was
        // denied".
        check("the in-scope request is allowed (" + v.errorClass() + ")", v.allow());
        check("browsing does not spend the run's budget (" + gate.calls + ")",
              gate.calls == 0);
    }

    static void theCrawlerSpendsTheGate() {
        CountingGate gate = new CountingGate();
        var v = gateOver(gate)
            .decide(req("GET", "http://app.test/x"), authorised(), Source.CRAWLER);
        check("the same request is allowed for the crawler (" + v.errorClass() + ")",
              v.allow());
        check("crawling does (" + gate.calls + ")", gate.calls == 1);
    }

    // ---- the gate the crawler actually reaches ---------------------------

    /**
     * THE TEST THAT DID NOT EXIST, AND ITS ABSENCE IS WHY A LIVE DEFECT SHIPPED.
     *
     * Every crawler case above stops SHORT of the Gate.
     * {@link #theCrawlerIsMethodChecked} drives a POST that `method.allow`
     * refuses; {@link #theCrawlerIsDangerousPathChecked} drives `/logout`;
     * {@link #scopeIsAbsoluteForTheCrawler} drives an out-of-scope host.
     * {@link #theCrawlerSpendsTheGate} does reach it -- against a
     * {@link CountingGate} that allows everything. The single crawler-listener
     * INTEGRATION test drives a POST too. So no test anywhere drove a crawler
     * request through scope, method and dangerous.path into the REAL Gate.
     *
     * WHAT THAT HID. {@link hx.send.Limits} is the Gate a real run carries, and
     * it answers `not_configured` -- "the rate and budget are not armed" --
     * until {@code arm} has run. `arm` had ONE call site, in the send
     * handler, so every crawler request that got this far was refused as
     * unauthorised on a correctly authorised run, until some unrelated `send`
     * happened to arm it. Fail-closed, and a denial that lies about why.
     *
     * SO THE FIXTURE IS THE REAL Limits AND NOT A CountingGate. A fake that
     * allows everything cannot fail this way, and that is the whole finding:
     * the gate that exists in production has a state the test double does not
     * have.
     *
     * THE THIRD CASE IS THE CONTROL. The operator gets the same request
     * through the SAME unarmed Limits and is allowed, because the operator
     * branch stops before the Gate -- so what the first case pins is the
     * Gate's state, not the request.
     *
     * WHAT THIS DOES NOT PIN: that HxExtension arms it. This class constructs
     * both objects itself. The wiring is text in a file no test can execute,
     * and it is counted by
     * {@code ChokepointTest.everyPathThatSpendsTheGateArmsItFirst}.
     */
    static void theCrawlerReachesTheGateAndAnUnarmedOneRefusesIt() {
        BridgeClient.Authorisation auth = authorised();
        // GET, in scope, not on the dangerous list: the three checks ahead of
        // the Gate all pass, so this request reaches it and nothing else does
        // the refusing.
        HxRequest allowed = req("GET", "http://app.test/x");

        var unarmed = gateOver(new Limits(new TickClock(1_000_000L), 5, 100))
                .decide(allowed, auth, Source.CRAWLER);
        check("an UNARMED gate refuses the crawler (" + unarmed.errorClass() + ")",
              !unarmed.allow() && "not_configured".equals(unarmed.errorClass()));
        // The detail is asserted, not just the class: `not_configured` is
        // shared with DENY-ALL and with an unattributable source, so the class
        // alone does not say that this is the Gate answering.
        check("and says the rate and budget are the thing that is missing ("
              + unarmed.detail() + ")",
              unarmed.detail() != null
              && unarmed.detail().contains("not armed"));

        Limits armed = new Limits(new TickClock(1_000_000L), 5, 100);
        armed.arm(auth);
        var ok = gateOver(armed).decide(allowed, auth, Source.CRAWLER);
        check("the SAME request is allowed once the gate is armed ("
              + ok.errorClass() + ")", ok.allow());

        // The control, and it is what makes the first case about the Gate.
        var operator = gateOver(new Limits(new TickClock(1_000_000L), 5, 100))
                .decide(allowed, auth, Source.OPERATOR);
        check("and the operator is allowed through the same unarmed gate, "
              + "because that branch never reaches it (" + operator.errorClass()
              + ")", operator.allow());
    }

    // ---- DENY-ALL --------------------------------------------------------

    static void unconfiguredRefusesBoth() {
        var none = new BridgeClient.Authorisation(0, Map.of());
        ProxyGate g = gateOver(new CountingGate());
        for (Source s : Source.values()) {
            var v = g.decide(req("GET", "http://app.test/x"), none, s);
            check("DENY-ALL holds for " + s + " (" + v.errorClass() + ")",
                  !v.allow() && "not_configured".equals(v.errorClass()));
        }

        // The separating input for ProxyGate's OWN epoch guard, and it is not
        // the checks above. Policy refuses an epoch-0 authorisation on both of
        // the paths this class calls, so with that guard deleted the three
        // above still print `ok` and the failure is the NPE thrown out of THIS
        // method the moment the loop below reaches a ProxyGate with no Policy
        // -- re-measured on this tree, 9 x ALL PASS + 1 FAILURE / 1652 ok, the
        // one FAIL being this method's name and a NullPointerException. (Row D
        // of the sabotage table measured it when Source had two constants; the
        // third constant adds a green check, not a red one, because an
        // unattributable source is refused either way.) The guard adds that
        // the answer is given BEFORE the
        // Policy is consulted, and a ProxyGate holding no Policy is the one
        // caller that can tell the two apart: with the guard it is a verdict,
        // without it an NPE. The per-method guard in TestSupport.t turns that
        // NPE into a named FAIL rather than a truncated run.
        for (Source s : Source.values()) {
            var v = new ProxyGate(null).decide(req("GET", "http://app.test/x"), none, s);
            check("and it is answered without consulting Policy for " + s
                  + " (" + v.errorClass() + ")",
                  !v.allow() && "not_configured".equals(v.errorClass()));
        }
    }

    // ---- the third answer ------------------------------------------------

    /**
     * A source this gate cannot recognise is REFUSED, and both spellings of
     * one are: `Source.UNATTRIBUTED` and a null.
     *
     * Both were ALLOWED before the guard that answers them existed --
     * measured, and with the whole suite at 10 x ALL PASS, because
     * `source == Source.CRAWLER` is false for each and the else branch is the
     * lenient one. The two requests are chosen as the separating inputs: a
     * POST the allowlist omits, and a GET on a dangerous path. The CONTROL is
     * that both are still allowed for Source.OPERATOR two methods up, so what
     * these pin is attribution and not the four rules.
     *
     * NOT claimed: that null and UNATTRIBUTED exhaust what this branch
     * catches. It is written as "neither of the two I know", so a constant
     * added to Source later lands here too -- and that constant needs its own
     * check, because this method names two and cannot see a third.
     */
    static void anUnattributableSourceIsRefused() {
        CountingGate gate = new CountingGate();
        ProxyGate g = gateOver(gate);
        Source[] unknown = { Source.UNATTRIBUTED, null };
        for (Source s : unknown) {
            var post = g.decide(req("POST", "http://app.test/login"), authorised(), s);
            check("a POST the allowlist omits is refused for " + s + " ("
                  + post.errorClass() + ")",
                  !post.allow() && "not_configured".equals(post.errorClass()));

            var logout = g.decide(req("GET", "http://app.test/logout"), authorised(), s);
            check("and so is a dangerous path for " + s + " ("
                  + logout.errorClass() + ")",
                  !logout.allow() && "not_configured".equals(logout.errorClass()));

            // The class is shared with DENY-ALL, so the class alone does not
            // say which guard answered. The detail does, and the prefix it
            // starts with is the one records.py declares for itself -- the
            // marker that separates "this jar is broken" from "the operator
            // never configured a run", pinned identical on both sides by
            // test_the_extension_fault_marker_is_the_same_string_on_both_sides.
            check("with the extension-fault marker on the detail for " + s
                  + " (" + logout.detail() + ")",
                  logout.detail() != null
                  && logout.detail().startsWith(BridgeClient.EXTENSION_FAULT));
        }
        check("and refusing an unattributable request spends nothing ("
              + gate.calls + ")", gate.calls == 0);
    }

    // ---- attribution -----------------------------------------------------

    static void theListenerPortDecides() {
        check("the crawler port attributes to CRAWLER",
              Source.forListenerPort(8081, 8081) == Source.CRAWLER);
        check("any other port attributes to OPERATOR",
              Source.forListenerPort(8080, 8081) == Source.OPERATOR);
        // A port that PARSED and belongs to no listener hx knows about is the
        // operator's: they may configure extra listeners, and crawler
        // attribution is the stricter branch, so getting it by default would
        // silently apply the agent's rules to a human.
        check("and an unrecognised but usable port is OPERATOR, not CRAWLER",
              Source.forListenerPort(9999, 8081) == Source.OPERATOR);
        // Behaviour, not a guard: an unconfigured crawler port must swallow
        // nothing. This input separates no branch of forListenerPort as it now
        // stands -- 8080 is in range and 8080 != 0 -- and is kept as a pin on
        // the answer rather than dressed up as more than it is.
        check("an unconfigured crawler port matches nothing",
              Source.forListenerPort(8080, 0) == Source.OPERATOR);

        // The four inputs that separate the range test, and with it the whole
        // third answer. Each is a port the caller could not determine, and
        // each answered OPERATOR -- the branch that drops four of the five
        // rules -- before the range test existed; measured, all four, against
        // the committed body. (0, 0) was the sharpest: it answered OPERATOR
        // only because of a `crawlerPort > 0` clause that existed for that one
        // pair, and a bare equality made it CRAWLER instead.
        check("a port that could not be read is UNATTRIBUTED, with a crawler configured",
              Source.forListenerPort(Source.NO_PORT, 8081) == Source.UNATTRIBUTED);
        check("and without one",
              Source.forListenerPort(Source.NO_PORT, 0) == Source.UNATTRIBUTED);
        check("a negative sentinel is UNATTRIBUTED, not a listener",
              Source.forListenerPort(-1, 8081) == Source.UNATTRIBUTED);
        check("and so is a number no TCP port can be",
              Source.forListenerPort(70000, 8081) == Source.UNATTRIBUTED);
        // The constant is the spelling Task 7 hands over, and it must be the
        // value the rule actually treats that way -- a NO_PORT of, say, 1
        // would make the two lines above pass while every real parse failure
        // answered OPERATOR.
        check("and NO_PORT is one of those numbers (" + Source.NO_PORT + ")",
              Source.NO_PORT < 1 || Source.NO_PORT > 65535);
    }

    /**
     * The other half of the attribution, and the only half that touches a
     * string a Burp handed over.
     *
     * {@link Source} takes two ints and does no parsing on purpose. Something
     * has to turn `listenerInterface()` into one of those ints, and that
     * something lives in HxExtension -- a file nothing can drive, except this
     * one static method, which is why it is public. Every failure here has to
     * answer {@link Source#NO_PORT}, because the alternative is a number that
     * might land on the crawler's port or on the operator's branch by
     * accident: a parse that GUESSES is attribution decided by a malformed
     * string.
     *
     * MEASURED FORM, from docs/burp-proxy-measurements.md Q1:
     * `"127.0.0.1:8080"`, a different port per listener, over plain HTTP and
     * through a CONNECT tunnel.
     */
    static void theListenerInterfaceIsParsedOrRefused() {
        check("the measured form parses (" + hx.HxExtension.listenerPort("127.0.0.1:8080") + ")",
              hx.HxExtension.listenerPort("127.0.0.1:8080") == 8080);
        check("and a different listener gives a different port",
              hx.HxExtension.listenerPort("127.0.0.1:8081") == 8081);
        // THE LAST colon, not the first. An IPv6 interface puts colons inside
        // the address, and splitting on the first would read `:1]:8080` --
        // non-numeric, so NO_PORT, so UNATTRIBUTED, so every request on an
        // IPv6 listener REFUSED. Fail-closed, but it would refuse a working
        // configuration and read as a broken jar.
        check("the port is taken after the LAST colon, so an IPv6 interface works ("
              + hx.HxExtension.listenerPort("[::1]:8080") + ")",
              hx.HxExtension.listenerPort("[::1]:8080") == 8080);

        // Everything else is NO_PORT. Each of these is a shape a caller in
        // trouble actually produces, and each would otherwise have to be
        // invented into a number.
        check("a null interface is NO_PORT",
              hx.HxExtension.listenerPort(null) == Source.NO_PORT);
        check("an interface with no colon at all is NO_PORT",
              hx.HxExtension.listenerPort("127.0.0.1") == Source.NO_PORT);
        check("an empty tail after the colon is NO_PORT",
              hx.HxExtension.listenerPort("127.0.0.1:") == Source.NO_PORT);
        check("a non-numeric tail is NO_PORT",
              hx.HxExtension.listenerPort("127.0.0.1:http") == Source.NO_PORT);
        check("and so is a tail that is only PARTLY numeric",
              hx.HxExtension.listenerPort("127.0.0.1:8080x") == Source.NO_PORT);
        check("a negative tail is NO_PORT, not a negative port",
              hx.HxExtension.listenerPort("127.0.0.1:-1") == Source.NO_PORT);
        check("an empty string is NO_PORT",
              hx.HxExtension.listenerPort("") == Source.NO_PORT);
        // THE INPUT THAT SEPARATES THE LENGTH BOUND FROM ITS ABSENCE. Without
        // it `Integer.parseInt` THROWS on a run of digits past 2^31 -- out of
        // the handler, on a Burp proxy thread, for a request that would then
        // be neither allowed nor refused nor recorded. Every other overlong
        // number is answered by Source's own range test; this one never
        // reaches it.
        check("a 30-digit tail is NO_PORT rather than an exception",
              hx.HxExtension.listenerPort("127.0.0.1:" + "9".repeat(30))
              == Source.NO_PORT);
        // And a number that parses but is not a port: handed over as itself,
        // because Source's range test is the one place that rule lives. Named
        // here so the boundary between the two files is visible from both
        // sides -- this method does NOT range-check.
        check("a 5-digit number out of TCP range is handed over as itself, for "
              + "Source to refuse (" + hx.HxExtension.listenerPort("127.0.0.1:70000") + ")",
              hx.HxExtension.listenerPort("127.0.0.1:70000") == 70000
              && Source.forListenerPort(70000, 8081) == Source.UNATTRIBUTED);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./extension/test.sh 2>&1 | grep -a ProxyGateTest`
Expected: a compile failure naming `hx.proxy.Source`.

- [ ] **Step 3: Write `Source`**

```java
// extension/src/hx/proxy/Source.java
package hx.proxy;

/**
 * Who is driving: the operator's own browser, the crawler, or NEITHER -- and
 * the third is an answer in its own right rather than a synonym for the first.
 *
 * This is a security boundary and it has its own file so the rule can be read
 * without reading anything else.
 *
 * S4: the two real sources are told apart by WHICH PROXY LISTENER the request
 * arrived on, never by anything in the traffic itself. A property of the
 * connection cannot be forged by a hostile page; a header can, and a page that
 * could make its requests look human-driven would dodge the crawler's rules
 * entirely -- including the dangerous-path denylist that exists so a crawler
 * finding "Delete account" does not click it.
 *
 * The listener is readable: `InterceptedRequest.listenerInterface()` returns
 * the accepting listener's own `host:port` and names a different port for each
 * listener, measured over plain HTTP and through a CONNECT tunnel -- see
 * docs/burp-proxy-measurements.md, Q1. There is no `listenerPort()`, so the
 * caller parses the port after the last `:` and hands the int here. This enum
 * does no parsing and imports nothing: it is handed two numbers so the
 * attribution rule is the only thing in the file, and so nothing that carries
 * traffic can reach it.
 *
 * THE DEFAULT DIRECTION, AND WHY IT IS TWO ANSWERS RATHER THAN ONE.
 *
 * A port that PARSES and is not the crawler's is OPERATOR. Crawler attribution
 * applies the AGENT's rules, and applying them to a human by accident is the
 * failure that drives an operator off the proxy -- at which point their
 * traffic is not recorded at all and the enforcement bought nothing. An
 * operator may legitimately configure extra listeners and hx cannot enumerate
 * them, so "a port I do not recognise" has to mean the human.
 *
 * What that costs, stated rather than argued away: ProxyGate asks Policy for
 * SCOPE ONLY on the OPERATOR branch, so a request attributed that way is not
 * method-checked, not dangerous-path-checked, spends no rate token and spends
 * no budget slot -- and NOTHING ELSE IN THIS SYSTEM APPLIES THOSE FOUR RULES
 * TO IT. S4 puts all four here on purpose ("Rate limiting, method allowlist,
 * dangerous-path denylist, and per-run budgets all live in the extension"):
 * the Python side carries `dangerous_paths` and `method.allow` as config to
 * ship to this jar and as denial-class names to record, and refuses none of
 * them -- grepped, 2026-08-25, and that grep is how to falsify this sentence:
 * a refusal appearing on the Python side would make it false, and
 * hx-design.md:192 is the line saying one should not.
 *
 * An earlier version of this comment claimed a crawler mis-attributed as an
 * operator was the safer error "because its own harness still refuses what it
 * must". There is no such harness refusal, and that false sentence was the
 * whole argument for answering OPERATOR to a question this enum could not
 * actually answer.
 *
 * So a port that CANNOT BE DETERMINED is no longer that answer. It is
 * UNATTRIBUTED, and {@link ProxyGate} REFUSES it: not knowing who is driving
 * is a code failure or a change in Burp, never a person browsing, and the
 * permissive branch is the one branch it must not silently become.
 *
 * WHAT UNATTRIBUTED COVERS AND WHAT IT EXCLUDES. It is the answer for an int
 * that is not a usable TCP port -- `port < 1 || port > 65535` -- which is the
 * shape a caller in trouble actually produces: {@link #NO_PORT} from an unset
 * field or from a `listenerInterface()` that did not parse, a negative from a
 * parse that returned a sentinel, a garbage large number from one that read
 * the wrong digits. It EXCLUDES a port that parsed into range and belongs to
 * no listener hx knows about: `(9999, 8081)` is OPERATOR, deliberately,
 * because that is the extra-listener case above and nothing here can tell it
 * from a typo. ProxyGateTest pins both sides of that line -- `(0, 8081)`,
 * `(-1, 8081)` and `(70000, 8081)` are UNATTRIBUTED; `(9999, 8081)` and
 * `(8080, 0)` are OPERATOR.
 *
 * What NO attribution weakens, whichever of the three it answers: scope.
 * ProxyGate applies scope to both real sources identically and refuses the
 * third outright, so a request attributed the wrong way is still refused when
 * it leaves the engagement's boundary -- pinned by ProxyGateTest's
 * out-of-scope checks, one method for each of the two real sources, and by
 * the refusal checks for the third.
 */
public enum Source {
    OPERATOR,
    CRAWLER,
    UNATTRIBUTED;

    /**
     * What a caller hands over when it has no port to hand over.
     *
     * Named so Task 7's parse has something to say "I could not read one"
     * WITH, rather than reaching for a bare 0 that used to mean the operator.
     * Any int outside 1..65535 answers the same way, so a caller that forgets
     * this constant and passes 0, -1 or a failed parse's sentinel still gets
     * UNATTRIBUTED; the constant is for the reader, not for the rule.
     */
    public static final int NO_PORT = 0;

    /**
     * @param port        the listener the request arrived on, or {@link #NO_PORT}
     *                    when the caller could not determine one
     * @param crawlerPort the configured crawler listener, or 0 if there is none
     */
    public static Source forListenerPort(int port, int crawlerPort) {
        // The range test comes FIRST and is what makes the third answer
        // reachable: without it, `port == crawlerPort` on two absences (an
        // unreadable port and an unconfigured crawler, 0 and 0) is CRAWLER,
        // and every other unreadable port is OPERATOR -- the agent's rules
        // applied to a human on the strength of two absences agreeing, or the
        // human's leniency applied to the agent. Both are now refusals.
        if (port < 1 || port > 65535) return UNATTRIBUTED;
        // No `crawlerPort > 0` guard here any more, and its absence is
        // deliberate: with `port` already constrained to 1..65535, a
        // crawlerPort of 0 or negative cannot equal it, so that clause is
        // subsumed and NO input in this suite separates it from its absence:
        // putting it back is 10 x ALL PASS / 1655 ok / 0 FAIL, measured, and
        // the range test above is why no input can. A guard nothing separates
        // is the finding this fix round is closing elsewhere; it is not
        // re-added here. `(8080, 0)` is still pinned in ProxyGateTest
        // as BEHAVIOUR -- an unconfigured crawler port matches nothing -- and
        // that check is honest about not separating a guard.
        return port == crawlerPort ? CRAWLER : OPERATOR;
    }
}
```

- [ ] **Step 4: Write `ProxyGate`**

```java
// extension/src/hx/proxy/ProxyGate.java
package hx.proxy;

import hx.bridge.BridgeClient;
import hx.policy.Decision;
import hx.policy.HxRequest;
import hx.policy.Policy;

/**
 * S4's second enforcement point. Decides; does not record, dial, or queue.
 *
 * The split this class exists for, in one sentence: SCOPE IS ABSOLUTE FOR
 * EVERYONE, and the other four rules constrain an AGENT.
 *
 * The reasoning is in S4 and is worth repeating where it is implemented,
 * because the first version of the spec said otherwise. Method allowlist,
 * dangerous-path denylist, rate limit and budget exist so a bad check or a
 * runaway loop cannot hurt the client. A human clicking a form is a
 * deliberate act by the person legally responsible for the engagement, and
 * applying the agent's rules to them makes S9's highest-quality source of
 * attack surface unusable: `method.allow` refuses their login POST, the rate
 * limit throttles their browsing, the budget ends their session mid-page.
 * Enforcement that drives an operator off the proxy buys nothing -- they
 * browse without hx and the traffic is not recorded at all.
 *
 * Scope is different in kind. It is the client's boundary, the thing the
 * engagement letter names, and no caller may spend it.
 *
 * The two branches are two QUESTIONS asked of one Policy, not two policies:
 * `Policy.decide` is the full pinned order and `Policy.decideScopeOnly` stops
 * after scope. Which of the two a request gets is the whole of what
 * {@link Source} buys.
 *
 * THIS POINT DOES NOT CHECK THE HALT, AND THAT IS A STATED GAP, NOT AN
 * OVERSIGHT. S4's decision order puts `halted` second. This class asks
 * {@link Policy}, and Policy does not know about halts -- the send path asks
 * {@link hx.send.HaltSwitch} separately, through
 * `Sender.issuanceHeldReason`. So while the run is HALTED, proxy traffic keeps
 * flowing and keeps being recorded.
 *
 * WHAT THAT ACTUALLY COSTS, stated in full because the comfortable version of
 * it was wrong. It is not only "a human who hit stop can close their browser".
 * FOUR things set the halt and only one of them is that human:
 *
 *   - a `halt` FRAME the operator sent. This is the comfortable case, and the
 *     browser is in their hands;
 *   - the SENTINEL FILE, S4's third kill path -- the one that works when the
 *     bridge does not. Someone reaching for that has already lost the channel;
 *   - the AUTO-HALT on target distress. NOT a human decision: S4 aborts the
 *     whole run above a 20% 5xx rate, above 5x the baseline p50 latency, or
 *     after 5 consecutive connection errors. hx has decided the target is in
 *     trouble and the operator's browser is still hitting it;
 *   - a halt RE-ASSERTED AFTER A RECONNECT, because an operator halt is
 *     durable and a fresh `hello` does not clear it. The operator may not be
 *     at the keyboard at all.
 *
 * AND IT RUNS THE OTHER WAY TOO: operator browsing feeds nothing into
 * `Distress`, which is fed from the SEND path's replies only. So operator
 * traffic can distress a host without ever tripping the auto-halt, and would
 * not be stopped by it if something else did.
 *
 * The ruling stands anyway, for the reason below -- closing the gap without
 * the row to put the refusal in breaks S4 with the fix for S4 -- and the
 * crawler, where the four above bite hardest, does not exist yet.
 *
 * WHAT PLAN 5 MUST DO TO CLOSE IT, written here because this is where its
 * implementer will look. Answering `halted` from this class is NOT a one-line
 * change: `halted` has to be added to `records.DENIAL_KIND` and to the
 * `denial.kind` CHECK in schema.sql (with the SCHEMA_VERSION bump that
 * implies), or `hx.capture`'s denial arm routes it to `row_for(...) is None`,
 * returns without writing anything, and the refusal VANISHES -- S4's "denials
 * are never silent" broken by the fix for S4. The condition is therefore:
 * close the gap and the row at the same time, or not at all.
 *
 * THERE IS A THIRD ANSWER AND IT IS NEITHER QUESTION. A source this class
 * cannot recognise -- `Source.UNATTRIBUTED`, or a null -- is REFUSED here
 * without asking Policy anything. The lenient branch is chosen for a human
 * whose deliberate act it is; "we could not work out who is driving" is a code
 * failure or a change in Burp, and defaulting it to the branch that drops four
 * of the five rules is a fail-open dressed as a default.
 */
public final class ProxyGate {
    private final Policy policy;

    /**
     * One Policy, and it carries the Gate. The rate limit and the budget live
     * inside the Policy this is constructed with (see {@link Policy#Policy}),
     * so a caller cannot hand this class a second Gate and end up spending two
     * budgets for one request -- and the operator branch spends neither,
     * because the question it asks stops before the Gate is reached.
     */
    public ProxyGate(Policy policy) {
        this.policy = policy;
    }

    public record Verdict(boolean allow, String errorClass, String detail) {
        static Verdict pass() { return new Verdict(true, null, null); }
        static Verdict deny(Decision d) {
            return new Verdict(false, d.errorClass(), d.detail());
        }
    }

    /**
     * @param auth   read ONCE by the caller and passed in, never fetched here.
     *               `configEpoch()` and `scopeConfig()` are two reads of one
     *               record and can straddle a commit; a decision made from two
     *               halves of different authorisations is a decision about a
     *               request nobody authorised.
     */
    public Verdict decide(HxRequest req, BridgeClient.Authorisation auth,
                          Source source) {
        if (auth == null || auth.epoch() == 0) {
            // DENY-ALL is the initial and terminal state, at BOTH points, and
            // this copy of it is REDUNDANT with the one inside Policy: both
            // questions below refuse an epoch-0 authorisation on their own, so
            // with these three lines deleted the three `DENY-ALL holds for`
            // checks in ProxyGateTest -- one per Source constant -- stay
            // green. Re-measured on this tree after the third constant was
            // added: 9 x ALL PASS + 1 FAILURE, 1652 ok, and the single FAIL is
            // an NPE out of unconfiguredRefusesBoth, not a check saying an
            // unconfigured extension allowed something. (Row D of this task's
            // sabotage table measured the same mutation when Source had two
            // constants.) What these lines change is WHEN the answer is given:
            // here, before the Policy reference is touched at all. The input
            // that separates the two is a ProxyGate holding no Policy, which
            // is where that NPE comes from and what ProxyGateTest uses it for.
            //
            // `== 0`, not `< 1`, at BOTH enforcement points (the other copy is
            // Policy.unusable). That is a REACHABILITY argument and not a
            // range check: epoch is a long, and a hand-built
            // `new Authorisation(-1, scope)` is treated as CONFIGURED and
            // decided under, here and there alike -- measured. Nothing in this
            // tree can produce one, because BridgeClient's counter is
            // pre-incremented from 0 and is the only writer of the field, so
            // the inherited shape is kept and the reachability is written down
            // rather than left for the next reader to re-derive.
            return new Verdict(false, "not_configured",
                               "no configure frame acknowledged yet");
        }
        if (source != Source.OPERATOR && source != Source.CRAWLER) {
            // UNATTRIBUTED, null, and anything a later constant adds. Written
            // as "not one of the two I know" rather than as
            // `source == Source.UNATTRIBUTED`, because the enum is CLOSED and
            // a fourth constant added later would otherwise fall into
            // whichever branch it was not named in -- and the operator branch
            // is the one it would fall into.
            //
            // Two separating inputs, both in ProxyGateTest and both ALLOWED
            // before this guard existed, measured: `POST /login` (no
            // method_denied on the operator branch) and `GET /logout` (no
            // dangerous_denied), each with source UNATTRIBUTED and again with
            // a null. The control is that the same two requests are still
            // allowed for Source.OPERATOR -- theOperatorIsNotMethodChecked and
            // theOperatorIsNotDangerousPathChecked -- so what these pin is
            // attribution, not the rules.
            //
            // The CLASS is `not_configured`, reusing S6's documented overload
            // rather than minting a wire class from a call site that does not
            // exist yet. The detail carries BridgeClient.EXTENSION_FAULT --
            // the prefix records.py declares as its own constant, pinned
            // byte-identical across the two languages by
            // test_the_extension_fault_marker_is_the_same_string_on_both_sides
            // -- because "this jar could not tell who was driving" is the same
            // kind of thing as "this jar has no send handler" and not the same
            // kind as "the operator never configured a run".
            //
            // A class of its own is Task 7's to settle when it wires the
            // recording: a new class needs a row to go in
            // (tests/test_records.py) and there is nothing to record from
            // here yet. Worth knowing before minting one HERE, and it is not
            // an argument for doing so: that test derives the class set by
            // scanning for `Decision.deny("...")` and `error(f, "...")`, and
            // this file's spelling is `new Verdict(false, "...")` -- which it
            // does not scan, for this line or for the epoch-0 one above. A
            // class introduced here would be invisible to the check that
            // exists to catch a denial with nowhere to go.
            return new Verdict(false, "not_configured",
                               BridgeClient.EXTENSION_FAULT
                               + "the proxy listener could not be attributed "
                               + "to the operator or the crawler");
        }
        if (source == Source.CRAWLER) {
            // The agent's rules, in S4's pinned order, Gate included -- plus
            // render.allow, which exists so that dropping a third-party
            // bundle does not silently stop the page under test from booting.
            Decision d = policy.decideCrawl(req, auth);
            return d.allowed() ? Verdict.pass() : Verdict.deny(d);
        }
        // The operator: scope, and nothing after it. Not a weaker call of the
        // same question -- a different question, which is why it is a sibling
        // method on Policy rather than a flag passed to `decide`. It does not
        // reach the Gate, so an operator's browsing spends no rate token and
        // no budget slot; the pair of counting checks in ProxyGateTest is what
        // separates that from a gate that ignores source entirely.
        Decision d = policy.decideScopeOnly(req, auth);
        return d.allowed() ? Verdict.pass() : Verdict.deny(d);
    }
}
```

- [ ] **Step 5: Add `decideScopeOnly` to `Policy`**

`Policy` currently exposes `decide(req, auth)`, which runs the full order, and the two halves `decideBeforeGate` / `checkGate` that the send path interleaves §7's credential refusal between. Add a third sibling that stops after scope. It must fail closed on its own — an epoch-0 or unreadable `Authorisation` is `not_configured` here as it is in `decideBeforeGate` — so the `not_configured` preamble is extracted into a private `unusable(auth)` and both call it. Two copies is where a fail-open drifts in: the one nobody edited answers `allowed()` for an authorisation the other refuses.

The shipped text of all three is in the whole-file `Policy.java` block of `docs/superpowers/plans/2026-08-22-enforcement-send-path.md`, which is the block the drift check compares (that plan is merged, so its blocks are **not** skipped). Sync it there, not here:

```bash
./scripts/sync_plan_block.py docs/superpowers/plans/2026-08-22-enforcement-send-path.md \
    extension/src/hx/policy/Policy.java
```

`ChokepointTest.bothHalvesOfTheDecisionAreAskedAndOnlyOnce` counts `.decideBeforeGate(` and `.checkGate(` and requires one of each. `ProxyGate` therefore calls **`decide`**, not the halves — a second call site of either turns that check red, and `decide` is documented as the right call for a caller with nothing to interleave.

- [ ] **Step 6: Register the test class**

Add `hx.proxy.ProxyGateTest` to `CLASSES` in `extension/test.sh`. The suite goes from nine summary lines to ten; every later step judges by ten.

- [ ] **Step 7: Run to verify it passes**

Run: `./extension/test.sh`
Expected: 10 × `ALL PASS`, no FAIL, no SKIP.

- [ ] **Step 8: Sabotage — seven rows, each judged by the ten summary lines**

| # | Edit | Went red (measured, 9 × ALL PASS + 1 FAILURE each) |
|---|---|---|
| A | `decide` returns `Verdict.pass()` for `Source.OPERATOR` unconditionally | 2 — `out of scope is refused even for the operator`, `and the class names the boundary crossed` |
| B | `Source.CRAWLER` takes the operator branch | 5 — the crawler's method pair, its dangerous-path pair, and `crawling does (0)` |
| C | `Source.OPERATOR` takes the crawler branch | 3 — the operator's POST, their logout click, and `browsing does not spend the run's budget (1)` |
| D | drop the `auth.epoch() == 0` guard in `ProxyGate` | 1 — and **not** the four `DENY-ALL holds for` checks, which stayed green: `Policy` refuses epoch 0 on both paths this class calls, so the guard is redundant *for the verdict* and load-bearing only for *when* it is given. The separating input is a `ProxyGate` holding no `Policy`; it turns an NPE (a named FAIL under `TestSupport.t`) into a verdict |
| E | `forListenerPort` drops the `crawlerPort > 0` clause | 1 — `and two absences do not agree their way into CRAWLER` (`forListenerPort(0, 0)`). `forListenerPort(8080, 0)` does **not** separate the clause from its absence and stayed green |
| F | `forListenerPort` returns `CRAWLER` for an unknown port | 4 — every check in `theListenerPortDecides` except the crawler port's own |
| G | add `http://evil.test/*` to the fixture's `scope.include` — the request the two scope checks exist to see refused, now authorised | 3 — both scope checks and the operator's error class. **Re-run with the fixture's host hard-coded back to `"app.test"` instead of taken from the url: 10 × ALL PASS, 0 FAIL.** The hard-coded host is the shape Step 1's block shipped with, and under it Policy answers those checks by its url-authority-vs-connection-host comparison before any include is matched, so they hold whatever `scope.include` says. The fixture derives the host from the url for that reason |

Name the expected sha256 to your harness before you start so it refuses a polluted tree, back up by **copy**, and re-verify the hash on restore.

- [ ] **Step 9: Sync the plan blocks and commit**

```bash
./scripts/sync_plan_block.py docs/superpowers/plans/2026-08-24-traffic-capture.md \
    extension/src/hx/proxy/Source.java extension/src/hx/proxy/ProxyGate.java \
    extension/test/hx/proxy/ProxyGateTest.java
.venv/bin/pytest tests/test_plan_matches_repo.py -q
git add extension/ docs/superpowers/plans/2026-08-24-traffic-capture.md
git commit -m "feat(proxy): the second enforcement point decides"
```

---

### Task 6: `Capture` and the two-body frame

The bounded queue, and the frame that carries an exchange's two halves.

**The one rule this task exists to honour:** capture never blocks the browser. §4 — *a wedged harness, a full queue or a dropped record changes what `hx` KNOWS, never what it ALLOWS.* The extension sits in the request path of a real person's browser during a live engagement, possibly against a production system. A harness bug must not become an incident on the client's application.

**And its converse:** a drop is never silent. It is counted, reported over the bridge, and lands in `run.dropped_total`, because a report that quietly claims coverage it does not have is the failure this project cares most about.

**Files:**
- Create: `extension/src/hx/proxy/Observed.java`, `extension/src/hx/proxy/Capture.java`
- Create: `extension/test/hx/proxy/CaptureTest.java`
- Modify: `extension/src/hx/bridge/Frame.java` (two-body encode/decode), `extension/src/hx/bridge/BridgeClient.java` (`exchangeSink()`), `extension/test.sh`

**Interfaces:**
- Consumes: `hx.send.Redactor` — `redactRequest(byte[], Injected)`, `redactResponse(byte[])`; `hx.bridge.Frame`
- Produces:
  - `record Observed(String method, String url, int status, long ms, byte[] request, byte[] response, Source source)`
  - `Capture(int capacity, ExchangeSink sink)` with `void offer(Observed o)`, `long dropped()`, `void start()`, `void stop()`
  - `interface Capture.ExchangeSink { void exchange(Map<String,Object> header, byte[] req, byte[] resp); void dropped(long n, Source source); }`
  - `BridgeClient.exchangeSink()` returning an `ExchangeSink` that frames and writes

- [ ] **Step 1: Write the failing test**

```java
// extension/test/hx/proxy/CaptureTest.java
package hx.proxy;

import hx.TestSupport;
import hx.bridge.BridgeClient;

import java.util.*;
import java.util.concurrent.*;

/**
 * The queue, and specifically the two things it must never do: block the
 * caller, and lose a record silently.
 *
 * Hand-rolled runner, like the other eleven classes: JUnit would be a
 * dependency, and this jar has none.
 */
public class CaptureTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(CaptureTest::check, name, body);
    }

    public static void main(String[] args) throws Exception {
        t("an offer reaches the sink", CaptureTest::anOfferReachesTheSink);
        t("offering never blocks, even with no sink draining",
          CaptureTest::offeringNeverBlocks);
        t("a full queue drops the OLDEST, not the newest",
          CaptureTest::aFullQueueDropsTheOldest);
        t("and every drop is counted", CaptureTest::everyDropIsCounted);
        t("and reported, not merely counted", CaptureTest::dropsAreReported);
        t("a drop is reported even when nothing follows it",
          CaptureTest::dropsAreReportedWithNothingBehindThem);
        t("each source's drops are reported against that source",
          CaptureTest::dropsAreReportedPerSource);
        t("a source with no spelling is refused, not filed as the operator",
          CaptureTest::anUnattributedRecordIsRefusedAndCounted);
        t("the header says what the harness reads",
          CaptureTest::theHeaderCarriesWhatTheConsumerReads);
        t("the outcome comes from the record, not from a literal",
          CaptureTest::theOutcomeComesFromTheRecord);
        t("a sink that throws does not kill the drain thread",
          CaptureTest::aThrowingSinkDoesNotKillTheDrain);
        t("a drop report that throws does not kill it either",
          CaptureTest::aThrowingDropReportDoesNotKillTheDrain);
        t("the drain thread is a daemon", CaptureTest::theDrainIsADaemon);
        t("stop() does not hang on a wedged sink, and ends the drain",
          CaptureTest::stopDoesNotHang);
        t("stop() counts and reports what it throws away",
          CaptureTest::stopFlushesWhatItThrowsAway);
        t("an offer after stop() is counted, not swallowed",
          CaptureTest::offerAfterStopIsCountedNotSwallowed);
        t("offers racing stop() are every one of them accounted for",
          CaptureTest::offersRacingStopAreAllAccountedFor);
        t("stop() then start() does not re-report the cumulative count",
          CaptureTest::stopThenStartDoesNotReReportTheCount);
        t("start() twice leaves one drain and one report",
          CaptureTest::startTwiceLeavesOneDrain);
        t("an exchange the sink would not take is a drop",
          CaptureTest::anUndeliveredExchangeIsCountedAsADrop);
        t("a drop report that answers 'not delivered' is retried in full",
          CaptureTest::aDropReportThatSaysNotDeliveredIsRetriedInFull);
        t("a denial is a frame of its own, with the keys the consumer reads",
          CaptureTest::aDenialIsItsOwnFrame);
        t("a denial the sink would not take is a drop against ITS source",
          CaptureTest::anUndeliveredDenialIsCountedAgainstItsOwnSource);
        t("a denial with no spelling is refused, like an exchange with none",
          CaptureTest::aDeniedRecordWithNoSpellingIsRefusedTheSameWay);
        t("countLost is charged to the source it is given",
          CaptureTest::countLostIsChargedToTheSourceItIsGiven);

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    // ---- fixtures -------------------------------------------------------

    static Observed obs(int n) {
        return obs(n, Source.OPERATOR);
    }

    static Observed obs(int n, Source s) {
        return new Observed("GET", "http://app.test/" + n, 200, "ok", 5L,
                            ("req" + n).getBytes(), ("resp" + n).getBytes(), s);
    }

    /** One refused request, as the proxy handler offers it. */
    static Denied den(int n, Source s) {
        return new Denied("POST", "http://app.test/refused/" + n,
                          "scope_denied", "detail " + n, s);
    }

    static final class Recording implements BridgeClient.ExchangeSink {
        final List<String> seen = Collections.synchronizedList(new ArrayList<>());
        final List<Long> drops = Collections.synchronizedList(new ArrayList<>());
        final List<String> dropSources =
                Collections.synchronizedList(new ArrayList<>());
        final List<Map<String, Object>> headers =
                Collections.synchronizedList(new ArrayList<>());
        /** Denial frames, kept apart from {@link #headers} so a denial routed
         *  through `exchange(...)` -- the naming lie this interface's third
         *  method exists to prevent -- cannot satisfy a check about denials. */
        final List<Map<String, Object>> denials =
                Collections.synchronizedList(new ArrayList<>());
        volatile CountDownLatch gate;
        volatile boolean throwOnce;
        volatile boolean throwOnDropOnce;
        volatile boolean refuseDenial;
        /** RETURN false rather than throw -- the production sink's shape.
         *  BridgeClient.exchangeSink catches its own IOException, so "the
         *  sink threw" is the case that never happens on the wire and "the
         *  sink returned without delivering" is the case that always does. */
        volatile boolean refuseExchange;
        volatile boolean refuseDropOnce;

        public boolean exchange(Map<String, Object> h, byte[] req, byte[] resp) {
            if (gate != null) { try { gate.await(); } catch (InterruptedException e) { return false; } }
            if (throwOnce) { throwOnce = false; throw new RuntimeException("sink"); }
            if (refuseExchange) return false;
            headers.add(new LinkedHashMap<>(h));
            seen.add(String.valueOf(h.get("url")));
            return true;
        }

        public boolean dropped(long n, String s) {
            if (throwOnDropOnce) { throwOnDropOnce = false; throw new RuntimeException("drop"); }
            if (refuseDropOnce) { refuseDropOnce = false; return false; }
            // Both lists appended under ONE monitor, and read back under the
            // same one: `reported()` pairs them by index, and two independent
            // synchronized lists let a reader see a count whose source has not
            // landed yet.
            synchronized (drops) {
                drops.add(n);
                dropSources.add(s);
            }
            return true;
        }

        public boolean denial(Map<String, Object> h) {
            if (refuseDenial) return false;
            denials.add(new LinkedHashMap<>(h));
            return true;
        }
    }

    /**
     * How long an offer gets before it is called blocked.
     *
     * EVERY offer in this class goes through {@link #offerAll}, and that is
     * the third truncation TestSupport.t's docstring names, met head on. An
     * offer that BLOCKS parks its test method forever: the class prints no
     * summary line at all, returns no exit code, and test.sh's `timeout 300`
     * kills it from outside -- which under `./test.sh | grep -c FAIL` reads
     * as ZERO FAILURES. Measured on this file: replacing the eviction loop
     * with `queue.put(o)` -- the mutation "offer blocks instead of evicting",
     * the ONE rule this class exists for -- took the suite from eleven
     * summary lines to TEN, with no FAIL line anywhere and every method after
     * the first blocking offer unrun. A guard that can only be observed by
     * counting summary lines is a guard one careless `grep` walks past.
     *
     * Five seconds: five times the 1 s bound offeringNeverBlocks asserts, so
     * it can only fire on a genuine block, and small enough that six of them
     * in a row stay well inside test.sh's 300 s backstop.
     */
    static final long OFFER_DEADLINE_MS = 5000L;

    /**
     * Offer, with a deadline on it. Throws rather than checks: a throw out of
     * a test method becomes a NAMED FAIL against that method through
     * {@link hx.TestSupport#t}, which is what the truncation above cost.
     *
     * The offering thread is a DAEMON and is deliberately left parked when the
     * deadline expires. Interrupting it would work -- `put` is interruptible --
     * and would hide the very thing being reported: the next assertion in the
     * test method would then run against a queue the mutant had quietly
     * finished filling. A leaked parked daemon costs nothing, because a daemon
     * cannot hold the JVM up after main() prints its summary.
     */
    static void offerAll(Capture c, Captured... records) throws Exception {
        Thread th = new Thread(() -> { for (Captured o : records) c.offer(o); });
        th.setDaemon(true);
        th.start();
        th.join(OFFER_DEADLINE_MS);
        if (th.isAlive())
            throw new AssertionError(
                "offer() had not returned after " + OFFER_DEADLINE_MS
                + " ms, so it BLOCKED -- the one thing this class exists to "
                + "forbid, because the caller is the request path of a real "
                + "person's browser");
    }

    /** `offerAll` over obs(0)..obs(n-1). */
    static void offerRange(Capture c, int n) throws Exception {
        Observed[] all = new Observed[n];
        for (int i = 0; i < n; i++) all[i] = obs(i);
        offerAll(c, all);
    }

    interface Cond { boolean ok(); }

    /** Five seconds, the same bound BridgeClientTest.waitUntil carries. Every
     *  wait here is for a DAEMON drain thread, so a condition that never
     *  becomes true would otherwise park this method until test.sh's 300 s
     *  backstop killed the class with no summary line printed -- which under
     *  `grep -c FAIL` reads as zero failures. */
    static void waitUntil(Cond c) throws Exception {
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            if (c.ok()) return;
            Thread.sleep(10);
        }
    }

    /** Everything the sink was told was dropped, for one source -- named by
     *  the spelling that crosses the bridge, `null` for a source that has
     *  none. */
    static long reported(Recording sink, String s) {
        long total = 0;
        synchronized (sink.drops) {
            for (int i = 0; i < sink.drops.size(); i++)
                if (Objects.equals(sink.dropSources.get(i), s))
                    total += sink.drops.get(i);
        }
        return total;
    }

    /** Everything the sink was told was dropped, whatever the source. */
    static long reportedTotal(Recording sink) {
        long total = 0;
        synchronized (sink.drops) {
            for (Long n : sink.drops) total += n;
        }
        return total;
    }

    /**
     * The live drain, found by the name {@link Capture#start} gives it.
     *
     * BY NAME, so it cannot tell a leaked drain from the live one -- which is
     * why every assertion about a STOPPED drain below is made against a
     * captured thread's IDENTITY (`!found.isAlive()`) and not against this.
     * A test that leaks a wedged daemon hands the next one a thread that
     * answers here; `stopDoesNotHang` used to be that test.
     */
    static Thread drainThread() {
        for (Thread th : Thread.getAllStackTraces().keySet())
            if ("hx-capture".equals(th.getName())) return th;
        return null;
    }

    /** How many live threads carry that name. One is correct; two is a leak,
     *  and drainThread() above cannot tell the difference. */
    static int drainCount() {
        int n = 0;
        for (Thread th : Thread.getAllStackTraces().keySet())
            if ("hx-capture".equals(th.getName()) && th.isAlive()) n++;
        return n;
    }

    // ---- the tests ------------------------------------------------------

    static void anOfferReachesTheSink() throws Exception {
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1));
            waitUntil(() -> sink.seen.size() == 1);
            check("the sink saw it", sink.seen.contains("http://app.test/1"));
        } finally { c.stop(); }
    }

    static void offeringNeverBlocks() throws Exception {
        // No drain thread at all: offer must still return promptly. This is
        // the property the operator's browser depends on.
        Capture c = new Capture(4, new Recording());
        long start = System.nanoTime();
        offerRange(c, 1000);
        long ms = (System.nanoTime() - start) / 1_000_000;
        check("1000 offers with nothing draining took " + ms + " ms", ms < 1000);
    }

    static void aFullQueueDropsTheOldest() throws Exception {
        // EVERY offer happens before the drain exists, and that is not
        // tidiness. Started first, the drain takes the head of the queue into
        // a wedged sink BEFORE the overflow begins, so the oldest record is
        // already out of the queue, is delivered when the sink unwedges, and
        // "the oldest did not survive" fails against correct code roughly one
        // run in three -- measured on this file. A test whose result depends
        // on which thread wins is a test that cannot say what eviction order
        // the queue has.
        Recording sink = new Recording();
        Capture c = new Capture(2, sink);
        offerRange(c, 6);
        c.start();
        try {
            waitUntil(() -> sink.seen.size() >= 2);
            Thread.sleep(50);
            // The NEWEST survive. Oldest-first is the right eviction for
            // traffic: the recent requests are the ones an operator is
            // looking at, and the old ones are the ones already reasoned
            // about.
            check("exactly the queue's worth survived (" + sink.seen + ")",
                  sink.seen.size() == 2);
            check("the newest survived (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/5"));
            check("and the one before it", sink.seen.contains("http://app.test/4"));
            check("and the oldest did not",
                  !sink.seen.contains("http://app.test/0"));
        } finally { c.stop(); }
    }

    static void everyDropIsCounted() throws Exception {
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(2, sink);
        try {
            offerRange(c, 10);
            check("dropped() counts them (" + c.dropped() + ")", c.dropped() > 0);
        } finally { sink.gate.countDown(); c.stop(); }
    }

    static void dropsAreReported() throws Exception {
        // Counted is not enough: S5 says a run with drops has coverage
        // numbers that are a floor, and nothing on the Python side can know
        // that unless the number crosses the bridge.
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(2, sink);
        c.start();
        try {
            offerRange(c, 10);
            sink.gate.countDown();
            waitUntil(() -> !sink.drops.isEmpty());
            check("the sink was told (" + sink.drops + ")", !sink.drops.isEmpty());
            long total = 0;
            for (Long n : sink.drops) total += n;
            check("and told the whole count, not a token one (" + total
                  + " reported, " + c.dropped() + " counted)",
                  total == c.dropped());
        } finally { c.stop(); }
    }

    static void dropsAreReportedWithNothingBehindThem() throws Exception {
        // THE INPUT THAT SEPARATES `poll(POLL_MS)` FROM `take()`, and finding
        // it took a measurement that came out the wrong way. The obvious
        // version -- overflow a queue, let the drain empty it, assert the
        // report arrived -- separates NOTHING: an EVICTION always leaves the
        // evicting record in the queue behind it, so a take()-parked drain is
        // woken by that record and reports on its way past. Measured: with
        // `take()` in place of the poll, that version stayed green.
        //
        // The refusal path is different in exactly the way that matters. An
        // unattributed record is counted and NOT enqueued, so a drop can be
        // the last thing that ever happens -- and a take()-parked drain then
        // sleeps on it forever. Which is the moment the report is most needed:
        // a saturated harness is what makes an operator stop browsing, and
        // "traffic stopped" is precisely "no record behind it".
        Recording sink = new Recording();
        Capture c = new Capture(4, sink);
        c.start();
        try {
            // Drain the queue first, so the drain is parked and idle.
            offerAll(c, obs(1));
            waitUntil(() -> sink.seen.size() == 1);
            check("the drain is idle with an empty queue", sink.seen.size() == 1);

            offerAll(c, obs(2, Source.UNATTRIBUTED));
            waitUntil(() -> !sink.drops.isEmpty());
            long total = 0;
            for (Long n : sink.drops) total += n;
            check("the drop was reported with nothing following it ("
                  + sink.drops + ")", total == 1);

        } finally { c.stop(); }

        // And the eviction path reports too -- behaviour, not a separator:
        // this half stays green under `take()`, and is kept as a pin on the
        // answer rather than dressed up as more than it is.
        //
        // ITS OWN CAPTURE, AND NOT STARTED UNTIL THE QUEUE HAS OVERFLOWED.
        // This assertion used to share the capture above and offer six
        // records at a live drain, which made an eviction a RACE the drain
        // had no reason to lose: `loop()` polls one record per iteration and
        // delivers it, so a drain that keeps up leaves `queue.offer` never
        // returning false, nothing evicted, `dropped()` still 1, and the
        // wait spinning out. MEASURED on 2026-09-02 -- four CI runs on
        // byte-identical Java, three green and one red, and reproduced here
        // at 2 failures in 12 with the JVM pinned to a single core
        // (`taskset -c 0`), which is the shape of a two-core runner. On 24
        // cores it never failed in 15 runs under full load, which is why it
        // read as unreproducible.
        //
        // `accepting` is true from construction, so an UNSTARTED capture
        // takes offers into its queue with nothing draining them: six
        // records into a queue of four evicts exactly two, by arithmetic
        // rather than by scheduling. `start()` then reports them, because
        // `loop()` calls `reportOutstanding()` on every iteration whether or
        // not it polled a record.
        Recording evicting = new Recording();
        Capture e = new Capture(4, evicting);
        offerAll(e, obs(3), obs(4), obs(5), obs(6), obs(7), obs(8));
        check("six records into a queue of four evicted two, before any "
              + "drain existed to race (" + e.dropped() + ")",
              e.dropped() == 2);
        e.start();
        try {
            waitUntil(() -> reported(evicting, "operator") > 0);
            check("and an evicted record's drop is reported as well ("
                  + evicting.drops + ")", reported(evicting, "operator") > 0);
        } finally { e.stop(); }
    }

    static void dropsAreReportedPerSource() throws Exception {
        // One counter with one source attached would file the crawler's drops
        // against whichever source happened to be reported -- and the far side
        // turns that string into a run KIND, so the wrong run's coverage is
        // the number an operator reads.
        Recording sink = new Recording();
        Capture c = new Capture(2, sink);
        // Offered before the drain exists, for the same reason as
        // aFullQueueDropsTheOldest: a drain that takes records while the
        // offers run changes WHICH source each eviction charges.
        offerAll(c, obs(0, Source.OPERATOR), obs(1, Source.OPERATOR),
                 obs(2, Source.OPERATOR), obs(3, Source.OPERATOR),
                 obs(4, Source.OPERATOR));
        offerAll(c, obs(0, Source.CRAWLER), obs(1, Source.CRAWLER),
                 obs(2, Source.CRAWLER), obs(3, Source.CRAWLER),
                 obs(4, Source.CRAWLER));
        // Ten offers into a queue of two: five of the operator's records are
        // evicted (three by later operator records, two by the crawler's
        // first two) and three of the crawler's.
        check("eight records were evicted in all (" + c.dropped() + ")",
              c.dropped() == 8);
        c.start();
        try {
            waitUntil(() -> sink.dropSources.contains("operator")
                            && sink.dropSources.contains("crawler"));
            check("the operator's five were reported against the operator ("
                  + reported(sink, "operator") + ")",
                  reported(sink, "operator") == 5);
            check("and the crawler's three against the crawler ("
                  + reported(sink, "crawler") + ")",
                  reported(sink, "crawler") == 3);
        } finally { c.stop(); }
    }

    static void anUnattributedRecordIsRefusedAndCounted() throws Exception {
        // ProxyGate refuses UNATTRIBUTED, so one should never reach here. If
        // one does it must not become an exchange row: `hx.capture._run` reads
        // "crawler" or anything-else, so any string this could emit files the
        // record under the operator's run -- traffic attributed to a human who
        // did not make it, and a request that never left in the first place.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1, Source.UNATTRIBUTED), obs(2, Source.OPERATOR));
            waitUntil(() -> sink.seen.size() == 1);
            Thread.sleep(50);
            check("the attributed record arrived (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/2"));
            check("and the unattributed one did not",
                  !sink.seen.contains("http://app.test/1"));
            waitUntil(() -> !sink.drops.isEmpty());
            check("refused is not discarded: it was counted (" + c.dropped() + ")",
                  c.dropped() == 1);
            // A NULL source, not the operator's spelling. The sink now takes a
            // String, so "no spelling" travels as null -- and null must not
            // become "operator" on this side of the interface any more than it
            // was allowed to on the other.
            check("and reported with NO spelling, not as the operator ("
                  + sink.dropSources + ")",
                  sink.dropSources.contains(null)
                  && !sink.dropSources.contains("operator"));
            check("and sourceName has no spelling for it",
                  Capture.sourceName(Source.UNATTRIBUTED) == null);
        } finally { c.stop(); }
    }

    static void theHeaderCarriesWhatTheConsumerReads() throws Exception {
        // hx/capture.py's EXCHANGE path reads these keys, and REFUSES an unknown `t`,
        // an unknown `via`, an unknown `outcome`, a missing `url` and a
        // non-integer `ms`. A header this side gets wrong is not a wrong row:
        // it is a ValueError on the read thread and no row at all.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, new Observed("POST", "http://app.test/login", 302, "ok",
                                     41L, "req".getBytes(), "resp".getBytes(),
                                     Source.CRAWLER));
            waitUntil(() -> sink.headers.size() == 1);
            Map<String, Object> h = sink.headers.get(0);
            check("t is the frame type hx.capture.FRAME_TYPES names ("
                  + h.get("t") + ")", "exchange".equals(h.get("t")));
            check("via is one of records.VIA_VALUES (" + h.get("via") + ")",
                  "proxy".equals(h.get("via")));
            check("source is the crawler's spelling (" + h.get("source") + ")",
                  "crawler".equals(h.get("source")));
            check("method survives (" + h.get("method") + ")",
                  "POST".equals(h.get("method")));
            check("url survives, and it has no default on the far side ("
                  + h.get("url") + ")",
                  "http://app.test/login".equals(h.get("url")));
            check("status is an integer, not a string (" + h.get("status") + ")",
                  Long.valueOf(302L).equals(h.get("status")));
            check("ms is an integer, not a string (" + h.get("ms") + ")",
                  Long.valueOf(41L).equals(h.get("ms")));
            check("outcome is in records.EXCHANGE_OUTCOMES (" + h.get("outcome") + ")",
                  "ok".equals(h.get("outcome")));
        } finally { c.stop(); }
    }

    /**
     * THE OUTCOME IS THE RECORD'S, NOT A LITERAL THIS CLASS WRITES.
     *
     * `deliverExchange` hardcoded `h.put("outcome", "ok")` -- the ONLY
     * `outcome` write on the whole proxy path -- so every proxy exchange was
     * filed healthy whatever its bytes said. The method above cannot see that:
     * its fixture is a healthy 302, so `"ok"` is the right answer for the
     * wrong reason and a hardcoded literal passes it.
     *
     * THE SEPARATING INPUT IS AN UNHEALTHY RECORD, and it is S5's shape:
     * `status=599` with `outcome='status_unreadable'`, which is what
     * {@link Recorder} produces for a `103 Early Hints` in front of a dead
     * origin. With the literal back, this method reads `ok` on a 599 -- the
     * pair `record_exchange`'s coherence guard exists to refuse, and the pair
     * that hands S4's auto-halt a healthy sample for a failing request.
     *
     * The 599 goes on `status` too, so the two travel as one answer: S5 makes
     * `status_unreadable` legal only beside 599, and a row carrying one
     * without the other is refused on the far side rather than written wrong.
     *
     * WHAT THIS DOES NOT PIN: that the SCAN is right, or that it runs. This
     * class builds the record by hand.
     * `RecorderTest.theStatusIsScannedOutOfTheBytesWithItsOutcome` drives the
     * scan over real bytes; between them the answer is computed from the bytes
     * and carried to the wire unchanged.
     */
    static void theOutcomeComesFromTheRecord() throws Exception {
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, new Observed("GET", "http://app.test/slow", 599,
                                     "status_unreadable", 12L,
                                     "req".getBytes(), "resp".getBytes(),
                                     Source.OPERATOR));
            waitUntil(() -> sink.headers.size() == 1);
            Map<String, Object> h = sink.headers.get(0);
            check("an unreadable exchange is NOT filed as healthy ("
                  + h.get("outcome") + ")",
                  "status_unreadable".equals(h.get("outcome")));
            check("and it carries the sentinel S5 pairs that outcome with ("
                  + h.get("status") + ")",
                  Long.valueOf(599L).equals(h.get("status")));
        } finally { c.stop(); }
    }

    static void aThrowingSinkDoesNotKillTheDrain() throws Exception {
        Recording sink = new Recording();
        sink.throwOnce = true;
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1), obs(2));
            waitUntil(() -> sink.seen.size() == 1);
            check("the record after the throw still arrived (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/2"));
        } finally { c.stop(); }
    }

    static void aThrowingDropReportDoesNotKillTheDrain() throws Exception {
        // The drop report is the other call into someone else's code, and a
        // throw out of it used to be the same fatality. The count is
        // cumulative, so the retry has to carry the whole outstanding total
        // rather than only what accrued since.
        Recording sink = new Recording();
        sink.throwOnDropOnce = true;
        Capture c = new Capture(1, sink);
        offerRange(c, 4);                             // 3 dropped
        c.start();
        try {
            waitUntil(() -> !sink.drops.isEmpty());
            long total = 0;
            for (Long n : sink.drops) total += n;
            check("the failed report was retried in full (" + sink.drops + ")",
                  total == 3);
            offerAll(c, obs(9));
            waitUntil(() -> sink.seen.contains("http://app.test/9"));
            check("and the drain is still delivering exchanges (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/9"));
        } finally { c.stop(); }
    }

    static void theDrainIsADaemon() throws Exception {
        // A non-daemon drain holds the JVM -- and inside Burp that is an
        // unloaded extension keeping the process alive on a thread nobody can
        // see. stop() is the polite path; this is what happens when it is not
        // reached, which is every crash and every hard unload.
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);   // never released: the drain is wedged
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1));
            waitUntil(() -> drainThread() != null);
            Thread found = drainThread();
            check("the drain thread exists and is named", found != null);
            check("and it is a daemon", found != null && found.isDaemon());
        } finally { sink.gate.countDown(); c.stop(); }
    }

    static void stopDoesNotHang() throws Exception {
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(8, sink);
        c.start();
        Thread found;
        try {
            offerAll(c, obs(1));
            // The drain has to be INSIDE the wedged sink before stop() is
            // called. Without this the queue may still be undrained, stop()
            // returns in microseconds, and the check passes against a drain
            // that was never wedged at all -- a green that measures the
            // scheduler.
            waitUntil(() -> {
                Thread d = drainThread();
                // WAITING and not TIMED_WAITING: an untaken record leaves the
                // drain in `queue.poll(POLL_MS, ...)`, which is TIMED_WAITING.
                // Only the wedged sink's `gate.await()` is WAITING.
                return d != null && d.getState() == Thread.State.WAITING;
            });
            found = drainThread();
            long start = System.nanoTime();
            c.stop();
            long ms = (System.nanoTime() - start) / 1_000_000;
            // Unloading the extension must not hang Burp. Same bound and same
            // reason as HaltSwitch.STOP_JOIN_MS.
            check("stop() returned in " + ms + " ms", ms < 4000);
            // AND THE DRAIN IS GONE, which is the half `ms < 4000` cannot see:
            // `join(STOP_JOIN_MS)` returns after two seconds whether or not
            // the thread ever died, so deleting `t.interrupt()` from stop()
            // left this class fully green -- 11 ALL PASS, 0 FAIL -- with one
            // live `hx-capture` daemon per call, each polling a queue and
            // calling into a torn-down BridgeClient. Inside Burp that is one
            // per extension reload. Asserted on the CAPTURED thread rather
            // than on drainThread(), which matches by name and so cannot tell
            // a leak from the live one.
            check("...and the drain thread is actually gone",
                  found != null && !found.isAlive());
        } finally {
            // RELEASED, unlike the version this replaced. A gate left closed
            // leaks a wedged daemon named `hx-capture` into every test that
            // runs after it.
            sink.gate.countDown();
            c.stop();
        }
    }

    // ---- what stop() throws away, and what a restart re-reports ----------

    static void stopFlushesWhatItThrowsAway() throws Exception {
        // MEASURED on the version this replaces: 200 records queued into a
        // 512-slot Capture behind a slow sink, then stop() -- delivered=0,
        // dropped()=0, reports=[]. Two hundred exchanges lost and counted as
        // ZERO, on every extension unload and at the end of every run, with
        // run.dropped_total still reading 0. S5 makes that number the reason
        // a run's coverage is a floor; a floor of zero is a claim of
        // completeness.
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);   // the drain wedges on record 1
        Capture c = new Capture(512, sink);
        c.start();
        try {
            offerRange(c, 200);
            // The drain has to be inside the wedged sink, or stop() may find
            // an empty queue and this measures nothing.
            waitUntil(() -> {
                Thread d = drainThread();
                return d != null && d.getState() == Thread.State.WAITING;
            });
            sink.gate.countDown();           // let stop()'s interrupt through
            c.stop();
            // THE PROPERTY, not the ordering. `c.dropped() == 200` was stable
            // over forty sequential and twenty-four eight-way-parallel runs,
            // and it still rests on stop()'s interrupt beating the
            // gate.countDown() two lines up: lose that race and record 1 is
            // DELIVERED instead, giving 199 counted of 200 with nothing at all
            // wrong. What has to hold on both sides of it is that no record is
            // NEITHER delivered nor counted -- and that at least one was
            // counted, because an empty queue here would mean this test
            // measured nothing.
            check("every queued record was counted or delivered, none lost ("
                  + sink.seen.size() + " delivered + " + c.dropped()
                  + " counted, of 200)",
                  sink.seen.size() + c.dropped() == 200 && c.dropped() >= 1);
            check("and the count crossed the sink (" + reportedTotal(sink)
                  + " reported, " + c.dropped() + " counted)",
                  reportedTotal(sink) == c.dropped());
        } finally { sink.gate.countDown(); c.stop(); }
    }

    static void offerAfterStopIsCountedNotSwallowed() throws Exception {
        // MEASURED on the version this replaces: stop(); offer(one record);
        // -- delivered=0, dropped()=0, reports=[]. offer() was gated on
        // nothing, so the record went into a queue with no drain behind it and
        // stayed there, counted nowhere.
        //
        // Not a corner case. Burp unloads the extension while proxy threads
        // are still inside offer(), so those exchanges are lost AND
        // run.dropped_total does not move -- S5's floor reading LOWER than the
        // real loss, which is the one direction the counter exists to close.
        Recording sink = new Recording();
        Capture c = new Capture(512, sink);
        c.start();
        c.stop();
        c.offer(obs(1));
        check("a record offered after stop() is counted (" + c.dropped()
              + " of 1)", c.dropped() == 1);
        check("...and was not delivered behind the operator's back (" + sink.seen + ")",
              sink.seen.isEmpty());
        // Nothing drains after stop(), so the count leaves on the NEXT stop().
        // That is what "idempotent" means here and it is not "a no-op": a
        // second call is how a loss during the unload reaches the far side.
        c.stop();
        check("...and the next stop() carries it across the sink ("
              + reportedTotal(sink) + " reported against " + c.dropped()
              + " counted)", reportedTotal(sink) == c.dropped());
    }

    static void offersRacingStopAreAllAccountedFor() throws Exception {
        // The shape above with the timing it actually has: Burp calls stop()
        // while proxy threads are INSIDE offer(). Nothing here pins which side
        // of the race any one record lands on -- that is the point. What is
        // pinned is the invariant that has to hold on both sides: every record
        // offered either reached the sink or was counted as a drop, and never
        // neither. Before the fix a record could be neither.
        Recording sink = new Recording();
        Capture c = new Capture(512, sink);
        c.start();
        int threads = 4, each = 200;
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> offerers = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int base = i * each;
            Thread w = new Thread(() -> {
                // Bounded, and a DAEMON: a worker that never releases would
                // hold the JVM open after this class printed ALL PASS.
                try {
                    if (!go.await(5000, TimeUnit.MILLISECONDS)) return;
                } catch (InterruptedException e) { return; }
                for (int n = 0; n < each; n++) {
                    c.offer(obs(base + n));
                    // PACED, so the offers straddle stop() instead of all
                    // landing before it. Unpaced, 800 offers are microseconds
                    // of work and finish inside the 10 ms waitUntil poll
                    // below -- and the test then passes on a Capture with the
                    // bug, which is a green measuring the scheduler.
                    try { Thread.sleep(1); } catch (InterruptedException e) { return; }
                }
            });
            w.setDaemon(true);
            offerers.add(w);
            w.start();
        }
        try {
            go.countDown();
            // stop() has to land WHILE they are still offering, or this
            // measures a scheduler that happened to finish first: 800 offers
            // is several times what one drain empties in the time stop() takes,
            // and one delivered record proves the offerers are running.
            waitUntil(() -> !sink.seen.isEmpty());
            c.stop();
            for (Thread w : offerers)
                TestSupport.join(w, 5000, "a proxy thread inside offer()");
            // NO second stop() before the check. A second stop() drains the
            // queue and counts it, so it makes this pass on a Capture that
            // strands every post-stop offer -- measured, 11 ALL PASS with the
            // bug still in. The accounting asserted here has to have been done
            // by offer() itself.
            int total = threads * each;
            check("every record offered across a stop() is delivered or counted"
                  + " (" + sink.seen.size() + " delivered + " + c.dropped()
                  + " dropped, of " + total + ")",
                  sink.seen.size() + c.dropped() == total);
        } finally { c.stop(); }
    }

    static void stopThenStartDoesNotReReportTheCount() throws Exception {
        // `reported[]` was a LOCAL in loop() and `dropped[]` a field, so every
        // restart re-reported the whole cumulative total from zero. Measured:
        // 3 real drops -> [3]; stop(); start(); -> [3, 3], SIX reported
        // against three that happened. `count_drop` accumulates and only
        // refuses n < 1, so the Python side cannot catch it: run.dropped_total
        // inflates without bound across reconnects.
        Recording sink = new Recording();
        Capture c = new Capture(1, sink);
        offerRange(c, 4);                              // 3 evicted
        c.start();
        try {
            waitUntil(() -> reportedTotal(sink) == 3);
            check("three drops, reported once (" + sink.drops + ")",
                  reportedTotal(sink) == 3 && c.dropped() == 3);
            c.stop();
            c.start();
            offerAll(c, obs(9));                       // wake the new drain
            waitUntil(() -> sink.seen.contains("http://app.test/9"));
            Thread.sleep(3 * POLL_SETTLE_MS);
            check("the restart re-reported nothing (" + sink.drops
                  + ", " + reportedTotal(sink) + " reported against "
                  + c.dropped() + " counted)",
                  reportedTotal(sink) == c.dropped());
        } finally { c.stop(); }
    }

    static void startTwiceLeavesOneDrain() throws Exception {
        // A leaked thread rather than an inflated count: the second start()
        // overwrote `drain`, so stop() could never reach the first again -- N
        // extension reloads, N live `hx-capture` daemons, each polling a queue
        // and calling into a torn-down BridgeClient. Counted, not found by
        // name: drainThread() matches on the name they all share, so it
        // answers just as confidently with two of them alive.
        Recording sink = new Recording();
        Capture c = new Capture(4, sink);
        c.start();
        try {
            waitUntil(() -> drainCount() == 1);
            check("one drain to begin with (" + drainCount() + ")",
                  drainCount() == 1);
            c.start();                                 // the second call
            Thread.sleep(3 * POLL_SETTLE_MS);
            check("start() twice is still ONE drain (" + drainCount() + ")",
                  drainCount() == 1);
            offerAll(c, obs(1));
            waitUntil(() -> sink.seen.contains("http://app.test/1"));
            check("and that drain is the one still delivering (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/1"));
        } finally { c.stop(); }
    }

    // ---- the sink says "not delivered" without throwing ------------------

    /** Three drain cycles' worth of settling, for the checks that assert a
     *  report did NOT happen. A negative needs a bound: nothing to wait for
     *  means nothing waitUntil can watch. */
    static final long POLL_SETTLE_MS = Capture.POLL_MS;

    static void anUndeliveredExchangeIsCountedAsADrop() throws Exception {
        // The third way a record is lost, and it used to touch no counter at
        // all: a frame over MAX_FRAME -- a 64 MB download through the proxy --
        // or a socket that died between two requests took
        // `catch (Throwable) { log.error(...) }` and vanished. hx then reported
        // complete coverage for a run that had lost them.
        Recording sink = new Recording();
        sink.refuseExchange = true;
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, obs(1), obs(2), obs(3));
            waitUntil(() -> c.dropped() == 3);
            check("a record the sink would not take is counted ("
                  + c.dropped() + ")", c.dropped() == 3);
            waitUntil(() -> reportedTotal(sink) == 3);
            check("and reported, against its own source ("
                  + sink.drops + " " + sink.dropSources + ")",
                  reported(sink, "operator") == 3);
            check("and nothing was recorded as delivered (" + sink.seen + ")",
                  sink.seen.isEmpty());
        } finally { c.stop(); }
    }

    static void aDropReportThatSaysNotDeliveredIsRetriedInFull() throws Exception {
        // THE PRODUCTION SHAPE, and the one aThrowingDropReportDoesNotKillTheDrain
        // could not reach. BridgeClient.exchangeSink catches its own
        // IOException, logs and returns -- so the only sink that ever SIGNALLED
        // failure was the test's, and against the real one the drain read a
        // failed write as success and advanced `reported` past it. Scenario:
        // the queue saturates while the Python harness restarts, 5,000 drops
        // are counted, the write fails, one line lands in Burp's log, the
        // bridge reconnects, and run.dropped_total reads 0.
        Recording sink = new Recording();
        sink.refuseDropOnce = true;
        Capture c = new Capture(1, sink);
        offerRange(c, 4);                             // 3 dropped
        c.start();
        try {
            waitUntil(() -> !sink.drops.isEmpty());
            check("the report that answered false was retried in full ("
                  + sink.drops + ")", reportedTotal(sink) == 3);
            offerAll(c, obs(9));
            waitUntil(() -> sink.seen.contains("http://app.test/9"));
            check("and the drain is still delivering exchanges (" + sink.seen + ")",
                  sink.seen.contains("http://app.test/9"));
        } finally { c.stop(); }
    }

    // ---- a denial is a record too ----------------------------------------

    static void aDenialIsItsOwnFrame() throws Exception {
        // `hx/capture.py`'s DENIAL arm reads `t`, `via`, `source`, `method`,
        // `url`, `error_class` and `detail`, and it refuses an unknown `t`, an
        // unknown `via` and a missing `url` -- each of which is a ValueError
        // on the bridge's read thread and NO ROW AT ALL, counted as one more
        // drop rather than recorded as the refusal it was.
        //
        // AND IT IS A DENIAL FRAME, not an exchange with two empty bodies.
        // `server.py::_capture` splits two bodies out of an `exchange` and
        // none out of a `denial`; a refusal routed through the exchange arm
        // arrives as a malformed exchange and is dropped.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, new Denied("POST", "http://app.test/account/delete",
                                   "dangerous_denied",
                                   "matches dangerous.path /account/delete",
                                   Source.CRAWLER));
            waitUntil(() -> sink.denials.size() == 1);
            check("it went out as a DENIAL, not through the exchange arm ("
                  + sink.denials.size() + " denials, " + sink.headers.size()
                  + " exchanges)",
                  sink.denials.size() == 1 && sink.headers.isEmpty());
            Map<String, Object> h = sink.denials.get(0);
            check("t is the frame type hx.capture.FRAME_TYPES names ("
                  + h.get("t") + ")", "denial".equals(h.get("t")));
            check("via is one of records.VIA_VALUES (" + h.get("via") + ")",
                  "proxy".equals(h.get("via")));
            check("source is the crawler's spelling (" + h.get("source") + ")",
                  "crawler".equals(h.get("source")));
            check("method survives (" + h.get("method") + ")",
                  "POST".equals(h.get("method")));
            check("url survives, and it has no default on the far side ("
                  + h.get("url") + ")",
                  "http://app.test/account/delete".equals(h.get("url")));
            check("error_class is what records.row_for routes on ("
                  + h.get("error_class") + ")",
                  "dangerous_denied".equals(h.get("error_class")));
            check("detail is what the operator reads (" + h.get("detail") + ")",
                  "matches dangerous.path /account/delete".equals(h.get("detail")));
            // NO EIGHTH KEY. An unknown key is IGNORED on the far side rather
            // than refused, so a key added here with no reader there is a fact
            // the operator never sees and a reason to believe it was recorded.
            // Notably there is no `status`, no `ms` and no `outcome`: a
            // request that never left has no answer for any of the three.
            check("and no eighth key (" + h.keySet() + ")", h.size() == 7);
        } finally { c.stop(); }
    }

    static void anUndeliveredDenialIsCountedAgainstItsOwnSource() throws Exception {
        // The same rule as an undelivered exchange, and it needs its own test
        // because it is served by its own arm of `deliver`: a denial that did
        // not reach the wire is a record hx does not have, and a refusal hx
        // recorded nowhere reads -- from the operator's side -- exactly like a
        // request that was allowed.
        Recording sink = new Recording();
        sink.refuseDenial = true;
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, den(1, Source.CRAWLER), den(2, Source.CRAWLER));
            waitUntil(() -> c.dropped() == 2);
            check("a denial the sink would not take is counted ("
                  + c.dropped() + ")", c.dropped() == 2);
            waitUntil(() -> reported(sink, "crawler") == 2);
            check("and reported against the crawler, whose refusals they were ("
                  + sink.drops + " " + sink.dropSources + ")",
                  reported(sink, "crawler") == 2
                  && reported(sink, "operator") == 0);
            check("and nothing was recorded as delivered (" + sink.denials + ")",
                  sink.denials.isEmpty());
        } finally { c.stop(); }
    }

    static void aDeniedRecordWithNoSpellingIsRefusedTheSameWay() throws Exception {
        // THE REACHABLE ONE, and the reason Capture's offer() comment no
        // longer says an unattributed record cannot arrive. ProxyGate refuses
        // Source.UNATTRIBUTED -- that is exactly what it is for -- and the
        // handler offers the refusal as a Denied carrying that same source. So
        // this record is the one hx records as a DROP rather than as a denial
        // row: `hx.capture._run` maps anything that is not "crawler" onto the
        // operator's browse run, and filing a refusal nobody could attribute
        // under the operator's own browsing is the failure UNATTRIBUTED exists
        // to prevent. The bytes did not leave either way.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            offerAll(c, den(1, Source.UNATTRIBUTED), den(2, Source.OPERATOR));
            waitUntil(() -> sink.denials.size() == 1);
            Thread.sleep(50);
            check("the attributed refusal was recorded (" + sink.denials.size() + ")",
                  sink.denials.size() == 1
                  && "http://app.test/refused/2".equals(sink.denials.get(0).get("url")));
            check("and the unattributable one was not",
                  c.dropped() == 1);
            waitUntil(() -> !sink.drops.isEmpty());
            check("it was reported with NO spelling, not as the operator ("
                  + sink.dropSources + ")",
                  sink.dropSources.contains(null)
                  && !sink.dropSources.contains("operator"));
        } finally { c.stop(); }
    }

    static void countLostIsChargedToTheSourceItIsGiven() throws Exception {
        // Path 6: a record that never entered the queue at all. The response
        // handler with no Pending entry has no start time and no attribution,
        // so it counts the loss instead of recording an exchange with a
        // guessed duration -- and it must be counted against the source the
        // CALLER names, because the far side turns that string into a run
        // KIND. A countLost that always charged the operator would file a
        // crawler's losses on the operator's browse run.
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            c.countLost(Source.CRAWLER);
            c.countLost(Source.CRAWLER);
            c.countLost(Source.UNATTRIBUTED);
            check("all three were counted (" + c.dropped() + ")", c.dropped() == 3);
            waitUntil(() -> reported(sink, "crawler") == 2
                            && reported(sink, null) == 1);
            check("two against the crawler (" + reported(sink, "crawler") + ")",
                  reported(sink, "crawler") == 2);
            // The response handler's own miss is charged here: it is the one
            // place the source is genuinely unknown, and a drop with no run
            // attached beats a drop filed against a run that was picked.
            check("and the unattributed one with no spelling at all ("
                  + sink.dropSources + ")", reported(sink, null) == 1);
            check("and none against the operator, who lost nothing ("
                  + reported(sink, "operator") + ")",
                  reported(sink, "operator") == 0);
            check("and nothing was delivered as a record (" + sink.seen + " "
                  + sink.denials + ")",
                  sink.seen.isEmpty() && sink.denials.isEmpty());
        } finally { c.stop(); }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./extension/test.sh 2>&1 | grep -a CaptureTest`
Expected: a compile failure naming `hx.proxy.Observed`.

- [ ] **Step 3: Write `Observed` and `Capture`**

```java
// extension/src/hx/proxy/Observed.java
package hx.proxy;

/**
 * One observed exchange, REDACTED, on its way to the harness.
 *
 * PACKAGE-PRIVATE, AND THAT IS THE WHOLE OF WHAT KEEPS ITS BYTES REDACTED.
 * A text scan cannot bound construction: `new Observed(` missed
 * `new hx.proxy.Observed(` and the widened `Observed(` missed `Observed::new`
 * -- both measured green, both leaking -- and a third needle would miss a
 * fourth spelling. The COMPILER bounds it instead: no code in another PACKAGE
 * can name this type by any spelling, so the only code that can build one is
 * code sitting next to {@link Recorder}, which is the class that redacts.
 * `RecorderTest.theCompilerBoundsConstruction` reads the compiled modifiers,
 * and adding `public` back here is the mutation that reopens it.
 *
 * WHAT PACKAGE-PRIVATE IS AND IS NOT. It is a COMPILE-TIME discipline over
 * this source tree, not a JVM boundary: anything that declares itself
 * {@code package hx.proxy;} gets in, which is precisely how `CaptureTest` and
 * `RecorderTest` build these records. That is the right bound for the defect
 * it closes -- someone in another package writing a fifth spelling of a
 * construction -- and it is not a claim that the type is unreachable.
 *
 * `status` AND `outcome` TRAVEL TOGETHER AND ARE BOTH THE SCAN'S. S5 makes
 * them one answer: `outcome='status_unreadable'` is legal only with
 * `status=599`, and the pair is what stops an unreadable head being filed as a
 * healthy sample. The proxy path shipped without the second half -- Montoya's
 * `statusCode()` passed through raw and a hardcoded `"ok"` written in
 * {@link Capture} -- so a `103 Early Hints` in front of a dead origin landed
 * `status=103, outcome=ok`, which is the pair S5 measured thirty of and the
 * one the send path needed five fix rounds to stop producing. Both fields are
 * now filled by {@link Recorder} from `hx.send.Sender.scanStatus`, the SAME
 * scan the send path uses, and there is no second implementation of it.
 *
 * `request` and `response` are post-redaction bytes. That is not a
 * convention: S7 says the blob store is content-addressed, so a credential
 * that reaches the hashing step is already unrecoverable, and the hashing
 * happens on the Python side. Redaction therefore has to be finished before
 * an Observed exists at all -- which is why the constructor takes bytes and
 * not a Montoya object.
 */
record Observed(String method, String url, int status, String outcome, long ms,
                byte[] request, byte[] response, Source source)
        implements Captured { }
```

```java
// extension/src/hx/proxy/Capture.java
package hx.proxy;

import hx.bridge.BridgeClient;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The bounded queue between the proxy handler and the bridge.
 *
 * ONE RULE: offering never blocks. The extension sits in the request path of
 * a real person's browser during a live engagement, possibly against a
 * production system. S4 puts it plainly -- a wedged harness, a full queue or
 * a dropped record changes what hx KNOWS, never what it ALLOWS -- and the
 * practical consequence is that a slow Python side must never become a stall
 * on the client's application. That would turn a harness bug into an
 * incident.
 *
 * ITS CONVERSE: a drop is never silent. S5 says a run with drops has coverage
 * numbers that are a FLOOR, and nothing on the far side can know that unless
 * it is told. There are SIX ways a record hx might have had does not reach
 * the far side, and each one increments {@link #dropped} for the record's own
 * source:
 *
 *   1. EVICTION, when {@link #offer} finds the queue full;
 *   2. REFUSAL, when a record's source has no spelling;
 *   3. AN UNDELIVERED RECORD -- the sink threw, or answered false;
 *   4. {@link #stop}, which throws away whatever is still queued;
 *   5. AN OFFER THAT ARRIVES AT OR AFTER {@link #stop} -- Burp unloading the
 *      extension while a proxy thread is still inside {@link #offer}. Such a
 *      record lands in a queue with no drain behind it, so {@link #offer}
 *      clears and counts the queue itself once it sees {@link #accepting}
 *      go false.
 *   6. A RECORD THAT NEVER ENTERED THE QUEUE AT ALL, counted through
 *      {@link #countLost}. The queue is not the only place a record is lost:
 *      the response handler that finds no {@link Pending} entry for a
 *      response has an exchange it cannot describe -- no start time, so no
 *      `ms`, and no attributed source -- and the honest answer is a drop
 *      rather than a row with a guessed duration on it.
 *
 * They are ONE number, not six, because they are one fact: a record hx does
 * not have. A frame over MAX_FRAME and a socket that died between two
 * requests differ to whoever is debugging the bridge and not at all to
 * whoever is reading the run's coverage.
 *
 * COUNTING THE INCREMENTS IS NOT A FALSIFIER, and this comment said it was.
 * It read "`incrementAndGet` appears exactly four times, once per path; a
 * fifth loss would need a fifth increment or would be a record leaving with
 * none, and either is visible in one grep." Path 5 was neither: the record
 * did not leave and nothing was incremented, it simply sat in the queue.
 * Measured before it was closed -- `stop(); offer(one record);` gave
 * `delivered=0, dropped()=0, reports=[]`, and 4 paced proxy threads offering
 * 800 records across a `stop()` gave `4 delivered + 284 dropped of 800`, the
 * missing 512 being exactly DEFAULT_CAPACITY sitting in a drainless queue.
 *
 * PATH 6 IS THE SAME LESSON A SECOND TIME, and it is why this paragraph is
 * amended rather than left standing. Task 7 added TWO `incrementAndGet` sites
 * to the four -- {@link #countLost} for path 6, and the denial arm of
 * {@link #deliver} for path 3 -- so the retired grep would now answer "six
 * sites, six paths" and LOOK right while meaning nothing. MEASURED, by
 * reading them: the six sites are the refusal (path 2), the eviction (path 1),
 * {@link #discardQueued} (paths 4 AND 5, one site for two), {@link #countLost}
 * (path 6), and ONE PER FRAME ARM for path 3 (two sites for one). Two paths
 * share a site and one path has two; that the totals agree is arithmetic, not
 * structure. The count of increments has never matched the count of paths in
 * any way a grep could check, and the moment it appears to is the moment it is
 * most misleading.
 *
 * WHAT DOES PIN THE SIX is a count of EXITS, not of increments. A record
 * enters this class through {@link #offer} or is counted without entering it
 * through {@link #countLost}, and nowhere else; it leaves DELIVERED or as one
 * of 1-6. Each of the first four increments was DELETED on
 * its own and measured: refusal -> 3 FAIL, eviction -> 9, undelivered -> 3,
 * discard -> 3, every one of them 11 summary lines with named FAIL lines, and
 * none of them a silent green. `offers racing stop() are every one of them
 * accounted for` is the test that holds when no single increment does: it
 * asserts only that delivered + dropped is everything offered, which is the
 * exits restated. {@link #countLost} is outside that identity by
 * construction -- its record never entered the queue -- so it has a test of
 * its own, `countLost is charged to the source it is given`, and that test is
 * the whole of what holds it.
 *
 * WHAT IS NOT COVERED, and cannot be from inside this class: a JVM that dies
 * without reaching {@link #stop} takes the queue with it uncounted, and so
 * does one that exits while the drain is still parked in a wedged sink with a
 * record in hand -- that record is counted when the sink finally answers, or
 * never. Both are Burp dying, not hx losing a record quietly, and there is no
 * code path left to run at that point.
 *
 * WHAT IS NOT CLAIMED HERE is that the count reaches the far side. It reaches
 * it when {@link BridgeClient.ExchangeSink#dropped} SAYS it did, by answering
 * true; a report that answers false leaves {@link #reported} where it was and
 * the whole outstanding total goes out on the next attempt. That distinction
 * is the entire point of the boolean: the production sink catches its own
 * IOException, and before it answered, a write that failed advanced the
 * counter anyway -- 5,000 drops became one line in Burp's log and
 * `run.dropped_total = 0`. A log line is not the coverage floor.
 *
 * Oldest-first eviction, deliberately. The recent requests are the ones an
 * operator is currently looking at; the old ones are already reasoned about.
 */
public final class Capture {

    /**
     * 512 exchanges, ~1 MB at ~2 KB apiece.
     *
     * Nothing against a JVM already holding Burp, and more requests than a
     * human generates in the seconds a slow harness takes to catch up. The
     * number is a ceiling on MEMORY, not on correctness: the queue is allowed
     * to overflow, it is not allowed to block, and every overflow is counted.
     */
    public static final int DEFAULT_CAPACITY = 512;

    /** Same bound and same reason as HaltSwitch.STOP_JOIN_MS: unloading the
     *  extension must not hang Burp. */
    static final long STOP_JOIN_MS = 2000L;

    /**
     * How long the drain parks waiting for the next record.
     *
     * `take()` would be the obvious call and it is the wrong one: drops are
     * reported by the drain, and a drain parked forever on an empty queue
     * reports nothing. The overflow that produced the drops is exactly the
     * moment traffic then STOPS -- the operator gives up on a page that will
     * not load -- so "the next record will carry the report out" is the one
     * assumption the drop path may not make. A bounded park makes the report
     * arrive on its own.
     */
    static final long POLL_MS = 100L;

    private final ArrayBlockingQueue<Captured> queue;
    private final BridgeClient.ExchangeSink sink;

    /**
     * Drops COUNTED PER SOURCE, because the report carries a source and the
     * far side turns it into a run KIND: `hx.capture` maps "crawler" to a
     * crawl run and everything else to a browse run. One counter with one
     * source attached would file a crawler's drops against the operator's run
     * whenever the two interleave -- a coverage figure wrong on the row an
     * operator reads, in a component whose entire purpose is not lying about
     * coverage.
     */
    private final AtomicLong[] dropped = new AtomicLong[Source.values().length];

    /**
     * How much of {@link #dropped} the far side has ACKNOWLEDGED, per source.
     *
     * A FIELD, and it used to be a local in `loop()`. Measured with it local:
     * three real drops reported `[OPERATOR:3]`, then `stop(); start();`
     * reported `[OPERATOR:3, OPERATOR:3]` -- six reported against three that
     * happened. `hx.capture` only refuses `n < 1` and `count_drop`
     * ACCUMULATES, so nothing on the Python side can catch an inflated
     * report: `run.dropped_total` climbs without bound across reconnects, and
     * the number that exists to say "coverage is a floor" becomes a number
     * that is wrong in the direction of alarm.
     *
     * Guarded by {@link #reportLock}, which is what lets {@link #stop} report
     * the flush without racing a drain that outlived its join.
     */
    private final long[] reported = new long[Source.values().length];

    /**
     * Held across one whole reporting pass.
     *
     * `stop()` reports too, and a drain that did not die inside STOP_JOIN_MS
     * is still reporting. Two passes over the same `reported[]` would each
     * read the same outstanding total and each send it -- E3's bug with two
     * threads instead of two runs. `stop()` takes it with `tryLock` and never
     * waits: a drain wedged INSIDE the sink holds this, and a stop() that
     * blocked on it would hang Burp's unload, which is the one thing
     * STOP_JOIN_MS exists to prevent.
     */
    private final ReentrantLock reportLock = new ReentrantLock();

    private volatile Thread drain;
    private volatile boolean running;

    /**
     * Whether {@link #offer} still has a drain to offer INTO.
     *
     * True from construction and false from {@link #stop} until the next
     * {@link #start}. {@link #running} cannot do this job, and that is not a
     * naming quibble: `running` is also false BEFORE the first `start()`, and
     * offering into a Capture that has not started yet is legitimate -- it is
     * how `stopThenStartDoesNotReReportTheCount` fills the queue, and it is
     * what the proxy handler does for any record that arrives between
     * construction and the drain's first poll. Those records have a drain
     * coming. A record offered after `stop()` does not.
     */
    private volatile boolean accepting = true;

    public Capture(int capacity, BridgeClient.ExchangeSink sink) {
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.sink = sink;
        for (int i = 0; i < dropped.length; i++) dropped[i] = new AtomicLong();
    }

    /** Total drops, across every source. */
    public long dropped() {
        long total = 0;
        for (AtomicLong c : dropped) total += c.get();
        return total;
    }

    /**
     * The two spellings the harness knows, and NO THIRD.
     *
     * `hx.capture._run` reads this string and answers "crawl" for "crawler"
     * and "browse" for anything else. So there is no string an UNATTRIBUTED
     * record could carry that does not become the operator's run on arrival,
     * which is why this answers null instead of inventing one -- and why
     * {@link #offer} refuses such a record rather than queueing it. Written as
     * two explicit answers rather than `s == CRAWLER ? "crawler" : "operator"`,
     * so a constant added to {@link Source} later is a null here and a refused
     * record, not a silent promotion to the operator's run.
     *
     * It lives HERE, and the sink takes the STRING it produces. `hx.bridge`
     * knowing how to spell an `hx.proxy` enum was a package cycle and a
     * second place the decision could drift; a `null` crossing to the sink
     * means "no spelling", and the sink's only job with it is to omit the key.
     */
    public static String sourceName(Source s) {
        if (s == Source.CRAWLER) return "crawler";
        if (s == Source.OPERATOR) return "operator";
        return null;
    }

    /**
     * Never blocks, never throws, never reports failure to its caller.
     *
     * The caller is a Montoya proxy handler on Burp's own thread. There is
     * nothing useful it could do with an exception and one thing it must not
     * do, which is fail to forward the request.
     *
     * A record whose source has no spelling ({@link #sourceName}) is REFUSED
     * here and counted as a drop, because recording it would file the request
     * under a run kind nothing chose. Counted rather than discarded, because
     * the count is the thing that says hx knows less than it might.
     *
     * ONE SUCH RECORD IS REACHABLE, and this comment used to say none was.
     * It read "ProxyGate already refuses UNATTRIBUTED, so one should never
     * arrive" -- true while the only thing offered here was an
     * {@link Observed} from a request the gate had ALLOWED. Task 7 wired the
     * refusals in as {@link Denied}, and the request the gate refuses BECAUSE
     * it could not attribute the listener carries exactly that source. So the
     * denial hx records for it is a DROP and not a `denial` row: the bytes
     * still did not leave -- the handler answers `drop()` before this is
     * reached -- and `run.dropped_total` moves instead of `denial`. Stated
     * rather than fixed, because the alternative is `hx.capture._run` filing
     * a refusal nobody could attribute under the operator's own browse run,
     * which is the failure {@link Source#UNATTRIBUTED} exists to prevent.
     * `aDeniedRecordWithNoSpellingIsRefusedTheSameWay` is what pins it.
     *
     * AND IT NOTICES A CAPTURE THAT HAS STOPPED UNDERNEATH IT. Burp unloads
     * the extension on its own thread while proxy threads are still in here;
     * without the check at the bottom those records queued into a drain that
     * no longer existed, which lost them AND left `run.dropped_total` where
     * it was -- the coverage floor reading lower than the real loss, which is
     * the one direction it may never move.
     */
    public void offer(Captured o) {
        if (sourceName(o.source()) == null) {
            dropped[o.source().ordinal()].incrementAndGet();
            return;
        }
        while (!queue.offer(o)) {
            // Evict the oldest and try again. `poll` returning null means
            // another thread drained it first, which is fine -- the retry
            // then succeeds.
            Captured evicted = queue.poll();
            if (evicted != null) dropped[evicted.source().ordinal()].incrementAndGet();
        }
        // AFTER the enqueue, not before, and that ordering is the whole
        // guarantee. `accepting` is volatile and the queue has a lock of its
        // own, so the two orderings cover each other: if this read sees TRUE
        // it precedes stop()'s write of false, so the enqueue above precedes
        // stop()'s drainTo and stop() counts the record; if it sees FALSE,
        // stop() may already have drained past the record, so this thread
        // clears the queue itself. A check BEFORE the enqueue would leave the
        // window between the two open, which is precisely the window Burp's
        // unload sits in.
        if (!accepting) discardQueued();
    }

    /**
     * Count everything queued, and keep nothing.
     *
     * Called by {@link #stop}, and by an {@link #offer} that found the
     * capture already stopped. NEVER by the drain: a record taken off the
     * queue to be DELIVERED is {@link #deliver}'s business, and counting it
     * here as well would report one loss twice.
     */
    private void discardQueued() {
        List<Captured> left = new ArrayList<>();
        queue.drainTo(left);
        for (Captured o : left) dropped[o.source().ordinal()].incrementAndGet();
    }

    /**
     * Count one record that never entered the queue. Path 6, and the only
     * entry point here that is not {@link #offer}.
     *
     * The caller is the proxy RESPONSE handler with a response it cannot turn
     * into a record: {@link Pending} had no entry for its message id, so
     * there is no start time and no attributed source, and an exchange row
     * with a guessed duration on it is fabricated evidence. It is also the
     * response handler's answer to a redaction that threw -- the bytes are
     * there and cannot be made safe to store, so the record is lost and says
     * so.
     *
     * The source is the CALLER'S to choose and this method does not
     * second-guess it: a miss is charged to {@link Source#UNATTRIBUTED},
     * which has no spelling, so the report crosses the bridge with the
     * `source` key OMITTED and lands on the operator's run the way
     * `hx.capture` documents an absent source. A record whose run genuinely
     * is not known must not invent one.
     */
    public void countLost(Source s) {
        dropped[s.ordinal()].incrementAndGet();
    }

    /**
     * Start the drain, or do nothing if it is already running.
     *
     * IDEMPOTENT, and that is not tidiness. Called twice, the previous
     * version started a second `hx-capture` thread over the first -- two
     * drains on one queue, and `drain` naming only the second, so `stop()`
     * could never reach the first again. Inside Burp that is one leaked
     * daemon per extension reload, each polling a queue and calling into a
     * torn-down BridgeClient.
     */
    public synchronized void start() {
        if (drain != null) return;
        accepting = true;
        running = true;
        Thread t = new Thread(this::loop, "hx-capture");
        t.setDaemon(true);   // must never hold Burp open
        drain = t;
        t.start();
    }

    /**
     * Stop the drain, and account for what is still queued.
     *
     * THE FLUSH IS THE POINT. Measured on the previous version: 200 records
     * queued into a 512-slot Capture behind a slow sink, then `stop()` --
     * `delivered=0, dropped()=0, reports=[]`. Two hundred exchanges gone and
     * counted as zero, on every extension unload and at the end of every run.
     *
     * The queue is COUNTED, not delivered. Delivering it would mean pushing
     * up to DEFAULT_CAPACITY frames into a sink that may be exactly as wedged
     * as the one that let the queue fill, on the thread Burp is unloading the
     * extension on -- an unbounded wait where STOP_JOIN_MS is the bound. A
     * record hx cannot pass on is a drop; saying so is the honest half, and
     * it is the half S5 depends on.
     *
     * Idempotent, AND A SECOND CALL IS NOT ALWAYS A NO-OP. It finds no drain,
     * but it finds whatever arrived after the first: a proxy thread inside
     * {@link #offer} when Burp tore the extension down has counted its record
     * (path 5) and had nothing left to report it through. The next `stop()`
     * is what carries that count across the sink.
     *
     * TASK 7 SETTLED THAT THERE IS ONLY ONE, in the unloading handler that
     * already closes the bridge, and the cost is written down rather than
     * argued away: a record offered by a proxy thread that was inside
     * {@link #offer} when Burp tore the extension down is COUNTED (path 5)
     * and its count has nothing left to leave through -- the bridge is closed
     * on the next line. A second call would race the first identically while
     * the JVM is being torn down, and a record offered DURING `stop()` counts
     * itself and is in the same position whichever call observes it. So the
     * loss is real and bounded by however many proxy threads were mid-offer,
     * and the honest statement is that this class's count is complete up to
     * the unload and not through it.
     */
    public synchronized void stop() {
        // FIRST, and before the drain is even asked to stop: from this write
        // on, an offer() that lands in the queue is responsible for counting
        // itself. See offer()'s closing comment for why that is enough.
        accepting = false;
        running = false;
        Thread t = drain;
        drain = null;
        if (t != null) {
            t.interrupt();
            try {
                t.join(STOP_JOIN_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        discardQueued();
        // tryLock, never lock: see reportLock. A drain wedged in the sink is
        // holding it, and there is nothing to report through anyway.
        if (reportLock.tryLock()) {
            try {
                reportOutstanding();
            } finally {
                reportLock.unlock();
            }
        }
    }

    private void loop() {
        while (running) {
            Captured o;
            try {
                o = queue.poll(POLL_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (o != null) deliver(o);
            reportLock.lock();
            try {
                reportOutstanding();
            } finally {
                reportLock.unlock();
            }
        }
    }

    /**
     * One record to the sink, or one more drop.
     *
     * The switch is over a SEALED interface with no `default` arm, so a third
     * kind of {@link Captured} is a compile error here rather than a record
     * that reaches no arm and is silently delivered as nothing.
     *
     * TWO FRAME TYPES, TWO SINK METHODS, and the denial does NOT go through
     * `exchange(...)` with two empty byte arrays. That method's name says
     * what its frame is; a denial routed through it is a naming lie the next
     * reader inherits, and `server.py::_capture` splits two bodies for an
     * `exchange` and none for a `denial`.
     */
    private void deliver(Captured c) {
        switch (c) {
            case Observed o -> deliverExchange(o);
            case Denied d -> deliverDenial(d);
        }
    }

    private void deliverExchange(Observed o) {
        boolean delivered;
        try {
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("t", "exchange");
            h.put("via", "proxy");
            h.put("source", sourceName(o.source()));
            h.put("method", o.method());
            h.put("url", o.url());
            h.put("status", (long) o.status());
            h.put("ms", o.ms());
            // THE RECORD'S, NOT A LITERAL. This line read `"ok"` and was the
            // only `outcome` write on the proxy path, so every proxy exchange
            // was filed healthy whatever its bytes said -- including the
            // `103 Early Hints` shape S5 measured thirty of. The answer is
            // computed in Recorder by the SAME scan the send path uses, and
            // arrives here already paired with the `status` above: S5 accepts
            // `status_unreadable` only alongside 599, and Recorder is the one
            // place that pairing is made.
            h.put("outcome", o.outcome());
            delivered = sink.exchange(h, o.request(), o.response());
        } catch (Throwable t) {
            // A sink that throws is someone else's code failing. Losing
            // this record is bad; losing every record after it because
            // the drain thread died is worse, and silent.
            delivered = false;
        }
        if (!delivered) dropped[o.source().ordinal()].incrementAndGet();
    }

    /**
     * A refusal, as the seven keys `hx.capture`'s denial arm reads.
     *
     * `t`, `via`, `source`, `method`, `url`, `error_class` and `detail`, and
     * NO EIGHTH: an unknown key is not refused on the far side, it is
     * ignored, so a key added here without a reader there is a fact the
     * operator will never see and a reason to think it was recorded. There is
     * no `status`, no `ms` and no `outcome`, because none of the three has an
     * answer for a request that never left.
     */
    private void deliverDenial(Denied d) {
        boolean delivered;
        try {
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("t", "denial");
            h.put("via", "proxy");
            h.put("source", sourceName(d.source()));
            h.put("method", d.method());
            h.put("url", d.url());
            h.put("error_class", d.errorClass());
            h.put("detail", d.detail());
            delivered = sink.denial(h);
        } catch (Throwable t) {
            // Same reasoning as the exchange arm: a sink that throws is
            // someone else's code failing, and killing the drain would lose
            // every record after it, silently.
            delivered = false;
        }
        if (!delivered) dropped[d.source().ordinal()].incrementAndGet();
    }

    /** Called with {@link #reportLock} held. */
    private void reportOutstanding() {
        for (Source s : Source.values()) {
            int i = s.ordinal();
            long now = dropped[i].get();
            if (now == reported[i]) continue;
            boolean told;
            try {
                told = sink.dropped(now - reported[i], sourceName(s));
            } catch (Throwable t) {
                // Same reasoning as deliver(): a sink that throws must not
                // kill the drain.
                told = false;
            }
            // ONLY on an acknowledged report. The count is cumulative, so the
            // next attempt carries the whole outstanding total -- and the
            // previous version advanced on a sink that had merely RETURNED,
            // which the production one does after logging its own IOException.
            if (told) reported[i] = now;
        }
    }
}
```

- [ ] **Step 4: Two bodies on the wire**

`Frame` currently encodes one header and one body. Add a two-body form: length-prefix both, and keep the one-body form byte-identical so every existing frame is unchanged on the wire. Mirror the decode in `src/hx/bridge/codec.py`, and give `BridgeServer` an `on_exchange(header, request, response)` sink called on the read thread — the same contract `on_hello` and `on_halted` already carry, which the read-loop docstring in `server.py:110` states.

`BridgeClient.exchangeSink()` returns a `Capture.ExchangeSink` that frames and writes. It never raises into `Capture`: a dead socket means the records are lost, and losing them must not also stop the browser.

- [ ] **Step 5: Run, sabotage, commit**

Register `hx.proxy.CaptureTest` in `extension/test.sh` (eleven summary lines from here). Run the suite. Then five mutations, each judged by the eleven lines: `offer` blocking instead of evicting; eviction taking the newest; `dropped` never incremented; `sink.dropped` never called; the drain thread not a daemon. Each must redden a named check and nothing else.

```bash
./scripts/sync_plan_block.py docs/superpowers/plans/2026-08-24-traffic-capture.md \
    extension/src/hx/proxy/Observed.java extension/src/hx/proxy/Capture.java \
    extension/test/hx/proxy/CaptureTest.java
git add extension/ src/hx/bridge/ docs/
git commit -m "feat(proxy): a bounded queue that never blocks and never lies"
```

---

### Task 7: Wire it — the second enforcement point goes live

The pieces exist and **nothing calls them**. `ProxyGate`, `Capture`, `Observed`
and `src/hx/capture.py` are all inert: no production caller, no registration,
no frame. This task is the join, and every serious defect on this branch and
the last has lived at a join.

It is the largest task in the plan and it is deliberately not split, because
the three pieces below only have one correct shape *together*: the denial
frame's fields are decided by what `capture.py` already reads, the pending
map's contents are decided by what the response handler cannot otherwise
know, and both are decided by what a Burp proxy thread is allowed to do
(nothing that blocks). Land it as the commits named in Step 8 so the review
can read the halves apart.

**Rulings already taken. Do not re-litigate; each is recorded with what it
costs if wrong.**

- **R1 — the JDK-egress count already exists.** An earlier draft of this task
  asked for a new `n4` check counting `new Socket(`, `HttpClient.`, `URL(`,
  `.openConnection(`, `SocketChannel.open(` with a named exception for
  `BridgeClient`'s unix socket. `ChokepointTest.noSecondEgressFamilyExists`
  has counted six such needles across `extension/src` since the previous
  branch's whole-branch review, all must-be-zero, read from **raw text** so a
  comment naming one turns it red. Its needles were chosen so the bridge's
  legitimate `SocketChannel.open(UnixDomainSocketAddress)` collides with none
  of them — which is why it needs no exception list. **Do not add a second
  copy, and above all do not add the exception list**: introducing one would
  weaken a check that currently needs none. Verify it is still there and still
  zero; that is all.
- **R2 — no new error class.** `ProxyGate` separates "this jar could not tell
  who was driving" from "the operator has not configured a run" only by the
  `extension fault: ` prefix on the detail, and that stays. A new class needs
  a `DENIAL_KIND` entry, a `denial.kind` CHECK widening, a `SCHEMA_VERSION`
  bump, and a row in `tests/test_records.py` — whose class-derivation scan
  reads `Decision.deny("...")` and `error(f, "...")` and **does not read**
  `new Verdict(false, "...")`, so a class minted in `ProxyGate` today is
  invisible to the check that exists to catch a denial with nowhere to go.
  Cost if wrong: `SELECT kind, COUNT(*) FROM denial` files an unattributable
  listener under `not_configured`, greppable by the prefix that
  `records.EXTENSION_FAULT` pins byte-identical across both languages.
- **R3 — the proxy path does not check the halt, and that is a stated gap.**
  §4's decision order puts `halted` second, and `ProxyGate` asks `Policy`,
  which does not know about halts — the send path asks `HaltSwitch`
  separately. Closing it here would need `halted` in `DENIAL_KIND` and in
  `denial.kind`'s CHECK, or the denial routes to `row_for(...) is None` and
  vanishes silently, which is §4's "denials are never silent" broken by the
  fix for §4. **Plan 5 closes it before the crawler ships**; write that
  condition into `ProxyGate`'s javadoc where Plan 5's implementer will read
  it. Cost if wrong, stated rather than argued away: between now and Plan 5 an
  operator's halt does not stop the operator's own browsing. That is the
  branch where it matters least — a human who hit stop can close their
  browser — and the crawler, where it matters, does not exist yet.
- **R4 — there is no plan block to sync.** This plan carries no
  `// extension/src/hx/HxExtension.java` block and no
  `// extension/test/hx/ChokepointTest.java` block, so
  `scripts/sync_plan_block.py` would exit with "no block ... opens with". Do
  not run it, and do not add blocks for them: transcribing finished work
  backwards into a plan is that script's own incidents 1-2. `Capture.java` and
  `CaptureTest.java` **do** have blocks and they are **stale** (P10) — leave
  them stale; they come off with the `plan-drift: pending` marker at the end
  of the plan, not in this task.
- **R5 — one `stop()`, on unload.** P8 asked whether Task 7 wants a second.
  It does not: a record offered *during* `stop()` counts itself and has
  nothing left to report through, and a second `stop()` races the first
  identically while the JVM is being torn down. One call, in the unloading
  handler that already closes the bridge.
- **R6 — `via` stays `"proxy"` for everything this point sees.** `Capture`
  hard-codes it and that is correct today: `via` is S5's *egress point*, and
  the crawler's traffic will leave through this same point. The consequence
  worth writing down for Plan 5 — a crawler-discovered surface lands with
  `discovered_by = 'proxy'`, not `'crawl'`, so S5's crawl-coverage figure
  reads zero until Plan 5 decides otherwise — is **P12**, not this task's.

**Files:**
- Create: `extension/src/hx/proxy/Captured.java`, `extension/src/hx/proxy/Denied.java`,
  `extension/src/hx/proxy/Pending.java`, `extension/test/hx/proxy/PendingTest.java`
- Modify: `extension/src/hx/HxExtension.java`,
  `extension/src/hx/proxy/Observed.java`, `extension/src/hx/proxy/Capture.java`,
  `extension/src/hx/proxy/ProxyGate.java` (javadoc only, per R3),
  `extension/src/hx/bridge/BridgeClient.java`,
  `extension/test/hx/proxy/CaptureTest.java`, `extension/test/hx/ChokepointTest.java`,
  `extension/test.sh`

**Interfaces:**
- Consumes: `Source.forListenerPort(int, int)`, `Source.NO_PORT`;
  `ProxyGate(Policy)` and `ProxyGate.decide(HxRequest, BridgeClient.Authorisation, Source)`
  returning `Verdict(boolean allow, String errorClass, String detail)`;
  `Capture(int, BridgeClient.ExchangeSink)`, `Capture.DEFAULT_CAPACITY`,
  `Capture.sourceName(Source)`; `BridgeClient.authorisation()`,
  `BridgeClient.exchangeSink()`, `BridgeClient.EXTENSION_FAULT`;
  `Redactor.redactRequest(byte[], Redactor.Injected)`,
  `Redactor.redactResponse(byte[])`, `new Redactor.Injected(byte[])`;
  `HxRequest(method, url, host, path, query, headers, body)`.
- Produces: nothing any later task consumes as a type. Task 8's CLI reads the
  **rows** this produces, never these classes.

**Measured Burp facts this task is built on. None is guessable from the code.**

- `InterceptedRequest` and `InterceptedResponse` both extend
  `InterceptedHttpMessage`, which declares `int messageId()` and
  `String listenerInterface()` — **compile-time, both of them.**
- `listenerInterface()` returns `"127.0.0.1:<port>"` and names a different
  port per listener, over plain HTTP and through a CONNECT tunnel. There is
  **no `listenerPort()`** on the intercepted message. (`ProxyHttpRequestResponse`,
  the *history* item, does have `listenerPort()` — it is a different type and
  is not reachable from a handler.)
- `destinationIpAddress()` compiles and **throws
  `UnsupportedOperationException: Not yet implemented`** on every call. Never
  call it.
- `messageId()` correlates request to response, including out of order.
- `drop()` sends **zero bytes** to the target and returns **`200 OK`** to the
  client with ~1529 bytes of Burp's own HTML. **A drop is indistinguishable
  from a delivery by status code.** No code and no test here may read a
  client-side response as evidence of a block.
- The drop above was measured from `handleRequestReceived`. `drop()` from
  `handleRequestToBeSent` is **not measured** — Step 5 uses it anyway, and
  says why, and Task 9 measures it.
- `InterceptedResponse.initiatingRequest()` returns the request that produced
  this response, so the request bytes need no map to reach the response
  handler.
- Neither handler carries timing. `InterceptedResponse` has no `timingData()`;
  only the history type does. `ms` must be measured by this extension or not
  reported.

- [ ] **Step 1: One queue, two kinds of record**

`Capture`'s queue holds `Observed`. A denial is not an observed exchange — the
request never left, there are no bodies, and `capture.py`'s denial arm reads
`error_class`, `detail`, `method`, `url`, `via` and `source` and no more. It
still needs the *same* queue: it is offered from a Burp proxy thread that may
not block, and a loss of it is a loss of coverage counted in the same number.

Introduce a sealed carrier and widen the queue to it:

```java
// extension/src/hx/proxy/Captured.java
package hx.proxy;

/** One record on its way to the harness: an exchange that happened, or a
 *  denial that stopped one happening. Sealed, so `Capture.deliver`'s switch
 *  is exhaustive and a third kind is a COMPILE error rather than a record
 *  that silently reaches no arm. */
public sealed interface Captured permits Observed, Denied {
    Source source();
}
```

```java
// extension/src/hx/proxy/Denied.java
package hx.proxy;

/**
 * One request this extension refused at S4's second enforcement point.
 *
 * PACKAGE-PRIVATE, like {@link Observed}, and for the symmetry rather than
 * for a leak of its own: a denial carries no bodies, so there is no redaction
 * here to get wrong. Leaving ONE of the two {@link Captured} kinds
 * constructible from outside the package would preserve exactly the shape the
 * other one was closed for -- a second door -- and the symmetry costs two
 * lines in {@link Recorder}.
 *
 * NO BODIES, deliberately. `bridge/server.py::_capture` reads `denial` and
 * `dropped` as frames that "describe something that produced no traffic, so
 * they arrive with an empty body" -- one body slot, not two -- and
 * `capture.py`'s denial arm writes a `denial` row with no blobs. Carrying
 * the refused request's bytes here would put a body on the wire nothing
 * reads and S7 never cleared for the store.
 *
 * WHAT A Denied IS NOT: proof that a denial row exists on the far side. A
 * Denied whose {@link Source} has no spelling is REFUSED by
 * {@link Capture#offer} and counted as a drop instead -- which is exactly
 * what happens to the request the gate refused BECAUSE it could not be
 * attributed. That is the honest reading and not an oversight: the bytes
 * still did not leave, and `hx.capture._run` would otherwise file the
 * refusal under the operator's run, which is the one thing
 * {@link Source#UNATTRIBUTED} exists to stop. CaptureTest's
 * `anUnattributedRecordIsRefusedAndCounted` pins the refusal for an
 * {@link Observed}; `aDeniedRecordWithNoSpellingIsRefusedTheSameWay` pins it
 * for this type.
 */
record Denied(String method, String url, String errorClass,
              String detail, Source source) implements Captured { }
```

`Observed` gains `implements Captured` and nothing else — its `source()`
accessor already satisfies the interface.

In `Capture`:
- `ArrayBlockingQueue<Observed>` becomes `ArrayBlockingQueue<Captured>`;
  `offer(Observed)` becomes `offer(Captured)`; `discardQueued`'s list and the
  `deliver` parameter follow.
- `deliver` switches on the kind. The exchange arm is unchanged. The denial
  arm builds `{t: "denial", via: "proxy", source, method, url, error_class,
  detail}` and sends it through **one body**, not two.
- add `public void countLost(Source s)`, which increments `dropped` for that
  source and does nothing else. Step 3 is its only caller. It is a **sixth**
  exit for a record that never entered the queue — update the class javadoc's
  enumeration and, more importantly, the paragraph that explains why counting
  `incrementAndGet` sites is **not** a falsifier. That paragraph exists
  because a previous count of the paths was wrong; adding a path without
  amending it repeats the error it was written about.

`BridgeClient.ExchangeSink` gains a third method, alongside `exchange` and
`dropped` and shaped exactly like `dropped`:

```java
        /** A request S4's second enforcement point refused. One body slot,
         *  empty: `server.py::_capture` hands `denial` and `dropped` to the
         *  sink as two empty halves. True once the frame is on the wire;
         *  false means the record is lost and the caller must count it. */
        boolean denial(Map<String, Object> header);
```

...implemented in `exchangeSink()` the way `dropped` is — `f.put("v",
PROTOCOL_VERSION)`, `f.putAll(header)`, `send(f, new byte[0])`, catch
`Throwable`, log, return false. **Not** through `exchange(...)` with two empty
byte arrays: that method's name says what its frame is, and a denial routed
through it is a naming lie that the next reader inherits.

`CaptureTest` gains, at minimum: a denial offered and delivered as a
`t: "denial"` frame with the six keys above and no seventh; a denial whose
sink answers false counted as a drop for **its own source**; and `countLost`
counted against the right source. Its existing fake sink needs the new method.

- [ ] **Step 2: Update `docs/bridge-protocol.md`**

The document still says `exchange {v,t,...} unsolicited; no id. Defined in a
later plan.` and names neither `dropped` nor `denial`. Three frames now exist
on the Java side and are read on the Python side; a protocol document that
does not carry them is a document a second implementation cannot be written
from. Add the three rows with their real fields, and say which carry one body
and which carry two. This is documentation of what Tasks 4 and 6 already
built, not new design.

- [ ] **Step 3: `Pending` — the two things a response handler cannot otherwise know**

The response handler needs the exchange's **duration** and its **source**.
Burp gives it neither: `InterceptedResponse` carries no timing at all, and
while it does expose `listenerInterface()`, that accessor was measured on
*requests* only — using it on a response would be an unmeasured assumption
sitting under the field that decides which run a record is filed against.

So the request handler records both, keyed by `messageId()`, and the response
handler takes them back:

`extension/src/hx/proxy/Pending.java`, whose javadoc must carry the
reasoning below — this is a SKETCH of the shape, not the file:

    // extension/src/hx/proxy/Pending.java
    package hx.proxy;

    /**
     * The start time and the attributed source of a request that has not been
     * answered yet, keyed by Burp's own message id.
     *
     * BOUNDED, AND EVICTION IS A LOSS SOMEONE IS TOLD ABOUT. The alternative --
     * an unbounded map in a Burp that runs for days -- leaks an entry for every
     * request that never gets a response, which includes every request the gate
     * dropped and every connection that died. `Capture`'s bound exists for the
     * same reason and this one follows its shape: a ceiling on MEMORY, oldest
     * evicted first, and the record's absence reported rather than papered over.
     * A `take` that misses is NOT an exchange recorded with a guessed duration;
     * it is a record hx does not have, and S5 makes that a number.
     */
    public final class Pending { ... }


Shape:
- `Pending(int capacity)`; the extension passes `Capture.DEFAULT_CAPACITY`, so
  one number bounds both and a miss cannot happen while the queue is coping.
- `void put(int messageId, long startNanos, Source source)`
- `Entry take(int messageId)` — removes and returns, or `null`.
- Backed by a `LinkedHashMap` in a `synchronized` block, evicting eldest past
  capacity. **Not** `ConcurrentHashMap`: eviction needs insertion order, and
  the critical section is a map write on a proxy thread — nanoseconds, next
  to a network round trip.
- `long evicted()` — a counter, for the test and for anyone reading a run
  whose coverage is short.

`PendingTest` must pin, at least: put/take round-trips the exact values;
a second `take` of the same id answers null (an entry is consumed once, so a
retried response cannot double-count); `capacity + 1` puts evict the **oldest**
and only the oldest; `evicted()` counts exactly the evictions; and a `take`
of an id never put answers null rather than throwing. Add
`hx.proxy.PendingTest` to `extension/test.sh`'s `CLASSES` list — **the run
goes from eleven summary lines to twelve, and Rule 1 judges by that count and
the exit code.**

- [ ] **Step 4: Register the handlers**

In `HxExtension.initialize`, after the send path is wired and **before** the
dial — the same rule the kill paths follow, and for the same reason: a window
in which the proxy is live and the gate is not is a window in which §4 is
false.

```java
        int crawlerPort = Integer.getInteger("hx.crawler_port", 0);
        ProxyGate gate = new ProxyGate(policy);   // THE SAME Policy. See below.
        Capture capture = new Capture(Capture.DEFAULT_CAPACITY, c.exchangeSink());
        Pending pending = new Pending(Capture.DEFAULT_CAPACITY);
```

`policy` is the field `HxExtension` already names for exactly this — one
`Policy` per run, so the rate limit and the per-run budget are one counter and
not two. `ChokepointTest.oneRunHasOnePolicy` reddens a second `new Policy(`.
**Do not construct one here.**

`-Dhx.crawler_port` defaults to `0`, which `Source.forListenerPort` reads as
"no crawler configured": a deployment that never sets it attributes every
request whose own listener port parses to `OPERATOR`, rather than accidentally
applying the agent's rules to a human.

The request handler, in order:

1. **Attribute the source.** Parse the port off `listenerInterface()` after
   the **last** `:`. When that parse fails — a null interface, no colon, a
   non-numeric tail, a number outside `1..65535` — hand `Source.NO_PORT` over
   rather than inventing one. `forListenerPort` answers `UNATTRIBUTED`, and
   `ProxyGate` **refuses** it with `not_configured` and a detail carrying
   `BridgeClient.EXTENSION_FAULT`. **Do not catch that refusal and retry as
   `OPERATOR`.** "We could not work out who is driving" is a code failure, and
   the operator branch is the one that drops the method allowlist, the
   dangerous-path denylist, the rate limit and the budget.
2. **Read `authorisation()` ONCE** into a local and pass it in. `configEpoch()`
   and `scopeConfig()` are two reads of one record and can straddle a commit;
   a decision made from two halves of two authorisations is a decision about a
   request nobody authorised. `ChokepointTest.theAuthorisationSnapshotIsReadInExactlyOnePlace`
   already counts this — check what it counts before you add a second read.
3. **Ask the gate**, inside a `try`. A `RuntimeException` out of `decide` or
   out of building the `HxRequest` is **DENY**, with `not_configured` and an
   `EXTENSION_FAULT` detail. A gate that threw has decided nothing, and the
   only safe reading of "nothing" is no.
4. **On refusal:** `capture.offer(new Denied(...))` carrying the verdict's
   `errorClass` and `detail`, then `return ProxyRequestReceivedAction.drop()`.
5. **On pass:** `pending.put(r.messageId(), System.nanoTime(), source)`, then
   `return ProxyRequestReceivedAction.continueWith(r)`.

`System.nanoTime()`, not the wall clock: this is a **duration**. `Instant.now()`
would measure an NTP step as latency. The entry point's `montoyaHttp` adapter
already makes this distinction and says why — match it.

The response handler (`handleResponseReceived`):

1. `Pending.Entry e = pending.take(r.messageId())`.
2. **On a miss:** `capture.countLost(<source from nothing>)` — and here is the
   one place the source is genuinely unknown, so count it against
   `Source.UNATTRIBUTED` and let it be a drop with no run attached rather than
   guessing a run. Then `continueWith`. **Do not record an exchange with a
   fabricated duration**; this project has refused fabricated evidence twice
   already (`transport_error`'s absence, and the 599 sentinel's separate
   outcome) and this is the same rule.
3. **On a hit:** redact **both halves** before anything else —
   `redactor.redactResponse(r.toByteArray().getBytes())` and
   `redactor.redactRequest(reqBytes, new Injected(reqBytes))` where `reqBytes`
   is `r.initiatingRequest().toByteArray().getBytes()`. The proxy path injects
   no identity, so the `Injected` is empty; it is still required, and it must
   be constructed **over the same array** the ranges would have been measured
   from — `Injected` compares by identity and refuses a different array.
4. `capture.offer(new Observed(method, url, r.statusCode(), ms, redactedReq,
   redactedResp, e.source()))`, then `continueWith`.

`ms` is `(System.nanoTime() - e.startNanos()) / 1_000_000L`.

**Redaction runs before `offer`, not after, and not in the drain.** S7 makes
the blob store content-addressed: a credential that reaches the hashing step
on the Python side is already unrecoverable. `Observed`'s own javadoc says its
byte arrays are post-redaction — an `Observed` holding raw bytes is a live
credential sitting in a queue, and it is the exact defect Step 7 row D exists
to catch.

Finally, `capture.start()` alongside `haltSwitch.start()`, and
`capture.stop()` in the unloading handler that already closes the bridge —
read the field into a local first, the way `client` and `halt` are, because
that handler runs on a different thread than `initialize`.

- [ ] **Step 5: Scope again, at the last point before the bytes leave**

`ProxyRequestHandler` has **two** methods. `handleRequestReceived` fires when
the request arrives from the browser; `handleRequestToBeSent` fires after
Burp's interception step, immediately before the request goes to the target.
Between them sits the Intercept tab, where an operator can rewrite the
request — including its host.

A gate that runs only at the first point therefore lets an **edited** request
leave without any decision at all. §4 is unambiguous about what that costs:
*"Scope is absolute at both points, for all traffic. It is the client's
boundary and the one thing no caller may spend."* A request that changed after
it was decided about is a request nobody decided about, and this is the one
hole in the whole system where bytes could cross the engagement boundary.

So `handleRequestToBeSent` asks **scope and nothing else**, for **every**
source:

- build the `HxRequest` from `r` as it now stands,
- read `authorisation()` once,
- `policy.decideScopeOnly(req, auth)`,
- on refusal, `capture.offer(new Denied(...))`, discard the pending entry for
  `r.messageId()` (it will never be answered), and
  `return ProxyRequestToBeSentAction.drop()`,
- otherwise `continueWith(r)`.

**`decideScopeOnly`, never `decide`.** The full question reaches the Gate,
which spends a rate token and a budget slot — asking it twice would charge a
crawler twice for one request, and `ChokepointTest.bothHalvesOfTheDecisionAreAskedAndOnlyOnce`
would not see it, because that check counts `Policy`'s internal halves on the
send path. `decideScopeOnly` spends nothing, so this re-check is free.

Two honest limits, both stated rather than discovered:

- **`drop()` from this callback is unmeasured.** Task 1 measured the drop from
  `handleRequestReceived` only. Task 9 measures this one against real Burp.
  Until then the claim in this step is "Montoya documents both actions
  identically", not "we saw zero bytes".
- **This is a second scope decision, not a second enforcement point.** §4
  counts egress paths, not callbacks; both of these belong to the one proxy
  request handler, and `ChokepointTest`'s egress counts are unchanged by it.

`handleResponseToBeSent` stays a bare `continueWith` — the response has
already been captured at `handleResponseReceived`, and capturing it twice
would double every row.

- [ ] **Step 6: Grow the structural test**

Four new checks in `ChokepointTest`, all counted over `code()` — the
comment-and-literal-stripped text — because each must be **exactly one** and a
count that must be one can be supplied by a comment anywhere in the tree. (The
class's own javadoc explains the per-needle rule; read it before choosing
`text` over `code`.)

```java
    // The second egress point exists, exactly once each.
    check("registerRequestHandler appears exactly once (" + n1 + ")", n1 == 1);
    check("registerResponseHandler appears exactly once (" + n2 + ")", n2 == 1);
    // ...and the gate is inside it. A handler that forwards without asking is
    // a third egress path wearing the second one's name.
    check("the proxy handler asks the gate (" + n3 + ")", n3 == 1);
    // ...and scope is asked again at the last point before the bytes leave,
    // because the Intercept tab sits between the two callbacks.
    check("scope is re-decided before the request is sent (" + n4 + ")", n4 == 1);
```

Then the two this task exists to protect, and **neither has a check yet —
write them**:

- **The gate is consulted before anything is queued.** Enforcement never waits
  on capture. Assert by position, the way `theAdapterBuildsItsRequestInsideTheTry`
  does: in `HxExtension`'s `code()`, the index of the `gate.decide(` call is
  less than the index of the first `capture.offer(`.
- **`Redactor` runs on both halves before `capture.offer(`.** Same technique:
  the indices of `redactRequest(` and `redactResponse(` are both less than the
  index of the `capture.offer(new Observed`.

Positional checks have a known weakness — they pass on any file where the
needles happen to fall in that order — so each must be shown to **separate**:
Step 7 rows C and D are exactly those two mutations, and a row that reddens
nothing is the finding, not a pass.

Per **R1**, verify `noSecondEgressFamilyExists` still runs and still counts
zero. Do not duplicate it and do not give it an exception list.

- [ ] **Step 7: Sabotage — seven rows, judged by the twelve summary lines and the exit code**

| # | Edit | Expect red |
|---|---|---|
| A | comment out `registerRequestHandler` | the registration count |
| B | request handler returns `continueWith` without asking the gate | the gate-is-inside-it check |
| C | move `capture.offer` above the gate decision | the new ordering check |
| D | offer raw bytes instead of redacted | the new redaction-ordering check |
| E | `handleRequestToBeSent` returns `continueWith` unconditionally | the scope-re-decided check |
| F | `Pending.take` returns the entry without removing it | `PendingTest`'s consumed-once check |
| G | `add new java.net.Socket()` to any file in `extension/src` | `noSecondEgressFamilyExists` |

Row G is a **verification of R1**, not new work: it must redden the check that
already exists. If it does not, that is a finding about the existing check and
it is worth more than anything else in this table.

Rows C and D are the two properties this task exists to protect. Report each
row's summary-line count **and** exit code, per Rule 1 — a hang prints no
summary line at all.

- [ ] **Step 8: Commit, in two**

```bash
./extension/test.sh && ./extension/build.sh
.venv/bin/pytest -q
git add extension/src/hx/proxy/ extension/src/hx/bridge/BridgeClient.java \
        extension/test/hx/proxy/ extension/test.sh docs/bridge-protocol.md
git commit -m "feat(proxy): a denial is a record, and a pending request has a clock"

git add extension/src/hx/HxExtension.java extension/test/hx/ChokepointTest.java
git commit -m "feat(proxy): the second egress point is wired and counted"
```

Do **not** run `scripts/sync_plan_block.py` — see R4.
### Task 8: `hx capture` and a grown `hx info`

Two verbs and a report. The CLI is where a human finds out what happened, and
§5's rule that a run with drops has coverage numbers which are a **floor** is
only true if something says so out loud.

**Corrections to this section, made before dispatch. The originals were wrong
about this repository.**

- **The CLI is `click`, not argparse, and there is no `run_cli` helper.**
  `src/hx/cli.py` is a `@click.group()` named `main` with two commands, `new`
  and `info`. Every test in `tests/test_cli.py` drives it with
  `click.testing.CliRunner().invoke(cli.main, [...])`. Use that; do not invent
  a wrapper.
- **None of the three fixtures named below existed.** Existing tests build an
  engagement inline by invoking `new` with `--root tmp_path`. Write the
  fixtures; do not assume them.
- **`hx capture stop` needs to say WHICH run.** There can be more than one
  live run at a time — `run.current_run` is per-kind, deliberately, because a
  crawl running while you browse is two runs. Ruled: **`stop` closes every
  live run of the engagement**, because that is what an operator means by
  "stop capturing", and reports how many it closed. `--kind` narrows it.
- **The close is `status='completed'`, `stop_reason='operator'`.**
  `run.status`'s CHECK is `running|completed|aborted|killed|error`;
  `stop_reason` is free text. An operator stopping a run is not an `error` and
  not `aborted` — those mean the harness or the auto-halt ended it.
- **`current_run` already anticipates this task** and its docstring says so:
  auto-open is the fallback so that an hour of browsing is never lost to a
  forgotten command, and `hx capture start` is the deliberately-named path.
  Do not remove or weaken auto-open.

**Files:**
- Modify: `src/hx/cli.py`
- Test: extend `tests/test_cli.py`

**Interfaces:**
- Consumes: `hx.run` — `open_run`, `close_run`, `current_run`, `reap_stale`,
  `RUN_KINDS`; `hx.config` for `safety_profile`; the `run`, `surface`,
  `exchange` and `denial` tables.
- Produces: `hx capture start [--kind browse]`, `hx capture stop [--kind ...]`,
  and `hx info` grown. Nothing later in this plan consumes them as Python;
  Task 9 drives them as a **subprocess**.

- [ ] **Step 1: Write the failing tests**

Three fixtures first, because six tests need them and none exists. Build them
on top of the `new` command the way the existing tests do, then write rows
through `hx.run` / `hx.store.records` rather than by hand-rolled SQL — a
fixture that invents its own INSERT is a second writer of the schema and will
drift from the real one.

```python
@pytest.fixture
def engagement(tmp_path: Path) -> Path:
    """A real engagement, made the way an operator makes one."""
    result = CliRunner().invoke(cli.main, [
        "new", "acme-2026-09", "--client", "Acme Corp",
        "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    return tmp_path
```

`engagement_with_drops` opens a run and calls `run.count_drop(..., n=4)`.
`engagement_with_stale_run` opens a run and backdates its `heartbeat_us` by
more than `run.IDLE_CLOSE_US` so `reap_stale` has something to find.

```python
def test_capture_start_opens_a_named_run(engagement):
    result = CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "browse" in result.output

def test_capture_start_refuses_a_kind_the_schema_will_not_take(engagement):
    """The vocabulary lives in run.RUN_KINDS and in a CHECK. A bad --kind must
    be refused by the CLI with a readable message, not by SQLite with
    `CHECK constraint failed: run`."""
    result = CliRunner().invoke(cli.main,
        ["capture", "start", "--kind", "scheduled", "--root", str(engagement)])
    assert result.exit_code != 0
    assert "scheduled" in result.output

def test_capture_stop_closes_it(engagement):
    CliRunner().invoke(cli.main, ["capture", "start", "--root", str(engagement)])
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output

def test_capture_stop_closes_every_live_run(engagement):
    """Two kinds live at once is the normal case, not the exotic one: a crawl
    runs while a human browses. An operator typing `stop` means both."""
    for kind in ("browse", "crawl"):
        CliRunner().invoke(cli.main,
            ["capture", "start", "--kind", kind, "--root", str(engagement)])
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "2" in result.output
    # ...and assert against the STORE, not the wording: no run of this
    # engagement is left with status='running'.

def test_capture_stop_with_no_run_says_so_rather_than_failing(engagement):
    """An operator typing stop twice has made no mistake worth an error."""
    result = CliRunner().invoke(cli.main, ["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "no" in result.output.lower()

def test_info_reports_drops_loudly_when_there_are_any(engagement_with_drops):
    """S5: a run with drops has coverage numbers that are a FLOOR, not a
    count. An operator who does not know that reads the surface count as
    complete."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement_with_drops)])
    assert "floor" in result.output.lower()
    # The COUNT, in its own context. A bare `"4" in output` passes on any
    # unrelated 4 -- four surfaces, a timestamp digit -- which is the shape of
    # a test that reads green for the wrong reason.
    assert "4 dropped" in result.output

def test_info_says_nothing_alarming_when_there_are_no_drops(engagement):
    """The separating case. A warning that is always present is not a
    warning."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert "floor" not in result.output.lower()

def test_info_reaps_stale_runs_before_reporting(engagement_with_stale_run):
    """Otherwise the first thing an operator sees after a crash is a run that
    claims to be running."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement_with_stale_run)])
    assert "error" in result.output.lower()
```

- [ ] **Step 2: Implement**

`capture` is a `@main.group()` with `start` and `stop` beneath it, matching
`new` and `info` on `--root`.

- `start` reads the profile from the engagement config, calls
  `run.current_run` — not `open_run`, so typing `start` twice is idempotent
  rather than two runs — and prints the kind and the run id.
- `stop` closes every live run with `status='completed'`,
  `stop_reason='operator'`, and prints how many it closed.
- `--kind` is validated against `run.RUN_KINDS` with
  `click.Choice(sorted(run.RUN_KINDS))`, so the vocabulary is DERIVED and
  cannot drift from the schema — `tests/test_vocabularies_match_the_schema.py`
  already pins `RUN_KINDS` against the CHECK, and reaching through it here
  means this file adds no third copy.

`hx info` gains, in this order:

- `run.reap_stale` **first**, so a crashed run reads `error` rather than
  `running`;
- surfaces by `kind`, exchanges by `outcome`, denials by `kind` — three
  `GROUP BY` counts;
- and, only when some run has `dropped_total > 0`, a line naming the total and
  saying the numbers above are a **floor**.

The floor line is the point of the task. Write it so it cannot be skimmed
past, and so the word the test pins (`floor`) is the word an operator reads.

- [ ] **Step 3: Run, and check the separating case**

```bash
.venv/bin/pytest tests/test_cli.py -q
```

Then the sabotage sweep, judged by the pytest summary line:

| # | Edit | Expect red |
|---|---|---|
| A | drop the `reap_stale` call from `info` | the stale-run test |
| B | print the floor line unconditionally | the no-drops test |
| C | print it never | the drops test |
| D | `stop` closes only the newest live run | the every-live-run test |
| E | `start` calls `open_run` instead of `current_run` | add a test if none reddens: `start` twice must not make two runs |
| F | `--kind` accepts any string | the bad-kind test |

Row E is the one to watch: if nothing reddens, that is the finding, and the
test it needs is the one this table names.

- [ ] **Step 4: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/cli.py tests/test_cli.py
git commit -m "feat(cli): capture start/stop, and info that admits its gaps"
```

---
### Task 9: End to end, against real Burp

Everything before this was fakes and unit tests. This is the task that finds what the fakes agreed to be wrong about — on the previous branch, the equivalent task changed no production code at all and found three tests that wrote **zero frames to the socket** while claiming to prove the invariant.

**Corrections made before dispatch. Six things this section was wrong or silent about.**

- **`launch_burp` does not pass `-Dhx.crawler_port`, and without it test 5 cannot pass.**
  Task 7 reads the crawler listener from that property, defaulting to `0`, which
  `Source.forListenerPort` reads as "no crawler configured" — so **every** request
  attributes to `OPERATOR` and the operator/crawler split proves nothing. This is
  precisely the `-Dhx.halt_sentinel` incident that `launch_burp`'s own comment
  documents: *"Task 6 made it mandatory and this fixture was not updated — the
  integration tests are deselected from the default run, so nothing said so for a
  day."* Do not repeat it two tasks later.
- **`BridgeServer` in the rig is built with NO `on_exchange` sink.** Exchange,
  denial and dropped frames are read and **discarded**. Install
  `hx.capture.Capture` as the sink or every assertion below reads an empty
  database while Burp cheerfully sends frames — and the natural, wrong diagnosis
  is to blame the extension.
- **The second listener already exists — in `launch_probe`, not `launch_burp`.**
  Lift the mechanism, do not reinvent it. It matters *how* it works: **Burp
  Community has no API for creating a listener**, so the second one comes from a
  project config file passed with `--config-file`, and **both** listeners are
  written explicitly — a config naming only the second leaves the first wherever
  Burp's defaults put it, which is the 8080 `_free_port()` exists to avoid.
  `proxy_port()` and `second_proxy_port()` read the real ports back.
- **`loopback_only` is not self-enforcing.** That string was the whole of the
  protection until `not_loopback_only()` was written, and changing it to
  `all_interfaces` left the suite green with the proxy bound to `*` — an open
  relay on whatever network the laptop is attached to. Call
  `not_loopback_only(pid, ports)` once the new listeners are up, as
  `test_proxy_facts.py`'s fixture does.
- **The count is stale.** There are **17** existing integration tests, not 14. The
  target is **24 passed**, and a run reporting 21 is a run that lost three.
- **The rig hand-inserts a `manual` run row.** Plan 4 owns run lifecycle now, and
  `capture.py` auto-opens `browse`/`crawl` runs. `current_run` is per-kind, so the
  pre-inserted `manual` row will not satisfy a `browse` lookup and a second run
  opens — which is correct, and is what test 6 asserts. Do not "fix" it.

**Files:**
- Create: `tests/integration/test_proxy_capture.py`
- Modify: `tests/integration/burp_fixture.py` (two listeners on `launch_burp`, and `-Dhx.crawler_port`), `tests/integration/conftest.py` (the capture sink, and the ports on the rig)

- [ ] **Step 1: Extend the rig**

Three changes, each named above:

1. `launch_burp` writes a two-listener project config the way `launch_probe`
   does, passes `--config-file`, and takes the crawler port so it can pass
   `-Dhx.crawler_port`. The operator listener is the first; the crawler
   listener is the second.
2. `conftest.rig` constructs `hx.capture.Capture` over the engagement's db,
   blob store and config, and installs it as `BridgeServer(on_exchange=...)`.
3. `Rig` gains the two ports, so a test can send through either.

Then assert the safety property before any test uses the listeners:
`not_loopback_only(proc.pid, ports)` must answer `None`.

- [ ] **Step 2: Write the end-to-end tests**

Seven, each proving a claim the unit tests can only assert:

1. **Browsing an in-scope URL through the proxy produces an exchange row**, with both blobs present on disk and readable.
2. **An out-of-scope URL is dropped**, the second target server — listening throughout — logs **zero** requests, and a `denial` row exists with `via='proxy'`. Assert against the TARGET's log, never the client's response: a drop returns `200 OK` with ~1529 bytes of Burp's own HTML, so the client cannot tell a drop from a delivery.
3. **Two ids under one endpoint produce one surface**, proven against a real normaliser on real captured traffic.
4. **A `Set-Cookie` in a real response is redacted before it reaches the blob store** — the blob is fetched and searched for the cookie value, which must be absent. §7's rule, on the live path. Do the same for a request `Cookie:` header, which is the hole five fix rounds closed.
5. **The operator listener allows a POST the crawler listener refuses** — the same request, two ports, two answers. This is the §4 split, end to end, and nothing short of two real listeners proves it.
6. **A run auto-opens on the first exchange** and its `kind` is `browse`.
7. **Killing the harness mid-browse does not stop the browser.** Stop `BridgeServer`, keep browsing, and assert the requests still reach the target. This is §4's "capture never gates enforcement" on the live path, and it is the one claim in this plan that a unit test structurally cannot make.

- [ ] **Step 3: Run**

Run: `.venv/bin/pytest -m integration -q`
Expected: **24 passed** (17 existing + 7). Judge by that summary line and the exit code. A run of 21 lost three tests; a run that prints no summary line hung.

- [ ] **Step 4: Report what real Burp disagreed with**

Write down every place the fakes and reality differed — timing, ordering, header casing, what `messageId()` did under load, whether `drop()` behaved as Task 1 measured, and whether `drop()` from `handleRequestToBeSent` behaves like the one from `handleRequestReceived` that Task 1 actually measured. **A report saying "everything matched" is one to disbelieve without the measurements behind it.**

Also settle P14, which five fix rounds could not: **does the handler HONOUR its verdict?** No unit test can see it — `if (!verdict.allow() && false)` is green in the whole suite. Test 2 is the one that closes it, and only if it reads the target's log.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/
git commit -m "test(proxy): the second enforcement point, proved against real Burp"
```

---
## What this plan does not do

- **The crawler.** Plan 5. This plan builds the listener it will arrive on and the rules that will govern it, so the crawler only has to drive. §9's hard decisions — `active_mutate`, per-run canary tokens, SPA route walking, the dangerous-path interaction — stay open for its own brainstorm.
- **Identity injection.** Plan 6. `Redactor.redactRequest` gets its first production caller here, which is what makes the two-body frame necessary now rather than then.
- **`scope_version_id` on `exchange` and `denial` rows.** Both record functions
  accept it and this plan passes `None`. The column is meant to pin which
  version of the scope a decision was made under, and the extension already
  carries the equivalent as `config_epoch` — but nothing writes a
  `scope_version` row, so there is no id to reference yet. Named here rather
  than left as an unexplained `None`: it is a real gap, it belongs to whichever
  plan first needs to answer "was this in scope at the time", and a reader
  finding `None` at that call site should find this sentence rather than assume
  an oversight.
- **The `scanStatus` head-boundary question.** Carried from Plan 3 and still a design question — whether `hx` should re-parse heads Burp has already parsed — rather than a patch.
