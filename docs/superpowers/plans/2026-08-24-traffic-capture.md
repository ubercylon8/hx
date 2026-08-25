# Traffic Capture Implementation Plan

<!-- plan-drift: pending -->
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
| `extension/src/hx/proxy/Source.java` | The traffic source enum (`OPERATOR`, `CRAWLER`) and how a request is attributed to one. One file because the attribution rule is the security boundary and must be readable on its own. |
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
"""
from __future__ import annotations

import http.client
import os
import time
from pathlib import Path

import pytest

from tests.integration import burp_fixture as bf
from tests.integration.target_server import TargetServer

pytestmark = pytest.mark.integration


@pytest.fixture
def probe(tmp_path):
    """Real Burp running the probe extension, with a private home."""
    if bf.missing():
        pytest.skip(f"missing: {', '.join(bf.missing())}")
    out = tmp_path / "probe.txt"
    target = TargetServer("127.0.0.1")
    target.start()
    proc = bf.launch_probe(tmp_path, out, extra_listener_port=0)
    try:
        assert bf.wait_for(lambda: out.exists() and "PROBE READY" in out.read_text()), \
            f"probe never started; burp.log: {tmp_path / 'burp.log'}"
        yield _Probe(out, target, bf.proxy_port(tmp_path))
    finally:
        proc.kill()
        proc.wait(timeout=30)
        target.stop()


class _Probe:
    def __init__(self, out: Path, target: TargetServer, proxy_port: int):
        self.out, self.target, self.proxy_port = out, target, proxy_port

    def lines(self) -> list[str]:
        return self.out.read_text().splitlines()

    def through_proxy(self, path: str, port: int | None = None) -> int | None:
        """One request through Burp's proxy. None means the connection died."""
        conn = http.client.HTTPConnection("127.0.0.1", port or self.proxy_port,
                                          timeout=10)
        try:
            conn.request("GET", f"{self.target.origin}{path}")
            return conn.getresponse().status
        except (http.client.HTTPException, OSError):
            return None
        finally:
            conn.close()
```

- [ ] **Step 4: Add the probe launcher to the fixture**

```python
# tests/integration/burp_fixture.py -- probe launch and listener discovery
def launch_probe(workdir: Path, out: Path,
                 extra_listener_port: int = 0) -> subprocess.Popen:
    """Burp running hx.proxy.Probe, with a SECOND proxy listener.

    The second listener is the whole point of Q1: one Burp, two ports, and the
    question is whether the extension can tell which one a request came in on.
    Port 0 means the caller does not care which port it gets; read the real one
    back with proxy_port().
    """
    home = make_home(workdir)
    log = (workdir / "burp.log").open("wb")
    cmd = [
        "java", "-Djava.awt.headless=true", f"-Duser.home={home}",
        f"-Dhx.probe.out={out}",
        *ADD_OPENS, "-cp", f"{BURP_JAR}:{EXT_JAR}",
        "burp.StartBurp",
        "--developer-extension-class-name=hx.proxy.Probe",
        "--disable-auto-update",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, cwd=LAB)
    proc.stdin.write(b"\n\n")
    proc.stdin.flush()
    return proc


def proxy_port(workdir: Path) -> int:
    """Burp Community's default proxy listener port.

    Hard-coded rather than discovered: Community does not expose a listener
    API and 8080 is its documented default. If a future Burp changes it, every
    test in test_proxy_facts.py fails at once, which is the correct blast
    radius for a wrong constant.
    """
    return 8080
```

- [ ] **Step 5: Write the three measurement tests**

```python
# tests/integration/test_proxy_facts.py -- the three questions
def test_q1_whether_a_request_names_the_listener_it_arrived_on(probe):
    """Q1. Plan 4's operator/crawler split rests on this answer.

    This test does NOT assert a particular answer -- it RECORDS one, and fails
    only if the set of available accessors changes. Both answers are workable:
    if a listener accessor exists, Source.attribute reads it; if not, the
    fallback is a second BridgeClient on a second socket. What must not happen
    is building on a guess.
    """
    assert probe.through_proxy("/health") == 200
    req = [l for l in probe.lines() if l.startswith("REQ ")]
    assert req, "no request reached the handler"
    line = req[0]
    present = {name for name in
               ("listenerInterface", "listenerPort", "sourceIpAddress",
                "destinationIpAddress", "httpService")
               if f"{name}=<absent>" not in line}
    recorded = Path("docs/burp-proxy-measurements.md").read_text()
    for name in present:
        assert name in recorded, (
            f"{name} is available on InterceptedRequest and is not recorded in "
            "docs/burp-proxy-measurements.md -- record what Burp offers before "
            "designing around what it does not")


def test_q2_message_id_correlates_a_response_to_its_request(probe):
    """Q2. Capture pairs the two halves of an exchange by this id."""
    assert probe.through_proxy("/health") == 200
    assert probe.through_proxy("/echo?x=1") == 200
    reqs = {l.split()[1] for l in probe.lines() if l.startswith("REQ ")}
    resps = {l.split()[1] for l in probe.lines() if l.startswith("RESP ")}
    assert resps, "no response reached the handler"
    assert resps <= reqs, (
        f"a response carried an id no request did: {resps - reqs}. Capture "
        "cannot pair the halves of an exchange by messageId if this is false.")


def test_q3_drop_means_the_target_receives_nothing(probe):
    """Q3. The whole enforcement claim for this egress point.

    The target server is LISTENING throughout. A drop that merely fails to
    forward is indistinguishable from a connection error unless something on
    the far side can say it saw nothing -- which is why this asserts on the
    target's own log rather than on what the client got back.
    """
    before = len(probe.target.hits)
    probe.through_proxy("/drop/secret")
    time.sleep(0.5)
    assert len(probe.target.hits) == before, (
        f"drop() did not prevent egress: the target received "
        f"{probe.target.hits[before:]}")
    assert any(l.startswith("DROPPED ") for l in probe.lines()), \
        "the handler never reached its drop branch; the test proved nothing"
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

import pytest

from hx import surface

PRESERVE = frozenset({"api", "v1", "v2", "v3"})
KW = {"preserve": PRESERVE, "slug_threshold": 12}


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


class TestPreservedSegments:
    def test_a_preserved_segment_is_never_templated(self):
        """`v1` is digits-adjacent and must survive; this is why the list exists."""
        assert t("/api/v1/order/7") == "/api/v1/order/{id}"

    def test_even_when_it_would_otherwise_match_a_rule(self):
        assert t("/v2") == "/v2"

    def test_a_segment_not_on_the_list_gets_no_protection(self):
        """Separates the preserve list from a blanket exemption."""
        assert t("/v9/order/7") == "/v9/order/{id}"


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

    def test_the_host_is_lowercased_and_the_path_is_not(self):
        """Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not.
        Lowercasing a path would merge /Admin and /admin, which on some
        servers are two different places."""
        n = surface.normalise("GET", "http://APP.Test/Admin", **KW)
        assert n.host == "app.test"
        assert n.path_template == "/Admin"


def test_the_version_is_an_integer_that_someone_must_bump():
    """A rule change without a version bump silently reinterprets history:
    old rows claim a template the current rules would never produce."""
    assert isinstance(surface.NORMALISER_VERSION, int)
    assert surface.NORMALISER_VERSION >= 1
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
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

# Bump this when any rule below changes. A rule change without a bump silently
# reinterprets history: rows written yesterday claim a template today's rules
# would never produce, and nothing can tell the two apart afterwards.
NORMALISER_VERSION = 1

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


def _decode_segment(seg: str) -> str:
    """Percent-decode one segment, but never into a separator.

    `/order/%31` and `/order/1` are one endpoint and must template alike.
    `/a%2fb` is NOT `/a/b`: whether the server splits on an encoded slash is
    the server's business, and assuming it does would merge two different
    endpoints into one surface. So a decode that would introduce a `/` is
    refused and the segment stays verbatim.

    A malformed escape is left alone for the same reason -- `unquote` is happy
    to hand back `%zz` unchanged, and guessing at a repair would be inventing
    a URL the client never saw.
    """
    decoded = unquote(seg)
    if "/" in decoded:
        return seg
    return decoded


def _template_segment(seg: str, preserve: frozenset[str],
                      slug_threshold: int) -> str:
    if seg in preserve:
        # Checked BEFORE decoding and before every shape rule: `v1` is
        # digit-adjacent and `v2` would otherwise survive only by accident.
        return seg
    decoded = _decode_segment(seg)
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
    return decoded


def path_template(path: str, *, preserve: frozenset[str],
                  slug_threshold: int) -> str:
    """The path with identifier-shaped segments replaced by placeholders."""
    if not path:
        return "/"
    # A trailing slash is significant: `/order/` and `/order` can be different
    # routes, and merging them is a guess about someone else's router. Split
    # keeps the empty final segment, and join puts it back.
    segments = path.split("/")
    out = [segments[0]]   # always "" for an absolute path
    for seg in segments[1:]:
        out.append(_template_segment(seg, preserve, slug_threshold) if seg else seg)
    return "/".join(out)


def query_key_set(query: str) -> str:
    """The comma-joined sorted set of query KEYS, values discarded.

    Two requests to the same endpoint differing only in a value are one
    surface. Two differing in which PARAMETERS they carry are not: a parameter
    is an input, and an input is where a flaw lives.
    """
    if not query:
        return ""
    keys = {k for k, _ in parse_qsl(query, keep_blank_values=True)}
    return ",".join(sorted(keys))


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
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    # Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not. Lowercasing
    # a path would merge /Admin and /admin, which on some servers are two
    # different places and on others are one -- and we do not get to decide
    # which server we are talking to.
    host = (parts.hostname or "").lower()
    port = parts.port or _DEFAULT_PORT.get(scheme, 0)
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

    def test_one_microsecond_inside_the_window_is_still_the_same_run(self, conn):
        """Inside the window, well away from the boundary."""
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production",
                                now_us=1000 + run_mod.IDLE_CLOSE_US - 1)
        assert b == a


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
        "SELECT id, heartbeat_us FROM run"
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


def reap_stale(conn: sqlite3.Connection, *, now_us: int | None = None,
               stale_after_us: int | None = None) -> list[str]:
    """Resolve runs whose harness died to `error`. Returns their ids.

    Deliberately a WIDER window than IDLE_CLOSE_US: an idle run is one nobody
    used, and a stale one is a run whose process is gone. Reaping at the idle
    boundary would file every ordinary pause as a crash.
    """
    at = _now_us() if now_us is None else now_us
    window = IDLE_CLOSE_US * 2 if stale_after_us is None else stale_after_us
    # COALESCE, not a bare comparison: heartbeat_us is NULLable, and in SQL
    # `NULL < x` is NULL, which WHERE treats as false. A `running` run that
    # never heartbeated at all would therefore never be reaped -- and a run
    # that died before its first heartbeat is precisely the case this
    # mechanism exists for. It falls back to started_us, which is NOT NULL, so
    # a run that started long ago and never reported is stale on its own
    # evidence.
    rows = conn.execute(
        "SELECT id FROM run WHERE status='running'"
        " AND COALESCE(heartbeat_us, started_us) < ?",
        (at - window,)).fetchall()
    ids = [r[0] for r in rows]
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
    """
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
def cap(tmp_path):
    root = tmp_path / "engagement"
    paths_mod.secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES(?,'T','T',1,'active')", (ENG,))
    cfg = config_mod.Config(name="t", client="t",
                            scope_include=["http://app.test/*"])
    c = cap_mod.Capture(conn=conn, blobs=blobs_mod.BlobStore(root / "blobs"),
                        engagement_id=ENG, config=cfg)
    yield c
    conn.close()


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


class TestRefusals:
    def test_an_unknown_via_is_refused(self, cap):
        with pytest.raises(ValueError, match="via"):
            cap.on_exchange(_header(via="carrier-pigeon"), REQ, RESP)

    def test_a_frame_with_no_url_is_refused_rather_than_guessed(self, cap):
        with pytest.raises(ValueError):
            cap.on_exchange(_header(url=None), REQ, RESP)
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_capture.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.capture'`

- [ ] **Step 3: Add `via` to the two record functions**

In `src/hx/store/records.py`, add near `EXCHANGE_OUTCOMES`:

```python
# src/hx/store/records.py -- the via vocabulary
# S5's `via` vocabulary, and the schema's CHECK enforces the same three. The
# send path was the only writer until Plan 4; `proxy` and `crawl` are the two
# other egress points, and a fourth value would mean a fourth path -- which S4
# forbids outright.
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
module is deliberately thin: it validates, it delegates, and it owns no rules
of its own beyond the order things happen in.

The order is load-bearing. Blobs are written BEFORE the row that names them,
so a crash between the two leaves an orphan blob rather than a row pointing at
nothing -- an orphan is garbage, a dangling reference is corruption.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from hx import config as config_mod
from hx import run as run_mod
from hx import surface as surface_mod
from hx.engagement import now_us
from hx.store import records
from hx.store.blobs import BlobStore


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

        if t == "dropped":
            n = int(header.get("n", 1))
            run_mod.count_drop(self.conn,
                               run_id=self._run(header.get("source", "operator")),
                               n=n)
            return None

        via = header.get("via", "proxy")
        if via not in records.VIA_VALUES:
            raise ValueError(f"unknown via {via!r}")
        url = header.get("url")
        if not url:
            raise ValueError("exchange frame has no url")
        method = header.get("method") or ""
        run_id = self._run(header.get("source", "operator"))
        at = now_us()
        run_mod.heartbeat(self.conn, run_id=run_id, now_us=at)

        if t == "denial":
            error_class = header.get("error_class") or ""
            # row_for answers ("denial", kind) OR ("exchange", outcome) -- it
            # is the supported way in precisely because reading DENIAL_KIND
            # directly gets the precedence wrong for the two classes that
            # appear in both maps. So the table it names is checked, not
            # assumed: passing an OUTCOME where a KIND belongs would fail the
            # denial table's CHECK at the far end of a read thread.
            row = records.row_for(error_class, issued=False)
            if row is None:
                return None
            table, value = row
            if table != "denial":
                raise ValueError(
                    f"{error_class!r} routes to {table!r}, not a denial; a "
                    "dropped request that produced no exchange cannot be "
                    "recorded as one")
            records.record_denial(
                self.conn, run_id=run_id, kind=value, method=method, url=url,
                detail=header.get("detail") or "", at_us=at, via=via)
            return None

        n = surface_mod.normalise(
            method, url,
            preserve=frozenset(self.config.preserve_segments),
            slug_threshold=self.config.slug_threshold)

        # Blobs first: an orphan blob is garbage, a row naming a blob that was
        # never written is corruption.
        req_blob, _ = self.blobs.put(request) if request else (None, None)
        resp_blob, resp_len = (self.blobs.put(response) if response
                               else (None, None))

        exchange_id = records.record_exchange(
            self.conn, run_id=run_id, method=method, url=url,
            status=header.get("status"), req_blob=req_blob,
            resp_blob=resp_blob, resp_len=resp_len,
            ms=int(header.get("ms") or 0), at_us=at,
            outcome=header.get("outcome") or "ok", via=via)

        # S5's run.requests_issued, which nothing has ever written to. It
        # counts what LEFT, so it is bumped here and not on the denial path:
        # a refused request is in `denial`, and counting it as issued would
        # inflate every coverage figure derived from this column.
        self.conn.execute(
            "UPDATE run SET requests_issued = requests_issued + 1 WHERE id=?",
            (run_id,))

        self.upsert_surface(n, exchange_id=exchange_id, run_id=run_id)
        return exchange_id

    def upsert_surface(self, n: surface_mod.Normalised, *, exchange_id: str,
                       run_id: str) -> str:
        """Insert or touch the surface this exchange belongs to.

        `first_seen_run` is written once and never updated; `last_seen_run`
        moves. The exemplar is likewise set only on insert -- a surface's
        exemplar is the first exchange that proved it exists, and rewriting it
        on every sighting would make "show me an example of this endpoint"
        return whatever happened most recently rather than what was reviewed.
        """
        self.conn.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
            " path_template, query_key_set, kind, normaliser_version,"
            " first_seen_run, last_seen_run, exemplar_exchange_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, method, scheme, host, port,"
            "             path_template, query_key_set)"
            " DO UPDATE SET last_seen_run=excluded.last_seen_run",
            (records.new_id("s"), self.engagement_id, n.method, n.scheme,
             n.host, n.port, n.path_template, n.query_key_set, n.kind,
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
- Modify: `extension/test.sh` — add `hx.proxy.ProxyGateTest` to `CLASSES`

**Interfaces:**
- Consumes: `hx.policy.Policy.decide(HxRequest, BridgeClient.Authorisation)`, `hx.policy.Decision`, `hx.policy.HxRequest`, `hx.bridge.BridgeClient.Authorisation`, `hx.policy.Gate`
- Produces:
  - `enum Source { OPERATOR, CRAWLER }` with `static Source forListenerPort(int port, int crawlerPort)`
  - `record ProxyGate.Verdict(boolean allow, String errorClass, String detail)`
  - `ProxyGate(Policy policy, Gate gate)` and `Verdict decide(HxRequest req, Authorisation auth, Source source)`

- [ ] **Step 1: Write the failing test**

```java
// extension/test/hx/proxy/ProxyGateTest.java
package hx.proxy;

import hx.TestSupport;
import hx.TestSupport.Reporter;
import hx.bridge.BridgeClient;
import hx.policy.*;

import java.util.List;
import java.util.Map;

/**
 * The gate, against fakes.
 *
 * The two cases that matter most are the pair: the SAME request is allowed
 * for the operator and refused for the crawler. A test that only exercises
 * one source cannot tell a working split from a gate that ignores source
 * entirely -- which is rule 3 on this project, and it fired on all eight
 * tasks of the previous plan.
 */
public class ProxyGateTest {
    public static void main(String[] args) throws Exception {
        Reporter r = new Reporter("ProxyGateTest");
        TestSupport.t(r, "scope is absolute for the operator",
                      ProxyGateTest::scopeIsAbsoluteForTheOperator);
        TestSupport.t(r, "and absolute for the crawler",
                      ProxyGateTest::scopeIsAbsoluteForTheCrawler);
        TestSupport.t(r, "the operator's own browsing is not method-checked",
                      ProxyGateTest::theOperatorIsNotMethodChecked);
        TestSupport.t(r, "but the crawler is",
                      ProxyGateTest::theCrawlerIsMethodChecked);
        TestSupport.t(r, "the operator is not dangerous-path checked",
                      ProxyGateTest::theOperatorIsNotDangerousPathChecked);
        TestSupport.t(r, "but the crawler is",
                      ProxyGateTest::theCrawlerIsDangerousPathChecked);
        TestSupport.t(r, "the operator does not spend the gate",
                      ProxyGateTest::theOperatorDoesNotSpendTheGate);
        TestSupport.t(r, "but the crawler does",
                      ProxyGateTest::theCrawlerSpendsTheGate);
        TestSupport.t(r, "an unconfigured extension refuses both sources",
                      ProxyGateTest::unconfiguredRefusesBoth);
        TestSupport.t(r, "the listener port decides the source",
                      ProxyGateTest::theListenerPortDecides);
        r.done();
    }

    static BridgeClient.Authorisation authorised() {
        return new BridgeClient.Authorisation(7, Map.of(
            "scope.include", List.of("http://app.test/*"),
            "method.allow", List.of("GET", "HEAD"),
            "dangerous.path", List.of("*/logout*")));
    }

    static HxRequest req(String method, String url) {
        return new HxRequest(method, url, "app.test",
                             java.net.URI.create(url).getPath(), "",
                             Map.of(), new byte[0]);
    }

    /** A Gate that counts, so "did this spend budget" is observable. */
    static final class CountingGate implements Gate {
        int calls;
        public Decision check(HxRequest r) { calls++; return Decision.allowed(); }
    }

    static void scopeIsAbsoluteForTheOperator() {
        ProxyGate g = new ProxyGate(new Policy(), new CountingGate());
        var v = g.decide(req("GET", "http://evil.test/x"), authorised(), Source.OPERATOR);
        TestSupport.check("out of scope is refused even for the operator", !v.allow());
        TestSupport.check("and the class names the boundary crossed (" + v.errorClass() + ")",
                          "scope_denied".equals(v.errorClass()));
    }

    static void scopeIsAbsoluteForTheCrawler() {
        ProxyGate g = new ProxyGate(new Policy(), new CountingGate());
        var v = g.decide(req("GET", "http://evil.test/x"), authorised(), Source.CRAWLER);
        TestSupport.check("out of scope is refused for the crawler too", !v.allow());
    }

    static void theOperatorIsNotMethodChecked() {
        ProxyGate g = new ProxyGate(new Policy(), new CountingGate());
        var v = g.decide(req("POST", "http://app.test/login"), authorised(), Source.OPERATOR);
        TestSupport.check("a POST the allowlist omits still goes out for a human ("
                          + v.errorClass() + ")", v.allow());
    }

    static void theCrawlerIsMethodChecked() {
        ProxyGate g = new ProxyGate(new Policy(), new CountingGate());
        var v = g.decide(req("POST", "http://app.test/login"), authorised(), Source.CRAWLER);
        TestSupport.check("the same POST is refused for the crawler", !v.allow());
        TestSupport.check("with method_denied (" + v.errorClass() + ")",
                          "method_denied".equals(v.errorClass()));
    }

    static void theOperatorIsNotDangerousPathChecked() {
        ProxyGate g = new ProxyGate(new Policy(), new CountingGate());
        var v = g.decide(req("GET", "http://app.test/logout"), authorised(), Source.OPERATOR);
        TestSupport.check("a deliberate click on a dangerous path is the operator's to make",
                          v.allow());
    }

    static void theCrawlerIsDangerousPathChecked() {
        ProxyGate g = new ProxyGate(new Policy(), new CountingGate());
        var v = g.decide(req("GET", "http://app.test/logout"), authorised(), Source.CRAWLER);
        TestSupport.check("a crawler that finds logout must not click it", !v.allow());
        TestSupport.check("with dangerous_denied (" + v.errorClass() + ")",
                          "dangerous_denied".equals(v.errorClass()));
    }

    static void theOperatorDoesNotSpendTheGate() {
        CountingGate gate = new CountingGate();
        new ProxyGate(new Policy(), gate)
            .decide(req("GET", "http://app.test/x"), authorised(), Source.OPERATOR);
        TestSupport.check("browsing does not spend the run's budget (" + gate.calls + ")",
                          gate.calls == 0);
    }

    static void theCrawlerSpendsTheGate() {
        CountingGate gate = new CountingGate();
        new ProxyGate(new Policy(), gate)
            .decide(req("GET", "http://app.test/x"), authorised(), Source.CRAWLER);
        TestSupport.check("crawling does (" + gate.calls + ")", gate.calls == 1);
    }

    static void unconfiguredRefusesBoth() {
        var none = new BridgeClient.Authorisation(0, Map.of());
        ProxyGate g = new ProxyGate(new Policy(), new CountingGate());
        for (Source s : Source.values()) {
            var v = g.decide(req("GET", "http://app.test/x"), none, s);
            TestSupport.check("DENY-ALL holds for " + s + " (" + v.errorClass() + ")",
                              !v.allow() && "not_configured".equals(v.errorClass()));
        }
    }

    static void theListenerPortDecides() {
        TestSupport.check("the crawler port attributes to CRAWLER",
                          Source.forListenerPort(8081, 8081) == Source.CRAWLER);
        TestSupport.check("any other port attributes to OPERATOR",
                          Source.forListenerPort(8080, 8081) == Source.OPERATOR);
        // The separating case. An unknown port must not become CRAWLER by
        // accident: crawler attribution is the STRICTER branch, and getting
        // it by default would silently apply the agent's rules to a human.
        TestSupport.check("and an unknown port is OPERATOR, not CRAWLER",
                          Source.forListenerPort(9999, 8081) == Source.OPERATOR);
        // ...and the converse, which is the one with teeth: a crawler port
        // that was never configured (0) must not swallow every request.
        TestSupport.check("an unconfigured crawler port matches nothing",
                          Source.forListenerPort(8080, 0) == Source.OPERATOR);
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
 * Who is driving: the operator's own browser, or the crawler.
 *
 * This is a security boundary and it has its own file so the rule can be read
 * without reading anything else.
 *
 * S4: the two are told apart by WHICH PROXY LISTENER the request arrived on,
 * never by anything in the traffic itself. A property of the connection
 * cannot be forged by a hostile page; a header can, and a page that could
 * make its requests look human-driven would dodge the crawler's rules
 * entirely -- including the dangerous-path denylist that exists so a crawler
 * finding "Delete account" does not click it.
 *
 * The default direction is deliberate and it is not the strict one. An
 * unrecognised port is OPERATOR, because crawler attribution applies the
 * AGENT's rules, and applying them to a human by accident is the failure that
 * drives an operator off the proxy -- at which point their traffic is not
 * recorded at all and the enforcement bought nothing. A crawler mis-attributed
 * as an operator is the safer error: its own harness still refuses what it
 * must, because the crawler is the thing asking.
 */
public enum Source {
    OPERATOR,
    CRAWLER;

    /**
     * @param port        the listener the request arrived on
     * @param crawlerPort the configured crawler listener, or 0 if there is none
     */
    public static Source forListenerPort(int port, int crawlerPort) {
        // `crawlerPort > 0` is load-bearing: with no crawler configured the
        // field is 0, and a bare equality test would attribute every request
        // arriving on port 0 -- and, worse, invites a future refactor where an
        // unknown port defaults to 0 and every request becomes CRAWLER.
        return (crawlerPort > 0 && port == crawlerPort) ? CRAWLER : OPERATOR;
    }
}
```

- [ ] **Step 4: Write `ProxyGate`**

```java
// extension/src/hx/proxy/ProxyGate.java
package hx.proxy;

import hx.bridge.BridgeClient;
import hx.policy.Decision;
import hx.policy.Gate;
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
 */
public final class ProxyGate {
    private final Policy policy;
    private final Gate gate;

    public ProxyGate(Policy policy, Gate gate) {
        this.policy = policy;
        this.gate = gate;
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
            // DENY-ALL is the initial and terminal state, at BOTH points.
            return new Verdict(false, "not_configured",
                               "no configure frame acknowledged yet");
        }
        if (source == Source.CRAWLER) {
            // The agent's rules, in S4's pinned order, gate included.
            Decision d = policy.decide(req, auth, gate);
            return d.allowed() ? Verdict.pass() : Verdict.deny(d);
        }
        // The operator: scope, and nothing else. `null` gate is not an
        // omission -- Policy consults the Gate last, and passing none is how
        // this call says the four agent rules do not apply. Policy.decide
        // must therefore accept a null gate and skip method, dangerous-path
        // and the gate itself; that is asserted by the pair of tests above.
        Decision d = policy.decideScopeOnly(req, auth);
        return d.allowed() ? Verdict.pass() : Verdict.deny(d);
    }
}
```

- [ ] **Step 5: Add `decideScopeOnly` to `Policy`**

`Policy` currently exposes `decide(req, auth, gate)`, which runs the full order. Add a sibling that stops after scope:

```java
    /**
     * Scope, and nothing after it.
     *
     * Separate method rather than a boolean parameter on `decide`, because a
     * boolean at a call site reads as a mode and this is a different
     * QUESTION. It also means the count test in ChokepointTest can assert
     * that exactly one caller asks the scope-only question, which a parameter
     * would make invisible.
     */
    public Decision decideScopeOnly(HxRequest req, BridgeClient.Authorisation auth) {
        Decision scope = checkScope(req, auth);
        return scope.allowed() ? Decision.allowed() : scope;
    }
```

- [ ] **Step 6: Register the test class**

Add `hx.proxy.ProxyGateTest` to `CLASSES` in `extension/test.sh`. The suite goes from nine summary lines to ten; every later step judges by ten.

- [ ] **Step 7: Run to verify it passes**

Run: `./extension/test.sh`
Expected: 10 × `ALL PASS`, no FAIL, no SKIP.

- [ ] **Step 8: Sabotage — six rows, each judged by the ten summary lines**

| # | Edit | Expect red |
|---|---|---|
| A | `decide` returns `Verdict.pass()` for `Source.OPERATOR` unconditionally | scope-is-absolute-for-the-operator |
| B | `Source.CRAWLER` takes the operator branch | the four crawler checks |
| C | `Source.OPERATOR` takes the crawler branch | the four operator checks |
| D | drop the `auth.epoch() == 0` guard | unconfigured-refuses-both |
| E | `forListenerPort` drops the `crawlerPort > 0` clause | unconfigured-crawler-port-matches-nothing |
| F | `forListenerPort` returns `CRAWLER` for an unknown port | unknown-port-is-OPERATOR |

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
import hx.TestSupport.Reporter;

import java.util.*;
import java.util.concurrent.*;

/**
 * The queue, and specifically the two things it must never do: block the
 * caller, and lose a record silently.
 */
public class CaptureTest {
    public static void main(String[] args) throws Exception {
        Reporter r = new Reporter("CaptureTest");
        TestSupport.t(r, "an offer reaches the sink", CaptureTest::anOfferReachesTheSink);
        TestSupport.t(r, "offering never blocks, even with no sink draining",
                      CaptureTest::offeringNeverBlocks);
        TestSupport.t(r, "a full queue drops the OLDEST, not the newest",
                      CaptureTest::aFullQueueDropsTheOldest);
        TestSupport.t(r, "and every drop is counted", CaptureTest::everyDropIsCounted);
        TestSupport.t(r, "and reported, not merely counted",
                      CaptureTest::dropsAreReported);
        TestSupport.t(r, "a sink that throws does not kill the drain thread",
                      CaptureTest::aThrowingSinkDoesNotKillTheDrain);
        TestSupport.t(r, "stop() does not hang on a wedged sink",
                      CaptureTest::stopDoesNotHang);
        r.done();
    }

    static Observed obs(int n) {
        return new Observed("GET", "http://app.test/" + n, 200, 5L,
                            ("req" + n).getBytes(), ("resp" + n).getBytes(),
                            Source.OPERATOR);
    }

    static final class Recording implements Capture.ExchangeSink {
        final List<String> seen = Collections.synchronizedList(new ArrayList<>());
        final List<Long> drops = Collections.synchronizedList(new ArrayList<>());
        volatile CountDownLatch gate;
        volatile boolean throwOnce;
        public void exchange(Map<String,Object> h, byte[] req, byte[] resp) {
            if (gate != null) { try { gate.await(); } catch (InterruptedException e) { return; } }
            if (throwOnce) { throwOnce = false; throw new RuntimeException("sink"); }
            seen.add(String.valueOf(h.get("url")));
        }
        public void dropped(long n, Source s) { drops.add(n); }
    }

    static void anOfferReachesTheSink() throws Exception {
        Recording sink = new Recording();
        Capture c = new Capture(8, sink);
        c.start();
        try {
            c.offer(obs(1));
            TestSupport.waitUntil(() -> sink.seen.size() == 1);
            TestSupport.check("the sink saw it", sink.seen.contains("http://app.test/1"));
        } finally { c.stop(); }
    }

    static void offeringNeverBlocks() throws Exception {
        // No drain thread at all: offer must still return promptly. This is
        // the property the operator's browser depends on.
        Capture c = new Capture(4, new Recording());
        long start = System.nanoTime();
        for (int i = 0; i < 1000; i++) c.offer(obs(i));
        long ms = (System.nanoTime() - start) / 1_000_000;
        TestSupport.check("1000 offers with nothing draining took " + ms + " ms",
                          ms < 1000);
    }

    static void aFullQueueDropsTheOldest() throws Exception {
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(2, sink);
        c.start();
        try {
            for (int i = 0; i < 6; i++) c.offer(obs(i));
            sink.gate.countDown();
            TestSupport.waitUntil(() -> sink.seen.size() >= 2);
            Thread.sleep(50);
            // The NEWEST survive. Oldest-first is the right eviction for
            // traffic: the recent requests are the ones an operator is
            // looking at, and the old ones are the ones already reasoned
            // about.
            TestSupport.check("the newest survived (" + sink.seen + ")",
                              sink.seen.contains("http://app.test/5"));
            TestSupport.check("and the oldest did not",
                              !sink.seen.contains("http://app.test/0"));
        } finally { c.stop(); }
    }

    static void everyDropIsCounted() throws Exception {
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);
        Capture c = new Capture(2, sink);
        try {
            for (int i = 0; i < 10; i++) c.offer(obs(i));
            TestSupport.check("dropped() counts them (" + c.dropped() + ")",
                              c.dropped() > 0);
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
            for (int i = 0; i < 10; i++) c.offer(obs(i));
            sink.gate.countDown();
            TestSupport.waitUntil(() -> !sink.drops.isEmpty());
            TestSupport.check("the sink was told (" + sink.drops + ")",
                              !sink.drops.isEmpty());
        } finally { c.stop(); }
    }

    static void aThrowingSinkDoesNotKillTheDrain() throws Exception {
        Recording sink = new Recording();
        sink.throwOnce = true;
        Capture c = new Capture(8, sink);
        c.start();
        try {
            c.offer(obs(1));
            c.offer(obs(2));
            TestSupport.waitUntil(() -> sink.seen.size() == 1);
            TestSupport.check("the record after the throw still arrived ("
                              + sink.seen + ")", sink.seen.contains("http://app.test/2"));
        } finally { c.stop(); }
    }

    static void stopDoesNotHang() throws Exception {
        Recording sink = new Recording();
        sink.gate = new CountDownLatch(1);   // never released
        Capture c = new Capture(8, sink);
        c.start();
        c.offer(obs(1));
        long start = System.nanoTime();
        c.stop();
        long ms = (System.nanoTime() - start) / 1_000_000;
        // Unloading the extension must not hang Burp. Same bound and same
        // reason as HaltSwitch.STOP_JOIN_MS.
        TestSupport.check("stop() returned in " + ms + " ms", ms < 4000);
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
 * `request` and `response` are post-redaction bytes. That is not a
 * convention: S7 says the blob store is content-addressed, so a credential
 * that reaches the hashing step is already unrecoverable, and the hashing
 * happens on the Python side. Redaction therefore has to be finished before
 * an Observed exists at all -- which is why the constructor takes bytes and
 * not a Montoya object.
 */
public record Observed(String method, String url, int status, long ms,
                       byte[] request, byte[] response, Source source) { }
```

```java
// extension/src/hx/proxy/Capture.java
package hx.proxy;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

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
 * ITS CONVERSE: a drop is never silent. Every eviction is counted and the
 * count crosses the bridge, because S5 says a run with drops has coverage
 * numbers that are a FLOOR and nothing on the far side can know that unless
 * it is told.
 *
 * Oldest-first eviction, deliberately. The recent requests are the ones an
 * operator is currently looking at; the old ones are already reasoned about.
 */
public final class Capture {
    public interface ExchangeSink {
        void exchange(Map<String, Object> header, byte[] request, byte[] response);
        void dropped(long n, Source source);
    }

    /** Same bound and same reason as HaltSwitch.STOP_JOIN_MS: unloading the
     *  extension must not hang Burp. */
    static final long STOP_JOIN_MS = 2000L;

    private final ArrayBlockingQueue<Observed> queue;
    private final ExchangeSink sink;
    private final AtomicLong dropped = new AtomicLong();
    private volatile Thread drain;
    private volatile boolean running;

    public Capture(int capacity, ExchangeSink sink) {
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.sink = sink;
    }

    public long dropped() { return dropped.get(); }

    /**
     * Never blocks, never throws, never reports failure to its caller.
     *
     * The caller is a Montoya proxy handler on Burp's own thread. There is
     * nothing useful it could do with an exception and one thing it must not
     * do, which is fail to forward the request.
     */
    public void offer(Observed o) {
        while (!queue.offer(o)) {
            // Evict the oldest and try again. `poll` returning null means
            // another thread drained it first, which is fine -- the retry
            // then succeeds.
            if (queue.poll() != null) dropped.incrementAndGet();
        }
    }

    public void start() {
        running = true;
        Thread t = new Thread(this::loop, "hx-capture");
        t.setDaemon(true);   // must never hold Burp open
        drain = t;
        t.start();
    }

    public void stop() {
        running = false;
        Thread t = drain;
        if (t != null) {
            t.interrupt();
            try {
                t.join(STOP_JOIN_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        drain = null;
    }

    private void loop() {
        long reported = 0;
        while (running) {
            Observed o;
            try {
                o = queue.take();
            } catch (InterruptedException e) {
                return;
            }
            try {
                Map<String, Object> h = new LinkedHashMap<>();
                h.put("t", "exchange");
                h.put("via", "proxy");
                h.put("source", o.source() == Source.CRAWLER ? "crawler" : "operator");
                h.put("method", o.method());
                h.put("url", o.url());
                h.put("status", (long) o.status());
                h.put("ms", o.ms());
                h.put("outcome", "ok");
                sink.exchange(h, o.request(), o.response());
            } catch (Throwable t) {
                // A sink that throws is someone else's code failing. Losing
                // this record is bad; losing every record after it because
                // the drain thread died is worse, and silent.
            }
            long now = dropped.get();
            if (now != reported) {
                try {
                    sink.dropped(now - reported, o.source());
                    reported = now;
                } catch (Throwable t) {
                    // Same reasoning; the count is cumulative, so the next
                    // successful report catches up.
                }
            }
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

### Task 7: Wire it, and grow the structural test

The pieces exist and nothing calls them. This task registers the handlers and makes the structural test cover the second egress point — including the gap the previous branch's whole-branch review left open.

**Files:**
- Modify: `extension/src/hx/HxExtension.java`, `extension/test/hx/ChokepointTest.java`

**Interfaces:**
- Consumes: everything from Tasks 5 and 6, plus `hx.send.Redactor`
- Produces: nothing new; this is the wiring task

- [ ] **Step 1: Register the handlers**

In `HxExtension.initialize`, after the send path is wired: construct `ProxyGate` and `Capture`, register a `ProxyRequestHandler` and a `ProxyResponseHandler`, and start the capture drain.

The request handler: read `authorisation()` **once**, attribute the `Source` from the listener (per Task 1's measured answer), ask `ProxyGate`, and either `drop()` — emitting a denial through the sink — or `continueWith`. The response handler pairs by `messageId()`, redacts both halves, and offers an `Observed`.

Two properties the code must have, and both are sabotaged in Step 3:

- **The gate is consulted before anything is queued.** Enforcement does not wait on capture.
- **`Redactor` runs on both halves before `Capture.offer`.** An `Observed` holding raw bytes would put a live credential in the queue, and §7 says the store is content-addressed so anything that reaches hashing is unrecoverable.

The crawler listener port comes from `-Dhx.crawler_port`, defaulting to `0` — which `Source.forListenerPort` reads as "no crawler configured", so a deployment that never sets it attributes everything to `OPERATOR` rather than accidentally applying the agent's rules to a human.

- [ ] **Step 2: Grow the structural test**

`ChokepointTest` asserts one Montoya HTTP call site. Add four checks, all counted over `code()` — the comment-and-literal-stripped text, so neither a comment nor a string can supply a wire:

```java
    // The second egress point exists, exactly once.
    check("registerRequestHandler appears exactly once (" + n1 + ")", n1 == 1);
    check("registerResponseHandler appears exactly once (" + n2 + ")", n2 == 1);
    // ...and the gate is inside it. A handler that forwards without asking is
    // a third egress path wearing the second one's name.
    check("the proxy handler asks the gate (" + n3 + ")", n3 == 1);
    // The family, not the spelling. The previous branch's whole-branch review
    // found ChokepointTest proving "one Montoya HTTP call" rather than "one
    // egress path": nothing counted java.net.Socket, HttpClient or
    // URL.openConnection, and BridgeClient already imports java.net.*, so a
    // future contributor needs no new import line to open one.
    check("no other socket-opening API appears in extension/src (" + n4 + ")",
          n4 == 0);
```

`n4` counts `new Socket(`, `HttpClient.`, `URL(`, `.openConnection(`, `SocketChannel.open(` across `extension/src`, **excluding** `BridgeClient.java`'s one legitimate `SocketChannel.open(UnixDomainSocketAddress` — named as a single explicit exception with its reason, the way `test_plan_matches_repo.py`'s `NOT_A_FILE` set is, so the exemption cannot quietly grow.

- [ ] **Step 3: Sabotage — five rows, judged by the eleven summary lines**

| # | Edit | Expect red |
|---|---|---|
| A | comment out `registerRequestHandler` | the registration count |
| B | handler returns `continueWith` without asking the gate | the gate-is-inside-it check |
| C | `Capture.offer` before the gate decides | a new check you must add; if nothing reddens, that is the finding |
| D | offer raw bytes instead of redacted | a new check; same rule |
| E | add `new java.net.Socket()` to any file in `extension/src` | the family count |

Row C and row D are the two this task exists to protect and neither has a check yet. Write them.

- [ ] **Step 4: Commit**

```bash
./extension/test.sh && ./extension/build.sh
./scripts/sync_plan_block.py docs/superpowers/plans/2026-08-24-traffic-capture.md \
    extension/src/hx/HxExtension.java extension/test/hx/ChokepointTest.java
git add extension/ docs/
git commit -m "feat(proxy): the second egress point is wired and counted"
```

---

### Task 8: `hx capture` and a grown `hx info`

Two verbs and a report. The CLI is where a human finds out what happened, and §5's rule that a run with drops has coverage numbers that are a floor is only true if something says so out loud.

**Files:**
- Modify: `src/hx/cli.py`
- Test: extend `tests/test_cli.py`

**Interfaces:**
- Consumes: `hx.run` — `open_run`, `close_run`, `current_run`, `reap_stale`; the `surface`, `exchange`, `denial` and `run` tables
- Produces: `hx capture start [--kind browse]`, `hx capture stop`, and `hx info` grown

- [ ] **Step 1: Write the failing tests**

```python
def test_capture_start_opens_a_named_run(engagement):
    result = run_cli(["capture", "start", "--root", str(engagement)])
    assert result.exit_code == 0
    assert "browse" in result.output

def test_capture_stop_closes_it(engagement):
    run_cli(["capture", "start", "--root", str(engagement)])
    result = run_cli(["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0

def test_capture_stop_with_no_run_says_so_rather_than_failing(engagement):
    """An operator typing stop twice has made no mistake worth an error."""
    result = run_cli(["capture", "stop", "--root", str(engagement)])
    assert result.exit_code == 0
    assert "no" in result.output.lower()

def test_info_reports_drops_loudly_when_there_are_any(engagement_with_drops):
    """S5: a run with drops has coverage numbers that are a FLOOR, not a
    count. An operator who does not know that reads the surface count as
    complete."""
    result = run_cli(["info", "--root", str(engagement_with_drops)])
    assert "incomplete" in result.output.lower()
    assert "4" in result.output

def test_info_says_nothing_alarming_when_there_are_no_drops(engagement):
    """The separating case. A warning that is always present is not a
    warning."""
    result = run_cli(["info", "--root", str(engagement)])
    assert "incomplete" not in result.output.lower()

def test_info_reaps_stale_runs_before_reporting(engagement_with_stale_run):
    """Otherwise the first thing an operator sees after a crash is a run that
    claims to be running."""
    result = run_cli(["info", "--root", str(engagement_with_stale_run)])
    assert "error" in result.output.lower()
```

- [ ] **Step 2–4: Implement, run, commit**

`hx info` gains: surfaces by kind, exchanges by outcome, denials by kind, and — when any run has `dropped_total > 0` — a line naming the count and saying the numbers above are a floor. It calls `run.reap_stale` first, so a crashed run is reported as `error` rather than as still running.

```bash
.venv/bin/pytest tests/test_cli.py -q
git add src/hx/cli.py tests/test_cli.py
git commit -m "feat(cli): capture start/stop, and info that admits its gaps"
```

---

### Task 9: End to end, against real Burp

Everything before this was fakes and unit tests. This is the task that finds what the fakes agreed to be wrong about — on the previous branch, the equivalent task changed no production code at all and found three tests that wrote **zero frames to the socket** while claiming to prove the invariant.

**Files:**
- Create: `tests/integration/test_proxy_capture.py`
- Modify: `tests/integration/burp_fixture.py` (a second proxy listener), `tests/integration/conftest.py` (extend the rig)

- [ ] **Step 1: Write the end-to-end tests**

Seven, each proving a claim the unit tests can only assert:

1. **Browsing an in-scope URL through the proxy produces an exchange row**, with both blobs present on disk and readable.
2. **An out-of-scope URL is dropped**, the second target server — listening throughout — logs **zero** requests, and a `denial` row exists with `via='proxy'`.
3. **Two ids under one endpoint produce one surface**, proven against a real normaliser on real captured traffic.
4. **A `Set-Cookie` in a real response is redacted before it reaches the blob store** — the blob is fetched and searched for the cookie value, which must be absent. §7's rule, on the live path.
5. **The operator listener allows a POST the crawler listener refuses** — the same request, two ports, two answers. This is the §4 split, end to end, and nothing short of two real listeners proves it.
6. **A run auto-opens on the first exchange** and its `kind` is `browse`.
7. **Killing the harness mid-browse does not stop the browser.** Stop `BridgeServer`, keep browsing, and assert the requests still reach the target. This is §4's "capture never gates enforcement" on the live path, and it is the one claim in this plan that a unit test structurally cannot make.

- [ ] **Step 2: Run**

Run: `.venv/bin/pytest -m integration -q`
Expected: 21 passed (14 existing + 7).

- [ ] **Step 3: Report what real Burp disagreed with**

Write down every place the fakes and reality differed — timing, ordering, header casing, what `messageId()` did under load, whether `drop()` behaved as Task 1 measured. **A report saying "everything matched" is one to disbelieve without the measurements behind it.**

- [ ] **Step 4: Commit**

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
