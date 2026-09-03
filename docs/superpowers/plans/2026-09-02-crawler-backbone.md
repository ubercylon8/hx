# Crawler Navigation Backbone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive Burp's bundled Chromium through the crawler proxy listener so that in-scope pages render, their JavaScript runs, and every request they make is recorded as `discovered_by = 'crawl'` — with budgets, honest truncation, and per-page render accounting.

**Architecture:** The crawler is a **traffic generator, not a discoverer**. It navigates a browser; the proxy records what the browser asks for; `capture` writes the surfaces. Control of the browser is Chrome DevTools Protocol carried over **file descriptors** (`--remote-debugging-pipe`), not a WebSocket, so nothing in `src/hx` gains the ability to address a network. The egress boundary the crawler crosses already exists and is already enforced: this plan adds a client to it, not a new one.

**Tech Stack:** Python 3.12 (stdlib only — `subprocess`, `os`, `json`, `selectors`, `html.parser`, `urllib.parse`), Burp Suite Community 2026.7.3 with its bundled Chromium 150.0.7871.186, Java 17 for the one extension change.

**Spec:** `docs/superpowers/specs/2026-09-02-crawler-design.md`
(master spec `docs/superpowers/specs/2026-08-21-hx-design.md`: §4 enforcement invariant, §5 data model, §9 discovery and crawling, §12 reporting, §13 v1 scope)

## Global Constraints

- **Loopback only.** No test may point a browser at a host outside `127.0.0.0/8`. `tests/integration/target_server.py` refuses anything else and that refusal is load-bearing, not tidiness.
- **`--proxy-bypass-list=<-loopback>` is mandatory on every browser launch.** Measured 2026-09-02: without it Chrome sent **0** connections to the proxy for a loopback target and reached it directly, around `ProxyGate` and every §4 enforcement point. Every target in this repo is loopback, so the flaw is invisible exactly where we are permitted to test.
- **No socket client in `src/hx`.** CDP travels over `--remote-debugging-pipe` (fds 3 and 4, NUL-separated JSON). Do not add `websockets`, `httpx`, `aiohttp`, or any package that opens a network connection. `pyproject.toml`'s httpx2 note is the standing reason.
- **The browser launches sandboxed.** Never pass `--no-sandbox`. If the sandbox will not initialise, refuse to crawl and say so; do not downgrade.
- **hx never bundles or redistributes Burp.** Chromium is located inside the operator's own Burp installation and is never copied, vendored, or downloaded.
- **Every security-relevant test is written so that a NAMED mutation turns it red, and the mutation is named in that test's own docstring.** This repo has shipped vacuous tests twice; the five shapes are catalogued in `docs/DECISIONS.md`.
- **The agent may never write finding status `confirmed` or `reported`.** Unchanged by this plan; do not touch the trigger.
- Engagement directories stay `0o700`, blob and DB files `0o600`.
- **ruff line-length is 88 and `E501` is NOT in `select`**, so ruff will not catch long lines. Check with `awk 'length > 88 {print FILENAME":"FNR": "length}' <files>`.
- **This plan must NOT carry the plan-drift pending marker** (the HTML comment `plan-drift: pending`). `2026-08-27-checks-and-reporting.md` holds it and `test_at_most_one_plan_is_pending` permits exactly one. Note that `_is_pending` substring-matches the first 40 lines and does not care that an occurrence sits inside a prohibition -- writing the marker out in full here would have made THIS plan pending, skipping every one of its code blocks from the gate. It did, on the first draft.
- **`EXPECTED_BLOCKS` in `tests/test_plan_matches_repo.py` must be updated in the same commit that adds this plan.** Run the drift gate and set it to the number the failure message reports.
- Java tests need the Montoya jar: `MONTOYA_JAR=$(pwd)/../burp-lab/probe/lib/montoya-api.jar ./extension/test.sh`. The default relative path does not resolve from a git worktree; both previous whole-branch reviewers hit this.

---

## File Structure

| File | Responsibility |
|---|---|
| `extension/src/hx/policy/Policy.java` *(modify)* | `render.allow` becomes enforceable, for the CRAWLER source only |
| `extension/src/hx/proxy/ProxyGate.java` *(modify)* | CRAWLER branch calls the render-aware decision |
| `src/hx/crawl/__init__.py` *(create)* | Package marker; re-exports nothing |
| `src/hx/crawl/cdp.py` *(create)* | CDP transport: framing, id correlation, timeouts. Knows nothing about crawling |
| `src/hx/crawl/browser.py` *(create)* | Locate Chromium, build the argv, launch sandboxed, tear down. Knows nothing about CDP semantics |
| `src/hx/crawl/frontier.py` *(create)* | The queue: scope refusal, dedupe, budgets. Pure functions over URLs |
| `src/hx/crawl/page.py` *(create)* | One page: navigate, settle, harvest, classify. Pure functions over CDP event streams |
| `src/hx/crawl/run.py` *(create)* | Orchestration: drive the frontier through the browser, build the summary |
| `src/hx/cli.py` *(modify)* | `hx crawl` |
| `src/hx/tools/impl/scan.py` *(modify)* | `crawl.run` handler replaces the stub; re-registered `needs_egress=True, mutates=True` |
| `src/hx/report.py` *(modify)* | The four disclosures of spec §9 |

The split is by responsibility and it is load-bearing for the tests: `cdp.py` can be driven by a fake child process, `frontier.py` and `page.py` are pure and need no browser at all. Only `browser.py` and `run.py` require real Chromium, and only in integration tests.

---

## Task 1: `render.allow` becomes enforceable

**Files:**
- Modify: `extension/src/hx/policy/Policy.java` (add `decideCrawl`, thread a flag through `checkScope`)
- Modify: `extension/src/hx/proxy/ProxyGate.java:182-185` (CRAWLER branch)
- Test: `extension/test/hx/policy/PolicyTest.java`

**Interfaces:**
- Consumes: `Decision.allow()`, `Decision.deny(String, String)`, the nested `Rule.forInclude(String)` / `Rule.forExclude(String)` / `r.allows(t, pathReadings)` / `r.denies(t, pathReadings)` / `r.source()`, and `BridgeClient.Authorisation.scope()` returning `Map<String, List<String>>`.
- Produces: `public Decision decideCrawl(HxRequest req, BridgeClient.Authorisation auth)` on `Policy`. Later tasks do not call it from Python; it is reached only through `ProxyGate`.

### Why this is Task 1 and why it is the only Java

`render_allow` is declared in three places and read in none:

- `src/hx/config.py:347` — `render_allow: list[str] = field(default_factory=list)`
- `src/hx/config.py:600` — shipped over the bridge as `render_allow`, arriving as the key `render.allow`
- `extension/src/hx/bridge/ConfigBody.java:15` — an accepted key in `KEYS`

`Policy.java` never references it. An operator who sets it today gets silence. That is harmless while nothing renders a page and stops being harmless the moment a browser starts loading subresources, which is Task 3 — so this lands first, with no browser code in the tree to confuse the review.

**Two properties are already structurally guaranteed and the test must pin them as structure, not simulate them as behaviour:**

1. **The proxy path injects no identity at all.** `grep -rn "identity" extension/src/hx/proxy/*.java` returns only comments — no `IdentityRegistry` reference exists in the package. So §4's *"identity is never attached to an out-of-scope destination"* cannot be violated by widening the crawler's allow set: there is no code on this path that could attach one.
2. **Identity attachment on the *send* path is gated by the identity's own registered origin**, not by the scope decision — `Sender.java:328-333` returns `identity_origin` with the comment *"The scope may well allow a third-party host; the operator's session on the TARGET has no business being sent to it."*

Do not write a test that "checks identity is not attached during a crawl". There is no code to make it fail. Write the structural assertion in Step 1 instead.

- [ ] **Step 1: Write the failing tests**

Add to `extension/test/hx/policy/PolicyTest.java`, and register each with `t("name", () -> ...)` inside `main` alongside the existing calls.

```java
// PolicyTest additions -- a sketch of the four cases, not a transcription
/** MUTATION: delete the `renders` loop from checkScope. Must go red. */
static void renderAllowLetsASubresourceThroughForTheCrawler() {
    Policy p = new Policy();
    BridgeClient.Authorisation auth = new BridgeClient.Authorisation(7, Map.of(
            "scope.include", List.of("https://app.test/*"),
            "render.allow", List.of("https://cdn.test/*")));
    HxRequest req = req("https://cdn.test/app.js", "cdn.test", "/app.js");
    check("crawler may render an allowed third-party subresource",
          p.decideCrawl(req, auth).allowed());
}

/** THE SEPARATING CASE. MUTATION: make `decide` consult render.allow too.
 *  Must go red -- a rendering concession must not widen what a CHECK can
 *  send a probe to. */
static void renderAllowDoesNotWidenTheSendPath() {
    Policy p = new Policy();
    BridgeClient.Authorisation auth = new BridgeClient.Authorisation(7, Map.of(
            "scope.include", List.of("https://app.test/*"),
            "render.allow", List.of("https://cdn.test/*")));
    HxRequest req = req("https://cdn.test/app.js", "cdn.test", "/app.js");
    check("render.allow does not widen decide()",
          !p.decide(req, auth).allowed());
}

/** MUTATION: place the renders loop BEFORE the excludes loop. Must go red. */
static void scopeExcludeStillBeatsRenderAllow() {
    Policy p = new Policy();
    BridgeClient.Authorisation auth = new BridgeClient.Authorisation(7, Map.of(
            "scope.include", List.of("https://app.test/*"),
            "scope.exclude", List.of("https://cdn.test/secret/*"),
            "render.allow", List.of("https://cdn.test/*")));
    HxRequest req = req("https://cdn.test/secret/k.js", "cdn.test", "/secret/k.js");
    check("scope.exclude outranks render.allow",
          !p.decideCrawl(req, auth).allowed());
}

/** STRUCTURAL, not behavioural: the proxy package has no identity code, so a
 *  render concession cannot attach a credential. MUTATION: add an
 *  IdentityRegistry field to any class in hx.proxy. Must go red. */
static void theProxyPackageAttachesNoIdentity() throws Exception {
    String pkg = Files.walk(Path.of("src/hx/proxy"))
            .filter(f -> f.toString().endsWith(".java"))
            .map(PolicyTest::readStrippingComments)
            .collect(Collectors.joining("\n"));
    check("no IdentityRegistry anywhere in hx.proxy",
          !pkg.contains("IdentityRegistry"));
}
```

`req(...)` and `readStrippingComments(...)` are small helpers: the first builds an `HxRequest` the way the existing `PolicyTest` cases do — copy that construction rather than inventing one — and the second reads a file and removes `//` and `/* */` runs so a comment mentioning the word cannot fail the structural check.

- [ ] **Step 2: Run the Java suite to verify the new tests fail**

```bash
MONTOYA_JAR=$(pwd)/../burp-lab/probe/lib/montoya-api.jar ./extension/test.sh 2>&1 | tail -25
```

Expected: compile error `cannot find symbol: method decideCrawl`. That is the correct first failure.

- [ ] **Step 3: Thread the flag through `checkScope`**

In `Policy.java`, change the private signature and the two existing callers. `checkScope` currently ends (around line 540) with the excludes loop, the includes loop, and a fallthrough denial. Insert the render branch **between the includes loop and the fallthrough**, so `scope.exclude` still runs first and `scope.include` still wins outright.

```java
// Policy.java -- the render.allow branch, a fragment and not the file
        for (Rule r : excludes)
            if (r.denies(t, pathReadings))
                return Decision.deny("scope_denied",
                        req.url() + " matches scope.exclude " + r.source());

        for (Rule r : includes)
            if (r.allows(t, pathReadings)) return Decision.allow();

        // AFTER the includes and AFTER the excludes, and both positions are
        // the point. render.allow is a concession to RENDERING, not a second
        // scope: an excluded destination stays excluded, and an included one
        // never needed it. It is consulted only when the crawler asked --
        // decide() passes false -- because a page needing a CDN to render is
        // not an argument for letting a CHECK send a probe there.
        if (renderAllow) {
            for (String pattern : scope.getOrDefault("render.allow", List.of())) {
                Rule r;
                try {
                    r = Rule.forInclude(pattern);
                } catch (IllegalArgumentException e) {
                    return Decision.deny("scope_denied",
                            "unusable render.allow pattern: " + e.getMessage());
                }
                if (r.allows(t, pathReadings)) return Decision.allow();
            }
        }

        return Decision.deny("scope_denied", req.url() + " matches no scope.include pattern");
```

- [ ] **Step 4: Add the public sibling and its private companion**

`decideBeforeGate` keeps its signature and delegates. Add `decideCrawl` beside `decide`.

```java
// Policy.java -- the new public surface, a fragment and not the file
    /**
     * The CRAWLER's question: everything decide() asks, plus render.allow.
     *
     * A sibling rather than a flag on decide(), for the reason
     * decideScopeOnly is a sibling: the caller identity is the whole
     * difference, and a boolean at 30 call sites is a boolean somebody passes
     * true from the send path. ChokepointTest counts issuing call sites; this
     * adds one, and it is ProxyGate's CRAWLER branch.
     */
    public Decision decideCrawl(HxRequest req, BridgeClient.Authorisation auth) {
        Decision before = beforeGate(req, auth, true);
        if (!before.allowed()) return before;
        return checkGate(req);
    }
```

`decideBeforeGate(req, auth)` becomes `return beforeGate(req, auth, false);` and the existing body moves into `private Decision beforeGate(HxRequest req, BridgeClient.Authorisation auth, boolean renderAllow)`, which passes `renderAllow` to `checkScope`. `decideScopeOnly` passes `false` — the operator is not rendering under our policy and never asked for the concession.

- [ ] **Step 5: Point ProxyGate's CRAWLER branch at it**

```java
// ProxyGate.java -- the CRAWLER branch, a fragment and not the file
        if (source == Source.CRAWLER) {
            // The agent's rules, in S4's pinned order, Gate included -- plus
            // render.allow, which exists so that dropping a third-party
            // bundle does not silently stop the page under test from booting.
            Decision d = policy.decideCrawl(req, auth);
            return d.allowed() ? Verdict.pass() : Verdict.deny(d);
        }
```

- [ ] **Step 6: Run the Java suite to verify it passes**

```bash
MONTOYA_JAR=$(pwd)/../burp-lab/probe/lib/montoya-api.jar ./extension/test.sh 2>&1 | tail -25
```

Expected: every suite `ALL PASS`, zero `FAIL` lines. Confirm with `./extension/test.sh 2>&1 | grep -c FAIL` returning `0`.

- [ ] **Step 7: Run each named mutation and confirm it goes red**

Apply one at a time, on an otherwise clean tree, and revert between them.

| Mutation | Test that must go red |
|---|---|
| delete the `renderAllow` loop from `checkScope` | `renderAllowLetsASubresourceThroughForTheCrawler` |
| make `decideBeforeGate` pass `true` | `renderAllowDoesNotWidenTheSendPath` |
| move the render loop above the `excludes` loop | `scopeExcludeStillBeatsRenderAllow` |
| add an `IdentityRegistry` field to `hx.proxy.ProxyGate` | `theProxyPackageAttachesNoIdentity` |

A mutation that leaves the suite green means the test is one of the catalogued unfailable shapes. Fix the test, not the tally.

- [ ] **Step 8: Commit**

```bash
git add extension/src/hx/policy/Policy.java extension/src/hx/proxy/ProxyGate.java \
        extension/test/hx/policy/PolicyTest.java
git commit -m "feat(policy): render.allow enforces, for the crawler only

Declared in config.py:347, shipped over the bridge, accepted in
ConfigBody.KEYS, and read by nothing. An operator setting it got silence.
Harmless while nothing rendered a page; not harmless once a browser
does, so it lands before the browser exists.

Consulted after scope.exclude and after scope.include, and only when the
caller is the crawler: a page needing a CDN to render is not an argument
for letting a check send a probe there."
```

---

## Task 2: CDP over pipes

**Files:**
- Create: `src/hx/crawl/__init__.py`
- Create: `src/hx/crawl/cdp.py`
- Test: `tests/test_crawl_cdp.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces, and later tasks depend on these exact names:
  - `class CdpError(Exception)` — base
  - `class CdpTimeout(CdpError)`
  - `class CdpClosed(CdpError)` — the child died or closed its pipe
  - `class Connection` with:
    - `Connection(read_fd: int, write_fd: int)`
    - `.call(method: str, params: dict | None = None, *, session_id: str | None = None, timeout: float = 30.0) -> dict` — returns the `result` object; raises `CdpError` on a protocol `error`
    - `.drain(timeout: float) -> list[dict]` — returns every event received within `timeout`, each a raw `{"method": ..., "params": ...}` dict
    - `.events` — a `list[dict]` of events received but not yet drained
    - `.close() -> None`

### What this is and is not

A transport. It frames messages, correlates replies to requests by `id`, buffers events, and enforces timeouts. It knows nothing about pages, navigation, or crawling — those are Tasks 4 and 5. **It opens no socket**, and that is the reason it exists in this shape: CDP's usual carrier is a WebSocket on `--remote-debugging-port`, which would put a network client in `src/hx`, and `pyproject.toml` already objects to exactly that about `httpx2`.

The wire format, verified 2026-09-02 against Chromium 150.0.7871.186: **UTF-8 JSON objects separated by a single `\0` byte**, ours written to the child's fd 3, the child's written to fd 4.

- [ ] **Step 1: Write the failing test**

`tests/test_crawl_cdp.py`. The double is a real child process speaking the protocol over real pipes — not a mock — because the framing and the fd handling are the things most likely to be wrong, and a mock would test neither.

```python
# tests/test_crawl_cdp.py -- the fake peer and the first cases
"""`hx.crawl.cdp`, driven by a real child process over real pipes.

NO BROWSER. The peer is a few lines of Python speaking CDP framing, which
is the whole point: the framing, the id correlation and the fd inheritance
are what break, and a `unittest.mock` double would exercise none of them.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from hx.crawl import cdp

PEER = r'''
import json, os, sys
buf = b""
while True:
    chunk = os.read(3, 65536)
    if not chunk:
        break
    buf += chunk
    while b"\0" in buf:
        raw, buf = buf.split(b"\0", 1)
        msg = json.loads(raw)
        if msg["method"] == "Peer.emitEvent":
            os.write(4, json.dumps(
                {"method": "Peer.happened", "params": {"n": 1}}).encode() + b"\0")
        if msg["method"] == "Peer.fail":
            os.write(4, json.dumps(
                {"id": msg["id"], "error": {"code": -32000,
                                            "message": "peer refused"}}).encode() + b"\0")
            continue
        if msg["method"] == "Peer.silent":
            continue
        os.write(4, json.dumps(
            {"id": msg["id"], "result": {"echo": msg.get("params", {})}}).encode() + b"\0")
'''


def _peer() -> tuple[cdp.Connection, subprocess.Popen]:
    """A child speaking CDP on fds 3 and 4, wired exactly as Chromium is."""
    to_child_r, to_child_w = os.pipe()
    from_child_r, from_child_w = os.pipe()

    def fixup():
        os.dup2(to_child_r, 3)
        os.dup2(from_child_w, 4)

    proc = subprocess.Popen([sys.executable, "-c", PEER],
                            preexec_fn=fixup, pass_fds=(3, 4), close_fds=True)
    os.close(to_child_r)
    os.close(from_child_w)
    return cdp.Connection(read_fd=from_child_r, write_fd=to_child_w), proc


def test_a_call_gets_its_own_reply():
    conn, proc = _peer()
    try:
        assert conn.call("Peer.echo", {"x": 7}) == {"echo": {"x": 7}}
    finally:
        conn.close()
        proc.kill()


def test_replies_are_matched_by_id_not_by_arrival_order():
    """THE CORRELATION TEST. Two calls in flight; the transport must return
    each caller its own reply.

    MUTATION: make `call` return the first message carrying any `id`.
    This test must go red.
    """
    conn, proc = _peer()
    try:
        conn.call("Peer.silent", {"a": 1}, timeout=0.2)
    except cdp.CdpTimeout:
        pass
    try:
        assert conn.call("Peer.echo", {"b": 2}) == {"echo": {"b": 2}}
    finally:
        conn.close()
        proc.kill()


def test_a_protocol_error_is_raised_and_not_returned_as_a_result():
    """MUTATION: return `msg` instead of raising when it carries `error`.
    Must go red -- a caller would read a CDP failure as a successful result.
    """
    conn, proc = _peer()
    try:
        with pytest.raises(cdp.CdpError, match="peer refused"):
            conn.call("Peer.fail")
    finally:
        conn.close()
        proc.kill()


def test_a_silent_peer_times_out_rather_than_blocking_forever():
    """MUTATION: drop the deadline from the read loop. Must hang, then red.

    The timeout is what stops one wedged navigation consuming the whole
    crawl budget -- spec S5's per-page cap depends on this raising.
    """
    conn, proc = _peer()
    try:
        with pytest.raises(cdp.CdpTimeout):
            conn.call("Peer.silent", timeout=0.3)
    finally:
        conn.close()
        proc.kill()


def test_events_arriving_during_a_call_are_buffered_not_discarded():
    """Events and replies share one pipe. An event that arrives while a call
    is outstanding must survive to be drained.

    MUTATION: in the read loop, `continue` past any message with no `id`
    instead of appending it to `self.events`. Must go red -- and the crawl
    would silently lose every Network event, reporting pages that requested
    nothing.
    """
    conn, proc = _peer()
    try:
        conn.call("Peer.emitEvent")
        events = conn.drain(timeout=1.0)
        assert any(e["method"] == "Peer.happened" for e in events)
    finally:
        conn.close()
        proc.kill()


def test_a_dead_peer_raises_closed_rather_than_hanging():
    """MUTATION: treat a zero-length read as 'nothing yet' and loop. Must go
    red by hanging -- a crashed browser would stall the crawl to its budget
    instead of failing the page.
    """
    conn, proc = _peer()
    proc.kill()
    proc.wait()
    with pytest.raises((cdp.CdpClosed, cdp.CdpTimeout)):
        conn.call("Peer.echo", timeout=2.0)
    conn.close()
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_crawl_cdp.py -q
```

Expected: `ModuleNotFoundError: No module named 'hx.crawl'`.

- [ ] **Step 3: Write the transport**

`src/hx/crawl/__init__.py` is empty apart from a docstring naming the spec. Then:

```python
# src/hx/crawl/cdp.py -- the transport, in full
"""Chrome DevTools Protocol over two file descriptors.

NOT OVER A WEBSOCKET, and the reason is `pyproject.toml`'s own note about
`httpx2`: an HTTP client in the runtime closure "is the kind of thing that
quietly stops being true" about S4's invariant that every byte leaving this
machine crosses the JVM. A WebSocket client aimed at loopback today is a
WebSocket client. Over pipes there is no port, no client and no address to
repoint -- the transport is two descriptors on a child process.

WIRE FORMAT, measured 2026-09-02 against Chromium 150.0.7871.186: UTF-8
JSON objects separated by one NUL byte. We write to the child's fd 3 and
read what it writes to fd 4.
"""
from __future__ import annotations

import json
import os
import selectors
import time


class CdpError(Exception):
    """The peer answered, and the answer was a protocol error."""


class CdpTimeout(CdpError):
    """The peer did not answer inside the deadline."""


class CdpClosed(CdpError):
    """The peer closed its pipe or died."""


class Connection:
    """One CDP session over a pair of descriptors.

    NOT THREAD-SAFE and deliberately synchronous. A crawl visits one page at
    a time under a budget; concurrency here would buy nothing and would make
    the id correlation below a lock instead of a dict.
    """

    def __init__(self, read_fd: int, write_fd: int) -> None:
        self._read_fd = read_fd
        self._write_fd = write_fd
        self._next_id = 0
        self._buf = b""
        self._replies: dict[int, dict] = {}
        self.events: list[dict] = []
        self._sel = selectors.DefaultSelector()
        self._sel.register(read_fd, selectors.EVENT_READ)
        self._closed = False

    def call(self, method: str, params: dict | None = None, *,
             session_id: str | None = None, timeout: float = 30.0) -> dict:
        """Send one command and return its `result`."""
        self._next_id += 1
        msg_id = self._next_id
        msg: dict = {"id": msg_id, "method": method, "params": params or {}}
        if session_id is not None:
            msg["sessionId"] = session_id
        self._write(msg)

        deadline = time.monotonic() + timeout
        while True:
            if msg_id in self._replies:
                reply = self._replies.pop(msg_id)
                if "error" in reply:
                    err = reply["error"]
                    raise CdpError(
                        f"{method}: {err.get('message', err)}")
                return reply.get("result", {})
            self._pump(deadline)

    def drain(self, timeout: float) -> list[dict]:
        """Every event received up to now, plus any arriving within `timeout`.

        Returns and CLEARS. A caller reading events twice would count one
        request twice, and the page classifier of `page.py` counts requests.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._pump(deadline)
            except (CdpTimeout, CdpClosed):
                break
        out, self.events = self.events, []
        return out

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._sel.close()
        for fd in (self._read_fd, self._write_fd):
            try:
                os.close(fd)
            except OSError:
                pass

    # --- internals ---------------------------------------------------------

    def _write(self, msg: dict) -> None:
        raw = json.dumps(msg).encode("utf-8") + b"\0"
        try:
            while raw:
                raw = raw[os.write(self._write_fd, raw):]
        except OSError as e:
            raise CdpClosed(f"write failed: {e}") from e

    def _pump(self, deadline: float) -> None:
        """Read once, decode whatever completed, and file it.

        A message with an `id` is somebody's reply and goes to `_replies`; a
        message without one is an event and goes to `self.events`. DISCARDING
        the second kind is the mutation `test_events_arriving_during_a_call_
        are_buffered_not_discarded` exists to catch: events and replies share
        one pipe, so an event that lands while a call is outstanding is read
        by that call's loop and by nothing else.
        """
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CdpTimeout("no reply before the deadline")
        if not self._sel.select(timeout=remaining):
            raise CdpTimeout("no reply before the deadline")
        try:
            chunk = os.read(self._read_fd, 1 << 16)
        except OSError as e:
            raise CdpClosed(f"read failed: {e}") from e
        if not chunk:
            raise CdpClosed("the peer closed its pipe")
        self._buf += chunk
        while b"\0" in self._buf:
            raw, self._buf = self._buf.split(b"\0", 1)
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                # A frame we cannot parse is not a frame we may guess at.
                # Dropping it loses one message; treating it as a reply would
                # answer a caller with garbage.
                continue
            if "id" in msg:
                self._replies[msg["id"]] = msg
            else:
                self.events.append(msg)
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
.venv/bin/pytest tests/test_crawl_cdp.py -q
```

Expected: 6 passed.

- [ ] **Step 5: Run each named mutation**

Apply one at a time on a clean tree; each must turn its named test red.

| Mutation in `cdp.py` | Test |
|---|---|
| in `_pump`, `continue` past messages with no `id` | `test_events_arriving_during_a_call_are_buffered_not_discarded` |
| in `call`, return `reply` even when it has `error` | `test_a_protocol_error_is_raised_and_not_returned_as_a_result` |
| in `_pump`, `select(timeout=None)` | `test_a_silent_peer_times_out_rather_than_blocking_forever` |
| in `_pump`, `if not chunk: return` | `test_a_dead_peer_raises_closed_rather_than_hanging` |

- [ ] **Step 6: Lint and commit**

```bash
.venv/bin/ruff check src/hx/crawl tests/test_crawl_cdp.py
awk 'length > 88 {print FILENAME":"FNR": "length}' src/hx/crawl/*.py tests/test_crawl_cdp.py
git add src/hx/crawl/__init__.py src/hx/crawl/cdp.py tests/test_crawl_cdp.py
git commit -m "feat(crawl): CDP over file descriptors, not a socket

The transport the rest of the crawler stands on. Framing, id correlation,
event buffering and timeouts over --remote-debugging-pipe's fds 3 and 4.

Over pipes rather than a WebSocket because a WebSocket client in src/hx is
a network client in the runtime closure, which is what pyproject's httpx2
note objects to. There is no port here and no address to repoint.

Tested against a real child process speaking the framing over real pipes.
A mock would exercise neither the framing nor the fd handling, which are
the two things that break."
```

---

## Task 3: Launching Chromium

**Files:**
- Create: `src/hx/crawl/browser.py`
- Test: `tests/test_crawl_browser.py`

**Interfaces:**
- Consumes: `hx.crawl.cdp.Connection`.
- Produces:
  - `class BrowserUnavailable(Exception)` — no Chromium, or it will not start sandboxed
  - `def find_chromium(burp_home: Path | None = None) -> Path` — newest `burpbrowser/<version>/chrome`
  - `def launch_argv(chrome: Path, *, proxy_port: int, user_data_dir: Path) -> list[str]`
  - `class Browser` — context manager with `.conn: cdp.Connection`, `.close()`

### The flag this task exists to get right

```
--proxy-bypass-list=<-loopback>
```

**Measured 2026-09-02.** Chromium with `--proxy-server=127.0.0.1:<port>`, asked for `http://127.0.0.1:18080/probe`:

| launch | connections the proxy received |
|---|---|
| without `--proxy-bypass-list` | **0** |
| with `--proxy-bypass-list=<-loopback>` | 1 — `GET http://127.0.0.1:18080/probe HTTP/1.1` |

Chrome bypasses configured proxies for loopback by default. Without the flag the crawler reaches a loopback target **directly** — around the crawler listener, around `ProxyGate`, around every §4 enforcement point — recording nothing and being refused nothing. Every target in this repo is loopback by mandate, so a crawler missing this flag looks perfect in every test we are permitted to write. Task 9 owns the integration test that can actually see it; this task owns the unit test that pins the argv.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crawl_browser.py -- argv and discovery, no browser launched
"""`hx.crawl.browser`: what we ask Chromium for, and where we find it.

MOSTLY WITHOUT LAUNCHING ONE. The argv is a list of strings and the
discovery is a directory walk; both are testable as data, and testing them
as data is what makes the flags reviewable. The one test that starts a real
Chromium lives in the integration suite (Task 9).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from hx.crawl import browser


def _fake_burp_home(tmp_path: Path, *versions: str) -> Path:
    for v in versions:
        d = tmp_path / "burpbrowser" / v
        d.mkdir(parents=True)
        (d / "chrome").write_text("#!/bin/true\n")
        (d / "chrome").chmod(0o755)
    return tmp_path


def test_the_proxy_bypass_flag_is_present():
    """THE LOAD-BEARING FLAG. Measured 2026-09-02: without it Chrome sent
    ZERO connections to the proxy for a loopback target and went direct,
    around ProxyGate and every S4 enforcement point.

    MUTATION: delete `--proxy-bypass-list=<-loopback>` from `launch_argv`.
    This test must go red. Task 9's integration test must ALSO go red -- a
    unit test on argv proves we ask for it, not that it works.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=8080,
                               user_data_dir=Path("/tmp/p"))
    assert "--proxy-bypass-list=<-loopback>" in argv


def test_the_proxy_is_the_only_route_out():
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=9999,
                               user_data_dir=Path("/tmp/p"))
    assert "--proxy-server=127.0.0.1:9999" in argv


def test_the_sandbox_is_never_disabled():
    """MUTATION: add `--no-sandbox` to `launch_argv`. Must go red.

    A security tool renders hostile pages. Verified 2026-09-02 that
    Chromium starts sandboxed on this platform via unprivileged user
    namespaces, so there is nothing to trade away.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=1,
                               user_data_dir=Path("/tmp/p"))
    assert "--no-sandbox" not in argv
    assert not any("disable-setuid-sandbox" in a for a in argv)


def test_the_profile_is_private_to_the_run():
    """A crawl never touches a real browser profile -- the rule the private
    Burp home already follows.

    MUTATION: drop `--user-data-dir` from the argv. Must go red.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=1,
                               user_data_dir=Path("/tmp/private-profile"))
    assert "--user-data-dir=/tmp/private-profile" in argv


def test_remote_debugging_is_a_pipe_and_never_a_port():
    """MUTATION: replace with `--remote-debugging-port=0`. Must go red.

    A port is a socket, a socket needs a client in `src/hx`, and that is the
    thing `pyproject.toml`'s httpx2 note objects to.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=1,
                               user_data_dir=Path("/tmp/p"))
    assert "--remote-debugging-pipe" in argv
    assert not any(a.startswith("--remote-debugging-port") for a in argv)


def test_the_newest_bundled_chromium_wins(tmp_path):
    home = _fake_burp_home(tmp_path, "9.0.1.2", "150.0.7871.186", "31.0.0.0")
    assert browser.find_chromium(home).parent.name == "150.0.7871.186"


def test_versions_are_compared_numerically_and_not_as_strings(tmp_path):
    """`"9" > "150"` lexicographically. MUTATION: sort with `sorted(dirs)`.
    Must go red -- and the crawler would silently drive an ancient browser.
    """
    home = _fake_burp_home(tmp_path, "9.0.0.0", "150.0.7871.186")
    assert browser.find_chromium(home).parent.name == "150.0.7871.186"


def test_a_missing_browser_is_a_named_refusal_not_a_crash(tmp_path):
    """Burp downloads its browser on first use, so 'not there yet' is an
    ordinary state an operator must be told how to fix."""
    with pytest.raises(browser.BrowserUnavailable, match="burpbrowser"):
        browser.find_chromium(tmp_path)
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_crawl_browser.py -q
```

Expected: `ModuleNotFoundError: No module named 'hx.crawl.browser'`.

- [ ] **Step 3: Write the module**

```python
# src/hx/crawl/browser.py -- locating and launching Chromium, in full
"""Burp's own bundled Chromium, launched sandboxed through our own proxy.

hx NEVER BUNDLES BURP and does not bundle a browser either. Chromium is
located inside the operator's own Burp installation, where Burp downloads
it on first use of the Proxy tab's browser. If it is not there, that is an
ordinary state with an ordinary fix, and this module says so rather than
raising a FileNotFoundError from somewhere in the middle of a crawl.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from hx.crawl import cdp

#: Where Burp puts the browser it downloads.
BURP_HOME = Path.home() / ".BurpSuite"


class BrowserUnavailable(Exception):
    """No usable Chromium, or one that will not start under a sandbox."""


def _version_key(name: str) -> tuple[int, ...]:
    """`150.0.7871.186` -> (150, 0, 7871, 186).

    Numeric, because lexicographic ordering puts "9.0.0.0" after
    "150.0.7871.186" and would silently pick a browser years out of date.
    """
    parts = []
    for piece in name.split("."):
        parts.append(int(piece) if piece.isdigit() else -1)
    return tuple(parts)


def find_chromium(burp_home: Path | None = None) -> Path:
    """The newest `burpbrowser/<version>/chrome` under `burp_home`."""
    home = Path(burp_home) if burp_home is not None else BURP_HOME
    root = home / "burpbrowser"
    candidates = []
    if root.is_dir():
        for child in root.iterdir():
            exe = child / "chrome"
            if child.is_dir() and exe.is_file() and os.access(exe, os.X_OK):
                candidates.append(child)
    if not candidates:
        raise BrowserUnavailable(
            f"no bundled Chromium under {root}. Burp downloads it the first "
            "time you open its own browser (Proxy -> Intercept -> Open "
            "browser); do that once and re-run. hx does not ship a browser.")
    newest = max(candidates, key=lambda d: _version_key(d.name))
    return newest / "chrome"


def launch_argv(chrome: Path, *, proxy_port: int,
                user_data_dir: Path) -> list[str]:
    """Exactly what we ask Chromium for, as data so it can be reviewed.

    THE SECOND FLAG IS THE ONE THAT MATTERS. Measured 2026-09-02: with
    `--proxy-server` alone and a loopback target, Chromium sent ZERO
    connections to the proxy and connected directly -- around the crawler
    listener, around ProxyGate, around every S4 enforcement point. Chrome
    bypasses proxies for loopback by default. Every target in this repo is
    loopback by mandate, so a crawler missing this flag passes every test we
    are allowed to write.

    NO `--no-sandbox`. Verified the same day that Chromium starts sandboxed
    here through unprivileged user namespaces, so there is nothing to trade.

    `--ignore-certificate-errors` is deliberate and its cost is written down
    in the spec: every certificate this browser can see is one Burp minted,
    because the two flags above leave it no other route. The crawler
    therefore cannot observe TLS problems on the target -- Burp still can,
    and does. Pinning to Burp's CA SPKI is the better version and is
    deferred, because hx does not parse certificates.
    """
    return [
        str(chrome),
        "--headless",
        f"--proxy-server=127.0.0.1:{proxy_port}",
        "--proxy-bypass-list=<-loopback>",
        "--ignore-certificate-errors",
        "--remote-debugging-pipe",
        f"--user-data-dir={user_data_dir}",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-client-side-phishing-detection",
        "--disable-sync",
        "--metrics-recording-only",
        "about:blank",
    ]


class Browser:
    """A launched Chromium and its CDP connection.

    A context manager, because a leaked Chromium survives the crawl, holds a
    private profile directory open, and keeps a proxy connection the
    extension is accounting for.
    """

    def __init__(self, *, proxy_port: int, burp_home: Path | None = None,
                 chrome: Path | None = None) -> None:
        self._chrome = Path(chrome) if chrome else find_chromium(burp_home)
        self._proxy_port = proxy_port
        self._tmp = tempfile.TemporaryDirectory(prefix="hx-crawl-profile-")
        self.proc: subprocess.Popen | None = None
        self.conn: cdp.Connection | None = None

    def __enter__(self) -> "Browser":
        to_child_r, to_child_w = os.pipe()
        from_child_r, from_child_w = os.pipe()

        def fixup() -> None:
            # dup2 ONTO 3 and 4, and `pass_fds=(3, 4)` below is not optional.
            # subprocess closes descriptors outside pass_fds AFTER preexec_fn
            # runs, so without it these are closed before exec and Chromium
            # answers "Remote debugging pipe file descriptors are not open."
            # Measured 2026-09-02, on the first attempt at this.
            os.dup2(to_child_r, 3)
            os.dup2(from_child_w, 4)

        argv = launch_argv(self._chrome, proxy_port=self._proxy_port,
                           user_data_dir=Path(self._tmp.name))
        self.proc = subprocess.Popen(
            argv, preexec_fn=fixup, pass_fds=(3, 4), close_fds=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        os.close(to_child_r)
        os.close(from_child_w)
        self.conn = cdp.Connection(read_fd=from_child_r, write_fd=to_child_w)
        try:
            self.conn.call("Browser.getVersion", timeout=20.0)
        except cdp.CdpError as e:
            stderr = b""
            if self.proc.stderr is not None:
                stderr = self.proc.stderr.read() or b""
            self.close()
            raise BrowserUnavailable(
                "Chromium started but did not answer CDP. If the message "
                "below mentions the sandbox, hx will not disable it: "
                f"{stderr.decode('utf-8', 'replace')[:400]}") from e
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        if self.proc is not None:
            self.proc.kill()
            self.proc.wait(timeout=10)
            self.proc = None
        self._tmp.cleanup()
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
.venv/bin/pytest tests/test_crawl_browser.py -q
```

Expected: 8 passed.

- [ ] **Step 5: Run each named mutation**

| Mutation in `browser.py` | Test |
|---|---|
| delete `--proxy-bypass-list=<-loopback>` | `test_the_proxy_bypass_flag_is_present` |
| add `--no-sandbox` | `test_the_sandbox_is_never_disabled` |
| `--remote-debugging-port=0` instead of the pipe | `test_remote_debugging_is_a_pipe_and_never_a_port` |
| `max(candidates, key=lambda d: d.name)` | `test_versions_are_compared_numerically_and_not_as_strings` |

- [ ] **Step 6: Lint and commit**

```bash
.venv/bin/ruff check src/hx/crawl tests/test_crawl_browser.py
awk 'length > 88 {print FILENAME":"FNR": "length}' src/hx/crawl/browser.py tests/test_crawl_browser.py
git add src/hx/crawl/browser.py tests/test_crawl_browser.py
git commit -m "feat(crawl): launch Burp's Chromium sandboxed through our proxy

--proxy-bypass-list=<-loopback> is the flag this commit is about. Measured
2026-09-02: without it Chromium sent ZERO connections to the proxy for a
loopback target and reached it directly, around ProxyGate and every S4
enforcement point. Every target in this repo is loopback by mandate, so
the flaw is invisible in exactly the environment we may test in.

No --no-sandbox: verified Chromium starts sandboxed here via unprivileged
user namespaces, so there is nothing to trade away.

The pass_fds=(3,4) beside preexec_fn is also not optional -- subprocess
closes descriptors outside pass_fds after preexec_fn runs."
```

---

## Task 4: The frontier

**Files:**
- Create: `src/hx/crawl/frontier.py`
- Test: `tests/test_crawl_frontier.py`

**Interfaces:**
- Consumes: nothing from earlier tasks. Pure functions and one class; no I/O.
- Produces:
  - `def normalise(url: str) -> str | None` — strip fragment, keep query, lowercase host; `None` for a scheme that is not http/https
  - `def origin_of(url: str) -> str | None` — `"https://host:port"`, port normalised away when default
  - `class Budget(NamedTuple)` — `max_pages: int`, `max_seconds: float`, `max_requests: int`
  - `class Frontier` with `.__init__(seeds: Iterable[str], budget: Budget, clock=time.monotonic)`, `.next() -> str | None`, `.offer(urls: Iterable[str]) -> int` (returns how many were newly enqueued), `.note_requests(n: int) -> None`, `.exhausted: str | None`, `.visited: int`

### The two decisions worth the reviewer's attention

**Dedupe is by URL, not by path template.** The normaliser used elsewhere in hx maps `/user/1` and `/user/2` onto one template, which is right for coverage attribution and wrong here: the second may reach code the first did not. Frontier growth is bounded by the budgets, not by collapsing distinct addresses.

**This is an origin allowlist and must not be called a scope check.** There is no Python scope matcher in this repo; scope lives in `Policy.Rule` behind percent-decoding to a fixed point, userinfo rejection, path-length bounds and reading sets. A second matcher is a second answer, and the one that drifts is the one nobody enforces with. The frontier answers the narrower question — *is this page worth visiting* — and the JVM answers the only question that gates egress.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crawl_frontier.py -- the queue, as pure functions
"""`hx.crawl.frontier`. No browser, no network, no clock of its own.

The budget clock is injected so that `max_seconds` is testable without a
sleep -- the pattern `extension/test/hx/policy/TickClock.java` uses on the
Java side for the same reason.
"""
from __future__ import annotations

from hx.crawl import frontier


def _b(pages=100, seconds=100.0, requests=10_000):
    return frontier.Budget(max_pages=pages, max_seconds=seconds,
                           max_requests=requests)


def test_a_fragment_is_not_a_different_page():
    assert frontier.normalise("https://a.test/x#frag") == "https://a.test/x"


def test_a_query_string_is_a_different_page():
    """The query is exactly what a scan later probes, so collapsing it would
    discard the surfaces this crawler exists to find.

    MUTATION: strip the query in `normalise`. This test must go red.
    """
    a = frontier.normalise("https://a.test/x?id=1")
    b = frontier.normalise("https://a.test/x?id=2")
    assert a != b


def test_two_ids_on_one_path_are_two_pages():
    """DEDUPE IS BY URL, NOT BY PATH TEMPLATE. hx's normaliser maps
    /user/1 and /user/2 to one template, which is right for coverage
    attribution and wrong here: the second may reach code the first did not.

    MUTATION: dedupe on a templated path. This test must go red.
    """
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["https://a.test/user/1", "https://a.test/user/2"]) == 2


def test_a_url_already_seen_is_not_enqueued_twice():
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["https://a.test/x"]) == 1
    assert f.offer(["https://a.test/x#other"]) == 0


def test_a_foreign_origin_is_not_enqueued():
    """The origin allowlist. NOT a scope check -- see the module docstring.

    MUTATION: drop the origin test from `offer`. This test must go red.
    """
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["https://cdn.test/app.js"]) == 0


def test_a_non_http_scheme_is_refused():
    """`javascript:`, `mailto:`, `data:` and `blob:` are not pages.

    MUTATION: accept any scheme in `normalise`. Must go red -- and the
    crawler would try to navigate to `javascript:alert(1)` harvested from a
    page under test.
    """
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["javascript:alert(1)", "mailto:x@a.test",
                    "data:text/html,x", "blob:https://a.test/z"]) == 0


def test_a_second_seed_origin_is_allowed():
    f = frontier.Frontier(["https://a.test/", "https://b.test/"], _b())
    assert f.offer(["https://b.test/x"]) == 1


def test_the_page_budget_stops_the_crawl_and_names_itself():
    """S12 one level up: a truncated crawl that presented as a complete one
    would be the same failure the report guards against.

    MUTATION: return None from `next()` without setting `exhausted`. Must go
    red -- the crawl would look complete.
    """
    f = frontier.Frontier(["https://a.test/1"], _b(pages=1))
    f.offer(["https://a.test/2"])
    assert f.next() is not None
    assert f.next() is None
    assert f.exhausted == "max_pages"


def test_the_request_budget_stops_the_crawl_and_names_itself():
    f = frontier.Frontier(["https://a.test/1"], _b(requests=10))
    f.offer(["https://a.test/2"])
    assert f.next() is not None
    f.note_requests(11)
    assert f.next() is None
    assert f.exhausted == "max_requests"


def test_the_time_budget_stops_the_crawl_and_names_itself():
    ticks = iter([0.0, 0.0, 99.0, 99.0])
    f = frontier.Frontier(["https://a.test/1"], _b(seconds=5.0),
                          clock=lambda: next(ticks))
    f.offer(["https://a.test/2"])
    assert f.next() is not None
    assert f.next() is None
    assert f.exhausted == "max_seconds"


def test_an_unexhausted_frontier_that_simply_ran_out_says_nothing():
    """THE SEPARATING CASE. A crawl that visited everything is COMPLETE, and
    must not report a budget as the reason it stopped.

    MUTATION: set `exhausted` whenever `next()` returns None. Must go red --
    every completed crawl would report itself truncated.
    """
    f = frontier.Frontier(["https://a.test/1"], _b())
    assert f.next() is not None
    assert f.next() is None
    assert f.exhausted is None
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_crawl_frontier.py -q
```

Expected: `ModuleNotFoundError: No module named 'hx.crawl.frontier'`.

- [ ] **Step 3: Write the module**

```python
# src/hx/crawl/frontier.py -- the queue, in full
"""What to visit next, and when to stop.

AN ORIGIN ALLOWLIST, NOT A SCOPE CHECK, and the distinction is the whole
design. There is no Python scope matcher in this repo: scope lives in
`Policy.Rule` behind percent-decoding to a fixed point, userinfo rejection,
path-length bounds and reading sets. A second matcher here would be a
second answer to the question that gates egress, and the one that drifts is
the one nobody is enforcing with.

So this file answers the narrower question -- IS THIS PAGE WORTH VISITING --
and the JVM answers the only one that matters for egress. A URL on a seed
origin but outside `scope.include` by path is enqueued, visited, dropped at
ProxyGate and recorded as a denial. That costs one refused request, and it
is the correct trade.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Callable, Iterable, NamedTuple
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


class Budget(NamedTuple):
    max_pages: int
    max_seconds: float
    max_requests: int


def normalise(url: str) -> str | None:
    """One canonical spelling of a page address, or None if it is not one.

    The fragment goes: `#a` and `#b` are one document and one request. The
    QUERY STAYS: it is exactly what a scan later probes, and collapsing it
    would discard the surfaces this crawler exists to find.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    if not parts.hostname:
        return None
    netloc = parts.hostname.lower()
    if parts.port and parts.port != _DEFAULT_PORTS[parts.scheme]:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/",
                       parts.query, ""))


def origin_of(url: str) -> str | None:
    """`scheme://host[:port]`, with a default port normalised away."""
    n = normalise(url)
    if n is None:
        return None
    parts = urlsplit(n)
    return f"{parts.scheme}://{parts.netloc}"


class Frontier:
    """The queue, the seen-set and the budgets."""

    def __init__(self, seeds: Iterable[str], budget: Budget,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._budget = budget
        self._clock = clock
        self._started = clock()
        self._queue: deque[str] = deque()
        self._seen: set[str] = set()
        self._origins: set[str] = set()
        self._requests = 0
        self.visited = 0
        self.exhausted: str | None = None

        for seed in seeds:
            origin = origin_of(seed)
            if origin is None:
                continue
            self._origins.add(origin)
        for seed in seeds:
            self._enqueue(seed)

    def offer(self, urls: Iterable[str]) -> int:
        """Enqueue every URL that is new and on a seed origin."""
        return sum(1 for url in urls if self._enqueue(url))

    def note_requests(self, n: int) -> None:
        self._requests += n

    def next(self) -> str | None:
        """The next page, or None -- and `exhausted` says which None it is.

        A budget sets `exhausted`; an empty queue does NOT. That difference
        is the whole of S12 applied one level up: a crawl that visited
        everything is COMPLETE, and must not report a budget as its reason
        for stopping.
        """
        if self.visited >= self._budget.max_pages:
            self.exhausted = "max_pages"
            return None
        if self._requests >= self._budget.max_requests:
            self.exhausted = "max_requests"
            return None
        if self._clock() - self._started >= self._budget.max_seconds:
            self.exhausted = "max_seconds"
            return None
        if not self._queue:
            return None
        self.visited += 1
        return self._queue.popleft()

    def _enqueue(self, url: str) -> bool:
        n = normalise(url)
        if n is None:
            return False
        if origin_of(n) not in self._origins:
            return False
        if n in self._seen:
            return False
        self._seen.add(n)
        self._queue.append(n)
        return True
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
.venv/bin/pytest tests/test_crawl_frontier.py -q
```

Expected: 11 passed.

- [ ] **Step 5: Run each named mutation**

| Mutation in `frontier.py` | Test |
|---|---|
| strip the query in `normalise` | `test_a_query_string_is_a_different_page` |
| drop the `origin_of(n) not in self._origins` guard | `test_a_foreign_origin_is_not_enqueued` |
| accept any scheme in `normalise` | `test_a_non_http_scheme_is_refused` |
| set `exhausted` whenever `next()` returns None | `test_an_unexhausted_frontier_that_simply_ran_out_says_nothing` |
| return None from a budget branch without setting `exhausted` | `test_the_page_budget_stops_the_crawl_and_names_itself` |

- [ ] **Step 6: Lint and commit**

```bash
.venv/bin/ruff check src/hx/crawl tests/test_crawl_frontier.py
awk 'length > 88 {print FILENAME":"FNR": "length}' src/hx/crawl/frontier.py tests/test_crawl_frontier.py
git add src/hx/crawl/frontier.py tests/test_crawl_frontier.py
git commit -m "feat(crawl): the frontier -- origin allowlist, URL dedupe, named budgets

Dedupe is by URL and not by path template: hx's normaliser maps /user/1
and /user/2 to one template, which is right for coverage attribution and
wrong here, because the second may reach code the first did not.

An origin allowlist, NOT a scope check. There is no Python scope matcher
in this repo and this does not become the first one -- scope lives in
Policy.Rule and a second matcher is a second answer.

A budget sets `exhausted`; an empty queue does not. A crawl that visited
everything is complete and must not report a budget as its reason."
```

---

## Task 5: One page — navigate, settle, harvest, classify

**Files:**
- Create: `src/hx/crawl/page.py`
- Test: `tests/test_crawl_page.py`

**Interfaces:**
- Consumes: `hx.crawl.cdp.Connection` (only its `.call` and `.drain`), `hx.crawl.frontier.origin_of`.
- Produces:
  - `def harvest(html: str, base_url: str) -> list[str]` — absolute URLs from `a[href]`, `area[href]`, `iframe[src]`, `form[action]`
  - `def classify(events: list[dict], *, page_origins: set[str], harvested: int) -> PageResult`
  - `class PageResult(NamedTuple)` — `state: str` (`"rendered" | "degraded" | "failed"`), `requests: int`, `dropped_hosts: tuple[str, ...]`, `in_scope_failures: tuple[str, ...]`, `capped: bool`
  - `def visit(conn, url: str, *, page_origins: set[str], settle: float = 2.0, cap: float = 20.0) -> tuple[PageResult, list[str]]`

### Why the classifier is a pure function over an event list

Because it encodes §12's judgement and §12's judgement is the thing most worth testing. The failure it prevents: the proxy drops an out-of-scope CDN bundle, the SPA never boots, the crawler visits the page, finds nothing, and records a **clean crawl of an application it never rendered**. Made pure, that judgement is exercised by a list of dicts and needs no browser at all.

**A deliberate imprecision, written down rather than discovered.** A genuinely empty page — a static confirmation screen with one dropped web font — is classified `degraded`. That is a false degradation and the rule errs that way on purpose: §12's asymmetry is that under-claiming coverage is survivable and over-claiming is not. Task 8's report copy therefore says *"may not have rendered"*, never *"did not render"*.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crawl_page.py -- harvesting and the S12 classifier
"""`hx.crawl.page`. No browser: the classifier is a pure function over a
list of CDP events, and the harvester is a pure function over HTML.

The events are the real shapes Chromium emits -- `Network.requestWillBeSent`
carries `request.url`, `Network.loadingFailed` carries `errorText`. They are
written out here rather than recorded from a live browser so that a reader
can see what each test is claiming.
"""
from __future__ import annotations

from hx.crawl import page

ORIGINS = {"https://app.test"}


def _sent(url: str) -> dict:
    return {"method": "Network.requestWillBeSent",
            "params": {"requestId": url, "request": {"url": url}}}


def _failed(url: str) -> dict:
    return {"method": "Network.loadingFailed",
            "params": {"requestId": url, "errorText": "net::ERR_EMPTY_RESPONSE"}}


def _ok(url: str) -> dict:
    return {"method": "Network.responseReceived",
            "params": {"requestId": url, "response": {"status": 200}}}


# --- harvesting ------------------------------------------------------------

def test_anchors_areas_iframes_and_form_actions_are_all_harvested():
    html = ('<a href="/a">x</a>'
            '<area href="/b">'
            '<iframe src="/c"></iframe>'
            '<form action="/d"></form>')
    out = page.harvest(html, "https://app.test/start")
    assert set(out) == {"https://app.test/a", "https://app.test/b",
                        "https://app.test/c", "https://app.test/d"}


def test_a_form_action_is_harvested_as_a_url_and_never_submitted():
    """S9's form policy is DEFERRED, and this pins the half that ships: the
    action is a page address we may GET, not a form we may POST.

    MUTATION: have `harvest` return a (url, method, fields) triple that a
    caller could submit. Must go red -- and the review that follows would be
    reviewing form submission, which this plan does not ship.
    """
    out = page.harvest('<form action="/pay" method="post">'
                       '<input name="amount"></form>', "https://app.test/")
    assert out == ["https://app.test/pay"]


def test_relative_urls_resolve_against_the_page_not_the_origin():
    out = page.harvest('<a href="b">x</a>', "https://app.test/deep/a")
    assert out == ["https://app.test/deep/b"]


def test_a_base_tag_is_honoured():
    out = page.harvest('<base href="https://app.test/api/">'
                       '<a href="v1">x</a>', "https://app.test/other")
    assert out == ["https://app.test/api/v1"]


def test_malformed_html_yields_what_it_can_rather_than_raising():
    """A page under test is attacker-influenced input. MUTATION: let the
    parser raise. Must go red -- one broken page would end the crawl.
    """
    assert page.harvest('<a href="/a">x<<<>>"', "https://app.test/") == \
        ["https://app.test/a"]


# --- classification: S12 applied to one page -------------------------------

def test_a_page_that_loaded_and_yielded_links_is_rendered():
    events = [_sent("https://app.test/"), _ok("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=3)
    assert r.state == "rendered"


def test_a_page_that_yielded_nothing_after_a_drop_is_degraded():
    """THE FAILURE THIS WHOLE FUNCTION EXISTS FOR. The proxy drops the CDN
    bundle, the SPA never boots, and a naive crawler records a clean crawl of
    an application it never rendered -- S12's exact failure.

    MUTATION: return "rendered" whenever the document itself loaded. This
    test must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://cdn.test/app.js"), _failed("https://cdn.test/app.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "degraded"
    assert r.dropped_hosts == ("cdn.test",)


def test_a_drop_that_did_not_matter_is_still_rendered():
    """THE SEPARATING CASE. A dropped font on a page that produced links did
    not stop anything, and calling it degraded would under-report coverage on
    every page with a third-party asset.

    MUTATION: return "degraded" whenever any drop occurred. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://fonts.test/f.woff2"),
              _failed("https://fonts.test/f.woff2")]
    r = page.classify(events, page_origins=ORIGINS, harvested=4)
    assert r.state == "rendered"


def test_an_in_scope_failure_is_the_target_failing_not_a_policy_drop():
    """Two different facts that must not be reported as one: hx dropped it,
    versus the target could not serve it.

    MUTATION: put every failure in `dropped_hosts`. Must go red -- and the
    operator would paste their own application's host into render_allow.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://app.test/broken.js"),
              _failed("https://app.test/broken.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=2)
    assert r.dropped_hosts == ()
    assert r.in_scope_failures == ("https://app.test/broken.js",)


def test_a_document_that_never_loaded_is_failed_not_degraded():
    events = [_sent("https://app.test/"), _failed("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "failed"


def test_a_page_with_xhr_but_no_links_still_counts_as_rendered():
    """The measured reason this crawler is worth building: S9's 65-requests
    result came from a page's own fetch calls, not from its links. A page
    that yielded only XHR has been reached.

    MUTATION: judge `rendered` on `harvested` alone. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://app.test/api/items?q=1"),
              _ok("https://app.test/api/items?q=1")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "rendered"
    assert r.requests == 2


def test_dropped_hosts_are_deduplicated_and_ordered():
    events = [_sent("https://app.test/"), _ok("https://app.test/")]
    for u in ("https://cdn.test/a.js", "https://cdn.test/b.js",
              "https://ads.test/t.gif"):
        events += [_sent(u), _failed(u)]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.dropped_hosts == ("ads.test", "cdn.test")
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_crawl_page.py -q
```

Expected: `ModuleNotFoundError: No module named 'hx.crawl.page'`.

- [ ] **Step 3: Write the module**

```python
# src/hx/crawl/page.py -- one page, in full
"""Navigate one page, wait for it to settle, harvest, and judge it.

THE JUDGEMENT IS THE POINT. S12: a report that cannot distinguish "tested,
clean" from "never reached" is worse than no report. Applied to a crawl, the
failure is precise -- the proxy drops an out-of-scope bundle, the SPA never
boots, and the crawler records a clean visit to an application it never
rendered. Only the browser can see this: the store knows a request was
denied, it does not know whose render the denial broke.

`classify` is therefore a pure function over CDP events, so the judgement
can be tested without a browser and read without running anything.
"""
from __future__ import annotations

import time
from html.parser import HTMLParser
from typing import NamedTuple
from urllib.parse import urljoin, urlsplit

from hx.crawl import cdp
from hx.crawl.frontier import normalise, origin_of

#: Attributes that carry a page address. `form action` is here because it is
#: an address we may GET; SUBMITTING a form is S9's deferred policy and this
#: build does not do it.
_LINK_ATTRS = {"a": "href", "area": "href", "iframe": "src", "form": "action"}


class PageResult(NamedTuple):
    state: str                       # rendered | degraded | failed
    requests: int
    dropped_hosts: tuple[str, ...]
    in_scope_failures: tuple[str, ...]
    capped: bool


class _Links(HTMLParser):
    """Tolerant by construction: a page under test is attacker-influenced
    input, and one malformed document must not end a crawl."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[str] = []
        self.base: str | None = None

    def handle_starttag(self, tag, attrs) -> None:
        d = dict(attrs)
        if tag == "base" and d.get("href"):
            self.base = d["href"]
            return
        attr = _LINK_ATTRS.get(tag)
        if attr and d.get(attr):
            self.found.append(d[attr])


def harvest(html: str, base_url: str) -> list[str]:
    """Absolute URLs a page points at, in document order, deduplicated.

    Read from the SETTLED DOM rather than the served HTML, which is the whole
    reason a browser is involved: verified 2026-09-02 that a JS-injected
    anchor appears in the rendered DOM and not in the source.
    """
    parser = _Links()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Whatever it parsed before giving up is still real. Raising here
        # would let one broken page end a crawl.
        pass
    base = urljoin(base_url, parser.base) if parser.base else base_url
    out: list[str] = []
    seen: set[str] = set()
    for raw in parser.found:
        absolute = urljoin(base, raw.strip())
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return out


def classify(events: list[dict], *, page_origins: set[str],
             harvested: int, capped: bool = False) -> PageResult:
    """What this page tells us, and what it does not.

    A failed subresource is classified by ORIGIN, and the two answers are
    different facts: an out-of-scope failure is one hx dropped, an in-scope
    failure is the target itself failing. Reporting them as one would send an
    operator to put their own application's host into `render_allow`.
    """
    urls: dict[str, str] = {}
    failed: set[str] = set()
    answered: set[str] = set()
    document: str | None = None

    for e in events:
        params = e.get("params", {})
        rid = params.get("requestId")
        if e.get("method") == "Network.requestWillBeSent":
            url = params.get("request", {}).get("url", "")
            urls[rid] = url
            if document is None:
                document = rid
        elif e.get("method") == "Network.loadingFailed":
            failed.add(rid)
        elif e.get("method") == "Network.responseReceived":
            answered.add(rid)

    dropped: set[str] = set()
    in_scope_failures: list[str] = []
    for rid in failed:
        url = urls.get(rid, "")
        if origin_of(url) in page_origins:
            in_scope_failures.append(url)
        else:
            host = urlsplit(url).hostname
            if host:
                dropped.add(host)

    if document is None or document in failed:
        state = "failed"
    else:
        # YIELD is links OR in-scope requests beyond the document itself.
        # The second half is not decoration: S9's measured 65-requests result
        # came from a page's own fetch calls, and a page that produced only
        # XHR has been reached.
        own = sum(1 for rid, url in urls.items()
                  if rid != document and origin_of(url) in page_origins)
        yielded = harvested > 0 or own > 0
        if yielded:
            state = "rendered"
        elif dropped:
            # DEGRADED, and deliberately imprecise. A genuinely empty page
            # with one dropped web font lands here and is a FALSE
            # degradation. The rule errs this way on purpose: S12's
            # asymmetry is that under-claiming coverage is survivable and
            # over-claiming is not. The report says "may not have rendered".
            state = "degraded"
        else:
            state = "rendered"

    return PageResult(state=state, requests=len(urls),
                      dropped_hosts=tuple(sorted(dropped)),
                      in_scope_failures=tuple(sorted(in_scope_failures)),
                      capped=capped)


def visit(conn: cdp.Connection, url: str, *, page_origins: set[str],
          settle: float = 2.0, cap: float = 20.0) -> tuple[PageResult, list[str]]:
    """Navigate, wait for quiet, harvest, judge.

    `cap` is what stops one long-polling endpoint, analytics beacon or open
    WebSocket consuming the whole crawl budget. A page that hits it is
    recorded as CAPPED, not as complete -- capped and complete are different
    claims and the summary keeps them apart.
    """
    conn.call("Network.enable")
    conn.call("Page.enable")
    conn.drain(timeout=0.0)

    events: list[dict] = []
    capped = False
    try:
        conn.call("Page.navigate", {"url": url}, timeout=cap)
    except cdp.CdpTimeout:
        capped = True

    deadline = time.monotonic() + cap
    quiet_since = None
    while time.monotonic() < deadline:
        batch = conn.drain(timeout=0.25)
        events.extend(batch)
        if batch:
            quiet_since = None
        else:
            quiet_since = quiet_since or time.monotonic()
            if time.monotonic() - quiet_since >= settle:
                break
    else:
        capped = True

    html = ""
    try:
        root = conn.call("DOM.getDocument", {"depth": -1}, timeout=cap)
        node_id = root.get("root", {}).get("nodeId")
        if node_id:
            html = conn.call("DOM.getOuterHTML", {"nodeId": node_id},
                             timeout=cap).get("outerHTML", "")
    except cdp.CdpError:
        # A document we cannot read is a page we harvested nothing from --
        # which `classify` will read as no yield, and that is honest.
        html = ""

    links = harvest(html, url) if html else []
    result = classify(events, page_origins=page_origins,
                      harvested=len(links), capped=capped)
    return result, [u for u in (normalise(x) for x in links) if u]
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
.venv/bin/pytest tests/test_crawl_page.py -q
```

Expected: 13 passed.

- [ ] **Step 5: Run each named mutation**

| Mutation in `page.py` | Test |
|---|---|
| return `"rendered"` whenever the document loaded | `test_a_page_that_yielded_nothing_after_a_drop_is_degraded` |
| return `"degraded"` whenever any drop occurred | `test_a_drop_that_did_not_matter_is_still_rendered` |
| put every failure into `dropped_hosts` | `test_an_in_scope_failure_is_the_target_failing_not_a_policy_drop` |
| compute `yielded` from `harvested` alone | `test_a_page_with_xhr_but_no_links_still_counts_as_rendered` |
| let `harvest` propagate the parser exception | `test_malformed_html_yields_what_it_can_rather_than_raising` |

- [ ] **Step 6: Lint and commit**

```bash
.venv/bin/ruff check src/hx/crawl tests/test_crawl_page.py
awk 'length > 88 {print FILENAME":"FNR": "length}' src/hx/crawl/page.py tests/test_crawl_page.py
git add src/hx/crawl/page.py tests/test_crawl_page.py
git commit -m "feat(crawl): one page -- settle, harvest, and the S12 judgement

classify() is a pure function over CDP events because the judgement it
encodes is the thing most worth testing: the proxy drops an out-of-scope
bundle, the SPA never boots, and a naive crawler records a clean visit to
an application it never rendered.

Only the browser can attribute this. The store knows a request was denied;
it does not know whose render the denial broke.

A dropped font on a page that produced links is still rendered -- the
separating case, without which every page carrying a third-party asset
would under-report. A genuinely empty page with a dropped font is called
degraded, which is a false degradation kept on purpose: under-claiming
coverage is survivable and over-claiming is not."
```

---

## Task 6: Orchestration and the summary

**Files:**
- Create: `src/hx/crawl/run.py`
- Test: `tests/test_crawl_run.py`

**Interfaces:**
- Consumes: `browser.Browser`, `frontier.Frontier`, `frontier.Budget`, `page.visit`, `page.PageResult`, `frontier.origin_of`.
- Produces:
  - `class CrawlSummary(NamedTuple)` — `pages: int`, `rendered: int`, `degraded: int`, `failed: int`, `capped: int`, `requests: int`, `dropped_hosts: tuple[str, ...]`, `truncated_by: str | None`
  - `def crawl(*, seeds, proxy_port, budget, burp_home=None, visit=page.visit, browser_factory=browser.Browser) -> CrawlSummary`

`visit` and `browser_factory` are parameters with defaults so the orchestration is testable without Chromium. That is not a testing convenience bolted on — it is the seam that lets the loop, the budget accounting and the summary arithmetic be exercised as pure logic.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crawl_run.py -- the loop and the summary, with a fake browser
"""`hx.crawl.run`. No Chromium: `crawl` takes its `visit` and its browser
factory as parameters, so the loop, the budget accounting and the summary
arithmetic are exercised as pure logic.
"""
from __future__ import annotations

from hx.crawl import frontier, page
from hx.crawl import run as crawl_run


class _FakeBrowser:
    def __init__(self, **kw) -> None:
        self.conn = object()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def close(self):
        self.closed = True


def _visitor(pages: dict[str, tuple[page.PageResult, list[str]]]):
    """A `visit` double: a map from URL to what that page yields."""
    default = (page.PageResult("rendered", 1, (), (), False), [])

    def visit(conn, url, *, page_origins, settle=2.0, cap=20.0):
        return pages.get(url, default)
    return visit


def _b(pages=100, seconds=100.0, requests=10_000):
    return frontier.Budget(max_pages=pages, max_seconds=seconds,
                           max_requests=requests)


def test_links_from_one_page_become_the_next_pages():
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 2, (), (), False),
                            ["https://a.test/x", "https://a.test/y"]),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert s.pages == 3


def test_the_summary_counts_each_state_separately():
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 1, (), (), False),
                            ["https://a.test/d", "https://a.test/f"]),
        "https://a.test/d": (page.PageResult("degraded", 1, ("cdn.test",), (),
                                             False), []),
        "https://a.test/f": (page.PageResult("failed", 1, (), (), False), []),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert (s.rendered, s.degraded, s.failed) == (1, 1, 1)


def test_dropped_hosts_are_unioned_across_pages_because_that_is_the_fix_list():
    """The summary's dropped-host list IS the list an operator pastes into
    `render_allow`. A per-page list would make them assemble it by hand.

    MUTATION: report only the last page's dropped hosts. Must go red.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 1, ("cdn.test",), (),
                                            False), ["https://a.test/b"]),
        "https://a.test/b": (page.PageResult("degraded", 1, ("ads.test",), (),
                                             False), []),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert s.dropped_hosts == ("ads.test", "cdn.test")


def test_a_truncated_crawl_names_the_budget_that_stopped_it():
    """MUTATION: leave `truncated_by` None. Must go red -- a truncated crawl
    would present as a complete one, which is S12 one level up.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 1, (), (), False),
                            ["https://a.test/x", "https://a.test/y"]),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1,
                        budget=_b(pages=2), visit=visit,
                        browser_factory=_FakeBrowser)
    assert s.truncated_by == "max_pages"


def test_a_complete_crawl_reports_no_truncation():
    """THE SEPARATING CASE, without which every crawl claims truncation."""
    visit = _visitor({})
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert s.truncated_by is None


def test_requests_are_charged_to_the_budget_as_pages_are_visited():
    """MUTATION: never call `note_requests`. Must go red -- `max_requests`
    would be unenforceable and a crawl could run away inside a page budget.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 40, (), (), False),
                            ["https://a.test/x", "https://a.test/y"]),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1,
                        budget=_b(requests=5), visit=visit,
                        browser_factory=_FakeBrowser)
    assert s.truncated_by == "max_requests"


def test_the_browser_is_closed_even_when_a_page_raises():
    """A leaked Chromium outlives the crawl and holds a proxy connection the
    extension is accounting for.

    MUTATION: drop the context manager around the loop. Must go red.
    """
    made: list[_FakeBrowser] = []

    def factory(**kw):
        b = _FakeBrowser()
        made.append(b)
        return b

    def boom(conn, url, **kw):
        raise RuntimeError("page exploded")

    try:
        crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=boom, browser_factory=factory)
    except RuntimeError:
        pass
    assert made and made[0].closed
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_crawl_run.py -q
```

Expected: `ImportError: cannot import name 'run' from 'hx.crawl'`.

- [ ] **Step 3: Write the module**

```python
# src/hx/crawl/run.py -- the loop and the summary, in full
"""Drive the frontier through one browser and report what happened.

`visit` and `browser_factory` are parameters rather than imports-by-name so
that the loop, the budget accounting and the summary arithmetic can be
tested without Chromium. That is the seam, not a convenience: the parts of
this file worth getting right are arithmetic, and arithmetic should not need
a browser to exercise.
"""
from __future__ import annotations

from typing import Callable, Iterable, NamedTuple

from hx.crawl import browser as browser_mod
from hx.crawl import frontier as frontier_mod
from hx.crawl import page as page_mod


class CrawlSummary(NamedTuple):
    pages: int
    rendered: int
    degraded: int
    failed: int
    capped: int
    requests: int
    dropped_hosts: tuple[str, ...]
    truncated_by: str | None


def crawl(*, seeds: Iterable[str], proxy_port: int,
          budget: frontier_mod.Budget, burp_home=None,
          visit: Callable = page_mod.visit,
          browser_factory: Callable = browser_mod.Browser) -> CrawlSummary:
    """Visit pages until the frontier is empty or a budget stops us."""
    seeds = list(seeds)
    origins = {o for o in (frontier_mod.origin_of(s) for s in seeds) if o}
    frontier = frontier_mod.Frontier(seeds, budget)

    counts = {"rendered": 0, "degraded": 0, "failed": 0}
    capped = 0
    requests = 0
    dropped: set[str] = set()

    with browser_factory(proxy_port=proxy_port, burp_home=burp_home) as browser:
        while True:
            url = frontier.next()
            if url is None:
                break
            result, links = visit(browser.conn, url, page_origins=origins)
            counts[result.state] = counts.get(result.state, 0) + 1
            capped += 1 if result.capped else 0
            requests += result.requests
            dropped.update(result.dropped_hosts)
            # CHARGED AS WE GO. Without this `max_requests` is unenforceable
            # and a crawl can run away inside a page budget -- one page that
            # fires a thousand XHR is a thousand requests against the target.
            frontier.note_requests(result.requests)
            frontier.offer(links)

    return CrawlSummary(
        pages=frontier.visited,
        rendered=counts["rendered"], degraded=counts["degraded"],
        failed=counts["failed"], capped=capped, requests=requests,
        dropped_hosts=tuple(sorted(dropped)),
        # NAMED, or None. A truncated crawl that presented as a complete one
        # is S12's failure one level up, and a complete crawl that claimed
        # truncation would be the same error pointing the other way.
        truncated_by=frontier.exhausted)
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
.venv/bin/pytest tests/test_crawl_run.py -q
```

Expected: 7 passed.

- [ ] **Step 5: Run each named mutation**

| Mutation in `run.py` | Test |
|---|---|
| `dropped = set(result.dropped_hosts)` instead of `update` | `test_dropped_hosts_are_unioned_across_pages_because_that_is_the_fix_list` |
| `truncated_by=None` | `test_a_truncated_crawl_names_the_budget_that_stopped_it` |
| delete the `frontier.note_requests(...)` call | `test_requests_are_charged_to_the_budget_as_pages_are_visited` |
| call `browser_factory(...)` without `with` | `test_the_browser_is_closed_even_when_a_page_raises` |

- [ ] **Step 6: Lint and commit**

```bash
.venv/bin/ruff check src/hx/crawl tests/test_crawl_run.py
awk 'length > 88 {print FILENAME":"FNR": "length}' src/hx/crawl/run.py tests/test_crawl_run.py
git add src/hx/crawl/run.py tests/test_crawl_run.py
git commit -m "feat(crawl): the loop, the budgets and the summary

visit and browser_factory are parameters so the arithmetic is testable
without Chromium -- a seam, not a convenience.

Requests are charged to the budget as pages are visited: without that,
max_requests is unenforceable and one page firing a thousand XHR runs away
inside a page budget.

truncated_by names the budget or is None. A truncated crawl presenting as
complete is S12 one level up; a complete crawl claiming truncation is the
same error pointing the other way, and both have tests."
```

---

## Task 7: `hx crawl` and unblocking `crawl.run`

**Files:**
- Modify: `src/hx/cli.py` (new `crawl` command, modelled on `capture_start` at `:285-383`)
- Modify: `src/hx/tools/impl/scan.py:103-137` (replace the stub handler and its registration)
- Test: `tests/test_crawl_tool.py`

**Interfaces:**
- Consumes: `hx.crawl.run.crawl`, `hx.crawl.run.CrawlSummary`, `hx.crawl.frontier.Budget`, `hx.tools.live.open_for`, `hx.run.open_run` / `close_run`.
- Produces: the `crawl.run` tool answering a real envelope; `hx crawl` on the CLI.

### What changes about the registration

The stub carries neither `needs_egress` nor `mutates`, because a handler that always raises never reaches the checks those flags drive. Both must be set now:

```python
# tools/impl/scan.py -- the replacement registration, a fragment
registry.register(spec.ToolSpec(
    name="crawl.run", handler=crawl, needs_egress=True, mutates=True,
    summary="Drive a browser over in-scope pages through the proxy so their "
            "requests are captured. Synchronous and bounded; must be called "
            "inside a crawl run. Submits no forms and clicks nothing.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "target": {"type": "string", "maxLength": 2048},
        "identity": {"type": "string", "maxLength": 64},
        "max_pages": {"type": "integer", "minimum": 1, "maximum": 10000},
        "max_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
    }}))
```

**`identity` stays in the schema and must be refused.** Authenticated crawling is deferred (spec §12), and a parameter the agent may pass that is silently ignored is worse than one that is rejected: the agent would believe it crawled as a user. Answer `unavailable/not_implemented` naming authenticated crawling specifically when `identity` is present.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crawl_tool.py -- the tool envelope, not the browser
"""`crawl.run` as the agent sees it. The crawl itself is stubbed; what is
under test is the envelope, the refusals and the flags.
"""
from __future__ import annotations

from hx.crawl import run as crawl_run
from hx.tools import registry


def test_crawl_run_is_registered_as_needing_egress():
    """MUTATION: drop `needs_egress=True`. Must go red -- a crawl that does
    not declare egress skips the checks every other sending tool passes.
    """
    spec = registry.get("crawl.run")
    assert spec.needs_egress is True
    assert spec.mutates is True


def test_the_summary_it_returns_names_truncation():
    """A truncated crawl must say so in the tool result, not only in a log.
    MUTATION: omit `truncated_by` from the returned dict. Must go red.
    """
    summary = crawl_run.CrawlSummary(
        pages=3, rendered=2, degraded=1, failed=0, capped=0, requests=9,
        dropped_hosts=("cdn.test",), truncated_by="max_pages")
    body = crawl_run.as_tool_result(summary)
    assert body["truncated_by"] == "max_pages"
    assert body["dropped_hosts"] == ["cdn.test"]
    assert body["degraded"] == 1


def test_asking_for_an_identity_is_refused_and_names_the_reason():
    """Authenticated crawling is deferred. A parameter the agent may pass
    that is silently ignored is worse than one that is rejected: the agent
    would report having crawled as a user.

    MUTATION: ignore `identity` instead of raising. Must go red.
    """
    from hx.tools import errors
    from hx.tools.impl import scan as scan_impl
    import pytest

    with pytest.raises(errors.ToolUnavailable, match="authenticated"):
        scan_impl.crawl(ctx=None, identity="admin")
```

`registry.get` and `errors.ToolUnavailable` are the existing names — confirm the spelling against `src/hx/tools/registry.py` and `src/hx/tools/errors.py` before writing, and use whatever those modules actually export rather than these if they differ.

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_crawl_tool.py -q
```

Expected: `AttributeError: module 'hx.crawl.run' has no attribute 'as_tool_result'`.

- [ ] **Step 3: Add `as_tool_result` to `src/hx/crawl/run.py`**

```python
# src/hx/crawl/run.py -- the tool projection, appended
def as_tool_result(summary: CrawlSummary) -> dict:
    """The summary as the agent sees it.

    `truncated_by` is not optional in this dict. A crawl that stopped on a
    budget and reported only its counts would read as a complete crawl of a
    small application, which is S12's failure with the numbers intact.
    """
    return {
        "pages": summary.pages,
        "rendered": summary.rendered,
        "degraded": summary.degraded,
        "failed": summary.failed,
        "capped": summary.capped,
        "requests": summary.requests,
        "dropped_hosts": list(summary.dropped_hosts),
        "truncated_by": summary.truncated_by,
        "not_done": ["forms are not submitted", "nothing is clicked",
                     "no interaction-gated route is walked",
                     "the crawl is unauthenticated"],
    }
```

- [ ] **Step 4: Replace the stub handler in `src/hx/tools/impl/scan.py`**

Delete the body that raises `not_implemented` unconditionally. The new handler resolves the live session for its `crawler_port`, builds a `Budget` from the parameters, calls `hx.crawl.run.crawl`, and returns `as_tool_result`. Refuse `identity` first:

```python
# tools/impl/scan.py -- the identity refusal, a fragment
def crawl(ctx, **kw) -> dict:
    if kw.get("identity"):
        raise ToolUnavailable(
            "not_implemented",
            "authenticated crawling is not in this build. The crawler runs "
            "unauthenticated, so anything behind a login was not reached by "
            "it -- browse the application through the proxy instead, which is "
            "how S9 covers authenticated applications. Re-run without "
            "`identity`.")
```

- [ ] **Step 5: Add the CLI command**

`hx crawl` in `src/hx/cli.py`, modelled on `capture_start` (`:285-383`) for its `--root` handling and engagement resolution. Options: `--target` (repeatable, the seeds), `--max-pages` (default 200), `--max-seconds` (default 600), `--max-requests` (default 5000). It opens a run with `kind="crawl"`, runs the crawl, closes the run, and prints the summary including the dropped-host list and any truncation.

- [ ] **Step 6: Run the whole unit suite**

```bash
.venv/bin/pytest -q 2>&1 | tail -5
```

Expected: every previous test still passing, plus the new ones.

- [ ] **Step 7: Commit**

```bash
git add src/hx/cli.py src/hx/tools/impl/scan.py src/hx/crawl/run.py tests/test_crawl_tool.py
git commit -m "feat(crawl): hx crawl, and crawl.run stops answering unavailable

Re-registered needs_egress=True and mutates=True -- the stub carried
neither, because a handler that always raises never reaches the checks
those flags drive.

`identity` stays in the schema and is REFUSED by name. Authenticated
crawling is deferred, and a parameter the agent may pass that is silently
ignored is worse than one that is rejected: the agent would report having
crawled as a user."
```

---

## Task 8: What the report says about what this crawler cannot do

**Files:**
- Modify: `src/hx/report.py:1533-1547` (the `crawls` branch of `_limits`)
- Test: `tests/test_report_crawl_limits.py`

**Interfaces:**
- Consumes: nothing new. The branch already exists and already derives `crawls` from `run.kind = 'crawl'`.

The branch was written in advance with its own note: *"Nothing writes `kind='crawl'` today, so the unchanged sentence is what renders... and the day a crawler lands, an engagement that crawled stops being told no crawl happened."* This task is that day. The `else` branch is correct as written and does not change; the `if crawls:` branch gains the four disclosures.

Without this, an engagement that crawled reports *"attack surface here is therefore not only what was browsed through the proxy"* and stops — claiming a crawl's coverage while saying nothing about the four things this crawler does not do.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_crawl_limits.py -- the four disclosures
"""A crawl that submits no forms and clicks nothing must say so.

S12's rule, and the mechanism the Findings scope line established on
2026-09-02: the report states the boundary in the same place it states the
result. Without this, an engagement that crawled reports a crawl's coverage
and discloses none of its four gaps.
"""
from __future__ import annotations

from hx import config as config_mod
from hx import report as report_mod


def _cfg():
    return config_mod.Config(name="T", client="T", safety_profile="staging",
                             scope_include=["https://app.test/*"])


def _crawled(conn):
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r-c','e-1','crawl','staging',1,'closed')")


def test_an_engagement_that_crawled_discloses_what_the_crawl_did_not_do(
        engagement_conn):
    """MUTATION: delete any one of the four disclosures. Must go red.

    Parametrised over the four rather than asserted as one string, so that
    losing exactly one cannot hide behind the other three.
    """
    _crawled(engagement_conn)
    out = report_mod.render(engagement_conn, engagement_id="e-1",
                            config=_cfg())
    for phrase in ("no form", "clicks nothing", "interaction",
                   "unauthenticated"):
        assert phrase in out.lower(), phrase


def test_an_engagement_that_did_not_crawl_keeps_its_own_sentence(
        engagement_conn):
    """THE SEPARATING CASE. The `else` branch predates this task and is
    correct; this pins that adding the disclosures did not displace it.

    MUTATION: render the crawl disclosures unconditionally. Must go red --
    a proxy-only engagement would be told what its crawler did not do.
    """
    out = report_mod.render(engagement_conn, engagement_id="e-1",
                            config=_cfg())
    assert "No automated crawl" in out
    assert "clicks nothing" not in out.lower()


def test_the_degraded_wording_does_not_overstate(engagement_conn):
    """A degraded page MAY not have rendered; we cannot know that it did
    not. S12's asymmetry runs the other way here -- see page.classify's own
    note about false degradation.

    MUTATION: change the copy to "did not render". Must go red.
    """
    _crawled(engagement_conn)
    out = report_mod.render(engagement_conn, engagement_id="e-1",
                            config=_cfg())
    assert "did not render" not in out.lower()
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_report_crawl_limits.py -q
```

Expected: the first test fails on `"no form"`.

- [ ] **Step 3: Extend the `if crawls:` branch**

Append to the existing bullet, keeping its first sentence unchanged:

```python
# report.py -- the crawl disclosures, appended inside `if crawls:`
        out.append("  This build's crawler follows links and renders "
                   "JavaScript. It submits **no forms**, **clicks nothing**, "
                   "walks no route that requires interaction to reach, and "
                   "runs **unauthenticated** -- so anything behind a login, "
                   "behind a button, or reachable only by submitting a form "
                   "was not discovered by it. Pages recorded as `degraded` "
                   "**may not have rendered**: a third-party resource they "
                   "requested was out of scope and was dropped.")
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
.venv/bin/pytest tests/test_report_crawl_limits.py -q
```

Expected: 3 passed.

- [ ] **Step 5: Run the whole unit suite and commit**

```bash
.venv/bin/pytest -q 2>&1 | tail -5
git add src/hx/report.py tests/test_report_crawl_limits.py
git commit -m "feat(report): a crawl discloses the four things it did not do

The `if crawls:` branch has existed since the reporting plan, written in
advance with a note saying it would matter the day a crawler landed. This
is that day.

Without it, an engagement that crawled claims a crawl's coverage and
discloses none of: no forms submitted, nothing clicked, no
interaction-gated route walked, unauthenticated.

'may not have rendered', never 'did not render' -- page.classify's
degradation rule is deliberately imprecise in the under-claiming
direction, and the copy must not overstate what it knows."
```

---

## Task 9: Integration — a real browser, and the flag that matters

**Files:**
- Create: `tests/integration/test_crawl_integration.py`
- Test: itself

**Interfaces:**
- Consumes: everything above, plus `tests/integration/target_server.py`'s `TargetServer` and the existing Burp session fixtures used by the other integration tests. **Read `tests/integration/` first and follow whatever fixture pattern is already there** — do not invent a second way to start Burp.

### Why this task exists separately

Every test before this one runs without a browser, which is what makes them fast and what makes them honest about what they check. But three claims cannot be checked without real Chromium and a real extension, and one of them is the most important claim in the plan.

- [ ] **Step 1: Write the tests**

```python
# tests/integration/test_crawl_integration.py -- real Chromium, real extension
"""The crawler against a real Burp and a real Chromium.

MARKED `integration`: needs the Burp jar and the bundled browser, and takes
tens of seconds. Everything checkable without a browser is checked in the
unit suite; these are the three claims that cannot be.

LOOPBACK ONLY. `TargetServer` refuses any host outside 127.0.0.0/8 and that
refusal is load-bearing, not tidiness.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_a_crawl_produces_exchanges_attributed_to_the_crawler(...):
    """THE TEST THIS WHOLE PLAN TURNS ON.

    Measured 2026-09-02: without `--proxy-bypass-list=<-loopback>`,
    Chromium sent ZERO connections to the proxy for a loopback target and
    reached it directly -- around ProxyGate and every S4 enforcement point.
    Every target in this repo is loopback by mandate, so a crawler missing
    that flag renders pages perfectly and passes any test that merely checks
    the page loaded.

    MUTATION: delete `--proxy-bypass-list=<-loopback>` from
    `browser.launch_argv`. This test MUST go red.

    It asserts on the STORE, not on the page: rows attributed to the crawler
    listener. A page-rendered assertion survives the mutation, which is why
    it is not the assertion here.
    """


def test_an_out_of_scope_destination_is_dropped_and_recorded(...):
    """`TargetServer` binds the in-scope target on 127.0.0.1 and the
    out-of-scope one on 127.0.0.2. BOTH ARE LOOPBACK, so this test shares
    the bypass blind spot above: without the flag the browser would reach
    127.0.0.2 directly and this test would be asserting the ABSENCE of a
    recording rather than the PRESENCE of a refusal.

    So it asserts the denial row exists, not that the exchange is missing.

    MUTATION: remove the CRAWLER branch from ProxyGate. Must go red.
    """


def test_render_allow_changes_the_outcome_for_the_crawler_only(...):
    """Task 1 end to end: with 127.0.0.2 in `render_allow`, the crawler
    reaches it; the send path still does not.

    MUTATION: have `decideBeforeGate` pass `renderAllow=true`. Must go red
    on the second half.
    """
```

Fill each body against the real fixtures. The docstrings are the contract; the assertions must match what they claim.

- [ ] **Step 2: Run the integration suite**

```bash
.venv/bin/pytest -m integration tests/integration/test_crawl_integration.py -q
```

Expected: 3 passed. These are slow; that is expected.

- [ ] **Step 3: Run the bypass mutation and confirm it goes red**

This is the single most important verification in the plan.

```bash
# remove the flag, run, restore
sed -i '/proxy-bypass-list/d' src/hx/crawl/browser.py
.venv/bin/pytest -m integration tests/integration/test_crawl_integration.py -q
git checkout src/hx/crawl/browser.py
```

Expected: `test_a_crawl_produces_exchanges_attributed_to_the_crawler` FAILS. If it passes, the test is asserting something that does not depend on the proxy — rewrite it against the store and try again. **Do not proceed until this mutation reddens the test.**

- [ ] **Step 4: Full verification**

```bash
.venv/bin/pytest -q 2>&1 | tail -3
.venv/bin/pytest -m integration -q 2>&1 | tail -3
MONTOYA_JAR=$(pwd)/../burp-lab/probe/lib/montoya-api.jar ./extension/test.sh 2>&1 | grep -c FAIL
.venv/bin/ruff check src tests
awk 'length > 88 {print FILENAME":"FNR": "length}' src/hx/crawl/*.py
```

Expected: unit suite green, integration green, `0` Java failures, ruff clean, no long lines.

- [ ] **Step 5: Update the drift gate and commit**

```bash
.venv/bin/pytest tests/test_plan_matches_repo.py -q 2>&1 | tail -20
```

If `test_the_check_actually_found_some_blocks` fails, set `EXPECTED_BLOCKS` in `tests/test_plan_matches_repo.py` to the number the message reports, and name this plan in the commit message as the reason.

```bash
git add tests/integration/test_crawl_integration.py tests/test_plan_matches_repo.py
git commit -m "test(crawl): the three claims that need a real browser

The first is the one this plan turns on: a crawl must produce exchanges
attributed to the CRAWLER listener. It asserts on the store rather than on
the page, because a page-rendered assertion survives the mutation it exists
to catch -- deleting --proxy-bypass-list=<-loopback>, without which
Chromium reached a loopback target directly and around every enforcement
point.

The out-of-scope test shares that blind spot by construction, since
TargetServer's out-of-scope target is also loopback, so it asserts the
presence of a denial row rather than the absence of an exchange."
```

---

## Done when

- `hx crawl --target http://127.0.0.1:<port>/` walks a loopback application and its requests appear as surfaces with `discovered_by = 'crawl'`
- `crawl.run` answers a real summary and refuses `identity` by name
- The report of an engagement that crawled discloses all four gaps
- `render_allow` enforces for the crawler and not for the send path
- Deleting `--proxy-bypass-list=<-loopback>` turns an integration test red
- Unit suite green, integration suite green, Java suite `0` FAIL, ruff clean
