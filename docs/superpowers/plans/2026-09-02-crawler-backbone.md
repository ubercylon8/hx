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

import os
import subprocess
import sys

import pytest

from hx.crawl import cdp

PEER = r'''
import json, os, sys
buf = b""
deferred = None
while True:
    chunk = os.read(3, 65536)
    if not chunk:
        break
    buf += chunk
    while b"\0" in buf:
        raw, buf = buf.split(b"\0", 1)
        msg = json.loads(raw)
        # Flush what we owe BEFORE answering the new message, so an older
        # reply reaches the pipe ahead of a newer one.
        if deferred is not None:
            os.write(4, json.dumps(
                {"id": deferred, "result": {"deferred": True}}).encode() + b"\0")
            deferred = None
        if msg["method"] == "Peer.deferred":
            deferred = msg["id"]
            continue
        if msg["method"] == "Peer.emitEvent":
            os.write(4, json.dumps(
                {"method": "Peer.happened", "params": {"n": 1}}).encode() + b"\0")
        if msg["method"] == "Peer.fail":
            err = {"code": -32000, "message": "peer refused"}
            os.write(4, json.dumps(
                {"id": msg["id"], "error": err}).encode() + b"\0")
            continue
        if msg["method"] == "Peer.silent":
            continue
        if msg["method"] == "Peer.garbled":
            os.write(4, b"{not json\0")
            reply = {"id": msg["id"], "result": {"echo": "after garbage"}}
            os.write(4, json.dumps(reply).encode() + b"\0")
            continue
        reply = {"id": msg["id"], "result": {"echo": msg.get("params", {})}}
        os.write(4, json.dumps(reply).encode() + b"\0")
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
    """THE SMOKE TEST for the whole call/reply mechanism: send one command
    over the pipe, get exactly the `result` field of its own reply back --
    not the full CDP envelope, and not a coincidentally-matching neighbour
    (with only one message in flight here, correlation-by-id itself is the
    sibling test's job below; this one is the baseline every other test in
    this file assumes still works).

    MUTATION: return the raw `reply` dict from `call` instead of `reply.
    get("result", {})`. This test must go red -- the returned value would be
    `{"id": 1, "result": {"echo": {"x": 7}}}`, the whole envelope, not the
    `{"echo": {"x": 7}}` a caller actually asked for.
    """
    conn, proc = _peer()
    try:
        assert conn.call("Peer.echo", {"x": 7}) == {"echo": {"x": 7}}
    finally:
        conn.close()
        proc.kill()


def test_replies_are_matched_by_id_not_by_arrival_order():
    """THE CORRELATION TEST, and the fixture is the whole of it.

    `Peer.deferred` leaves the peer owing a reply to id=1. That reply is
    flushed to the pipe immediately BEFORE the reply to id=2, so two replies
    arrive out of order and the transport must hand each caller its own.

    MUTATION: in `call`, return the first message carrying any `id` rather
    than the one matching `msg_id`. This test must go red -- id=2's caller
    would receive `{"deferred": True}`.

    An earlier draft of this test used a peer that never replied at all, so
    only one reply ever existed and the mutation above still passed it. That
    is why the fixture is shaped this way and not more simply.
    """
    conn, proc = _peer()
    try:
        with pytest.raises(cdp.CdpTimeout):
            conn.call("Peer.deferred", timeout=0.3)
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
    """MUTATION: in `_pump`, replace `if not chunk: raise CdpClosed(...)`
    with `if not chunk: return`. Must go red.

    The peer closes only its OUTPUT (fd 4) and then blocks, keeping its
    INPUT (fd 3) open. That forces the failure through `_pump`'s read loop:
    `_write` still succeeds (a reader is still attached), so the only way
    this call can fail is a zero-length read on our end. A peer killed
    outright would instead break the write with EPIPE and raise CdpClosed
    from `_write`, unaffected by this mutation -- passing this test for the
    wrong reason regardless of what `_pump` does with a zero-length read.

    Under the mutation, `_pump` returns instead of raising, `call` loops
    back around, `_pump` reads EOF again (a closed pipe is always
    select()-ready), and this repeats until the call's own deadline fires
    CdpTimeout -- a *different* exception than the CdpClosed asserted below,
    so the mutation still turns this red rather than slipping through a
    tuple of acceptable exceptions.
    """
    to_child_r, to_child_w = os.pipe()
    from_child_r, from_child_w = os.pipe()

    def fixup():
        os.dup2(to_child_r, 3)
        os.dup2(from_child_w, 4)

    proc = subprocess.Popen(
        [sys.executable, "-c", "import os, time; os.close(4); time.sleep(5)"],
        preexec_fn=fixup, pass_fds=(3, 4), close_fds=True,
    )
    os.close(to_child_r)
    os.close(from_child_w)
    conn = cdp.Connection(read_fd=from_child_r, write_fd=to_child_w)
    try:
        with pytest.raises(cdp.CdpClosed):
            conn.call("Peer.echo", timeout=2.0)
    finally:
        conn.close()
        proc.kill()
        proc.wait()


def test_a_fully_dead_peer_fails_the_write_not_the_read():
    """MUTATION: in `_write`, swallow the `OSError` and `return` instead of
    raising `CdpClosed`. Must go red -- with the write silently dropped,
    `call` proceeds into `_pump`, finds nothing to read (the read pipe's
    write end is deliberately held open below, so there is no EOF to catch
    it either), and instead of failing closed it just burns its timeout and
    raises `CdpTimeout` -- a different exception than the `CdpClosed`
    asserted here.

    COMPANION to `test_a_dead_peer_raises_closed_rather_than_hanging`, and
    deliberately a SEPARATE fixture rather than one shared with it -- and
    deliberately NOT a real child process either, unlike every other test in
    this file. A "kill the peer outright" child (the brief's original
    fixture, and my first attempt at this one) makes the mutation
    UNOBSERVABLE: with both of the peer's fds gone, a silently-swallowed
    write failure is immediately backstopped by `_pump`'s own (unmutated,
    correct) read-EOF check, which also raises `CdpClosed` -- so the test
    goes green for the wrong reason, the very failure this task exists to
    catch. A "close only fd 3, then sleep" child fixes that in principle but
    is racy in practice: nothing guarantees the child has closed its read
    end before this test's first `os.write` runs, and a write that lands
    before the close just sits unread in the kernel buffer forever, timing
    out regardless of whether `_write` is correct or mutated -- confirmed
    empirically, the "corrected" child fixture still failed on CORRECT code.
    Two bare pipes, entirely in this process, are what make each end's
    state deterministic: no fork, no exec, no race to lose.

    `to_peer_w` has its only reader closed before `Connection` ever touches
    it, so `_write`'s `os.write` is guaranteed EPIPE. `from_peer_r`'s writer
    (`from_peer_w`) is held open and never written to, so a read on it can
    only block, never see EOF -- there is no other way this call can end
    except through `_write`'s own error handling.
    """
    to_peer_r, to_peer_w = os.pipe()
    os.close(to_peer_r)
    from_peer_r, from_peer_w = os.pipe()

    conn = cdp.Connection(read_fd=from_peer_r, write_fd=to_peer_w)
    try:
        with pytest.raises(cdp.CdpClosed):
            conn.call("Peer.echo", timeout=2.0)
    finally:
        conn.close()
        os.close(from_peer_w)


def test_a_malformed_frame_is_dropped_not_fatal():
    """CONTROLLER RULING: `_pump`'s `except ValueError: continue` stays, even
    though dropping an unparseable frame looks like it violates this
    project's fail-closed rule as literally stated. It does not: fail-closed
    governs decisions that could permit egress or authorise an action --
    never allow what you could not verify. A garbled frame on a local pipe
    from a browser we launched authorises nothing. Raising would let one
    malformed frame end an entire crawl. Dropping is the safe direction on
    both branches: a lost reply surfaces as the caller's own `CdpTimeout`,
    which is loud; a lost event makes a page look like it requested less
    than it did, which the crawler's page classifier reads as less yield --
    i.e. it under-claims coverage, the direction spec Sec 12 explicitly
    prefers.

    MUTATION: re-raise instead of `continue` in that except block. Must go
    red -- the call would die on the garbage frame instead of returning the
    good reply that follows it on the same pipe.
    """
    conn, proc = _peer()
    try:
        assert conn.call("Peer.garbled") == {"echo": "after garbage"}
    finally:
        conn.close()
        proc.kill()
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
as data is what makes the flags reviewable. The two tests that drive a
subprocess use a tiny fake "chrome" script, never real Chromium -- the one
test that starts a real Chromium lives in the integration suite (Task 9).
"""
from __future__ import annotations

import os
import sys
import time
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
    """`--proxy-server` must carry the CALLER'S port, not a hardcoded one --
    the sibling test above pins that the bypass-list flag exists at all;
    this one pins that the proxy address itself is wired through correctly.

    MUTATION: hardcode the port, e.g. `"--proxy-server=127.0.0.1:8080"`
    instead of `f"--proxy-server=127.0.0.1:{proxy_port}"`. This test must go
    red -- called with `proxy_port=9999`, the assertion looks for
    `...:9999` and finds `...:8080` in argv instead.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=9999,
                                user_data_dir=Path("/tmp/p"))
    assert "--proxy-server=127.0.0.1:9999" in argv


def test_the_sandbox_is_never_disabled():
    """MUTATION: add `--no-sandbox` to `launch_argv`. Must go red.

    A security tool renders hostile pages. Verified 2026-09-02 that
    Chromium starts sandboxed on this platform via unprivileged user
    namespaces, so there is nothing to trade off.
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
    """The general "newest wins" claim, with three candidates in no
    particular directory order -- distinct from the sibling test below,
    which pins the NUMERIC-vs-lexicographic comparison specifically
    (`"9" > "150"` as strings). This one would pass even with a naive
    string sort, so it needs its own mutation on the selection itself.

    MUTATION: pick the OLDEST candidate instead of the newest, e.g.
    `newest = min(candidates, key=lambda d: _version_key(d.name))`. This
    test must go red -- `find_chromium` would return `9.0.1.2`, the lowest
    version present, instead of `150.0.7871.186`.
    """
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
    ordinary state an operator must be told how to fix.

    MUTATION: raise a bare `RuntimeError(...)` (same message) instead of
    `BrowserUnavailable(...)` in `find_chromium`. This test must go red --
    `pytest.raises(browser.BrowserUnavailable, ...)` requires that specific
    class, and a caller catching `BrowserUnavailable` to print the fix would
    let a `RuntimeError` propagate as an unhandled crash instead.
    """
    with pytest.raises(browser.BrowserUnavailable, match="burpbrowser"):
        browser.find_chromium(tmp_path)


def test_session_id_is_none_before_the_browser_is_entered():
    """Ruling 9: `Browser` exposes `.session_id` so Task 5/6 can read it. It
    starts `None` -- there is no page session before a Chromium exists.

    MUTATION: initialise `self.session_id: str | None = ""` instead of
    `None` in `Browser.__init__`. This test must go red -- a caller who
    checks `if browser.session_id is None` to decide whether `__enter__` has
    run yet would see `""`, which is falsy but not `None`, and the check
    would silently give the wrong answer.
    """
    b = browser.Browser(proxy_port=1, chrome=Path("/x/chrome"))
    assert b.session_id is None


def test_a_construction_failure_leaves_no_fds_process_or_profile_dir(
        tmp_path, monkeypatch):
    """`__enter__` opens two pipes, then calls `Popen()` and
    `cdp.Connection()` -- both of which can raise something that is not a
    `cdp.CdpError` (a bad exec, fd exhaustion, a `Connection()` construction
    failure). Only the CDP-call block was ever guarded; an exception from
    `Popen()` or `Connection()` used to propagate out of `__enter__`
    uncaught. Python never calls `__exit__` on a context manager whose
    `__enter__` didn't return, so `close()` never ran: a leaked Chromium (if
    `Popen()` had succeeded) plus the profile dir plus whichever pipe fds
    hadn't yet been handed off.

    This fixture makes `Popen()` itself fail: `chrome` exists but is not
    executable, so `Popen()` raises `PermissionError` while trying to exec
    it -- a plain `OSError`, not `cdp.CdpError`, so only a guard around the
    WHOLE construction (not just the CDP calls) can catch it. At the moment
    of failure all four pipe fds `__enter__` opened are still unhanded-off
    (Popen never returned, so the parent-side `os.close()` calls right
    after it never ran either) -- which is exactly the case that exercises
    the fix, not a degenerate one where there was nothing left to leak.

    MUTATION: remove the `try`/`except BaseException` wrapping the whole of
    `__enter__` (i.e. revert to guarding only the CDP-call block, as the
    task brief originally had it). Must go red: the four fds this test
    tracks stay open (`os.fstat` on them no longer raises), and the profile
    directory survives.

    `os.pipe` is spied on rather than guessed at, so the test checks the
    OWN four fds `__enter__` made, not a coincidence. `b` is kept alive for
    the whole test (never `del`eted, never let go out of scope before the
    assertions run) specifically so `TemporaryDirectory`'s GC finalizer
    cannot be the thing that removes the profile directory -- a finalizer
    only runs once nothing still references the `TemporaryDirectory`, and a
    live `b` holds one via `b._tmp` throughout. If the directory is gone,
    `close()` removed it, not garbage collection.
    """
    chrome = tmp_path / "not-executable-chrome"
    chrome.write_text("#!/bin/true\n")
    # Deliberately NOT chmod'd +x.

    created_fds: list[int] = []
    real_pipe = os.pipe

    def spy_pipe():
        pair = real_pipe()
        created_fds.extend(pair)
        return pair

    monkeypatch.setattr(os, "pipe", spy_pipe)

    b = browser.Browser(proxy_port=1, chrome=chrome)
    with pytest.raises(PermissionError):
        b.__enter__()

    # `__enter__`'s own two `os.pipe()` calls happen first, before
    # `Popen()` -- which then opens an fd pair of its OWN internally, to
    # report a failed exec back to the parent. That third pair is
    # `subprocess`'s to close, not ours; only the first four are `__enter__`'s.
    assert len(created_fds) >= 4, "fixture assumption: __enter__ opens two pipes"
    our_fds = created_fds[:4]
    for fd in our_fds:
        with pytest.raises(OSError):
            os.fstat(fd)  # closed fds fail fstat with EBADF

    assert b.proc is None
    assert b.conn is None
    assert not Path(b._tmp.name).exists(), \
        "profile dir survived a failed __enter__"


# --- fixtures for the two tests that drive a subprocess --------------------


def _fake_chrome_script(tmp_path: Path, body: str) -> Path:
    """A tiny shebang script standing in for Chromium on fds 3/4.

    Popen execs `argv[0]` directly (no shell), so this must be a real
    executable file, not a `python -c ...` invocation -- `launch_argv`
    appends Chromium-shaped flags after `argv[0]` that a bare interpreter
    invocation could not parse. A shebang script ignores them like any CLI
    tool ignores flags it doesn't ask for.
    """
    script = tmp_path / "fake-chrome"
    script.write_text(f"#!{sys.executable}\n{body}")
    script.chmod(0o755)
    return script


_CDP_PEER_BODY = """
import json, os

def send(msg):
    os.write(4, json.dumps(msg).encode() + b"\\0")

buf = b""
while True:
    chunk = os.read(3, 65536)
    if not chunk:
        break
    buf += chunk
    while b"\\0" in buf:
        raw, buf = buf.split(b"\\0", 1)
        if not raw:
            continue
        msg = json.loads(raw)
        method = msg.get("method")
        if method == "Browser.getVersion":
            send({"id": msg["id"], "result": {"product": "fake/1.0"}})
        elif method == "Target.createTarget":
            send({"id": msg["id"], "result": {"targetId": "target-1"}})
        elif method == "Target.attachToTarget":
            if msg.get("params", {}).get("flatten") is True:
                send({"id": msg["id"],
                      "result": {"sessionId": "session-abc"}})
            else:
                send({"id": msg["id"],
                      "error": {"code": -1, "message": "flatten required"}})
        else:
            send({"id": msg["id"], "result": {}})
"""


def test_entering_attaches_a_flattened_page_session(tmp_path):
    """Ruling 9, measured 2026-09-02 against real Chromium: a
    `--remote-debugging-pipe` connection is BROWSER-level. `Page`, `Network`,
    `DOM` and `Runtime` don't exist on it (`Page.enable: 'Page.enable' wasn't
    found`). `__enter__` must create a page target and attach with
    `flatten: True`, and store the resulting session id.

    MUTATION 1: remove the `Target.createTarget` / `Target.attachToTarget`
    calls from `__enter__` (revert to the pre-Ruling-9 handshake). Must go
    red -- `session_id` stays `None` and the assertion below fails.

    MUTATION 2: drop `"flatten": True` from the `Target.attachToTarget`
    params. Must go red -- this fixture's fake peer refuses to hand out a
    session id without it, so `__enter__` raises `BrowserUnavailable`
    instead of returning.
    """
    chrome = _fake_chrome_script(tmp_path, _CDP_PEER_BODY)
    with browser.Browser(proxy_port=1, chrome=chrome) as b:
        assert b.session_id == "session-abc"


def test_a_browser_that_never_answers_cdp_fails_instead_of_hanging(tmp_path):
    """Ruling 6, and it overrides the brief. The brief's error path read
    `proc.stderr.read()` BEFORE killing the child; `read()` blocks until
    EOF, and a Chromium that launched but never answers CDP is still alive,
    so the crawler would hang forever inside the very handler that exists to
    report a refused sandbox. MEASURED 2026-09-02: `read()` had not returned
    after 2s against a live child.

    MUTATION: in `_kill_and_read_stderr`, move `self.proc.kill()` to AFTER
    `self.proc.communicate(...)`. Must go red: `communicate()` then waits
    for the still-running fake "chromium" to exit on its own, which it never
    does until it hits ITS OWN `communicate(timeout=self._stderr_timeout)`
    ceiling -- blowing the wall-clock bound asserted below. This is the
    "goes red by timing out, not by asserting" case the ruling calls for:
    `pytest-timeout` is not a dependency, so the bound is measured with
    `time.monotonic()` instead of a marker.

    Uses `handshake_timeout=` / `stderr_timeout=` -- testability seams added
    to `Browser.__init__` for exactly this test, documented in the task
    report. Production code never sets them; the defaults are the timeouts
    Ruling 6 and Ruling 9 specify (10s / 20s).
    """
    chrome = _fake_chrome_script(
        tmp_path,
        "import sys, time\n"
        "sys.stderr.write('fake refusal: sandbox message\\n')\n"
        "sys.stderr.flush()\n"
        "time.sleep(60)\n",
    )
    start = time.monotonic()
    with pytest.raises(browser.BrowserUnavailable, match="sandbox"):
        with browser.Browser(proxy_port=1, chrome=chrome,
                              handshake_timeout=0.3, stderr_timeout=3.0):
            pass
    elapsed = time.monotonic() - start
    # Correct code: kill first, so `communicate()` on an already-dead child
    # returns near-instantly -- measured ~0.3s (just handshake_timeout, the
    # CdpTimeout on the browser-level handshake). Under the mutation,
    # `communicate()` runs BEFORE the kill and must wait out the full
    # `stderr_timeout` against a child that is still very much alive --
    # measured ~3.3s. 2s cleanly separates the two without being flaky.
    assert elapsed < 2.0, f"took {elapsed:.2f}s -- the error path hung"
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
    """A launched Chromium, its CDP connection, and its one page session.

    A context manager, because a leaked Chromium survives the crawl, holds a
    private profile directory open, and keeps a proxy connection the
    extension is accounting for.

    `--remote-debugging-pipe` gives a BROWSER-level CDP session: the Page,
    Network, DOM and Runtime domains do not exist on it (Ruling 9, measured
    2026-09-02 -- `Page.enable` came back "wasn't found" without this).
    `__enter__` therefore creates a page target and attaches to it with
    `flatten: True`, exposing the resulting `session_id` for callers (Task 5's
    `page.visit`) to pass on every domain call. The attach lives here, on the
    browser's lifetime, rather than per page: re-attaching per page would be
    both wasteful and racy.
    """

    def __init__(self, *, proxy_port: int, burp_home: Path | None = None,
                 chrome: Path | None = None, handshake_timeout: float = 20.0,
                 stderr_timeout: float = 10.0) -> None:
        self._chrome = Path(chrome) if chrome else find_chromium(burp_home)
        self._proxy_port = proxy_port
        # `ignore_cleanup_errors` because Chromium outlives its own main
        # process: zygote and renderer children can still be flushing the
        # profile when `close()` removes it, and the removal then raises
        # `OSError: [Errno 39] Directory not empty`. MEASURED 2026-09-04 --
        # it appeared only once a crawl got far enough to write a real
        # profile, so the shorter crawls before it never hit it.
        #
        # A scratch directory that will not delete is a few hundred kilobytes
        # in /tmp. Failing the whole crawl over it would discard everything
        # the run captured, which is the worse of the two outcomes by a wide
        # margin.
        self._tmp = tempfile.TemporaryDirectory(
            prefix="hx-crawl-profile-", ignore_cleanup_errors=True)
        self.proc: subprocess.Popen | None = None
        self.conn: cdp.Connection | None = None
        self.session_id: str | None = None
        # Testability seams: production callers never set these, so the
        # defaults are the timeouts measured for a real Chromium handshake
        # (Ruling 9) and for reading a killed child's stderr (Ruling 6).
        # Tests that must stay fast without a real browser pass shorter
        # values through the constructor rather than mocking `cdp.Connection`.
        self._handshake_timeout = handshake_timeout
        self._stderr_timeout = stderr_timeout

    def __enter__(self) -> Browser:
        # `open_fds` is every raw descriptor this method still owns and must
        # close on any path that is not a successful return. Two things hand
        # descriptors off to something else that will close them instead: a
        # successful `Popen()` (the child's dup2'd copies of fds 3/4 become
        # the CHILD's to close on exit, so the parent's `to_child_r` and
        # `from_child_w` are closed right here) and a successful
        # `cdp.Connection(...)` (which owns `from_child_r`/`to_child_w` from
        # then on, via `Connection.close()`). Each handoff removes its fds
        # from this set so a failure after it does not double-close them --
        # and a failure BEFORE either handoff (even the first `os.pipe()`
        # succeeding but the second failing) still finds every fd it made in
        # the set and closes it exactly once.
        open_fds: set[int] = set()
        try:
            to_child_r, to_child_w = os.pipe()
            open_fds.update((to_child_r, to_child_w))
            from_child_r, from_child_w = os.pipe()
            open_fds.update((from_child_r, from_child_w))

            def fixup() -> None:
                # dup2 ONTO 3 and 4, and `pass_fds=(3, 4)` below is not
                # optional. subprocess closes descriptors outside pass_fds
                # AFTER preexec_fn runs, so without it these are closed
                # before exec and Chromium answers "Remote debugging pipe
                # file descriptors are not open." Measured 2026-09-02, on
                # the first attempt at this.
                os.dup2(to_child_r, 3)
                os.dup2(from_child_w, 4)

            argv = launch_argv(self._chrome, proxy_port=self._proxy_port,
                                user_data_dir=Path(self._tmp.name))
            self.proc = subprocess.Popen(
                argv, preexec_fn=fixup, pass_fds=(3, 4), close_fds=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            os.close(to_child_r)
            open_fds.discard(to_child_r)
            os.close(from_child_w)
            open_fds.discard(from_child_w)
            self.conn = cdp.Connection(read_fd=from_child_r, write_fd=to_child_w)
            open_fds.discard(from_child_r)
            open_fds.discard(to_child_w)

            self.conn.call("Browser.getVersion", timeout=self._handshake_timeout)
            target_id = self.conn.call(
                "Target.createTarget", {"url": "about:blank"},
                timeout=self._handshake_timeout)["targetId"]
            self.session_id = self.conn.call(
                "Target.attachToTarget",
                {"targetId": target_id, "flatten": True},
                timeout=self._handshake_timeout)["sessionId"]
        except cdp.CdpError as e:
            detail = self._kill_and_read_stderr()
            self.close()
            raise BrowserUnavailable(
                "Chromium started but did not answer CDP. If the message "
                "below mentions the sandbox, hx will not disable it: "
                f"{detail}") from e
        except BaseException:
            # BaseException, not Exception: a KeyboardInterrupt between
            # `Popen()` and the handshake must not leak a running Chromium
            # either. Whatever wasn't handed off above is still in
            # `open_fds`; whatever WAS handed off is closed by `close()`
            # via `self.proc`/`self.conn`, which are `None` if their
            # construction never completed.
            for fd in open_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self.close()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _kill_and_read_stderr(self) -> str:
        """Chromium's own words about why it would not start.

        KILL FIRST, and that ordering is the whole method.
        `proc.stderr.read()` blocks until EOF, and a Chromium that launched
        but never answered CDP is still running -- so reading before killing
        hangs the error path forever. MEASURED 2026-09-02: `read()` had not
        returned after 2s against a live child.
        """
        if self.proc is None:
            return ""
        self.proc.kill()
        try:
            _, err = self.proc.communicate(timeout=self._stderr_timeout)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            return ""
        return (err or b"").decode("utf-8", "replace")[:400]

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        if self.proc is not None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
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
    """`#a` and `#b` are one document and one request -- see the module
    docstring's "the fragment goes" line.

    MUTATION: pass `parts.fragment` instead of `""` as the fifth element of
    the `urlunsplit(...)` tuple in `normalise`. This test must go red.
    """
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
    """The `_seen` set, not just the queue: a URL already visited-or-queued
    must not be offered again, or the same page would be crawled twice for
    every link back to it. The second offer spells the URL with a different
    fragment on purpose, so this also depends on `normalise` collapsing it to
    the same seen-set key as the first.

    MUTATION: delete the `if n in self._seen: return False` guard in
    `_enqueue` (leave the unconditional `self._seen.add(n)` in place). This
    test must go red -- the second `offer()` would return 1, not 0.
    """
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

    The `normalise()` assertion on `ftp://a.test/x` is load-bearing and the
    `offer()` assertion alone is not enough: `javascript:`/`mailto:`/
    `data:`/`blob:` have no host, so the `not host` branch refuses them
    with the scheme check deleted entirely -- a wrong-reason pass. And
    `ftp://a.test/x` DOES have a host, but routed through `offer()` its
    differing scheme also gives it a differing origin, so the origin
    allowlist would refuse it even with the scheme check gone -- a second
    wrong-reason pass. Only a direct call to `normalise()` isolates the
    scheme guard from both of those.

    MUTATION: accept any scheme in `normalise`. Must go red -- and the
    crawler would try to navigate to `javascript:alert(1)` harvested from a
    page under test.
    """
    assert frontier.normalise("ftp://a.test/x") is None
    assert frontier.normalise("ws://a.test/x") is None
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["javascript:alert(1)", "mailto:x@a.test",
                    "data:text/html,x", "blob:https://a.test/z",
                    "ftp://a.test/x"]) == 0


def test_a_second_seed_origin_is_allowed():
    """The origin allowlist is built from EVERY seed, not just the first --
    a two-origin engagement (say `app.test` plus its `api.app.test`) must be
    able to crawl both.

    MUTATION: build `self._origins` from only the first seed, e.g.
    `for seed in list(seeds)[:1]:` in `Frontier.__init__`. This test must go
    red -- `b.test` would never make it into the allowlist and `offer()`
    would return 0.
    """
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
    """`next()`'s three budget checks read three DIFFERENT fields off
    `self._budget`, and it is easy to copy-paste one check into another's
    shape and read the wrong field -- `_b(requests=10)` leaves `max_pages`
    and `max_seconds` at their generous defaults, so only the requests check
    can fire here, and this test isolates it from its two siblings rather
    than merely happening not to collide with them.

    MUTATION: in the `self._requests >= self._budget.max_requests` check,
    read `self._budget.max_pages` instead. This test must go red -- with
    `max_pages` still at its default of 100, `11 >= 100` is false and
    `next()` returns the queued page instead of `None`.
    """
    f = frontier.Frontier(["https://a.test/1"], _b(requests=10))
    f.offer(["https://a.test/2"])
    assert f.next() is not None
    f.note_requests(11)
    assert f.next() is None
    assert f.exhausted == "max_requests"


def test_the_time_budget_stops_the_crawl_and_names_itself():
    """Same isolation concern as the request-budget test above, for the
    third of `next()`'s three budget checks: `_b(seconds=5.0)` leaves
    `max_pages` and `max_requests` at their generous defaults, so only the
    elapsed-time check can fire.

    MUTATION: in the `self._clock() - self._started >= self._budget.
    max_seconds` check, read `self._budget.max_requests` instead. This test
    must go red -- with `max_requests` still at its default of 10_000, the
    elapsed 99.0 seconds does not clear it and `next()` returns the queued
    page instead of `None`.
    """
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


# -- Ruling 13: three bugs measured in the brief's `normalise`, corrected. --


def test_a_malformed_port_is_refused_and_does_not_end_the_crawl():
    """These URLs come from `harvest`, which reads the DOM of a page under
    test -- ATTACKER-INFLUENCED INPUT. `urlsplit` does not validate the
    port; `parts.port` does, and it raises. MEASURED 2026-09-02: the first
    draft read `.port` outside its `try` and one
    `<a href="https://a.test:99999/">` ended the whole crawl with an
    unhandled ValueError.

    MUTATION: move the `parts.port` read outside the `try`. Must go red.
    """
    for bad in ("https://a.test:99999/x", "https://a.test:-1/x",
                "https://a.test:abc/x"):
        assert frontier.normalise(bad) is None


def test_an_ipv6_host_keeps_its_brackets():
    """`parts.hostname` strips them and a bare `::1` is not an authority.

    MUTATION: drop the re-bracketing. Must go red -- and the crawler would
    build `https://::1:8443/x`, which nothing can navigate to and which
    compares equal to no origin.
    """
    assert frontier.normalise("https://[::1]:8443/x") == "https://[::1]:8443/x"
    assert frontier.origin_of("https://[::1]:8443/x") == "https://[::1]:8443"


def test_userinfo_is_refused_rather_than_stripped():
    """REFUSED, NOT REWRITTEN. Stripping would visit a URL the page did not
    name -- the confusion userinfo exists to create, and the shape
    `Policy.checkScope` refuses on the Java side.

    MUTATION: strip the userinfo and continue instead of returning None.
    Must go red.
    """
    assert frontier.normalise("https://evil.test@app.test/") is None
    assert frontier.normalise("https://user:pw@a.test/x") is None
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

    These URLs come from `harvest`, which reads the DOM of a page under
    test -- attacker-influenced input. Every failure mode below must
    resolve to `None`, never to a raised exception or a rewritten URL:
    a malformed port must not end the crawl, and userinfo must be
    refused, not silently stripped (see ruling-13-normalise.md).
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port  # INSIDE the try: `.port` validates and raises,
        # and this input came from a page under test
        username = parts.username
        password = parts.password
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    if username is not None or password is not None:
        # REFUSED, NOT STRIPPED. Rewriting would visit a URL the page did
        # not name -- exactly the confusion userinfo exists to create, and
        # the shape `Policy.checkScope` refuses on the Java side.
        return None
    # Re-bracket IPv6: `.hostname` removes the brackets and a bare `::1`
    # is not a URL authority.
    netloc = f"[{host}]" if ":" in host else host.lower()
    if port and port != _DEFAULT_PORTS[parts.scheme]:
        netloc = f"{netloc}:{port}"
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

from hx.crawl import cdp, page

ORIGINS = {"https://app.test"}


def _sent(url: str, *, rtype: str | None = None) -> dict:
    params = {"requestId": url, "request": {"url": url}}
    if rtype is not None:
        params["type"] = rtype
    return {"method": "Network.requestWillBeSent", "params": params}


def _failed(url: str) -> dict:
    return {"method": "Network.loadingFailed",
            "params": {"requestId": url, "errorText": "net::ERR_EMPTY_RESPONSE"}}


def _ok(url: str) -> dict:
    return {"method": "Network.responseReceived",
            "params": {"requestId": url, "response": {"status": 200}}}


# --- harvesting ------------------------------------------------------------

def test_anchors_areas_iframes_and_form_actions_are_all_harvested():
    """All four link-bearing tags in one call, so a fix or refactor to one
    entry of `_LINK_ATTRS` cannot silently drop another.

    MUTATION: remove the `"area": "href"` entry from `_LINK_ATTRS`. This
    test must go red -- `https://app.test/b` would be missing from `out`,
    and an `<area>` inside an image map (the one HTML link shape none of
    the other tests here uses) would go uncrawled.
    """
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
    """`urljoin` needs the FULL page URL, path and all, or `b` off
    `/deep/a` resolves to the wrong place. The origin alone is not enough.

    MUTATION: when no `<base>` tag is present, resolve against the page's
    origin instead of its full URL, e.g. `base = f"{urlsplit(base_url).
    scheme}://{urlsplit(base_url).netloc}/"`. This test must go red --
    `b` would resolve to `https://app.test/b`, discarding the `/deep/`
    the page actually lives under.
    """
    out = page.harvest('<a href="b">x</a>', "https://app.test/deep/a")
    assert out == ["https://app.test/deep/b"]


def test_a_base_tag_is_honoured():
    """A page that sets `<base>` means relative links there, not against its
    own URL -- `v1` here must resolve under `/api/`, not under `/other`.

    MUTATION: drop the `<base>`-tag branch and always resolve against
    `base_url` (`base = base_url`, unconditionally). This test must go red --
    `v1` would resolve to `https://app.test/v1`, ignoring the declared base.
    """
    out = page.harvest('<base href="https://app.test/api/">'
                       '<a href="v1">x</a>', "https://app.test/other")
    assert out == ["https://app.test/api/v1"]


def test_grossly_malformed_markup_does_not_raise():
    """Documents the tolerant behaviour on real garbled markup. NOT a
    mutation-carrying test: CPython's `html.parser` is deliberately
    exception-safe for any `str` input (strict mode was removed in 3.5) --
    fuzzed 20,000 random strings over `<>"'=/!` plus NUL, a lone surrogate,
    and out-of-range numeric character references, and none raised. So this
    input alone cannot exercise `harvest`'s `except Exception` guard; see
    `test_malformed_html_yields_what_it_can_rather_than_raising` below for
    the test that actually forces that path and carries the mutation.
    """
    assert page.harvest('<a href="/a">x<<<>>"', "https://app.test/") == \
        ["https://app.test/a"]


def test_malformed_html_yields_what_it_can_rather_than_raising(monkeypatch):
    """A page under test is attacker-influenced input, and some future
    document could make parsing fail partway through. MUTATION: let that
    exception propagate out of `harvest` (delete its try/except around
    `parser.feed`/`.close`). Must go red -- one broken page would end the
    crawl.

    CPython's `html.parser` will not raise for any crafted HTML string we
    could find (see the sibling test above), so the failure is forced the
    only way available in this Python version: patching the per-tag handler
    `feed` calls into, so the SAME code path `harvest` protects -- an
    exception raised while `HTMLParser.feed` is running -- is exercised for
    real, and the first tag's link (parsed before the raise) is still real
    and still returned.
    """
    real_handle = page._Links.handle_starttag

    def flaky(self, tag, attrs):
        real_handle(self, tag, attrs)
        if tag == "b":
            raise ValueError("simulated parser failure mid-document")

    monkeypatch.setattr(page._Links, "handle_starttag", flaky)
    out = page.harvest('<a href="/a">x</a><b href="/b">y</b>',
                       "https://app.test/")
    assert out == ["https://app.test/a"]


# --- classification: S12 applied to one page -------------------------------

def test_a_page_that_loaded_and_yielded_links_is_rendered():
    """`classify` returns "rendered" from two different places: the `yielded`
    branch (`if yielded: state = "rendered"`) and the fallback at the bottom
    of the same if/elif/else (`else: state = "rendered"`, taken whenever
    nothing was dropped). MEASURED: as first written this test's events had
    no drop, so `dropped` was empty and deleting the `yielded` branch
    entirely (`if False: state = "rendered"`) fell straight through to the
    no-drop fallback and produced the identical verdict -- the test stayed
    green under a mutation that removed the exact thing it claims to check.
    A dropped third party is included below (the same fix
    `test_a_page_with_xhr_but_no_links_still_counts_as_rendered` already
    needed for its own case) so the assertion actually depends on `yielded`:
    without it, `dropped` is non-empty and this page would fall to
    "degraded", not "rendered".

    MUTATION: delete the `if yielded: state = "rendered"` branch (e.g.
    replace its condition with `if False:`), leaving `elif dropped: state =
    "degraded"` as the next thing tested. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://cdn.test/app.js"), _failed("https://cdn.test/app.js")]
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


def test_page_origins_is_seed_origins_so_unseeded_in_scope_failure_reads_dropped():
    """F2, PINNING THE DOCUMENTED LIMITATION rather than hiding it: `page_
    origins` is SEED origins, not scope (see `classify`'s docstring). A
    scope that covers `api.app.test` but was only ever seeded from
    `app.test` has no way, from inside this function, to tell "target-side
    failure on an in-scope-but-unseeded origin" apart from "hx dropped an
    out-of-scope host" -- both look identical here: a failed request whose
    origin is not in `page_origins`. This is CURRENT, INTENDED-DOCUMENTED
    behaviour (the fix is the docstring plus the CLI's pointer at the
    authoritative denial rows, not a second scope matcher -- spec §7
    forbids one) -- this test exists to keep the limitation visible rather
    than let a future change silently narrow or widen it unnoticed.

    MUTATION: swap the two branches of the `dropped_candidates` loop (`if
    origin_of(url) in page_origins: dropped.add(host)` / `else: in_scope_
    failures.append(url)`, i.e. the opposite of today's code). Must go
    red -- `api.app.test` is not in `page_origins` here, so under the swap
    it lands in `in_scope_failures` and `dropped_hosts` comes back empty,
    failing both assertions below.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://api.app.test/data"),
              _failed("https://api.app.test/data")]
    r = page.classify(events, page_origins={"https://app.test"}, harvested=2)
    assert r.dropped_hosts == ("api.app.test",)
    assert r.in_scope_failures == ()


def test_a_document_that_never_loaded_is_failed_not_degraded():
    """The document itself is the request in `dropped_candidates` here (no
    `responseReceived` for it at all) -- the most basic case `document in
    dropped_candidates` exists for, distinct from the `degraded` cases below
    where a THIRD PARTY, not the document, drops.

    MUTATION: drop `or document in dropped_candidates` from the `state =
    "failed"` guard, leaving only `if document is None:`. This test must go
    red -- `document` is not `None` here (it is the sent request's id), so
    the mutated guard does not fire; the loop below then classifies the
    document's own origin as in-scope (it IS in `page_origins`) and files it
    under `in_scope_failures` rather than `dropped`, so `dropped` stays
    empty and `classify` falls all the way to the "no drop" fallback,
    reporting `rendered` for a page that never loaded.
    """
    events = [_sent("https://app.test/"), _failed("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "failed"


def test_a_page_with_xhr_but_no_links_still_counts_as_rendered():
    """The measured reason this crawler is worth building: S9's 65-requests
    result came from a page's own fetch calls, not from its links. A page
    that yielded only XHR has been reached.

    A dropped third party is included so the assertion actually depends on
    `own` rather than passing by the unconditional "no drop -> rendered"
    branch: with no drop present at all, `state` lands on "rendered"
    regardless of `yielded`, and this test would pass even with the named
    mutation applied, catching nothing. (Found by asking, of this test,
    "is there any other path to this same assertion?")

    MUTATION: judge `rendered` on `harvested` alone (drop `or own > 0`).
    Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://app.test/api/items?q=1"),
              _ok("https://app.test/api/items?q=1"),
              _sent("https://cdn.test/app.js"), _failed("https://cdn.test/app.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "rendered"
    assert r.requests == 3


def test_dropped_hosts_are_deduplicated_and_ordered():
    """Two dropped requests to `cdn.test` (`a.js` and `b.js`) must collapse
    to one entry, and the two distinct hosts must come back sorted rather
    than in event-arrival order (`cdn.test` is sent first here, `ads.test`
    second, and the expected tuple is alphabetical).

    DEDUPLICATION is structural, not something a mutation can meaningfully
    target: `dropped` is a `set`, and a set cannot hold `"cdn.test"` twice
    by construction (see DECISIONS.md's "Structure beats behaviour"). The
    runtime-testable half of this test's name is the ORDERING, which is a
    behavioural choice (`sorted(...)`) and can regress.

    MUTATION: sort in reverse, `tuple(sorted(dropped, reverse=True))`. This
    test must go red -- `dropped_hosts` would come back as `("cdn.test",
    "ads.test")`.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/")]
    for u in ("https://cdn.test/a.js", "https://cdn.test/b.js",
              "https://ads.test/t.gif"):
        events += [_sent(u), _failed(u)]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.dropped_hosts == ("ads.test", "cdn.test")


# --- classification: F4 -- the document is identified by `type`, not by
# arrival order -------------------------------------------------------------

def test_a_stale_request_from_the_previous_page_does_not_masquerade_as_the_document():
    """F4, the re-diagnosed favicon race. `visit` reuses one page session for
    every URL in the crawl, and `drain(0.0)` before navigation only clears
    events that have ALREADY arrived -- a trailing event from page N-1 can
    still be in flight and be the FIRST thing this page's event list holds.
    Judging "the document" by arrival order then risks taking that stale,
    successful request as this page's document while the real, typed
    `Document` request failed -- an OVER-CLAIM (`rendered` for a page that
    never loaded), which §12 calls the unsurvivable direction.

    Here the stale request (no `type`, arrives first, succeeds) precedes the
    real document (`type="Document"`, arrives second, fails with no
    response).

    MUTATION: identify the document by first arrival (`first_seen`) instead
    of preferring `typed_document`. Must go red -- first-arrival picks the
    stale successful request as the document, and this page would be
    reported `rendered` (having harvested nothing but a drop of nobody, so
    it would in fact fall through to `rendered` on the "no drop" branch)
    instead of `failed`.
    """
    events = [
        _sent("https://app.test/favicon.ico"),  # stale, from the prior page
        _ok("https://app.test/favicon.ico"),
        _sent("https://app.test/real-page", rtype="Document"),
        _failed("https://app.test/real-page"),
    ]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "failed"


def test_the_document_falls_back_to_first_arrival_when_nothing_carries_type():
    """F4's fallback half: a synthetic or truncated event stream (every
    OTHER test in this file, and a real capped/aborted page) may carry no
    `type` field on any event at all. The fix must not regress those --
    first-arrival is still used when no event is typed.

    MUTATION: require a typed event unconditionally (drop the `if typed_
    document is not None else first_seen` fallback, e.g. leave `document`
    as `None` whenever nothing is typed). Must go red -- with `document`
    forced to `None`, `classify` takes the `document is None` branch and
    reports `failed` for a page that in fact loaded and yielded a link.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=1)
    assert r.state == "rendered"


# --- classification: Ruling 11 -- a drop is a failure with NO response -----

def test_a_document_served_then_truncated_is_not_reported_as_failed():
    """MEASURED 2026-09-02: a request can appear in BOTH `responseReceived`
    and `loadingFailed` -- served, then broken mid-body. The crawler did
    receive and harvest that page.

    MUTATION: classify the document on `failed` rather than on
    `failed - answered`. Must go red -- a page we read would be reported as
    one that never loaded.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _failed("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=3)
    assert r.state == "rendered"


def test_a_third_party_served_then_broken_is_not_named_as_dropped():
    """`dropped_hosts` is the list an operator pastes into `render_allow`.
    A resource that WAS served and then broke was not blocked by anything,
    and naming it would have them widen scope to fix a phantom.

    MUTATION: put every out-of-scope failure in `dropped_hosts` rather than
    only those with no response. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://cdn.test/a.js"), _ok("https://cdn.test/a.js"),
              _failed("https://cdn.test/a.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=2)
    assert r.dropped_hosts == ()


# --- visit: Ruling 18 -- a page's CDP error is contained, a dead browser is
# not -------------------------------------------------------------------

class _FakeConn:
    """A `cdp.Connection` double whose `.call` raises once, on a named
    method, and answers empty-but-valid on everything else. `.drain` never
    raises -- the real `Connection.drain` swallows `CdpTimeout`/`CdpClosed`
    internally (see `cdp.py`), so `visit` never sees those from `drain`.
    """

    def __init__(self, raise_on: str, exc: Exception) -> None:
        self._raise_on = raise_on
        self._exc = exc
        self.calls: list[str] = []

    def call(self, method, params=None, *, session_id=None, timeout=None):
        self.calls.append(method)
        if method == self._raise_on:
            raise self._exc
        if method == "DOM.getDocument":
            return {"root": {"nodeId": 1}}
        if method == "DOM.getOuterHTML":
            return {"outerHTML": "<a href=\"/x\">x</a>"}
        return {}

    def drain(self, timeout):
        return []


def test_a_page_whose_network_enable_raises_cdp_error_is_recorded_failed():
    """Ruling 18: `visit`'s contract is "tell me about this page", and "I
    could not reach it" is an ANSWER, not an exception -- `classify` already
    has a `failed` state for exactly that.

    MUTATION: remove the `except cdp.CdpError` guard around `Network.enable`
    / `Page.enable` inside `visit` (let the error propagate). Must go red --
    without it, `page.visit` itself raises instead of returning, so this
    call raises `cdp.CdpError` instead of returning a `PageResult`.
    """
    conn = _FakeConn(raise_on="Network.enable", exc=cdp.CdpError("boom"))
    result, links = page.visit(conn, "https://app.test/",
                               page_origins=ORIGINS, session_id="s1")
    assert result == page.PageResult(state="failed", requests=0,
                                     dropped_hosts=(), in_scope_failures=(),
                                     capped=False)
    assert links == []


def test_a_page_whose_call_raises_cdp_closed_propagates():
    """Ruling 18: `cdp.CdpClosed` means the browser itself is gone -- every
    later page would fail the identical way, so ending the crawl by letting
    it propagate is correct. This is the more important of the two halves:
    catching `CdpClosed` alongside `CdpError` would turn a dead browser into
    a silent run of N "failed" pages, which is S12's failure wearing a new
    hat.

    MUTATION: catch `cdp.CdpClosed` inside `visit` (e.g. list it after the
    general `except cdp.CdpError`, or drop its `except cdp.CdpClosed: raise`
    clause entirely) so it is treated the same as a contained `CdpError`.
    Must go red -- `visit` would return a failed `PageResult` instead of
    raising.
    """
    conn = _FakeConn(raise_on="Network.enable", exc=cdp.CdpClosed("closed"))
    try:
        page.visit(conn, "https://app.test/", page_origins=ORIGINS,
                  session_id="s1")
    except cdp.CdpClosed:
        pass
    else:
        raise AssertionError("expected cdp.CdpClosed to propagate")


def test_a_page_whose_dom_read_raises_cdp_closed_also_propagates():
    """Ruling 18, the third site. The DOM-read guard's `except cdp.CdpError`
    is a superclass match and would ALSO catch `CdpClosed` unless it has its
    own `except cdp.CdpClosed: raise` ahead of it -- silently reducing a
    dead browser mid-DOM-read to `html = ""` instead of ending the crawl.

    Both tests above raise on `Network.enable`, the FIRST call `visit`
    makes, so neither one ever reaches this guard. This is the test that
    does: `Network.enable`, `Page.enable` and `Page.navigate` must all
    succeed here, or this test would pass because of an earlier guard and
    prove nothing about the site it names.

    MUTATION: at the DOM-read site, remove `except cdp.CdpClosed: raise` so
    the broad `except cdp.CdpError` swallows it. Must go red.
    """
    conn = _FakeConn(raise_on="DOM.getDocument", exc=cdp.CdpClosed("closed"))
    try:
        page.visit(conn, "https://app.test/", page_origins=ORIGINS,
                  session_id="s1", settle=0.0)
    except cdp.CdpClosed:
        pass
    else:
        raise AssertionError("expected cdp.CdpClosed to propagate")
    assert conn.calls[:4] == ["Network.enable", "Page.enable",
                              "Log.enable", "Page.navigate"]


# --- the page's own account of what it could not load ----------------------

def _console_error(text: str, url: str = "") -> dict:
    """A `Log.entryAdded` in the shape measured off real Chromium 150."""
    return {"method": "Log.entryAdded",
            "params": {"entry": {"source": "javascript", "level": "error",
                                 "text": text, "url": url}}}


_MODULE_FAIL = ("Failed to load module script: Expected a JavaScript-or-Wasm "
                'module script but the server responded with a MIME type of '
                '"text/html". Strict MIME type checking is enforced for module '
                "scripts per HTML spec.")


def test_a_page_that_could_not_load_its_own_module_is_degraded():
    """THE JUICE SHOP CASE, and the reason this signal exists.

    MEASURED 2026-09-03 against OWASP Juice Shop through this crawler's own
    Burp: its Express server mishandles the absolute-form request line every
    client sends to a proxy, so four module scripts came back as `text/html`,
    Chrome refused all four, and Angular never bootstrapped. The crawl saw 5
    requests instead of 41 and reported the page `rendered` with no
    truncation -- nothing was dropped and no budget was hit, so every other
    S12 mechanism in this file stayed silent.

    MUTATION: delete the `elif failures:` branch from `classify`. This test
    must go red -- the page would be `rendered`, exactly as it wrongly was.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error(_MODULE_FAIL, "https://app.test/chunk-a.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)

    assert r.state == "degraded"
    assert r.load_errors == ("https://app.test/chunk-a.js",)


def test_a_load_failure_outranks_a_page_that_yielded_something():
    """THE SEPARATING CASE, and the one that makes the branch worth having
    where it sits. A document that fetched links and THEN could not execute
    its main module has not rendered the application; counting those links as
    yield reports it `rendered`.

    MUTATION: move the `elif failures:` branch below the `if yielded:` one.
    Must go red -- and the Juice Shop page would be reported `rendered` again
    the moment it harvested a single link.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://app.test/api/x"), _ok("https://app.test/api/x"),
              _console_error(_MODULE_FAIL, "https://app.test/main.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=7)

    assert r.state == "degraded"


def test_an_ordinary_console_error_is_not_a_load_failure():
    """NARROW ON PURPOSE. A page under test logs errors all day -- a caught
    exception, a deprecation, a failed analytics beacon -- and none of them
    mean the application did not come up. Marking every one `degraded` would
    make the verdict noise.

    MUTATION: treat any `level == "error"` entry as a load failure, dropping
    the `_LOAD_FAILURE_MARKERS` test. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error("Uncaught TypeError: x is not a function"),
              _console_error("[Deprecation] SomeAPI is deprecated")]
    r = page.classify(events, page_origins=ORIGINS, harvested=4)

    assert r.state == "rendered"
    assert r.load_errors == ()


def test_a_warning_is_not_an_error():
    """MUTATION: drop the `level != "error"` guard. Must go red -- a warning
    is the browser telling you about something it went ahead and did.
    """
    warn = {"method": "Log.entryAdded",
            "params": {"entry": {"source": "network", "level": "warning",
                                 "text": "Failed to load resource: slow",
                                 "url": "https://app.test/z.js"}}}
    events = [_sent("https://app.test/"), _ok("https://app.test/"), warn]
    r = page.classify(events, page_origins=ORIGINS, harvested=3)

    assert r.state == "rendered"


def test_load_failures_are_deduplicated():
    """Four chunks failing the same way is four entries; the same chunk
    logged twice is one."""
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error(_MODULE_FAIL, "https://app.test/a.js"),
              _console_error(_MODULE_FAIL, "https://app.test/a.js"),
              _console_error(_MODULE_FAIL, "https://app.test/b.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)

    assert r.load_errors == ("https://app.test/a.js", "https://app.test/b.js")


def test_a_dead_favicon_is_not_a_load_failure():
    """THE MARKER THAT WAS TOO BROAD. `"failed to load resource"` is Chrome's
    generic console message for ANY failed subresource -- a 404 favicon, a
    blocked analytics beacon, a missing font. It was in
    `_LOAD_FAILURE_MARKERS` for one review round, which made the exact
    example the module's own comment gives as NOT a load failure into one.

    Every surviving marker is the browser refusing to EXECUTE or APPLY
    something. A dead image is not refused; it is simply absent.

    MUTATION: re-add `"failed to load resource"` to `_LOAD_FAILURE_MARKERS`.
    This test must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error(
                  "Failed to load resource: the server responded with a "
                  "status of 404 (Not Found)", "https://app.test/favicon.ico")]
    r = page.classify(events, page_origins=ORIGINS, harvested=5)

    assert r.state == "rendered"
    assert r.load_errors == ()
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

SESSION REQUIRED (Ruling 9, measured 2026-09-02): `--remote-debugging-pipe`
gives a BROWSER-level CDP connection. `Page`, `Network` and `DOM` do not
exist on it -- `Page.enable` came back "wasn't found" without a page-target
session attached. `visit` therefore takes a required `session_id` and every
domain call carries it; `Browser.__enter__` (`hx.crawl.browser`) is what
creates that session, once, for the browser's whole lifetime.
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
    load_errors: tuple[str, ...] = ()


#: Console text meaning A RESOURCE THIS PAGE NEEDED DID NOT LOAD.
#:
#: NARROW ON PURPOSE. A page under test logs errors all day -- a failed
#: analytics beacon, a caught exception, a deprecation warning -- and none of
#: those mean the application did not come up. These do: each is the browser
#: refusing to EXECUTE something the document asked for.
#:
#: MEASURED 2026-09-03 against OWASP Juice Shop through this crawler's own
#: Burp. Its Express server mishandles the absolute-form request line every
#: client sends to a proxy (RFC 9112 s3.2.2), so `GET http://host/chunk.js`
#: fell through to the SPA catch-all and returned `index.html` with
#: `Content-Type: text/html`. Chrome enforces strict MIME checking on module
#: scripts, refused all four, and Angular never bootstrapped -- 5 requests
#: instead of 41, and NOT ONE of the parameterised API endpoints a scan
#: exists to probe.
#:
#: The crawl reported that page `rendered`, with no truncation, because
#: nothing was dropped and no budget was hit. Every S12 mechanism in this
#: file stayed silent while the page loaded 0.4% of its application. The
#: browser had said so in plain English the whole time, on a domain nobody
#: had enabled.
#: EVERY ONE IS THE BROWSER REFUSING TO EXECUTE OR APPLY SOMETHING, which is
#: the semantic that separates "the app did not come up" from "a fetch
#: failed". `"failed to load resource"` was in this tuple for one review
#: round and is deliberately NOT: it is Chrome's generic message for ANY
#: failed subresource -- a 404 favicon, a blocked beacon, a missing font --
#: so it made the very example this file's own comment gives as NOT a load
#: failure into one. A marker list that contradicts the paragraph above it is
#: worse than a short list.
_LOAD_FAILURE_MARKERS = (
    "failed to load module script",
    "refused to execute script",
    "refused to apply style",
    "was blocked due to mime type",
)


def load_failures(events: list[dict]) -> tuple[str, ...]:
    """What the PAGE ITSELF reported it could not load, deduplicated.

    Reads `Log.entryAdded` -- the shape measured above is
    `{"entry": {"source", "level", "text", "url"}}`. Only `level == "error"`
    counts: a warning is the browser telling you about something it went
    ahead and did.
    """
    out: list[str] = []
    for e in events:
        if e.get("method") != "Log.entryAdded":
            continue
        entry = e.get("params", {}).get("entry", {})
        if entry.get("level") != "error":
            continue
        text = (entry.get("text") or "").lower()
        if not any(m in text for m in _LOAD_FAILURE_MARKERS):
            continue
        what = entry.get("url") or entry.get("text") or ""
        if what and what not in out:
            out.append(what)
    return tuple(out)


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

    `page_origins` IS SEED ORIGINS, NOT SCOPE -- read that literally, not as
    a simplification. Spec §6 describes this split as made "by re-running the
    scope predicate"; spec §7 forbids a second Python scope matcher (`there
    is no Python scope matcher in this repo today ... a second matcher is a
    second answer`). `hx.crawl.run.crawl` resolves that by building
    `page_origins` from the seed URLs' own origins, which is a narrower
    question than scope and can disagree with it in exactly one direction:
    an engagement whose scope covers a second origin that was NEVER SEEDED
    (say scope allows `api.app.test` but only `app.test` was given as a
    seed) will have a target-side failure on that unseeded-but-in-scope
    origin classified here as an out-of-scope drop, because this function has
    no way to know the origin is in scope -- it only knows it was not seeded.
    That host then lands in `dropped_hosts` (the list `render_allow` is
    pasted from) instead of `in_scope_failures`, and nothing here contradicts
    it. The JVM's own `denial` table is the authoritative record of what was
    actually dropped by policy (§6: "cross-checkable against the denial
    rows, which remain authoritative") -- an operator relying on
    `dropped_hosts` alone should confirm against those rows before treating
    a host as policy-dropped, precisely because this predicate can be wrong
    in that one direction. It is never wrong the other way: an origin this
    predicate calls in-scope really was seeded, so `in_scope_failures` never
    contains a host hx would have dropped.
    """
    urls: dict[str, str] = {}
    failed: set[str] = set()
    answered: set[str] = set()
    first_seen: str | None = None
    typed_document: str | None = None

    for e in events:
        params = e.get("params", {})
        rid = params.get("requestId")
        if e.get("method") == "Network.requestWillBeSent":
            url = params.get("request", {}).get("url", "")
            urls[rid] = url
            if first_seen is None:
                first_seen = rid
            # F4 (whole-branch review, re-diagnosis of a previously-logged
            # favicon race): the page session is REUSED for every URL in the
            # crawl, and `visit`'s `conn.drain(timeout=0.0)` before
            # navigation only clears events that have ALREADY ARRIVED -- a
            # trailing event from the PREVIOUS page can still be in flight
            # and be the first thing this page's event list sees. Judging
            # "the document" by arrival order then risks taking page N-1's
            # request as page N's document, and if that stale request
            # happened to succeed while the real document failed, this page
            # OVER-CLAIMS -- reported `rendered` for a page that never
            # loaded, which is the direction §12 calls unsurvivable.
            # Chromium sets `type` on `Network.requestWillBeSent` and marks
            # exactly the navigation request `"Document"`, so that field
            # identifies the real document regardless of arrival order.
            if typed_document is None and params.get("type") == "Document":
                typed_document = rid
        elif e.get("method") == "Network.loadingFailed":
            failed.add(rid)
        elif e.get("method") == "Network.responseReceived":
            answered.add(rid)

    # PREFER THE TYPED DOCUMENT; FALL BACK TO FIRST ARRIVAL. A synthetic or
    # truncated event stream (as every test in this file constructs, and as
    # a capped/aborted real page may produce) may carry no `type` field at
    # all -- first-arrival is still the best available signal then, exactly
    # as it was before this fix, so a stream with no typed event classifies
    # exactly as it always did.
    document = typed_document if typed_document is not None else first_seen

    # A DROP IS A FAILURE WITH NO RESPONSE (Ruling 11, measured 2026-09-02):
    # a proxy that closes without answering produces `loadingFailed`
    # (net::ERR_EMPTY_RESPONSE) and NO `responseReceived`, while a resource
    # that was served and then broke mid-body produces BOTH. Treating the
    # sets as disjoint would put a served-then-broken third party into
    # `dropped_hosts` -- and that list is what an operator pastes into
    # `render_allow`, so they would widen scope to fix something nothing
    # blocked. It would also report a document that loaded and then had a
    # trailing body error as `failed`, when it was in fact received and
    # harvested.
    dropped_candidates = failed - answered

    dropped: set[str] = set()
    in_scope_failures: list[str] = []
    for rid in dropped_candidates:
        url = urls.get(rid, "")
        if origin_of(url) in page_origins:
            in_scope_failures.append(url)
        else:
            host = urlsplit(url).hostname
            if host:
                dropped.add(host)

    failures = load_failures(events)

    if document is None or document in dropped_candidates:
        state = "failed"
    elif failures:
        # THE PAGE SAID SO ITSELF, and it outranks `yielded` deliberately.
        # A document that fetched three links and then could not execute its
        # own main module has not rendered the application, and counting the
        # three as yield would report it `rendered`. Measured against Juice
        # Shop: 5 requests, no drops, no budget hit, four refused module
        # scripts -- and a confident `rendered` for a page that loaded 0.4%
        # of its app.
        #
        # This can over-fire: a broken analytics script on an otherwise
        # healthy page lands here. That is a FALSE DEGRADATION and it is the
        # direction this file already errs in on purpose -- S12's asymmetry
        # is that under-claiming coverage is survivable and over-claiming is
        # not. `_LOAD_FAILURE_MARKERS` is kept narrow so it stays rare.
        state = "degraded"
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
                      capped=capped, load_errors=failures)


def _failed() -> tuple[PageResult, list[str]]:
    """CONTAINED (Ruling 18): "I could not reach this page" is an ANSWER to
    `visit`'s question, not an exception -- `classify` already has a
    `failed` state for exactly that, so a page `visit` could not reach still
    appears in the crawl's summary instead of vanishing from it.
    """
    return (PageResult(state="failed", requests=0, dropped_hosts=(),
                       in_scope_failures=(), capped=False), [])


def visit(conn: cdp.Connection, url: str, *, page_origins: set[str],
          session_id: str, settle: float = 2.0,
          cap: float = 20.0) -> tuple[PageResult, list[str]]:
    """Navigate, wait for quiet, harvest, judge.

    `session_id` is the page-target session `Browser.__enter__` attached
    (Ruling 9) -- required, not optional, because every call below is a
    `Page`/`Network`/`DOM` domain call and none of those domains exist on
    the browser-level connection `--remote-debugging-pipe` hands us.

    `cap` is what stops one long-polling endpoint, analytics beacon or open
    WebSocket consuming the whole crawl budget. A page that hits it is
    recorded as CAPPED, not as complete -- capped and complete are different
    claims and the summary keeps them apart.

    RULING 18 -- one page's failure must not end the crawl, but a dead
    browser must. `cdp.CdpError` (and its `CdpTimeout` sibling, where not
    already given a more specific meaning below) is CONTAINED here as a
    `failed` `PageResult`: `crawl()` calls `visit` with no guard of its own,
    on purpose, because the guard belongs to the question `visit` answers,
    not to the loop that asks it. `cdp.CdpClosed` means the browser itself
    is gone -- every later page would fail the identical way, so it
    PROPAGATES uncaught. Each `except` below lists `CdpClosed` before the
    general `CdpError` it is a subclass of, so a dead browser is never
    caught by the broader clause and reported as one more failed page.
    """
    try:
        conn.call("Network.enable", session_id=session_id)
        conn.call("Page.enable", session_id=session_id)
        # THE DOMAIN THAT WAS MISSING. `Log` costs nothing and carries the
        # one signal that separates "this page had little to offer" from
        # "this page could not load itself" -- see `_LOAD_FAILURE_MARKERS`.
        conn.call("Log.enable", session_id=session_id)
    except cdp.CdpClosed:
        raise
    except cdp.CdpError:
        return _failed()
    conn.drain(timeout=0.0)

    events: list[dict] = []
    capped = False
    try:
        conn.call("Page.navigate", {"url": url}, session_id=session_id,
                  timeout=cap)
    except cdp.CdpTimeout:
        # A slow navigation is not a failed page -- the settle loop below
        # still collects whatever the page produced before the cap, and
        # `capped` keeps that distinct from a complete visit.
        capped = True
    except cdp.CdpClosed:
        raise
    except cdp.CdpError:
        return _failed()

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
        root = conn.call("DOM.getDocument", {"depth": -1},
                         session_id=session_id, timeout=cap)
        node_id = root.get("root", {}).get("nodeId")
        if node_id:
            html = conn.call("DOM.getOuterHTML", {"nodeId": node_id},
                             session_id=session_id,
                             timeout=cap).get("outerHTML", "")
    except cdp.CdpClosed:
        raise
    except cdp.CdpError:
        # A document we cannot read is a page we harvested nothing from --
        # which `classify` will read as no yield, and that is honest. This
        # is narrower than the whole-page failure above: the events already
        # collected are still real and still classified.
        #
        # DELIBERATELY NOT `_failed()` here, unlike the two guards above --
        # and this is the whole asymmetry, not an inconsistency to tidy up.
        # By this point the network events have already been collected: we
        # know what the page requested. Reporting `failed` would discard
        # that real signal in favour of a weaker claim. Letting `classify`
        # judge on the events alone (in-scope requests seen -> `rendered`;
        # nothing, plus drops -> `degraded`) is strictly more informative,
        # and S12's preference is always the most specific true statement
        # available. The other two sites fail BEFORE any signal exists;
        # this one fails AFTER. That is the whole asymmetry.
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
        self.session_id = "fake-session"
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

    def visit(conn, url, *, page_origins, session_id, settle=2.0, cap=20.0):
        return pages.get(url, default)
    return visit


def _b(pages=100, seconds=100.0, requests=10_000):
    return frontier.Budget(max_pages=pages, max_seconds=seconds,
                           max_requests=requests)


def test_links_from_one_page_become_the_next_pages():
    """A page's harvested links must reach the frontier, or the crawl never
    leaves its seeds.

    MUTATION: drop the `frontier.offer(links)` call. Must go red.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 2, (), (), False),
                            ["https://a.test/x", "https://a.test/y"]),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert s.pages == 3


def test_the_summary_counts_each_state_separately():
    """`rendered`/`degraded`/`failed` are separate counts, not one bucket --
    an operator reading only `pages` cannot tell a clean crawl from one that
    never rendered.

    MUTATION: bucket every page's result into `counts["rendered"]`
    regardless of `result.state`. Must go red.
    """
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
    """THE SEPARATING CASE, without which every crawl claims truncation.

    MUTATION: report `truncated_by=frontier.exhausted or "max_pages"`
    (or any expression that names a budget even when the queue simply
    emptied). Must go red.
    """
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

    MUTATION: drop the context manager around the loop (call
    `browser_factory(...)` directly instead of `with browser_factory(...)`).
    Must go red.
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

SESSION REQUIRED (Ruling 9): a `--remote-debugging-pipe` connection is
BROWSER-level -- `Page`/`Network`/`DOM` do not exist on it. `browser.Browser`
attaches a page target once, for the browser's whole lifetime, and exposes
the resulting `.session_id`; every call to `visit` below passes it on.

ONE PAGE'S FAILURE DOES NOT END THE CRAWL, BUT A DEAD BROWSER DOES (Ruling
18). That guard lives inside `page.visit`, not here: `visit`'s contract is
"tell me about this page", and "I could not reach it" is an answer
(`PageResult(state="failed", ...)`), not an exception -- so this loop calls
`visit` with no guard of its own, on purpose. A `cdp.CdpClosed` means the
browser itself is gone and `visit` lets it propagate; this function does not
catch it either, so it propagates out of `crawl` and the `with` block below
still closes the browser on the way out.
"""
from __future__ import annotations

from typing import Callable, Iterable, NamedTuple

from hx.crawl import browser as browser_mod
from hx.crawl import frontier as frontier_mod
from hx.crawl import page as page_mod


#: The four things this crawler does not do, worded once. `as_tool_result`
#: puts these in the agent-facing dict as `not_done`; `hx crawl`'s CLI
#: (`cli.py`) echoes them verbatim as the closing lines of its printed
#: summary, so the operator who ran the crawl from a terminal reads the
#: identical disclosure the agent gets rather than a fifth phrasing of the
#: same four facts. Spec §9: the crawl summary AND the report's Limits
#: section must both say this in as many words.
NOT_DONE = (
    "forms are not submitted",
    "nothing is clicked",
    "no interaction-gated route is walked",
    "the crawl is unauthenticated",
)


class CrawlSummary(NamedTuple):
    pages: int
    rendered: int
    degraded: int
    failed: int
    capped: int
    requests: int
    dropped_hosts: tuple[str, ...]
    truncated_by: str | None
    #: Pages that reported they could not load a script or stylesheet they
    #: asked for. LAST, WITH A DEFAULT, so every existing positional
    #: construction stays valid -- a field added mid-tuple silently changes
    #: what `CrawlSummary(a, b, c, ...)` means at every call site.
    load_failed: int = 0


def crawl(*, seeds: Iterable[str], proxy_port: int,
          budget: frontier_mod.Budget, burp_home=None,
          visit: Callable = page_mod.visit,
          browser_factory: Callable = browser_mod.Browser) -> CrawlSummary:
    """Visit pages until the frontier is empty or a budget stops us.

    The browser is opened as a context manager and stays one for the whole
    loop, on purpose: a page that raises must still close it. A leaked
    Chromium outlives the crawl and holds a proxy connection the extension
    is accounting for.
    """
    seeds = list(seeds)
    origins = {o for o in (frontier_mod.origin_of(s) for s in seeds) if o}
    frontier = frontier_mod.Frontier(seeds, budget)

    counts = {"rendered": 0, "degraded": 0, "failed": 0}
    capped = 0
    load_failed = 0
    requests = 0
    dropped: set[str] = set()

    with browser_factory(proxy_port=proxy_port, burp_home=burp_home) as br:
        while True:
            url = frontier.next()
            if url is None:
                break
            result, links = visit(br.conn, url, page_origins=origins,
                                  session_id=br.session_id)
            counts[result.state] = counts.get(result.state, 0) + 1
            capped += 1 if result.capped else 0
            # A PAGE THAT COULD NOT LOAD ITS OWN CODE, counted separately
            # from the drop-driven `degraded`. The two mean different things
            # to an operator: one is our scope refusing a third party, the
            # other is the application failing to come up.
            load_failed += 1 if result.load_errors else 0
            requests += result.requests
            # UNIONED across pages (not just the last one), because this
            # list is what an operator pastes into `render_allow` -- a
            # per-page list would make them assemble it by hand.
            dropped.update(result.dropped_hosts)
            # CHARGED AS WE GO. Without this `max_requests` is unenforceable
            # and a crawl can run away inside a page budget -- one page that
            # fires a thousand XHR is a thousand requests against the
            # target, not zero.
            frontier.note_requests(result.requests)
            frontier.offer(links)

    return CrawlSummary(
        pages=frontier.visited,
        rendered=counts["rendered"], degraded=counts["degraded"],
        failed=counts["failed"], capped=capped, requests=requests,
        load_failed=load_failed,
        dropped_hosts=tuple(sorted(dropped)),
        # NAMED, or None. A truncated crawl that presented as complete is
        # S12's failure one level up; a complete crawl that claimed
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
"""`crawl.run` as the agent sees it. The crawl itself is stubbed throughout;
what is under test is the envelope, the refusals and the flags.

Dispatcher-level round trips (does `dispatch()` see the same `needs_egress`
and run-kind guards it gives `scan.run`) live in `tests/test_tools_scan.py`,
next to `scan.run`'s own. This file calls the handler directly, the way the
plan's own Step 1 does, so a guard's ORDER inside the handler is pinned even
against a `ctx` that would crash if touched (`ctx=None`).
"""
from __future__ import annotations

import dataclasses

import pytest

from hx import run as run_mod
from hx.crawl import browser as browser_mod
from hx.crawl import frontier as frontier_mod
from hx.crawl import run as crawl_run
from hx.tools import errors, registry
from hx.tools.impl import scan as scan_impl
from tests.test_probe import FakeBridge


@pytest.fixture
def tool_run_crawl(tool_ctx):
    """A `tool_ctx` with a `crawl` run already open and a fake session on it
    -- the bracket `crawl.run`'s own guard requires, and the `crawler_port`
    every successful call reads."""
    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="crawl",
        safety_profile=tool_ctx.config.safety_profile)
    tool_ctx.session = type(
        "S", (), {"bridge": FakeBridge(), "crawler_port": 41999,
                  "operator_port": 41998})()
    return tool_ctx


def test_crawl_run_is_registered_as_needing_egress():
    """MUTATION: drop `needs_egress=True`. Must go red -- a crawl that does
    not declare egress skips the checks every other sending tool passes.
    """
    spec = registry.lookup("crawl.run")
    assert spec is not None
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

    MUTATION: ignore `identity` instead of raising. Must go red -- `ctx` is
    `None` here on purpose, so a mutated handler that let this call fall
    through to any other guard (the run-kind check, the missing-`target`
    check) hits `ctx.open_runs()` or similar on `None` and raises
    `AttributeError`, which `pytest.raises(ToolUnavailable, ...)` does not
    accept either. There is no other path to the same green result.
    """
    with pytest.raises(errors.ToolUnavailable, match="authenticated"):
        scan_impl.crawl(ctx=None, identity="admin")


def test_identity_is_refused_before_anything_else_is_even_looked_at():
    """The refusal fires even with a well-formed `target` present, which is
    the proof identity is checked FIRST rather than merely checked somewhere
    before the run-kind guard happens to be hit with `ctx=None` too.

    MUTATION: move the identity check after the run-kind guard. Must go red
    -- with a `target` supplied, that guard is the next thing reached, and
    it touches `ctx.open_runs()` on a `None` ctx, raising `AttributeError`
    rather than the `ToolUnavailable` this test requires.
    """
    with pytest.raises(errors.ToolUnavailable, match="authenticated"):
        scan_impl.crawl(ctx=None, identity="admin", target="http://x.test/")


def test_it_refuses_outside_a_crawl_run(tool_ctx):
    """The same mechanical reason `scan.run` refuses outside a `scan` run:
    `crawl.run` has no run of its own to auto-open, so a run this layer did
    not open is a run `run.finish` would never close.

    MUTATION: drop the run-kind guard. Must go red -- `tool_ctx` has no
    session, so a mutated handler would fall through to `ctx.session.
    crawler_port` and raise `AttributeError` on `None`, not the intended
    `ToolRefused`.
    """
    with pytest.raises(errors.ToolRefused) as exc_info:
        scan_impl.crawl(ctx=tool_ctx, target="http://127.0.0.1:8080/")
    assert exc_info.value.reason == "wrong_run_kind"


def test_it_refuses_with_no_target(tool_run_crawl, monkeypatch):
    """MUTATION: drop the `target` check. Must go red -- with the run-kind
    and session guards satisfied by `tool_run_crawl`, a mutated handler
    would reach the (stubbed) crawler with `seeds=[None]` and return
    normally instead of raising.
    """
    def _must_not_run(**kw):
        raise AssertionError("the crawler must not run without a target")

    monkeypatch.setattr(crawl_run, "crawl", _must_not_run)
    with pytest.raises(errors.ToolRefused) as exc_info:
        scan_impl.crawl(ctx=tool_run_crawl)
    assert exc_info.value.reason == "bad_args"


def test_it_drives_the_crawler_through_the_crawler_port_not_the_operator_one(
        tool_run_crawl, monkeypatch):
    """`operator_port` and `crawler_port` are NOT interchangeable (Ruling
    21): the extension tells the operator's own browsing from an agent's
    crawl by WHICH LISTENER a request arrived on, and nothing in the
    traffic itself. Dialling the wrong one silently swaps the two rule
    sets.

    MUTATION: pass `ctx.session.operator_port` instead of `.crawler_port`.
    Must go red -- the two ports are set to different, distinctive values
    on the fixture, so the assertion below tells them apart directly; there
    is no other value in this handler that could produce 41999.
    """
    seen = {}

    def fake_crawl(**kw):
        seen.update(kw)
        return crawl_run.CrawlSummary(
            pages=1, rendered=1, degraded=0, failed=0, capped=0, requests=1,
            dropped_hosts=(), truncated_by=None)

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/")
    assert seen["proxy_port"] == 41999


def test_it_builds_the_budget_from_the_call_and_the_session_config(
        tool_run_crawl, monkeypatch):
    """`max_pages`/`max_seconds` come from the agent's own call; `max_
    requests` comes from `ctx.config` -- the schema carries no such
    parameter (Global Constraints), so the budget must not invent one from
    a hardcoded number or accept one from the agent.

    MUTATION: hardcode `max_requests` in the `Budget` instead of reading
    `ctx.config.max_requests`. Must go red -- the fixture's config is set to
    the distinctive value 777 below, which no plausible hardcoded default
    (2000, 5000, ...) would match.
    """
    tool_run_crawl.config = dataclasses.replace(
        tool_run_crawl.config, max_requests=777)
    seen = {}

    def fake_crawl(**kw):
        seen.update(kw)
        return crawl_run.CrawlSummary(
            pages=0, rendered=0, degraded=0, failed=0, capped=0, requests=0,
            dropped_hosts=(), truncated_by=None)

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/",
                    max_pages=5, max_seconds=30)
    assert seen["budget"] == frontier_mod.Budget(
        max_pages=5, max_seconds=30, max_requests=777)


def test_a_missing_browser_reaches_the_agent_as_unavailable_not_broken(
        tool_run_crawl, monkeypatch):
    """F3: `browser.BrowserUnavailable` is not a `ToolError`, and `dispatch`
    (`hx.tools.dispatch`) renders any non-`ToolError` exception as
    `envelope.failed` -- which tells the agent hx itself is broken. A Burp
    that has never downloaded its own bundled browser is the MOST LIKELY
    failure of `crawl.run`, and it has a clear operator fix (open Burp's own
    browser once so it downloads Chromium); that is an unavailability, not a
    defect, and this module's own docstring is about exactly that
    distinction for the old always-unavailable stub.

    `find_chromium`'s own message is carried through verbatim rather than
    reworded here.

    MUTATION: drop the `except browser_mod.BrowserUnavailable` wrap around
    the `crawl_run_mod.crawl` call inside `scan_impl.crawl` (let it
    propagate bare). Must go red -- `pytest.raises(errors.ToolUnavailable,
    ...)` would instead see the raw `browser_mod.BrowserUnavailable`
    propagate uncaught, which is not a `ToolUnavailable` at all.
    """
    def fake_crawl(**kw):
        raise browser_mod.BrowserUnavailable(
            "no bundled Chromium under /tmp/no-such-home/.BurpSuite/burpbrowser")

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    with pytest.raises(errors.ToolUnavailable,
                       match="no bundled Chromium") as exc_info:
        scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/")
    assert exc_info.value.reason == "not_configured"


def test_it_returns_the_projection_the_agent_reads(
        tool_run_crawl, monkeypatch):
    """The handler must hand back `as_tool_result`'s dict, not the raw
    `CrawlSummary` namedtuple -- an agent reading `.truncated_by` off a
    namedtuple would get it, but `.not_done` does not exist there at all.

    MUTATION: return the bare `CrawlSummary` instead of `as_tool_result
    (summary)`. Must go red -- `not_done` is only ever added by the
    projection.
    """
    def fake_crawl(**kw):
        return crawl_run.CrawlSummary(
            pages=4, rendered=3, degraded=1, failed=0, capped=0, requests=7,
            dropped_hosts=("evil.test",), truncated_by="max_seconds")

    monkeypatch.setattr(crawl_run, "crawl", fake_crawl)
    body = scan_impl.crawl(ctx=tool_run_crawl, target="http://a.test/")
    assert body["truncated_by"] == "max_seconds"
    assert body["dropped_hosts"] == ["evil.test"]
    assert "not_done" in body
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
        "load_failed": summary.load_failed,
        "requests": summary.requests,
        "dropped_hosts": list(summary.dropped_hosts),
        "truncated_by": summary.truncated_by,
        "not_done": list(NOT_DONE),
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
        " status) VALUES('r-c','e-1','crawl','staging',1,'completed')")


def test_an_engagement_that_crawled_discloses_what_the_crawl_did_not_do(
        engagement_conn):
    """MUTATION: delete any one of the four disclosures. Must go red.

    Parametrised over the four rather than asserted as one string, so that
    losing exactly one cannot hide behind the other three. The two phrases
    that read as ordinary English words elsewhere in the report --
    "interaction" (the no-blind-only-checks bullet) and "unauthenticated"
    (the every-probe-was-sent-unauthenticated bullet, which this minimal
    engagement also renders, having proved no session) -- are asserted by
    the LONGER phrase unique to the crawl bullet, so this test cannot pass
    on the strength of an unrelated bullet that happens to share one word.
    """
    _crawled(engagement_conn)
    out = report_mod.render(engagement_conn, engagement_id="e-1",
                            config=_cfg())
    for phrase in ("no forms", "clicks nothing", "interaction to reach",
                   "runs **unauthenticated**"):
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

WHY A REAL CRAWL RATHER THAN `rig.browse`, in the first two tests. `rig.browse`
(the model `test_proxy_capture.py` follows for the operator/crawler split) is
a raw socket that hands bytes straight to a Burp listener -- it never asks
Chromium to decide whether a loopback destination should go through the
configured proxy at all, so it cannot see the ONE bug this task exists to
catch. Only `hx.crawl.run.crawl`, driving `hx.crawl.browser.Browser`'s real
`launch_argv`, puts that decision in the path. The third test is a Policy
question with no browser-specific claim in it, so it uses `rig.browse` like
every other proxy-split test in this suite -- see its own docstring.
"""
from __future__ import annotations

import dataclasses
import socket
import time

import pytest

from hx.crawl import frontier as frontier_mod
from hx.crawl import run as crawl_run_mod
from tests.integration.test_proxy_capture import status_of
from tests.integration.test_send_path import _refusal_from

pytestmark = pytest.mark.integration


def rows(rig, sql: str, args=()) -> list[dict]:
    return [dict(row) for row in rig.eng.db.execute(sql, args).fetchall()]


# A budget generous enough that nothing here truncates on a slow CI box, and
# small enough that a runaway crawl (a page that somehow keeps yielding new
# same-origin links) cannot turn a broken test into a hung one. Every seed
# below is one JSON endpoint with no links, so in the unbroken case the
# frontier empties itself after exactly one page and none of these numbers is
# ever actually reached.
_BUDGET = frontier_mod.Budget(max_pages=3, max_seconds=45, max_requests=50)


def _crawl(rig, *, seeds: list[str]) -> crawl_run_mod.CrawlSummary:
    return crawl_run_mod.crawl(seeds=seeds, proxy_port=rig.crawler_port,
                               budget=_BUDGET)


# ---------------------------------------------------------------------------
# 1. THE TEST THIS WHOLE PLAN TURNS ON.
# ---------------------------------------------------------------------------

def test_a_crawl_produces_exchanges_attributed_to_the_crawler(rig):
    """A real Chromium, launched with the real `browser.launch_argv`, must
    put its traffic through the crawler listener rather than around it.

    MEASURED 2026-09-02: a Chromium launched with `--proxy-server` alone and
    pointed at a loopback target sent ZERO connections to the proxy and
    reached it directly -- Chrome bypasses a configured proxy for loopback by
    default, and every target this suite is permitted to use is loopback.
    `browser.launch_argv` carries a second flag, `--proxy-bypass-list=<-
    loopback>`, that closes exactly this hole.

    MUTATION: delete that flag from `browser.launch_argv`
    (`sed -i '/proxy-bypass-list/d' src/hx/crawl/browser.py`). This test MUST
    go red.

    IT ASSERTS ON THE STORE, NEVER ON THE PAGE. A missing flag still renders
    the page perfectly -- Chromium reaches the target directly and gets the
    same bytes back -- so `summary.rendered == 1` or any assertion about the
    DOM would stay green under the mutation and prove nothing. What can only
    be true if the traffic actually crossed the crawler listener is a row in
    `exchange`, attributed to a `crawl` run, naming this request. Without the
    flag Chromium never dials the proxy at all, so no frame ever reaches
    `BridgeServer`, the sink is never called, and this settle times out --
    which is the failure this test is written to produce.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? Under the mutation above,
    Chromium still renders `/health` (a direct loopback connection succeeds
    identically to a proxied one against this target), so `crawl()` still
    returns a normal-looking `CrawlSummary` with one rendered page. The
    settle below is the only thing that can tell the two situations apart,
    and its own failure message says why -- see `Rig.settle`.
    """
    assert rig.configure() == 1

    seed = f"{rig.target.origin}/health"
    summary = _crawl(rig, seeds=[seed])
    assert summary.pages == 1, (
        f"the crawl visited {summary.pages} page(s) for one seed with no "
        f"links; something about the frontier or the seed URL is wrong "
        f"before this test can say anything about attribution: {summary}")

    rig.settle(
        lambda: rows(rig, "SELECT e.id FROM exchange e"
                          " JOIN run r ON e.run_id = r.id"
                          " WHERE r.kind = 'crawl'"),
        "an exchange row attributed to a crawl run -- meaning Chromium's "
        "request for the seed above actually crossed the crawler proxy "
        "listener rather than going around it")

    crawler_rows = rows(
        rig, "SELECT e.*, r.kind AS run_kind FROM exchange e"
             " JOIN run r ON e.run_id = r.id WHERE r.kind = 'crawl'")
    urls = {row["url"] for row in crawler_rows}
    assert seed in urls, (
        f"a crawl run recorded exchanges, but none of them named the seed "
        f"{seed!r}: {urls}. The crawler listener is carrying SOME traffic; "
        f"this crawl's own request is not it")
    for row in crawler_rows:
        # 'proxy', not 'send' -- this came through ProxyGate, not the bridge
        # send handler. Every row here should agree, since this test drove
        # exactly one browser through exactly one listener.
        assert row["via"] == "proxy", row
        assert row["run_id"] in {r["id"] for r in
                                 rows(rig, "SELECT id FROM run"
                                          " WHERE kind='crawl'")}

    seed_row = next(row for row in crawler_rows if row["url"] == seed)
    assert seed_row["method"] == "GET"
    assert seed_row["outcome"] == "ok"
    assert seed_row["status"] == 200


# ---------------------------------------------------------------------------
# 2. An out-of-scope destination is dropped and the drop is recorded.
# ---------------------------------------------------------------------------

def test_an_out_of_scope_destination_is_dropped_and_recorded(rig):
    """`TargetServer` binds the in-scope target on 127.0.0.1 and the
    out-of-scope one (`rig.offside`) on 127.0.0.2 -- BOTH LOOPBACK, so this
    shares test 1's blind spot: if Chromium bypassed the crawler's proxy for
    loopback, it would reach 127.0.0.2 DIRECTLY, and "no exchange was
    recorded for it" would be true for entirely the wrong reason -- a bypass,
    not a refusal.

    So the assertion is the PRESENCE of a denial row and the offside
    target's log staying flat, never the absence of an exchange on its own.

    MUTATION: remove the `if (source == Source.CRAWLER)` branch from
    `ProxyGate.decide` (`extension/src/hx/proxy/ProxyGate.java`). Must go red.

    THREE CONTROLS, the same shape `test_proxy_capture.py`'s out-of-scope
    test uses and for the same reason -- "the log did not move" is satisfied
    by a great many things that are not enforcement:

      - the offside target is hit DIRECTLY first, so its log is proven able
        to move at all;
      - an in-scope crawl through the SAME listener is proven to deliver,
        so the proxy path is known to be carrying traffic when the refusal
        is measured;
      - the denial ROW is asserted, so "nothing arrived" (a broken crawl, a
        dead listener) is told apart from "hx refused it".

    A SECOND MEASUREMENT LIVES BELOW THE FIRST, and it is not decoration --
    it is the only half of this test the named mutation actually reaches.
    MEASURED: with the CRAWLER branch removed, a request from that listener
    falls to `Policy.decideScopeOnly` -- the OPERATOR's question -- which
    asks about scope and stops. For a destination `scope.include` never
    named at all, `decideScopeOnly` denies it exactly as `decideCrawl` would
    have (both are `checkScope` underneath), so the out-of-scope half above
    is UNCHANGED by this mutation and stays green: confirmed by running it
    against the mutated jar before writing this paragraph. `dangerous.path`
    is what `decideScopeOnly` never asks and `decideCrawl` does, so a
    request that is IN scope and ALSO matches a dangerous pattern is what
    the mutation actually flips from denied to delivered -- proven the same
    way, against the same jar: the out-of-scope half stayed green and the
    dangerous-path half below went red, naming a hit at `/account/logout`.
    """
    assert rig.configure() == 1

    # Control 1: the offside log moves when something reaches it directly.
    direct = socket.create_connection((rig.offside.host, rig.offside.port),
                                      timeout=10)
    try:
        direct.sendall(b"GET /health HTTP/1.1\r\n"
                       b"Host: " + rig.offside.host.encode() + b"\r\n"
                       b"Connection: close\r\n\r\n")
        while direct.recv(65536):
            pass
    finally:
        direct.close()
    assert [(h.method, h.path) for h in rig.offside.hits] == [("GET", "/health")]

    # Control 2: the crawler listener is carrying real browser traffic right
    # now, against the in-scope target.
    control = _crawl(rig, seeds=[f"{rig.target.origin}/health"])
    assert control.pages == 1, control
    rig.settle(
        lambda: rows(rig, "SELECT id FROM exchange WHERE url=?",
                    (f"{rig.target.origin}/health",)),
        "the in-scope control's exchange row -- without this, a refusal "
        "below would be satisfied by a crawler that is not working at all")

    # The measurement. 127.0.0.2 is out of scope -- the engagement's
    # scope.include is the 127.0.0.1 target's origin and nothing else -- and
    # it is LISTENING throughout, so a refusal that merely failed to deliver
    # is separable from one that actively kept the bytes off it.
    before = len(rig.offside.hits)
    seed = f"{rig.offside.origin}/health"
    summary = _crawl(rig, seeds=[seed])
    assert summary.pages == 1, summary

    rig.settle(
        lambda: rows(rig, "SELECT id FROM denial"
                          " WHERE via='proxy' AND kind='scope'"),
        "the out-of-scope crawler denial")
    # Settled, then given the same window again: the denial arriving proves
    # the extension decided, not that the bytes stayed put -- a request that
    # leaked around the gate would reach a loopback server well inside this.
    time.sleep(0.5)

    assert len(rig.offside.hits) == before, (
        "THE VERDICT WAS NOT HONOURED, or Chromium never asked for one: the "
        f"out-of-scope target received "
        f"{[(h.method, h.path) for h in rig.offside.hits[before:]]}. Either "
        "the crawler's `--proxy-bypass-list=<-loopback>` flag is doing "
        "nothing for this destination, or the extension refused this "
        "request and the bytes went out anyway.")

    # THE SECOND MEASUREMENT. In scope, on the SAME listener, matching the
    # dangerous.path denylist -- the rule decideScopeOnly never asks, so this
    # is what actually moves under the mutation named above.
    dangerous_path = "/account/logout"
    dangerous_before = len(rig.target.hits_for(dangerous_path))
    dangerous = _crawl(rig, seeds=[f"{rig.target.origin}{dangerous_path}"])
    assert dangerous.pages == 1, dangerous

    rig.settle(
        lambda: rows(rig, "SELECT id FROM denial"
                          " WHERE via='proxy' AND kind='dangerous'"),
        "the crawler's dangerous-path denial")
    time.sleep(0.5)

    assert len(rig.target.hits_for(dangerous_path)) == dangerous_before, (
        "a dangerous-path destination reached the target through the "
        f"crawler listener: {dangerous_path} took "
        f"{len(rig.target.hits_for(dangerous_path)) - dangerous_before} "
        "more hit(s). This is the half of the test that the CRAWLER-branch "
        "mutation actually moves -- see the docstring.")

    dangerous_denial = rows(
        rig, "SELECT * FROM denial WHERE via='proxy' AND kind='dangerous'")[0]
    assert dangerous_denial["url"] == f"{rig.target.origin}{dangerous_path}"

    denial = rows(rig, "SELECT * FROM denial"
                       " WHERE via='proxy' AND kind='scope'")[0]
    assert denial["method"] == "GET"
    assert denial["url"] == seed
    kinds = {row["id"]: row["kind"] for row in rows(rig, "SELECT id, kind FROM run")}
    assert kinds[denial["run_id"]] == "crawl", (
        "the refused request was attributed to a run of kind "
        f"{kinds.get(denial['run_id'])!r}, not 'crawl' -- the denial is real "
        "but filed under the wrong driver")

    # No exchange for the offside seed either, which is the complementary
    # half of the same fact -- not the primary claim (see the docstring
    # above for why "absent" is not load-bearing on its own here).
    assert rows(rig, "SELECT id FROM exchange WHERE url=?", (seed,)) == []


# ---------------------------------------------------------------------------
# 3. render.allow enforces for the crawler and not for the send path.
# ---------------------------------------------------------------------------

def test_render_allow_changes_the_outcome_for_the_crawler_only(rig):
    """Task 1 end to end. `Policy.decideCrawl` consults `render.allow` after
    `scope.include`/`scope.exclude`; `Policy.decideBeforeGate` -- the path
    `Sender` sends every CHECK's probe through -- calls the same shared
    `beforeGate` with `renderAllow=false` and never looks at it.

    NO BROWSER-SPECIFIC CLAIM LIVES HERE, unlike the two tests above: this is
    a question about which of two Java methods a listener calls, and
    `rig.browse` -- a raw socket handed straight to a Burp listener, the same
    shape `test_proxy_capture.py`'s operator/crawler split test uses -- puts
    that decision in the path just as well as a real Chromium would, at a
    fraction of the cost. `render.allow` is set into the engagement's real
    config and travels to the extension over the real `configure` frame
    either way.

    MUTATION: change `Policy.decideBeforeGate` to call
    `beforeGate(req, auth, true)` instead of `false`
    (`extension/src/hx/policy/Policy.java`). Must go red on the SECOND half
    -- the send-path probe below would then be silently authorised by
    render.allow too, which is exactly the widening s4's send/crawl split
    exists to prevent: a rendering concession is not a licence for a security
    check to issue a probe.
    """
    rig.eng.config = dataclasses.replace(
        rig.eng.config, render_allow=[f"{rig.offside.origin}/*"])
    assert rig.configure() == 1

    # THE CRAWLER HALF: render.allow authorises a destination scope.include
    # never named.
    crawler_resp = rig.browse("GET", "/health", to=rig.offside,
                              port=rig.crawler_port)
    assert status_of(crawler_resp) == 200, (
        "the crawler listener refused a destination named in render.allow: "
        f"{status_of(crawler_resp)}")
    assert rig.offside.hits_for("/health"), (
        "render.allow authorised the request on this side, and the offside "
        "target never saw it -- a client-side 200 is not evidence of "
        "delivery (see DROP_LOOKS_LIKE); read its log instead")
    rig.settle(
        lambda: rows(rig, "SELECT e.id FROM exchange e"
                          " JOIN run r ON e.run_id = r.id"
                          " WHERE r.kind='crawl' AND e.url=?",
                    (f"{rig.offside.origin}/health",)),
        "the crawler's render.allow exchange row")

    # THE SEND-PATH HALF: same render.allow in force, same destination, and
    # this route must refuse it exactly as if render.allow did not exist --
    # `send_unguarded` drops only THIS side's own refusals (see its
    # docstring), so a refusal that comes back proves the JVM decided, not
    # this harness's bookkeeping.
    before = len(rig.offside.hits)
    refusal = _refusal_from(rig.send_unguarded, "GET", "/health",
                            to=rig.offside)
    assert refusal is not None, (
        "a send-path probe to a render.allow-only destination was ALLOWED. "
        "render.allow is a concession to RENDERING (Task 1's own words) and "
        "must never widen what a security CHECK may send -- Sender calls "
        "Policy.decideBeforeGate, which is not supposed to consult it at all")
    assert refusal.error_class == "scope_denied", refusal
    assert len(rig.offside.hits) == before, (
        "the send path was refused on this side and the offside target's "
        f"log moved anyway: {rig.offside.hits[before:]}")
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
