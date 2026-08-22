# Enforcement and the Send Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the issuance gate — the single point inside the JVM through which every request `hx` sends must pass, enforcing scope, method, dangerous paths, rate and budget, with auto-halt, a durable kill switch, and credential redaction.

**Architecture:** One chokepoint (`Sender.issue`) is the only caller of Montoya's HTTP API in the extension, asserted by a structural test. The decision itself is a pure function — `Policy.decide(request, authorisation, gate)` — that takes an immutable `Authorisation` snapshot and returns a verdict, so the whole ruleset is testable without sockets, Burp, or a clock. Everything that owns time (`Limiter`, `Distress`, `HaltSwitch`) takes an injected `Clock`, so windows and thresholds are exercised at exact boundaries rather than approached with sleeps.

**Tech Stack:** Java 21 (`javac --release 21`, zero third-party dependencies, hand-rolled test runner), Python 3.12, the Plan 2 bridge (`src/hx/bridge/`, `extension/src/hx/bridge/`), the Plan 1 store (`src/hx/store/`).

**Spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` — §4 (the enforcement invariant), §6 (bridge protocol), §7 (redaction). All three were amended in `f957960` specifically for this plan; read the amended text, not your memory of the original.

## Global Constraints

- **Zero third-party dependencies in the extension.** No JUnit, no Gradle, no Maven. `javac --release 21`, hand-rolled test runner (`extension/test.sh`). The jar enforces scope against client production systems and its supply chain is deliberately empty.
- **The extension must not gain a compile-time dependency on Montoya** beyond `HxExtension` and the one HTTP call in `Sender`. `Policy`, `Limiter`, `Distress`, `Redactor` and `HaltSwitch` import no `burp.*` types.
- **`http().sendRequest` appears exactly once in `extension/src`.** Asserted by a test. §4: "never add a third egress path."
- **DENY-ALL is the terminal state.** Disconnect, protocol error, malformed frame, halt, close, an unreadable sentinel file, or an unhandled exception all land there. An exception is never an implicit allow.
- **Read `authorisation()` once per decision.** `configEpoch()` and `scopeConfig()` are `@Deprecated`; calling them separately is two reads of one record and a commit lands between them (measured wrong in 393/400 trials, in the unsafe direction). Nothing on the send path may call them.
- **Redaction runs before hashing.** The blob store is content-addressed; hashing raw bytes and redacting afterwards means the raw bytes are already on disk.
- JSON numbers parse to `Long` on the Java side — compare with `Long.valueOf(1L).equals(x)`, never `== 1`.
- All test targets are **loopback only**. Nothing in this project has ever sent a request off the machine and this plan does not change that.
- `tests/test_plan_matches_repo.py` byte-compares this plan's code blocks against the files they name. If your file differs from the block, **sync the block from the file**; never hand-edit the block.
- Python floor is 3.12. Engagement directories are `0o700`, blob and DB files `0o600` — never looser, never widened.

---

## File Structure

**Java — the policy core (no Montoya, no I/O, no clock of its own):**

| File | Responsibility |
|---|---|
| `extension/src/hx/policy/HxRequest.java` | value type: method, url, host, path, query, headers, body. What `Policy` decides about. |
| `extension/src/hx/policy/Decision.java` | verdict: allowed, error class, detail, `retryAfterUs`. |
| `extension/src/hx/policy/Gate.java` | one method, `check(HxRequest) -> Decision`. Lets `Policy` consult a rate/budget gate without importing one. |
| `extension/src/hx/policy/Policy.java` | the five checks in fixed order. Pure. |
| `extension/src/hx/policy/Clock.java` | `nowUs()`. Injected everywhere time matters. |
| `extension/src/hx/policy/Limiter.java` | `implements Gate`: rate limit + per-run budget. |
| `extension/src/hx/policy/Distress.java` | rolling per-host window → auto-halt verdict. |

**Java — the send path (touches Montoya and the filesystem):**

| File | Responsibility |
|---|---|
| `extension/src/hx/send/Redactor.java` | injected-range registry, placeholder substitution, unmanaged-credential detection, response `Set-Cookie` redaction. |
| `extension/src/hx/send/HaltSwitch.java` | the halted flag; `halt` frames and the sentinel-file poller both feed it. |
| `extension/src/hx/send/Sender.java` | **the chokepoint.** decide → issue → time → redact → reply. |
| `extension/src/hx/send/Http.java` | one-method interface over Montoya's HTTP call, so `Sender` is testable with a fake. |

**Java — modified:**

| File | Change |
|---|---|
| `extension/src/hx/bridge/BridgeClient.java` | route `send` frames to a `SendHandler`; expose halt to `HaltSwitch`. |
| `extension/src/hx/HxExtension.java` | construct the pieces and the real Montoya `Http`. |

**Python:**

| File | Responsibility |
|---|---|
| `src/hx/halt.py` | durable operator halt: store row + sentinel file, re-asserted after every hello. |
| `src/hx/store/records.py` | `record_denial()`, `record_exchange()` against Plan 1's schema. |
| `src/hx/bridge/server.py` (modify) | `send()`, the `halted` frame, halt durability. |

**Tests:** one test class per unit, mirroring the paths above, plus `extension/test/hx/ChokepointTest.java` (structural) and `tests/integration/test_send_path.py` (real Burp against a loopback target).

---

## The Interface Contract

Every task binds to these exact signatures. They are repeated in the tasks that
use them, but this is the source of truth — if a task's code disagrees with
this block, this block is right.

```java
// hx.policy
public record HxRequest(String method, String url, String host, String path,
                        String query, Map<String, List<String>> headers, byte[] body) { }

public record Decision(boolean allowed, String errorClass, String detail, long retryAfterUs) {
    public static Decision allow();
    public static Decision deny(String errorClass, String detail);
    public static Decision rateLimited(long retryAfterUs, String detail);
}

public interface Gate { Decision check(HxRequest req); }

public interface Clock { long nowUs(); }

public final class Policy {
    public Policy(Gate gate);
    public Decision decide(HxRequest req, BridgeClient.Authorisation auth);
}

public final class Limiter implements Gate {
    public Limiter(Clock clock, long ratePerSecond, long maxRequests);
    public Decision check(HxRequest req);
    public long issued();
}

public final class Distress {
    public Distress(Clock clock, double max5xxRate, double latencyMultiple,
                    int maxConsecutiveErrors);
    public void record(String host, int status, long ms, boolean connectionError);
    public String stopReason();          // null when healthy
    public String stopHost();
    public String window();              // human-readable, for the `halted` frame
}
```

```java
// hx.send
public final class Redactor {
    public void register(String identityId, int start, int end);
    public String unmanagedCredential(HxRequest req);   // header name, or null
    public byte[] redactRequest(byte[] raw);
    public byte[] redactResponse(byte[] raw);
    public void clear();
}

public final class HaltSwitch {
    public HaltSwitch(Clock clock, Path sentinel, long pollIntervalMs);
    public void start();
    public void stop();
    public void haltedByFrame(String reason);
    public void resumedByFrame();
    public boolean halted();
    public String reason();
}

public interface Http { HttpReply send(HxRequest req, long deadlineUs) throws IOException; }

public record HttpReply(int status, byte[] raw, long ms, boolean connectionError) { }

public final class Sender {
    public Sender(Policy policy, Redactor redactor, HaltSwitch halt,
                  Distress distress, Http http, Clock clock);
    public Map<String, Object> issue(Map<String, Object> header, byte[] body,
                                     BridgeClient.Authorisation auth);
    public void setHaltNotifier(BridgeClient.HaltNotifier n);
}
```

```java
// hx.bridge -- seams added to BridgeClient so the send path can be installed
public interface SendHandler {
    Map<String, Object> handle(Map<String, Object> header, byte[] body, Authorisation auth);
}
public interface HaltSink {                 // a halt/resume frame reaching the send path
    void halted(String reason);
    void resumed();
}
public interface HaltNotifier {             // the unsolicited `halted` frame, burp -> py
    void halted(String reason, String host, String window);
}
// on BridgeClient:
public void setSendHandler(SendHandler h);
public void setHaltSink(HaltSink s);
public HaltNotifier haltNotifier();         // frames {v, t:"halted", reason, host, window}
```

```python
# contract sketch for src/hx/halt.py -- NOT the file, and deliberately
# not a path marker: tests/test_plan_matches_repo.py byte-compares any block whose
# first line names a .py file, and this one is a signature list, not an implementation.
class OperatorHalt:
    def __init__(self, engagement_dir: Path, db: sqlite3.Connection) -> None: ...
    def halt(self, reason: str) -> None: ...
    def resume(self) -> None: ...
    @property
    def halted(self) -> bool: ...
    @property
    def reason(self) -> str | None: ...
    @property
    def sentinel_path(self) -> Path: ...

# src/hx/store/records.py
def record_denial(conn, *, run_id: str, kind: str, method: str, url: str,
                  detail: str, at_us: int) -> str: ...
def record_exchange(conn, *, run_id: str, method: str, url: str, status: int,
                    req_blob: str, resp_blob: str, ms: int, at_us: int) -> str: ...
def abort_run(conn, *, run_id: str, stop_reason: str, at_us: int) -> bool: ...
DENIAL_KIND: dict[str, str]          # error class -> denial.kind, defined ONCE here

# src/hx/bridge/server.py  (additions)
class BridgeServer:
    BODY_KEY = "@body"               # where a frame's raw body rides in the reply dict
    def send(self, req: dict, body: bytes = b"", timeout: float = 30.0) -> dict: ...
    # raises BridgeError carrying .error_class and .retry_after_us
    on_halted: Callable[[dict], None] | None      # the unsolicited `halted` frame
```

**Error classes** (§6, as amended): `scope_denied`, `method_denied`,
`dangerous_denied`, `rate_limited`, `budget_exhausted`, `not_configured`,
`unmanaged_credential`, `transport_error`, `timeout`, `bridge_lost`.

Two more are emitted by the send path for malformed input rather than by policy:
`bad_frame` (a `send` with no `deadline_us`, or a body that will not parse) and
`engagement_mismatch`. They are refusals like any other — §4 says denials are never
silent — so they must appear in `SEND_PATH_ERROR_CLASSES` and in `records.UNRECORDABLE`
with a reason, even though they produce no `denial` row.

**Decision order**, and a test pins it: `not_configured` → `halted` →
`scope_denied` → `method_denied` → `dangerous_denied` → `rate_limited` →
`budget_exhausted`. When a request violates several rules, the earliest wins.

---
