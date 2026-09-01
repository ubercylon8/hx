# Tool Layer Plan B — Egress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the six egress tools (`http.send`, `http.grep`, `http.body`, `http.replay_as`, `scan.run`, `crawl.run`), the session bracket that gives them a live Burp, and the MCP adapter that hosts them — completing the 17-tool v1 surface.

**Architecture:** Plan A built the definition (registry, envelope, dispatcher, journal) and left two seams: `ToolContext.session`, which is `None` throughout, and `ToolSpec.needs_egress`, which the dispatcher already refuses against. Plan B fills the first and exercises the second. Underneath the tools, a new `hx.issue` module becomes the one writer of `via='send'` exchange rows — the record that `http.grep`, `http.body` and `evidence.attach` all read and that nothing in this build has ever produced. Above them, `hx mcp` is a hand-rolled newline-delimited JSON-RPC 2.0 server over stdio, one long-lived process that can hold a Burp open across calls in a way `hx tool` structurally cannot.

**Tech Stack:** Python 3.12, click, PyYAML (no new dependencies — see Global Constraints). SQLite via `hx.store`. Burp Suite Community 2026.7.3 via the existing Java extension, unmodified by this plan.

**Spec:** `docs/superpowers/specs/2026-08-31-tool-layer-design.md` (§7 the tool catalogue, §8 session lifecycle, §9 adapters, §10 the two-plan split). Master spec: `docs/superpowers/specs/2026-08-21-hx-design.md` (§4 the enforcement invariant, §5 the data model, §8 the tool layer's six principles and the digest, §12 reporting).

**Base:** master at `1f59054` (PR #12 merged). Baseline: 1830 passed / 1 skipped / 44 deselected; 44 integration passed; Java 13 suites ALL PASS.

---

## Global Constraints

Every task's requirements implicitly include this section.

**Security — these are the invariants the product exists to hold.**

- **§4, unchanged and untouched by this plan:** every byte that leaves this machine crosses one of two points inside the JVM. Nothing in Plan B adds a third. `hx.issue` sends through `BridgeServer.send` and by no other route.
- **DENY-ALL is terminal.** An unconfigured or halted extension refuses everything; nothing on the Python side may talk its way past that.
- **A credential value never appears in `config.yaml`**, in a tool's arguments, in a return value, in `agent_action`, in a log line, or in a rendered report. Identity is passed **by name**; resolution happens below the tool layer (Principle 5).
- **Redaction runs before hashing.** The extension redacts the response before the bytes cross the bridge, because the blob store is content-addressed. Nothing here may hash a raw response.
- **All test targets are loopback only.** The `TargetServer` fixture refuses any host outside `127.0.0.0/8`, and that refusal is load-bearing — do not weaken it, and do not add a test that would need it weakened.
- **Never run Burp against the real `$HOME`.** The integration fixture builds a private Burp home per run.
- **Engagement directories are `0o700`; blob and DB files are `0o600`.** Never looser, never widened.
- **The agent may never write finding status `confirmed` or `reported`** (enforced by a DB trigger).
- **`hx` never bundles or redistributes Burp.**

**Dependencies.**

- **No new Python dependencies.** The MCP adapter is hand-rolled. This was §13's open question and it is now settled: MCP stdio is newline-delimited JSON-RPC 2.0 and a server needs `initialize`, `tools/list` and `tools/call`. This project runs on two Python dependencies and a Java extension with none, and a security tool's dependency footprint is part of its argument. Revisit only if MCP's transport requirements grow.
- **No Java changes.** Plan B is Python-only. If a task appears to need one, that is a finding to raise, not a change to make.

**The plan-drift gate (`tests/test_plan_matches_repo.py`).**

- Code blocks are matched by a first-line `# path` marker and byte-compared against the file. **A block for a file that does not exist yet is skipped**; a block for a file that already exists is compared immediately.
- **Therefore: a block describing a modification to a file that already exists must NOT carry a `# path` marker** until the modification has shipped. Markers for such blocks go on in the task's final commit, or at the end of the plan. A block describing a file this plan *creates* may carry its marker from the start.
- `EXPECTED_BLOCKS` in `tests/test_plan_matches_repo.py` must be updated **in the same commit** that adds or removes a marked block, and the commit message must name the block.
- **This plan must not be marked `<!-- plan-drift: pending -->`.** `2026-08-27-checks-and-reporting.md` already carries that marker and at most one plan may.

**Style, matching what the repo already does.**

- Comments carry the reasoning. Where a decision could plausibly have gone the other way, the code says why it did not — and says what was *measured*, not what was assumed.
- Line length ≤ 88. `ruff check` must stay clean (`select = ["E4", "E7", "E9", "F"]`).
- Tests are `pytest`, run with `.venv/bin/pytest`. Integration tests carry `@pytest.mark.integration` and are deselected by default.
- **A red suite is never DONE, and never commit red.** If the suite is red and you cannot make it green within the task, report BLOCKED with the failing output.
- **A test that asserts nothing is a defect**, not a placeholder. Four vacuous tests were found in Plan A's reviews; do not add a fifth.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `src/hx/http_text.py` | Reading an HTTP message off raw bytes: head/body split, header lookup. Promoted out of `checks/passive/_http.py` so a core module need not import from `checks/`. |
| `src/hx/issue.py` | The one route from the tool layer to the wire, and the **only** writer of `via='send'` exchange rows. |
| `src/hx/delta.py` | `delta_vs_baseline` — what changed between a response and its surface's exemplar. Pure. |
| `src/hx/tools/live.py` | The session bracket: which run kinds imply egress, launching, holding, tearing down, and registering identities on the live bridge. |
| `src/hx/tools/impl/http.py` | `http.send`, `http.grep`, `http.body`, `http.replay_as`. |
| `src/hx/tools/impl/scan.py` | `scan.run` and `crawl.run`. |
| `src/hx/tools/adapters/mcp.py` | `hx mcp` — newline-delimited JSON-RPC 2.0 over stdio. |

**Modified:**

| File | Change |
|---|---|
| `src/hx/checks/passive/_http.py` | Re-export the four parsing helpers from `hx.http_text`. No call site changes. |
| `src/hx/store/records.py` | `record_exchange` gains `identity`, `identity_generation`, `identity_state`. |
| `src/hx/tools/dispatch.py` | `ToolContext` gains `stack` and `_registered`. |
| `src/hx/tools/impl/run.py` | `run.start` opens the session bracket; `run.finish` closes it. |
| `src/hx/tools/impl/__init__.py` | Import the two new handler modules. |
| `src/hx/tools/adapters/cli.py` | `build_context` takes an optional `stack`. |
| `src/hx/cli.py` | The `hx mcp` command. |
| `tests/conftest.py` | A `FakeBridge` fixture the egress tests share. |

---

## The rulings this plan makes

Recorded here because each could plausibly have gone the other way, and an implementer who disagrees should raise it rather than quietly re-decide it.

1. **The send path records exchanges from Python, not from Java.** The extension's `result` frame already carries the redacted response bytes, the status, the timing and the outcome; the request bytes are the ones this side composed. That is everything an `exchange` row needs. A Java change would give two things Python cannot get — the post-injection request bytes and the resolved IP — and cost a second write path into a table whose proxy writer took a plan to get right. **What this costs if wrong:** `exchange.req_blob` on a `via='send'` row is the request hx *asked* to be sent, not the bytes that left the JVM; they differ by the identity header the extension injects. That difference is documented at the writer, and it is the *safe* direction — the credential is injected inside the JVM and so cannot be in the bytes this side hashes.

2. **`resolved_ip` and `scope_version_id` stay NULL on send-path rows.** The proxy writer leaves both NULL too. Filling one and not the other would make `via` the thing that decides how much a row knows.

3. **A send's `identity_state` is `assumed`, never `proven`.** A canary bracket proves a *run*; a single send has none. `assumed` is exactly the word for it, the CHECK constraint already admits it, and `scan.run` keeps its own proven/assumed logic untouched.

4. **Egress kinds are `manual` and `scan`.** `browse` is the operator's own browser through `hx capture start`, which owns its own Burp — §8 says a browse run never needed the tool layer to launch anything. `crawl.run` is permanently unavailable, so a `crawl` run has nothing to send.

5. **The tool layer holds at most one session, owned by the run that launched it.** A second egress run opens normally and is told, in its own result, that the session is held and by which run. **What this costs if wrong:** an agent that wants to scan mid-manual must `run.finish` first. That is one extra call and it makes every scan run bracketed.

6. **A session that will not start does not stop the run from opening.** `run.start` returns the run *and* a `session` object saying `live: false` with a reason. Refusing outright would leave no `run` row and no `agent_action` row — no trace of the failure. The agent learns immediately, non-egress work still proceeds, and every egress tool then answers `unavailable / no_session` on its own. This is §12's rule applied to the agent's knowledge of its own instrument, the same argument that registers `crawl.run`.

7. **`http.grep` matches literal bytes, not regular expressions.** Python's `re` has no timeout, the pattern is agent-authored, and a catastrophic backtrack would hang the one long-lived process that holds the Burp. A literal match cannot hang, needs no scanned-byte games, and serves Principle 2's actual purpose: you search for the payload token you just sent. `http.body(range)` remains the escape hatch. **What this costs if wrong:** finding a *class* of thing (every `Set-Cookie` without `Secure`) needs several literal greps or a passive check. Record this in `docs/DECISIONS.md` as known debt with the reason, so a later regex design starts from why this one said no.

8. **`http.replay_as` takes `include_anonymous` as its own boolean**, not a magic identity name. The unauthenticated comparison is the single most valuable row in an authz table and deserves a named flag rather than a string an operator could collide with.

9. **`scan.run` refuses unless the current run is a `scan` run.** `hx.scan.run` calls `run.current_run(kind="scan")`, which *auto-opens* a run when none is open — and a run the tool layer did not open is a run nothing will close, which would make the next `run.start(kind='scan')` refuse with `run_open` forever. Requiring the bracket keeps `current_run` in its finding role and never in its opening one.

---

## Task 1: The send-path exchange writer

Nothing in this build stores a `via='send'` exchange row. `src/hx/store/schema.sql:79` says so in as many words, and the Java confirms it: `via` is written in exactly two places, both in `proxy/Capture.java`. Every tool in Plan B rests on that row — §8's digest opens with `exchange_id`, and `http.grep` and `http.body` are defined as reads keyed on one. This task writes it.

**Files:**
- Create: `src/hx/http_text.py`
- Modify: `src/hx/checks/passive/_http.py` (delete four definitions, import them instead)
- Modify: `src/hx/store/records.py` (`record_exchange`, the identity triple)
- Create: `src/hx/issue.py`
- Test: `tests/test_http_text.py`, `tests/test_issue.py`
- Modify: `tests/conftest.py` (a shared `FakeBridge`)

**Interfaces:**
- Consumes: `hx.bridge.server.BridgeServer.send(req, body, timeout=…) -> dict` raising `BridgeError`; `hx.store.blobs.BlobStore.put(bytes) -> (digest, length)`; `hx.capture.Capture(conn, blobs, engagement_id, config).upsert_surface(norm, exchange_id=…, run_id=…, via=…)`; `hx.surface.normalise(method, url, preserve=…, slug_threshold=…)`.
- Produces, and later tasks depend on these exact names:
  - `hx.http_text.split_head_body(raw) -> (head, body)`, `header_lines(head) -> list[bytes]`, `header_names(head) -> list[str]`, `header_values(head, name) -> list[str]`
  - `hx.issue.Issued` — frozen dataclass with `exchange_id, status, bytes, ms, outcome, content_type, body_sha256, first_line, response`
  - `hx.issue.IssueRefused(Exception)` with `.reason` and `.detail`
  - `hx.issue.request_bytes(method, path, host, headers, body=b"") -> bytes`
  - `hx.issue.issue(bridge, conn, blobs, config, *, engagement_id, run_id, scheme, host, port, method, path, headers=(), body=b"", identity=None, timeout=30.0) -> Issued`

---

- [ ] **Step 1: Write the failing test for the promoted parsers**

```python
# tests/test_http_text.py
"""The parsers, at their new address.

These four moved out of `hx.checks.passive._http` so `hx.issue` could read a
content type without a core module importing from `hx.checks`. The tests that
prove their BEHAVIOUR still live in the passive-check suites, which is right --
they were earned there. What is proved here is the move itself: one
implementation, reachable from both names, with the bare-LF and repeated-header
rules intact at the new address.
"""
from hx import http_text
from hx.checks.passive import _http


def test_the_old_private_names_are_the_new_public_ones():
    """A re-export, not a copy. `is` rather than `==`: two functions that
    agree today and were edited separately tomorrow are exactly the drift
    this move exists to prevent."""
    assert _http._split_head_body is http_text.split_head_body
    assert _http._header_lines is http_text.header_lines
    assert _http.header_names is http_text.header_names
    assert _http.header_values is http_text.header_values


def test_a_bare_lf_response_still_splits():
    """RFC 9112 s2.2. The version that only knew CRLF handed every
    body-searching check an EMPTY body and answered `clean` because it failed
    to read."""
    head, body = http_text.split_head_body(b"HTTP/1.1 200 OK\nX: 1\n\nhello")
    assert head == b"HTTP/1.1 200 OK\nX: 1"
    assert body == b"hello"


def test_the_first_terminator_wins():
    """A body containing CRLFCRLF must not pull the boundary back past a head
    that ended with a bare LF."""
    raw = b"HTTP/1.1 200 OK\n\nbody with \r\n\r\n inside"
    head, body = http_text.split_head_body(raw)
    assert head == b"HTTP/1.1 200 OK"
    assert body == b"body with \r\n\r\n inside"


def test_repeated_headers_all_come_back():
    """`Set-Cookie` legitimately repeats; a parser returning the first would
    check one cookie of five and report the surface clean."""
    head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2"
    assert http_text.header_values(head, "set-cookie") == ["a=1", "b=2"]
```

- [ ] **Step 2: Run it to watch it fail**

Run: `.venv/bin/pytest tests/test_http_text.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.http_text'`

- [ ] **Step 3: Create `src/hx/http_text.py`**

Move the four functions **verbatim** out of `src/hx/checks/passive/_http.py`, renaming `_split_head_body` to `split_head_body` and `_header_lines` to `header_lines`. Keep every docstring byte for byte — they carry the reasoning that earned each rule.

```python
# src/hx/http_text.py
"""Reading an HTTP message off the wire, for anything holding raw bytes.

These four were `hx.checks.passive._http`'s until Plan B needed them one layer
down. `hx.issue` writes the exchange row a send produces, and has to read a
status line and a content type out of the same kind of bytes a passive check
reads.

THE ALTERNATIVES WERE BOTH WORSE. A core module importing from
`hx.checks.passive` inverts the dependency -- `checks` is built on the store
and the wire, not the other way round -- and a second copy of
`split_head_body` is the thing this repo keeps naming: a copy is what drifts.
The rules below were each earned by a specific failure (a bare-LF response
read as an empty body; a `Set-Cookie` parser that checked one cookie of five),
and a second copy is a second place for the next such failure to be fixed
only once.

`_http` re-exports all four under the names it already used, so no call site
in `hx/checks/` changes and the behavioural tests that earned these rules stay
where they are.
"""
from __future__ import annotations


def split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    """Head and body, accepting either line terminator.

    RFC 9112 s2.2 requires a recipient to accept a bare LF as a line
    terminator. `partition(b"\\r\\n\\r\\n")` on a bare-LF response matches
    nothing and returns `(raw, b"", b"")`, which hands every body-searching
    check an EMPTY body and every header-reading check the whole response as
    one unsplit head. The tool then answers `clean` because it failed to
    read, which is the one direction an assessment must never be wrong in.

    Whichever terminator appears FIRST is the real one, so a body that
    happens to contain `\\r\\n\\r\\n` cannot pull the boundary backwards past
    a head that actually ended with a bare `\\n\\n`.
    """
    crlf = raw.find(b"\r\n\r\n")
    lf = raw.find(b"\n\n")
    if crlf == -1 and lf == -1:
        return raw, b""
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return raw[:crlf], raw[crlf + 4:]
    return raw[:lf], raw[lf + 2:]


def header_lines(head: bytes) -> list[bytes]:
    """Header lines, minus the status line, for either terminator.

    Splits on LF and strips at most one trailing CR per line, rather than
    also splitting on a bare CR: a lone CR inside a header value is data, and
    splitting on it would invent a header boundary the wire did not carry.
    """
    return [line[:-1] if line.endswith(b"\r") else line
            for line in head.split(b"\n")[1:]]


def header_names(head: bytes) -> list[str]:
    return [line.partition(b":")[0].decode("latin-1").strip()
            for line in header_lines(head) if b":" in line]


def header_values(head: bytes, name: str) -> list[str]:
    """Every value for one header name, ASCII-case-insensitively.

    A list, not a value: `Set-Cookie` legitimately repeats, and a parser that
    returned the first would check one cookie of five and report the surface
    clean.
    """
    want = name.lower()
    out = []
    for line in header_lines(head):
        key, sep, value = line.partition(b":")
        if sep and key.decode("latin-1").strip().lower() == want:
            out.append(value.decode("latin-1").strip())
    return out
```

**Note:** copy `header_values`'s loop body from the current `_http.py` rather than trusting the reconstruction above — the file is the authority.

- [ ] **Step 4: Make `_http.py` re-export**

Delete the four definitions from `src/hx/checks/passive/_http.py` and add the import near the top, after the existing imports. **This block carries no marker** — `_http.py` already exists, so a marked block would be compared against the pre-change file and fail.

```python
from ...http_text import (  # noqa: F401
    # PROMOTED FOR PLAN B. `hx.issue` needs the same parsing one layer down,
    # and a core module importing from `hx.checks.passive` would invert the
    # dependency. Re-exported under the names this module already used, so
    # nothing in `hx/checks/` changes and the behavioural tests that earned
    # these rules stay where they are. `header_names` and `header_values` are
    # re-exports for this module's importers rather than for its own body,
    # hence the noqa.
    header_lines as _header_lines,
    header_names,
    header_values,
    split_head_body as _split_head_body,
)
```

**The comment goes inside the parentheses on purpose.** A fenced Python block whose *first* line is a `# ` comment is read by `tests/test_plan_matches_repo.py` as a path marker, and this one names no file — so a comment above the import turns that suite red. Same trap for every other block in this plan that opens with prose.

- [ ] **Step 5: Run the parser tests and the whole passive suite**

Run: `.venv/bin/pytest tests/test_http_text.py -q && .venv/bin/pytest -q -k "passive or checks" `
Expected: PASS, and no change in the passive-check counts. If any passive test fails, the move dropped or altered something — fix the move, do not adjust the test.

- [ ] **Step 6: Commit the move on its own**

```bash
git add src/hx/http_text.py src/hx/checks/passive/_http.py tests/test_http_text.py
git commit -m "refactor: promote the HTTP parsers out of checks/passive

hx.issue needs split_head_body and header_values one layer down, and a core
module importing from hx.checks.passive would invert the dependency. Moved
verbatim; _http re-exports all four under its old names, so no call site in
hx/checks/ changes and the behavioural tests stay where they were earned."
```

- [ ] **Step 7: Write the failing test for the widened `record_exchange`**

Append to `tests/test_records.py` (or the file that already covers `record_exchange` — find it with `.venv/bin/pytest --collect-only -q | command grep record_exchange`, and follow that file's existing fixtures).

```python
def test_record_exchange_carries_the_identity_triple(conn, run_row):
    """The three columns have existed since SCHEMA_VERSION 9 and nothing has
    ever filled them. A send issued under a named identity is the first
    traffic in this build that HAS an identity to record."""
    row_id = records.record_exchange(
        conn, run_id=run_row, method="GET", url="http://127.0.0.1:8080/a",
        status=200, req_blob=None, resp_blob=None, ms=5, at_us=1,
        identity="staff", identity_generation=3, identity_state="assumed")
    got = conn.execute(
        "SELECT identity, identity_generation, identity_state"
        " FROM exchange WHERE id=?", (row_id,)).fetchone()
    assert tuple(got) == ("staff", 3, "assumed")


def test_record_exchange_still_defaults_the_triple_to_null(conn, run_row):
    """Every existing call site passes none of the three, and an anonymous
    send has none to pass. NULL is the fact, not a gap."""
    row_id = records.record_exchange(
        conn, run_id=run_row, method="GET", url="http://127.0.0.1:8080/a",
        status=200, req_blob=None, resp_blob=None, ms=5, at_us=1)
    got = conn.execute(
        "SELECT identity, identity_generation, identity_state"
        " FROM exchange WHERE id=?", (row_id,)).fetchone()
    assert tuple(got) == (None, None, None)
```

- [ ] **Step 8: Run it to watch it fail**

Run: `.venv/bin/pytest tests/test_records.py -q -k identity_triple`
Expected: FAIL — `TypeError: record_exchange() got an unexpected keyword argument 'identity'`

- [ ] **Step 9: Widen `record_exchange`**

Three keyword arguments with `None` defaults, three columns on the INSERT. Add this paragraph to the docstring, and extend the signature and the INSERT. **No marker on these blocks** — `records.py` exists.

Signature:

```python
def record_exchange(conn: sqlite3.Connection, *, run_id: str | None,
                    method: str, url: str, status: int | None,
                    req_blob: str | None, resp_blob: str | None, ms: int,
                    at_us: int, outcome: str = "ok", via: str = "send",
                    resp_len: int | None = None,
                    surface_id: str | None = None,
                    scope_version_id: str | None = None,
                    seq: int | None = None,
                    identity: str | None = None,
                    identity_generation: int | None = None,
                    identity_state: str | None = None) -> str:
```

Docstring paragraph, added at the end of the existing docstring:

```
    THE IDENTITY TRIPLE IS NULL FOR EVERYTHING THIS BUILD HAD UNTIL PLAN B.
    The three columns arrived with SCHEMA_VERSION 9 and nothing filled them:
    proxy traffic carries the operator's own browser session, which the
    identity design puts out of scope, and no send path recorded a row at
    all. `hx.issue` is the first caller with an answer, and it writes
    `identity_state='assumed'` -- never `proven`. A canary bracket proves a
    RUN (spec section 6); one send has no bracket, so `assumed` is the whole
    of what is known and `proven` here would be a claim no canary backs.
    Defaulted to None so every existing call site is byte-for-byte unchanged.
```

INSERT, replacing the existing one:

```python
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " recv_us, method, url, status, req_blob, resp_blob, resp_len,"
        " body_shed, scope_version_id, seq, identity, identity_generation,"
        " identity_state)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (row_id, run_id, surface_id, via, outcome, at_us,
         at_us + ms * 1000, method, url, status, req_blob, resp_blob,
         resp_len,
         # S6: solicited exchanges are NEVER shed -- they are about to become
         # evidence. Only unsolicited proxy observations may set this.
         0,
         scope_version_id, seq, identity, identity_generation,
         identity_state),
    )
```

- [ ] **Step 10: Run the records suite**

Run: `.venv/bin/pytest tests/test_records.py -q`
Expected: PASS, with two more tests than before.

- [ ] **Step 11: Extend the `FakeBridge` that already exists**

**DO NOT WRITE A NEW ONE.** `tests/test_probe.py` already holds a `FakeBridge`
that reproduces the real send shape -- a dict back on success, a raised
`BridgeError` on every refusal, never a dict with a class key -- and
`tests/test_scan_probes.py` already imports it with
`from tests.test_probe import FakeBridge`. A second double is a second idea of
what `BridgeServer.send` does, and the two would drift on the first protocol
change. Every test file in this plan imports that one.

It needs two additions, both additive:

```python
    def register_identity(self, resolved, *, origins) -> None:
        """Recorded, never asserted-on by this class. `hx.tools.live` must
        register an identity exactly once per generation -- the real
        extension refuses a repeat with `stale_generation` -- so a test needs
        to be able to COUNT registrations, and the credential must be
        countable without being printed."""
        self.identities.append((resolved.id, resolved.generation, origins))

    def replies(self, seq) -> None:
        """Queue successive answers for successive sends.

        `reply()` sets ONE answer that every send gets, which is right for a
        probe loop asking the same question. `http.replay_as` sends N times
        inside ONE tool call and the whole point is that the answers DIFFER --
        a single reply would make an authz test pass against a bridge that
        cannot tell two identities apart.
        """
        self._queue = list(seq)
```

with `self.identities: list = []` and `self._queue: list | None = None` added
to `__init__`, and `send` consuming `self._queue` before falling back to
`self._header`. Keep `reply()` and `refuse()` working exactly as they do --
`test_probe.py` and `test_scan_probes.py` depend on them, and this plan's
blocks are byte-compared against the file.

Add one helper beside it for the result frames this plan needs:

```python
def sent_result(body=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi",
                *, status=200, ms=7, outcome="ok", epoch=1):
    """One `result` frame, shaped as `Sender.decideAndIssue` builds it."""
    return ({"status": status, "bytes": len(body), "ms": ms,
             "outcome": outcome, "config_epoch": epoch}, body)
```

**Every test in this plan therefore opens with**
`from tests.test_probe import FakeBridge, sent_result` -- absolute, because
`tests/` is a package and that is the import shape the repo already uses.

- [ ] **Step 11b: A run must be open before anything sends**

`tool_ctx.run_id` resolves from `hx.run.open_runs` and is **None** when no run
is open. `issue()` would then write `record_exchange(run_id=None)` -- legal,
the column is nullable -- and its `UPDATE run SET requests_issued = ... WHERE
id = NULL` would match nothing, so `test_requests_issued_counts_the_send`
reads `SELECT ... WHERE id = NULL`, gets no row, and raises `TypeError` on a
`None` subscript. That failure would look like a bug in `issue` and would not
be one.

Add a fixture to `tests/conftest.py` beside `tool_ctx`:

```python
@pytest.fixture
def tool_run(tool_ctx):
    """A `tool_ctx` with a manual run already open.

    EVERY EGRESS TEST NEEDS ONE and the reason is not bookkeeping: `run_id`
    is what `record_exchange` attributes an exchange to and what
    `run.requests_issued` counts on. A context with no run open resolves
    `run_id` to None, writes an orphan exchange row, and silently counts
    nothing -- which is a coverage figure of zero for traffic that happened.
    """
    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="manual",
        safety_profile=tool_ctx.config.safety_profile)
    return tool_ctx
```

and use `tool_run` rather than `tool_ctx` in every test below that sends.

- [ ] **Step 12: Write the failing tests for `hx.issue`**

```python
# tests/test_issue.py
"""The only writer of `via='send'` exchange rows.

WHY THIS MODULE EXISTS AT ALL is the first thing to know when reading these
tests. `src/hx/store/schema.sql` records that `Capture.java` delivers
`via: proxy` and nothing else, so until this module there was no send-path
exchange row in this build -- and `http.grep`, `http.body` and
`evidence.attach` are all defined as reads keyed on one. Every assertion below
about a row, a blob or a surface is an assertion about whether those three
tools have anything to read.
"""
import hashlib

import pytest

from hx import issue
from hx.bridge.server import BridgeError

from tests.test_probe import FakeBridge, sent_result


def test_a_send_writes_an_exchange_row_a_later_tool_can_read(tool_run):
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a")

    row = tool_run.conn.execute(
        "SELECT via, method, url, status, outcome, req_blob, resp_blob,"
        " surface_id FROM exchange WHERE id=?", (got.exchange_id,)).fetchone()
    via, method, url, status, outcome, req_blob, resp_blob, surface_id = row
    assert via == "send"
    assert (method, status, outcome) == ("GET", 200, "ok")
    assert url == "http://127.0.0.1:8080/a"
    # BOTH blobs, and the surface back-reference. A row with a NULL
    # `resp_blob` is a row `http.grep` cannot read, and a row with a NULL
    # `surface_id` is one `surface.detail` will never join to.
    assert req_blob and resp_blob and surface_id


def test_the_digest_is_section_8s_digest(tool_run):
    body = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{}"
    bridge = FakeBridge()
    bridge.replies([sent_result(body, status=201, ms=42)])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="POST", path="/a")
    assert got.status == 201
    assert got.ms == 42
    assert got.content_type == "application/json"
    assert got.first_line == "HTTP/1.1 201 Created"
    assert got.body_sha256.startswith("sha256:")
    # `bytes` counts the WHOLE redacted response; `body` and `body_sha256`
    # are the payload alone, split from the head. The two are different
    # spans on purpose -- see finding 2 below for what goes wrong if
    # `body_sha256` ever hashes `response` instead.
    assert got.bytes == len(body)
    assert got.body == b"{}"
    assert got.body_sha256 == "sha256:" + hashlib.sha256(b"{}").hexdigest()


def test_body_sha256_hashes_only_the_body_not_the_headers(tool_run):
    """Finding 2. Two responses whose PAYLOAD is identical and whose headers
    are not -- a fresh `Date`, a per-session `Set-Cookie` -- must produce the
    same `body_sha256`. If this hashed `response` (status line and headers
    included) instead, `http.replay_as` would report an authorisation
    difference between two replies that answered identically."""
    bridge = FakeBridge()
    bridge.replies([
        sent_result(b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2001 00:00:00 GMT"
                    b"\r\n\r\nsame payload"),
        sent_result(b"HTTP/1.1 200 OK\r\nDate: Tue, 02 Jan 2001 00:00:00 GMT"
                    b"\r\nSet-Cookie: sid=abc123\r\n\r\nsame payload"),
    ])
    kwargs = dict(
        bridge=bridge, conn=tool_run.conn, blobs=tool_run.blobs,
        config=tool_run.config, engagement_id=tool_run.engagement.id,
        run_id=tool_run.run_id, scheme="http", host="127.0.0.1", port=8080,
        method="GET")
    first = issue.issue(**kwargs, path="/a")
    second = issue.issue(**kwargs, path="/b")
    assert first.body == second.body == b"same payload"
    # The responses genuinely differ (in `bytes`, the whole-response count),
    # which is what makes an EQUAL body_sha256 the meaningful assertion here
    # rather than a coincidence of two identical replies.
    assert first.bytes != second.bytes
    assert first.body_sha256 == second.body_sha256


def test_the_surface_is_upserted_as_agent_discovered(tool_run):
    """`capture.DISCOVERED_BY` maps `send` to `agent`, and nothing has ever
    exercised that entry. A surface an agent found and a surface the operator
    browsed are different facts and a report distinguishes them."""
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a")
    discovered_by = tool_run.conn.execute(
        "SELECT s.discovered_by FROM surface s JOIN exchange x"
        " ON x.surface_id = s.id WHERE x.id=?", (got.exchange_id,)).fetchone()
    assert discovered_by[0] == "agent"


def test_requests_issued_counts_the_send(tool_run):
    """S5's coverage floor. The proxy writer bumps it and this one must too,
    or a run that sent a hundred requests reports having issued none."""
    before = tool_run.conn.execute(
        "SELECT requests_issued FROM run WHERE id=?",
        (tool_run.run_id,)).fetchone()[0]
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    issue.issue(bridge, tool_run.conn, tool_run.blobs,
                tool_run.config, engagement_id=tool_run.engagement.id,
                run_id=tool_run.run_id, scheme="http", host="127.0.0.1",
                port=8080, method="GET", path="/a")
    after = tool_run.conn.execute(
        "SELECT requests_issued FROM run WHERE id=?",
        (tool_run.run_id,)).fetchone()[0]
    assert after == before + 1


@pytest.mark.parametrize("cls", [
    "scope_denied", "method_denied", "dangerous_denied", "rate_limited",
    "budget_exhausted", "halted", "not_configured", "transport_error",
    "timeout", "bridge_lost",
])
def test_every_refusal_class_raises_rather_than_returning(tool_run, cls):
    """`BridgeServer.send` NEVER returns a refusal as a dict, and the whole
    of `hx.checks.probe`'s rule-one argument applies here with the same
    force: a refusal that came back as a value is one a caller can read as a
    response."""
    bridge = FakeBridge()
    bridge.replies([BridgeError(f"{cls}: no", error_class=cls)])
    with pytest.raises(issue.IssueRefused) as exc:
        issue.issue(bridge, tool_run.conn, tool_run.blobs, tool_run.config,
                    engagement_id=tool_run.engagement.id,
                    run_id=tool_run.run_id, scheme="http", host="127.0.0.1",
                    port=8080, method="GET", path="/a")
    assert exc.value.reason == cls
    # AND NO ROW. A refused send put no bytes on the wire for most of these
    # classes, and a row would make a denial indistinguishable from traffic.
    assert tool_run.conn.execute(
        "SELECT COUNT(*) FROM exchange").fetchone()[0] == 0


def test_a_send_under_an_identity_records_it_as_assumed(tool_run):
    """Never `proven`: a canary bracket proves a run, and one send has none."""
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a",
        identity=("staff", 3))
    row = tool_run.conn.execute(
        "SELECT identity, identity_generation, identity_state"
        " FROM exchange WHERE id=?", (got.exchange_id,)).fetchone()
    assert tuple(row) == ("staff", 3, "assumed")
    # And the frame carried the id, so the EXTENSION does the injection.
    assert bridge.requests[0]["identity_id"] == "staff"


def test_an_anonymous_send_sends_no_identity_key_at_all(tool_run):
    """An ABSENT key is anonymous; a null would leave the extension deciding
    what a null means. `Sender.decideAndIssue` reads the field as
    `instanceof String`, so a null happens to be anonymous there today -- and
    a key sent only when it means something cannot acquire a second meaning
    from a later reader."""
    bridge = FakeBridge()
    bridge.replies([sent_result()])
    issue.issue(bridge, tool_run.conn, tool_run.blobs, tool_run.config,
                engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
                scheme="http", host="127.0.0.1", port=8080, method="GET",
                path="/a")
    assert "identity_id" not in bridge.requests[0]


@pytest.mark.parametrize("bad", [
    ("GE T", "/a"), ("GET", "/a b"), ("GET", "/a\r\nX: 1"),
    ("GET\n", "/a"), ("GET", "/a\x00"),
])
def test_a_request_that_could_be_split_is_refused_before_the_wire(bad):
    """Request smuggling starts at home. A method or path carrying CR, LF,
    NUL or a space would let an agent's ONE request become two, and the
    second would not have crossed the gate as itself. Refused here as a
    ValueError -- a caller's mistake, not a denial -- so it never lands in a
    journal row as an ordinary refusal."""
    method, path = bad
    with pytest.raises(ValueError):
        issue.request_bytes(method, path, "127.0.0.1", ())


def test_a_header_line_without_a_colon_is_refused():
    with pytest.raises(ValueError):
        issue.request_bytes("GET", "/a", "127.0.0.1", ("not a header",))


@pytest.mark.parametrize("line", [":evil", " X: 1"])
def test_a_header_with_an_empty_or_whitespace_led_name_is_refused(line):
    """Finding 3. `:evil` names no field at all; ` X: 1` is obs-fold, which
    some parsers reject and others fold into the PRECEDING header -- a
    parser-disagreement primitive reachable through http.send's headers
    array, even though neither shape can split a request by itself."""
    with pytest.raises(ValueError):
        issue.request_bytes("GET", "/a", "127.0.0.1", (line,))


def test_a_body_with_no_framing_header_gets_a_computed_content_length():
    """Finding 1. RFC 9112 S6.3: a request with neither Content-Length nor
    Transfer-Encoding has a ZERO-length body, so an unframed body sits in
    the connection buffer to be parsed as the head of the NEXT request on
    that keep-alive connection -- request splitting, produced by the exact
    function whose `FORBIDDEN` guard exists to prevent it."""
    raw = issue.request_bytes("POST", "/a", "h.test", (), b"x=1")
    assert b"\r\nContent-Length: 3\r\n" in raw
    assert raw.endswith(b"x=1")


def test_an_agreeing_content_length_is_left_alone():
    raw = issue.request_bytes(
        "POST", "/a", "h.test", ("Content-Length: 3",), b"x=1")
    assert raw.count(b"Content-Length:") == 1


def test_a_disagreeing_content_length_is_refused():
    """A CL that does not match the body is a request-smuggling primitive
    (CL.TE / TE.CL), not a typo -- refused rather than silently corrected,
    which would send a request different from the one the caller asked
    for."""
    with pytest.raises(ValueError, match="disagrees"):
        issue.request_bytes(
            "POST", "/a", "h.test", ("Content-Length: 99",), b"x=1")


def test_transfer_encoding_is_refused_outright():
    with pytest.raises(ValueError, match="Transfer-Encoding"):
        issue.request_bytes(
            "GET", "/a", "h.test", ("Transfer-Encoding: chunked",))


def test_an_empty_body_emits_no_content_length():
    raw = issue.request_bytes("GET", "/a", "h.test", ())
    assert b"Content-Length" not in raw


def test_the_host_header_is_not_duplicated():
    """The caller may spell `Host:` themselves -- a virtual-host test needs
    to -- and two Host headers is a request smuggling primitive, not a
    preference."""
    raw = issue.request_bytes("GET", "/a", "127.0.0.1", ("Host: other.test",))
    assert raw.count(b"Host:") == 1
    assert b"Host: other.test" in raw
```

- [ ] **Step 13: Run them to watch them fail**

Run: `.venv/bin/pytest tests/test_issue.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.issue'`

- [ ] **Step 14: Write `src/hx/issue.py`**

```python
# src/hx/issue.py
"""The one route from the tool layer to the wire, and the only writer of
`via='send'` exchange rows.

WHAT WAS MISSING. `src/hx/store/schema.sql` says it plainly: "`Capture.java`
delivers `via: proxy` and nothing else, so this build stores no send-path
exchange row at all." The Java confirms it -- `via` is written in exactly two
places, both in `proxy/Capture.java`, and `send/Sender.java` returns a result
map without ever pushing an `exchange` frame. Meanwhile spec section 8's
digest opens with `exchange_id`, and `http.grep`, `http.body` and
`evidence.attach` are each defined as a read keyed on one. Six tools rested on
a row nothing wrote. This module writes it.

FROM PYTHON, NOT FROM JAVA, and the trade is worth saying out loud. The result
frame already carries the redacted response bytes, the status, the timing and
the outcome; the request bytes are the ones this side composed. That is
everything the `exchange` table needs. What a Java change would add is the
POST-INJECTION request bytes and the resolved IP -- and would cost a second
writer into a table whose proxy writer took a plan to get right.

SO `req_blob` IS WHAT HX ASKED TO BE SENT, NOT WHAT LEFT THE JVM. They differ
by the identity header the extension injects. That difference is in the SAFE
direction and is the reason this is tolerable rather than merely cheap: the
credential is injected inside the JVM, so it cannot be in the bytes this side
hashes, and the blob store is content-addressed -- hashing raw bytes and
redacting afterwards would mean the raw bytes are already on disk. An agent
that needs to know an identity applied reads `exchange.identity`, which this
module writes, rather than grepping the request blob for a header it will
never find there.

A REFUSAL RAISES, and the argument is `hx.checks.probe`'s rule one word for
word: a sender that RETURNED a refusal would leave a caller free to read it as
a response. `BridgeServer.send` never returns one -- it raises `BridgeError`
with the wire's class on `.error_class` -- and this module raises
`IssueRefused` with that class as its reason.

`resolved_ip` AND `scope_version_id` STAY NULL, because the proxy writer
leaves both NULL too. Filling one here and not there would make `via` the
thing that decides how much a row knows.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import capture as capture_mod
from . import http_text
from . import surface as surface_mod
from .bridge.server import BridgeError, BridgeServer
from .store import db as db_mod
from .store import records

#: Bytes that end a line or terminate a string, in any position of a request
#: line or a header. One request becoming two is the whole of request
#: smuggling, and a `\r\n` an agent put in a path would do it below the gate
#: -- the extension decides about the request it was handed, and the second
#: request was never handed to it.
FORBIDDEN = ("\r", "\n", "\0")

#: Default scheme ports, omitted from the stored URL so a send and a proxy
#: observation of the same endpoint normalise onto ONE surface. Burp's own URL
#: omits them, and a surface split by nothing but the writer would double
#: every coverage figure.
DEFAULT_PORTS = {"http": 80, "https": 443}


class IssueRefused(Exception):
    """The request did not produce an answer. `reason` is the wire's class."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Issued:
    """Spec section 8's digest, plus the bytes for a caller that wants them.

    `response` is the REDACTED response, whole, and it is here so that
    `http.replay_as` can compare two replies without a second round trip to
    the blob store it just wrote. `body` is `response`'s payload alone, split
    from the head with `http_text.split_head_body` -- what `body_sha256`
    hashes and what `hx.delta` diffs. Neither is part of what a tool returns
    to an agent: Principle 1 is handles and digests, never payloads.

    `bytes` AND `body_sha256` DELIBERATELY DESCRIBE DIFFERENT SPANS OF THE
    SAME RESPONSE. `bytes` counts the WHOLE redacted response, because that
    is the number the extension's own frame reports and the two must not
    disagree; `body_sha256` hashes only the PAYLOAD, because that is the span
    `http.grep` and `http.replay_as` mean by "the body" and the one section 8
    named the field for. Two byte-identical bodies with a fresh `Date:` or a
    per-session `Set-Cookie` would hash differently if this hashed the whole
    response -- reporting an authorisation difference that does not exist.
    """

    exchange_id: str
    status: int | None
    bytes: int
    ms: int
    outcome: str
    content_type: str | None
    body_sha256: str
    first_line: str
    response: bytes
    body: bytes


def _url(scheme: str, host: str, port: int, path: str) -> str:
    if DEFAULT_PORTS.get(scheme) == port:
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def _clean(what: str, value: str) -> str:
    for ch in FORBIDDEN:
        if ch in value:
            raise ValueError(
                f"{what} contains {ch!r}, which would end the line: "
                f"{value!r}. One request becoming two is the whole of request "
                "smuggling, and it would happen BELOW the gate -- the "
                "extension decides about the request it was handed, and the "
                "second request was never handed to it.")
    return value


def request_bytes(method: str, path: str, host: str,
                  headers=(), body: bytes = b"") -> bytes:
    """One origin-form HTTP/1.1 request, or a ValueError.

    HEADERS ARE WIRE LINES, `Name: value`, not a mapping. `hx.tools.schema`
    requires `additionalProperties: false` on every object it publishes, so a
    free-key map is not expressible as a tool argument at all -- and an array
    of lines is what HTTP itself carries, so the agent writes what the wire
    will hold rather than a shape this side has to flatten.

    A ValueError, never an `IssueRefused`: nothing on the wire said no, a
    caller made a mistake, and an `IssueRefused` would land in a journal row
    as an ordinary refusal indistinguishable from a rate limit -- the same
    distinction `hx.checks.probe.ProbeSender.get` draws for the same reason.

    FRAMING IS THIS FUNCTION'S OWN PROBLEM, not its caller's. A non-empty
    body with no `Content-Length` and no `Transfer-Encoding` is, per RFC 9112
    S6.3, a request with a ZERO-LENGTH body -- the peer stops reading at the
    blank line, and the bytes this function put after it sit in the
    connection buffer to be parsed as the START of the NEXT request on that
    keep-alive connection. That is request splitting, produced by the exact
    function whose `FORBIDDEN` guard above exists to stop it, and the JVM
    does not repair it: `Sender.wireBytes` appends the body verbatim and
    computes no length of its own. So: no framing header given and a
    non-empty body means one is COMPUTED here.

    A caller-supplied `Content-Length` that disagrees with `len(body)`, and
    any `Transfer-Encoding` at all, are both REFUSALS rather than
    corrections. A CL/TE mismatch -- or two framing mechanisms naming two
    different lengths for the same message -- is a request-smuggling
    primitive in its own right (CL.TE / TE.CL), and this seam is not where
    one gets built by accident: correcting it silently would make the
    request this function sends different from the one the caller asked for,
    which is worse than refusing. Deliberate desync testing needs a
    different tool than the one every agent request goes through.
    """
    _clean("method", method)
    _clean("path", path)
    if " " in method or not method:
        raise ValueError(f"method must be one token, got {method!r}")
    if not path.startswith("/"):
        raise ValueError(
            f"path must be origin-form and start with '/', got {path!r}")
    if " " in path:
        raise ValueError(
            f"path contains a space, which ends the request target: {path!r}. "
            "Percent-encode it.")
    lines = [f"{method} {path} HTTP/1.1"]
    given = []
    has_content_length = False
    for line in headers:
        _clean("header", line)
        if ":" not in line:
            raise ValueError(
                f"header {line!r} has no ':'; headers are wire lines of the "
                "form 'Name: value'")
        name, _, value = line.partition(":")
        if not name or name[0] in " \t":
            raise ValueError(
                f"header {line!r} has an empty or whitespace-led field "
                "name. RFC 9112 has no field name that starts with "
                "whitespace -- that shape is obs-fold, which some parsers "
                "reject and some fold into the PRECEDING header, and an "
                "agent-supplied header line is not the place either "
                "behaviour is safe to invite.")
        lname = name.strip().lower()
        if lname == "transfer-encoding":
            raise ValueError(
                f"header {line!r} sets Transfer-Encoding, refused outright. "
                "A Content-Length/Transfer-Encoding disagreement is a "
                "request-smuggling primitive (CL.TE / TE.CL), and this seam "
                "is not where one gets built by accident -- deliberate "
                "desync testing needs a different tool than the one every "
                "agent request goes through.")
        if lname == "content-length":
            try:
                declared = int(value.strip())
            except ValueError:
                raise ValueError(
                    f"header {line!r} is not a valid Content-Length "
                    "integer") from None
            if declared != len(body):
                raise ValueError(
                    f"header {line!r} disagrees with the body actually "
                    f"given ({len(body)} bytes). A Content-Length that does "
                    "not match its body is a request-smuggling primitive, "
                    "not a typo to silently correct.")
            has_content_length = True
        given.append(line)
    # THE CALLER'S HOST WINS AND IS NOT JOINED BY A SECOND. A virtual-host
    # test needs to spell `Host:` itself, and two Host headers is a smuggling
    # primitive rather than a preference.
    if not any(line.partition(":")[0].strip().lower() == "host"
               for line in given):
        lines.append(f"Host: {host}")
    lines += given
    if body and not has_content_length:
        lines.append(f"Content-Length: {len(body)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


def issue(bridge, conn, blobs, config, *, engagement_id: str,
          run_id: str, scheme: str, host: str, port: int, method: str,
          path: str, headers=(), body: bytes = b"", identity=None,
          timeout: float = 30.0) -> Issued:
    """Send one request and record it. Raises `IssueRefused` on every refusal.

    `identity` is `(id, generation)` or None -- NEVER a `Resolved`. Principle
    5 keeps the credential below the tool layer, and a function that took one
    could put it in a return value that gets journalled. The extension holds
    the secret; this side holds the name, sends it as `identity_id`, and
    stores it on the row.
    """
    raw = request_bytes(method, path, host, headers, body)
    req = {"target_host": host, "target_port": port, "tls": scheme == "https"}
    if identity is not None:
        # PRESENT ONLY WHEN BOUND. See `ProbeSender.get` -- an absent key is
        # anonymous, and a null would leave the extension deciding what a
        # null means.
        req["identity_id"] = identity[0]

    try:
        result = bridge.send(req, raw, timeout=timeout)
    except BridgeError as exc:
        cls = exc.error_class or "transport_error"
        detail = str(exc).removeprefix(f"{cls}: ")
        raise IssueRefused(cls, "" if detail == cls else detail) from exc

    # `BridgeServer.BODY_KEY` directly, not `type(bridge).BODY_KEY`: the test
    # double in `tests/test_probe.py` reproduces the real reply SHAPE without
    # subclassing `BridgeServer`, and this module has to read that shape too.
    response = result.get(BridgeServer.BODY_KEY, b"")
    status = result.get("status")
    outcome = result.get("outcome", "ok")
    ms = int(result.get("ms") or 0)
    head, response_body = http_text.split_head_body(response)
    types = http_text.header_values(head, "content-type")
    first_line = head.split(b"\n", 1)[0].rstrip(b"\r").decode(
        "latin-1", "replace")

    url = _url(scheme, host, port, path)
    norm = surface_mod.normalise(
        method, url,
        preserve=frozenset(config.preserve_segments),
        slug_threshold=config.slug_threshold)

    # BLOBS BEFORE THE TRANSACTION, deliberately, and the argument is the
    # proxy writer's: the blob store is not in the database, so a ROLLBACK
    # cannot take a file back. Writing them first leaves an orphan blob a
    # sweep can collect; writing them after a committed row that NAMES them
    # would leave corruption a report reads as evidence.
    req_blob, _ = blobs.put(raw)
    resp_blob, resp_len = blobs.put(response) if response else (None, None)

    cap = capture_mod.Capture(conn=conn, blobs=blobs,
                              engagement_id=engagement_id, config=config)
    at = capture_mod.now_us()
    with db_mod.transaction(conn):
        exchange_id = records.record_exchange(
            conn, run_id=run_id, method=method, url=url, status=status,
            req_blob=req_blob, resp_blob=resp_blob, resp_len=resp_len,
            ms=ms, at_us=at, outcome=outcome, via="send",
            identity=None if identity is None else identity[0],
            identity_generation=None if identity is None else identity[1],
            # NEVER `proven`. A canary bracket proves a RUN (spec section 6);
            # one send has no bracket, so `assumed` is the whole of what is
            # known and `proven` would be a claim no canary backs.
            identity_state=None if identity is None else "assumed")
        # S5's coverage floor, and the proxy writer bumps it for the same
        # reason: a run that sent a hundred requests and reports having
        # issued none makes every figure derived from this column wrong.
        conn.execute(
            "UPDATE run SET requests_issued = requests_issued + 1"
            " WHERE id=?", (run_id,))
        surface_id = cap.upsert_surface(norm, exchange_id=exchange_id,
                                        run_id=run_id, via="send")
        # The back-reference, and it cannot be written earlier: the surface's
        # exemplar is this exchange, so the exchange row has to exist before
        # the surface row can name it.
        conn.execute("UPDATE exchange SET surface_id=? WHERE id=?",
                     (surface_id, exchange_id))

    return Issued(
        exchange_id=exchange_id, status=status, bytes=len(response), ms=ms,
        outcome=outcome, content_type=types[0] if types else None,
        # HASHES THE BODY, NOT `response`. `bytes` above is the whole
        # redacted response -- it has to match the extension's own frame --
        # while this is the payload alone; see `Issued`'s docstring for why
        # the two spans differ on purpose and are not a mismatch to "fix".
        body_sha256="sha256:" + hashlib.sha256(response_body).hexdigest(),
        first_line=first_line, response=response, body=response_body)
```

**Two things to verify against the repo rather than trusting this text:**
1. `capture_mod.now_us` — confirm the name and that it is importable (`command grep -n "def now_us\|now_us" src/hx/capture.py`). If it lives elsewhere, import it from there.
2. `type(bridge).BODY_KEY` — the real `BridgeServer` defines `BODY_KEY`; confirm it is a class attribute and not an instance one. If it is module-level, import it directly.

- [ ] **Step 15: Run the issue tests**

Run: `.venv/bin/pytest tests/test_issue.py -q`
Expected: PASS, all of them.

- [ ] **Step 16: Run the whole suite and ruff**

Run: `.venv/bin/pytest -q && .venv/bin/ruff check src tests`
Expected: 1830 + the new tests passed, 1 skipped; ruff clean.

- [ ] **Step 17: Commit**

```bash
git add src/hx/issue.py src/hx/store/records.py tests/test_issue.py tests/conftest.py
git commit -m "feat(issue): the send path records an exchange row

Nothing in this build stored via='send'. schema.sql said so, the Java
confirmed it, and six of Plan B's tools are defined as reads keyed on an
exchange_id that nothing produced. hx.issue composes the request, sends it
through the one bridge seam, writes both blobs, upserts the surface as
agent-discovered and bumps run.requests_issued.

record_exchange gains the identity triple, defaulted to None so every
existing call site is unchanged. A send under an identity records
identity_state='assumed': a canary bracket proves a run, and one send
has none."
```

---

## Task 2: `delta_vs_baseline`

Principle 1's own justification: *"a bare `{exchange_id, status, bytes, ms}` is uninformative: twelve XSS payload variants against one endpoint return twelve identical-looking tuples."* The delta is what makes the digest worth returning.

**Files:**
- Create: `src/hx/delta.py`
- Test: `tests/test_delta.py`

**Interfaces:**
- Consumes: `hx.store.blobs.BlobStore.get(digest, expected_len)`; `hx.http_text.split_head_body`; the `surface` and `exchange` tables.
- Produces:
  - `hx.delta.against(baseline_status, baseline_body, status, body) -> dict` with keys `status_changed`, `len_delta`, `new_tokens`, and `new_tokens_truncated` when it applies
  - `hx.delta.baseline_for(conn, blobs, surface_id) -> tuple[int | None, bytes] | None` -- the second element is the exemplar's BODY, not its whole stored response
  - `hx.delta.TOKEN`, `MAX_TOKENS`, `MAX_DIFF_BYTES`

---

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_delta.py
"""What changed between a response and its surface's exemplar.

The digest exists because twelve payload variants against one endpoint return
twelve identical tuples without it. So the test that matters most here is the
one where a reflected token appears in `new_tokens` and nothing else does.
"""
from hx import delta, issue

from tests.test_probe import FakeBridge, sent_result


def test_a_reflected_payload_shows_up_as_a_new_token():
    """The whole point. An agent sends `hZq9xK` and wants to be told, in the
    digest, that `hZq9xK` came back -- without reading a 1.2 MB body."""
    base = b"<html><body>Hello visitor</body></html>"
    now = b"<html><body>Hello hZq9xK</body></html>"
    got = delta.against(200, base, 200, now)
    assert got["new_tokens"] == ["hZq9xK"]
    assert got["status_changed"] is False
    assert got["len_delta"] == len(now) - len(base)


def test_tokens_present_in_the_baseline_are_not_new():
    base = b"session=abcdef ; csrf=ghijkl"
    now = b"session=abcdef ; csrf=ghijkl ; extra=mnopqr"
    assert delta.against(200, base, 200, now)["new_tokens"] == ["mnopqr"]


def test_short_runs_are_not_tokens():
    """A six-character floor. Without it every `<div>`, `class` and `href`
    in a re-rendered page is a `new_token`, and the field an agent reads for
    signal becomes the field it learns to skip."""
    assert delta.against(200, b"a", 200, b"a bc def ghij")["new_tokens"] == []


def test_a_status_change_is_reported_even_when_the_body_is_identical():
    got = delta.against(200, b"same", 403, b"same")
    assert got["status_changed"] is True
    assert got["len_delta"] == 0
    assert got["new_tokens"] == []


def test_tokens_are_capped_and_the_cap_is_declared():
    """A silent cap reads as "that was all of them", which is section 12's
    failure in a single field."""
    now = b" ".join(b"tok%05d" % i for i in range(delta.MAX_TOKENS + 10))
    got = delta.against(200, b"", 200, now)
    assert len(got["new_tokens"]) == delta.MAX_TOKENS
    assert got["new_tokens_truncated"] is True


def test_an_oversized_body_reports_null_tokens_rather_than_scanning_it():
    """`new_tokens: null` is "not computed"; `[]` is "computed, none found".
    Collapsing the two would let an agent read a 40 MB download it never
    diffed as proof that nothing changed."""
    big = b"x" * (delta.MAX_DIFF_BYTES + 1)
    got = delta.against(200, b"", 200, big)
    assert got["new_tokens"] is None
    assert got["len_delta"] == len(big)
    assert got["status_changed"] is False


def test_a_surface_with_no_exemplar_has_no_baseline(tool_ctx):
    assert delta.baseline_for(tool_ctx.conn, tool_ctx.blobs, "no-such") is None


def test_baseline_for_returns_the_exemplars_body_not_its_whole_response(
        tool_run):
    """The row is built by `hx.issue.issue`, the one writer of `via='send'`
    exchange rows -- a fixture that wrote the surface/exchange rows itself
    would pass while the real writer wrote something else. The exemplar
    response here carries a `Date` header the body does not, so a
    `baseline_for` that returned the whole response rather than the body
    would fail the equality assertion below by leaking that header in.
    """
    bridge = FakeBridge()
    body = b"<html><body>Hello visitor</body></html>"
    resp = (b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2001 00:00:00 GMT\r\n"
            b"Content-Type: text/html\r\n\r\n" + body)
    bridge.replies([sent_result(resp, status=200)])
    got = issue.issue(
        bridge, tool_run.conn, tool_run.blobs, tool_run.config,
        engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
        scheme="http", host="127.0.0.1", port=8080, method="GET", path="/a")

    row = tool_run.conn.execute(
        "SELECT surface_id FROM exchange WHERE id=?",
        (got.exchange_id,)).fetchone()
    surface_id = row[0]

    baseline = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id)
    assert baseline == (200, body)


def _two_exchanges_on_one_surface(tool_run):
    """Two `via='send'` exchanges against the same surface, through the real
    writer (`hx.issue.issue`) rather than hand-built rows -- the same reason
    `test_baseline_for_returns_the_exemplars_body_not_its_whole_response`
    goes through it above. `first` becomes the surface's exemplar (`hx.
    capture.Capture.upsert_surface`'s `INSERT ... ON CONFLICT DO UPDATE`
    writes `exemplar_exchange_id` only on the INSERT branch); `second` does
    not. Returns `(first, second, surface_id, first_payload)`.
    """
    bridge = FakeBridge()
    first_payload = b"Hello visitor"
    second_payload = b"Hello again"
    bridge.replies([
        sent_result(b"HTTP/1.1 200 OK\r\n\r\n" + first_payload),
        sent_result(b"HTTP/1.1 200 OK\r\n\r\n" + second_payload),
    ])
    kw = dict(engagement_id=tool_run.engagement.id, run_id=tool_run.run_id,
              scheme="http", host="127.0.0.1", port=8080, method="GET",
              path="/x")
    first = issue.issue(bridge, tool_run.conn, tool_run.blobs,
                        tool_run.config, **kw)
    second = issue.issue(bridge, tool_run.conn, tool_run.blobs,
                         tool_run.config, **kw)
    surface_id = tool_run.conn.execute(
        "SELECT surface_id FROM exchange WHERE id=?",
        (first.exchange_id,)).fetchone()[0]
    return first, second, surface_id, first_payload


# --- `exclude_exchange_id`, fix round 1's finding 4 -------------------------
#
# The NULL-safety contract lived only in a comment on `baseline_for`: `x.id
# IS NOT ?` against a NULL parameter, not `!=`, which SQLite evaluates to
# NULL -- neither true nor false -- and which would silently match NO row for
# every caller that passes nothing. These four cases are the ones the
# reviewer probed by hand.


def test_no_exclusion_returns_the_baseline(tool_run):
    first, _second, surface_id, payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id)
    assert got == (first.status, payload)


def test_excluding_the_exemplar_itself_returns_no_baseline(tool_run):
    """The guard `hx.tools.impl.http._digest` relies on: `hx.issue.issue`
    makes a brand-new surface's exemplar the very exchange that just created
    it, so a caller diffing THAT exchange's response against "the baseline"
    must not diff it against itself -- a zero delta reporting a comparison
    that was never made."""
    first, _second, surface_id, _payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id,
                             exclude_exchange_id=first.exchange_id)
    assert got is None


def test_excluding_a_different_exchange_leaves_the_baseline_intact(tool_run):
    """Only an exclusion naming the EXEMPLAR itself may suppress the
    baseline. Excluding the second exchange -- which is not the exemplar --
    must change nothing."""
    first, second, surface_id, payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id,
                             exclude_exchange_id=second.exchange_id)
    assert got == (first.status, payload)


def test_exclude_exchange_id_of_none_leaves_the_baseline_intact(tool_run):
    """`None` PASSED EXPLICITLY, not merely omitted -- pinning the same
    NULL-safety contract as `test_no_exclusion_returns_the_baseline` against
    the keyword itself rather than against its default."""
    first, _second, surface_id, payload = _two_exchanges_on_one_surface(
        tool_run)
    got = delta.baseline_for(tool_run.conn, tool_run.blobs, surface_id,
                             exclude_exchange_id=None)
    assert got == (first.status, payload)
```

Add one more test once Task 1 is in: `baseline_for` over a surface whose exemplar exchange has a `resp_blob`, asserting it returns `(status, body_bytes)` -- the BODY, not the whole stored response. Build the row with `hx.issue.issue` and a `FakeBridge` rather than by hand — a fixture that writes the row itself would pass while the real writer wrote something else.

- [ ] **Step 2: Run to watch it fail**

Run: `.venv/bin/pytest tests/test_delta.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.delta'`

- [ ] **Step 3: Write `src/hx/delta.py`**

```python
# src/hx/delta.py
"""What changed between a response and its surface's exemplar.

SPEC SECTION 8 PUTS THIS IN THE DIGEST AND GIVES THE REASON: "a bare
{exchange_id, status, bytes, ms} is uninformative: twelve XSS payload variants
against one endpoint return twelve identical-looking tuples". Principle 1 says
handles and digests, never payloads -- and a digest that cannot tell two
responses apart makes Principle 1 a rule against usefulness rather than
against volume.

THE BASELINE IS THE SURFACE'S EXEMPLAR, and there is no other honest choice
available here. `surface.exemplar_exchange_id` is the request that first
defined the endpoint; it is what "normal" means for that surface in this
engagement's own data. A request that reaches no known surface has NO baseline
and the digest then carries `delta_vs_baseline: null` -- not a zero delta,
which would read as "nothing changed" about a comparison never made.

`new_tokens` IS THREE-VALUED FOR THE SAME REASON. `[]` is "computed, none
found"; `null` is "not computed, the bodies were too large to diff". Section
12's rule is that a report which cannot distinguish tested-clean from
never-reached is worse than no report, and a field that spells both `[]` is
that rule broken inside one key.

`baseline_for` RETURNS THE EXEMPLAR'S BODY, NEVER ITS WHOLE STORED RESPONSE.
A review of Task 1's `hx.issue` established why: two responses with
byte-identical content still differ in their `Date:` header and their
per-session `Set-Cookie`, so a delta computed over whole responses counts
that header churn as change -- `new_tokens` fills with `Date`, `ETag` and
cookie-value tokens that have nothing to do with the request under test,
drowning the one signal section 8 built the digest for and potentially
pushing the real reflected payload past `MAX_TOKENS` before it is ever
reported.
"""
from __future__ import annotations

import re

from . import http_text

#: A token is a run of characters a payload or an identifier is made of. The
#: SIX-CHARACTER FLOOR is what makes the field readable: without it every
#: `<div>`, `class`, `href` and `span` in a re-rendered page is a new token,
#: and the one field an agent reads for signal becomes the one it learns to
#: skip. Six admits every realistic payload marker and excludes almost all
#: HTML and English.
TOKEN = re.compile(rb"[A-Za-z0-9_-]{6,}")

#: Reported, never silent -- see `new_tokens_truncated`. A response that
#: differs in three hundred tokens has been rewritten, and the first twenty
#: say so as well as all three hundred would.
MAX_TOKENS = 20

#: Above this, tokens are not computed and the field says so. Two 8 MB bodies
#: tokenised into sets is tens of megabytes of transient allocation inside the
#: one long-lived process that also holds the Burp bridge connection.
MAX_DIFF_BYTES = 2 * 1024 * 1024


def against(baseline_status, baseline_body: bytes,
            status, body: bytes) -> dict:
    """The delta, with `new_tokens` None when the bodies were too big to diff.

    `status_changed` and `len_delta` are ALWAYS computed: they cost nothing
    and they are the two facts that survive a body no one could diff.
    """
    out = {
        "status_changed": baseline_status != status,
        "len_delta": len(body) - len(baseline_body),
        "new_tokens": None,
    }
    if len(body) > MAX_DIFF_BYTES or len(baseline_body) > MAX_DIFF_BYTES:
        return out
    seen = set(TOKEN.findall(baseline_body))
    fresh = []
    for tok in TOKEN.findall(body):
        if tok in seen:
            continue
        seen.add(tok)
        fresh.append(tok.decode("latin-1"))
    if len(fresh) > MAX_TOKENS:
        out["new_tokens_truncated"] = True
        fresh = fresh[:MAX_TOKENS]
    out["new_tokens"] = fresh
    return out


def baseline_for(conn, blobs, surface_id, *, exclude_exchange_id=None):
    """`(status, body_bytes)` for a surface's exemplar, or None.

    None for every way there is not one: no surface row, no exemplar, an
    exemplar whose response was never stored. All three are "there is nothing
    to compare against", and a caller that told them apart would be reporting
    on its own bookkeeping rather than on the application.

    BODY, NOT THE WHOLE STORED RESPONSE -- see this module's docstring. A
    delta over whole responses counts header churn as change: `new_tokens`
    fills with `Date` and `Set-Cookie` noise, which is the signal section 8
    built the digest for being drowned out by the transport that carried it,
    not by the application.

    `exclude_exchange_id`, WHEN GIVEN, treats an exemplar equal to it as no
    baseline at all. `hx.issue.issue` makes a brand-new surface's exemplar
    the very exchange that just created it, inside its own transaction,
    before it ever returns `Issued` -- so a caller diffing that first
    exchange's response against "the baseline" would be diffing it against
    itself: a zero delta reporting a comparison that was never made. This is
    the caller's guard against exactly that, pushed into the query rather
    than a second round trip at the call site (`hx.tools.impl.http._digest`
    is the one caller). `x.id IS NOT ?` rather than `!=` because SQLite's
    `!=` against a NULL parameter is NULL -- neither true nor false -- and
    would silently match no row at all for every caller that passes nothing;
    `IS NOT` is NULL-safe, so a `None` here is simply "exclude nothing".
    """
    row = conn.execute(
        "SELECT x.status, x.resp_blob, x.resp_len FROM surface s"
        " JOIN exchange x ON x.id = s.exemplar_exchange_id"
        " WHERE s.id = ? AND x.id IS NOT ?",
        (surface_id, exclude_exchange_id)).fetchone()
    if row is None or row[1] is None:
        return None
    _head, body = http_text.split_head_body(blobs.get(row[1], row[2]))
    return row[0], body
```

- [ ] **Step 4: Run the delta tests**

Run: `.venv/bin/pytest tests/test_delta.py -q`
Expected: PASS

- [ ] **Step 5: Full suite, ruff, commit**

```bash
.venv/bin/pytest -q && .venv/bin/ruff check src tests
git add src/hx/delta.py tests/test_delta.py
git commit -m "feat(delta): the digest's delta_vs_baseline

Spec section 8's justification for the digest is that twelve payload variants
return twelve identical tuples without it. Baseline is the surface's exemplar;
no exemplar means null rather than a zero delta, and new_tokens is null when
the bodies were too large to diff rather than an empty list that would read as
'nothing changed'."
```

---

## Task 3: The session bracket

`ToolContext.session` has been `None` since Plan A shipped. This task fills it — and settles what happens in the adapter that structurally cannot hold one.

**Files:**
- Create: `src/hx/tools/live.py`
- Modify: `src/hx/tools/dispatch.py` (`ToolContext` gains two fields)
- Modify: `src/hx/tools/impl/run.py` (`start` opens, `finish` closes)
- Modify: `src/hx/tools/adapters/cli.py` (`build_context` takes `stack`)
- Test: `tests/test_tools_live.py`, additions to `tests/test_tools_run.py`, `tests/integration/test_tool_session.py`

**Interfaces:**
- Consumes: `hx.session.session(eng, *, instance, jar=None, workdir=None, seed=None)` — a context manager yielding `LiveSession(operator_port, crawler_port, epoch, bridge, workdir, proc)`, raising `SessionError`. `LiveSession.gone() -> str | None`.
- Produces:
  - `hx.tools.live.EGRESS_KINDS`, `INSTANCE`
  - `hx.tools.live.open_for(ctx, run_id, kind) -> dict` — never raises
  - `hx.tools.live.close_for(ctx, run_id) -> bool`
  - `hx.tools.live.ensure_identity(ctx, identity_id) -> tuple[str, int]`
  - `ToolContext.stack: contextlib.ExitStack | None`, `ToolContext._registered: set`, `ToolContext._session_run_id: str | None`

---

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_tools_live.py
"""The session bracket.

FIVE OUTCOMES, AND FOUR OF THEM ARE "NO SESSION". That is the shape worth
holding in mind while reading: a run opens either way, and what varies is the
reason it has no Burp. An agent that is told `not_needed` knows its browse run
never wanted one; one told `no_host` knows it is running under `hx tool` and
should move to `hx mcp`; one told `launch_failed` has an operator problem; one
told `session_held` knows which run to finish. A single `live: false` would
collapse four different next actions into one shrug.

NOTHING HERE LAUNCHES A JVM. `session.session` is monkeypatched in every test
that gets past the first two branches, which is right for a suite about
bookkeeping -- and `tests/integration/test_tool_session.py` proves the one
claim a fake cannot, that a real Burp comes up configured and goes away again.
"""
import contextlib

import pytest

from hx import identity as identity_mod
from hx import session as session_mod
from hx.tools import live
from tests.test_probe import FakeBridge


class FakeLive:
    """What `session.session()` yields, minus the JVM."""

    operator_port = 18080
    crawler_port = 18081
    epoch = 3
    bridge = object()

    def gone(self):
        return None


@contextlib.contextmanager
def _fake_session(eng, **kw):
    yield FakeLive()


def test_a_browse_run_is_told_it_never_needed_one(tool_ctx):
    got = live.open_for(tool_ctx, "run-1", "browse")
    assert got["live"] is False
    assert got["reason"] == "not_needed"


def test_without_a_host_stack_it_names_the_adapter_and_the_fix(tool_ctx):
    """`hx tool` is one process per call. A session launched there would be
    torn down microseconds later by `session()`'s own unconditional
    teardown, so the honest answer is that this ADAPTER cannot hold one."""
    tool_ctx.stack = None
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "no_host"
    assert "hx mcp" in got["detail"]


#: A string no real `SessionError` can carry. The obvious message for the
#: test below -- "no burp jar under ~/F0RT1KA/burp-lab" -- is very close to
#: what `find_burp_jar` really says on a machine with no Burp, so the test
#: would have passed against an UNPATCHED `session()` and proved nothing
#: about the seam it names. The sentinel makes only the patched function able
#: to satisfy it.
LAUNCH_SENTINEL = "hx-test-sentinel-4f21a9"


def test_a_launch_failure_is_reported_not_raised(tool_ctx, monkeypatch):
    """`run.start` must still open the run: refusing outright would leave no
    run row and no agent_action row -- no trace that the instrument failed."""
    def boom(eng, **kw):
        raise session_mod.SessionError(
            f"no burp jar under ~/F0RT1KA/burp-lab [{LAUNCH_SENTINEL}]")

    monkeypatch.setattr(session_mod, "session", boom)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "launch_failed"
    # The operator's own sentence, intact -- and the sentinel, which says the
    # sentence came from the patched `session()` and not from a real one.
    assert "burp-lab" in got["detail"]
    assert LAUNCH_SENTINEL in got["detail"]


def test_a_successful_launch_binds_the_session_and_reports_its_ports(
        tool_ctx, monkeypatch):
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is True
    assert got["operator_port"] == 18080
    assert got["crawler_port"] == 18081
    assert got["epoch"] == 3
    assert tool_ctx.session is not None


def test_a_scan_run_gets_one_too(tool_ctx, monkeypatch):
    """EGRESS_KINDS is two kinds, not one. `manual` alone would leave the
    agent's own check pass -- the one thing in section 8 that certainly
    sends -- reporting `not_needed` for a run that needs it most."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    assert live.open_for(tool_ctx, "run-1", "scan")["live"] is True


def test_a_second_egress_run_is_told_who_holds_the_session(
        tool_ctx, monkeypatch):
    """One Burp at a time, owned by the run that launched it. The second run
    OPENS -- it can still record findings and query surfaces -- and is told
    exactly which run to finish."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    got = live.open_for(tool_ctx, "run-2", "scan")
    assert got["live"] is False
    assert got["reason"] == "session_held"
    assert got["owner_alive"] is True
    assert "run-1" in got["detail"]


def test_a_session_held_by_a_corpse_says_so_and_names_the_fix(
        tool_ctx, monkeypatch):
    """Section 12 once more: "blocked by a live session" and "blocked by a
    corpse" are different facts, and only one of them means wait. A JVM that
    died mid-run leaves `ctx.session` set, so every later egress run is
    refused -- and an agent told only `session_held` would go on waiting for
    a run that will never give the instrument back on its own.

    OWNERSHIP IS NOT TAKEN HERE. The dead session is not torn down and not
    stolen: `run.finish` on the owning run is the fix, and the detail says
    so, because a run helping itself to another run's teardown is how two
    runs come to share one instrument.
    """
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    held = tool_ctx.session
    tool_ctx.session = type(
        "Corpse", (), {"gone": lambda self: "Burp exited (status 137)"})()

    got = live.open_for(tool_ctx, "run-2", "scan")
    assert got["reason"] == "session_held"
    assert got["owner_alive"] is False
    assert "run.finish" in got["detail"] and "run-1" in got["detail"]
    assert "status 137" in got["detail"]
    # Not stolen and not torn down: the owner still holds what it held.
    assert tool_ctx._session_run_id == "run-1"
    assert held is not None


def test_only_the_owning_run_can_close_the_session(tool_ctx, monkeypatch):
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    assert live.close_for(tool_ctx, "run-2") is False
    assert tool_ctx.session is not None
    assert live.close_for(tool_ctx, "run-1") is True
    assert tool_ctx.session is None


def test_closing_with_no_session_at_all_is_false_not_a_raise(tool_ctx):
    """`run.finish` calls this on every run it closes, egress or not: a
    browse run, or a manual run whose launch failed, has no session and must
    still be closeable."""
    tool_ctx.stack = contextlib.ExitStack()
    assert live.close_for(tool_ctx, "run-1") is False


def test_the_stack_is_reusable_so_a_second_run_can_open_its_own(
        tool_ctx, monkeypatch):
    """One `hx mcp` conversation opens and closes many runs on ONE stack.
    `ExitStack.close()` unwinds and leaves the stack usable, which is what
    makes that true -- a stack that could only be closed once would give the
    second egress run of a conversation `launch_failed` for ever."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    live.close_for(tool_ctx, "run-1")
    assert live.open_for(tool_ctx, "run-2", "manual")["live"] is True
    assert tool_ctx._session_run_id == "run-2"


def test_a_dead_session_is_not_handed_out_as_live(tool_ctx, monkeypatch):
    """`LiveSession.gone()` has two ways to be true and neither is 'the
    process exited': a JVM that is up while its extension dropped the bridge
    reconnects at DENY-ALL -- alive, proxying nothing, recording nothing."""
    class Dead(FakeLive):
        def gone(self):
            return "Burp's extension dropped the bridge connection"

    @contextlib.contextmanager
    def dead_session(eng, **kw):
        yield Dead()

    monkeypatch.setattr(session_mod, "session", dead_session)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "launch_failed"
    assert tool_ctx.session is None


def test_a_dead_session_is_torn_down_rather_than_left_running(
        tool_ctx, monkeypatch):
    """A Burp at DENY-ALL is a Burp that is UP. Reporting `launch_failed` and
    leaving the context manager on the stack would leave a 900 MB JVM running
    for a session nobody holds -- section 8's orphaned JVM, arrived at by the
    one branch that knows the session is no good."""
    torn_down = []

    @contextlib.contextmanager
    def dead_session(eng, **kw):
        class Dead(FakeLive):
            def gone(self):
                return "Burp exited (status 1) while the session was live"
        try:
            yield Dead()
        finally:
            torn_down.append(True)

    monkeypatch.setattr(session_mod, "session", dead_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    assert torn_down == [True], "the dead session was left on the stack"


def test_an_identity_is_registered_once_per_generation(
        tool_ctx, monkeypatch, staff_identity_config):
    """A second registration of the same generation would be refused
    `stale_generation` by the extension, so a tool that re-registered on
    every send would fail on its second one."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()

    first = live.ensure_identity(tool_ctx, "staff")
    second = live.ensure_identity(tool_ctx, "staff")
    assert first == second == ("staff", 1)
    assert len(tool_ctx.session.bridge.identities) == 1


def test_the_credential_never_leaves_this_function(
        tool_ctx, monkeypatch, staff_identity_config):
    """Principle 5. What comes back is a name and a number -- an exchange
    row's worth -- and never a `Resolved`, which a journalled return value
    would put the secret into.

    THE EQUALITY IS THE WHOLE CLAIM. This test used to add
    `assert "s3cret" not in repr(got)` under it, which the line above had
    already settled -- a pair that IS `("staff", 1)` cannot contain anything
    else -- so it read as credential-containment coverage that was not there.
    Containment on the OTHER side of the call, where the credential really
    does travel, is `test_the_declared_origins_bound_the_credential`: it
    reads what reached the bridge and pins it to the id, the generation and
    the declared origins.
    """
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    assert live.ensure_identity(tool_ctx, "staff") == ("staff", 1)


def test_the_declared_origins_bound_the_credential(
        tool_ctx, monkeypatch, staff_identity_config):
    """`origins` is what the extension applies the credential within, and an
    empty tuple is 'the operator did not widen it' rather than 'everywhere'.
    Dropping it here would send a client's live session to every host in
    scope, which is the widening `Identity.origins` exists to prevent."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    live.ensure_identity(tool_ctx, "staff")
    assert tool_ctx.session.bridge.identities == [
        ("staff", 1, ("https://app.test/",))]


def test_a_credential_that_is_not_in_the_environment_is_not_registered(
        tool_ctx, monkeypatch, staff_identity_config):
    """`resolve` refuses rather than issuing anonymously, and the refusal
    must not leave a half-registration behind: an identity recorded here that
    the extension never heard of would make the NEXT call believe it had
    already registered and send unauthenticated under its name."""
    monkeypatch.delenv("HX_STAFF_TOKEN", raising=False)
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    with pytest.raises(identity_mod.IdentityError, match="HX_STAFF_TOKEN"):
        live.ensure_identity(tool_ctx, "staff")
    assert tool_ctx._registered == set()
    assert tool_ctx.session.bridge.identities == []


def test_an_undeclared_identity_names_what_is_declared(
        tool_ctx, staff_identity_config):
    tool_ctx.config = staff_identity_config
    with pytest.raises(ValueError, match="staff"):
        live.ensure_identity(tool_ctx, "nope")


def test_close_for_tears_down_the_session_and_nothing_else_on_the_stack(
        tool_ctx, monkeypatch):
    """WHAT THE NESTING BUYS. Task 8 hands `hx mcp`'s own long-lived
    ExitStack straight to `build_context`, so anything that adapter registers
    on it must survive an ordinary `run.finish`. The session goes onto an
    INNER stack for exactly that reason; closing the outer one still unwinds
    the inner, so a crash kills the JVM either way."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    adapters_own = []
    with contextlib.ExitStack() as stack:
        stack.callback(adapters_own.append, "the adapter's own clean-up")
        tool_ctx.stack = stack
        live.open_for(tool_ctx, "run-1", "manual")
        assert live.close_for(tool_ctx, "run-1") is True
        assert adapters_own == [], (
            "run.finish tore down the adapter's own stack entries")
    assert adapters_own == ["the adapter's own clean-up"]


def test_the_inner_stack_is_made_once_and_reused(tool_ctx, monkeypatch):
    """A fresh inner stack per session would leave one spent `__exit__`
    callback on the adapter's stack per session -- a no-op each, and unbounded
    growth across an `hx mcp` conversation that opens and closes runs all
    day."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    first = tool_ctx._session_stack
    live.close_for(tool_ctx, "run-1")
    live.open_for(tool_ctx, "run-2", "manual")
    assert tool_ctx._session_stack is first


def test_a_teardown_that_raises_still_clears_the_bookkeeping(
        tool_ctx, monkeypatch):
    """The failure mode this guards is a tool layer that can never open a
    session again. With `ctx.session` left set for a session that is gone,
    every later egress run is told `session_held` naming a run that is
    already closed -- recoverable only by restarting `hx mcp`. The raise is
    still allowed out; what it may not do is take the context with it."""
    @contextlib.contextmanager
    def brittle_session(eng, **kw):
        yield FakeLive()
        raise RuntimeError("the JVM would not die")

    monkeypatch.setattr(session_mod, "session", brittle_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")
    with pytest.raises(RuntimeError, match="would not die"):
        live.close_for(tool_ctx, "run-1")
    assert tool_ctx.session is None
    assert tool_ctx._session_run_id is None
    assert tool_ctx._registered == set()

    # And the proof that it matters: the next egress run gets a session
    # rather than being told `session_held` by a run that is already closed.
    monkeypatch.setattr(session_mod, "session", _fake_session)
    assert live.open_for(tool_ctx, "run-2", "manual")["live"] is True


def test_a_gone_that_cannot_answer_is_not_read_as_a_live_session(
        tool_ctx, monkeypatch):
    """`open_for` NEVER RAISES, and the liveness read is inside that promise.
    A `gone()` that throws is not evidence that the holder is alive, so it is
    reported as `owner_alive: False` with the reason in the detail."""
    monkeypatch.setattr(session_mod, "session", _fake_session)
    tool_ctx.stack = contextlib.ExitStack()
    live.open_for(tool_ctx, "run-1", "manual")

    def explode(self):
        raise OSError("no such process")

    tool_ctx.session = type("Broken", (), {"gone": explode})()
    got = live.open_for(tool_ctx, "run-2", "manual")
    assert got["reason"] == "session_held"
    assert got["owner_alive"] is False
    assert "no such process" in got["detail"]


def test_a_launch_that_arrives_dead_reports_rather_than_raising_from_gone(
        tool_ctx, monkeypatch):
    """The dead-session check is guarded, because "NEVER RAISES" is stated
    without qualification and a reader will rely on it -- not on an argument
    that `gone()` happens not to raise.

    AND THE JVM STILL GOES. By the time `gone()` is called the session is
    already on the inner stack, so a guard that only turned the raise into a
    `launch_failed` would leave a live Burp held by a stack nothing closes
    until the adapter exits, with the next `open_for` entering a SECOND
    session beside it.
    """
    torn_down = []

    @contextlib.contextmanager
    def unreadable_session(eng, **kw):
        class Unreadable(FakeLive):
            def gone(self):
                raise OSError("proc table went away")
        try:
            yield Unreadable()
        finally:
            torn_down.append(True)

    monkeypatch.setattr(session_mod, "session", unreadable_session)
    tool_ctx.stack = contextlib.ExitStack()
    got = live.open_for(tool_ctx, "run-1", "manual")
    assert got["live"] is False
    assert got["reason"] == "launch_failed"
    assert "proc table went away" in got["detail"]
    assert tool_ctx.session is None
    assert torn_down == [True], "a session whose liveness is unreadable was left"
```

- [ ] **Step 2: Run to watch it fail**

Run: `.venv/bin/pytest tests/test_tools_live.py -q`
Expected: FAIL — `ImportError: cannot import name 'live' from 'hx.tools'`

- [ ] **Step 3: Add the three `ToolContext` fields**

In `src/hx/tools/dispatch.py`. **No marker** — the file exists. Add `import contextlib` to the imports, and these fields after `session`:

```python
    #: The ADAPTER'S ExitStack, and the reason egress belongs to a long-lived
    #: adapter rather than to `hx tool`. `hx.session.session()` tears Burp
    #: down on EVERY exit, so a JVM launched inside a one-shot `hx tool`
    #: process dies microseconds later -- there is no object in that adapter
    #: for a session to outlive. `hx mcp` is one process for the whole
    #: conversation, opens a stack around its serve loop, and hands it here;
    #: `run.start` pushes the session onto it and `run.finish` pops it. A
    #: crash unwinds the stack, which is spec section 8's "a crash must not
    #: orphan a JVM" -- the FIRST of its three layers, the other two being
    #: `run.reap_stale` and `session()`'s own teardown.
    #:
    #: None means this adapter cannot host a session, which is a different
    #: fact from "no session is open" and is reported as its own reason.
    stack: Any = None
    #: The run that launched the session on `stack`. At most one session at a
    #: time -- see `hx.tools.live`.
    _session_run_id: str | None = dataclasses.field(default=None, repr=False)
    #: `(identity_id, generation)` already registered on THIS session's
    #: extension. `BridgeServer.register_identity` refuses a generation that
    #: does not advance what the extension holds (`stale_generation`), so a
    #: second registration of the same pair is an error, not a no-op. Cleared
    #: with the session, because a new extension has heard of none of them.
    _registered: set = dataclasses.field(default_factory=set, repr=False)
```

- [ ] **Step 4: Write `src/hx/tools/live.py`**

```python
# src/hx/tools/live.py
"""The session bracket: which runs get a Burp, and who owns it.

SPEC SECTION 8 GIVES THE SHAPE. `run.start` opens the bracket and
`run.finish` closes it; an egress tool outside that bracket answers
`unavailable / no_session`. This is "each command owns its own Burp" -- the
rule already chosen for the CLI -- scaled to a session rather than replaced.

FOUR WAYS TO HAVE NO SESSION, AND THEY ARE FOUR DIFFERENT NEXT ACTIONS. That
is why `open_for` returns a reason rather than a bool:

  not_needed     this run kind never wanted one (browse, crawl)
  no_host        this ADAPTER cannot hold one -- use `hx mcp`
  launch_failed  Burp would not start, or started dead
  session_held   another run has it; finish that one

Section 12's rule is that a report which cannot distinguish "tested, clean"
from "never reached" is worse than no report, and the same rule applies to an
agent's knowledge of its own instrument. A single `live: false` would collapse
four distinguishable situations into one shrug -- which is exactly the
argument that registers `crawl.run` rather than omitting it.

A FAILED LAUNCH DOES NOT STOP THE RUN FROM OPENING. Refusing `run.start`
outright would leave no `run` row and no `agent_action` row: no trace that the
instrument failed, on the one call that was trying to set it up. The run
opens, the failure is in the result and in the journal, non-egress work
proceeds, and every egress tool answers `no_session` on its own -- so nothing
false can be concluded from it.
"""
from __future__ import annotations

import contextlib
import os

from .. import identity as identity_mod
from .. import session as session_mod

#: Run kinds that imply traffic this side issues. `browse` is the operator's
#: own browser through `hx capture start`, which owns its own Burp -- spec
#: section 8: "a browse run never needed the tool layer to launch anything".
#: `crawl` is here for completeness and is not in the set, because `crawl.run`
#: is permanently unavailable and a crawl run has nothing to send.
EGRESS_KINDS = frozenset({"manual", "scan"})

#: `hx.session.session`'s `instance`, which names both the `-Dhx.instance` the
#: extension reports and the directory under the engagement root this session
#: owns. Distinct from "capture" and "scan" so an agent's session and an
#: operator's `hx capture start` do not collide on a bridge socket path.
INSTANCE = "tools"


def open_for(ctx, run_id: str, kind: str) -> dict:
    """Launch Burp for a run of this kind, or say why not. NEVER RAISES.

    A raise here would come out of `run.start`, and `dispatch` would render it
    `error / internal` -- "hx is broken" for a Burp that is merely not
    installed. The distinction between a defect and a missing instrument is
    the one this whole return value exists to draw.
    """
    if kind not in EGRESS_KINDS:
        return {"live": False, "reason": "not_needed",
                "detail": f"a {kind} run issues no traffic from this side, "
                          "so it needs no session"}
    if ctx.stack is None:
        return {"live": False, "reason": "no_host",
                "detail": "this adapter is one process per call and cannot "
                          "hold a Burp open across calls: `hx.session."
                          "session()` tears it down on every exit. Run the "
                          "tool layer under `hx mcp`, which is one long-lived "
                          "process, or use the 11 tools that need no session."}
    if ctx.session is not None:
        return _held(ctx)
    try:
        # NESTED, so that `close_for` can unwind the session and NOTHING
        # ELSE. `ctx.stack` is the ADAPTER'S, and Task 8 hands `hx mcp`'s own
        # long-lived stack straight to `build_context` -- anything that
        # adapter ever registers there would otherwise be torn down by an
        # ordinary `run.finish`. Created once per context and reused (see
        # `ToolContext._session_stack`), because a fresh inner stack per
        # session leaves a spent callback on the adapter's stack per session.
        if ctx._session_stack is None:
            ctx._session_stack = ctx.stack.enter_context(contextlib.ExitStack())
        live = ctx._session_stack.enter_context(
            session_mod.session(ctx.engagement, instance=INSTANCE))
    except Exception as exc:            # noqa: BLE001 -- see the docstring
        return {"live": False, "reason": "launch_failed",
                "detail": f"{type(exc).__name__}: {exc}"}
    # A SESSION THAT ARRIVES DEAD IS NOT A SESSION. `gone()` has two ways to
    # be true and only one is a dead JVM: an extension that dropped the
    # bridge reconnects at DENY-ALL, which is a Burp that is up, proxies
    # nothing and records nothing. Handing that back as `live` would give
    # every later tool a session object whose every send is refused.
    #
    # GUARDED, because this function's contract is "NEVER RAISES" without
    # qualification and a reader relies on that rather than on an argument
    # that `gone()` and `close()` happen not to raise today. NOT folded into
    # the `try` above, though, which is the shape that first suggests itself:
    # by this line the session is already ON the inner stack, so a single
    # wide `try` would answer `launch_failed` while leaving a live JVM held
    # by a stack nothing will close until the adapter exits -- and the next
    # `open_for` would enter a SECOND session onto the same stack.
    try:
        dead = live.gone()
    except Exception as exc:            # noqa: BLE001
        # A `gone()` that cannot answer is not evidence of a live session.
        dead = f"its liveness could not be read: {type(exc).__name__}: {exc}"
    if dead is not None:
        try:
            ctx._session_stack.close()
        except Exception as exc:        # noqa: BLE001
            # Reported, not raised, and not hidden either: the teardown of a
            # session that was never handed out is exactly the kind of
            # failure that leaves a JVM behind, so it belongs in the detail
            # an operator reads.
            dead = (f"{dead}; and tearing it down failed too: "
                    f"{type(exc).__name__}: {exc}")
        return {"live": False, "reason": "launch_failed", "detail": dead}
    ctx.session = live
    ctx._session_run_id = run_id
    ctx._registered = set()
    return {"live": True, "operator_port": live.operator_port,
            "crawler_port": live.crawler_port, "epoch": live.epoch}


def _held(ctx) -> dict:
    """`session_held`, and WHETHER THE HOLDER IS STILL ALIVE.

    "Blocked by a live session" and "blocked by a corpse" are different facts
    and only one of them means wait. A JVM that died mid-run leaves
    `ctx.session` set, so every later egress run is refused -- and an agent
    told only `session_held` would keep waiting for a run that will never
    give the instrument back on its own.

    OWNERSHIP IS NOT TAKEN HERE, alive or dead. The run that opened a session
    is the run that closes it; `run.finish` on the owner tears down a corpse
    exactly as it tears down a live one, and a second run helping itself to
    another run's teardown is how two runs come to share an instrument.
    """
    try:
        dead = ctx.session.gone()
    except Exception as exc:            # noqa: BLE001 -- open_for never raises
        # A `gone()` that cannot answer is not evidence of a live session.
        dead = f"its liveness could not be read ({type(exc).__name__}: {exc})."
    owner = ctx._session_run_id
    if dead is None:
        detail = (f"run {owner} holds this engagement's Burp; one session at "
                  "a time. Finish that run first -- a scan and a manual pass "
                  "are different runs and should not share an instrument.")
    else:
        detail = (f"run {owner} holds this engagement's Burp and it is no "
                  f"longer live: {dead} Waiting will not free it -- run.finish "
                  f"on {owner} tears the dead session down, and only the run "
                  "that opened a session may close it.")
    return {"live": False, "reason": "session_held",
            "owner_alive": dead is None, "detail": detail}


def close_for(ctx, run_id: str) -> bool:
    """Tear down the session if this run owns it. True if it did.

    THE SESSION AND ONLY THE SESSION. The stack closed here is
    `_session_stack`, nested inside the adapter's own `ctx.stack` -- because
    Task 8 hands `hx mcp`'s long-lived stack to `build_context`, and anything
    that adapter registers on it (its store, its serve loop's own clean-up)
    must survive an ordinary `run.finish`. Closing the OUTER stack still
    unwinds this one, so a crash kills the JVM either way; what the nesting
    buys is that a routine close does not.

    THE BOOKKEEPING IS CLEARED WHATEVER THE TEARDOWN DOES. If `close()`
    raised and the three assignments below it were skipped, `ctx.session`
    would stay set for a session that is gone, and every later egress run
    would be told `session_held` naming a run that is already closed -- a
    tool layer permanently unable to open a session again, recoverable only
    by restarting `hx mcp`. The raise is still allowed out (`dispatch` renders
    it, and a teardown that failed is worth an `error`); what is not allowed
    is for it to take the context with it.
    """
    if ctx.session is None or ctx._session_run_id != run_id:
        return False
    try:
        ctx._session_stack.close()
    finally:
        ctx.session = None
        ctx._session_run_id = None
        ctx._registered = set()
    return True


def declaration_of(ctx, identity_id: str):
    """The `Identity` this config declares under `identity_id`, or ValueError.

    SPLIT OUT OF `ensure_identity` FOR RULING 16, and it is the whole of the
    check that costs nothing. `ensure_identity` RESOLVES and REGISTERS, and a
    registration can fire the extension's liveness canary against the
    client's application -- so a tool replaying under several identities
    checks EVERY name here first and only then resolves any of them. A typo
    in the third name discovered after the first two had been registered
    would be a typo found after traffic had reached the client, which is the
    thing "resolve before sending" exists to prevent.

    ONE FUNCTION RATHER THAN A SECOND COPY OF THE SENTENCE. The message an
    agent reads for an undeclared name is one message, and a copy is what
    drifts.
    """
    found = ctx.config.identities.get(identity_id)
    if found is None:
        raise ValueError(
            f"identity {identity_id!r} is not declared in this config. "
            f"Declared: {sorted(ctx.config.identities) or 'none'}")
    return found


def ensure_identity(ctx, identity_id: str) -> tuple[str, int]:
    """Resolve and register one identity; return `(id, generation)`.

    THE CREDENTIAL NEVER COMES BACK. Principle 5 puts resolution below the
    tool layer, and this function is that boundary: a `Resolved` is built,
    handed straight to the extension, and dropped. What returns is a name and
    a number, which is what an exchange row stores and what a journal may
    hold.

    REGISTERED ONCE PER (id, generation) PER SESSION.
    `BridgeServer.register_identity` refuses a generation that does not
    advance what the extension already holds -- `stale_generation` -- so a
    second registration of the same pair is an ERROR rather than a no-op, and
    a tool that re-registered on every send would fail on its second one.

    Raises ValueError for an undeclared identity (a caller's mistake, and the
    message lists what IS declared) and BridgeError for a refusal from the
    extension.
    """
    declared = declaration_of(ctx, identity_id)
    resolved = identity_mod.resolve(declared, dict(os.environ))
    key = (resolved.id, resolved.generation)
    if key not in ctx._registered:
        ctx.session.bridge.register_identity(
            resolved, origins=tuple(declared.origins))
        ctx._registered.add(key)
    return key
```

**Note on the unused imports:** `codec` and `BridgeError` are imported for the exception types a caller must handle. If `ruff` flags either as unused, remove it rather than adding a `noqa` — the docstring already names them.

- [ ] **Step 5: Write the identity-registration test**

Add to `tests/test_tools_live.py`. It needs a config carrying a declared identity; find how `tests/test_scan_identity.py` (or whichever suite covers `_identity_bracket`) builds one and follow it, rather than hand-rolling a `Config`.

```python
def test_an_identity_is_registered_once_per_generation(
        tool_ctx, monkeypatch, staff_identity_config):
    """A second registration of the same generation would be refused
    `stale_generation` by the extension, so a tool that re-registered on
    every send would fail on its second one."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()

    first = live.ensure_identity(tool_ctx, "staff")
    second = live.ensure_identity(tool_ctx, "staff")
    assert first == second == ("staff", 1)
    assert len(tool_ctx.session.bridge.identities) == 1


def test_the_credential_never_leaves_this_function(
        tool_ctx, monkeypatch, staff_identity_config):
    """Principle 5. What comes back is a name and a number -- an exchange
    row's worth -- and never a `Resolved`, which a journalled return value
    would put the secret into."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_ctx.config = staff_identity_config
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    tool_ctx._registered = set()
    got = live.ensure_identity(tool_ctx, "staff")
    assert got == ("staff", 1)
    assert "s3cret" not in repr(got)


def test_an_undeclared_identity_names_what_is_declared(
        tool_ctx, staff_identity_config):
    tool_ctx.config = staff_identity_config
    with pytest.raises(ValueError, match="staff"):
        live.ensure_identity(tool_ctx, "nope")
```

- [ ] **Step 6: Wire the bracket into `run.start` and `run.finish`**

In `src/hx/tools/impl/run.py`. **No markers** — the file exists.

`start`, replacing its return:

```python
    run_id = run_mod.open_run(ctx.conn, engagement_id=ctx.engagement.id,
                              kind=kind,
                              safety_profile=ctx.config.safety_profile)
    ctx.run_id = run_id
    # AFTER the run row, deliberately: `open_for` can fail, and a failure
    # that had to be reported with no run to report it against would be a
    # failure with no journal row and no run row -- the one call that was
    # trying to set the instrument up, leaving no trace that it did not.
    return {"id": run_id, "kind": kind,
            "safety_profile": ctx.config.safety_profile,
            "session": live_mod.open_for(ctx, run_id, kind)}
```

`finish`, after the run is closed and before its return, adding `session_closed` to the result dict:

```python
    # THE JVM GOES WITH THE RUN. `run.finish` is the one tool exempt from the
    # halt refusal (`dispatch.HALT_EXEMPT`) precisely so that an operator who
    # has hit STOP can still close the bracket -- and closing the bracket has
    # to include tearing the Burp down, or a halt leaves a live JVM behind
    # with nothing left that is allowed to stop it.
    closed = live_mod.close_for(ctx, run_id)
```

and add `"session_closed": closed` to what `finish` returns.

Import: `from .. import live as live_mod`.

- [ ] **Step 7: Let `build_context` take a stack**

In `src/hx/tools/adapters/cli.py`. **No marker.**

```python
def build_context(engagement, *, stack=None) -> dispatch_mod.ToolContext:
```

with `stack=stack` passed through, and this paragraph replacing the last two sentences of the existing docstring:

```
    `stack` IS NONE FROM THIS ADAPTER AND THAT IS THE HONEST ANSWER, not a
    limitation waiting to be lifted. `hx.session.session()` tears Burp down on
    every exit, so a JVM launched inside a one-shot `hx tool` process dies
    with it -- there is no object here for a session to outlive. `run.start`
    is told so and reports `session: {live: false, reason: "no_host"}`, which
    names `hx mcp` as the adapter that can. The parameter exists because
    `hx mcp` builds its context through this same function.
```

- [ ] **Step 8: Extend the `run.start` / `run.finish` tests**

Add to `tests/test_tools_run.py`: `run.start` on a `manual` run through a context with no stack reports `session.reason == "no_host"` and still returns a run id; `run.finish` reports `session_closed: false` when there was none. Do not re-test `live.open_for`'s branches here — they are Task 3's own suite.

- [ ] **Step 9: Write the integration test**

```python
# tests/integration/test_tool_session.py
"""The bracket against a real Burp.

Everything else about the bracket is proved with a monkeypatched
`session.session`, which is right -- the branches are about bookkeeping. This
file proves the one thing a fake cannot: that `run.start` on a manual run
brings up a JVM whose extension is CONFIGURED, and that `run.finish` takes it
away again.

THE EXITSTACK IS THE TEST'S OWN SAFETY NET AS WELL AS THE PRODUCT'S. It is
the same object `hx mcp` will hand `build_context`, and it is what section 8's
"a crash must not orphan a JVM" rests on first: an assertion that fails
between `run.start` and `run.finish` unwinds it on the way out, which is why
the JVM here cannot outlive a red test. `tests/integration/conftest.py`
records what happens without that discipline -- "a 900 MB JVM per debugging
attempt".

THE SEED HOME IS NOT THE OPERATOR'S. `hx.tools.live.open_for` calls
`session()` with no `seed`, deliberately: a tool layer has no business
choosing which Burp home a consultant's licence lives in. So this test says so
the way an operator would, through `$HX_BURP_SEED_HOME` -- the same override
`tests/integration/test_cli_session.py` gives the `hx capture start`
subprocess, and for the same reason. Without it `make_home` would copy the
developer's real `$HOME`, which on a consultant's machine is live client
project state.
"""
from __future__ import annotations

import contextlib

import pytest

from hx import halt as halt_mod
from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401 -- registers every tool
from tests.integration import burp_fixture as bf

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _prerequisites(monkeypatch):
    """The rig's order: an unbuilt jar FAILS, a missing Burp SKIPS.

    Asking the skip question first would turn a forgotten `extension/build.sh`
    into a silently skipped suite, which is how this project's tests have
    twice gone dark while reporting green.
    """
    if bf.unbuilt():
        pytest.fail("unbuilt: " + ", ".join(bf.unbuilt()))
    if bf.missing():
        pytest.skip("missing: " + ", ".join(bf.missing()))
    monkeypatch.setenv("HX_BURP_SEED_HOME", str(bf.SEED_HOME))


def test_run_start_brings_up_a_configured_burp_and_run_finish_stops_it(
        engagement):
    with contextlib.ExitStack() as stack:
        ctx = dispatch_mod.ToolContext(
            engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
            config=engagement.config,
            halt=halt_mod.OperatorHalt(engagement.root, engagement.db),
            stack=stack)
        env = dispatch_mod.dispatch(ctx, "run.start", {"kind": "manual"},
                                    why="prove the bracket brings up a JVM")
        assert env.outcome == "ok"
        sess = env.result["session"]
        assert sess["live"] is True, sess
        # EPOCH IS NEVER 0 HERE. 0 is what the extension reports at DENY-ALL,
        # and a session that reached this object got a `configure` the
        # extension accepted. An assertion on the ports alone would pass
        # against a Burp that refuses everything.
        assert sess["epoch"] != 0
        assert ctx.session is not None
        proc = ctx.session.proc
        assert proc.poll() is None, "run.start reported a JVM that is not there"

        env = dispatch_mod.dispatch(ctx, "run.finish", {"status": "completed"},
                                    why="close the bracket")
        assert env.outcome == "ok"
        assert env.result["session_closed"] is True
        assert ctx.session is None
        assert proc.poll() is not None, "run.finish left the JVM running"
```

**Before writing this:** read `tests/integration/conftest.py` for the `engagement` and Burp fixtures it actually provides and follow them exactly, including the unbuilt-jar guard. The `halt=...` above is a placeholder — construct `OperatorHalt` the way `tests/conftest.py`'s `tool_ctx` does.

- [ ] **Step 10: Run everything**

```bash
extension/build.sh                                    # the jar must not be stale
.venv/bin/pytest -q
.venv/bin/pytest -m integration -q
.venv/bin/ruff check src tests
```

Expected: unit green; integration 45 passed (44 + the new one). **If the integration run reports `unbuilt: extension jar is older than its sources`, that is the fixture doing its job** — run `extension/build.sh` and re-run. Note that `extension/test.sh` compiles test classes *without* rebuilding the jar, so running it leaves the jar stale.

- [ ] **Step 11: Commit**

```bash
git add src/hx/tools/live.py src/hx/tools/dispatch.py src/hx/tools/impl/run.py \
        src/hx/tools/adapters/cli.py tests/test_tools_live.py \
        tests/test_tools_run.py tests/integration/test_tool_session.py
git commit -m "feat(tools): run.start opens the session bracket

ToolContext.session has been None since Plan A. run.start on a manual or scan
run now launches Burp onto the adapter's ExitStack and run.finish tears it
down; a crash unwinds the stack, which is section 8's first layer against an
orphaned JVM.

Four ways to have no session and they are four different next actions:
not_needed, no_host, launch_failed, session_held. hx tool reports no_host and
names hx mcp, because session() tears Burp down on every exit and a one-shot
process has nothing for a session to outlive."
```

---

## Task 4: `http.send`

The first tool an agent reaches for, and the one every other egress tool is measured against.

**Files:**
- Create: `src/hx/tools/impl/http.py` (this task writes `send` only; Tasks 5 and 6 append to it)
- Modify: `src/hx/tools/impl/__init__.py`
- Test: `tests/test_tools_http.py`
- Test: `tests/integration/test_tool_http.py`

**Interfaces:**
- Consumes: `hx.issue.issue(...) -> Issued`, `hx.issue.IssueRefused`; `hx.delta.against`, `hx.delta.baseline_for`; `hx.tools.live.ensure_identity`; `hx.tools.errors.ToolRefused`, `ToolUnavailable`.
- Produces: the registered tool `http.send`, and the module-level helper `hx.tools.impl.http._digest(ctx, issued) -> dict` that Task 6 reuses.

---

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_tools_http.py
"""The four http.* tools.

WHAT THESE TESTS ARE FOR, given that `tests/test_issue.py` already proves the
send path: the TOOL layer's own obligations. Does a refusal from the wire
arrive as `refused` with the wire's class as the reason, or as `error /
internal`? Does the digest an agent receives carry a payload, in defiance of
Principle 1? Does an argument the schema should have caught reach the handler?
Those are questions about this layer and not about `hx.issue`.
"""
import pytest

from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401 -- registers every tool
from hx.bridge.server import BridgeError

from tests.test_probe import FakeBridge, sent_result


def _with_session(ctx, replies=()):
    """A context whose session is a bridge and nothing else.

    The tools reach `ctx.session.bridge` and never anything else on the
    session, which is worth knowing when reading these: a `LiveSession`'s
    ports, workdir and `proc` belong to the bracket, not to a send.

    `replies` is the queue `FakeBridge.replies` consumes, one per send. The
    double is `tests/test_probe.py`'s -- the project has ONE, and a second
    would be a second idea of what `BridgeServer.send` does.
    """
    bridge = FakeBridge()
    bridge.replies(list(replies))
    ctx.session = type("S", (), {"bridge": bridge})()
    return ctx


def test_send_returns_the_digest_and_not_the_body(tool_run):
    """Principle 1, and the one assertion in this file that is about the
    product's shape rather than its plumbing. A body in the envelope would be
    journalled into `agent_action.result_summary` and would put a client's
    response bytes in a table that is read by whoever asks what the run did."""
    body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>secret</h1>"
    ctx = _with_session(tool_run, [sent_result(body)])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="probe the index")
    assert env.outcome == "ok"
    assert set(env.result) >= {"exchange_id", "status", "bytes", "ms",
                               "content_type", "body_sha256", "first_line",
                               "outcome", "delta_vs_baseline"}
    assert b"secret" not in repr(env.result).encode()


def test_a_scope_denial_is_refused_with_the_wires_own_class(tool_run):
    """Principle 6: the safety profile is enforced in the extension and the
    tool layer merely REPORTS what was refused. `error / internal` here would
    tell the agent hx is broken when in fact hx worked exactly as designed."""
    ctx = _with_session(tool_run,
                        [BridgeError("scope_denied: not in scope",
                                     error_class="scope_denied")])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "evil.test", "port": 80,
                                 "method": "GET", "path": "/a"},
                                why="try an out-of-scope host")
    assert env.outcome == "refused"
    assert env.reason == "scope_denied"


def test_without_a_session_it_is_unavailable_not_an_error(tool_run):
    """The dispatcher's own `needs_egress` guard, which Plan A shipped and
    nothing has ever reached until now: `http.send` is the first registered
    tool with the bit set."""
    tool_run.session = None
    env = dispatch_mod.dispatch(tool_run, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="no session on purpose")
    assert env.outcome == "unavailable"
    assert env.reason == "no_session"


def test_send_without_a_why_is_refused(tool_run):
    """Principle 5. `http.send` mutates -- it puts bytes on a client's
    network -- so `missing_why` fires before anything reaches the wire."""
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"})
    assert env.outcome == "refused"
    assert env.reason == "missing_why"
    assert ctx.session.bridge.requests == [], "a why-less send reached the wire"


def test_send_is_refused_while_the_engagement_is_halted(tool_run):
    """An operator has hit STOP. `http.send` mutates and is not in
    HALT_EXEMPT, so the dispatcher refuses before the handler runs."""
    tool_run.halt.halt("operator stopped the run")
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="should never reach the wire")
    assert env.outcome == "refused"
    assert env.reason == "halted"
    assert ctx.session.bridge.requests == []


@pytest.mark.parametrize("args", [
    {"host": "127.0.0.1", "method": "GET"},                     # no path
    {"host": "127.0.0.1", "method": "GET", "path": "a"},        # not origin-form
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "port": 0},                                                # port floor
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "port": 70000},                                            # port ceiling
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "scheme": "gopher"},                                       # scheme enum
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "headers": "X: 1"},                                        # headers is a list
    {"host": "127.0.0.1", "method": "GET", "path": "/a",
     "nonsense": 1},                                            # additionalProperties
])
def test_bad_arguments_never_reach_the_wire(tool_run, args):
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send", args, why="malformed")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert ctx.session.bridge.requests == []


def test_a_path_carrying_crlf_is_refused_as_bad_args(tool_run):
    """`issue.request_bytes` raises ValueError for this, and the handler must
    turn it into `bad_args` rather than letting it become `error / internal`.
    An agent told hx is broken retries; one told its path is malformed fixes
    the path."""
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a\r\nX: 1"},
                                why="attempt a split")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert ctx.session.bridge.requests == []


def test_an_undeclared_identity_is_refused_and_names_the_declared_ones(
        tool_run):
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a",
                                 "identity": "ghost"},
                                why="use an identity that does not exist")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert "ghost" in (env.detail or "")
    assert ctx.session.bridge.requests == []


def test_an_identity_registration_refused_by_the_wire_carries_its_class(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 13, fix round 1's finding 1. `hx.tools.live.ensure_identity`
    can raise `BridgeError` -- the extension's own liveness canary already
    having answered `identity_dead` for this identity, say -- and not only
    `ValueError`. That must reach the agent as the wire's own class, exactly
    like a send refusal, rather than `error / internal`: told hx is broken,
    an agent would retry the identical send forever instead of re-opening
    its session."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ctx = _with_session(tool_run, [sent_result()])
    ctx.session.bridge.refuse_identity("identity_dead", "canary failed")
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a",
                                 "identity": "staff"},
                                why="identity registration is refused")
    assert env.outcome == "unavailable"
    assert env.reason == "identity_dead"
    assert ctx.session.bridge.requests == [], "send reached the wire anyway"


def test_a_declared_identity_whose_credential_will_not_resolve_is_unavailable(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 13, fix round 1's finding 2. `identity: "staff"` is a perfectly
    valid argument -- the operator's environment is what is missing, and no
    argument the agent can write would fix it, so this is NOT `bad_args`
    (that stays reserved for an UNDECLARED identity name, which the agent
    does control). The detail names the environment variable and must never
    carry its value -- moot here since none was set, but `hx.identity`'s own
    messages are value-free by construction."""
    monkeypatch.delenv("HX_STAFF_TOKEN", raising=False)
    tool_run.config = staff_identity_config
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a",
                                 "identity": "staff"},
                                why="the credential is not in the environment")
    assert env.outcome == "unavailable"
    assert env.reason == "identity_unresolved"
    assert "HX_STAFF_TOKEN" in (env.detail or "")
    assert ctx.session.bridge.requests == [], "send reached the wire anyway"


def test_the_delta_is_null_when_the_surface_has_no_exemplar_yet(tool_run):
    """`null` and not a zero delta: nothing was compared, and a zero delta
    would read as 'identical to normal' about a comparison never made."""
    ctx = _with_session(tool_run, [sent_result()])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/brand-new"},
                                why="first ever request to this path")
    assert env.result["delta_vs_baseline"] is None


def test_a_second_send_to_the_same_surface_gets_a_delta(tool_run):
    """The first send becomes the surface's exemplar; the second is compared
    against it. This is the shape an agent actually uses: baseline, then
    payload."""
    first = b"HTTP/1.1 200 OK\r\n\r\nHello visitor"
    second = b"HTTP/1.1 200 OK\r\n\r\nHello hZq9xK"
    ctx = _with_session(tool_run,
                        [sent_result(first), sent_result(second)])
    args = {"host": "127.0.0.1", "port": 8080, "method": "GET", "path": "/x"}
    dispatch_mod.dispatch(ctx, "http.send", args, why="baseline")
    env = dispatch_mod.dispatch(ctx, "http.send", args, why="payload")
    got = env.result["delta_vs_baseline"]
    assert got is not None
    assert got["new_tokens"] == ["hZq9xK"]


def _refusing(cls: str):
    """One `BridgeError` of a class no `REASON_FOR_CLASS` entry names."""
    return [BridgeError(f"{cls}: mystery", error_class=cls)]


def test_an_unknown_wire_class_does_not_escape_dispatch(tool_run):
    """`dispatch` NEVER RAISES, and an unmapped reason is the one way left
    to make it. MEASURED: `Envelope.__post_init__` raises ValueError for a
    reason outside the closed set, and that raise lands inside `except
    ToolError` where the `except Exception` beside it cannot catch it."""
    ctx = _with_session(tool_run, _refusing("nova_class_from_2027"))
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/a"},
                                why="unknown class")
    assert env.outcome in ("refused", "unavailable")
    assert "nova_class_from_2027" in (env.detail or "")


def _one_exchange_on(ctx, body, *, path):
    """One stored exchange at `path`, sent through a fake bridge; its id.

    THE SESSION IS THE CALLER'S WHEN THERE IS ONE, and that is the whole of
    what this adds over `_one_exchange` below. A replay test queues the
    baseline's reply and its replays' replies in ONE `_with_session` call --
    the ORDER of that queue is the fact under test, since the whole point of
    `http.replay_as` is that the answers DIFFER -- so opening a second
    session here would throw the queue away and leave the replay sending into
    a bridge with nothing left to say.
    """
    if ctx.session is None:
        ctx = _with_session(ctx, [sent_result(body)])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": path},
                                why="set up a body to read")
    return env.result["exchange_id"]


def _one_exchange(ctx, body=b"HTTP/1.1 200 OK\r\n\r\nneedle in a haystack"):
    """Send one request through a fake bridge and return its exchange id."""
    return _one_exchange_on(ctx, body, path="/hay")


def test_grep_finds_a_literal_and_reports_its_offset(tool_run):
    """The offset is the whole point: `http.body(range)` is the escape hatch
    used AFTER a match yields one."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "needle"})
    assert env.outcome == "ok"
    row = env.result["rows"][0]
    assert row["exchange_id"] == xid
    assert row["part"] == "response"
    assert isinstance(row["offset"], int)
    assert "needle" in row["match"]


def test_grep_that_matches_nothing_is_empty_not_ok(tool_run):
    """Principle 4. `empty` says the search ran and found nothing; `ok` with
    zero rows would be indistinguishable from a search that never ran."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "absent"})
    assert env.outcome == "empty"


def test_grep_searches_the_request_when_asked(tool_run):
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "/hay",
                                 "part": "request"})
    assert env.outcome == "ok"
    assert env.result["rows"][0]["part"] == "request"


def test_grep_needs_no_session(tool_run):
    """It reads the blob store, which is on this side. An agent that has
    finished its run can still read what it captured -- and a tool marked
    needs_egress would have refused that."""
    xid = _one_exchange(tool_run)
    tool_run.session = None
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "needle"})
    assert env.outcome == "ok"


def test_grep_reports_which_exchanges_it_could_not_read(tool_run):
    """Section 12 inside one envelope, AND Ruling 14's partial case.

    One exchange is readable and one is not, so the search RAN -- `ok`, not
    `unavailable` -- and both halves must be true at once: the readable
    exchange's match still surfaces in `rows`, and the unreadable one is
    named in the facet rather than silently folded into "no matches". A
    facet that said `0 matches` about both would be the report that cannot
    distinguish tested from unreached, and a test that checked only the
    facet -- as this one used to -- would not catch a regression that
    dropped the real match while still populating `unreadable`."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid, "x-nonexistent"],
                                 "pattern": "needle"})
    assert env.outcome == "ok"
    assert env.result["rows"][0]["exchange_id"] == xid
    assert env.result["rows"][0]["match"] == "needle"
    assert env.result["facets"]["unreadable"] == ["x-nonexistent"]


def test_grep_over_only_unreadable_exchanges_is_unavailable_not_empty(
        tool_run):
    """Ruling 14. `empty` is `envelope.answered`'s reading of a zero-row
    page and means "I searched and found nothing" -- an agent told `empty`
    moves on, which is exactly wrong when nothing was searchable at all.
    `unavailable` is the outcome whose job is to say the tool could not run,
    and that is precisely what happened when every requested exchange is
    unreadable. The `unreadable` facet alone is not enough: it is not the
    field an agent branches on."""
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": ["x-nope1", "x-nope2"],
                                 "pattern": "needle"})
    assert env.outcome == "unavailable"
    assert env.reason == "unreadable"


def test_body_returns_a_bounded_range_and_the_total(tool_run):
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 0, "length": 8})
    assert env.outcome == "ok"
    assert len(env.result["bytes"]) == 8
    # THE TOTAL IS ALWAYS THERE, so an agent knows whether it has the whole
    # thing. A range with no total is a window with no idea how far the room
    # extends.
    assert env.result["total"] > 8


def test_body_past_the_end_answers_ok_with_zero_length_and_the_real_total(
        tool_run):
    """Reading past the end is a legitimate way to discover the end, so it is
    not an error -- and it is not `empty` either.

    `empty` IS PRINCIPLE 3's LIST VOCABULARY and `http.body` returns no list.
    `envelope.answered` reads `empty` off a page envelope's `total == 0`, so
    spelling this `empty` would mean reporting `total: 0` for a body that is
    5 KB long -- a lie about the one number an agent needs in order to know
    it has read the whole thing. `ok` with `length: 0` and the true `total`
    says exactly what happened and where the end is."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 99999,
                                 "length": 10})
    assert env.outcome == "ok"
    assert env.result["length"] == 0
    assert env.result["total"] > 0


def test_body_of_an_unknown_exchange_is_refused(tool_run):
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": "x-nope", "start": 0,
                                 "length": 8})
    assert env.outcome == "refused"
    assert env.reason == "bad_args"


def test_a_binary_body_round_trips_rather_than_becoming_question_marks(
        tool_run):
    """Latin-1 is chosen for exactly this: every byte maps to one character
    and back. A UTF-8 decode with `errors='replace'` would turn a binary
    body into a string of U+FFFD an agent then greps for a payload it can
    never find."""
    raw = b"HTTP/1.1 200 OK\r\n\r\n\x00\x80\xff\xfe"
    xid = _one_exchange(tool_run, raw)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 0,
                                 "length": 64, "part": "response"})
    assert env.result["bytes"].encode("latin-1") == raw


def test_grep_reports_a_corrupt_blob_as_unavailable_not_internal_error(
        tool_run):
    """`_blobs_for`'s own docstring says a blob the store cannot return is
    covered by the same None it returns for a missing row -- so a corrupt
    blob must land the exchange in `unreadable`, not blow up as
    `error / internal`. `error / internal` here would tell an agent hx is
    broken when in fact one stored blob failed its digest check.

    The one exchange requested is the one that is corrupt, so by Ruling 14
    this is the all-unreadable case: `unavailable / unreadable`, not
    `empty` -- the tool could not run, which is a different fact from
    running and finding nothing."""
    from hx.store.blobs import CorruptBlob

    xid = _one_exchange(tool_run)
    real_get = tool_run.blobs.get

    def _corrupt(digest, expected_len=None):
        raise CorruptBlob(f"blob {digest} failed digest verification")

    tool_run.blobs.get = _corrupt
    try:
        env = dispatch_mod.dispatch(tool_run, "http.grep",
                                    {"exchange_ids": [xid],
                                     "pattern": "needle"})
    finally:
        tool_run.blobs.get = real_get
    assert env.outcome == "unavailable"
    assert env.reason == "unreadable"


def _also(config, name, header):
    """`config` with a SECOND declared identity, so that a two-identity
    replay is two identities and not one identity twice.

    `staff_identity_config` declares one, which is all Tasks 3 and 4 needed.
    Section 12's rule inside one result -- "two identities, one answer and
    one rate limit" must stay distinguishable from "two identities, one
    answer" -- is a claim about a row that is NOT the first, and a fixture
    with one identity cannot make it.
    """
    import dataclasses

    from hx import config as config_mod

    ident = config_mod.Identity(
        id=name, strategy="static",
        inject=config_mod.Inject(header=header,
                                 value_from_env=f"HX_{name.upper()}_TOKEN"),
        liveness=config_mod.Liveness(path="/account", expect_body="Sign out",
                                     expect_absent="Sign in"),
        origins=("https://app.test/",))
    return dataclasses.replace(
        config, identities={**config.identities, name: ident})


def test_replay_as_returns_one_row_per_identity_plus_the_baseline(
        tool_run, staff_identity_config, monkeypatch):
    """The shape an authz finding is written from: same request, several
    sessions, one column of differences."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    denied = b"HTTP/1.1 403 Forbidden\r\n\r\nno"
    ctx = _with_session(tool_run,
                        [sent_result(ok), sent_result(denied, status=403)])
    xid = _one_exchange_on(ctx, ok, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"]},
        why="check whether /admin is reachable as staff")
    assert env.outcome == "ok"
    rows = env.result["rows"]
    assert [r["identity"] for r in rows] == ["staff"]
    assert rows[0]["digest"]["status"] == 403
    assert rows[0]["differs"] is True


def test_the_replayed_path_comes_from_the_request_line_not_the_redacted_url(
        tool_run, staff_identity_config, monkeypatch):
    """The trap `_parts_of` exists for. `records.redact_url` runs on EVERY
    write to `exchange.url`, so the stored url for a request carrying
    `?token=` holds `{{observed:param}}` where the credential was. Replaying
    THAT path would put a placeholder on the wire -- a different request from
    the one under investigation, answered differently, and the difference
    reported as an authorisation finding. The stored request BLOB is not
    rewritten by that rule, so its own request line is the one to re-issue.

    The origin still comes from the url, because an origin-form request line
    carries none -- which is the half that looks like an inconsistency."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin/users?token=abc123")
    stored_url, = ctx.conn.execute(
        "SELECT url FROM exchange WHERE id=?", (xid,)).fetchone()
    assert "abc123" not in stored_url, \
        "the url was never redacted, so this test proves nothing"

    dispatch_mod.dispatch(ctx, "http.replay_as",
                          {"exchange_id": xid, "identities": ["staff"]},
                          why="replay the admin listing as staff")
    replayed = ctx.session.bridge.bodies[-1]
    assert replayed.startswith(b"GET /admin/users?token=abc123 HTTP/1.1\r\n")
    assert b"observed:param" not in replayed
    # And to the same origin, taken from the url rather than from the
    # origin-form request line, which carries none.
    sent = ctx.session.bridge.requests[-1]
    assert (sent["target_host"], sent["target_port"]) == ("127.0.0.1", 8080)


def test_an_identity_header_in_the_stored_request_is_never_replayed(
        tool_run, staff_identity_config, monkeypatch):
    """THE LOAD-BEARING RULE OF THIS TOOL. `staff` injects `Cookie` and the
    stored request already carries one. Replayed verbatim, the original
    session's cookie would go out under staff's name: the application would
    answer both replays as the SAME session, every row would come back
    identical, and the tool would report "no difference" for two sessions
    that were never two. An authorisation finding gets written from these
    rows.

    The `X-Trace` half is the other direction and is not decoration: a
    replay that dropped every header would be equally wrong, and would send
    a request the agent never captured."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    env = dispatch_mod.dispatch(
        ctx, "http.send",
        {"host": "127.0.0.1", "port": 8080, "method": "GET", "path": "/admin",
         "headers": ["Cookie: session=alice", "X-Trace: 7"]},
        why="capture a request that carries a session cookie")
    xid = env.result["exchange_id"]
    assert b"Cookie: session=alice" in ctx.session.bridge.bodies[0], \
        "the fixture never put the cookie on the wire, so nothing is proven"

    dispatch_mod.dispatch(ctx, "http.replay_as",
                          {"exchange_id": xid, "identities": ["staff"]},
                          why="replay /admin as staff")
    replayed = ctx.session.bridge.bodies[-1]
    assert b"session=alice" not in replayed
    assert b"Cookie" not in replayed
    assert b"X-Trace: 7" in replayed, \
        "a replay that drops a header no identity injects sends a request " \
        "the agent never captured"


def test_include_anonymous_adds_an_unauthenticated_row(
        tool_run, staff_identity_config, monkeypatch):
    """Its own boolean, not a magic identity name. The unauthenticated
    comparison is the single most valuable row in an authz table, and a
    reserved string could collide with a name an operator declared."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    away = b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok),
                                   sent_result(away, status=302)])
    xid = _one_exchange_on(ctx, ok, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"],
         "include_anonymous": True},
        why="compare staff against anonymous")
    assert [r["identity"] for r in env.result["rows"]] == ["staff", None]
    # UNAUTHENTICATED ON THE WIRE, not merely labelled so. `hx.issue` omits
    # `identity_id` entirely rather than sending a null, because an absent
    # key is what the extension reads as anonymous.
    staff_send, anon_send = ctx.session.bridge.requests[-2:]
    assert staff_send["identity_id"] == "staff"
    assert "identity_id" not in anon_send


def test_replay_of_an_unknown_exchange_is_refused_before_any_send(tool_run):
    ctx = _with_session(tool_run, [])
    env = dispatch_mod.dispatch(ctx, "http.replay_as",
                                {"exchange_id": "x-nope",
                                 "identities": ["staff"]},
                                why="replay something that is not there")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert ctx.session.bridge.requests == []


def test_an_undeclared_identity_is_refused_before_any_identity_registers(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 16. Every name is CHECKED before any name is RESOLVED, and both
    happen before anything sends.

    `bridge.identities` is the half that `bridge.requests` cannot see:
    `ensure_identity` registers with the extension, whose liveness canary is
    itself traffic against the client's application, so a typo in the second
    name found after the first had been registered is still a typo found
    after the client had been touched. An empty `requests` alone would let
    that regression through."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    sent_before = len(ctx.session.bridge.requests)

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff", "ghost"]},
        why="one good name and one typo")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert "ghost" in (env.detail or "")
    assert len(ctx.session.bridge.requests) == sent_before, \
        "staff's replay reached the wire before the typo was found"
    assert ctx.session.bridge.identities == [], \
        "staff was registered -- and its canary fired -- before the typo " \
        "in the second name was found"


def test_one_identitys_refusal_does_not_lose_the_others(
        tool_run, staff_identity_config, monkeypatch):
    """A rate limit on the second identity must not discard the first
    identity's answer. Section 12 again: 'two identities, one answer, one
    refusal' and 'two identities, one answer' are different facts."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    monkeypatch.setenv("HX_AUDITOR_TOKEN", "an0ther")
    tool_run.config = _also(staff_identity_config, "auditor", "Authorization")
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [
        sent_result(ok), sent_result(ok),
        BridgeError("rate_limited: slow down", error_class="rate_limited")])
    xid = _one_exchange_on(ctx, ok, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff", "auditor"]},
        why="compare staff against auditor")
    assert env.outcome == "ok"
    rows = env.result["rows"]
    assert [r["identity"] for r in rows] == ["staff", "auditor"]
    assert rows[0]["digest"] is not None
    assert rows[1]["digest"] is None
    assert rows[1]["refused"] == "rate_limited"


def test_an_original_with_no_stored_response_compares_against_nothing(
        tool_run, staff_identity_config, monkeypatch):
    """`resp_blob` is NULL for an exchange whose body was shed and for one
    whose transport failed before a response existed. Diffing against `b""`
    there would report a length delta and `differs: true` on EVERY row -- an
    authorisation difference on every single call, which is the one claim
    this tool must never make wrongly. `null` says the comparison was not
    made, exactly as `delta.new_tokens` is null rather than `[]` when the
    bodies were too large to diff, and the facet names the reason."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    ctx.conn.execute(
        "UPDATE exchange SET resp_blob=NULL, resp_len=NULL WHERE id=?", (xid,))

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as", {"exchange_id": xid, "identities": ["staff"]},
        why="replay an exchange whose response was never stored")
    assert env.outcome == "ok"
    row = env.result["rows"][0]
    # The replay still happened and its digest is still worth having.
    assert row["digest"]["status"] == 200
    assert row["differs"] is None
    assert row["diff_vs_original"] is None
    assert env.result["facets"]["original_body_stored"] is False


def test_a_corrupt_request_blob_is_unavailable_and_reaches_no_wire(
        tool_run, staff_identity_config, monkeypatch):
    """A blob that fails its own digest check is not a bad argument and it is
    not a defect in hx: `unavailable / unreadable`, the same answer
    `http.grep` gives for the same failure. And nothing may reach a client's
    application on the way to finding out."""
    from hx.store.blobs import CorruptBlob

    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    sent_before = len(ctx.session.bridge.requests)
    real_get = ctx.blobs.get

    def _corrupt(digest, expected_len=None):
        raise CorruptBlob(f"blob {digest} failed digest verification")

    ctx.blobs.get = _corrupt
    try:
        env = dispatch_mod.dispatch(
            ctx, "http.replay_as",
            {"exchange_id": xid, "identities": ["staff"]},
            why="replay an exchange whose request blob is corrupt")
    finally:
        ctx.blobs.get = real_get
    assert env.outcome == "unavailable"
    assert env.reason == "unreadable"
    assert len(ctx.session.bridge.requests) == sent_before


def test_replay_needs_a_why_and_a_session(tool_run):
    """It mutates -- it puts N more requests on a client's network -- and it
    needs egress."""
    ctx = _with_session(tool_run, [])
    args = {"exchange_id": "x-nope", "identities": ["staff"]}
    env = dispatch_mod.dispatch(ctx, "http.replay_as", args)
    assert env.outcome == "refused"
    assert env.reason == "missing_why"
    assert ctx.session.bridge.requests == []

    bridge = ctx.session.bridge
    ctx.session = None
    env = dispatch_mod.dispatch(ctx, "http.replay_as", args,
                                why="no session on purpose")
    assert env.outcome == "unavailable"
    assert env.reason == "no_session"
    assert bridge.requests == []


def test_a_stale_content_length_is_recomputed_rather_than_replayed(
        tool_run, staff_identity_config, monkeypatch):
    """A stored request whose `Content-Length` disagrees with its stored body
    -- a proxy observation whose body was shed, say -- is exactly what
    `issue.request_bytes` REFUSES: a Content-Length that does not match its
    body is a request-smuggling primitive, not a typo to correct silently.
    So the header is dropped and recomputed from the body actually being
    sent, and the replay happens. Replayed verbatim it would refuse instead,
    and an authz question would go unanswered over a header nobody read."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    stale = (b"POST /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n"
             b"Content-Length: 99\r\n\r\nx=1")
    digest, _len = ctx.blobs.put(stale)
    ctx.conn.execute(
        "UPDATE exchange SET req_blob=?, method='POST' WHERE id=?",
        (digest, xid))

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as", {"exchange_id": xid, "identities": ["staff"]},
        why="replay a request whose stored Content-Length is stale")
    assert env.outcome == "ok"
    replayed = ctx.session.bridge.bodies[-1]
    assert b"Content-Length: 3\r\n" in replayed
    assert b"Content-Length: 99" not in replayed
    assert replayed.endswith(b"\r\n\r\nx=1")


def _dated(body, *, date, cookie):
    """One response whose HEAD is unique and whose BODY is not.

    `Date:` and a per-session `Set-Cookie` are the two headers that differ
    between any two replies to one request, which is exactly what makes
    comparing whole responses report a difference every time.
    """
    return (b"HTTP/1.1 200 OK\r\nDate: " + date + b"\r\nSet-Cookie: s="
            + cookie + b"\r\nContent-Type: text/html\r\n\r\n" + body)


def test_replies_differing_only_in_date_and_cookie_do_not_differ(
        tool_run, staff_identity_config, monkeypatch):
    """TRAP 4, and `replay_as`'s own comment calls it the one answer this
    tool must never give wrongly. Two replays of one request differ in their
    `Date:` and their per-session `Set-Cookie` even when the application
    returned byte-identical content, so a comparison over WHOLE responses
    reports an authorisation difference on EVERY single call -- and an
    authz finding gets written from these rows.

    `differs is False` is the assertion, not `not differs`: null is "not
    computed" and would satisfy a falsiness check while meaning the
    opposite."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    page = b"admin panel, unchanged"
    ctx = _with_session(tool_run, [
        sent_result(_dated(page, date=b"Mon, 01 Sep 2026 00:00:00 GMT",
                           cookie=b"aaaaaa")),
        sent_result(_dated(page, date=b"Mon, 01 Sep 2026 00:00:07 GMT",
                           cookie=b"bbbbbb")),
        sent_result(_dated(page, date=b"Mon, 01 Sep 2026 00:00:09 GMT",
                           cookie=b"cccccc"))])
    xid = _one_exchange_on(ctx, page, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"],
         "include_anonymous": True},
        why="two sessions that are shown the same page")
    rows = env.result["rows"]
    assert [r["identity"] for r in rows] == ["staff", None]
    assert rows[0]["differs"] is False
    assert rows[1]["differs"] is False
    assert rows[0]["diff_vs_original"]["len_delta"] == 0
    assert rows[1]["diff_vs_original"]["len_delta"] == 0


def test_a_credential_header_no_identity_declares_is_never_replayed(
        tool_run, staff_identity_config, monkeypatch):
    """RULING 15, and the half the declared set cannot reach. `staff` injects
    `Cookie`, so an `Authorization` in the stored request is named by NO
    declared identity -- and it is exactly what a request lifted from Burp's
    history carries, which `Sender.java` itself names as the natural agent
    action.

    Replayed verbatim, the extension refuses it as `unmanaged_credential`
    before the Gate, so every row comes back refused and no authz table can
    be built at all. `FakeBridge` implements no such check, which is why the
    SENT BYTES are what this asserts on rather than the envelope."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok), sent_result(ok)])
    env = dispatch_mod.dispatch(
        ctx, "http.send",
        {"host": "127.0.0.1", "port": 8080, "method": "GET", "path": "/admin",
         "headers": ["Authorization: Bearer alices-token", "X-Trace: 7"]},
        why="capture a request lifted from history, bearer and all")
    xid = env.result["exchange_id"]
    assert b"alices-token" in ctx.session.bridge.bodies[0], \
        "the fixture never put the bearer on the wire, so nothing is proven"

    dispatch_mod.dispatch(ctx, "http.replay_as",
                          {"exchange_id": xid, "identities": ["staff"]},
                          why="replay /admin as staff")
    replayed = ctx.session.bridge.bodies[-1]
    assert b"alices-token" not in replayed
    assert b"Authorization" not in replayed
    assert b"X-Trace: 7" in replayed, \
        "a replay that drops a header carrying no credential sends a " \
        "request the agent never captured"


def test_more_identities_than_the_bound_is_refused_not_silently_truncated(
        tool_run, staff_identity_config, monkeypatch):
    """The schema's `maxItems` already holds this, so the handler's own guard
    is unreachable through `dispatch` -- which is why it is asserted against
    the handler directly. A SLICE is the wrong shape for a bound whose whole
    subject is blast radius: it would drop the identities past the eighth and
    return a complete-looking table that never asked about them."""
    from hx.tools.errors import ToolRefused
    from hx.tools.impl import http as http_mod

    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    ctx = _with_session(tool_run, [sent_result(ok)])
    xid = _one_exchange_on(ctx, ok, path="/admin")
    sent_before = len(ctx.session.bridge.requests)

    with pytest.raises(ToolRefused) as caught:
        http_mod.replay_as(
            ctx, exchange_id=xid,
            identities=["staff"] * (http_mod.MAX_IDENTITIES + 1))
    assert caught.value.reason == "bad_args"
    assert len(ctx.session.bridge.requests) == sent_before
```

- [ ] **Step 2: Run to watch it fail**

Run: `.venv/bin/pytest tests/test_tools_http.py -q`
Expected: FAIL — every case refused `not_registered`, because `http.send` is not a tool yet. That is the right first failure: it proves the dispatcher's registry gate is what stands between an agent and an unimplemented name.

- [ ] **Step 3: Write `src/hx/tools/impl/http.py`**

```python
# src/hx/tools/impl/http.py
"""The four ways an agent touches the wire and what it got back.

PRINCIPLE 1 IS THE SHAPE OF THIS MODULE: handles and digests, never payloads.
`send` and `replay_as` return a digest; `grep` and `body` are how the bytes
behind a digest are read, and they are separate tools precisely so that
reading is a decision an agent makes and a journal records, rather than
something that happens to every response whether or not anyone wanted it.

PRINCIPLE 2 IS WHY `grep` COMES BEFORE `body`. An agent does not know where in
a 1.2 MB bundle the interesting bytes are, so match-addressed reading is the
documented default and `body(range)` is the escape hatch used AFTER a match
yields an offset.

PRINCIPLE 6 IS WHY ALMOST NOTHING HERE DECIDES ANYTHING. Scope, method,
dangerous paths, rate and budget are the extension's, and this module's whole
job on a refusal is to report the class the wire answered with. A refusal
translated into `error / internal` would tell an agent hx is broken at the
exact moment hx worked as designed.
"""
from __future__ import annotations

from ... import config as config_mod
from ... import delta as delta_mod
from ... import http_text
from ... import identity as identity_mod
from ... import issue as issue_mod
from ...bridge.server import BridgeError
from ...store.blobs import CorruptBlob
from .. import envelope, live, registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: Latin-1 everywhere bytes become text in a return value, and it is a
#: deliberate choice rather than a default. It is the only codec that maps
#: every byte to exactly one character and back, so a response no UTF-8
#: decoder could read still round-trips through a JSON envelope -- and a
#: binary body does not silently become a string of replacement characters
#: that an agent then greps for a payload it will never find.
TEXT = "latin-1"

#: The methods the tool layer will compose. Not a security control -- the
#: extension's `method.allow` is that, and it is checked again in the JVM --
#: but a list an agent can read off `tools/list` beats a 400 from a peer.
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

#: One megabyte of request body. `hx.tools.journal` spills arguments over 4 KB
#: to the blob store, so a large body costs a blob rather than a giant
#: `agent_action` row -- this cap is about the WIRE, not the journal.
MAX_BODY = 1024 * 1024

#: The extension's error classes, placed in the envelope's closed vocabulary.
#: A class this build has never seen must NOT reach `Envelope` unmapped: the
#: constructor raises for an unknown reason, and that raise lands inside
#: `dispatch`'s `except ToolError` handler where the `except Exception` beside
#: it cannot catch it -- so it escapes `dispatch`, which never raises. A new
#: class from a future extension would take the call out with a traceback and
#: write no journal row, which is the one failure this layer is built to make
#: impossible. The fallback keeps the raw class in `detail`, so nothing is
#: lost and nothing crashes.
REASON_FOR_CLASS = {
    "scope_denied": ("refused", "scope_denied"),
    "method_denied": ("refused", "method_denied"),
    "dangerous_denied": ("refused", "dangerous_denied"),
    "rate_limited": ("refused", "rate_limited"),
    "budget_exhausted": ("refused", "budget_exhausted"),
    "bad_frame": ("refused", "bad_frame"),
    "halted": ("refused", "halted"),
    # An identity the extension's own liveness canary has declared dead: a
    # `register_identity` refusal, not a send refusal -- the one class this
    # table maps that never comes off `issue()`. See `send`'s
    # `except BridgeError` below.
    "identity_dead": ("unavailable", "identity_dead"),
    "not_configured": ("unavailable", "not_configured"),
    "bridge_lost": ("unavailable", "bridge_lost"),
    "transport_error": ("unavailable", "transport_error"),
    "timeout": ("unavailable", "timeout"),
}
UNKNOWN_CLASS = ("unavailable", "transport_error")


def _raise_for_class(reason: str, detail: str, cause: BaseException) -> None:
    """Turn a wire error class into the right `ToolError` subclass.

    SHARED by `send`'s two wire-refusal sites: `issue_mod.IssueRefused` for
    the request itself, and `BridgeError` for an identity registration the
    extension refused -- its liveness canary already having answered
    `identity_dead` for this identity, for one. Both are "the wire decided
    something", so both go through the same table.

    PRINCIPLE 6: the class is the wire's, unchanged, so an agent that gets
    `dangerous_denied` learns the profile refused it and one that gets
    `rate_limited` learns to slow down -- two different next actions that a
    single `error` would have made one. An identity refusal told as `error /
    internal` is the same defect from the other side: an agent that reads
    "hx is broken" retries the identical send forever instead of re-opening
    its session, and the report counts an instrument event -- the canary
    tripping -- as an internal defect in hx.

    A CLASS NOT IN `REASON_FOR_CLASS` falls back to `UNKNOWN_CLASS` rather
    than raising `ValueError` out of `Envelope.__post_init__` -- see this
    module's own comment on the table above. The raw class is prefixed onto
    the detail whenever the fallback fires, so an operator reading the
    journal can still see what the extension actually said even though this
    build has no name for it.
    """
    outcome, mapped = REASON_FOR_CLASS.get(reason, UNKNOWN_CLASS)
    if reason not in REASON_FOR_CLASS:
        detail = f"[unmapped class {reason!r}] {detail}".rstrip()
    cls = ToolRefused if outcome == "refused" else ToolUnavailable
    raise cls(mapped, detail) from cause


def _digest(ctx, issued) -> dict:
    """Section 8's digest for one `Issued`, including its delta.

    The bytes never appear. `issued.body` exists so this function can diff
    against the baseline's body without a round trip to the blob store
    `issue` just wrote, and it stops here.

    ONE SURFACE LOOKUP, THEN `delta.baseline_for` DOES THE REST. A first
    version of this function ran a second query here to find the surface's
    `exemplar_exchange_id` and compare it in Python against `issued.
    exchange_id`, to stop a brand-new surface's first exchange from being
    diffed against itself. `hx.issue.issue` sets that exemplar to exactly
    this exchange, inside its own transaction, before it returns -- so the
    guard is real, but the second query was a call-site workaround for
    something `baseline_for` can rule out in the query it already runs. It
    now takes `exclude_exchange_id` and does that itself.
    """
    row = ctx.conn.execute(
        "SELECT surface_id FROM exchange WHERE id=?",
        (issued.exchange_id,)).fetchone()
    base = None
    if row is not None and row[0] is not None:
        base = delta_mod.baseline_for(
            ctx.conn, ctx.blobs, row[0],
            exclude_exchange_id=issued.exchange_id)
    return {
        "exchange_id": issued.exchange_id,
        "status": issued.status,
        "bytes": issued.bytes,
        "ms": issued.ms,
        "outcome": issued.outcome,
        "content_type": issued.content_type,
        "body_sha256": issued.body_sha256,
        "first_line": issued.first_line,
        "delta_vs_baseline": (
            None if base is None
            else delta_mod.against(base[0], base[1], issued.status,
                                   issued.body)),
    }


def send(ctx, *, host: str, method: str, path: str, port: int = 80,
         scheme: str = "http", headers=None, body: str | None = None,
         identity: str | None = None) -> dict:
    """Issue one request and return its digest."""
    ident = None
    if identity is not None:
        try:
            ident = live.ensure_identity(ctx, identity)
        except ValueError as exc:
            # AN UNDECLARED IDENTITY IS THE AGENT'S MISTAKE, not a defect.
            # `bad_args` puts it beside a malformed path, which is where an
            # agent will look for it; `error / internal` would put it beside
            # a crash. Distinct from the two exceptions below: `identity:
            # "ghost"` is an argument the agent wrote and can correct.
            raise ToolRefused("bad_args", str(exc)) from exc
        except identity_mod.IdentityError as exc:
            # RULING 13. A DECLARED identity whose credential will not
            # resolve is a DIFFERENT mistake from an undeclared one:
            # `identity: "staff"` is a perfectly valid argument, and no
            # argument the agent can write fixes an operator's unset
            # `HX_STAFF_TOKEN`. `refused` would say the agent's call was
            # wrong; `unavailable` says the instrument -- the credential --
            # was not there, which is what an operator who forgot an
            # `export` needs to be told. `hx.identity`'s messages are
            # already value-free (they name the environment variable, never
            # its value), so the message is passed through rather than
            # composed anew.
            raise ToolUnavailable("identity_unresolved", str(exc)) from exc
        except BridgeError as exc:
            # The extension refused the REGISTRATION itself -- see
            # `_raise_for_class`'s docstring for why this goes through the
            # same table as a send refusal rather than becoming `error /
            # internal`.
            cls_ = exc.error_class or "transport_error"
            detail = str(exc).removeprefix(f"{cls_}: ")
            _raise_for_class(cls_, detail, exc)
    try:
        issued = issue_mod.issue(
            ctx.session.bridge, ctx.conn, ctx.blobs, ctx.config,
            engagement_id=ctx.engagement.id, run_id=ctx.run_id,
            scheme=scheme, host=host, port=port, method=method, path=path,
            headers=tuple(headers or ()),
            body=(body or "").encode(TEXT), identity=ident)
    except ValueError as exc:
        # `request_bytes` raises this for a request that could be split, and
        # the schema cannot catch it: a CR inside a string is a valid string.
        raise ToolRefused("bad_args", str(exc)) from exc
    except issue_mod.IssueRefused as exc:
        _raise_for_class(exc.reason, exc.detail or "", exc)
    return _digest(ctx, issued)


registry.register(spec.ToolSpec(
    name="http.send", handler=send, needs_egress=True, mutates=True,
    summary="Issue one HTTP request through the extension and return its "
            "digest -- never its body. Use http.grep to read what came back.",
    params={"type": "object", "additionalProperties": False,
            "required": ["host", "method", "path"], "properties": {
                "host": {"type": "string", "minLength": 1, "maxLength": 253,
                         "description": "target host; scope is enforced in "
                                        "the extension, not here"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                         "description": "default 80"},
                "scheme": {"type": "string", "enum": ["http", "https"],
                           "description": "default http"},
                "method": {"type": "string", "enum": METHODS},
                "path": {"type": "string", "minLength": 1, "maxLength": 4096,
                         "description": "origin-form, starts with '/', "
                                        "percent-encoded"},
                "headers": {"type": "array", "maxItems": 64,
                            "items": {"type": "string", "maxLength": 8192},
                            "description": "wire lines, 'Name: value'. A Host "
                                           "header is added if you omit one."},
                "body": {"type": "string", "maxLength": MAX_BODY,
                         "description": "request body, latin-1"},
                "identity": {"type": "string", "maxLength": 64,
                             "description": "the NAME of an identity declared "
                                            "in config.yaml. The credential "
                                            "is resolved and injected below "
                                            "this layer; you never handle it."},
            }}))


#: `both` is the default because an agent looking for its own payload does
#: not always know which half reflected it -- a header echoed into a
#: response, a parameter echoed into the request log.
PARTS = ["request", "response", "both"]

CONTEXT_DEFAULT = 64
CONTEXT_MAX = 512
#: 64 KB per `http.body` call. Above this an agent should be grepping.
RANGE_MAX = 64 * 1024
#: Exchanges per grep. Bounded because each one is a whole body read out of
#: the blob store into memory in the one process that also holds the Burp.
MAX_EXCHANGES = 50


def _blobs_for(ctx, exchange_id, part):
    """`[(part_name, bytes)]` for one exchange, or None if it is not there.

    None covers every way there is nothing to read -- no such row, a NULL
    blob, a blob the store cannot return -- because all three are "this
    exchange cannot be searched", and a caller that told them apart would be
    reporting on hx's bookkeeping rather than on the traffic. A per-part
    `CorruptBlob` (digest mismatch, missing file) is caught here rather than
    left to propagate: uncaught it would reach `dispatch`'s generic `except
    Exception` and answer `error / internal`, telling an agent hx is broken
    when in fact one stored blob failed its own integrity check -- exactly
    the "tested, clean" vs "never reached" confusion section 12 rules out.
    """
    row = ctx.conn.execute(
        "SELECT req_blob, resp_blob, resp_len FROM exchange WHERE id=?",
        (exchange_id,)).fetchone()
    if row is None:
        return None
    out = []
    if part in ("request", "both") and row[0]:
        try:
            out.append(("request", ctx.blobs.get(row[0])))
        except CorruptBlob:
            pass
    if part in ("response", "both") and row[1]:
        try:
            out.append(("response", ctx.blobs.get(row[1], row[2])))
        except CorruptBlob:
            pass
    return out or None


def grep(ctx, *, exchange_ids, pattern: str, part: str = "response",
         context_bytes: int = CONTEXT_DEFAULT,
         ignore_case: bool = False) -> dict:
    """Principle 2: match-addressed reading, the documented default.

    LITERAL BYTES, NOT A REGULAR EXPRESSION, and this is a decision rather
    than an omission. Python's `re` has no timeout, the pattern here is
    agent-authored, and a catastrophic backtrack would hang the ONE
    long-lived process that also holds this engagement's Burp open -- taking
    the session, the run and the operator's halt path with it. A literal
    match cannot backtrack. It also serves what this tool is actually for:
    you search for the payload token you just sent, and `delta_vs_baseline`
    already tells you which tokens are new. Anything a literal cannot express
    is `http.body(range)`'s job, or a passive check's. Recorded as known debt
    in `docs/DECISIONS.md`.

    RULING 14 -- WHERE `unavailable` AND `empty` SPLIT. `unavailable` means
    the tool could not run at all; having searched even one exchange, it
    ran. If EVERY requested exchange is unreadable, this raises
    `ToolUnavailable("unreadable", ...)` rather than answering `empty`:
    `empty` is `envelope.answered`'s reading of a zero-row page, and to an
    agent it means "I searched and found nothing" -- which is exactly wrong
    when nothing was searchable. If even ONE exchange is readable, the
    search ran, and `ok` or `empty` plus the `unreadable` facet is honest --
    the facet names precisely which exchanges were skipped, and the agent
    can see it searched a subset rather than nothing.
    """
    needle = pattern.encode(TEXT)
    if ignore_case:
        needle = needle.lower()
    considered = exchange_ids[:MAX_EXCHANGES]
    rows, unreadable = [], []
    any_readable = False
    for xid in considered:
        found = _blobs_for(ctx, xid, part)
        if found is None:
            unreadable.append(xid)
            continue
        any_readable = True
        for part_name, data in found:
            hay = data.lower() if ignore_case else data
            at = hay.find(needle)
            while at != -1:
                start = max(0, at - context_bytes)
                end = min(len(data), at + len(needle) + context_bytes)
                rows.append({
                    "exchange_id": xid, "part": part_name, "offset": at,
                    "before": data[start:at].decode(TEXT),
                    "match": data[at:at + len(needle)].decode(TEXT),
                    "after": data[at + len(needle):end].decode(TEXT),
                })
                at = hay.find(needle, at + len(needle))
    if considered and not any_readable:
        raise ToolUnavailable(
            "unreadable",
            f"none of the {len(considered)} requested exchange(s) could be "
            "read -- surface.detail lists what this engagement actually "
            "holds.")
    # UNREADABLE IS A FACET AND NOT A SILENCE. An exchange whose blob is gone
    # is not an exchange with no matches, and section 12's rule -- a report
    # that cannot tell "tested, clean" from "never reached" is worse than no
    # report -- is exactly as true of one envelope as of a whole engagement.
    return envelope.page(rows, total=len(rows), limit=envelope.MAX_LIMIT,
                         facets={"unreadable": unreadable,
                                 "searched": len(considered)})


def body(ctx, *, exchange_id: str, start: int = 0,
         length: int = RANGE_MAX, part: str = "response") -> dict:
    """Principle 2's escape hatch, used after a match yields an offset."""
    if part == "both":
        raise ToolRefused(
            "bad_args", "http.body reads one part; 'both' is grep's default, "
                        "not a range this tool can return")
    found = _blobs_for(ctx, exchange_id, part)
    if found is None:
        raise ToolRefused(
            "bad_args",
            f"no readable {part} for exchange {exchange_id!r}. It may not "
            "exist, or its body may never have been stored -- surface.detail "
            "lists the exchanges this engagement holds.")
    _name, data = found[0]
    window = data[start:start + min(length, RANGE_MAX)]
    # ONE SHAPE, INCLUDING PAST THE END. Reading past the end is a legitimate
    # way to find the end, so it is not an error -- and it is not `empty`
    # either: `empty` is Principle 3's LIST vocabulary, and
    # `envelope.answered` reads it off a page envelope's `total == 0`. To
    # spell this `empty` would mean reporting `total: 0` for a body that is
    # 5 KB long, which is a lie about the one number an agent needs to know
    # whether it has the whole thing. `length: 0` beside the true `total`
    # says where the end is.
    return {"exchange_id": exchange_id, "part": part, "start": start,
            "length": len(window), "total": len(data),
            "bytes": window.decode(TEXT)}


registry.register(spec.ToolSpec(
    name="http.grep", handler=grep,
    summary="Search stored request/response bytes for a literal string and "
            "return each match with its offset and surrounding context.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_ids", "pattern"], "properties": {
                "exchange_ids": {"type": "array", "maxItems": MAX_EXCHANGES,
                                 "items": {"type": "string", "maxLength": 64}},
                "pattern": {"type": "string", "minLength": 1,
                            "maxLength": 1024,
                            "description": "a literal string, NOT a regular "
                                           "expression"},
                "part": {"type": "string", "enum": PARTS,
                         "description": "default response"},
                "context_bytes": {"type": "integer", "minimum": 0,
                                  "maximum": CONTEXT_MAX,
                                  "description": "bytes either side of each "
                                                 "match; default 64"},
                "ignore_case": {"type": "boolean"},
            }}))

registry.register(spec.ToolSpec(
    name="http.body", handler=body,
    summary="Read a bounded range of one stored request or response. Use "
            "http.grep first to find the offset.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_id"], "properties": {
                "exchange_id": {"type": "string", "maxLength": 64},
                "start": {"type": "integer", "minimum": 0,
                          "maximum": 1_000_000_000},
                "length": {"type": "integer", "minimum": 1,
                           "maximum": RANGE_MAX},
                "part": {"type": "string", "enum": ["request", "response"]},
            }}))


#: Identities per replay. Each one is a whole extra request against a client's
#: application, so this is a blast-radius bound rather than a performance one.
#: THE SEND CEILING IS ONE HIGHER: `include_anonymous` adds a row that is not
#: an identity and is not counted here, so a full call issues nine requests,
#: not eight. Named rather than folded in, because the bound an operator
#: reasons about is "how many sessions am I comparing" and the anonymous row
#: is the comparison rather than one of the sessions.
MAX_IDENTITIES = 8


def _parts_of(url: str, raw: bytes) -> tuple[str, str, int, str]:
    """The `(scheme, host, port, path)` one stored exchange is replayed with.

    THE ORIGIN COMES FROM THE STORED URL AND THE PATH COMES FROM THE STORED
    REQUEST LINE. That looks like an inconsistency and it is not.
    `records.redact_url` runs on EVERY write to `exchange.url`, so a stored
    url whose request carried userinfo or a credential parameter has been
    rewritten -- `{{observed:userinfo}}@app.test` for the first,
    `?token={{observed:param}}` for the second. Replaying THAT path would put
    a placeholder on the wire and ask the application a different question
    from the one under investigation, and the answer would be reported as an
    authorisation difference.

    The stored request BLOB is not rewritten by that rule. `hx.issue` stores
    the bytes this side composed and the credential is injected below it, so
    a send-path blob's request line still carries the target that was sent;
    a proxy-captured blob had the SAME redaction applied to its request line
    inside the JVM, so taking the path from there is never WORSE than taking
    it from the url. The authority has to come from the url either way: an
    origin-form request line does not carry one.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        raise ToolRefused(
            "bad_args",
            f"the stored url {url!r} has no authority, so there is no host "
            "to replay this exchange against.")
    authority = rest
    for delim in ("/", "?", "#"):
        authority = authority.split(delim, 1)[0]
    # THE USERINFO WAS REPLACED, NOT REMOVED -- `redact_url`'s cut ends AT the
    # `@` so the result still reads as an authority. RFC 3986 3.2.1 puts
    # everything before the last `@` in the userinfo, and none of it is host.
    authority = authority.rpartition("@")[2]
    host, port = authority, issue_mod.DEFAULT_PORTS.get(scheme, 80)
    # An IPv6 literal KEEPS ITS BRACKETS: `Host:` carries them, and the colons
    # inside them are not the port delimiter. So a port is what follows the
    # LAST colon, and only when that colon is outside the brackets and what
    # follows it is ASCII digits -- `str.isdigit()` alone answers True for
    # superscript two, which `int()` then refuses.
    before, colon, after = authority.rpartition(":")
    if colon and "]" not in after and after.isascii() and after.isdigit():
        host, port = before, int(after)
    line = raw.split(b"\n", 1)[0].rstrip(b"\r").decode(TEXT)
    target = line.split(" ")
    if len(target) < 2 or not target[1].startswith("/"):
        raise ToolRefused(
            "bad_args",
            f"the stored request line {line!r} carries no origin-form target, "
            "so there is no path to replay.")
    return scheme, host, port, target[1]


def _replayed_headers(ctx, raw: bytes) -> tuple[str, ...]:
    """The stored request's header lines, minus the ones a replay must drop.

    DROPPING EVERY DECLARED IDENTITY'S HEADER IS THE LOAD-BEARING LINE OF
    THIS TOOL. The stored request may already carry a header that some
    identity injects -- a `Cookie` a proxy observation captured, a bearer
    token an earlier send was bound to. Replayed verbatim under identity B,
    that header sends identity A's credential under B's name: the application
    answers both replays as the SAME session, every row comes back identical,
    and the tool reports "no difference" for two sessions that were never two
    sessions. An authorisation finding gets written from these rows, so that
    is the one answer this tool must never give wrongly.

    EVERY DECLARED IDENTITY'S HEADER, not just the one this exchange was
    issued under. `exchange.identity` is NULL for proxy traffic and for an
    anonymous send, so the header a stored request carries is not always a
    name this side knows -- and a rule that dropped only the known one would
    be exactly as wrong on the rows where it matters most.

    RULING 15: THE DROP SET IS `config.CREDENTIAL_HEADERS` UNION THE DECLARED
    ONES, and both halves are needed. The declared half covers the identities
    THIS engagement configured. The standing half covers a credential the
    original request carried that no identity here declares -- an
    `Authorization` on an engagement whose only identity injects `Cookie` --
    and that is the case a replay is MOST likely to meet, since the natural
    agent action is replaying a request lifted from Burp's history. Without
    it the extension refuses every replay as `unmanaged_credential` before
    the Gate (`Redactor.unmanagedCredential`), so the tool is not wrong so
    much as dead: every row comes back refused and no authz table can be
    built at all. `config.CREDENTIAL_HEADERS` is IMPORTED rather than
    restated, because it is already pinned byte for byte against the
    extension's own list and a second copy is a second thing to keep in sync.

    `Content-Length` GOES TOO, for a plainer reason: `issue.request_bytes`
    computes it from the body it is handed and REFUSES a caller-supplied one
    that disagrees, because a Content-Length that does not match its body is
    a request-smuggling primitive rather than a typo to correct silently. A
    stored request whose body was shed or truncated carries exactly such a
    disagreement, so replaying the header would turn a perfectly replayable
    request into a refusal over a number this side can simply recompute.
    """
    drop = {name.lower() for name in config_mod.CREDENTIAL_HEADERS}
    drop.update(ident.inject.header.strip().lower()
                for ident in ctx.config.identities.values())
    drop.add("content-length")
    head, _body = http_text.split_head_body(raw)
    kept = []
    for line in http_text.header_lines(head):
        name, sep, _value = line.partition(b":")
        if not sep:
            continue
        if name.decode(TEXT).strip().lower() in drop:
            continue
        kept.append(line.decode(TEXT))
    return tuple(kept)


def _replayed_body(raw: bytes) -> bytes:
    """Everything after the stored request's head.

    `http_text.split_head_body` rather than a partition on CRLFCRLF, for the
    reason that function's own docstring gives: a bare-LF head matches
    nothing, and every replay of such a request would carry an EMPTY body --
    a different request from the one being investigated, answered differently
    and reported as an authorisation difference.
    """
    _head, body = http_text.split_head_body(raw)
    return body


def replay_as(ctx, *, exchange_id: str, identities,
              include_anonymous: bool = False) -> dict:
    """Re-issue one stored request under several identities and compare.

    THE BASELINE IS THE ORIGINAL EXCHANGE, not the first replay. An authz
    question is "does this identity see what that one saw", and the thing
    that was seen is the exchange the agent is pointing at. Comparing replays
    only against each other would answer a different question and would give
    no answer at all for a single identity.

    ONE IDENTITY'S REFUSAL DOES NOT DISCARD THE OTHERS. A row carries either
    a `digest` or a `refused` class, never neither and never both -- so "two
    identities, one answer and one rate limit" stays distinguishable from
    "two identities, one answer", which is section 12's rule inside one
    result.

    `include_anonymous` IS ITS OWN FLAG rather than a reserved name in
    `identities`. The unauthenticated comparison is the most valuable row in
    an authz table and a magic string could collide with an identity an
    operator declared.

    AN ORIGINAL WITH NO STORED RESPONSE BODY IS COMPARED AGAINST NOTHING, AND
    THE ROWS SAY SO. `resp_blob` is NULL for an exchange whose body was shed
    and for one whose transport failed before a response existed. Diffing
    against `b""` there would report a length delta and `differs: true` on
    EVERY row -- an authorisation difference on every single call, which is
    the one claim this tool must never make wrongly. So `differs` and
    `diff_vs_original` are null, "not computed", exactly as `delta`'s own
    `new_tokens` is null rather than `[]` when the bodies were too big to
    diff, and the `original_body_stored` facet names the reason.

    A NULL `differs` MEANS "NOT COMPUTED", NEVER "NO DIFFERENCE", and it
    happens two ways: the identity's replay was REFUSED, so there is no
    response to compare, or the original had no stored response body, so
    there is nothing to compare against. `false` is the only value that says
    the two bodies matched. An agent writing `if not row["differs"]` reads a
    row where nothing was ever sent as a clean result, which is section 12's
    "tested, clean" against "never reached" inside one key -- `refused` tells
    the two apart on the row and `original_body_stored` on the facet.
    """
    row = ctx.conn.execute(
        "SELECT req_blob, resp_blob, resp_len, status, method, url"
        " FROM exchange WHERE id=?", (exchange_id,)).fetchone()
    if row is None or row[0] is None:
        raise ToolRefused(
            "bad_args",
            f"exchange {exchange_id!r} has no stored request to replay. "
            "surface.detail lists the exchanges this engagement holds.")
    req_blob, resp_blob, resp_len, status, method, url = row
    try:
        raw = ctx.blobs.get(req_blob)
    except CorruptBlob as exc:
        # `unavailable / unreadable`, the same answer `http.grep` gives a blob
        # that fails its own digest check: the tool could not run, which is a
        # different fact from a bad argument and a very different one from a
        # defect in hx. `error / internal` here would tell an agent hx is
        # broken when one stored blob merely failed verification.
        raise ToolUnavailable(
            "unreadable",
            f"the stored request for exchange {exchange_id!r} could not be "
            f"read, so there is nothing to replay: {exc}") from exc
    # THE BODY, NOT THE WHOLE RESPONSE, and the same rule `delta.baseline_for`
    # follows for the same reason. Two replays of one request differ in their
    # `Date:` and their per-session `Set-Cookie` even when the application
    # returned byte-identical content -- so a comparison over whole responses
    # reports an authorisation difference on every single call, which is the
    # one answer this tool must never give wrongly.
    base_body = None
    if resp_blob:
        try:
            _head, base_body = http_text.split_head_body(
                ctx.blobs.get(resp_blob, resp_len))
        except CorruptBlob:
            # Not fatal the way an unreadable REQUEST is: the replays can
            # still be issued and their digests are still worth having. What
            # is lost is the comparison, and the rows say so rather than
            # diffing against bytes nobody read.
            base_body = None

    scheme, host, port, path = _parts_of(url, raw)
    headers = _replayed_headers(ctx, raw)
    body = _replayed_body(raw)
    # THE COMPOSED REQUEST IS CHECKED BEFORE ANYTHING SENDS, for the same
    # reason the identities are resolved first. `request_bytes` refuses a
    # request this side must not re-issue -- a stored `Transfer-Encoding`, a
    # target that would end the line -- with a ValueError, and one raised
    # from inside the loop below would surface as `error / internal`: hx
    # reported broken for a stored request it merely cannot replay.
    try:
        issue_mod.request_bytes(method, path, host, headers, body)
    except ValueError as exc:
        raise ToolRefused("bad_args", str(exc)) from exc

    # THE BOUND REFUSES RATHER THAN SLICING. The schema's `maxItems` already
    # holds it, so this is unreachable through `dispatch` -- but a SLICE is
    # the wrong shape for a bound whose whole subject is blast radius: relax
    # the schema and it would silently drop the identities past the eighth
    # and report a complete-looking table that never asked about them.
    wanted = list(identities)
    if len(wanted) > MAX_IDENTITIES:
        raise ToolRefused(
            "bad_args",
            f"{len(wanted)} identities is more than the {MAX_IDENTITIES} one "
            "replay may put on a client's application. Split the call.")
    # RULING 16, AND IT IS TWO PASSES RATHER THAN ONE. `ensure_identity`
    # RESOLVES AND REGISTERS, and a registration can fire the extension's
    # liveness canary against the client's application -- which is traffic. A
    # typo in the third name found after the first two had been registered
    # would be a typo found after traffic had already reached the client, and
    # that traffic is not recallable. So the check that costs NOTHING -- a
    # lookup in `config.identities`, no I/O of any kind -- runs over every
    # name before the step that can touch the client runs over any of them.
    try:
        for name in wanted:
            live.declaration_of(ctx, name)
        # ...AND ONLY NOW. Still before any SEND, which is the second half of
        # the same ruling: nothing goes on the wire until every identity has
        # a credential behind it.
        resolved = [live.ensure_identity(ctx, name) for name in wanted]
    # CATCHING THE PASS ABOVE, AND STANDING GUARD OVER THE ONE BELOW.
    # `declaration_of` raises this for an undeclared name, so the clause is
    # reached in the ordinary way. It also covers `ensure_identity`'s own
    # `ValueError` -- which the pre-pass has already made unreachable, and
    # which is kept anyway: a future refactor that drops or reorders the
    # declaration pass would otherwise turn an undeclared name into
    # `error / internal` silently, and the agent would be told hx is broken
    # for a typo it could fix.
    except ValueError as exc:
        raise ToolRefused("bad_args", str(exc)) from exc
    except identity_mod.IdentityError as exc:
        # RULING 13, and `send`'s own clauses unchanged: a DECLARED identity
        # whose credential will not resolve is an operator's missing
        # `export`, not an argument the agent could have written differently.
        raise ToolUnavailable("identity_unresolved", str(exc)) from exc
    except BridgeError as exc:
        # The extension refused the REGISTRATION itself -- through the same
        # table as a send refusal, for the reason `_raise_for_class` gives.
        cls_ = exc.error_class or "transport_error"
        detail = str(exc).removeprefix(f"{cls_}: ")
        _raise_for_class(cls_, detail, exc)
    plan = list(zip(wanted, resolved))
    if include_anonymous:
        plan.append((None, None))

    rows = []
    for name, ident in plan:
        try:
            issued = issue_mod.issue(
                ctx.session.bridge, ctx.conn, ctx.blobs, ctx.config,
                engagement_id=ctx.engagement.id, run_id=ctx.run_id,
                scheme=scheme, host=host, port=port, method=method,
                path=path, headers=headers, body=body, identity=ident)
        except issue_mod.IssueRefused as exc:
            rows.append({"identity": name, "digest": None,
                         "refused": exc.reason, "detail": exc.detail,
                         "diff_vs_original": None, "differs": None})
            continue
        rows.append({
            "identity": name, "digest": _digest(ctx, issued), "refused": None,
            "detail": None,
            "diff_vs_original": (
                None if base_body is None
                else delta_mod.against(status, base_body, issued.status,
                                       issued.body)),
            "differs": (None if base_body is None
                        else (status != issued.status
                              or base_body != issued.body)),
        })
    return envelope.page(rows, total=len(rows), limit=envelope.MAX_LIMIT,
                         facets={"original": exchange_id,
                                 "original_status": status,
                                 "original_body_stored": base_body is not None})


registry.register(spec.ToolSpec(
    name="http.replay_as", handler=replay_as, needs_egress=True, mutates=True,
    summary="Re-issue one stored request under several identities and report "
            "each one's digest and how it differs from the original. A null "
            "`differs` means NOT COMPARED -- the replay was refused, or the "
            "original's response body was never stored -- never 'the same'.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_id", "identities"], "properties": {
                "exchange_id": {"type": "string", "maxLength": 64},
                "identities": {"type": "array", "maxItems": MAX_IDENTITIES,
                               "items": {"type": "string", "maxLength": 64},
                               "description": "NAMES declared in config.yaml"},
                "include_anonymous": {
                    "type": "boolean",
                    "description": "also replay with no identity at all"},
            }}))
```

- [ ] **Step 3b: Widen the closed reason vocabulary — MEASURED, NOT OPTIONAL**

`envelope.REASONS_FOR` is a **closed** vocabulary and `Envelope.__post_init__`
raises `ValueError` for a reason outside it. Read where that raise lands:

```
    except ToolError as exc:
        env = envelope.Envelope(tool=name, outcome=exc.outcome,
                                reason=exc.reason, detail=exc.detail)
    except Exception as exc:
        env = envelope.failed(name, ...)
```

A `ValueError` raised **inside** the `except ToolError` handler is not caught
by the `except Exception` beside it — handlers do not chain. It propagates
straight out of `dispatch()`, which the module docstring promises **never
raises**. So an unknown reason is not a cosmetic problem: the first
`scope_denied` from a real extension would take the whole call out with a
traceback, and the journal row would never be written.

Two changes, together:

**1. Widen the sets.** In `src/hx/tools/envelope.py`:

```
    "refused": {..., "scope_denied", "method_denied", "dangerous_denied",
                "rate_limited", "budget_exhausted", "bad_frame",
                "wrong_run_kind"},
    "unavailable": {..., "identity_dead", "transport_error", "timeout",
                    "bridge_lost", "not_configured"},
```

The split is not arbitrary and belongs in a comment where it lands. **Refused
is "something decided no"** — scope, method, dangerous-path, rate and budget
are the extension's policy answering, and a client-facing count of refusals is
a statement about scope discipline. **Unavailable is "no answer came back"** —
a timeout, a dropped bridge or an unconfigured extension decided nothing, and
counting those as refusals would put network weather into a number an operator
reads as policy. Both are `ran=False`, so neither can be misread as a clean
result; what differs is what the report is entitled to say about them.

**2. Map the wire's classes through a table with a fallback**, in
`src/hx/tools/impl/http.py`:

```python
#: The extension's error classes, placed in the envelope's closed vocabulary.
#: A class this build has never seen must NOT reach `Envelope` unmapped: the
#: constructor raises for an unknown reason, and that raise lands inside
#: `dispatch`'s `except ToolError` handler where the `except Exception` beside
#: it cannot catch it -- so it escapes `dispatch`, which never raises. A new
#: class from a future extension would take the call out with a traceback and
#: write no journal row, which is the one failure this layer is built to make
#: impossible. The fallback keeps the raw class in `detail`, so nothing is
#: lost and nothing crashes.
REASON_FOR_CLASS = {
    "scope_denied": ("refused", "scope_denied"),
    "method_denied": ("refused", "method_denied"),
    "dangerous_denied": ("refused", "dangerous_denied"),
    "rate_limited": ("refused", "rate_limited"),
    "budget_exhausted": ("refused", "budget_exhausted"),
    "bad_frame": ("refused", "bad_frame"),
    "halted": ("refused", "halted"),
    "not_configured": ("unavailable", "not_configured"),
    "bridge_lost": ("unavailable", "bridge_lost"),
    "transport_error": ("unavailable", "transport_error"),
    "timeout": ("unavailable", "timeout"),
}
UNKNOWN_CLASS = ("unavailable", "transport_error")
```

and a helper that raises the right `ToolError` subclass from an
`IssueRefused`, prefixing the detail with the raw class whenever the fallback
is used so an operator can see what actually came back.

**A test proves the fallback**, with a class no build has ever answered:

```python
def test_an_unknown_wire_class_does_not_escape_dispatch(tool_run):
    """`dispatch` NEVER RAISES, and an unmapped reason is the one way left
    to make it. MEASURED: `Envelope.__post_init__` raises ValueError for a
    reason outside the closed set, and that raise lands inside `except
    ToolError` where the `except Exception` beside it cannot catch it."""
    ctx = _with_session(tool_run, _refusing("nova_class_from_2027"))
    env = dispatch_mod.dispatch(ctx, "http.send", {...}, why="unknown class")
    assert env.outcome in ("refused", "unavailable")
    assert "nova_class_from_2027" in (env.detail or "")
```

**Also confirm `hx.tools.errors`:** `ToolRefused(reason, detail)` and
`ToolUnavailable(reason, detail)` both exist and subclass `ToolError`, which
carries `.outcome`.

- [ ] **Step 4: Register the module**

`src/hx/tools/impl/__init__.py` — **no marker**:

```python
from . import checks, finding, http, report, run, surface  # noqa: F401
```

- [ ] **Step 5: Run the tests**

Run: `.venv/bin/pytest tests/test_tools_http.py -q`
Expected: PASS. If `test_a_second_send_to_the_same_surface_gets_a_delta` fails with a zero delta, the exemplar guard in `_digest` is wrong — read it again rather than adjusting the test.

- [ ] **Step 6: The integration test**

```python
# tests/integration/test_tool_http.py
"""http.send against a real extension.

ONE TEST, AND IT IS THE ONE A FAKE CANNOT DO: that the bytes this side
composes are bytes the extension accepts, decides about, and issues -- and
that the row written afterwards names an exchange whose blobs are readable.
Every refusal class is proved against `FakeBridge` in the unit suite, because
a loopback target will never produce most of them.
"""
import pytest

from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401


@pytest.mark.integration
def test_send_reaches_a_loopback_target_and_records_a_readable_exchange(
        tool_session, target):
    # `/health` rather than the brief's `/`: `TargetServer` answers `/` with
    # a bare 404 (`tests/test_target_server.py` pins it -- "a 404 here would
    # leave the integration [...] this suite relies on") and this test wants
    # a 200 to assert on. `/health` is the route built for exactly that.
    env = dispatch_mod.dispatch(
        tool_session, "http.send",
        {"host": target.host, "port": target.port, "method": "GET",
         "path": "/health"},
        why="prove the composed request survives the extension")
    assert env.outcome == "ok", env.as_dict()
    assert env.result["status"] == 200

    # FIX ROUND 1'S FINDING 5. A 200 alone only proves SOMETHING answered --
    # a Burp that, say, answered from a cached response or a different
    # listener would still produce one. `target.hits` is the one witness on
    # this side of the extension no state on the hx side can fake (the same
    # argument `Rig.send_unguarded`'s own docstring makes for using it): it
    # is what the loopback SERVER itself recorded, before it ever answered.
    assert len(target.hits) == 1, "the target never received the request"
    hit = target.hits[0]
    assert hit.method == "GET"
    assert hit.path == "/health"

    row = tool_session.conn.execute(
        "SELECT via, req_blob, resp_blob FROM exchange WHERE id=?",
        (env.result["exchange_id"],)).fetchone()
    assert row[0] == "send"
    # THE BLOBS ARE READ BACK, not merely asserted non-null: a digest naming
    # a blob the store cannot return is exactly the corruption a report would
    # read as evidence.
    assert tool_session.blobs.get(row[1])
    assert tool_session.blobs.get(row[2])
```

**Add a `tool_session` fixture** to `tests/integration/conftest.py`: a `ToolContext` with an `ExitStack`, a real engagement and a live Burp, built by dispatching `run.start` with `kind="manual"` and torn down by `run.finish`. Follow the existing fixtures' Burp guards exactly. `target` is the existing loopback `TargetServer` fixture — **do not point it anywhere outside `127.0.0.0/8`; the fixture refuses, and that refusal is load-bearing.**

- [ ] **Step 7: Full suite, ruff, commit**

```bash
extension/build.sh
.venv/bin/pytest -q && .venv/bin/pytest -m integration -q && .venv/bin/ruff check src tests
git add src/hx/tools/impl/http.py src/hx/tools/impl/__init__.py \
        src/hx/tools/envelope.py tests/test_tools_http.py \
        tests/integration/test_tool_http.py tests/integration/conftest.py
git commit -m "feat(tools): http.send

The first registered tool with needs_egress set, so the dispatcher's own
no_session guard is reached for the first time since Plan A shipped it.

Returns section 8's digest and never the body: a body in the envelope is a
body in agent_action.result_summary. A refusal carries the WIRE's class
unchanged (Principle 6) -- scope_denied and rate_limited are two different
next actions, and one 'error' would have made them one."
```

---

## Task 5: `http.grep` and `http.body`

Principle 2, both halves.

**Files:**
- Modify: `src/hx/tools/impl/http.py` (append)
- Test: `tests/test_tools_http.py` (append)

**Interfaces:**
- Consumes: `hx.http_text.split_head_body`; `BlobStore.get`; `hx.tools.envelope.page`.
- Produces: the registered tools `http.grep` and `http.body`; `hx.tools.impl.http.PARTS`, `CONTEXT_DEFAULT`, `CONTEXT_MAX`, `RANGE_MAX`, `MAX_EXCHANGES`.

---

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tools_http.py`:

```python
def _one_exchange(ctx, body=b"HTTP/1.1 200 OK\r\n\r\nneedle in a haystack"):
    """Send one request through a fake bridge and return its exchange id."""
    ctx = _with_session(ctx, [sent_result(body)])
    env = dispatch_mod.dispatch(ctx, "http.send",
                                {"host": "127.0.0.1", "port": 8080,
                                 "method": "GET", "path": "/hay"},
                                why="set up a body to read")
    return env.result["exchange_id"]


def test_grep_finds_a_literal_and_reports_its_offset(tool_run):
    """The offset is the whole point: `http.body(range)` is the escape hatch
    used AFTER a match yields one."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "needle"})
    assert env.outcome == "ok"
    row = env.result["rows"][0]
    assert row["exchange_id"] == xid
    assert row["part"] == "response"
    assert isinstance(row["offset"], int)
    assert "needle" in row["match"]


def test_grep_that_matches_nothing_is_empty_not_ok(tool_run):
    """Principle 4. `empty` says the search ran and found nothing; `ok` with
    zero rows would be indistinguishable from a search that never ran."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "absent"})
    assert env.outcome == "empty"


def test_grep_searches_the_request_when_asked(tool_run):
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "/hay",
                                 "part": "request"})
    assert env.outcome == "ok"
    assert env.result["rows"][0]["part"] == "request"


def test_grep_needs_no_session(tool_run):
    """It reads the blob store, which is on this side. An agent that has
    finished its run can still read what it captured -- and a tool marked
    needs_egress would have refused that."""
    xid = _one_exchange(tool_run)
    tool_run.session = None
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid], "pattern": "needle"})
    assert env.outcome == "ok"


def test_grep_reports_which_exchanges_it_could_not_read(tool_run):
    """Section 12 inside one envelope. An exchange whose blob is missing is
    not an exchange with no matches, and a facet that said `0 matches` about
    both would be the report that cannot distinguish tested from unreached."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.grep",
                                {"exchange_ids": [xid, "x-nonexistent"],
                                 "pattern": "needle"})
    assert env.result["facets"]["unreadable"] == ["x-nonexistent"]


def test_body_returns_a_bounded_range_and_the_total(tool_run):
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 0, "length": 8})
    assert env.outcome == "ok"
    assert len(env.result["bytes"]) == 8
    # THE TOTAL IS ALWAYS THERE, so an agent knows whether it has the whole
    # thing. A range with no total is a window with no idea how far the room
    # extends.
    assert env.result["total"] > 8


def test_body_past_the_end_answers_ok_with_zero_length_and_the_real_total(
        tool_run):
    """Reading past the end is a legitimate way to discover the end, so it is
    not an error -- and it is not `empty` either.

    `empty` IS PRINCIPLE 3's LIST VOCABULARY and `http.body` returns no list.
    `envelope.answered` reads `empty` off a page envelope's `total == 0`, so
    spelling this `empty` would mean reporting `total: 0` for a body that is
    5 KB long -- a lie about the one number an agent needs in order to know
    it has read the whole thing. `ok` with `length: 0` and the true `total`
    says exactly what happened and where the end is."""
    xid = _one_exchange(tool_run)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 99999,
                                 "length": 10})
    assert env.outcome == "ok"
    assert env.result["length"] == 0
    assert env.result["total"] > 0


def test_body_of_an_unknown_exchange_is_refused(tool_run):
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": "x-nope", "start": 0,
                                 "length": 8})
    assert env.outcome == "refused"
    assert env.reason == "bad_args"


def test_a_binary_body_round_trips_rather_than_becoming_question_marks(
        tool_run):
    """Latin-1 is chosen for exactly this: every byte maps to one character
    and back. A UTF-8 decode with `errors='replace'` would turn a binary
    body into a string of U+FFFD an agent then greps for a payload it can
    never find."""
    raw = b"HTTP/1.1 200 OK\r\n\r\n\x00\x80\xff\xfe"
    xid = _one_exchange(tool_run, raw)
    env = dispatch_mod.dispatch(tool_run, "http.body",
                                {"exchange_id": xid, "start": 0,
                                 "length": 64, "part": "response"})
    assert env.result["bytes"].encode("latin-1") == raw
```

- [ ] **Step 2: Run to watch it fail**

Run: `.venv/bin/pytest tests/test_tools_http.py -q -k "grep or body"`
Expected: FAIL — refused `not_registered`.

- [ ] **Step 3: Append the two tools to `src/hx/tools/impl/http.py`**

**This block carries no marker** — `http.py` exists after Task 4.

```python
#: `both` is the default because an agent looking for its own payload does
#: not always know which half reflected it -- a header echoed into a
#: response, a parameter echoed into the request log.
PARTS = ["request", "response", "both"]

CONTEXT_DEFAULT = 64
CONTEXT_MAX = 512
#: 64 KB per `http.body` call. Above this an agent should be grepping.
RANGE_MAX = 64 * 1024
#: Exchanges per grep. Bounded because each one is a whole body read out of
#: the blob store into memory in the one process that also holds the Burp.
MAX_EXCHANGES = 50


def _blobs_for(ctx, exchange_id, part):
    """`[(part_name, bytes)]` for one exchange, or None if it is not there.

    None covers every way there is nothing to read -- no such row, a NULL
    blob, a blob the store cannot return -- because all three are "this
    exchange cannot be searched", and a caller that told them apart would be
    reporting on hx's bookkeeping rather than on the traffic.
    """
    row = ctx.conn.execute(
        "SELECT req_blob, resp_blob, resp_len FROM exchange WHERE id=?",
        (exchange_id,)).fetchone()
    if row is None:
        return None
    out = []
    if part in ("request", "both") and row[0]:
        out.append(("request", ctx.blobs.get(row[0])))
    if part in ("response", "both") and row[1]:
        out.append(("response", ctx.blobs.get(row[1], row[2])))
    return out or None


def grep(ctx, *, exchange_ids, pattern: str, part: str = "response",
         context_bytes: int = CONTEXT_DEFAULT,
         ignore_case: bool = False) -> dict:
    """Principle 2: match-addressed reading, the documented default.

    LITERAL BYTES, NOT A REGULAR EXPRESSION, and this is a decision rather
    than an omission. Python's `re` has no timeout, the pattern here is
    agent-authored, and a catastrophic backtrack would hang the ONE
    long-lived process that also holds this engagement's Burp open -- taking
    the session, the run and the operator's halt path with it. A literal
    match cannot backtrack. It also serves what this tool is actually for:
    you search for the payload token you just sent, and `delta_vs_baseline`
    already tells you which tokens are new. Anything a literal cannot express
    is `http.body(range)`'s job, or a passive check's.
    """
    needle = pattern.encode(TEXT)
    if ignore_case:
        needle = needle.lower()
    rows, unreadable = [], []
    for xid in exchange_ids[:MAX_EXCHANGES]:
        found = _blobs_for(ctx, xid, part)
        if found is None:
            unreadable.append(xid)
            continue
        for part_name, data in found:
            hay = data.lower() if ignore_case else data
            at = hay.find(needle)
            while at != -1:
                start = max(0, at - context_bytes)
                end = min(len(data), at + len(needle) + context_bytes)
                rows.append({
                    "exchange_id": xid, "part": part_name, "offset": at,
                    "before": data[start:at].decode(TEXT),
                    "match": data[at:at + len(needle)].decode(TEXT),
                    "after": data[at + len(needle):end].decode(TEXT),
                })
                at = hay.find(needle, at + len(needle))
    # UNREADABLE IS A FACET AND NOT A SILENCE. An exchange whose blob is gone
    # is not an exchange with no matches, and section 12's rule -- a report
    # that cannot tell "tested, clean" from "never reached" is worse than no
    # report -- is exactly as true of one envelope as of a whole engagement.
    return envelope.page(rows, total=len(rows), limit=envelope.MAX_LIMIT,
                         facets={"unreadable": unreadable,
                                 "searched": len(exchange_ids[:MAX_EXCHANGES])})


def body(ctx, *, exchange_id: str, start: int = 0,
         length: int = RANGE_MAX, part: str = "response") -> dict:
    """Principle 2's escape hatch, used after a match yields an offset."""
    if part == "both":
        raise ToolRefused(
            "bad_args", "http.body reads one part; 'both' is grep's default, "
                        "not a range this tool can return")
    found = _blobs_for(ctx, exchange_id, part)
    if found is None:
        raise ToolRefused(
            "bad_args",
            f"no readable {part} for exchange {exchange_id!r}. It may not "
            "exist, or its body may never have been stored -- surface.detail "
            "lists the exchanges this engagement holds.")
    _name, data = found[0]
    window = data[start:start + min(length, RANGE_MAX)]
    # ONE SHAPE, INCLUDING PAST THE END. Reading past the end is a legitimate
    # way to find the end, so it is not an error -- and it is not `empty`
    # either: `empty` is Principle 3's LIST vocabulary, and
    # `envelope.answered` reads it off a page envelope's `total == 0`. To
    # spell this `empty` would mean reporting `total: 0` for a body that is
    # 5 KB long, which is a lie about the one number an agent needs to know
    # whether it has the whole thing. `length: 0` beside the true `total`
    # says where the end is.
    return {"exchange_id": exchange_id, "part": part, "start": start,
            "length": len(window), "total": len(data),
            "bytes": window.decode(TEXT)}


registry.register(spec.ToolSpec(
    name="http.grep", handler=grep,
    summary="Search stored request/response bytes for a literal string and "
            "return each match with its offset and surrounding context.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_ids", "pattern"], "properties": {
                "exchange_ids": {"type": "array", "maxItems": MAX_EXCHANGES,
                                 "items": {"type": "string", "maxLength": 64}},
                "pattern": {"type": "string", "minLength": 1,
                            "maxLength": 1024,
                            "description": "a literal string, NOT a regular "
                                           "expression"},
                "part": {"type": "string", "enum": PARTS,
                         "description": "default response"},
                "context_bytes": {"type": "integer", "minimum": 0,
                                  "maximum": CONTEXT_MAX,
                                  "description": "bytes either side of each "
                                                 "match; default 64"},
                "ignore_case": {"type": "boolean"},
            }}))

registry.register(spec.ToolSpec(
    name="http.body", handler=body,
    summary="Read a bounded range of one stored request or response. Use "
            "http.grep first to find the offset.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_id"], "properties": {
                "exchange_id": {"type": "string", "maxLength": 64},
                "start": {"type": "integer", "minimum": 0,
                          "maximum": 1_000_000_000},
                "length": {"type": "integer", "minimum": 1,
                           "maximum": RANGE_MAX},
                "part": {"type": "string", "enum": ["request", "response"]},
            }}))
```

**Verify against `envelope.page`'s real signature** before writing: it takes `limit + 1` rows to detect truncation and accepts `total`, `limit`, `cursor_of`, `facets`. The calls above pass fewer rows than the limit, which is the non-truncated path — confirm that is what `page` expects, and confirm a zero-row page produces outcome `empty`.

- [ ] **Step 4: Run and commit**

```bash
.venv/bin/pytest -q && .venv/bin/ruff check src tests
git add src/hx/tools/impl/http.py tests/test_tools_http.py
git commit -m "feat(tools): http.grep and http.body

Principle 2, both halves: match-addressed reading is the default and a
bounded range is the escape hatch used after a match yields an offset.

grep matches LITERAL bytes. Python's re has no timeout, the pattern is
agent-authored, and a catastrophic backtrack would hang the one long-lived
process that also holds the Burp -- taking the session, the run and the
operator's halt path with it. Recorded as known debt in DECISIONS.md.

Neither tool needs a session: both read this side's blob store, so an agent
that has finished its run can still read what it captured."
```

---

## Task 6: `http.replay_as`

The authorisation table, in one call.

**Files:**
- Modify: `src/hx/tools/impl/http.py` (append)
- Test: `tests/test_tools_http.py` (append)

**Interfaces:**
- Consumes: `hx.issue.issue`, `hx.issue.request_bytes` (for the round trip out of a stored blob), `hx.delta.against`, `hx.tools.live.ensure_identity`, `hx.tools.impl.http._digest`.
- Produces: the registered tool `http.replay_as`; `MAX_IDENTITIES`.

---

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tools_http.py`:

```python
def test_replay_as_returns_one_row_per_identity_plus_the_baseline(
        tool_run, staff_identity_config, monkeypatch):
    """The shape an authz finding is written from: same request, several
    sessions, one column of differences."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ok = b"HTTP/1.1 200 OK\r\n\r\nadmin panel"
    denied = b"HTTP/1.1 403 Forbidden\r\n\r\nno"
    ctx = _with_session(tool_run,
                        [sent_result(ok), sent_result(denied, status=403)])
    xid = _one_exchange_on(ctx, ok, path="/admin")

    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"]},
        why="check whether /admin is reachable as staff")
    assert env.outcome == "ok"
    rows = env.result["rows"]
    assert [r["identity"] for r in rows] == ["staff"]
    assert rows[0]["digest"]["status"] == 403
    assert rows[0]["differs"] is True


def test_include_anonymous_adds_an_unauthenticated_row(
        tool_run, staff_identity_config, monkeypatch):
    """Its own boolean, not a magic identity name. The unauthenticated
    comparison is the single most valuable row in an authz table, and a
    reserved string could collide with a name an operator declared."""
    monkeypatch.setenv("HX_STAFF_TOKEN", "s3cret")
    tool_run.config = staff_identity_config
    ...
    env = dispatch_mod.dispatch(
        ctx, "http.replay_as",
        {"exchange_id": xid, "identities": ["staff"],
         "include_anonymous": True},
        why="compare staff against anonymous")
    assert [r["identity"] for r in env.result["rows"]] == ["staff", None]


def test_replay_of_an_unknown_exchange_is_refused_before_any_send(tool_run):
    ctx = _with_session(tool_run, [])
    env = dispatch_mod.dispatch(ctx, "http.replay_as",
                                {"exchange_id": "x-nope",
                                 "identities": ["staff"]},
                                why="replay something that is not there")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert ctx.session.bridge.requests == []


def test_one_identitys_refusal_does_not_lose_the_others(
        tool_run, staff_identity_config, monkeypatch):
    """A rate limit on the second identity must not discard the first
    identity's answer. Section 12 again: 'two identities, one answer, one
    refusal' and 'two identities, one answer' are different facts."""
    ...
    rows = env.result["rows"]
    assert rows[0]["digest"] is not None
    assert rows[1]["digest"] is None
    assert rows[1]["refused"] == "rate_limited"


def test_replay_needs_a_why_and_a_session(tool_run):
    """It mutates -- it puts N more requests on a client's network -- and it
    needs egress."""
    ...
```

Fill the elided bodies following the patterns already in this file. Add a `_one_exchange_on(ctx, body, *, path)` helper beside `_one_exchange` rather than copying it: the two differ only by path.

- [ ] **Step 2: Run to watch it fail**

Run: `.venv/bin/pytest tests/test_tools_http.py -q -k replay`
Expected: FAIL — refused `not_registered`.

- [ ] **Step 3: Append `replay_as`**

**No marker.**

```python
#: Identities per replay. Each one is a whole extra request against a client's
#: application, so this is a blast-radius bound rather than a performance one.
MAX_IDENTITIES = 8


def replay_as(ctx, *, exchange_id: str, identities,
              include_anonymous: bool = False) -> dict:
    """Re-issue one stored request under several identities and compare.

    THE BASELINE IS THE ORIGINAL EXCHANGE, not the first replay. An authz
    question is "does this identity see what that one saw", and the thing
    that was seen is the exchange the agent is pointing at. Comparing replays
    only against each other would answer a different question and would give
    no answer at all for a single identity.

    ONE IDENTITY'S REFUSAL DOES NOT DISCARD THE OTHERS. A row carries either
    a `digest` or a `refused` class, never neither and never both -- so "two
    identities, one answer and one rate limit" stays distinguishable from
    "two identities, one answer", which is section 12's rule inside one
    result.

    `include_anonymous` IS ITS OWN FLAG rather than a reserved name in
    `identities`. The unauthenticated comparison is the most valuable row in
    an authz table and a magic string could collide with an identity an
    operator declared.
    """
    row = ctx.conn.execute(
        "SELECT req_blob, resp_blob, resp_len, status, method, url"
        " FROM exchange WHERE id=?", (exchange_id,)).fetchone()
    if row is None or row[0] is None:
        raise ToolRefused(
            "bad_args",
            f"exchange {exchange_id!r} has no stored request to replay. "
            "surface.detail lists the exchanges this engagement holds.")
    req_blob, resp_blob, resp_len, status, method, url = row
    raw = ctx.blobs.get(req_blob)
    # THE BODY, NOT THE WHOLE RESPONSE, and the same rule `delta.baseline_for`
    # follows for the same reason. Two replays of one request differ in their
    # `Date:` and their per-session `Set-Cookie` even when the application
    # returned byte-identical content -- so a comparison over whole responses
    # reports an authorisation difference on every single call, which is the
    # one answer this tool must never give wrongly.
    base_raw = ctx.blobs.get(resp_blob, resp_len) if resp_blob else b""
    _head, base_body = http_text.split_head_body(base_raw)

    scheme, host, port, path = _parts_of(url, raw)

    # RESOLVE EVERY IDENTITY BEFORE SENDING ANYTHING. A typo in the third
    # name would otherwise be discovered after two requests had already
    # reached the client's application -- and those two are not recallable.
    wanted = list(identities)[:MAX_IDENTITIES]
    try:
        resolved = [live.ensure_identity(ctx, name) for name in wanted]
    except ValueError as exc:
        raise ToolRefused("bad_args", str(exc)) from exc
    plan = list(zip(wanted, resolved))
    if include_anonymous:
        plan.append((None, None))

    rows = []
    for name, ident in plan:
        try:
            issued = issue_mod.issue(
                ctx.session.bridge, ctx.conn, ctx.blobs, ctx.config,
                engagement_id=ctx.engagement.id, run_id=ctx.run_id,
                scheme=scheme, host=host, port=port, method=method,
                path=path, headers=_replayed_headers(raw),
                body=_replayed_body(raw), identity=ident)
        except issue_mod.IssueRefused as exc:
            rows.append({"identity": name, "digest": None,
                         "refused": exc.reason, "detail": exc.detail,
                         "differs": None})
            continue
        rows.append({
            "identity": name, "digest": _digest(ctx, issued), "refused": None,
            "diff_vs_original": delta_mod.against(
                status, base_body, issued.status, issued.body),
            "differs": (status != issued.status
                        or base_body != issued.body),
        })
    return envelope.page(rows, total=len(rows), limit=envelope.MAX_LIMIT,
                         facets={"original": exchange_id,
                                 "original_status": status})


registry.register(spec.ToolSpec(
    name="http.replay_as", handler=replay_as, needs_egress=True, mutates=True,
    summary="Re-issue one stored request under several identities and report "
            "each one's digest and how it differs from the original.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_id", "identities"], "properties": {
                "exchange_id": {"type": "string", "maxLength": 64},
                "identities": {"type": "array", "maxItems": MAX_IDENTITIES,
                               "items": {"type": "string", "maxLength": 64},
                               "description": "NAMES declared in config.yaml"},
                "include_anonymous": {
                    "type": "boolean",
                    "description": "also replay with no identity at all"},
            }}))
```

**Three helpers this task must also write**, each small and each with its own test:

- `_parts_of(url, raw) -> (scheme, host, port, path)`. The stored `url` is **redacted** (`records.redact_url` runs on every write), so a URL that carried userinfo or a credential parameter has been rewritten. Take the scheme, host and port from the URL and the **path from the stored request line**, which is not redacted. Say that in a comment — it is the kind of thing that looks like an inconsistency and is not.
- `_replayed_headers(raw) -> tuple[str, ...]`. The stored request's header lines, **minus any the extension injects** — an identity header from the original replayed verbatim would defeat the whole tool by sending identity A's credential under identity B's name. Drop every header named by any declared identity's `inject.header`, and drop `Content-Length` (recomputed by `request_bytes`'s caller from the body). Comment the first of those two; it is the load-bearing one.
- `_replayed_body(raw) -> bytes`. Everything after the head.

- [ ] **Step 4: Run, ruff, commit**

```bash
.venv/bin/pytest -q && .venv/bin/ruff check src tests
git add src/hx/tools/impl/http.py tests/test_tools_http.py
git commit -m "feat(tools): http.replay_as

Same request, several identities, one column of differences -- the shape an
authz finding is written from. include_anonymous is its own boolean rather
than a reserved name that could collide with an identity an operator declared.

Every identity resolves BEFORE anything sends: a typo in the third name
would otherwise be found after two requests had already reached the client's
application, and those are not recallable. A refusal on one identity keeps
the others' answers, because 'one answer and one rate limit' and 'one answer'
are different facts."
```

---

## Task 7: `scan.run` and `crawl.run`

**Files:**
- Create: `src/hx/tools/impl/scan.py`
- Modify: `src/hx/tools/impl/__init__.py`
- Test: `tests/test_tools_scan.py`

**Interfaces:**
- Consumes: `hx.scan.run(conn, *, engagement_id, blobs, config, checks=None, surface_filter=None, max_seconds=None, bridge=None, identity=None) -> ScanSummary`; `hx.scan.IdentityDead`; `hx.checks.registry.CHECKS`, `.KNOWN_CLASSES`; `ctx.open_runs()`.
- Produces: the registered tools `scan.run` and `crawl.run`.

---

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_tools_scan.py
"""scan.run and crawl.run.

`crawl.run` is registered and always unavailable, and the test for that is
the most important one in this file. An agent with NO crawl tool has no
reason to say discovery was proxy-only; an agent that asks and is told
`not_implemented` does. That is section 12's rule applied to the agent's
knowledge of its own instrument, and a tool that quietly did not exist would
be the silence the rule is against.
"""
from __future__ import annotations

from hx import run as run_mod
from hx import scan as scan_mod
from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401


def test_crawl_run_is_registered_and_permanently_unavailable(tool_ctx):
    env = dispatch_mod.dispatch(tool_ctx, "crawl.run",
                                {"target": "http://127.0.0.1:8080/"},
                                why="see whether crawling exists")
    assert env.outcome == "unavailable"
    assert env.reason == "not_implemented"
    # AND IT SAYS WHAT TO DO INSTEAD. An `unavailable` that names no
    # alternative leaves an agent with a dead end where it needs a next step.
    assert "proxy" in (env.detail or "").lower()


def test_crawl_run_is_unavailable_even_with_a_live_session(tool_ctx):
    """`unavailable` here is about the FEATURE, not about the instrument. A
    version that answered `no_session` would tell an agent that starting a
    session would help, and it would not. No `why` either: a call that can
    never mutate anything must never be told it needs one."""
    tool_ctx.session = object()
    env = dispatch_mod.dispatch(tool_ctx, "crawl.run",
                                {"target": "http://127.0.0.1:8080/"})
    assert env.outcome == "unavailable"
    assert env.reason == "not_implemented"


def test_scan_run_refuses_outside_a_scan_run(tool_ctx):
    """`hx.scan.run` calls `run.current_run(kind='scan')`, which AUTO-OPENS a
    run when none is open -- and a run the tool layer did not open is a run
    nothing will close, which makes the next `run.start(kind='scan')` refuse
    `run_open` forever. Requiring the bracket keeps `current_run` in its
    finding role and never in its opening one.

    A session is set up (so the dispatcher's `no_session` guard does not fire
    first) but the open run is `manual`, never `scan` -- this must be refused
    by the HANDLER'S OWN check, not by the egress guard above it.
    """
    from tests.test_probe import FakeBridge

    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="manual",
        safety_profile=tool_ctx.config.safety_profile)
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()

    env = dispatch_mod.dispatch(tool_ctx, "scan.run", {},
                                why="try it without a scan run")
    assert env.outcome == "refused"
    assert env.reason == "wrong_run_kind"
    assert "run.start" in (env.detail or "")


def test_scan_run_reports_the_summary_an_operator_would_see(
        live_session, monkeypatch):
    """`checks_run` is check_run ROWS WRITTEN and `findings` is DISTINCT
    findings -- both hard-won meanings (see ScanSummary's docstring), and a
    tool that recomputed either would be a third place they can disagree."""
    summary = scan_mod.ScanSummary(
        surfaces=3, checks_run=5, skipped=2, findings=1)

    def fake_run(conn, **kw):
        return summary

    monkeypatch.setattr(scan_mod, "run", fake_run)

    env = dispatch_mod.dispatch(live_session, "scan.run", {},
                                why="run the corpus")
    assert env.outcome == "ok"
    assert env.result["surfaces"] == 3
    assert env.result["checks_run"] == 5
    assert env.result["skipped"] == 2
    assert env.result["findings"] == 1
    # NOT re-derived from anything but `checks_run` and `skipped` -- the CLI's
    # own relationship, per `ScanSummary`'s docstring, not a value the store
    # holds anywhere on its own.
    assert env.result["executed"] == 3


def test_a_dead_identity_is_unavailable_rather_than_an_error(
        live_session, monkeypatch):
    """`IdentityDead` means the scan HALTED rather than completing clean, and
    section 12 is explicit that those must not render alike. `error` would
    say hx broke; `unavailable / identity_dead` says the session died and the
    coverage is short."""
    def dead(*a, **kw):
        raise scan_mod.IdentityDead("staff could not be proved live",
                                    stop_reason="identity staff dead")

    monkeypatch.setattr(scan_mod, "run", dead)

    env = dispatch_mod.dispatch(live_session, "scan.run", {},
                                why="run against a dying identity")
    assert env.outcome == "unavailable"
    assert env.reason == "identity_dead"


def test_unknown_check_ids_are_refused_and_the_known_ones_are_named(
        live_session):
    """A typo'd check id that was silently dropped would produce a scan that
    ran fewer checks than the agent asked for and reported success."""
    env = dispatch_mod.dispatch(
        live_session, "scan.run", {"checks": ["hx.passive.no-such-check"]},
        why="typo'd a check id")
    assert env.outcome == "refused"
    assert env.reason == "bad_args"
    assert "hx.passive.no-such-check" in (env.detail or "")
    assert "checks.list" in (env.detail or "")
```

Fill the elided bodies. A `live_session` fixture (a `tool_ctx` with a fake bridge on `ctx.session` and an open run of the right kind) belongs in `tests/conftest.py` beside `FakeBridge`, since Task 6's tests want it too.

- [ ] **Step 2: Run to watch it fail**

Run: `.venv/bin/pytest tests/test_tools_scan.py -q`
Expected: FAIL — refused `not_registered`.

- [ ] **Step 3: Write `src/hx/tools/impl/scan.py`**

```python
# src/hx/tools/impl/scan.py
"""Running the corpus, and the one tool that never runs at all.

`crawl.run` IS REGISTERED AND ALWAYS UNAVAILABLE, and registering a tool that
never succeeds looks like noise and is the opposite. An agent with no `crawl`
tool has no reason to say discovery was proxy-only; an agent that asks and is
told `not_implemented` does. That is section 12's governing rule -- a report
that cannot distinguish "tested, clean" from "never reached" is worse than no
report -- applied to the agent's own knowledge of its instrument, and it is
what `unavailable` exists for.
"""
from __future__ import annotations

from ... import scan as scan_mod
from ...checks import registry as check_registry
from .. import registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: Wall-clock ceiling for one `scan.run`. All v1 tools are synchronous -- no
#: job runner, no job table, no polling -- so a scan is a call an agent waits
#: on, and an unbounded one is a conversation that never comes back. The
#: caller may ask for less and not for more.
MAX_SECONDS = 1800


def run(ctx, *, surface_ids=None, checks=None,
        max_seconds: int = MAX_SECONDS) -> dict:
    """Run the enabled corpus over some or all surfaces. Synchronous.

    IT MUST BE CALLED INSIDE A `scan` RUN, and the reason is mechanical
    rather than tidy. `hx.scan.run` resolves its run with
    `hx.run.current_run(kind="scan")`, which AUTO-OPENS one when none is
    open. A run the tool layer did not open is a run `run.finish` will never
    close, and the next `run.start(kind="scan")` then refuses `run_open`
    forever against a run nobody remembers. Requiring the bracket keeps
    `current_run` in its finding role and never in its opening one.
    """
    open_now = dict((kind, rid) for rid, kind in ctx.open_runs())
    if "scan" not in open_now:
        raise ToolRefused(
            "wrong_run_kind",
            "scan.run belongs inside a scan run, and none is open. "
            "`run.start` with kind='scan' first -- a scan run is what "
            "`check_run` rows are attributed to, and one this layer did not "
            "open is one nothing will close.")

    corpus = None
    if checks is not None:
        known = {c.id: c for c in check_registry.CHECKS}
        unknown = sorted(set(checks) - set(known))
        if unknown:
            # NEVER SILENTLY DROPPED. A typo'd id that vanished would produce
            # a scan that ran fewer checks than was asked for and reported
            # success, which is a coverage lie with a green tick on it.
            raise ToolRefused(
                "bad_args",
                f"unknown check ids {unknown}. `checks.list` names every "
                "check in the corpus, including the disabled ones.")
        corpus = tuple(known[c] for c in checks)

    wanted = None if surface_ids is None else set(surface_ids)
    try:
        summary = scan_mod.run(
            ctx.conn, engagement_id=ctx.engagement.id, blobs=ctx.blobs,
            config=ctx.config, checks=corpus,
            # A PREDICATE, because that is what `hx.scan.run` takes. `surface`
            # rows arrive as sqlite rows and `[0]` is the id -- read
            # `hx.scan.run`'s own use of `surface_filter` and follow it
            # rather than trusting this index.
            surface_filter=(None if wanted is None
                            else (lambda s: s[0] in wanted)),
            max_seconds=min(max_seconds, MAX_SECONDS),
            # `needs_egress=True` on the spec means `dispatch` already
            # refused `unavailable / no_session` before this handler ran, so
            # `ctx.session` is never None here.
            bridge=ctx.session.bridge,
            # NOT OVERRIDDEN. `hx.scan.run` resolves `config.scan_identity`
            # itself and is the only thing in the product that reads that
            # field; passing None here is what lets it. An identity chosen
            # per call would put the run's bracket and the run's traffic
            # under two different answers.
            identity=None)
    except scan_mod.IdentityDead as exc:
        # THE SCAN HALTED RATHER THAN COMPLETING CLEAN, and section 12 is
        # explicit that those two must not render alike. `error` would say hx
        # broke; this says the session died and the coverage is short.
        raise ToolUnavailable("identity_dead", str(exc)) from exc

    return {
        "surfaces": summary.surfaces,
        "checks_run": summary.checks_run,
        "skipped": summary.skipped,
        "findings": summary.findings,
        # `checks_run` is ROWS WRITTEN and `findings` is DISTINCT findings --
        # both meanings were argued for in `ScanSummary`'s docstring after a
        # scan printed `findings 40` while the store held 1. Read, never
        # recomputed: a second place these are derived is a second place they
        # can disagree with the report.
        "executed": summary.checks_run - summary.skipped,
    }


def crawl(ctx, **kw) -> dict:
    raise ToolUnavailable(
        "not_implemented",
        "hx has no crawler in v1. Discovery is the operator's browser "
        "through the proxy (`hx capture start`), and `surface.query` shows "
        "what that has reached. Say so in the report: a surface nobody "
        "browsed is a surface nothing tested.")


registry.register(spec.ToolSpec(
    name="scan.run", handler=run, needs_egress=True, mutates=True,
    summary="Run the enabled checks over some or all surfaces. Synchronous "
            "and bounded; must be called inside a scan run.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "surface_ids": {"type": "array", "maxItems": 500,
                        "items": {"type": "string", "maxLength": 64},
                        "description": "omit to scan every surface"},
        "checks": {"type": "array", "maxItems": 100,
                   "items": {"type": "string", "maxLength": 64},
                   "description": "check ids from checks.list; omit for the "
                                  "enabled corpus"},
        "max_seconds": {"type": "integer", "minimum": 1,
                        "maximum": MAX_SECONDS},
    }}))

registry.register(spec.ToolSpec(
    name="crawl.run", handler=crawl,
    summary="NOT IMPLEMENTED in v1 and always answers unavailable. Listed "
            "so that a report can say discovery was proxy-only.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "target": {"type": "string", "maxLength": 2048},
        "identity": {"type": "string", "maxLength": 64},
        "max_pages": {"type": "integer", "minimum": 1, "maximum": 10000},
        "max_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
    }}))
```

**`crawl.run` carries neither `needs_egress` nor `mutates` on purpose.** With `needs_egress` set, the dispatcher's guard would answer `no_session` first — telling an agent that starting a session would help, when it would not. With `mutates` set it would demand a `why` for a call that can never do anything. `not_implemented` must be the *first* answer, every time; add a test that proves it with no session and no `why`.

**Also check `ToolUnavailable`'s reasons:** `not_implemented` and `identity_dead` must be in `envelope.REASONS_FOR["unavailable"]`, and `wrong_run_kind` in `REASONS_FOR["refused"]`. Add them if they are not, in the same commit.

- [ ] **Step 4: Register, run, commit**

`src/hx/tools/impl/__init__.py` — **no marker**:

```python
from . import checks, finding, http, report, run, scan, surface  # noqa: F401
```

```bash
.venv/bin/pytest -q && .venv/bin/ruff check src tests
git add src/hx/tools/impl/scan.py src/hx/tools/impl/__init__.py \
        src/hx/tools/envelope.py tests/test_tools_scan.py tests/conftest.py
git commit -m "feat(tools): scan.run and crawl.run

scan.run refuses outside a scan run: hx.scan.run resolves its run with
current_run(kind='scan'), which auto-opens one, and a run this layer did not
open is a run run.finish will never close -- the next run.start(kind='scan')
would then refuse run_open forever against a run nobody remembers.

crawl.run is registered and always unavailable, with neither needs_egress nor
mutates, so not_implemented is the FIRST answer rather than no_session. An
agent with no crawl tool has no reason to say discovery was proxy-only; one
that asks and is told does."
```

---

## Task 8: `hx mcp` — the adapter

The seventeen tools, over stdio, in one long-lived process that can hold a Burp.

**Files:**
- Create: `src/hx/tools/adapters/mcp.py`
- Modify: `src/hx/cli.py` (the `hx mcp` command)
- Test: `tests/test_mcp_adapter.py`

**Interfaces:**
- Consumes: `hx.tools.registry.TOOLS`, `hx.tools.dispatch.dispatch`, `hx.tools.adapters.cli.build_context`.
- Produces: `hx.tools.adapters.mcp.serve(engagement, stdin, stdout)`, `handle(ctx, message) -> dict | None`, `PROTOCOL_VERSION`, `tool_schema(tool) -> dict`.

---

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_mcp_adapter.py
"""hx mcp: JSON-RPC 2.0 over stdio, hand-rolled.

WHY HAND-ROLLED is a decision the spec left open and this task settles: MCP
stdio is newline-delimited JSON-RPC 2.0 and a server needs `initialize`,
`tools/list` and `tools/call`. That is what this module is. This project runs
on two Python dependencies and a Java extension with none, and a security
tool's dependency footprint is part of its argument -- an SDK here would be a
third dependency, plus its transitive closure, inside the process that holds
the client's credentials and the operator's halt path.

THE TESTS DRIVE `handle` RATHER THAN THE LOOP wherever they can. The loop is
four lines of framing; the protocol is the part that can be wrong.
"""
import io
import json
import subprocess
import sys
from pathlib import Path

from hx.tools import registry
from hx.tools.adapters import mcp


def test_initialize_answers_with_a_protocol_version_and_tool_capability():
    got = mcp.handle(None, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {}})
    assert got["id"] == 1
    assert got["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert "tools" in got["result"]["capabilities"]


def test_a_notification_gets_no_reply_at_all():
    """JSON-RPC: a message with no `id` is a notification and answering one
    is a protocol violation. `notifications/initialized` is the one every
    client sends immediately after `initialize`, so a server that replied
    would break on its first real conversation."""
    assert mcp.handle(None, {"jsonrpc": "2.0",
                             "method": "notifications/initialized"}) is None


def test_tools_list_publishes_every_registered_tool(tool_ctx):
    got = mcp.handle(tool_ctx, {"jsonrpc": "2.0", "id": 2,
                                "method": "tools/list"})
    names = {t["name"] for t in got["result"]["tools"]}
    assert names == set(registry.TOOLS)
    assert len(names) == 17


def test_a_mutating_tools_published_schema_carries_why(tool_ctx):
    """MCP hands a tool ONE arguments object, so `why` has to travel inside
    it -- there is nowhere else for Principle 5's reason to go. The adapter
    pops it back out before `dispatch` validates, because `ToolSpec.params`
    sets `additionalProperties: false` and would otherwise refuse it."""
    got = mcp.handle(tool_ctx, {"jsonrpc": "2.0", "id": 2,
                                "method": "tools/list"})
    by_name = {t["name"]: t for t in got["result"]["tools"]}
    assert "why" in by_name["run.start"]["inputSchema"]["properties"]
    assert "why" in by_name["run.start"]["inputSchema"]["required"]
    # And NOT on a read-only tool, where it would be noise an agent fills in.
    assert "why" not in by_name["surface.query"]["inputSchema"]["properties"]


def test_tools_call_dispatches_and_why_never_reaches_the_handler(tool_ctx):
    got = mcp.handle(tool_ctx, {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "run.start",
                   "arguments": {"kind": "manual", "why": "start probing"}}})
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["outcome"] == "ok"
    assert payload["result"]["kind"] == "manual"
    # `why` reached agent_action and not the handler: had it been passed
    # through as an argument, the schema's additionalProperties: false would
    # have refused the call as bad_args.
    row = tool_ctx.conn.execute(
        "SELECT why FROM agent_action ORDER BY rowid DESC LIMIT 1").fetchone()
    assert row[0] == "start probing"


def test_a_refused_tool_is_isError_but_still_a_jsonrpc_result(tool_ctx):
    """A refusal is the tool answering, not the transport failing. A
    JSON-RPC `error` here would make `scope_denied` look like a broken server
    and would lose the envelope an agent needs to read."""
    got = mcp.handle(tool_ctx, {
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "run.start", "arguments": {"kind": "manual"}}})
    assert "error" not in got
    assert got["result"]["isError"] is True
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["reason"] == "missing_why"


def test_an_unknown_method_is_a_jsonrpc_error(tool_ctx):
    got = mcp.handle(tool_ctx, {"jsonrpc": "2.0", "id": 5,
                                "method": "resources/list"})
    assert got["error"]["code"] == -32601


def test_a_malformed_line_does_not_kill_the_server(tool_ctx):
    """The one property the loop must have. An agent that emits one bad line
    -- a truncated write, a stray log -- must not take the session, the run
    and the operator's halt path down with it."""
    out = io.StringIO()
    mcp.serve_streams(tool_ctx, io.StringIO(
        "not json\n"
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700     # parse error
    assert lines[1]["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION


def test_nothing_but_json_rpc_reaches_stdout(tool_ctx):
    """stdout IS the protocol. A print, a warning, a library's banner --
    anything else on this stream desynchronises the client for the rest of
    the conversation, and there is no resynchronising a newline-delimited
    protocol."""
    out = io.StringIO()
    mcp.serve_streams(tool_ctx, io.StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'), out)
    for line in out.getvalue().splitlines():
        assert json.loads(line)["jsonrpc"] == "2.0"


def test_every_published_schema_is_one_this_validator_can_enforce():
    """`tool_schema` adds `why` to a schema `check_schema` already passed,
    and a publisher that emitted something the validator ignores would be
    promising a constraint nothing applies -- which is the exact defect
    `check_schema` exists to refuse."""
    from hx.tools import schema
    for tool in registry.TOOLS.values():
        schema.check_schema(mcp.tool_schema(tool)["inputSchema"],
                            where=tool.name)


def test_hx_mcp_subprocess_writes_only_two_json_rpc_lines_to_real_stdout(
        tmp_path):
    """THE ONE TEST THAT INSPECTS THE REAL OS-LEVEL FILE DESCRIPTOR.

    Every test above drives `handle`/`serve_streams` with an injected
    `io.StringIO`, which proves `serve_streams` writes only valid JSON-RPC
    into the stream IT IS GIVEN. That cannot see a stray `print`, a library's
    deprecation warning, or any other write that lands on file descriptor 1
    directly -- and it does not: a mutation that put `print("noise")` at the
    top of `serve_streams` left `test_nothing_but_json_rpc_reaches_stdout`
    green, because that test's `stdout` was never real. Deleting this test as
    "redundant with" that one is exactly the mistake that lets a stray line
    back in -- a newline-delimited protocol has no resynchronisation point,
    so ONE such line desynchronises the client for the rest of the
    conversation, which is the single highest-value property in this file.

    A REAL SUBPROCESS rather than `capfd` around an in-process `mcp.serve`,
    per Ruling 17: the two catch the same fd-1 writes, but the subprocess
    also exercises the actual `hx mcp` Click command -- the lines added to
    `cli.py`, which nothing else in the suite drives. One test proving two
    things beats one test plus an untested command.

    stderr is read but INTENTIONALLY NOT ASSERTED ON: diagnostics belong
    there by design, and pinning its shape would make this test brittle
    against any future logging line.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod

    cfg = config_mod.Config(name="t", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng = eng_mod.create(tmp_path / "e", cfg, author="test")
    eng.db.close()

    # The console script `pyproject.toml` installs, not `python -m` or an
    # import -- `hx mcp` is the command an operator's MCP client actually
    # spawns, matching `tests/integration/test_cli_session.py`'s own `HX`.
    hx_bin = Path(sys.executable).with_name("hx")
    assert hx_bin.is_file(), (
        f"{hx_bin} is not there -- the console script `pyproject.toml` "
        "installs. `pip install -e .`")

    messages = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')

    # `input=` writes the three messages and then closes stdin, giving
    # `serve_streams`'s `for line in stdin` its EOF -- without that the loop
    # blocks on a read that never returns and the timeout below is what
    # fails the suite instead of wedging it.
    proc = subprocess.run(
        [str(hx_bin), "mcp", "--root", str(eng.root)],
        input=messages, capture_output=True, text=True, timeout=20)

    lines = proc.stdout.splitlines()
    assert len(lines) == 2, (
        f"expected exactly two JSON-RPC lines, got {len(lines)}:\n"
        f"{proc.stdout!r}\nstderr: {proc.stderr!r}")
    first, second = (json.loads(line) for line in lines)
    assert first["jsonrpc"] == "2.0" and first["id"] == 1
    assert first["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert second["jsonrpc"] == "2.0" and second["id"] == 2
    assert len(second["result"]["tools"]) == 17
```

- [ ] **Step 2: Run to watch it fail**

Run: `.venv/bin/pytest tests/test_mcp_adapter.py -q`
Expected: FAIL — `ImportError: cannot import name 'mcp'`

- [ ] **Step 3: Write `src/hx/tools/adapters/mcp.py`**

```python
# src/hx/tools/adapters/mcp.py
"""`hx mcp` -- the seventeen tools over stdio, spoken as JSON-RPC 2.0.

HAND-ROLLED, AND THAT WAS THE SPEC'S ONE OPEN QUESTION FOR THIS PLAN. MCP's
stdio transport is newline-delimited JSON-RPC 2.0, and a server needs three
methods: `initialize`, `tools/list` and `tools/call`. That is this file. The
alternative was the `mcp` Python SDK -- a third dependency plus its transitive
closure, inside the one process that holds this engagement's credentials, its
Burp and the operator's halt path. This project runs on two Python
dependencies and a Java extension with none, and a security tool's dependency
footprint is part of its argument. Revisit if MCP's transport requirements
grow past three methods and a line of JSON.

THIS ADAPTER IS ONE PROCESS FOR A WHOLE CONVERSATION, which is the only reason
egress works at all. `hx.session.session()` tears Burp down on every exit, so
`hx tool` -- one process per call -- has nothing for a session to outlive and
reports `no_host`. Here there is an `ExitStack` around the serve loop:
`run.start` pushes a session onto it, `run.finish` pops it, and ANY exit from
`serve` -- return, exception, the agent closing the pipe -- unwinds it. That
is spec section 8's "a crash must not orphan a JVM", first of its three
layers.

`why` TRAVELS INSIDE THE ARGUMENTS AND IS TAKEN BACK OUT. MCP hands a tool one
arguments object and has nowhere else to put Principle 5's reason, so
`tools/list` publishes `why` as a required property of every mutating tool and
`tools/call` pops it before `dispatch` validates -- `ToolSpec.params` sets
`additionalProperties: false` and would refuse it otherwise. The published
schema and the enforced schema are therefore NOT the same object, which is
worth saying out loud: `tool_schema` builds the published one from the
enforced one, and a test runs `check_schema` over the result so the extra
property cannot become a constraint nothing applies.

STDOUT IS THE PROTOCOL. Nothing else may be written to it -- not a print, not
a warning, not a traceback. A newline-delimited protocol has no
resynchronisation point, so one stray line desynchronises the client for the
rest of the conversation. Diagnostics go to stderr.
"""
from __future__ import annotations

import contextlib
import json
import sys

from .. import dispatch as dispatch_mod
from .. import impl  # noqa: F401 -- registers every tool
from .. import registry
from . import cli as cli_adapter

#: The MCP revision this server speaks. A client that asks for another is
#: answered with this one, which is what the specification says to do: the
#: server states what it supports and the client decides.
PROTOCOL_VERSION = "2025-06-18"

SERVER_INFO = {"name": "hx", "version": "0.1.0"}

#: JSON-RPC 2.0 s5.1.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603

WHY_DESCRIPTION = (
    "Why you are doing this, in a sentence. It is written to agent_action "
    "and read by whoever asks what this run did.")


def tool_schema(tool) -> dict:
    """One `tools/list` entry: the enforced schema, plus `why` when it needs
    one.

    A COPY, never the registered object. `ToolSpec` is frozen and its
    `params` is the dict `dispatch` validates against; adding a key to it in
    place would publish a property the validator then refuses.
    """
    params = json.loads(json.dumps(tool.params))
    if tool.requires_why:
        params.setdefault("properties", {})["why"] = {
            "type": "string", "minLength": 1, "maxLength": 500,
            "description": WHY_DESCRIPTION}
        params["required"] = sorted(set(params.get("required", [])) | {"why"})
    return {"name": tool.name, "description": tool.summary,
            "inputSchema": params}


def _ok(msg_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def handle(ctx, msg) -> dict | None:
    """One message in, one reply out -- or None for a notification.

    A NOTIFICATION IS A MESSAGE WITH NO `id`, and answering one is a protocol
    violation. `notifications/initialized` is the message every client sends
    the moment `initialize` returns, so a server that replied to it would
    break on its first real conversation rather than in some corner.
    """
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _err(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
    msg_id = msg.get("id")
    method = msg.get("method")
    if msg_id is None:
        return None
    if method == "initialize":
        return _ok(msg_id, {"protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {"tools": {}},
                            "serverInfo": SERVER_INFO})
    if method == "tools/list":
        return _ok(msg_id, {"tools": [tool_schema(registry.TOOLS[n])
                                      for n in sorted(registry.TOOLS)]})
    if method == "tools/call":
        params = msg.get("params") or {}
        args = dict(params.get("arguments") or {})
        # POPPED, not passed through. `ToolSpec.params` is
        # additionalProperties: false, so a `why` left in here would be
        # refused as bad_args -- and Principle 5's reason belongs in
        # agent_action, which is where `dispatch`'s keyword puts it.
        why = args.pop("why", None)
        env = dispatch_mod.dispatch(ctx, params.get("name"), args, why=why)
        # A REFUSAL IS A RESULT, NOT A TRANSPORT ERROR. `isError` is MCP's
        # way of saying the tool answered badly; a JSON-RPC `error` would say
        # the SERVER failed, would lose the envelope, and would make
        # `scope_denied` -- the extension working exactly as designed -- look
        # like a broken server.
        return _ok(msg_id, {
            "content": [{"type": "text",
                         "text": json.dumps(env.as_dict(), sort_keys=True)}],
            "isError": not env.ran})
    return _err(msg_id, METHOD_NOT_FOUND, f"unknown method {method!r}")


def serve_streams(ctx, stdin, stdout) -> None:
    """The loop. Takes streams so a test can drive it without a subprocess.

    ONE BAD LINE MUST NOT END THE CONVERSATION. A truncated write or a stray
    log line from the agent's side is a parse error for that message and
    nothing more -- ending the loop would take the session, the run and the
    operator's halt path with it, over one malformed line.
    """
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            reply = _err(None, PARSE_ERROR, f"could not parse: {exc}")
        else:
            try:
                reply = handle(ctx, msg)
            except Exception as exc:            # noqa: BLE001
                # `dispatch` never raises, so reaching this is a defect in
                # THIS file. Named in the reply rather than swallowed, and
                # the loop continues: a broken `tools/list` should not cost
                # an operator their live session.
                reply = _err(msg.get("id") if isinstance(msg, dict) else None,
                             INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def serve(engagement) -> None:
    """`hx mcp`, wired to the real stdio.

    THE EXITSTACK IS THE POINT OF THIS FUNCTION. It is what `run.start`
    pushes a Burp onto, and every way out of here -- the agent closing the
    pipe, a raise, a signal that unwinds -- tears that Burp down.
    """
    with contextlib.ExitStack() as stack:
        ctx = cli_adapter.build_context(engagement, stack=stack)
        serve_streams(ctx, sys.stdin, sys.stdout)
```

- [ ] **Step 4: Add the `hx mcp` command**

In `src/hx/cli.py`, following the shape of the neighbouring commands (engagement resolution, error handling). **No marker.**

```python
@main.command()
@click.pass_context
def mcp(ctx):
    """Serve the tool layer over MCP on stdio.

    THE ADAPTER THAT CAN HOLD A BURP. `hx tool` is one process per call and
    `hx.session.session()` tears Burp down on every exit, so egress tools
    there answer `no_host`. This command is one process for the whole
    conversation: `run.start` brings a session up and `run.finish` -- or any
    exit from this command -- takes it down.

    NOTHING BUT JSON-RPC MAY REACH STDOUT while this runs.
    """
    eng = _open_engagement(ctx)     # follow the neighbouring commands
    mcp_adapter.serve(eng)
```

- [ ] **Step 5: Run everything**

```bash
.venv/bin/pytest -q && .venv/bin/ruff check src tests
```

Then drive it by hand once, because a protocol is worth seeing speak:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | .venv/bin/hx --engagement <path> mcp | .venv/bin/python -m json.tool --json-lines
```

Expected: exactly two lines out for three in, and 17 tools in the second.

- [ ] **Step 6: Commit**

```bash
git add src/hx/tools/adapters/mcp.py src/hx/cli.py tests/test_mcp_adapter.py
git commit -m "feat(mcp): hx mcp, hand-rolled JSON-RPC 2.0 over stdio

Settles the spec's section 13 open question: hand-rolled, no mcp SDK. The
stdio transport is newline-delimited JSON-RPC and the server needs three
methods. An SDK would be a third dependency plus its transitive closure
inside the process that holds this engagement's credentials, its Burp and the
operator's halt path.

One process for the whole conversation, with an ExitStack around the loop:
run.start pushes a Burp onto it and any exit unwinds it. That is what makes
the six egress tools reachable at all.

why travels inside the arguments -- MCP hands a tool one object -- and is
popped back out before dispatch validates, because ToolSpec.params is
additionalProperties: false. A test runs check_schema over every published
schema so the added property cannot become a constraint nothing enforces."
```

---

## Finishing the plan

- [ ] **Step 1: Arm the plan-drift markers**

Every block in this plan that describes a file which now exists must carry its `# path` marker, and every excerpt block must be a contiguous run of the file byte for byte. Run `scripts/sync_plan_block.py` for each, then:

```bash
.venv/bin/pytest tests/test_plan_matches_repo.py -q
```

It will fail on the count. Update `EXPECTED_BLOCKS` to the number reported, and **name the blocks in the commit message** — the constant exists so that a number moving is a decision somebody wrote down.

- [ ] **Step 2: Record the debts in `docs/DECISIONS.md`**

Add a `## The egress tools` chapter and these rows to the known-debt table:

| Debt | Why it is not paid |
|---|---|
| `http.grep` matches literal bytes, not regexes | `re` has no timeout and the pattern is agent-authored; a catastrophic backtrack would hang the process holding the Burp and the halt path. A regex design needs a bounded engine or a subprocess, and neither belongs in this plan. |
| `exchange.req_blob` on a `via='send'` row is the pre-injection request | The extension injects the identity header inside the JVM. Fixing it needs `Sender` to push an exchange frame — a Java change, and a second writer into the exchange table. |
| `resolved_ip` is NULL on every exchange row | True of the proxy writer too. Filling it on one path only would make `via` decide how much a row knows. |
| A send's `identity_state` is always `assumed` | A canary bracket proves a run; a single send has none. Proving one per send would double the traffic. |

- [ ] **Step 3: Update `README.md` if it lists the tools**

Check (`command grep -n "hx tool\|tool layer" README.md`) and, if the 11 are listed, make it 17 — and say which six need `hx mcp`.

- [ ] **Step 4: The full gate**

```bash
extension/build.sh                    # never run test.sh last; it leaves the jar stale
.venv/bin/pytest -q
.venv/bin/pytest -m integration -q
.venv/bin/ruff check src tests
.venv/bin/mypy src/hx || true         # non-blocking, as CI has it
extension/test.sh                     # unchanged by this plan; prove it
```

All green, or the plan is not done.

---

## Self-Review

Run against the spec with fresh eyes before dispatching Task 1.

**Spec coverage.** §7's six Plan B tools: `http.send` (Task 4), `http.grep` and `http.body` (Task 5), `http.replay_as` (Task 6), `scan.run` and `crawl.run` (Task 7). §8's session lifecycle: Task 3, with the three anti-orphan layers named. §9's MCP adapter and its open question: Task 8. §10's split: this plan is B, and it modifies `run.start` — which §10 warned it would, and which is why Task 3 reads Plan A's `run.start` rather than assuming it.

**Not covered, deliberately, and each is stated where it lands:** `delta_vs_baseline`'s `new_tokens` is capped and can be `null`; `http.grep` is literal-only; the send-path request blob is pre-injection. All four are in the DECISIONS table above.

**Type consistency.** `Issued` is produced in Task 1 and consumed in Tasks 4 and 6 under the same field names. `live.open_for`'s four reasons are asserted in Task 3's tests and rendered in `run.start`'s result. `_digest` is defined in Task 4 and reused in Task 6. `ensure_identity` returns `(id, generation)` in Task 3 and is passed to `issue`'s `identity=` parameter — which takes exactly that tuple, not a `Resolved`, in Task 1.

**The one structural risk.** Task 4's `_digest` guards against comparing a first-sight surface with its own exchange as exemplar. That guard has two SQL round trips and an ordering assumption about when `issue` writes the exemplar. If Task 4's review finds it wrong, the fix belongs in `delta.baseline_for` — give it the exchange id to exclude — not in a third query at the call site.

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-08-31-tool-layer-egress.md`. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration. This is how Plan A ran, and its per-task reviews found a defect in every one of eleven tasks.

**2. Inline Execution** — tasks executed in this session with checkpoints for review.
