# hx web app — design spec

**Date:** 2026-09-01 · **Status:** approved
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md`
(§4 enforcement invariant, §5 data model, §7 identity and redaction,
§8 tool layer, §11 web app, §12 reporting, §13 v1 scope)

This builds §13's *"the web app screens"* — one of the two v1 items still
unbuilt, the crawler being the other. It is where the act §8 forbids the
agent becomes possible: *"Creating an engagement and confirming a finding
are human acts; they live in the CLI and the web app."*

---

## 1. What this is, and what it deliberately is not

**It is a read-only window onto an engagement store, plus exactly two
buttons.** §11 fixes the control surface at two things — the STOP button
and finding triage — and this design does not widen it. Message editing,
resend and payload crafting are Repeater's job and are not here.

**It opens no egress path and enforces nothing.** §4's invariant is that
every byte leaving the machine crosses one of two points inside the JVM.
The web app sends nothing to a target. It has no bridge client, no
`Sender`, no socket to the extension. The only bytes it writes anywhere
are one halt sentinel and two SQLite rows.

So the security question here is not "what does the web app enforce".
It is **"what can the web app leak, and to whom."** The answer has two
halves, and §4 has already solved one of them: credential redaction runs
extension-side, before hashing, so the blob bytes this app renders are
already redacted. The half that remains is this app's own — it renders
attacker-influenced bytes into a browser with no authentication in front
of it, and §4 (*"a loopback port is reachable by any local process or
browser tab"*) is exactly the reasoning that applies. Section 4 below is
that threat model.

**It is not a second reader API.** Reads do not go through
`tools/dispatch.py`; section 5 gives the reason.

---

## 2. What already exists

Verified in the tree on 2026-09-01 at master `caf6933`, not recalled:

| Fact | Where |
|---|---|
| A read-only connection factory, with the same pragmas | `store/db.py::connect(path, readonly=True)` |
| Per-engagement layout: `hx.db`, `config.yaml`, `blobs/`, `exports/`, all `0700`/`0600` | `engagement.create`, `store/paths.py::secure_mkdir` |
| Schema version 9, and `open_` refuses a store that does not match | `store/db.py::SCHEMA_VERSION`, `engagement.open_` |
| The 14 tables, including `finding_status_event` and `agent_action` | `store/schema.sql` |
| Four triggers guarding status: agent-cannot-confirm on INSERT and UPDATE, and append-only on both | `store/schema.sql` |
| `upsert_finding` deliberately never touches `status` or `first_seen_run` | `store/records.py::upsert_finding` |
| URL userinfo redaction, character-for-character the same rule as the Java side | `store/records.py::redact_url` |
| The report's single redaction choke point, wrapping it | `report.py::_redact` |
| Credential redaction of blob bytes, before hashing, five jobs | `extension/src/hx/send/Redactor.java` |
| A complete, tested STOP: sentinel written atomically at `0o600`, plus an `agent_action` row with `actor='operator'` | `halt.py::OperatorHalt` |
| The staleness rule for a run whose harness died | `run.py::reap_stale` |
| A throwaway on-disk engagement fixture | `tests/conftest.py::engagement` |
| The name rule for an engagement directory | `cli.py::_NAME_RE` |

**Nothing in `src/` has ever written `finding_status_event`.** The table,
its four triggers and their tests exist; the writer does not. This design
supplies it.

---

## 3. Process model

### 3.1 Entry point

A new CLI command:

```
hx web [--base DIR] [--port N]
```

**There is no `--host` option.** §11 says v1 binds `127.0.0.1` only, and
the way to guarantee that is to give the operator no flag to get it
wrong — the same reasoning the `TargetServer` fixture uses when it
refuses any address outside `127.0.0.0/8`. §11 already states the terms
on which a wider binding arrives: *"when it is bound, a per-install
bearer token lands before the first write endpoint."* Neither ships here.

`--base` names the engagements **parent** directory and defaults to
`cli.default_root()`. This matches what `hx new --root` already means.

> **Known inconsistency, recorded as debt, not fixed here.** `hx new
> --root BASE` creates `BASE/NAME` — the parent. Every other command
> passes `--root` to `engagement.open_`, which wants the engagement
> directory itself. `default_root()` serves as both. Renaming a flag on
> six merged commands is not this plan's work; `--base` is a new name
> that does not inherit the ambiguity, and `DECISIONS.md` gains a debt
> row stating both meanings.

### 3.2 Dependencies and layout

Three new runtime dependencies — `starlette`, `jinja2`, `uvicorn` —
taking the installed closure from 2 packages to 10, measured:
`anyio click h11 idna jinja2 markupsafe pyyaml starlette
typing-extensions uvicorn`.
One new dev dependency, `httpx`, which `TestClient` is built on. htmx is
**vendored** into the tree, not installed and not fetched from a CDN,
with its version and sha256 recorded beside it.

```
src/hx/web/__init__.py
src/hx/web/app.py          Starlette app factory, middleware, routes
src/hx/web/registry.py     base-dir scan; the engagement allowlist
src/hx/web/reads.py        read-only queries, one per screen
src/hx/web/render.py       Jinja environment and filters (redact_url)
src/hx/web/templates/      base.html and one per screen
src/hx/web/static/         vendored htmx, one stylesheet
src/hx/triage.py           set_status: the only writer of finding_status_event
src/hx/coverage.py         the query half extracted from report._coverage
```

Each file has one job, and `reads.py` is the one to watch: if it grows
past a few hundred lines it should split per screen rather than become
the module that knows everything.

### 3.3 Engagement registry

The registry scans `<base>/*/hx.db` **per request** rather than caching a
listing, so an engagement created in another terminal appears on refresh.

The scan produces the **allowlist**: a URL path segment that is not the
directory name of a scanned engagement is a 404. This is an allowlist,
not a sanitiser applied to a path join, and it is the whole traversal
defence.

An engagement whose `PRAGMA user_version` does not match `SCHEMA_VERSION`
renders as a row saying so, naming both versions. `engagement.open_`
raises on mismatch, and one stale directory must not take down the list.

### 3.4 Connections

**Reads: a fresh read-only connection per request, closed on the way
out.** Starlette runs `def` endpoints in a threadpool and `sqlite3`
connections default to `check_same_thread=True`, so a cached connection
raises `ProgrammingError` as soon as two requests land on different
threads. Opening a WAL reader is a file open; per-request connections
mean the app holds no shared mutable state.

`connect(..., readonly=True)` opens `file:...?mode=ro`, so a write
attempt from a read path fails at the SQLite layer. A bug in a query
helper or a template filter cannot mutate an engagement. This database is
evidence, and `scope_version` and `finding_status_event` are append-only
because someone may one day dispute what it says; a read path that
*cannot* write is a stronger claim than one that merely does not.

**Writes: a short-lived read-write connection per action**, opened for
the action and closed immediately. WAL plus the existing
`busy_timeout=5000` covers the agent or the CLI writing concurrently.
There is no Python-side writer queue today — §5's *"in-process queue"* is
`Capture.java`, extension-side — so a second OS process writing the same
file is the existing situation, not a new one.

### 3.5 Stale runs are rendered, never reaped

`run.reap_stale` is an UPDATE, so the read path cannot call it. But §5 is
explicit that a run left `running` by a dead harness *"resolves to
`error`, not `completed`"*, and a screen showing it as live would be the
first thing an operator sees after a crash.

The predicate — `status='running' AND COALESCE(heartbeat_us, started_us)
< now - window` — moves into a shared `run.is_stale()` that both
`reap_stale` and the web renderer call, so there is one definition of
stale rather than two that can drift.

---

## 4. Threat model: this app renders bytes captured from hostile targets

This is what makes the web app different from an ordinary internal
dashboard, and the naive version is genuinely dangerous.

**The core threat.** The exchange viewer displays response bodies
captured from a client's application. Those bodies are
attacker-influenced by definition — half the check corpus exists to find
places where attacker input comes back in them. A body containing
`<script>` rendered unescaped executes in the operator's browser, on this
app's own origin, with no authentication in front of it, and can
therefore read every engagement the app can reach. A target's response
body becoming a cross-client data breach is the failure mode to design
against.

**DNS rebinding defeats "bound to loopback".** Binding `127.0.0.1` stops
remote packets; it does not stop a page the operator is browsing from
issuing requests to `127.0.0.1:PORT`. A hostile site that resolves its
own name to `127.0.0.1` gets same-origin access to the whole app. §4
already names the shape of this — *"a loopback port is reachable by any
local process or browser tab"* — as its reason for the bridge being a
Unix socket. The web app cannot be a Unix socket, so it takes the
standard stateless defence instead.

| Threat | Defence |
|---|---|
| Stored XSS from a captured response body | Jinja autoescape, **asserted by a test** rather than trusted as a framework default. No `\|safe`, no `Markup`, nothing rendered into a `<script>` or bare-attribute context |
| The same, defence in depth | `default-src 'none'` CSP with `script-src 'self'`; htmx **vendored as a file** with its version and sha256 recorded — no CDN, no inline handlers, no `hx-on:` |
| DNS rebinding | `Host` header allowlist: `127.0.0.1:PORT` and `localhost:PORT`, everything else refused |
| CSRF on the two write routes | `Origin` / `Sec-Fetch-Site` check, refused **before** any write |
| Content sniffing | `X-Content-Type-Options: nosniff`. Any raw-bytes route is `application/octet-stream` with `Content-Disposition: attachment`, never the captured `Content-Type` |
| Path traversal by engagement name | The registry scan is the allowlist (§3.3) |
| Credentials in URL columns | One Jinja filter wrapping `records.redact_url`, mirroring `report._redact`. Never a third rule |
| Evidence in logs | uvicorn access log off by default |

**Body bytes decode as `latin-1`**, matching `tools/impl/http.py`'s
`TEXT = "latin-1"`. It round-trips all 256 byte values, so the viewer
shows what was on the wire and agrees with what `http.grep` matched.

**The app does not redact blob bytes, and must not.** `Redactor.java`
runs extension-side before hashing, so what is on disk already carries
`{{identity:<id>:authz}}` and `{{observed:set-cookie}}` where credentials
were. §4's rule is that these decisions live in the JVM and *"Python must
never gain a second place that decides any of them."* The web app
inherits the guarantee. The one thing it does redact is URL userinfo in
table columns, and only by calling the existing shared rule.

---

## 5. The data layer, and the one extraction

### 5.1 Reads do not go through the tool layer

Reusing `surface.query`, `finding.query` and the rest would be the
DRY-looking choice. It is wrong on a fact: `dispatch` journals every
call, and `journal.record` defaults to `actor="agent"`. Browsing the UI
would write one `agent_action` row per page view, so the agent-transcript
screen would fill with the act of reading it, and the report's provenance
section with it. The audit trail would stop being able to answer "what
did the agent do", which is the question it exists to answer.

The shapes disagree too. The tool layer's envelopes are built for a model
with a context window and an audit obligation — handles and digests
rather than payloads, match-addressed reads, token-budget caps. A human
with a browser has neither constraint, and the exchange viewer needs
whole bodies.

So `src/hx/web/` owns its read queries against `connect(readonly=True)`.

### 5.2 Coverage is extracted, and only coverage

`report._coverage` fuses its query with its Markdown. What it encodes is
not a query — it is §12 reasoning learned the hard way, and its own
docstring records the failure: *"ten captured surfaces with one scanned
rendered as four `clean 1` rows and no note."* It now states the
denominator, names the surfaces nothing answered for, and prefixes
**"These numbers are partial"** when a run behind it did not finish.

If the overview screen writes its own coverage query it will lose all of
that and show a reassuring number on exactly the engagements where the
report shows a warning. Two surfaces of one product disagreeing about
what was tested, in front of a client, is the §12 failure with extra
steps.

**Therefore:** the query half of coverage — the captured-surface count,
the untested set, the per-`(check_id, verdict)` grouping and the
unfinished-run flag — moves into a shared module returning data.
`report._coverage` renders Markdown from it; the overview screen renders
HTML from it. A test asserts both produce the same numbers from one
store.

**Scope of the extraction is coverage and nothing else.** The other
fourteen `report.py` helpers stay where they are. This is a targeted
improvement to code the work touches, not a refactor of a merged module.

**Cost check:** `2026-08-27-checks-and-reporting.md` already carries
`<!-- plan-drift: pending -->`, so its four blocks quoting `report.py`
are not compared and will not stale. The web plans must not claim that
marker — at most one plan may hold it.

---

## 6. Screens and routes

### 6.1 Plan A

| Route | Screen |
|---|---|
| `GET /` | **Engagements.** Name, client, status, created, run and finding counts, severity breakdown. An unopenable store renders as a row naming its schema version |
| `GET /e/{name}` | **Overview.** Scope and `scope_version.sha256`, the `authorization` in force, runs (stale rendered as `error`), coverage summary, severity counts, drops warning, halt banner |
| `GET /e/{name}/surfaces` | **Surface.** Method, scheme, host, port, path template, query keys, kind, `discovered_by`, exchange count, checks answered |
| `GET /e/{name}/findings` | **Findings.** Severity, title, status, surface, confidence, first and last seen; filters on severity and status |
| `GET /e/{name}/findings/{id}` | **Finding detail.** Description, impact, remediation, CWE, references, payload, insertion, the evidence chain, observation history, status history |
| `GET /e/{name}/exchanges/{id}` | **Plain exchange view** — escaped `<pre>` request and response plus metadata. Plan B upgrades this route in place |
| `POST /e/{name}/findings/{id}/status` | **Triage** |
| `POST /e/{name}/halt` | **STOP** |

**Why the plain exchange view is in Plan A.** §8 puts triage in v1
because it has no substitute, but triage has a prerequisite: you cannot
decide whether a finding is real without looking at the exchange that
produced it. Shipping the button with an evidence chain whose links go
nowhere would ship the act without the thing that makes performing it
meaningful.

### 6.2 Plan B

| Route | Screen |
|---|---|
| `GET /e/{name}/exchanges` | Exchange list; filters on run, surface, outcome, status |
| `GET /e/{name}/exchanges/{id}` | **The exchange viewer** — §11's *"one screen worth real effort"*: syntax highlighting, in-body search, hex toggle |
| `GET /e/{name}/exchanges/{a}/diff/{b}` | Side-by-side `replay_as` diff |
| `GET /e/{name}/runs/{id}` | Run progress |
| `GET /e/{name}/runs/{id}/events` | The SSE stream behind it |
| `GET /e/{name}/transcript` | Agent transcript from `agent_action` |

### 6.3 Two rules the screens follow

**The app can stop but not start.** STOP writes the halt sentinel;
**resume stays CLI-only**, per §11's *"control in v1 is exactly two
things"*. The asymmetry is deliberate and the UI says so: one click to
stop, a deliberate trip to a terminal to lift it.

**Halt renders the way the extension reads it.** §4 is explicit that an
unreadable sentinel — permissions, a vanished directory, an I/O error —
*is* halted: *"unknown state is stop."* `OperatorHalt.halted` already
answers that way. The banner follows it rather than showing "unknown".

**A caveat sits with the figure it qualifies.** A run with
`dropped_total > 0` has coverage numbers that are a floor, not a count
(§5), and the overview says so in the same place it shows the number.
Putting the caveat on a different screen is how the honest version loses
to the reassuring one.

---

## 7. The two human acts

### 7.1 STOP

A route over existing machinery: open a read-write connection, call
`halt.OperatorHalt(engagement_dir, conn).halt(reason)`, close. That
already writes the sentinel atomically at `0o600` and an `agent_action`
row with `actor='operator'`, `tool='halt'`. `OperatorHalt` reads its
state from the store and the filesystem on construction, so a fresh
instance per request is correct, and `_write_sentinel` writes a temp file
and `os.replace`s it, so halting twice is idempotent.

**No new halt logic.** A second implementation of "stop" is the last
thing this project needs.

### 7.2 Triage

`src/hx/triage.py`, the first writer of `finding_status_event`:

```
set_status(conn, *, finding_id, to_status, note=None, now_us=None) -> StatusChange
```

- **`actor='human'` is hardcoded, not a parameter.** Both callers are
  humans; a parameter is a slot a future caller fills in wrongly. The
  enforcement stays where it already is — §8's *"the tool registry is an
  allowlist: what is not in it has no path"* — and a test asserts no
  triage name is ever registered.
- **Targets are `confirmed` and `false_positive` only**, per §11. Both
  directions work between them, so a mistake is correctable and the
  append-only log keeps the correction visible. `triaged` and `reported`
  are unreachable in v1.
- **The event row and the `finding.status` projection are written in one
  `db.transaction`** — both or neither. The event is the source of truth;
  the column is a read optimisation, as `schema.sql` already says.
- **Repeating the current status is an idempotent no-op** that writes
  nothing. A double-clicked button must not put `confirmed → confirmed`
  in an audit trail.
- **A note is required for `false_positive`, optional for `confirmed`.**
  Dismissing a finding is the decision a client can challenge and a
  retest must honour, so "why did you drop this" is answered at the
  moment it is dropped. Confirming is the bulk action and carries no
  friction.
- **No optimistic concurrency in v1.** Two operators triaging one finding
  both get events recorded; last write wins the projection. Auditable,
  and a version token is machinery for a problem that does not exist yet.

**A CLI command lands with it:**
`hx triage FINDING_ID --status confirmed|false_positive [--note TEXT]`,
because §8 says triage lives in the CLI *and* the web app.

### 7.3 The note reaches the report

`report._findings` renders `· *status: false_positive*` with no reason
attached, so a dismissed finding reaches the client deliverable labelled
but unargued. That is §12's rule pointed at triage instead of coverage: a
report that cannot distinguish *we checked and it is not real* from *we
did not want to write it up*.

The status line gains the latest `finding_status_event.note`:
`*status: false_positive — "<note>"*`. The field and its destination land
together, or the requirement to write a note is friction that goes
nowhere.

---

## 8. Two plans

**Plan A — skeleton, read screens, and the two human acts.** The
Starlette app factory, the engagement registry, the read layer, the
coverage extraction, the base template and vendored htmx, the `hx web`
and `hx triage` commands, and the eight routes of §6.1. Ends with an app
an engagement can actually be run from.

**Plan B — depth and liveness.** The exchange viewer with real effort,
the `replay_as` diff, SSE run progress, and the agent transcript.

Plan A's skeleton is proven before Plan B builds the hard screen on it,
and each lands as working software with its own review cycle.

---

## 9. Testing

**No new integration tests.** The web app never touches Burp, so the
46-test integration suite is unchanged. One new dev dependency: `httpx`,
which `starlette.testclient.TestClient` is built on.

Two fixtures over the existing `engagement`: a `web_base` holding two or
three engagements — so the list screen and the isolation tests have
something real — and a `client` wrapping it in a `TestClient`.

**1. Screens render the right data.** Not `status_code == 200`; this repo
has shipped that shape of test before. Each screen test asserts something
that changes if the query is wrong: the specific title appears, the count
matches the rows inserted, the surface absent from `check_run` is the one
named as untested.

**2. Security invariants, each written so a mutation turns it red.**

| Test | Mutation that must break it |
|---|---|
| A response body containing `<script>` renders escaped, and the raw form is absent from the whole page | Turn autoescape off |
| `Host: evil.example` is refused | Remove the middleware |
| A cross-origin POST to triage is refused **and the status is unchanged** | Remove the Origin check — asserting the 403 alone passes code that writes first |
| The CSP header carries `default-src 'none'` | Drop the header |
| The read layer's connection raises on write | Change `readonly=True` to `False` |
| `/e/{traversal}` answers 404 | Replace the registry allowlist with a path join |
| `http://user:pass@host/` in `exchange.url`: `pass` absent from the entire response body | Skip the `redact_url` filter |

The last gets its own file, `tests/test_credentials_never_reach_the_screen.py`,
mirroring the existing `test_credentials_never_reach_the_store.py`.

**3. §12 honesty.** A run with `dropped_total > 0` renders the floor
warning. A `running` run with a stale heartbeat renders `error`. And the
test that justifies the extraction: one store rendered through the
overview and through `report.render` produces the same coverage numbers.

**4. Triage.** One event plus one projection update; a repeated status
writes nothing; `false_positive` without a note is refused **with the
event count unchanged** (asserting only the exception passes code that
writes then raises); the note reaches `report.render`; no triage name is
in the tool registry.

Then the established mutation pass at the end of each plan — one mutation
at a time on a clean tree, confirming the intended test goes red.

---

## 10. Out of scope

| Deferred | Why it is safe to defer |
|---|---|
| Authentication and non-loopback binding | §11 sets the terms: the bearer token lands *before* the first write endpoint on a wider binding. Neither is needed while the app is loopback-only |
| Resume from the UI | §11 fixes control at two things. Lifting a halt should cost a deliberate trip to a terminal |
| Message editing, resend, payload crafting | §11: *"That is Repeater."* |
| Engagement creation from the UI | `hx new` exists and takes scope and authorisation arguments a form would have to reproduce |
| Optimistic concurrency on triage | One operator, an append-only log |
| Extracting the other fourteen `report.py` helpers | Only coverage is duplicated by these screens |
| Renaming `--root` across the merged commands | Recorded as debt in `DECISIONS.md`; `--base` is a new name that does not inherit the ambiguity |

---

## 11. Amendments to the master spec

Landing with this design, in the same commit:

- **§11 stack.** *"FastAPI + Jinja + htmx"* becomes *"Starlette + Jinja +
  htmx"*. Measured on 2026-09-01: `fastapi uvicorn jinja2` resolves to 15
  packages, `starlette uvicorn jinja2` to 9. The six FastAPI adds are
  `fastapi`, `pydantic`, `pydantic-core` (a compiled extension),
  `annotated-types`, `annotated-doc` and `typing-inspection`, and they
  buy request validation and OpenAPI generation that a server-rendered
  Jinja app with two write routes does not use. §11's own stated
  reason — *"a tool holding client engagement data should not pull
  hundreds of transitive packages to render a table"* — is the argument
  for the smaller closure. FastAPI is Starlette plus those two features;
  routing, `Jinja2Templates`, form parsing and `StreamingResponse` for
  SSE all come from Starlette itself.

---

## 12. Provenance

Brainstormed 2026-09-01 against master `caf6933`, immediately after the
tool layer landed (PRs #12 and #13; 2033 unit tests, 46 integration, all
17 v1 tools registered).

Four decisions were taken by the operator during the session: the app
browses a base directory rather than serving one engagement; the stack is
Starlette rather than FastAPI; the subsystem becomes one spec and two
plans; and the triage note is rendered into the report.

Two claims made during the session were checked against the tree and
corrected before reaching this document. Reads were said to be refused
under a halt — they are not: `dispatch`'s `halted` gate applies only to
`mutates` tools, deliberately, because *"a halt stops the engagement from
changing; it does not blind the operator's agent."* And the tool layer's
disqualification rests on journalling, which was verified at
`journal.record(..., actor="agent")` rather than assumed.
