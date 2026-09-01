# hx tool layer — design spec

**Date:** 2026-08-31 · **Status:** approved
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md`
(§3 architecture, §4 enforcement invariant, §5 data model, §8 tool layer,
§12 reporting, §13 v1 scope)

This builds §13's *"17 synchronous tools"* — the second of the three
unbuilt v1 items, and the one that makes the project's name literal.
`hx` is described as agent-driven and is today CLI-driven: nothing in
`src/hx/` dispatches anything.

---

## 1. What this is, and what it deliberately is not

**It is a typed, journalled front door onto code that already exists.**
`finding.record` calls `records.upsert_finding`. `report.render` calls
`report.render`. `scan.run` calls `scan.run`.

**It adds no security logic and opens no new egress path.** §4's invariant
is that every byte leaving the machine crosses one of two points inside
the JVM. A tool layer that could send bytes any other way would void it.
The tool layer's own §8 Principle 6 says the same from the other side:
*"the safety profile is enforced in the extension, and the tool layer
merely reports what was refused."*

So the security question for this design is not "what does the tool layer
enforce" — it is **"what can the tool layer fail to prevent an agent from
reaching."** §5 answers it: the registry is an allowlist, and what is not
in it has no code path.

---

## 2. What already exists

Verified in the tree on 2026-08-31 at master `fe3f2db`, not recalled:

| Fact | Where |
|---|---|
| `agent_action` table, with `actor`, `tool`, `args_blob`, `result_summary`, `why` | `store/schema.sql:371` |
| …already written, `actor='operator'`, by halt/resume | `halt.py:165,182` |
| …`args_blob` and `result_summary` are **never written by anything** | — |
| `finding.created_by` CHECK already admits `'agent'` | `schema.sql:238` |
| `trg_agent_cannot_confirm`(+`_update`) abort a `finding_status_event` with `actor='agent'` and `to_status` in `confirmed`/`reported` | `schema.sql:300,307` |
| `evidence` has `role`, `kind`, `note`; `record_evidence` hardcodes `'proof'`/`'exchange'` and writes no note | `schema.sql:344`, `records.py:1024` |
| Blob store holds full redacted bodies, content-addressed | `store/blobs.py`, `records.py:609` |
| `run` lifecycle: `open_run` / `close_run` / `current_run` / `heartbeat` | `run.py:39,60,110,53` |
| `scan.run(conn, *, engagement_id, blobs, config, checks, surface_filter, max_seconds, bridge, identity)` | `scan.py:209` |
| `report.render(conn, *, engagement_id, config, blobs=None)` | `report.py:260` |
| `checks.registry.enabled(config)`, `KNOWN_CLASSES` | `checks/registry.py:124,27` |
| `session.session(eng, *, instance, jar, …)` yields a `LiveSession` with `.bridge` | `session.py:833,701` |
| `OperatorHalt`, sentinel file + `agent_action` rows | `halt.py:60` |
| Dependencies: `PyYAML`, `click`. Java extension: none. | `pyproject.toml:6` |

**No crawler exists.** `records.py:635` still says in its own words that
*"`crawl` has no caller yet"*.

---

## 3. The definition is the deliverable

§8's first sentence is the architecture: *"One definition; an MCP adapter
in v1 and an embedded loop later."* The definition is what is built; every
transport is a thin adapter over it.

```
src/hx/tools/
  spec.py       ToolSpec — name, summary, params (JSON Schema), needs_egress,
                mutates, requires_why, handler
  registry.py   TOOLS: dict[str, ToolSpec]        ← the allowlist
  schema.py     a JSON Schema subset that REFUSES what it cannot enforce
  envelope.py   the uniform outer shape; Principle 3's page envelope
  dispatch.py   validate → authorise → call → journal
  errors.py     ToolRefused / ToolUnavailable, each carrying a closed reason
  impl/         run.py surface.py finding.py checks.py report.py
                http.py scan.py crawl.py
  adapters/
    cli.py      `hx tool <name> --json '{…}' [--why '…']`
    mcp.py      `hx mcp` — stdio JSON-RPC                       (Plan B)
```

`schema.py` exists because `params` is JSON Schema and validating it needs a
validator this project will not add a dependency for. The subset is the easy
half; the load-bearing half is that `check_schema` **refuses every keyword it
does not implement**, and `registry.register` calls it — so an unenforceable
schema fails at import and in a test run, never at an agent's call. A subset
that silently ignored `pattern` would publish a constraint to the agent that
nothing applies.

A handler is a plain function `(ctx, **args) -> result`. It does not
validate, does not authorise, does not journal, and does not know which
adapter called it. That is what makes the same tests drive the CLI
adapter, the MCP adapter and the v2 embedded loop.

`ctx` carries the engagement, the open connection, the blob store, the
config, the halt, the current run id, and — in Plan B — the live session.
It carries **no credential**: see §6.

---

## 4. The envelope, and the tri-state at this layer

Every tool returns the same outer shape. Not only list tools.

```json
{"tool": "surface.query", "outcome": "ok", "reason": null, "result": { … }}
```

`outcome` is one of five:

| outcome | meaning | example |
|---|---|---|
| `ok` | did the thing | `surface.query` returned 12 rows |
| `empty` | ran, nothing matched | `surface.query` returned 0 rows |
| `unavailable` | **could not run** | `crawl.run` always; an egress tool with no session |
| `refused` | a gate said no | halted; `why` missing; args invalid |
| `error` | a defect | an exception the handler did not expect |

**`empty` and `unavailable` are the whole reason this field exists.**
§8 Principle 4 requires the tri-state *at every layer*, and §12's
governing rule says a report that cannot distinguish *tested, clean* from
*never reached* is worse than no report. `check_run.verdict` already
carries that distinction for checks. Without it here, an agent whose
`surface.query` returned nothing because the *engagement is empty* writes
the same sentence as one whose query returned nothing because **the tool
could not run** — and §12's failure arrives one layer above the layer that
was hardened against it.

`reason` is non-null for `unavailable` and `refused`, and comes from a
closed vocabulary (§5). It is never free text: free text cannot be counted,
and the report counts refusals.

List tools put Principle 3's envelope inside `result`:

```json
{"rows": [ … ], "returned": 50, "total": 3400, "truncated": true,
 "next_cursor": "s-0f21", "facets": {"host": {"app.example.com": 3100}}}
```

Default limit **50**, hard ceiling **500**. Ordering is stable and by
novelty/risk, never by rowid — §8 Principle 3: *"a tool that can return
3,400 rows must never do so by default."*

---

## 5. Authorisation, in a published order

One order, published, that every layer and every test agrees on — the same
device that made §4's send path reviewable. The send path publishes
`not_configured, halted, scope, method, dangerous, rate, budget`. This
layer publishes:

```
not_registered → halted → missing_why → bad_args → no_session
```

Earliest matching rule wins. Each is terminal.

**`not_registered` is an absence, not a check.** The registry *is* the
allowlist. §8's "Not agent-facing" list — `engagement.create`,
`surface.add`, `finding.set_status` — is enforced by those names having no
entry, so there is no code path to forget on a future refactor. This is
the same move §4 makes in the JVM (two enforcement points, both
unavoidable) and the same move `IdentityRegistry.register` makes (the
three-name header allowlist lives at the one door, not at each caller).

**`halted` is consulted before every tool with `mutates=True`.** The STOP
button already stops issuance; it must also stop the agent, or a halted
engagement still accumulates agent-written findings. Read tools are
allowed while halted **deliberately**: an operator who has just hit STOP
wants the agent able to explain what it was doing.

**`missing_why` implements Principle 5** from the spec, not from each
handler remembering: `mutates=True` implies `requires_why=True`, and the
dispatcher refuses a blank or whitespace-only `why`.

**`bad_args`** — every tool declares JSON Schema params, and validation is
the dispatcher's, so an adapter cannot skip it.

**`no_session`** — Plan B. An egress tool outside a live run answers
`unavailable`, reason `no_session`, which is this layer's spelling of the
send path's `not_configured`.

**What the layer still does not decide:** scope, rate, budget, dangerous
paths, method allowlist, and credential redaction. All of those are in the
JVM and stay there. A tool reports what came back.

---

## 6. The journal

One `agent_action` row per dispatch — including refusals, which are the
rows that make the refusal counts in §12 real.

```
actor='agent'  tool=<name>  args_blob=<see below>  result_summary=<one line>
why=<Principle 5, or NULL for read tools>  run_id=<ctx run or NULL>
```

**Decision — `args_blob` holds inline JSON up to 4096 bytes, and above
that a `sha256:<digest>` reference into the engagement blob store.** The
column is TEXT and its name follows `req_blob`/`resp_blob`, which are
digests. But `http.send` can carry a 100 KB request and `scan.run` a
thousand surface ids, while the overwhelming majority of calls are a few
hundred bytes — and `run.journal` is the most-read tool in the set, so a
blob dereference per row is the wrong default. Inline-with-spill keeps the
common read cheap and refuses to truncate the record of what was tried.
The `sha256:` prefix makes the two cases unambiguous to a reader.

**Storing args verbatim is safe only because Principle 5 holds.** The
agent passes identity **by name**; `hx.identity.resolve` runs below this
layer and no tool returns a `Resolved`. If a tool ever accepted a
credential value, this column would become the place credentials are
written to disk in the clear — so `test_credentials_never_reach_the_store`
gains an `agent_action` case.

`run.journal(since | last_n, tool)` reads this table.

`run.resume()` composes the recovery brief §8 asks for, over
`agent_action` + `run` + `finding` + `check_run` + halt state: the current
run and its kind, surfaces covered, findings by severity, the last N
actions, and whether a halt is armed. §8: *"`run.journal` and `run.resume`
exist because a long run compacts… This is the loop-prevention hole and
the compaction-recovery hole, and they are the same hole."*

---

## 7. The 17 tools

`E` = needs a live session · `M` = mutates (⇒ requires `why`) · `B` in the `E` column = acquires that dependency in Plan B, not Plan A.

| Tool | E | M | Calls | Notes |
|---|:-:|:-:|---|---|
| `run.start(kind, why)` | B | ✓ | `run.open_run` | `kind ∈ browse\|crawl\|manual\|scan`. Plan B also launches Burp — §8. |
| `run.finish(status, note)` | | ✓ | `run.close_run` | `status ∈ completed\|aborted\|error`; `killed` is not the agent's to write. |
| `run.journal(since\|last_n, tool)` | | | `agent_action` | List envelope. |
| `run.resume()` | | | several | §6. |
| `surface.query(filter, cursor)` | | | `surface` | Filters: host, method, kind, `discovered_by`, `first_seen_run`, untested. |
| `surface.detail(surface_id)` | | | `surface` + `exchange` + `check_run` | Includes what has been tested and what has not. |
| `checks.list(class)` | | | `registry.enabled` | `class ∈ KNOWN_CLASSES`. Reports each check's hooks and whether it needs a bridge. |
| `finding.record(…)` | | ✓ | `records.upsert_finding` | Builds a `Candidate`, computes `records.dedupe_key`, writes `created_by='agent'`. |
| `finding.query(filter, cursor)` | | | `finding` | List envelope. |
| `evidence.attach(finding_id, exchange_id, role, note)` | | ✓ | `records.record_evidence` | **Needs a widening — see below.** |
| `report.render(engagement)` | | | `report.render` | Returns Markdown. |
| `http.send(request, identity, why)` | ✓ | ✓ | send path | Returns the §8 digest, not the body. |
| `http.grep(exchange_ids, pattern, part, context_bytes)` | | | blob store | Principle 2's documented default. |
| `http.body(exchange_id, part, range)` | | | blob store | The escape hatch, used after a match yields an offset. |
| `http.replay_as(exchange_id, identities[])` | ✓ | ✓ | send path | Per-identity digest + diff. |
| `scan.run(surface_ids[], checks[], budget)` | ✓ | ✓ | `scan.run` | Synchronous, bounded. Returns `check_run` outcomes. |
| `crawl.run(target, identity, max_pages, max_seconds)` | | | — | **Permanently `unavailable`, reason `not_implemented`.** |

### `finding.record` does not let the agent name its own dedupe key

`records.dedupe_key` takes ten keyword arguments and produces the
nine-part canonical string. `checks/base.Candidate`'s own docstring gives
the rule: *"The check does NOT compute the dedupe key. That is one
canonical string and one place must build it, or two checks will spell the
same finding two ways."* The same applies with more force to an agent. The
tool takes the Candidate fields and the surface; it computes the key.

`Candidate` requires `exchange_ids`, so **an agent-recorded finding must
cite exchanges**. That is not an incidental type constraint; it is the
property that keeps `created_by='agent'` findings answerable in a client
report.

### `crawl.run` is registered and always unavailable

Registering a tool that never succeeds looks like noise, and is the
opposite. An agent with no `crawl` tool has no reason to say discovery was
proxy-only; an agent that asks and is told `not_implemented` does. That is
§12's rule applied to the agent's own knowledge of its instrument, and it
is what §8 Principle 4's `unavailable` is for.

### `evidence.attach` needs `record_evidence` widened

`records.record_evidence` writes `role='proof', kind='exchange'` as
literals and never writes `note` — the columns exist, nothing has ever
filled them. §8 names both parameters. **Decision: widen
`record_evidence` with `role: str = "proof"` and `note: str | None = None`
keyword arguments rather than add a second evidence writer.** The default
preserves every existing call site byte for byte, and evidence keeps one
writer — which matters because the table is append-only by trigger
(`trg_evidence_no_update`, `trg_evidence_no_delete`) and a second writer
is a second chance to get `seq` wrong.

`kind` stays `'exchange'` and is **not** exposed: the only evidence kind
this layer can attach is an exchange the store already holds.

---

## 8. Session lifecycle (Plan B)

**`run.start` opens the bracket; `run.finish` closes it.** When the run's
kind implies egress, `run.start` launches Burp via `session.session(…)`
and holds the `LiveSession` on `ctx`; `run.finish` stops it. An egress
tool outside that bracket answers `unavailable / no_session`.

This is *"each command owns its own Burp"* — the rule already chosen for
the CLI — scaled to a session rather than replaced. §8 already gives
`run.start`/`run.finish` as the bracket, so the 17 map onto a run's
lifecycle without inventing a lifecycle.

`run.start` therefore grows between the two plans: in Plan A it opens the
run row; in Plan B it also launches a JVM. That seam is deliberate and
honest — a `browse` run never needed the tool layer to launch anything —
but it means Plan B modifies a tool Plan A shipped, and Plan B's review
must read Plan A's `run.start` rather than assume it.

**A crash must not orphan a JVM.** `run.finish` in a `finally`, plus the
existing `run.reap_stale` heartbeat path, plus `session.session`'s own
context-manager teardown.

---

## 9. Adapters

**`hx tool <name> --json '{…}' [--why '…']`** — the CLI adapter. Prints
the envelope as JSON on stdout, exit code 0 for `ok`/`empty`, non-zero
otherwise. This is what the test suite drives and what an agent with a
shell can use with no MCP wiring at all.

**`hx mcp`** — the MCP adapter, Plan B. `ToolSpec.params` is already JSON
Schema, so `tools/list` is a projection of the registry and `tools/call`
is one dispatch.

**Open question, settled in Plan B:** whether to depend on the `mcp` Python
SDK or hand-roll the stdio transport. MCP stdio is newline-delimited
JSON-RPC 2.0 and the server side needs `initialize`, `tools/list` and
`tools/call` — roughly 150 lines with no dependency. This project runs on
two Python dependencies and a Java extension with none, and a security
tool's dependency footprint is part of its argument. **Recommendation:
hand-roll, and revisit if MCP's transport requirements grow.**

---

## 10. Two plans

| | Tools | Needs Burp |
|---|---|:-:|
| **Plan A** — *the definition* | `run.start` `run.finish` `run.journal` `run.resume` `surface.query` `surface.detail` `finding.record` `finding.query` `evidence.attach` `checks.list` `report.render` (11) + registry, envelope, dispatcher, journal, CLI adapter | no |
| **Plan B** — *egress* | `http.send` `http.grep` `http.body` `http.replay_as` `scan.run` `crawl.run` (6) + session bracket + MCP adapter | yes |

`http.grep` and `http.body` are pure blob-store reads and could have sat
in Plan A. They stay in B so all four `http.*` tools get one design
review: Principle 2 makes `grep` and `body` the documented way to read
what `send` returned, and splitting them would ship two tools in A whose
primary purpose cannot be exercised there.

Plan A is testable with **no Burp at all**, which is the point of the
split: a fast suite and a review that is about the definition rather than
about a JVM.

---

## 11. Testing

Beyond per-tool tests, five properties are asserted about the layer:

1. **The registry matches §8's list, name for name.** A test holds the 17
   literal names and asserts set equality with `TOOLS`, so adding a tool
   without spec'ing it fails, and so does spec'ing one without building
   it. This mirrors `test_plan_matches_repo.py`'s existing discipline.
2. **The three not-agent-facing names are absent.** `engagement.create`,
   `surface.add`, `finding.set_status` are asserted *not* in `TOOLS`.
3. **The decision order is the published one.** A test constructs a call
   that trips several rules at once and asserts the earliest wins — the
   same test shape the send path's order already has.
4. **The agent cannot confirm its own finding, two ways over.** The
   registry has no `finding.set_status`, so there is no path; and
   `trg_agent_cannot_confirm` aborts any `finding_status_event` written
   with `actor='agent'` and `to_status` in `confirmed`/`reported`. The
   test asserts the absence *and* exercises the trigger, because the
   absence is the rule and the trigger is what survives someone adding
   the tool back.
5. **`agent_action.args_blob` never holds a credential-shaped string.**
   A new case in `test_credentials_never_reach_the_store.py`.

Every tool with `mutates=True` gets a test that it is refused while a halt
is armed.

---

## 12. Out of scope

Deferred by §13 and untouched here: the async job runner (`crawl.status`,
`scan.status`, a job table), `run.diff`, OAST tools, and the web app. The
crawler itself is the third gap and is not built here — `crawl.run` is
registered `unavailable` precisely so that stays visible.

Also out: any tool that widens scope, lifts a halt, resolves a credential,
or confirms a finding. Those are operator acts and live in the CLI and the
web app, per §8.

---

## 13. Open questions

1. **Whether `scan.run` stays synchronous** — inherited unchanged from
   §14.3 of the master spec. Revisit with measurements, not intuition.
2. **`run.resume()`'s brief has no size budget yet.** It is read after
   compaction, so it must fit in a context window that is by definition
   under pressure. A cap belongs in Plan A; the number needs a real
   engagement to set.
3. **MCP SDK versus hand-rolled stdio** — §9, settled in Plan B.

---

## 14. Provenance

Brainstormed 2026-08-31 against master `fe3f2db`. Four decisions taken by
the operator: definition plus two thin adapters; `crawl.run` registered
and `unavailable`; the session bracketed by `run.start`/`run.finish`; and
the split into two plans, no-egress first.
