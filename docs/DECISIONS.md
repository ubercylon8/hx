# Decisions

Why `hx` is shaped the way it is. Each entry is a decision that was actually contested
during implementation, with the reasoning and what it costs if it turns out wrong.

Distilled from the execution ledgers in `.superpowers/sdd/`, which are working files and
are not kept. This document is the durable record.

---

## Safety envelope

### Enforcement lives in Java, not Python

The Python side has no socket. It can only ask the extension to send, and the extension
can refuse. A bug in a check, a bad config parse, or a compromised Python process cannot
widen scope — it can only be denied.

*Cost if wrong:* the Java side is harder to change and needs its own test suite. Accepted;
that suite is 2,330 assertions and is the reason the envelope is trustworthy.

### Deny-all is the default and a halt is terminal

An unconfigured extension refuses everything. Once the halt sentinel exists, no later
message re-opens the run — `hx resume` starts a *new* run rather than reviving the halted
one.

*Cost if wrong:* an operator who halts by accident starts over. Cheap, and the opposite
error is unbounded.

### The operator/agent split is decided by listener, never by traffic

Rate limits, the method allowlist and the dangerous-path denylist apply to `hx`'s traffic
and not to the operator's browser. The two are told apart by **which proxy listener the
request arrived on**.

*Why not a header or a marker:* anything in the traffic can be forged by the target. A
target that could make its own requests look like operator traffic would exempt itself from
every rule.

### A refused request spends no budget

`Limiter.check` increments its counter only on the allow path. A gate refusal never leaves
the JVM.

This is what makes the client-side retry safe: `ProbeSender` waits out a `rate_limited`
refusal and retries, bounded, and cannot double-spend the run budget by doing so. The
published decision order (`not_configured → halted → scope → method → dangerous → rate →
budget`) also means a `rate_limited` answer implies scope, method and dangerous already
passed — so waiting can never turn a denial into an allow.

### `hx` never bundles or redistributes Burp

You bring your own copy. CI enforces it (`.github/workflows/no-burp.yml`) rather than
trusting convention. The Montoya API jar is fetched from Maven Central at build time,
because it is the interface, not the product.

---

## Reporting honesty

### A report that cannot tell "tested, clean" from "never reached" is worse than no report

This is the rule the rest of this section serves. Coverage is part of the deliverable: a
check that could not run appears by name with a reason, never as an absence.

### An active check may never retire a finding

A finding retires when a check *examined* its issue type and did not find it. That is sound
only if `clean` means "I actually tested this" — and eight distinct ways were found for an
active check to answer `clean` from a probe that tested nothing:

1. probing the literal `{id}` path template
2. `str.replace` of a placeholder against a concrete path, silently matching nothing and
   re-sending the original request
3. unauthenticated probes against authenticated surfaces
4. a WAF `403` or a `5xx` read as a conclusive negative
5. a `302 → /login`
6. a `state_changing` surface probed with a `GET`
7. a **200 login page**, which no response-status rule can catch
8. an enumeration of "refusal" statuses that let `422`, `410`, `407` and ~11 others through

The first six and the eighth are fixed. The seventh cannot be fixed while probes are
unauthenticated, so retirement was removed from the active corpus entirely.

*Why removal rather than a ninth guard:* each guard is a discriminator that can be wrong,
and this one had been wrong seven times. Removing the consequence removes the class.

**Superseded 2026-08-31 by the identity work — read this heading as "may not retire
without proof".** The seventh spelling's cause was that probes were unauthenticated, and
that is no longer true. `hx.scan._retirable` now honours an active check's `considered`
when **both** hold:

- the run's `IdentityWindow.state_for_run()` is `proven`, and
- the finding sits on the `(scheme, host, port)` the liveness canary actually proved.

`proven` is **necessary and not sufficient** — a ninth spelling was found in exactly that
gap. `origins` had defaulted to the whole of `scope.include`, so probes at hosts the canary
never reached were stamped `proven` and retired findings there. See *Identity* below.

Anonymous runs, `assumed` runs and `dead` runs still retire nothing, byte for byte as
before. Passive retirement was never affected: it reads captured traffic and never depended
on a session.

### A response is an answer only if it is 2xx

`unanswered` is an **allowlist** (`range(200, 300)`), not a list of statuses that mean
refusal. An enumeration must be maintained against a growing web; an allowlist of "the
application processed my payload" cannot go stale.

The same pattern appears twice more, for the same reason: `probe._NOT_ISSUED` is an
exclusion set so an unknown error class counts as traffic, and the rate-limit retry is a
one-class allowlist so a new error class stays terminal. **Unknown input gets the safe
treatment.**

`open_redirect` needs no exception: its marker-in-`Location` test runs before the status
gate, so its legitimate `302` finding is already a candidate.

### `requests_sent` counts issuances and defaults to counting

Refusals the gate decides before issuing count zero; **everything else counts**, including
error classes this build has never seen. Overstating what `hx` put on a client's system is
survivable; understating it is not.

### Findings are keyed on nine parts

`check | issue_type | scheme | host | port | method | path_template | insertion_kind |
insertion_name`. `scope_level` blanks parts; it is not itself a part.

---

## Scope decisions

### GET-only probes, and surfaces that cannot be probed are skipped

Body-parameter, mutating and DoS probing are out of v1. A `state_changing` surface, or a
`HEAD` surface, is therefore **skipped with a reason** rather than probed with a GET —
probing a POST endpoint with a GET tests something the client's users never do.

`HEAD` is excluded even though a GET response is a superset of a HEAD response, because
three checks read a response *body* and a HEAD surface has none. The exclusion is wider
than the hazard (a HEAD surface really can reflect into a header, and that finding is given
up with the unsound ones); consistency with the identity argument is worth more than the
coverage.

### Probes use the exemplar's concrete path, never the template

And `ProbeSender.get` **raises** on a path still carrying a `{placeholder}`, so a future
check cannot reintroduce the bug by forgetting. Substitution aligns address and template by
segment *index* and replaces every occurrence, because `insertion.derive` keys placeholders
into a set by name — a template repeating `{id}` yields one insertion point, and a
first-only substitution would leave the real value at the spot it skipped.

### Cookie and credential-header insertion points are not probed

The send path refuses credentials it did not inject, so probing them spends budget on a
guaranteed refusal. A refusal on one insertion point ends that point, not the check.

*Still true after the identity work, and "did not inject" now means something.* Until then
nothing injected anything, so `unmanaged_credential` refused every credential header it saw.
`hx` now injects one deliberately — and a **check** still cannot put a credential anywhere.
The runner binds the identity; §7 keeps identity below the check layer, and a check may not
choose, read, or ask about one.

---

## Identity

### A credential value never appears in `config.yaml`

`hx.engagement.record_scope_version` writes the config YAML **verbatim** into
`scope_version.yaml` (`engagement.py:114`), a table the schema calls "append-only:
tamper-evidence for contract disputes". A credential written there is copied, unredactable,
into a table designed to be impossible to rewrite — the same warning §7 gives about the
content-addressed blob store, in a different table.

So the config **declares** an identity and the environment **supplies** the secret. A
`Resolved` holds the value and never touches `Config`; the two never meet in a serialiser,
and `Resolved.__repr__` is overridden so a dataclass repr cannot put a live session cookie
into every traceback that happens to hold one.

*Second property, for free:* rotating a credential changes no scope hash. Rotating a session
is not a movement of the engagement boundary, and a scope-version row that appeared because
a cookie expired would make the tamper-evident record lie about what it is evidence of.

### Identity is its own bridge frame, not a `configure` key

A later `configure` naming a different rate or budget is *refused, not applied* — a run must
not talk its way into a larger allowance mid-flight. A programmatic refresh has to advance a
generation **without** re-opening scope, so folding identity into `configure` would either
weaken that rule or make refresh impossible.

It is also the only frame in the protocol whose payload is a secret. Kind and correlation id
may be logged; the body never.

### Injection happens after every gate, and the range is registered before the copy

Order in `Sender.decideAndIssue` is `unmanagedCredential → checkGate → resolve identity →
check origins → inject + register → send`. **A request the gate refused never has a
credential written into it** — injecting first would mean an out-of-scope send composed a
request carrying a live session, with only a refusal returning in time between it and the
wire.

Registration precedes the copy that crosses the bridge, which is what keeps "redaction runs
before hashing" true. The blob store is content-addressed, so an unredacted credential does
not merely get stored — it becomes an **address** that exists in every backup.

### Generation is monotonic, and an equal generation changes nothing

A lower generation is refused; an equal one **keeps the held entry**. A value that can go
backwards is a value a replayed frame can control, and a same-generation frame carrying
different content would be a content change that never advanced the counter whose only job
is to gate content changes. `identity.refresh()` returns `generation + 1` unconditionally,
so nothing legitimate needs that door.

### A canary that a status code satisfies is worthless

An application answering a logged-out request with a **200 login page** is the seventh
spelling above, and no response-status rule can catch it. So `liveness.expect_body` is
**required** by the config loader, a non-2xx is an automatic failure but never the only
test, and `expect_absent` exists for a page carrying both signatures.

### `proven` is a window bracketed by two passing canaries, not a moment

§7's motivating case is a session dying *mid-run* — "an SSO session dying at 01:50 produces
six hours of unauthenticated traffic that every check reads as *not vulnerable*". One canary
at the start would stamp all six hours `proven`, and retirement runs on that stamp. So the
canary fires at run start, every `every_n_probes`, and always at run end; **any failure
anywhere downgrades the whole run to `assumed`.** The run under-claims rather than
over-claims.

A dead session **halts** the run, because the alternative is silent: a run carrying on under
a dead session answers `clean` for every surface, and those answers are indistinguishable in
the report from an application with nothing wrong.

### `origins` binds a credential to the host its session was proved on

It defaulted to the whole of `scope.include`, and the spec said in the same breath that a
third-party host in scope must never carry the target's session. The second sentence defeated
the first: a `scope.include` naming the app, an API, an SSO provider and a CDN is the
ordinary shape of a multi-host engagement, so the bound equalled the thing it existed to
bound and a client's live session was registered for a third party's server.

It now defaults to the **one host the liveness canary proves**. An operator widens it
explicitly per identity in `config.yaml` — where §4 wants blast-radius decisions recorded.

*Cost:* a multi-host engagement that widens nothing loses active-check coverage on every host
but the proved one. Probes there are refused `identity_origin` and read `inconclusive`; the
report's Limits section explains the pattern and names the fix.

## The tool layer

### The registry is an allowlist, so the forbidden names have no entry

Spec §8 keeps `engagement.create`, `surface.add` and `finding.set_status` out of
the agent's hands. `hx.tools.registry` enforces that by those three names
**having no entry** — `register` refuses them, and `dispatch` can only reach
what `lookup` returns. There is no check to forget on a future code path.

The same move as §4's two enforcement points inside the JVM, and as
`IdentityRegistry.register` keeping the three-name header allowlist at the one
door rather than at each caller. **Make the unsafe thing unreachable rather
than checked** is the rule this project keeps arriving at.

`TOOLS` is a module dict, so a determined caller can still write to it
directly. That is parked rather than fixed: Python has no private module state,
and `tests/test_tools_contract.py` asserting the three names are absent *after
every impl module has imported* catches a real bypass where encapsulation
would be theatre.

### `empty` and `unavailable` are different outcomes, at every layer

§12's governing rule — a report that cannot tell "tested, clean" from "never
reached" is worse than no report — is a claim about the whole stack, not about
`check_run.verdict`. So the envelope carries five outcomes and never four:
`ok · empty · unavailable · refused · error`. `empty` means the tool ran and
matched nothing; `unavailable` means it could not run.

This branch learned the same lesson in four separate places before it stuck:
the envelope's two outcomes; a journal row that is missing versus one that was
never written (`_journalled` logs rather than swallowing); `checks.list`
listing a disabled class rather than omitting it; and `finding.record`
distinguishing "no run is open" from "several are, I cannot tell which you
mean". Each was found separately. The rule generalises; noticing that it
generalises did not.

### A refusal must say what to do next

`not_registered`, `bad_args` and `run_open` all carry a `detail` that names the
next action — the open run's id and the tool that closes it, the argument that
was wrong, the tool list that exists. A bare reason sends an agent round the
loop the journal exists to break, and `journal.summarise` therefore records the
detail rather than the reason alone.

The one thing a detail never carries is the **value** it rejected.
`hx.tools.schema` names the property and the constraint; the rejected value is
the one thing the agent already knows, and echoing it put a credential-shaped
argument into `agent_action.result_summary` in the clear.

### Argument values are journalled only for a call that passed a schema

Principle 5 makes `args_blob` safe to store verbatim: identity is passed by
name and resolved below this layer. That argument covers arguments a schema
**accepted**, and nothing else. Every refusal at or before validation carries a
dict nobody checked — and since every tool schema sets
`additionalProperties: false`, sending `{"password": …}` to a real tool *is* a
`bad_args` refusal.

So `dispatch` journals sorted key **names** for an unvalidated call. The names
stay because they are the whole loop-prevention signal: "I keep calling this
with a password field" needs no value to say it.

### A gate must state each keyword's applicable type and its value's type

`hx.tools.schema` refuses any JSON Schema keyword it cannot enforce, because a
subset that silently ignored `pattern` would publish a constraint to the agent
that nothing applies. Getting that right took three rounds, all one bug class:
the gate validated keyword **names** and nothing else, so `{"type": "string",
"minimum": 5}` was accepted and inert, and `{"type": "integer", "minimum":
"five"}` was accepted and then raised.

`CONSTRAINTS` is now a table mapping each keyword to *(the types it applies to,
the type its value must be)*, with the public frozenset derived from its keys.
The test that ended the sequence is categorical rather than case-by-case: for
every keyword crossed with every type, the pairing either fails `check_schema`
or is enforced by `validate`. Adding `minItems`/`maxItems` two rounds later
could not be done halfway, because that test iterates the table.

### The open run belongs to the engagement, not to the process

`ToolContext.run_id` resolves from the store, because every `hx tool`
invocation is its own process and a field holding only what *this* process did
left three of eleven tools unable to succeed — `run.finish` answering `no_run`
forever, and `run.start` then refusing `run_open` forever.

Resolution is **memoised per dispatch**, not per access. Re-resolving on every
read let one `finding.record` call see two different answers when a concurrent
actor opened a run of another kind mid-call, failing
`finding_observation.run_id NOT NULL` and losing the finding under an
`error/internal` the agent reads as an hx defect.

When several runs are open, resolution refuses and names the kinds rather than
guessing. `hx.run.current_run` is deliberately not used here: it auto-opens,
which is right for `hx capture start` — where a forgotten command costs an hour
of unrecorded browsing — and wrong for a tool whose contract is "open a run".

### A halt stops the engagement doing more, so `run.finish` is exempt

Mutating tools are refused while a halt is armed; reads are not, because an
operator who has just hit STOP wants the agent able to explain itself.
`dispatch.HALT_EXEMPT` holds exactly one name. Closing an open run does *less*,
not more — and in Plan B `run.finish` is what stops the Burp JVM, so refusing
it under a halt would orphan one, the outcome §8's bracket exists to prevent.

A named set rather than a `ToolSpec` flag, so no future tool can opt itself
out.

### An agent-recorded finding must cite traffic, and does not spell its own key

Both inherited from `checks.base.Candidate` rather than invented:
`exchange_ids` is required, so a finding with nothing behind it cannot be
built; and the dedupe key is computed in one place, because "two writers will
spell the same finding two ways" is truer of an agent than of a check.

`type_` is the literal `agent`, which also makes a check/agent collision
unreachable — the two vocabularies cannot meet unless a check is ever named
`agent`.

## The egress tools

### The send path records its own exchange, from Python

Nothing in this build stored a `via='send'` exchange row. `store/schema.sql`
said so in as many words, and the Java confirmed it: `via` is written in
exactly two places, both in `proxy/Capture.java`. Meanwhile §8's digest opens
with `exchange_id`, and `http.grep`, `http.body` and `evidence.attach` are each
defined as a read keyed on one. Six tools rested on a row nothing wrote.

`hx.issue` writes it from this side rather than from the JVM, because the
result frame already carries the redacted response, the status, the timing and
the outcome, and `records.record_exchange` had defaulted `via="send"` since the
store was built, waiting for a caller. What a Java change would add is the
post-injection request bytes and the resolved IP, at the cost of a second
writer into a table whose proxy writer took a plan to get right.

So `req_blob` on a send row is the request hx *asked* to be sent, not the bytes
that left the JVM — they differ by the identity header the extension injects.
That difference is in the safe direction and is why this is tolerable rather
than merely cheap: the credential is injected inside the JVM, so it cannot be
in the bytes this side hashes, and the blob store is content-addressed.

### `hx tool` cannot hold a session, and says so by name

`hx.session.session()` tears Burp down on every exit and each `hx tool` call is
its own process, so there is no object there for a session to outlive. That is
not a limitation waiting to be lifted; it is what the CLI adapter *is*.
`run.start` therefore reports `session: {live: false, reason: "no_host"}` and
names `hx mcp`, rather than letting six tools answer a generic `no_session`
that reads as "start a run first" — advice that would never work.

Four ways to have no session, and they are four different next actions:
`not_needed` (this run kind never wanted one), `no_host` (this adapter cannot
hold one), `launch_failed` (Burp would not start, or started dead), and
`session_held` (another run has it — with `owner_alive`, because "blocked by a
live session" and "blocked by a corpse" are different facts and only one means
wait). A single `live: false` would collapse all four into one shrug.

### A comparison is between bodies, never between whole responses

Two replays of one request differ in their `Date:` and their per-session
`Set-Cookie` even when the application returned byte-identical content. So a
delta over whole responses reports a difference on every call — which in
`http.replay_as` means **manufacturing** an authorisation finding rather than
missing one, and in `delta.new_tokens` means drowning the reflected-payload
signal §8 built the digest for.

One root cause, three sites: `delta.baseline_for`, `_digest`, and
`replay_as`'s own comparison. The trap has a fourth door — an original with no
stored response body would diff against `b""` and differ from everything — and
that one answers `differs: null` plus an `original_body_stored` facet.

### A replayed request drops every credential it is carrying

`http.replay_as` drops `config.CREDENTIAL_HEADERS` **union** every declared
identity's `inject.header`. The declared half is the load-bearing one: an
identity header replayed verbatim under a different identity would send
identity A's credential wearing B's name, and the tool would report "no
difference" for two sessions that were never two sessions.

The standing half covers a credential the captured request carried that no
identity here declares. Without it the tool fails on its most likely real
input — the extension answers `unmanaged_credential` and every row comes back
refused, on precisely what `Sender.java`'s own comment names as "the natural
agent action … replaying a request lifted from Burp's history".

### The wire's error class survives into the envelope, all twenty of them

Principle 6 says the tool layer reports what the extension refused and decides
nothing. That means `scope_denied` and `rate_limited` reach the agent as
themselves: they are different next actions, and one generic `error` makes them
one. The split follows what actually happened — *something decided no* is
`refused`; *no answer came back* is `unavailable` — so a client-facing count of
refusals stays a statement about scope discipline rather than about network
weather.

The mapping is **derived** from `tests/test_records.py::ERROR_CLASSES`, which
already reads the authoritative list off the Java emit sites. A second
hand-maintained list of wire classes would be a second thing to keep in sync
with the extension, and the first eleven-of-twenty version of this table is
what that costs.

### A reason nothing can produce is evidence of a broken path

`identity_dead` sat in the closed vocabulary with nothing able to reach it —
which was the tell for a real Principle 6 violation: `http.send` guarded
`except ValueError` while `ensure_identity` also raises `BridgeError`, so an
extension refusing an identity landed as `error / internal`. An agent told
`identity_dead` re-opens its session; one told `internal` retries the identical
send forever.

The heuristic generalises past this project: in any closed enum, a member
nothing constructs is either dead weight or a missing path, and grepping for
each member's constructors is a cheap audit with a high hit rate.

### `hx mcp` is hand-rolled, and stdout is the protocol

MCP's stdio transport is newline-delimited JSON-RPC 2.0 and a server needs
`initialize`, `tools/list` and `tools/call`. The `mcp` SDK would be a third
dependency plus its transitive closure inside the one process that holds this
engagement's resolved credentials, its live Burp, and the operator's halt path.
A security tool's dependency footprint is part of its argument.

Nothing but JSON-RPC may reach stdout — not a print, not a warning, not a
traceback — because a newline-delimited protocol has no resynchronisation
point, so one stray line desynchronises the client for the rest of the
conversation. The test that guards it runs `hx mcp` as a real subprocess and
inspects the OS-level fd: the `StringIO` tests cannot see a `print`, and a
surviving mutation proved it.

`why` travels inside the arguments because MCP hands a tool one object, and is
popped back out before `dispatch` validates — `ToolSpec.params` sets
`additionalProperties: false`. The published schema and the enforced schema are
therefore different objects, `tool_schema` deep-copies, and a test runs
`check_schema` over every published one so the added property cannot become a
constraint nothing enforces.

## The web app

### Starlette, not FastAPI

Measured 2026-09-01: `fastapi uvicorn jinja2` resolves to 15 packages against
`starlette uvicorn jinja2`'s 9, and the six extra include `pydantic-core`, a
compiled extension. FastAPI is Starlette plus pydantic validation and OpenAPI
generation, and this app's entire validated input is a status enum and a note
string — S11's own "should not pull hundreds of transitive packages to render
a table" is the argument for the smaller closure.

### Reads do not go through the tool layer

`tools/dispatch.py` journals every call, and `journal.record` defaults to
`actor="agent"` — so routing a page view through it would write one
`agent_action` row per view, and the agent transcript screen would fill with
the act of reading it. The audit trail would stop being able to answer "what
did the agent do", which is the question it exists to answer. The envelopes
disagree too: handles and digests, match-addressed reads and token-budget caps
are shaped for a model with a context window, and a human with a browser has
neither constraint. `src/hx/web/reads.py` owns its own queries instead, one
function per screen, over a connection the caller opened read-only and closes
at the end of the request.

### Coverage was extracted, and nothing else

`hx.coverage.facts` and `hx.run.is_stale`/`stale_before_us` are the only two
pieces of `report.py`/`run.py` Task 1 pulled out, because they are the only
two with a SECOND caller: the report and the web overview screen both need
the same coverage figures and the same definition of a dead run, and two
copies of either is how a screen and a report end up disagreeing about the
same engagement. Nothing else in `report.py` — `_findings`, `_provenance`,
`_limits` — has a second consumer yet, so extracting it would be indirection
with no argument behind it.

### The app can stop but not start

The web app spec fixes the control surface at exactly two things — the STOP
button and finding triage — "and this design does not widen it" (§1 of
`docs/superpowers/specs/2026-09-01-web-app-design.md`, quoting master spec
§8's *"creating an engagement and confirming a finding are human acts; they
live in the CLI and the web app"*). Starting a scan is not a database write:
it launches Burp, drives the bridge, and holds a process for the run's whole
duration, and none of that is a thing an unauthenticated loopback HTTP
request should be able to trigger. Stopping and triaging are cheap and
synchronous by comparison — one sentinel file, one SQLite row, one
status-event insert — which is exactly the shape the spec draws the line at.

## What has been measured, and what has only been argued

### `sql-behaviour`'s `Tentative` is now a number: 18 true positives, 0 false

Measured 2026-09-02 against OWASP Benchmark 1.2, joined to its own
`expectedresults-1.2.csv`. Every finding `hx.active.sql-behaviour` filed was
a genuine SQL injection by that corpus's ground truth.

The check ships `confidence="Tentative"` on the REASONED grounds that a
quote differential proves the quote reached a PARSER and not that the parser
is a database — an input validator or a WAF that rejects a bare quote and
accepts an escaped one produces an identical signal. That reasoning stands;
it now has evidence beside it rather than only an argument.

**IT DOES NOT LICENSE PROMOTING IT TO `Firm`.** Eighteen findings, one
corpus, all of one shape, on a run that did not finish. The number says the
check is not obviously noisy. It does not say what its rate is on an
application with real input validation, which is the case the Tentative
grade exists for.

### The same run measured NOTHING for two other checks, and says so

| check | findings | clean | no answer |
|---|---|---|---|
| `sql-behaviour` | 18 | 0 | 149 |
| `sql-error` | 0 | 0 | 167 |
| `path-traversal` | 0 | 0 | 167 |

The scan ABORTED: `5xx rate 22.0% over the last 50 requests exceeds 20.0%`.
So the 18 is a floor, 149 of 167 surfaces went unanswered, and **there is no
false-positive measurement for `sql-error` or `path-traversal` at all**.
Recording the gap is the point: a measurement that cannot distinguish
"measured, clean" from "never reached" is section 12's failure aimed at our
own evidence.

### hx cannot fully scan a target that errors under injection

That abort is not a defect and was not worked around. Section 4's distress
detector exists so a scanner does not hammer a client's application into the
ground, and OWASP Benchmark's SQLi cases are DESIGNED to return 500 when
injected — so it fires at 22% and the run ends.

The threshold is hardcoded in the extension rather than configurable per
engagement, and it was left alone deliberately. The same argument had
already been made that morning, when a 500-answering integration route
halted the Java suite: **a target must not need the harness's own safety
valve disabled to be testable.** Raising it here to buy a bigger number
would have been that rule broken for our own convenience.

### Only 22% of that corpus is reachable, and the other 78% is three safety decisions

Of Benchmark's 772 SQL-injection and path-traversal cases, 167 take their
input from a GET query parameter and the rest do not:

| input source | cases | why hx cannot reach it |
|---|---|---|
| `formparam` | 363 | a POST body; the default method allowlist is GET/HEAD/OPTIONS |
| `header` | 167 | none of the three checks measured here declares a `header` insertion kind (`reflected_input` does, and is not one of them) |
| `cookie` | 75 | the extension refuses caller-supplied credential headers |
| `getparam` | **167** | reachable |

The unreachable majority is not a coverage failure to fix; it is three
deliberate refusals showing up as a number. The report's Limits section
already says request-body parameters are recorded and not probed. This puts
a figure on what that costs: on this corpus, 47% of the SQLi cases.

### One number from that run is NOT a false-positive rate, and was retracted

The same join reported `hx.active.reflected-input` at 12 true and 3 false.
**That is a category mismatch, not three errors.** Benchmark's label answers
"is this SQL injection"; `reflected-input` answers "is input echoed back". A
case can be labelled safe for SQLi and still reflect its input, so the label
cannot judge that check. Only `sql-behaviour` was validly measurable here,
because it and the label ask the same question.

### The free half of the measurement: hx pointed at its own web app

`hx web` takes `?severity=` and `?status=`, refuses unrecognised values with
400, and every query behind it is parameterised — an input validator with no
SQL, which is exactly the false-positive shape `sql-behaviour` is Tentative
about. Scanned on 2026-09-02: **zero findings from all three injection
checks**, with `sql-behaviour` recording

> both probes came back 400 and identical, so nothing here separates
> `tested, clean` from `never reached` -- an endpoint that refuses every
> request refuses an unbalanced quote and an escaped one alike

That is the gap branch a corpus contract forced into the check the same
morning, working against a real validator on a target whose ground truth is
known absolutely.

Two things that run surfaced in passing. The distress detector aborted it
too, on latency rather than 5xx. And `hx.active.reflected-input` filed two
`Certain` findings there while its own description records that `<>"'` did
not survive — honest about what it proves ("reflected, not exploitable"),
and still noise in a client report on an app that escapes correctly.

### A measurement harness needs a stabler key than the path

The join nearly failed: hx's normaliser templated `BenchmarkTest00026` into
`/benchmark/sqli-00/{slug}`, so the path no longer identified the case. It
worked only because the test name is ALSO a query parameter and survives in
`surface.query_key_set`. Anything built to repeat this measurement must key
on something the normaliser does not rewrite.

## Process decisions

### A plan is a historical argument, not live documentation

Plans quote the code they specify and a drift test enforces it. But when a *later* plan
rewrites that code, the earlier plan is **not** re-synced to match — that would make it
claim it specified code it never specified. Corrections go to the spec, in dated amendment
paragraphs with the original text left standing.

### Comments are held to the same standard as code

Twelve comments asserting behaviour the code did not have were caught by measurement during
the active-checks work. Three had a number that merely *looked* right — a count that
matched a neighbouring count reads as consistent, so nobody checks it.

Two patterns worth naming:

- **A comment that justifies a design by describing the code around it is a hostage to the
  next commit.** One docstring was wrong in both directions on one branch: it said "nothing
  renders this sentence", which was true until the next commit rendered it.
- **A countable claim is a trap.** "Exactly one shape escapes" is falsified the moment
  anyone finds a second member. Name the class, not the count.

### Ruff is lint-only, and the rule set is the default

`ruff format` would rewrite 89 of 97 files, staling essentially all 144 plan-quoted blocks
at once — a large risky diff whose only correctness effect is the chance of a mistake while
making it. Widening the rule set adds exactly 110 findings, every one `E501 line-too-long`
and none a bug.

The gate earned its place before it was configured: its first run found an `F811` where one
test shadowed another of the same name, so the shadowed one — the stronger of the two — had
not run since the commit that added the second.

---

## Known debt

| | |
|---|---|
| `--root` means the engagements PARENT to `hx new` and one engagement's OWN directory to every other command; `hx web --base` is a third name for the first meaning | Renaming a flag on six merged commands is a breaking change to an operator's muscle memory and to any script they have written, in exchange for tidiness. `--base` is a new name that does not inherit the ambiguity. |
| No authentication, and no non-loopback binding | S11 sets the terms: a per-install bearer token lands *before* the first write endpoint on a wider binding. Neither is needed while the Host allowlist and loopback binding hold. |
| A GET can create `blobs/tmp/` via `BlobStore.__init__` | The one filesystem side effect on a read path. It creates a directory at `0700` inside an engagement that already exists and touches no database, blob or config file. Removing it means a read-only BlobStore constructor, which is a change to a module three other callers share. |
| Triage has no optimistic concurrency | Two operators triaging one finding both get events recorded and the last wins the cached projection. The log is append-only, so the race is visible rather than silent. |
| The web app does not render `denial` rows | The overview shows what was tested and found; what was REFUSED is a fourth screen, and S11's screen list does not name one. `hx info` and the report both show denial counts today. |
| `finding.normaliser_version DEFAULT 1` | Inherited from a merged plan whose own deadline expired before the branch that noticed it. Cannot produce a wrong result today: nothing writes or reads the column |
| `2026-08-27-checks-and-reporting.md` holds `plan-drift: pending` | 26 blocks uncompared, including whole-file markers for code later plans rewrote |
| `open_redirect` can only be shown a fix on a 2xx | A fix delivered by `302 → /home` leaves the finding live indefinitely. The discriminator that would fix it does not exist without a control probe: a login redirect is typically same-origin too |
| The probe's own exchange is not recorded | An active finding cites a captured request to the affected surface rather than the probe that demonstrated it. Needs a new bridge frame type and writer |
| `Limiter.java`'s "no new refusal after the gate" rule is false | The identity branch added two — `unknown_identity` and `identity_origin` — which land after `checkGate` has spent a rate slot and a budget unit while the target sees nothing and `requests_sent` reads 0. The comment is corrected and the decision order deliberately untouched; the burn can only make `hx` send *fewer* requests than authorised, never more |
| A surface carrying any finding retires nothing on that surface | The `finding` branch offers no `considered`, because it short-circuits above the gaps check the passive corpus relies on. Under-claims, and disclosed to the client |
| `codec.identity_body` does not enforce the three-name header set | `hx.config` refuses a fourth name with a better message and `IdentityRegistry` refuses it inside the JVM, which is where §4 puts enforcement. A third copy would be a third place to drift |
| `path_traversal` cannot probe a `path_segment` in practice | Its name filter wants a file-shaped name; the normaliser's vocabulary is `{id}/{uuid}/{hex}/{slug}`. A false negative, disclosed in the report |
| `agent_action` has no index matching how it is read | `run.journal` and `run.resume` filter on `engagement_id + actor`; the only index is `idx_action_run(run_id, ts_us)`, and `run_id` is NULL on every CLI-adapter row. A table scan on the most-read tool in the set. |
| `surface.query`'s `facets.host` is unbounded | 300 hosts repeat on every 50-row page — measured at 18 KB per envelope on 3,000 surfaces. Principle 3's spirit, uncapped. |
| The report renders no `created_by` | A client cannot tell an agent-asserted finding from a check-verified one. The column records it; the renderer does not read it. A reporting decision, not a storage one. |
| `http.grep` matches literal bytes, not regular expressions | Python's `re` has no timeout and the pattern is agent-authored; a catastrophic backtrack would hang the one long-lived process that also holds this engagement's Burp, taking the session, the run and the operator's halt path with it. A literal match cannot backtrack. Finding a *class* of thing (every `Set-Cookie` without `Secure`) needs several literal greps or a passive check instead of one regex. |
| `journal.encode_args` redacts credential headers at a LINE START only | `_CREDENTIAL_LINE` matches at the start of a string and after `\n` or `\r`, so every spelling of a header line is covered — but a credential name that does not start a line (`a=1; Cookie: b`) is deliberately left alone, because prose and form fields are not header lines and a redactor firing on them would corrupt the journal's account of what was tried. Separately, `why` is written to its own column without passing through the encoder at all. **This row described `.match`-anchored non-MULTILINE behaviour until 2026-09-01, two commits after that stopped being true** — a stale debt row is worse than none, and it was found by a review rather than by its author. |
| One mapped wire class no Java site emits | `identity_dead` is kept — removing it would contradict the refused/unavailable split — as a named `MAPPED_BUT_NOT_EMITTED_BY_THE_JVM` exception, so the *next* unreachable entry fails a test. The assertion is `extra <= set(...)`, so an exception that later becomes emitted goes stale silently. |
| `hx tool` cannot reach the six egress tools | Structural, not a defect: `session()` tears Burp down on every exit and each call is its own process. Reported as `no_host` naming `hx mcp`, rather than left to look like a bug. |
| No false-positive measurement exists for `sql-error` or `path-traversal` | The 2026-09-02 Benchmark run aborted on the 5xx distress threshold before either got a single verdict — 167 inconclusive each. The abort is correct behaviour; the consequence is that two shipped checks have a confidence grade backed by argument alone. |
| A measurement run cannot cover a corpus that errors under injection | Section 4's distress detector stops issuance at a 20% 5xx rate, and OWASP Benchmark's SQLi cases are designed to 500. Scanning such a corpus in windows small enough to stay under the threshold needs batching hx does not have, and raising the threshold is the safety valve disabled for our own convenience. |
