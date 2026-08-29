# Active checks: the probe pass and the `active_safe` corpus

**Status:** approved 2026-08-28
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§4 enforcement invariant,
§5 tables, §10 check classes, §12 reporting, §13 v1 scope)
**Builds on:** Plan 3 (enforcement and the send path), Plan 4 (traffic capture),
Plan 5 (passive corpus and Markdown reporting), merged at `a28649d`.

**Blocked on the bridge session, discovered 2026-08-28 while planning.** Nothing in
`src/hx/` calls `bridge.configure()`. `hx capture start` writes a `run` row and nothing
else; `scripts/demo_capture.py:226` (as it stood then — the bridge-session plan
rewired it) and `tests/integration/conftest.py`'s
`build_config_body` each stand up their own session because the product has none. The
extension defaults to DENY-ALL, so an unconfigured one refuses everything — and an active
check cannot send through a bridge that was never configured. **The session plan lands
first; this design is implemented after it.** The `max_requests` wiring in §8 belongs to
that plan, since it is the plan that first builds a configure body in the product.

## 1. Purpose

Plan 5 shipped the passive corpus and a report that is honest about what it did not test.
This plan makes `hx` *probe*: the first checks that send requests, the runner pass that
drives them, and the contract change that lets a check retire a finding it no longer sees.

It also closes three items Plan 5 deferred by name.

**In scope.** The probe pass in `scan.run` · the send seam · the `Verdict.considered`
contract and the retirement change that depends on it · five `active_safe` checks ·
`max_requests` wiring · the `\r\n` header-parsing fix · the report follow-through.

**Out of scope, and why.** `active_timing` (time-based blind injection) and
boolean-differential need different machinery — capped concurrency with a wall-clock
budget, and response-variation analysis, which §10 specifies via Burp's
`createResponseVariationsAnalyzer`, a Montoya API nothing in this repo references yet.
They are Plan 7. Multi-identity access-control diffing needs identities and belongs to the
identity plan. `active_mutate` and `active_dos` remain off and unimplemented.

## 2. What already exists and is idle

This plan is mostly *wiring what previous plans built*, and the design should be read that
way. Verified against the tree at `a28649d`:

- **`bridge.server.send(req, body, timeout, *, enforce_locally)` has zero callers in
  `src/hx/`.** The whole Java send path — `Sender`, `Limits`, `Redactor`, `HaltSwitch`,
  `Http`, `HttpReply` — exists and is tested. It has never been driven from Python.
- **`insertion.derive` has exactly one caller: `report.py`**, which renders the derived
  points to the client under the heading that they were *not probed*. Every shipped check
  declares `insertion_kinds = frozenset()`.
- **The registry already names the hook.** `_HOOKS["active_safe"] = ("probes",
  "on_corpus")`, and `_RUNNER_CALLS = ("on_surface",)` carries the comment *"WHEN A RUNNER
  PASS IS ADDED, ADD ITS HOOK HERE"*. F7 of Plan 5's whole-branch review currently refuses
  a check implementing only `probes`, because nothing calls it. This plan makes the call
  exist and adds the hook to `_RUNNER_CALLS`.
- **`check_run.requests_sent` exists** (`INTEGER NOT NULL DEFAULT 0`) and is never written.
- **`limit.max_requests` is already a permitted config key** in `bridge/codec.py` and is
  already read by `Limits.arm()`. Only `Config` lacks the field that would populate it.
- **`budget_exhausted`** is already an error class on the wire, a `check_run.reason` value,
  and a documented no-retry condition.

## 3. The probe pass

`scan.run` gains a second pass beside the passive one. Per surface, per enabled
`active_safe` check: derive insertion points from the surface's exemplar exchange, open a
`check_run` row, and call the check's `probes` hook.

`"probes"` joins `_RUNNER_CALLS`, which is what makes such a check runnable at all.

**The check never owns a socket.** It is handed a sender; it cannot construct one. Every
byte still leaves through the extension, so §4's invariant — every byte that leaves this
machine crosses one of two points inside the JVM, and DENY-ALL is terminal — holds
unchanged and needs no new argument. **No Java changes in this plan.**

Passive and active passes both run under one `run` row. A surface with no derivable
insertion points gets a `skipped` row with a reason, not silence: §12's governing rule is
that a report which cannot distinguish "tested, clean" from "never reached" is worse than
no report.

## 4. The send seam

A small `ProbeSender`, constructed per `check_run`, wrapping the bridge:

- counts every attempt into `check_run.requests_sent`;
- translates the extension's refusals into the verdict the check must return.

**A refusal is never `clean`.** `budget_exhausted`, `halted`, `rate_limited`,
`scope_denied`, `method_denied`, `dangerous_denied`, and any transport error mean the check
did not get its answer, so it returns `inconclusive(reason)`. §10 states this as a rule for
checks; here it is enforced at the seam so a check cannot get it wrong by omission.

`enforce_locally` stays at its default. This plan does not use the escape hatch.

## 5. The verdict contract

`Verdict` gains **`considered`**: the issue types this check examined on this surface and
reached a conclusion about.

`_mark_unobserved`'s current gate — retire only when the whole `(surface, check)` answered
`clean` — is replaced by: **retire a finding when its issue type was considered and not
re-emitted.**

The gate was sound when a check filed at most one finding per surface. Plan 5's F1 fix made
N-per-surface the norm without updating it, so a check that finds one of three issues
answers `finding` and the other two are never retired: they render live off stale
observations with no marker. That is a client being told a fixed issue is still open.

Design notes that bind the implementation:

- **Dynamic issue types must work.** `cookie_flags` mints an issue type per cookie name, so
  a static class-level declaration cannot express its coverage. `considered` is populated
  at run time, from what the check actually looked at.
- **It fails safe.** A check that populates nothing retires nothing. The failure mode is a
  finding staying live, never a finding falsely closed.
- **All four passive checks populate it.** This is the plan's highest-regression-risk
  change: it rewrites what tells a client "fixed", on code stabilised over five review
  rounds. It gets tested in both directions — a fixed issue retires; an issue the check
  never examined does not.
- **Retirement becomes true for the active corpus.** Re-probing an insertion point and
  getting no reflection is a genuine re-test, unlike the passive corpus where the original
  exchange stays in the store forever. Plan 5 had to disclose that gap in Limits; this plan
  does not close it for passive, and that disclosure stays.

## 6. The five `active_safe` checks

`active_safe` is §10's "idempotent GET/HEAD payloads, bounded". All five stay inside
GET/HEAD/OPTIONS (§7).

| Check | Shape |
|---|---|
| Reflected input / XSS | canary in an insertion point, look for it in the response; on reflection, characterise the context |
| SQL error | syntax-breaking character, look for database error signatures |
| Path traversal | traversal sequence, look for file-content signatures |
| Open redirect | off-site value in a redirect-shaped parameter, inspect `Location` without following |
| CORS misconfiguration | one GET carrying `Origin`, inspect `Access-Control-Allow-*` |

**Canary-first, escalate on evidence.** One distinctive marker per insertion point. Only a
response that reflects it, or errors in a telling way, earns further requests. Volume then
scales with what the application does rather than with surface count — a 200-surface app
costs roughly 200 requests plus follow-ups, instead of thousands spent equally on static
assets and search boxes.

Issue text, severity and CWE come from Burp's vendored issue definitions, per §10, so the
report keeps the vocabulary a Pro user's report has.

Open redirect must **not** follow the redirect. The send path is configured
`RedirectionMode.NEVER`; a check that followed one would be making a request the operator
did not authorise against a host that may be out of scope.

## 7. Methods, and what stays unprobed

`Policy.java` sets `DEFAULT_METHODS = ("GET", "HEAD", "OPTIONS")` and reads
`scope.getOrDefault("method.allow", DEFAULT_METHODS)` — the extension already honours an
override. Python's `Config` has **no `method` key at all**, so nothing can set one.

**This plan does not add one.** `active_safe` is idempotent by §10's definition, and GET is
what idempotent means. The consequence is that `body_form` and `body_json` insertion points
are underivable to probe, and stay so.

The report's existing Limits bullet already states that request-body parameters were
recorded but not probed. It remains true and must stay accurate: whichever half of it
mentions "no active checks" has to become derived rather than typed, or it will be false
the moment this plan lands.

Body probing belongs to `active_mutate`, which §10 already defines as non-idempotent,
off by default, opt-in with confirmation. That is the right home for it, not a widened
`active_safe`.

## 8. Budget

`max_requests` becomes a `Config` field and a CLI option, travels in the configure frame,
and is armed by Java's existing `Limits`. **No Java change is needed**, and the gap is
narrower than "half-wired" suggests:

- `bridge/codec.py` already permits `limit.rate_rps`, `limit.concurrency` and
  **`limit.max_requests`** on the wire.
- `Limits.arm()` already reads `limit.max_requests` from the authorisation body, falling
  back to a `defaultMaxRequests` that `Distress.java` documents as **2000** per run.
- `Config` supplies `rate_limit_rps` and `max_concurrency` for the first two keys and has
  **no field for the third**, so the permitted key is never populated.

The work is therefore: add the `Config` field and CLI option, populate the key that is
already allowed, and write `check_run.requests_sent` at the seam.

§5 settles the semantics and the implementation follows rather than reinterprets them: the
budget is **per run**, taken from the **first** authorisation, **monotonic**, and a later
`configure` naming a different rate or budget is **refused**, not applied. A run must not
talk its way into a larger allowance mid-flight.

`check_run.requests_sent` is written by the send seam, so per-check attribution exists even
though the ceiling is per-run.

## 9. The header-parsing fix

`checks/passive/_http.py` splits response heads on `\r\n` only. A server using bare-LF line
endings therefore has its headers mis-parsed: `security_headers` can miss a header that is
present, and `cookie_flags` can misread a cookie name.

That is a **false negative in a security assessment** — the tool reports clean because it
failed to read, not because there was nothing there — and it is the worst class of defect
this tool can have, because nobody goes looking for it.

Plan 5 closed the report-integrity consequence at the render boundary (a bare LF in a
cookie name could inject a Markdown heading). The parsing consequence is still open, and it
matters more here: active checks parse responses they provoked.

## 10. Report follow-through

- Insertion coverage must stop describing probed points as not probed.
- `active_safe` stops being an unshipped class, so the "enabled in this config but this
  build ships no checks in that class" note must stop appearing for it.
- Any Limits sentence asserting that no active checks exist must become derived from the
  registry or be removed. Plan 5 established the standard: a sentence that *discloses a
  limitation* may be typed if a test holds it against the spec that mandates it; a sentence
  that *excuses an absence* should be removed rather than guarded.

## 11. Error handling

- A check raising is caught per check, writes `error` with the exception summary, and does
  not stop the run — the existing pattern.
- `budget_exhausted` ends the run's probing. Nothing retries. Remaining checks record
  `skipped` with that reason so coverage shows the truth.
- An operator halt is terminal and immediate; in-flight probes end as `inconclusive`.
- A run that ends unfinished is already rendered as unfinished by Plan 5's work, in both
  the Findings and Coverage sections. Probing must not introduce a path that bypasses it.

## 12. Testing

The integration fixture's loopback target grows endpoints that reflect input, emit SQL
error text, expose traversal, redirect off-site, and return permissive CORS headers.

**Loopback only.** These are the first checks that send, so the fixture's guarantee stops
being incidental and becomes load-bearing: nothing in this project has ever sent a request
off this machine, and no test may be the first. Burp continues to run against a private
home built per run, never the real `$HOME`.

Beyond per-check tests, two properties need their own:

1. **Retirement, both directions.** A fixed issue retires and renders with the marker; an
   issue the check never examined does not retire.
2. **The seam refuses correctly.** Each refusal class produces `inconclusive` with that
   reason and never `clean`, and `requests_sent` counts attempts including refused ones.

## 13. Decisions taken

| Decision | Choice | Why |
|---|---|---|
| Scope | Foundation + five `active_safe` checks; `active_timing` and boolean-differential to Plan 7 | Splits on an infrastructure boundary — timing needs concurrency and wall-clock budget, differential needs variation analysis — not an arbitrary count |
| Body parameters | Stay GET-only, disclose | §10 defines `active_safe` as idempotent; `active_mutate` already exists for the non-idempotent case; adds no blast radius on client systems |
| Payload depth | Canary-first, escalate on evidence | Volume scales with application behaviour rather than surface count |
| Verdict contract | `Verdict.considered`, retire what was considered and not re-emitted | Only option that expresses dynamically-minted issue types; fails safe; makes retest genuinely work for the active corpus |
