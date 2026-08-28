# Checks and reporting — design

**Status:** approved 2026-08-27. Implements §10 (checks) and §12 (reporting) of
`docs/superpowers/specs/2026-08-21-hx-design.md`, against the capture engine
delivered by Plans 1–4.

**Goal.** A consultant browses the target through Burp, runs `hx scan`, and
gets a Markdown report whose coverage section honestly distinguishes *tested,
clean* from *never reached*. No crawler, no identity, no tool layer, no web
app — none of which this needs.

Against §1's four gaps this closes **report generation** outright and opens
**Scanner** with a real corpus. It is the shortest path from what exists to a
client deliverable.

**Scope, honestly.** This is at the upper limit of one plan — a types layer, a
registry, insertion derivation, a runner, roughly nine checks, the finding
upsert layer, a renderer and two CLI commands. Plan 4 was nine tasks. If it
proves too big in the writing, the natural cut is **checks engine + passive
corpus** first and **active corpus + report** second; they are separable
because the runner's interface does not change between them. It is presented
whole because the report is what proves the checks recorded honestly, and
splitting them hides that proof behind a second plan.

---

## 1. What was decided, and by whom

Four decisions were taken in brainstorming and are settled; the rest of this
document is their consequences.

1. **Passive and `active_safe`.** Not `active_timing` — a sleep payload *is*
   the p50-above-5×-baseline signal §4's auto-halt exists to catch, and
   reconciling the two is spec work before it is code. Not `active_mutate` or
   `active_dos`, which §10 ships off.
2. **Two hooks.** A check sees one surface at a time; a separate optional hook
   sees the whole corpus, for the findings `scope_level = engagement|host`
   exists for — §5's own example is a shared error handler across many
   surfaces.
3. **One `hx scan`.** With no bridge it runs the passive corpus and records the
   active checks as `skipped` with `reason = 'no_bridge'`. The honesty lives in
   the rows, not in a second command.
4. **The check declares, the runner mutates.** A check yields
   `(insertion, payload, detector)`; the runner performs the mutation, spends
   the budget, issues through the send path and hands back the exchange.

And one ruling taken here rather than asked:

5. **The registry is an explicit list, not discovery.** §10 wants checks cheap
   to add, and one line in a list is cheap. `extension/test.sh` already
   records the other half of this lesson — *"a class nobody lists is a file
   that compiles, never runs, and reads in review exactly like a test that
   passes."* For a security tool that failure is worse than a missing test: a
   check that silently does not run renders as **tested, clean**.

---

## 2. Architecture

Six units. The runner is the only one that touches the bridge, computes a
`dedupe_key`, or spends budget.

```
src/hx/checks/base.py       the types: Check, Verdict, Probe, Insertion, Candidate
src/hx/checks/registry.py   the explicit list + validation of each entry
src/hx/checks/passive/*.py  one file per check
src/hx/checks/active/*.py   one file per check
src/hx/insertion.py         insertion points, derived from the exemplar exchange
src/hx/scan.py              the runner: iterate, budget, mutate, send, record
src/hx/report.py            render() -> one Markdown file
```

CLI: `hx scan` and `hx report`, alongside the existing `new`, `info`,
`capture`, `halt`, `resume`.

**What a check may not do.** Build a request. Write a row. Compute a
`dedupe_key`. Learn its own `check_run` id. Reach the bridge. Each of those is
the runner's, and each is a place where one implementation must serve every
check or the guarantees stop being uniform.

---

## 3. The check interface

```python
class Check:
    id: str                          # stable, e.g. "hx.passive.cookie-flags"
    version: str                     # bumped when its verdicts can change
    klass: str                       # 'passive' | 'active_safe'
    insertion_kinds: frozenset[str]  # empty for checks that are not insertion-scoped

    def on_surface(self, ctx, surface, exchanges) -> Verdict: ...
    def probes(self, ctx, surface, insertion) -> Iterable[Probe]: ...
    def on_corpus(self, ctx, surfaces) -> Verdict: ...      # optional
```

`klass` decides which hooks are legal: a `passive` check implementing `probes`
is a registry error, not a runtime surprise. The registry validates this at
import, so the failure is loud and early.

**`Verdict` is what a check may say, and it is narrower than the column.**

```python
Verdict.clean()
Verdict.finding(*candidates)
Verdict.inconclusive(reason)      # reason is REQUIRED
```

`check_run.verdict` also carries `pending`, `skipped` and `error`. Those are
the **runner's** words. A check cannot claim it was skipped, cannot report its
own crash, and — per §10 — must return `inconclusive(reason)` where it could
not run, never `clean`.

**Rows are written `pending` before the check runs and updated after.** A scan
killed mid-flight then leaves rows saying *started, never finished* rather
than no rows at all. §12's rule — a report that cannot tell *tested, clean*
from *never reached* is worse than no report — applies to the crash case too,
and only this ordering satisfies it.

`ctx` carries the engagement config, the blob store, a logger, and the run id.
It does **not** carry the database connection: a check that can write is a
check that can write the wrong thing.

---

## 4. Insertion points

§5 is explicit that they are **derived, not stored** — there is no `insertion`
table in v1, and `insertion_name` / `insertion_kind` live as columns on
`check_run` and `finding` where they are needed for identity.

**Derivation source.** `surface.exemplar_exchange_id` → that exchange's request
blob. The master spec calls this `surface.detail`; **there is no such column**,
and this document names the real path rather than inheriting a reference to
something that does not exist.

**The vocabulary, and it is new:**

```
query          a query-string parameter
path_segment   a templated segment, i.e. the {id} the normaliser produced
header         a request header the client sent
cookie         a single cookie by name
body_form      application/x-www-form-urlencoded
body_json      a JSON body member, by dotted path
```

`body_form` and `body_json` are **derived and recorded but never probed in
this plan**, and the reason is §4 rather than effort: the production profile's
method allowlist is `GET/HEAD/OPTIONS`, so an `active_safe` check can only
re-issue a GET. A payload cannot reach a body until an engagement runs on
`staging` or the allowlist is widened. Recording them anyway means the coverage
section can say *this parameter exists and was not probed*, which is the honest
answer and is worth more than omitting it.

**Consequence, stated plainly:** on a production profile this corpus finds less
than Burp Professional's scanner would, and the report must not imply
otherwise.

---

## 5. The runner

Order per surface: passive checks first (they cost nothing and their findings
inform nothing else), then active. The corpus hook runs once, last, when every
surface has been visited.

**Budget.** `hx scan --max-requests N --max-seconds S`, synchronous over a
bounded batch, no job runner and no resumption machinery (§13). On exhaustion
the remaining rows become `skipped` with `reason = 'budget'` — **never
absent**.

**The JVM's budget is the real ceiling.** §4's per-run budget and rate limit
are enforced inside the extension and a check cannot route around them. The
scan's own budget is a *courtesy stop*, so an operator sees `skipped/budget`
rather than a wall of `budget_exhausted` denials. When the two disagree the JVM
wins, and that is by design.

**`requests_sent`** is counted by the runner, because the runner is what sends.
A check counting its own requests is a number that drifts the first time a
check is wrong about itself.

**Config.** `config.DEFAULT_CHECKS` already exists and already carries exactly
§10's five class names. `hx scan` runs a check only if its class is enabled
there. Note that `active_timing` defaults to `True` and this plan ships **no
checks in that class** — so an engagement enabling it gets an empty class, and
the scan summary must say so rather than imply the class ran.

---

## 6. Findings

A check returns `Candidate`s — title, severity, confidence, insertion, the
exchanges that evidence it. The runner does everything else:

- **Computes `dedupe_key`**, in exactly one place, to §5's canonical form:
  `type|scheme|host|port|method|path_template|insertion_kind|insertion_name`,
  literal `-` for absent parts and never `NULL`, because SQLite treats NULLs
  as distinct in a UNIQUE index and would silently defeat the constraint.
- **Upserts `finding`** on `(engagement_id, dedupe_key)`, with
  `created_by = 'check'` and `status = 'new'`. A check may never write
  `confirmed` or `reported` — a database trigger already forbids it, and a
  check is not a human.
- **Writes `finding_observation`** for this run.
- **Writes `evidence`** rows, ordered by `seq`, pointing at the exchanges.

**Retest, and the boundary that makes it honest.** A finding present in the
engagement but not observed this run gets `observed = 0` — **only if its
surface was actually tested this run.** A finding whose surface was never
reached gets no observation row at all. Otherwise "not observed" would mean
"not looked at", which is §12's own failure wearing a different hat.

---

## 7. Reporting

`hx report` renders **one Markdown file** into `exports/`, in the structure
already delivered by hand — not a format × audience matrix (§12).

Sections:

1. **Engagement** — client, dates, scope, `scope_version.sha256`, and the
   authorisation record in force. What you were permitted to touch is part of
   the deliverable.
2. **Findings**, by severity, each with its evidence chain and the exchanges
   behind it.
3. **Coverage**, generated from `check_run`: which checks ran against which
   surfaces, with verdicts, and the counts of `skipped` by reason. This is the
   section that lets you answer *"did you test the password reset flow?"*, and
   it is what makes a retest honest.
4. **Limits** — what this corpus does not cover, named rather than implied:
   no blind-only checks without a collector (§13), no body insertion on a
   production profile (§4), no crawler, and a floor on coverage whenever
   `run.dropped_total > 0`.

**Redaction runs on export**, per §12. The blobs are already redacted at
capture; export re-applies `records.redact_url` to anything rendered, because
a report is the one artifact that leaves the machine.

---

## 8. Error handling

- A check that **raises** → `check_run.verdict = 'error'`, `reason` carries the
  exception type and message, the scan continues. One bad check must not end a
  scan.
- A check that **returns nothing** → `error`, not `clean`. Silence is not a
  verdict.
- A **send refused** by the gate (scope, method, dangerous-path, rate, budget)
  → the denial row already exists; the check's row records `inconclusive` with
  the error class as its reason. The check did not fail; it was not permitted.
- The **bridge dies mid-scan** → remaining active rows become
  `skipped/no_bridge`; passive continues.
- A **finding whose surface vanished** between capture and scan → skip with a
  reason; do not fabricate a row against a surface id that no longer resolves.

---

## 9. Testing

- **Per check:** fixture exchanges in, verdict out. A check with no test that
  separates `finding` from `clean` is not done.
- **The registry:** every entry's declared `klass` matches the hooks it
  implements, every `id` is unique, and every `id` is stable across a version
  bump.
- **The runner:** budget exhaustion leaves `skipped/budget` and not absence;
  a raising check yields `error` and the scan continues; `pending` survives a
  simulated kill.
- **`dedupe_key`:** one canonical builder, pinned against §5's field order,
  with a test that two findings differing only in method are two rows.
- **Insertion derivation:** every kind in §4's vocabulary is derived from a
  fixture exchange, and `body_form` / `body_json` are asserted **present in the
  derivation and absent from anything probed**. That pairing is the only thing
  standing between "recorded, not probed" and a body payload going out under a
  method allowlist that forbids it.
- **The report:** a golden file, plus a test that a run with drops renders the
  coverage floor.
- **Vocabularies:** any new CHECK constraint is derived, never restated —
  `tests/test_vocabularies_match_the_schema.py` already enforces this and will
  demand a pairing for `insertion_kind` if it becomes constrained.

---

## 10. What this plan does not do

- **The crawler.** Its own plan. **It must not ship before `ProxyGate`
  consults the halt** — closing that needs `halted` in `DENIAL_KIND` and in
  `denial.kind`'s CHECK plus a `SCHEMA_VERSION` bump, or the refusal routes
  nowhere and vanishes. That condition travels with the crawler, not with a
  plan number.
- **Identity injection**, and therefore multi-identity access-control diffing.
- **The agent tool layer.** §10: adding a check does not add a tool.
- **The web app**, and with it finding triage. `status` stays `new` until a
  human moves it by some means this plan does not provide.
- **`active_timing`, `active_mutate`, `active_dos`.**
- **Per-engagement custom checks.** The registry is in-tree; loading a check
  from an engagement directory is a later, additive change.
- **OAST.** Deferred in §13 with reasons; v1 ships no blind-only checks and
  says so in the report.

---

## 11. Open questions

1. **Insertion-kind vocabulary as a CHECK constraint.** It is a free TEXT
   column today. Constraining it buys the drift protection the other
   vocabularies have; it also makes adding a kind a schema change. Decide when
   the second consumer appears.
2. **Whether `hx report` should refuse an engagement with zero `check_run`
   rows.** A report with no coverage section is exactly the report §12 calls
   worse than none — but refusing may be wrong for an engagement documented
   entirely by hand.
3. **`active_timing`'s conflict with the auto-halt.** A sleep payload is
   indistinguishable from a distressed host by §4's p50 rule. Whichever plan
   ships it must settle that first, in the spec.
