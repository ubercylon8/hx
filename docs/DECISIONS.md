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

*Cost:* the active corpus has no retest story in v1. A client must verify an active finding
by hand. The report says so in as many words.

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

---

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
| `finding.normaliser_version DEFAULT 1` | Inherited from a merged plan whose own deadline expired before the branch that noticed it. Cannot produce a wrong result today: nothing writes or reads the column |
| `2026-08-27-checks-and-reporting.md` holds `plan-drift: pending` | 26 blocks uncompared, including whole-file markers for code later plans rewrote |
| `open_redirect` can only be shown a fix on a 2xx | A fix delivered by `302 → /home` leaves the finding live indefinitely. The discriminator that would fix it does not exist without a control probe: a login redirect is typically same-origin too |
| The probe's own exchange is not recorded | An active finding cites a captured request to the affected surface rather than the probe that demonstrated it. Needs a new bridge frame type and writer |
| `path_traversal` cannot probe a `path_segment` in practice | Its name filter wants a file-shaped name; the normaliser's vocabulary is `{id}/{uuid}/{hex}/{slug}`. A false negative, disclosed in the report |
