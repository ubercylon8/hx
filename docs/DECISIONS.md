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
| `Limiter.java`'s "no new refusal after the gate" rule is false | The identity branch added two — `unknown_identity` and `identity_origin` — which land after `checkGate` has spent a rate slot and a budget unit while the target sees nothing and `requests_sent` reads 0. The comment is corrected and the decision order deliberately untouched; the burn can only make `hx` send *fewer* requests than authorised, never more |
| A surface carrying any finding retires nothing on that surface | The `finding` branch offers no `considered`, because it short-circuits above the gaps check the passive corpus relies on. Under-claims, and disclosed to the client |
| `codec.identity_body` does not enforce the three-name header set | `hx.config` refuses a fourth name with a better message and `IdentityRegistry` refuses it inside the JVM, which is where §4 puts enforcement. A third copy would be a third place to drift |
| `path_traversal` cannot probe a `path_segment` in practice | Its name filter wants a file-shaped name; the normaliser's vocabulary is `{id}/{uuid}/{hex}/{slug}`. A false negative, disclosed in the report |
