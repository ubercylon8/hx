# Identity and authentication — design

**Status:** approved 2026-08-30
**Implements:** §7 of `2026-08-21-hx-design.md`, minus multi-identity replay
**Master spec:** `2026-08-21-hx-design.md` — §4 (enforcement invariant), §5 (data model),
§6 (bridge), §7 (identity), §12 (reporting), §13 (v1 scope)

---

## 1. What this builds, and why now

`hx` can capture and probe an application, but every request it originates is
**unauthenticated**. `config.yaml` accepts an `identities` block that nothing reads, and
`exchange.identity`, `.identity_generation` and `.identity_state` are columns that stay
NULL.

The cost is not only coverage. Because an unauthenticated probe cannot tell a login page
from an answer, active checks were stripped of the ability to retire a finding at all
(`hx.scan._retirable`) — so an application's whole authenticated surface is both untested
and un-retestable. This plan is the root fix for both.

**Half of §7 already ships.** `Redactor.Injected.register(identityId, start, end)` exists,
validates overlaps, refuses a range running past the end of the request, and emits
`{{identity:<id>:authz}}`. `BridgeServer.send`'s contract already names `identity_id` as a
field the send frame carries. Nothing registers a range and nothing sets the field. This
plan is the missing injection half, not a new subsystem.

## 2. Scope

**In:** the `static` and `programmatic` strategies · secret resolution outside the config
record · an `identity` bridge frame · the extension-side identity registry and per-send
application · registration of injected ranges with the existing `Redactor` · generation ·
the liveness canary · halt-on-liveness-failure · probes running under an identity ·
re-enabling active-check retirement under a **proven** identity.

**Out, deliberately:**

| Deferred | Why |
|---|---|
| Multi-identity replay / access-control diffing | Needs two proven sessions and a *semantic response comparison*, which is a different problem from holding a session. Its own plan, once this one gives it sessions |
| `registerSessionHandlingAction` | §7: registration was proved on Community, invocation was not. Identity is applied on the send path we control |
| Browser-login identity strategy | §13 defers it: log in by hand once and hand `hx` the session |
| Applying identity to **proxy** traffic | The operator's browser already carries its own session. §4's split says the proxy listener is recorded, not governed |

## 3. The constraint that shapes the config

`scope_version.yaml` is `TEXT NOT NULL` and holds the **full config YAML verbatim**. The
schema calls the table "append-only: tamper-evidence for contract disputes", and a new row
is written whenever the config changes.

So a credential written into `config.yaml` is copied verbatim into a table designed to be
impossible to rewrite, once per scope version, permanently. That is §7's own warning about
the blob store — *"once raw credentials are content-addressed into the blob store, they are
in every backup"* — in a different table, and no more retrofittable.

**Therefore: a credential value never appears in `config.yaml`.** The config declares the
identity; the environment supplies the secret.

This also gets a second property for free: **rotating a credential changes no scope hash.**
Rotating a session is not a movement of the engagement boundary, and a scope-version row
that appeared because a cookie expired would make the tamper-evident record lie about what
it is evidence of.

## 4. Config

```yaml
identities:
  user:
    strategy: static
    inject:
      header: Cookie
      value_from_env: HX_IDENTITY_USER
    liveness:
      path: /account
      expect_body: "Sign out"
      expect_absent: "Sign in"        # optional
      every_n_probes: 25              # optional; default 25
  admin:
    strategy: programmatic
    refresh:
      command: ["./scripts/mint-admin-token.sh"]
      value_from: stdout              # the command PRINTS the credential
    inject:
      header: Authorization
    liveness:
      path: /admin/whoami
      expect_body: '"role":"admin"'

scan_identity: user                   # which identity `hx scan` probes under; omit for anonymous
```

**Rules the loader enforces, each failing closed at `hx new`/load time rather than mid-run:**

- `inject.header` must be one of `Cookie`, `Authorization`, `Proxy-Authorization` — the
  three the send path already refuses when unmanaged. Injecting anything else would not be
  a credential and would not need this machinery.
- `value_from_env` names a variable; the **value is never read into the config object's
  serialised form**. `config.dumps()` must round-trip the declaration without the secret,
  and a test pins that the rendered YAML contains no environment *value*.
- `liveness` is **required** for every identity. An identity with no liveness proof can
  never be `proven`, and §7's whole argument for generation is that an unproven session
  produces "six hours of unauthenticated traffic that every check reads as *not
  vulnerable*".
- `expect_body` is **required**. See §6.
- `scan_identity`, if present, must name a declared identity.
- A `static` identity may not declare `refresh`; a `programmatic` one must.

## 5. The bridge: `identity` is its own frame

Identity is **not** a `configure` key.

§5 and §6 say a later `configure` naming a different rate or budget is *refused, not
applied* — configure re-authorises **scope**, and a run must not talk its way into a larger
allowance mid-flight. A programmatic refresh has to bump an identity's generation *without*
re-opening scope, so folding identities into `configure` would either weaken that rule or
make refresh impossible.

A new frame type, `identity`, carrying:

```
{ "identity_id": "user",
  "generation": 3,
  "inject": {"header": "Cookie", "value": "<secret>"},
  "origins": ["https://app.acme.test"] }
```

- **Registration is per-identity and idempotent by generation.** A frame naming a
  generation the extension already holds is accepted and changes nothing; a *lower*
  generation is **refused** — a monotonic counter, for the same reason `Limiter`'s budget
  is monotonic, so a replayed frame cannot roll a session back.
- **`origins` bounds where the credential may be applied.** An identity is scoped to the
  hosts it belongs to, so a probe against a third-party host in scope never carries the
  target's session. Defaults to the hosts in `scope.include`.
- The frame is refused unless the extension is `configured` and not halted, exactly as
  `send` is.
- **The frame carries a live credential, so it is never logged on either side.** The
  bridge's own diagnostics print frame *kinds* and correlation ids, never bodies; an
  `identity` frame must not become the exception. This is the only frame in the protocol
  whose payload is a secret, and a debug line added later is exactly how it would leak. A
  test asserts that neither side's log output contains an injected value.

## 6. Liveness, and what `proven` is allowed to mean

**A canary that accepts a status code is worthless, and would reintroduce the exact defect
this plan is meant to close.**

The active-check corpus was found able to answer `clean` from a probe that tested nothing
in eight distinct ways; the last, which no response-status rule can catch, is an
application answering a logged-out request with a **200 login page**. A liveness canary
that checked `status == 200` would be satisfied by that page, stamp the identity `proven`,
and — since §9 below re-enables retirement on exactly that stamp — hand the hazard back
with a proof attached to it.

So:

- `expect_body` is **required** and must match for the canary to pass. It is a positive
  signature: a string only an authenticated response carries.
- `expect_absent`, if given, must **not** match. A negative signature (`"Sign in"`) catches
  the case where a page contains both.
- Status is checked only to the extent that a non-2xx is an automatic failure. It is never
  sufficient on its own.

**Outcomes:**

| Canary result | Identity state | Run |
|---|---|---|
| passes | `proven` at this generation | continues |
| fails, `static` | `dead` | **halts** |
| fails, `programmatic` | refresh, then re-canary | continues if the second canary passes |
| fails after refresh | `dead` | **halts** |

Halting rather than continuing is §7's explicit instruction, and the reason is that the
alternative is silent: a dead session produces a run of "not vulnerable" answers that look
exactly like a clean application.

### When the canary runs — and why one at the start is not enough

A canary that runs only at the start of a run **cannot** deliver what §7 asks of it. Its
motivating scenario is a session dying *mid-run* — "an SSO session dying at 01:50 produces
six hours of unauthenticated traffic that every check reads as *not vulnerable*" — and a
single canary at 01:00 would stamp every one of those six hours `proven`. §9 then retires
findings on that stamp. The hole would be worse than having no proof at all, because it
would carry one.

So `proven` is a property of a **window bracketed by two passing canaries**, not of a
moment:

- **At run start.** A failure here halts before any probe is sent.
- **Every `liveness.every_n_probes` probes** (default 25). Bounds how much traffic one
  undetected death can contaminate.
- **At run end**, always, even if no probe was sent since the last one.

An exchange is `proven` only if the canaries **on both sides of it** passed. When a canary
fails, every exchange back to the last passing canary is downgraded from `proven` to
`assumed` — they were issued into an unknown state, and the run must not claim otherwise.
Since §9 gates retirement on `proven`, a downgrade retires nothing, which is the correct
outcome for traffic that may have been unauthenticated.

This is the same rule the check corpus already lives by: a result is only as good as the
proof that the thing was actually tested.

**The canary is ordinary traffic.** It goes through the send path like any other request,
carries the identity, and is subject to scope, the method allowlist, the rate limit and the
budget. It is counted in `requests_sent` for the run, because it is a request `hx` put on
the client's system.

**`identity_state` on `exchange`** is written from the identity's state *at the moment of
issuance*: `proven` if the canary passed for that generation, `assumed` if the identity was
applied without a current proof, `dead` if it had failed. The column already exists with
exactly this CHECK constraint.

## 7. The extension side

A new `IdentityRegistry` holding `identity_id → {header, value, origins, generation}`,
consulted on the send path immediately before issuance:

1. `Sender` reads `identity_id` from the send frame. Absent means anonymous — the current
   behaviour, unchanged.
2. If present and unknown, the send is **refused** (`unknown_identity`). Failing closed:
   issuing anonymously when the caller asked for an identity would produce exactly the
   unauthenticated-answer confusion this plan exists to remove.
3. If the request's host is not in the identity's `origins`, the send is **refused**
   (`identity_origin`). A credential is not sprayed at whatever host a check names.
4. The header is injected, and **the byte range written is registered with the
   `Redactor.Injected` for that request** before the request is issued or stored.
5. `unmanaged_credential` still fires for a credential header the extension did **not**
   inject. Injection does not weaken it; it is what finally gives the refusal an
   alternative.

**Ordering is load-bearing.** Injection happens after every gate — scope, method,
dangerous, rate, budget — so a refused request never has a credential written into it, and
the published decision order is unchanged. Registration happens before the copy that
crosses the bridge is made, which is what keeps §7's "redaction runs before hashing" true.

## 8. Probes run under an identity

`hx.scan.run` resolves `scan_identity` once, and `ProbeSender` is constructed bound to it —
the same shape as its existing binding to one surface. `ProbeSender.get` puts `identity_id`
in the send frame.

**A check still never knows about authentication.** It cannot choose an identity, read one,
or ask whether one applied; §7 puts identity below the check layer and nothing here changes
that. The runner decides, exactly as it decides the surface.

## 9. Retirement, re-enabled narrowly

`hx.scan._retirable` currently refuses `considered` from every non-passive check. It becomes:

> An active check's `considered` is honoured **only if** every probe it sent ran under an
> identity whose canary was `proven` at the generation in force for that request.

Anonymous probes, `assumed` probes and `dead` identities retire nothing — identical to
today's behaviour. Passive retirement is untouched.

The report's Limits section must change with it: the current text states flatly that an
active finding is never automatically marked as fixed. That becomes conditional, and the
condition has to be stated in the client's terms — a finding was re-tested under a session
proved live, or it was not.

## 10. What the report must say

- Which identities were declared, and for each: strategy, how many generations, and how
  many exchanges were `proven` / `assumed` / `dead`.
- **A run that halted on a dead session says so**, prominently. It is the difference
  between "we tested this and found nothing" and "our session died at 01:50".
- The unauthenticated-probe limitation stays on the page whenever `scan_identity` is
  absent, unchanged.
- No credential, and no environment variable *value*, appears anywhere in a rendered
  report. A test pins it.

## 11. Failure modes this design accepts

| | |
|---|---|
| A `programmatic` refresh runs an operator-supplied command | It is the operator's own machine and their own command, declared in their own config. It is not passed anything from the target, and its output is treated as a credential, never as a shell fragment: `command` is a list, never a string, and is executed without a shell |
| An identity whose `expect_body` also appears on the login page | The canary would pass on a logged-out response. `expect_absent` exists for it, and the config docs say what a good signature is. Not detectable from inside `hx` |
| A session that dies *between* two canaries | Real, and closable only by a canary per request, which would double the traffic `hx` puts on a client's system to buy certainty about a window the bracket already bounds. The bracket handles it correctly rather than optimistically: a failing canary downgrades the whole window to `assumed`, so the run under-claims instead of over-claiming, and retires nothing |
| A session that dies and *recovers* between two canaries | Both canaries pass, the window reads `proven`, and some exchanges inside it were anonymous. Undetectable without per-request proof. It is the one case where `proven` can be wrong, it requires an application that logs a session out and back in unaided, and the cost is bounded by `every_n_probes` |

## 12. Open questions

None blocking. One noted for the plan: whether `value_from_env` should be joined by
`value_from_file` for operators who prefer a mode-0600 file to an exported variable. The
env path is sufficient for v1 and a file path is additive, so it is not decided here.
