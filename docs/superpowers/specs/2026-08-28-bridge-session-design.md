# The bridge session

**Status:** approved 2026-08-28
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§4 enforcement invariant
and the DENY-ALL default, §5 tables, §6 bridge with correlation ids and `configure`/epoch,
§13 v1 scope)
**Blocks:** `docs/superpowers/specs/2026-08-28-active-checks-design.md`

## 1. Purpose, and the gap that produced it

**Nothing in `src/hx/` calls `bridge.configure()`.** Found while planning active checks:

- `hx capture start` (`cli.py:214-238`) opens a `run` row and prints a line. It does not
  launch Burp, serve the bridge, or configure anything.
- `configure()` exists at `bridge/server.py:650` with no caller in `src/`. Its callers were
  `scripts/demo_capture.py:226`, `scripts/demo_gate.py:159` and the integration tests —
  **three, not two**; an earlier correction here enumerated only the first and the tests,
  and left `demo_gate` out of a sentence whose whole purpose was to enumerate. **As of
  `1f23336` `demo_capture` calls `configure` through `hx.session.session()` and not
  directly.** `demo_gate` still calls it: it narrates the gate one refusal at a time with a
  hand-typed body (`limit.max_requests: 10`, a two-entry `dangerous.path`) that is the
  point of the script rather than a second spelling of the product's — but its scope hash
  is `hx.session.stored_scope_sha256`'s now, because a recomputed hash is the one thing §5
  forbids and the demo an operator runs must not teach it. The sentence above describes
  the gap that produced this plan, not the tree after it.
- The rig assembles the authorisation **inline in `Rig.configure`** — there was no
  named function to point at. (An earlier draft of this spec claimed a
  `build_config_body` in `tests/integration/conftest.py`. That was wrong *when it was
  written*: the only `build_config_body` in the tree then was `hx.bridge.codec`'s wire
  encoder, which a conftest docstring mentions and which does something else entirely.
  It stopped being wrong on this branch — Task 8 created
  `tests/integration/conftest.py:119 build_config_body`, which is
  `hx.session.config_body` plus the two keys only a test wants. The claim was corrected
  2026-08-28 and the correction is what is now out of date, in the other direction.)
- `launch_burp`, `wait_for`, `proxy_port`, `second_proxy_port`, `not_loopback_only` and
  `_jar_problem` live in `tests/integration/burp_fixture.py`, and the demo script imports
  them **from the test tree**.

The extension defaults to DENY-ALL, so an unconfigured extension refuses everything. The
demo and the rig each stand up their own session because the product has none — which is
why capture works in a demo and not from the CLI, and why an active check has nowhere to
send.

This plan builds the session the product should always have had. It is mostly **promotion
of proven code out of `tests/` into `src/`**, not new design.

## 2. Lifetime: each command owns its own Burp

`BridgeServer` holds a socket and a thread inside the process that created it, so a
one-shot CLI command cannot leave a session behind. Rather than introduce a daemon:

- **`hx capture start`** launches Burp, prints the operator proxy port, opens the run, and
  **blocks** while the consultant browses. Ctrl-C closes the run and tears everything down.
- **`hx scan`** launches its own short-lived Burp, configures it, does its work, and exits.
- **`hx capture stop`** keeps its present job: closing a run row left open by a crash.

Capture and scan never share a Burp, because scan does not need the operator's browsing
session — only somewhere enforced to send from. This buys the design out of a second IPC
channel, PID files, stale-daemon detection, orphaned processes, and the question of who is
authorised to talk to a control socket. The cost is Burp's startup on each scan.

## 3. `src/hx/session.py`

One module, one context manager, yielding a live and configured session.

Promoted from `tests/integration/burp_fixture.py`: `launch_burp`, `wait_for`,
`proxy_port`, `second_proxy_port`, `not_loopback_only`, `_free_port`, `_jar_problem`.

The session assembles what the demo assembles today — `OperatorHalt`, the exchange sink,
`BridgeServer`, the launched process, the handshake wait, the loopback check, `configure` —
and guarantees teardown.

**The test fixture and `scripts/demo_capture.py` are then rewritten to import the
product's implementation.** That is the point rather than a tidy-up: `conftest.py`'s own
comment already warns that "a config body spelled anywhere else is a second spelling free
to drift from this one". Today there are three spellings and none of them ships.

## 4. The configure body

Built from `Config`, using `codec.CONFIG_KEYS` as the vocabulary:

| Key | Source |
|---|---|
| `scope.include` | `Config.scope_include` |
| `scope.exclude` | `Config.scope_exclude` |
| `dangerous.path` | `Config.dangerous_paths` |
| `render.allow` | `Config.render_allow` |
| `limit.rate_rps` | `Config.rate_limit_rps` |
| `limit.concurrency` | `Config.max_concurrency` |
| `method.allow` | the constant `GET, HEAD, OPTIONS` |
| `limit.max_requests` | **omitted in this plan** |

`method.allow` is a constant because `Config` has no `method` key and this plan does not
add one — `Policy.DEFAULT_METHODS` is the same three verbs, so sending them explicitly
states the intent without widening anything.

`limit.max_requests` is omitted deliberately. `Limits.arm()` falls back to a
`defaultMaxRequests` that `Distress.java` documents as 2000 per run, and the active-checks
plan adds the `Config` field and the CLI option when it has something that spends the
budget. **Omitting it costs a browsing consultant nothing**: §4 is explicit that the
method allowlist, dangerous-path denylist, rate limit and budget "apply to the send path in
full, and to crawler traffic in full. They do **not** apply to traffic from the operator's
own browser." The two are told apart by which proxy listener the request arrived on, so
the session must plumb **both** listeners and report the operator's.

## 5. The scope hash comes from the store

`engagement.py:120` records `scope_version.sha256 = sha256(yaml_text)`. The demo instead
*recomputes* `sha256(config.dumps(cfg))` for its configure frame.

**The session sends the `scope_version` row's recorded `sha256`, read from the store, and
never recomputes one.** If the two ever diverged — a hand-edited `config.yaml`, a
different key order, an added comment — the report would render one hash as the authorised
scope while the extension had been authorised against another, and nothing would notice.
Reading the stored value makes the report's provenance and the extension's authorisation
the same fact rather than two facts that usually agree.

This matters more since Plan 5, whose F4 fix made the report render `scope_version.sha256`
as provenance for contract disputes.

## 6. Locating Burp

In order: an explicit `--burp-jar`, then `HX_BURP_JAR`, then a search of `HX_BURP_LAB`
(default `~/F0RT1KA/burp-lab`) for `burpsuite_desktop_v*.jar`. The fixture hardcodes
`burpsuite_desktop_v2026.7.3.jar`, which is right for a pinned fixture and wrong for a
product whose user upgrades Burp.

**When the search matches more than one jar it is an error, not a guess.** The message
lists what it found and says to pass `--burp-jar`. Silently picking the newest would let a
consultant run an assessment against a different Burp from the one they believe they are
running, and the report records the version.

`_jar_problem`'s judgement — missing, stale, future, or fine — is promoted with it, and
each state produces a specific message naming the fix rather than a stack trace.

**`hx` never bundles or redistributes Burp.** Locating a jar the operator already has is
the whole of this section.

## 7. Safety

- **Loopback-only listeners are enforced, not observed.** `not_loopback_only` moves into
  the product, and a session whose proxy listeners are bound beyond loopback **refuses to
  continue**. It is a control a consultant needs against a client network far more than a
  test needs it.
- **A failed `configure` tears the session down.** The alternative is leaving a running
  Burp whose extension is at DENY-ALL, which looks like a working session and captures
  nothing.
- **Teardown is unconditional**, including on Ctrl-C and on any exception. A Burp process
  is never orphaned.
- Engagement directories stay `0o700`, blobs and the database `0o600`.

## 8. Error handling

Each of these produces a distinct message and a non-zero exit: the jar is missing, stale,
or unreadable; the extension jar is unbuilt; the handshake does not complete inside its
timeout; the listeners are not loopback-only; `configure` is refused (`bad_config`,
`protocol_mismatch`, `engagement_mismatch`); Burp dies mid-session.

A handshake failure points at Burp's own log, as the demo already does — the common cause
is an unbuilt extension jar, and Burp starts happily without one.

## 9. Testing

The integration suite drives **the product's session** rather than the rig's copy, which is
the substance of this plan rather than a side effect: the code a consultant runs becomes
the code under test.

Two properties need tests of their own beyond the happy path:

1. **A refused `configure` leaves no Burp running.** The failure this guards is a session
   that looks alive and is at DENY-ALL.
2. **A session whose listeners are not loopback-only refuses to continue** and tears down.

All targets are loopback only. Burp runs against a private home built per run, never the
real `$HOME`. Nothing in this project has ever sent a request off this machine.

## 10. Decisions taken

| Decision | Choice | Why |
|---|---|---|
| Burp lifecycle | `hx` launches it | Community has no project files, so a manually-loaded extension would need re-adding every launch; launching is also what the demo and rig already prove |
| Session lifetime | Each command owns its own Burp | Avoids a daemon, a second IPC channel, and stale-process lifecycle this project has no machinery for; scan does not need the operator's session |
| Scope hash | Read `scope_version.sha256` from the store | Makes the report's provenance and the extension's authorisation one fact, not two that usually agree |
| `limit.max_requests` | Omitted here | The agent budget does not touch operator browsing, and the plan that spends it should be the plan that bounds it |

## 11. Out of scope

Attaching to an operator's existing Burp · session reuse across commands · a daemon or
control socket · the crawler beyond plumbing its listener through · what `max_requests`
should bound · identities · the agent tool layer.
