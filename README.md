# hx

An agent-driven web application security assessment harness that uses **Burp Suite
Community as an engine, not a frontend**.

Burp Community has no scanner, no automation API and no session handling. `hx` supplies
those from the outside: a Java extension inside Burp's JVM enforces safety policy, a
Python side drives it over a local socket, and everything either of them observes lands in
a per-engagement SQLite database that a report is rendered from.

`hx` does not bundle, redistribute, or modify Burp Suite. You bring your own copy.

---

## The safety model, first

`hx` exists to send crafted requests at systems that belong to somebody else. Every design
decision below follows from that, and none of it is optional at runtime.

**One enforcement point, inside the JVM.** Every byte that leaves the machine crosses
either the send path or the proxy request handler, both in `extension/`. There is no third
route, and the Python side cannot reach past either — it can only ask. A bug in Python
cannot widen scope.

**Deny-all by default, and terminal.** An unconfigured extension refuses everything. A
`halt` is not a pause: once the sentinel exists, the run is over and no later message
re-opens it.

**Written down or it does not happen.** An under-specified engagement config is a *safe*
config — production profile, mutating and DoS checks off, a low rate limit. Anything that
increases blast radius has to be typed into `config.yaml`, where it is recorded and
reviewable.

**The operator is not the agent.** The method allowlist, dangerous-path denylist, rate
limit and budget apply in full to `hx`'s own traffic and not at all to your browser. The
two are told apart by *which proxy listener the request arrived on* — never by anything in
the traffic itself, which could be forged.

**A report that cannot tell "tested, clean" from "never reached" is worse than no report.**
Coverage is part of the deliverable. A check that could not run says so, by name, with a
reason.

---

## Requirements

| | |
|---|---|
| Python | 3.12+ |
| Java | 21 (to build the extension) |
| Burp Suite | Community 2026.7.3 (any recent Community build should work) |
| Montoya API | `montoya-api.jar` — the extension API, from [Maven Central](https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api) |

## Install

```bash
uv sync                                    # or: pip install -e .
MONTOYA_JAR=/path/to/montoya-api.jar ./extension/build.sh
```

## Use

```bash
hx new acme-2026 --client "Acme Ltd" --scope 'https://app.acme.test/*'
hx capture start                           # launches Burp; browse the target through it
hx capture stop
hx scan                                    # runs the check corpus against what was seen
hx report --out report.md
```

`--scope` is repeatable and at least one is required; `--exclude` takes patterns out again.
`hx capture start` and `hx scan` each take `--burp-jar` if yours is not where `hx` looks,
and `--max-requests` to override the engagement's budget for that run.

`hx halt` stops everything immediately and permanently for that engagement; `hx resume`
starts a new run rather than reviving the halted one. `hx info` prints engagement state.

---

## What it does today

**Discovery is proxy-only.** `hx` sees the application as you browse it through Burp. It
records requests, responses and the surfaces they imply. There is no crawler yet (see
below), so anything you do not visit is not tested.

**Nine checks**, in two classes:

| Class | Checks |
|---|---|
| `passive` — reads captured traffic, sends nothing | `cookie-flags` · `security-headers` · `secret-in-response` · `stack-trace` |
| `active_safe` — idempotent GET probes | `cors` · `open-redirect` · `reflected-input` · `sql-error` · `path-traversal` |

`active_timing`, `active_mutate` and `active_dos` are check *classes* the config and the
extension already understand; no checks of those classes ship yet.

**Findings persist across runs**, keyed on a nine-part dedupe key, so re-scanning an
engagement updates findings rather than duplicating them.

### Known limitations, stated because the report states them

- **Probes are unauthenticated.** They carry no cookie, no `Authorization`, and none of the
  endpoint's other parameters, so against an application that requires a session they test
  the logged-out view. A login redirect or an authorisation refusal is recorded as
  `inconclusive`, never as clean — but an application that answers a logged-out request
  with a **200 login page** cannot be told apart from one that answered.
- **Active findings are never automatically marked as fixed.** Because of the above, a
  re-scan is not evidence a finding is resolved. Verify an active finding yourself before
  closing it. Passive findings do retire, because they read captured traffic.
- **No out-of-band (OAST) capability.** `hx` ships no blind-only checks and says so in the
  report rather than leaving the gap silent.
- **Cookie and credential-header insertion points are not probed**, because the send path
  refuses credentials it did not inject.

## What is not built yet

Against the v1 scope in the design spec, five of nine items are done. Outstanding:

- **The crawler** — the schema and the extension's crawler listener exist; nothing drives a
  crawl.
- **Identities** — `config.yaml` accepts an `identities` block and nothing applies it. This
  is the root of the unauthenticated-probe limitation above.
- **The agent tool interface** — `hx` is CLI-driven today.
- **The web app screens.**

---

## Development

```bash
uv run pytest                  # unit + fast integration-free suite
uv run pytest -m integration   # launches a REAL headless Burp; needs BURP_JAR
./extension/test.sh            # the Java suite; needs MONTOYA_JAR
uv run ruff check .            # lint gate (CI-blocking)
```

The integration suite is deselected by default because it needs a real Burp. Everything it
drives is **loopback only** — no test in this repository has ever sent a request off the
machine, and the target-server fixture refuses any address outside `127.0.0.0/8`.

Design specs and implementation plans live in `docs/superpowers/`. Plans quote the source
they specify, and `tests/test_plan_matches_repo.py` fails if a quoted block drifts from the
file it names — so a plan cannot silently come to describe code that no longer exists.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit, and
[`docs/DECISIONS.md`](docs/DECISIONS.md) for the decisions behind them.
