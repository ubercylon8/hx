# hx crawler — design spec

**Date:** 2026-09-02 · **Status:** draft
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md`
(§4 enforcement invariant, §5 data model, §9 discovery and crawling,
§12 reporting, §13 v1 scope)

This builds §13's *"the crawler (CLI + bounded `crawl.run`)"* — the last
v1 item. The web app, its sibling, shipped 2026-09-02.

Everything mechanical in this document was **measured on this machine on
2026-09-02**, against Burp's bundled Chromium 150.0.7871.186. Where a
claim is an argument rather than a measurement it says so, because the
chapter this repo added to `docs/DECISIONS.md` earlier the same day is
about exactly that distinction.

---

## 1. What this is, and what it deliberately is not

**It is a traffic generator, not a discoverer.** The crawler drives a
browser at in-scope pages. The browser makes requests. Those requests
cross the crawler proxy listener, the extension records them, and
`capture` writes surfaces with `discovered_by = 'crawl'` — machinery that
already exists (`capture.py:89`). The crawler itself writes no surface
row and parses no response body for the store's benefit.

That inversion is worth stating plainly because it explains the scope cut
below. §9's measured result — *"a link-following crawl found 7
references, all static assets; the browser-driven crawl found 65 requests
and 9 parameterised endpoints, including the one carrying an injection
flaw"* — comes from **the page's own XHR and `fetch` calls**, not from
clicking anything. A crawler that only navigates and never interacts
still collects all of it, because the collection happens at the proxy.

**This plan ships the navigation backbone only.** In: seed URLs, JS
rendering, link harvesting, an in-scope frontier, budgets, honest
truncation, and per-page render accounting. Out, and deferred to their
own spec and plan: **form submission, clicking, SPA route walking, and
authenticated crawling.** §9 specifies all four. Section 9 below says how
the report is required to disclose their absence.

The cut is not arbitrary. Form submission is §9's most safety-critical
paragraph — *"a crawler that finds 'Delete account' and dutifully clicks
it is the worst possible failure of this system"* — and it deserves a
review cycle in which it is the subject, not a passenger in the plan that
is also introducing a browser, a CDP client, a frontier and a new egress
path.

**It opens no new enforcement surface.** Section 3 is the argument: the
crawler's egress point was built ahead of it and is already load-bearing.

---

## 2. The mechanism, measured

| Decision | Basis |
|---|---|
| Burp's own bundled Chromium | §9 requires it. Found at `~/.BurpSuite/burpbrowser/<version>/chrome`; hx locates the newest and never ships one. |
| CDP over `--remote-debugging-pipe` | Verified: `Browser.getVersion` answered over fds 3/4. Full protocol, stdlib only, **no socket**. |
| Sandbox ON | Verified: launches sandboxed with no `--no-sandbox`, via unprivileged user namespaces (`kernel.unprivileged_userns_clone = 1`). Burp's `chrome-sandbox` is not setuid and is not needed. |
| `--proxy-bypass-list=<-loopback>` | **Verified, and load-bearing — see §4.** |
| Private `--user-data-dir` per run | The rule the Burp home already follows: a run never touches a real profile. |

### Why pipes and not a WebSocket

The ordinary way to drive Chromium is CDP over a WebSocket on
`--remote-debugging-port`. That would put a socket client inside
`src/hx`, and `pyproject.toml` already carries the objection, written
about `httpx2`:

> nothing in `src/hx` imports it, and the app itself makes no outbound
> HTTP request of any kind — S4's invariant is that every byte leaving
> this machine crosses the JVM, and an HTTP client in the runtime closure
> is the kind of thing that quietly stops being true.

A WebSocket client aimed at loopback today is a WebSocket client. Over
pipes there is no port, no client, and no address to repoint: the
transport is two file descriptors on a child process. The crawler gets
full browser control and the runtime closure gains nothing that can
address a network.

**Implementation trap, measured.** `subprocess` closes descriptors
outside `pass_fds` *after* `preexec_fn` runs, so dup2-ing onto fds 3 and 4
inside `preexec_fn` without also passing `pass_fds=(3, 4)` gets them
closed before exec, and Chromium answers `Remote debugging pipe file
descriptors are not open.` The first attempt at this failed exactly that
way.

### TLS

The browser is launched with `--ignore-certificate-errors`. Every
certificate it can see is one Burp minted, because its only route to
anything is the loopback proxy (§4), and hx does not currently parse
certificates, so pinning `--ignore-certificate-errors-spki-list` to
Burp's CA is not available without new machinery.

**What this costs, stated rather than buried:** the crawler cannot
observe TLS problems on the target. It is not blind to them as a system —
Burp validates the upstream connection itself and the extension records
the result — but the browser's own view is unconditionally trusting.
Pinning to Burp's CA SPKI is the strictly better version and is deferred
with that name.

---

## 3. The enforcement boundary already exists

§4: *"The crawler's browser is the second egress path, and it is
enforced, not observed."* That enforcement is built, shipped and tested,
ahead of the thing it governs — §4 line 140 says so on purpose
(*"request handler ships in Plan 4, ahead of the crawler rather than with
it"*). Verified in the tree today:

- `Source.forListenerPort(port, crawlerPort)` attributes a request to
  `CRAWLER` or `OPERATOR` **by which listener it arrived on**
  (`extension/src/hx/proxy/Source.java:117`). Not by a flag the caller
  sends.
- `ProxyGate` line 182: the `CRAWLER` branch runs `policy.decide(req, auth)`
  — the *full* agent policy, scope and Gate and rate and budget. The
  `OPERATOR` branch runs `decideScopeOnly`.
- `api.proxy().registerRequestHandler` returns
  `ProxyRequestReceivedAction.drop()` for out-of-scope destinations
  (`extension/src/hx/HxExtension.java:396`).
- `RUN_KINDS` already contains `crawl` (`src/hx/run.py:28`), and
  `capture.py:89` already maps the crawler listener to
  `discovered_by = 'crawl'`.

**So this plan adds no enforcement point and moves none.** The crawler is
a client of a boundary that already refuses it.

Python will *also* refuse to enqueue an out-of-scope URL. That is
defence in depth and is explicitly not the gate — the same relationship
`_probe_util` has with the extension's credential-header refusal, where
the Python check is redundant and the JVM one is authoritative. A test
must pin that ordering, so that a future reader cannot mistake the Python
frontier for the thing that makes the crawler safe.

### The one gap: `render_allow` is declared and inert

§4 names `render_allow` as the reviewable escape hatch for third-party
page resources. Today it is:

- a Python config field — `src/hx/config.py:347`
- shipped over the bridge as `render.allow` — `config.py:600`
- an accepted key in `ConfigBody.KEYS` — `extension/src/hx/bridge/ConfigBody.java:15`
- **read by nothing.** `Policy.java` never references it.

An operator who sets it today gets silence. That is harmless while
nothing renders pages and stops being harmless in this plan, so making it
enforce is **Task 1**, before any browser code exists. It is the only
Java in this plan.

Its semantics, narrowly:

- A destination matching `render_allow` is permitted **as a subresource
  of an in-scope page**, never as a crawl frontier entry.
- **Identity is never attached to it.** §4's rule is unconditional and
  `render_allow` does not qualify it.
- It is recorded like any other decision, so a report can show what was
  allowed to render and why.

---

## 4. `--proxy-bypass-list=<-loopback>`, and why it gets its own section

**Measured 2026-09-02.** A Chromium launched with
`--proxy-server=127.0.0.1:<port>` and pointed at
`http://127.0.0.1:18080/probe`:

| launch | connections the proxy received |
|---|---|
| without `--proxy-bypass-list` | **0** |
| with `--proxy-bypass-list=<-loopback>` | 1 — `GET http://127.0.0.1:18080/probe HTTP/1.1` |

Chrome bypasses configured proxies for loopback destinations by default.
Without that flag the crawler's browser reaches a loopback target
**directly**: around the crawler listener, around `ProxyGate`, around
every §4 enforcement point, recording nothing and being refused nothing.

This is not a performance footnote, it is the §4 invariant surviving or
not, and it has a second property that earns it a section: **it is
invisible in exactly the environment this repo is allowed to test in.**
Every test target here is loopback by mandate — `TargetServer` refuses
any host outside `127.0.0.0/8`. A crawler missing this flag would drive a
browser that never crosses the JVM, render pages perfectly, discover
surfaces through the *operator's* listener or not at all, and present as
a working enforced crawler in every integration test written against it.

It reaches further than the happy path. `TargetServer` binds the
in-scope target on `127.0.0.1` and the **out-of-scope** target on
`127.0.0.2` — a second loopback address. Both are bypassed. So a test
asserting that an out-of-scope destination is *dropped* would also be
driving a browser that reached it directly, and would be asserting the
absence of a recording rather than the presence of a refusal. The
enforcement test and the bypass share a blind spot.

**Required test, and it must fail for the right reason.** An integration
test asserts that a crawl of a loopback target produces exchanges
attributed to the `crawl` source. The named mutation is *delete
`--proxy-bypass-list=<-loopback>` from the launch arguments*; the test
must go red. A test that merely asserts the page rendered would stay
green through that mutation, which makes it one of the five catalogued
shapes of unfailable test and not acceptable here.

---

## 5. The page lifecycle

For each URL taken off the frontier:

1. **Navigate.** `Page.navigate`, with `Network` and `Page` domains
   enabled beforehand so no event is missed.
2. **Settle.** Wait for in-flight requests to reach zero and stay there
   for a short quiet period, bounded by a hard per-page cap. Network-idle
   is the heuristic that best matches what this crawler is for — the
   value is the XHR a page fires after load — and the cap is what stops
   one long-polling endpoint, analytics beacon or open WebSocket
   consuming the entire crawl budget. A page that hits the cap is
   recorded as capped, not as complete.
3. **Harvest.** Read the settled DOM and collect candidate URLs:
   `<a href>`, `<area href>`, `<iframe src>`, and `<form action>`
   (recorded as a URL; **not submitted** — see §9). Resolved against the
   document's base URI.
4. **Account.** Classify every subresource the page requested — §6.

Harvesting reads the *settled* DOM rather than the served HTML, which is
the entire reason a browser is involved: verified today, a JS-injected
`<a href="/found/by/js?id=1">` appears in `--dump-dom` output and does
not appear in the source.

---

## 6. Render accounting, which is §12 applied to a crawl

The failure this prevents: the proxy drops an out-of-scope CDN bundle,
the SPA never boots, the crawler visits the page, finds nothing, and
records a **clean crawl of an application it never rendered**. That is
"tested, clean" indistinguishable from "never reached", which §12 calls
worse than no report.

Only the browser can attribute this. The store knows a request was
denied; it does not know whose render the denial broke. So accounting is
per page, from CDP `Network` events, and each failed subresource is
classified by re-running the scope predicate:

- **out-of-scope failure** → hx dropped it. Cross-checkable against the
  denial rows, which remain authoritative.
- **in-scope failure** → the target itself failed. A different fact, and
  not a policy artifact.

Each page ends as exactly one of:

| state | meaning |
|---|---|
| `rendered` | the document loaded and the page yielded links or in-scope requests |
| `degraded` | out-of-scope subresources were dropped **and** the page yielded nothing beyond its own document |
| `failed` | the document itself never loaded |

The crawl summary reports the counts and **lists the dropped hosts** —
which is precisely the list an operator pastes into `render_allow`, so
the diagnostic and the fix are one artifact rather than two.

**A deliberate imprecision, written down rather than discovered.** A
genuinely empty page — a static confirmation screen with one dropped web
font — will be classified `degraded`. That is a false degradation. The
rule errs that way on purpose: §12's asymmetry is that under-claiming
coverage is survivable and over-claiming it is not. The report says
`degraded` means *"this page may not have rendered"*, never *"this page
did not render"*.

---

## 7. The frontier

- **Seeded** from an explicit target argument and any seed list in
  `config.yaml`'s crawl hints.
- **Origin-allowlisted, which is not a scope check and must not be called
  one.** The frontier enqueues a URL only when its origin matches one of the
  seed origins. It is deliberately *not* a Python reimplementation of scope:
  there is no Python scope matcher in this repo today, scope matching lives
  in `Policy.Rule` behind percent-decoding to a fixed point, userinfo
  rejection, path-length bounds and reading sets, and **a second matcher is a
  second answer**. The one that drifts is the one nobody is enforcing with.

  So the frontier answers a narrower question — *"is this page worth
  visiting"* — and the JVM answers the only question that gates egress. A URL
  on a seed origin but outside `scope.include` by path **will** be enqueued,
  visited, dropped at `ProxyGate`, and recorded as a denial. That costs one
  refused request and is the correct outcome: the alternative buys nothing
  and adds a matcher that can disagree with the enforcer.
- **Deduplicated by URL**, not by path template. The normaliser's
  templating is right for coverage attribution and wrong here: it maps
  `/user/1` and `/user/2` to one template, and the second may reach code
  the first did not. Frontier growth is bounded by the budgets, not by
  collapsing distinct addresses.
- **Fragment-stripped**; query strings preserved, since a query parameter
  is the thing a scan later probes.

**Budgets**, per §9: `max_pages`, `max_seconds`, `max_requests`, plus the
per-page settle cap of §5. Exhausting any of them **returns what was
found and reports the crawl as truncated, naming which budget stopped
it.** A truncated crawl that presented as a complete one would be §12's
failure again, one level up.

---

## 8. Surfaces: the CLI and the tool

**`hx crawl`** — the CLI step. Long crawls belong here, outside the agent
session, per §9.

**`crawl.run`** — the same crawler, bounded and synchronous, so an agent
can sweep a newly-found area mid-session. It is already registered and
already answers `unavailable/not_implemented`; this plan replaces the
handler. §8 put it in the agent's tool list at spec time and this
document does not reopen that. It **must be re-registered**
`needs_egress=True` and `mutates=True` — the stub carries neither,
because a handler that always raises never reaches the checks those
flags drive. Like `scan.run`, it must be called inside a run, of kind
`crawl`.

The `not_implemented` message it currently returns is doing real work in
reports today — *"discovery was proxy-only"* — and §9's disclosure
requirement in section 9 below is what replaces that work.

---

## 9. What the report must say about what this crawler cannot do

A backbone crawler that reports "crawled" while never having submitted a
form or clicked a control claims coverage it does not have. §12 forbids
that, and the mechanism is the one the Findings scope line already
established on 2026-09-02: **the report states the boundary in the same
place it states the result.**

The crawl summary and the report's Limits section must both say, in as
many words, that this crawler:

- follows links and renders JavaScript, and **submits no forms**
- **clicks nothing**, so any surface reachable only through interaction
  was not discovered
- **walks no SPA route** that requires interaction to reach
- crawls **unauthenticated**, so anything behind a login was not reached
  by the crawler — §9's first discovery source, the operator's own
  browsing, is how authenticated applications get covered

Each of those is a deferred feature with a name, not a defect, and the
report says which.

---

## 10. Shape

```
src/hx/crawl/cdp.py       pipe transport, id correlation, timeouts   (no sockets)
src/hx/crawl/browser.py   locate Chromium, launch, sandbox check, private profile,
                          proxy wiring incl. the flag of §4
src/hx/crawl/page.py      navigate, settle, harvest, per-page accounting
src/hx/crawl/frontier.py  queue, dedupe, scope refusal, budgets
src/hx/crawl/run.py       orchestration, truncation, summary
src/hx/cli.py             `hx crawl`
src/hx/tools/impl/scan.py `crawl.run` handler replaces the stub
extension/src/hx/policy/  render_allow enforcement                    (Task 1)
```

---

## 11. Testing

The split follows the one this repo already uses.

**Unit, no browser.** The CDP transport is driven by a fake child process
speaking the protocol over real pipes. The frontier, the budgets, the
scope refusal and the page classifier are pure functions over synthetic
CDP event streams. This is the bulk of the suite and it runs in CI.

**Integration, real Chromium**, marked `@pytest.mark.integration`,
against the loopback-only `TargetServer`. Small in number and specific in
purpose: that a crawl produces exchanges attributed to `crawl`; that the
proxy-bypass mutation of §4 turns that red; that an out-of-scope
destination is dropped and the drop is recorded; that a `render_allow`
entry changes the outcome.

**Every security-relevant test is written so that a named mutation turns
it red, and the mutation is named in the test's own docstring.** This
repo has shipped vacuous tests twice and the five shapes are catalogued
in `docs/DECISIONS.md`. The two that this plan is most exposed to:

- a test that asserts a page rendered when it means to assert the request
  was proxied (§4's mutation is the guard)
- a test whose fixture makes two branches fire at once, so deleting
  either leaves it green — the shape that the SQLi behavioural check's
  own status-differential test shipped with and was caught by mutation

**No test may point a browser at a non-loopback host.** `TargetServer`'s
refusal of anything outside `127.0.0.0/8` is load-bearing and this plan
does not relax it.

---

## 12. Deferred, with names

| Deferred | Why it is not here |
|---|---|
| Form submission | §9's most safety-critical paragraph; gets a spec and a plan in which it is the subject |
| Clicking and SPA route walking | Rides with forms — both are "interact with the page", one CDP capability |
| Authenticated crawling | Needs identity attach plus halt-on-session-death; §9's operator-browsing path covers authenticated apps in the meantime |
| File upload inputs | §9 skips them in v1 outright |
| TLS pinning to Burp's CA SPKI | Needs certificate parsing hx does not have (§2) |
| Async job runner, `crawl.status` | §13 already refuses it: budgets and truncation instead of resumption machinery |
