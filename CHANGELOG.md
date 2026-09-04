# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, the CLI surface, the tool schemas and the on-disk engagement format may
change between minor versions. The enforcement invariants will not weaken.

## [Unreleased]

## [0.1.0] - 2026-09-04

First public release.

### Added

- **Enforcement.** Every byte leaving the machine crosses one of two points
  inside Burp's JVM: the send path and the proxy request handler. Scope, an
  HTTP method allowlist, a dangerous-path denylist, a token-bucket rate limit,
  request and time budgets, and a halt sentinel are all decided there and are
  not reachable from Python. DENY-ALL is terminal.
- **Engagement store.** SQLite, created `0o700` with its database and blobs
  `0o600`. Scope is versioned and append-only; runs are stamped with the scope
  version that authorised them. A database trigger prevents the agent from ever
  writing a finding status of `confirmed` or `reported` — only a person does
  that. `hx amend` is the one sanctioned way to change a config the integrity
  guard has already recorded.
- **Traffic capture.** A proxy that attributes each request to the operator or
  to the agent by the listener it arrived on, so browsing through it is exempt
  from the agent's limits without either side being able to claim the other's.
- **Ten checks**, six of them active. False-positive rate for the SQL
  behavioural check is measured, not asserted: 18 true positives and 0 false
  positives over the reachable subset of OWASP Benchmark 1.2. The method is
  written down in `docs/DECISIONS.md`, including why only 167 of 772 cases are
  reachable by a black-box tool.
- **Crawler**, navigation backbone only. Renders with Burp's bundled Chromium
  over a CDP pipe, harvests links from the settled DOM, walks an in-scope
  frontier under explicit budgets, and accounts for every subresource that
  failed to load — classifying each page `rendered`, `degraded` or `failed`
  rather than reporting a silent partial crawl as a complete one.
- **Reporting** built on one rule: a report that cannot distinguish "tested,
  clean" from "never reached" is worse than no report. Coverage is stated per
  check, and what the crawler did not do — submit forms, click, walk
  interaction-gated routes, authenticate — is disclosed in words.
- **A tool layer** so an agent can drive all of the above, with egress-capable
  tools declared as such.
- **Redaction** ahead of hashing, so a credential cannot reach the blob store,
  the database, a log line, `agent_action`, or a rendered report.

### Known limitations

Stated here because the tool states them too:

- No out-of-band interaction server, so blind-only vulnerability classes are
  not reachable.
- The crawler submits no forms, clicks nothing, and crawls unauthenticated.
- `rate_burst` defaults to `rate_limit_rps`. A modern single-page application
  fires its whole bundle in one burst; at a low rate limit the rest are denied,
  and the browser refuses the denial as a script. The crawl reports `degraded`
  rather than lying about it, but an operator pointing hx at an SPA should set
  `rate_burst` at engagement creation. See the user guide.
- False-positive rate is measured for one check against one corpus.
- `hx` bundles no Burp Suite and never will; you supply your own.

[Unreleased]: https://github.com/ubercylon8/hx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ubercylon8/hx/releases/tag/v0.1.0
