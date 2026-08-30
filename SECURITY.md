# Security

## Reporting a vulnerability in hx

Email **james@fortika.io**. Please do not open a public issue.

Include what you did, what happened, and what you expected. If you have a proof of concept,
a failing test against a loopback target is the most useful form — every test in this
repository targets `127.0.0.0/8` and the fixture refuses anything else.

## What counts as a vulnerability here

`hx` is a tool that sends crafted HTTP requests at systems belonging to somebody else. Its
security properties are therefore mostly about **restraint**. Anything that lets it send
what it should not, or store what it should not, matters more than a crash:

- **Escaping the enforcement point.** Any way to originate a request that does not cross
  the send path or the proxy request handler inside Burp's JVM (see
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)).
- **Widening scope from Python.** The Python side is supposed to be unable to. Any path by
  which it can is a real finding.
- **Defeating a gate** — scope, method allowlist, dangerous-path denylist, rate limit,
  budget, or the halt sentinel. A halt that can be revived is a vulnerability.
- **Storing a credential.** Redaction runs before hashing; a credential reaching the blob
  store or the database is a finding, including via a path nobody anticipated.
- **Traffic attributed to the wrong side.** The operator/agent split is what exempts a
  browser from the agent's limits. Anything in the *traffic* that can move a request across
  that boundary defeats it.
- **A report that misleads.** A finding rendered as fixed when it is live, or coverage
  claimed for a check that never ran, is a security bug in a tool whose output a client
  acts on.

## What is out of scope

- Findings that require an operator to deliberately misconfigure their own engagement. The
  config is meant to make blast radius explicit, not to be unforgeable against its owner.
- Burp Suite itself. Report those to PortSwigger.
- The absence of features that are documented as absent — see the limitations in the
  [README](README.md).

## Handling of client data

An engagement directory is created `0o700` and its database and blobs `0o600`. Neither is
widened at any point. Captured traffic never leaves the machine, and `hx` has no telemetry,
no update check, and no network destination other than the target in scope.
