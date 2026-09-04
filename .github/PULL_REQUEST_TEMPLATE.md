## What changed and why

<!-- Short description. Link an issue if there is one. -->

## How this was verified

<!-- Which of these did you run, and what did they show? CI cannot run the
     integration suite -- it needs a real Burp, which is not redistributable --
     so a green build does not mean it passed. -->

- [ ] `uv run pytest` (unit)
- [ ] `uv run pytest -m integration` (real headless Burp; required if this
      touches the bridge, the session, or a check)
- [ ] `./extension/test.sh` (if `extension/` changed)
- [ ] `uv run ruff check .`
- [ ] `./scripts/ci/check-identifiers.sh`

## Invariant checklist

<!-- See docs/DECISIONS.md -- most of these are here because something went
     wrong first. Delete the lines that genuinely do not apply. -->

- [ ] Every request still crosses one of the two enforcement points inside the
      JVM. Nothing new originates traffic from Python.
- [ ] No test sends a request outside `127.0.0.0/8`.
- [ ] Redaction still runs before hashing; no credential can reach the blob
      store, the database, a log line, or a rendered report.
- [ ] A safety change (scope, gates, redaction, halt) ships with a test that
      fails without it -- and the control was checked to actually control.
- [ ] Any test asserting a security property names its mutation in its own
      docstring, and that mutation was run.
- [ ] Coverage claims still distinguish "tested, clean" from "never reached".
- [ ] No real domains, hostnames, or IP addresses added (fixtures, docs,
      comments, logs).
