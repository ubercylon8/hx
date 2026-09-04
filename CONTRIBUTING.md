# Contributing

## Getting set up

```bash
uv sync
MONTOYA_JAR=/path/to/montoya-api.jar ./extension/build.sh
```

The Montoya API jar comes from [Maven
Central](https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api).
Burp Suite itself you supply yourself; it is never committed here, and CI fails if a jar
appears in the tree.

## The three suites

```bash
uv run pytest                  # unit — fast, no Burp, runs in CI
uv run pytest -m integration   # launches a REAL headless Burp (~5 min)
./extension/test.sh            # the Java suite (needs MONTOYA_JAR)
uv run ruff check .            # lint — blocking in CI
uv run mypy                    # advisory for now; see pyproject.toml
./scripts/ci/check-identifiers.sh   # no real infrastructure in tracked files
```

CI runs the unit, Java, and lint gates. **It cannot run the integration suite** — that
needs a real Burp, which is not redistributable — so a green build does not mean the
integration tests passed. Run them locally before proposing a change that touches the
bridge, the session, or a check.

## House rules

**No real infrastructure in tracked files.** No target hostnames, client domains, IP
addresses or absolute home paths — in fixtures, docs, comments or logs. This is a blocking
gate, not a preference: a CGNAT address of the machine `hx` was written on reached 447 of
609 commits as an "example of a non-loopback address" before anyone noticed, and publishing
the repository would have published it. `scripts/ci/check-identifiers.sh` runs on every PR.
Use `app.example.test`, `203.0.113.10`, `100.64.0.x`, `fd00::/8`.

**Everything is loopback.** No test in this repository has ever sent a request off the
machine. The target-server fixture refuses any address outside `127.0.0.0/8`, and that
refusal is load-bearing, not tidy — it is the only thing between a payload and somebody
else's server.

**Never run Burp against your real `$HOME`.** The fixture builds a private Burp home per
run. A test that reads your own Burp profile will pick up real client project state.

**Comments are held to the same standard as code.** A comment asserting behaviour the code
does not have is treated as a defect, not a nitpick — twelve were caught by measurement
during the active-checks work. Two habits to avoid: justifying a design by describing the
code *around* it (the next commit makes it false), and making a countable claim ("exactly
one case escapes") where naming the class would survive.

**Measure, don't assert from memory.** If a comment or a test docstring gives a number,
that number should have been observed. Several that "looked right" were not.

**Safety changes need a test that fails without them.** Anything touching scope, the gates,
redaction, or the halt path needs a negative control — and check the control actually
controls. One in this repo's own history passed while proving nothing, because the decoy it
used was refused by `.gitignore` before the check ever saw it.

## Specs and plans

`docs/superpowers/` holds design specs and implementation plans. Plans quote the source
they specify and `tests/test_plan_matches_repo.py` fails on drift; use
`scripts/sync_plan_block.py` when the code legitimately moves. It requires you to supply
the line range for an excerpt on purpose — a sync that guesses its own region is how a plan
comes to describe code nobody wrote.

A **merged** plan is history and is not re-synced to match code a later plan rewrote.
Corrections go to the spec, as dated amendments with the original text left standing.

## Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

See [`docs/DECISIONS.md`](docs/DECISIONS.md) before proposing a change to the safety model
or the reporting rules — most of it is there because something went wrong first.
