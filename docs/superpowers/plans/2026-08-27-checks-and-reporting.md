# Checks and Reporting Implementation Plan

<!-- plan-drift: pending -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A consultant browses the target through Burp, runs `hx scan`, and gets a Markdown report whose coverage section honestly distinguishes *tested, clean* from *never reached*.

**Architecture:** Six new units on top of the completed capture engine. Checks are pure: they read a surface and its exchanges and return a verdict. The runner owns everything else — it writes `check_run` rows `pending` first, computes every `dedupe_key`, upserts findings, and is the only thing that touches the database. The report is a consumer of `check_run` and `finding`, and its coverage section is what makes the whole thing honest.

**Tech Stack:** Python 3.12, `click`, SQLite, no new third-party dependencies. Tests with `.venv/bin/pytest`.

**Spec:** `docs/superpowers/specs/2026-08-27-checks-and-reporting-design.md` (approved 2026-08-27), which implements §10 and §12 of the master spec `docs/superpowers/specs/2026-08-21-hx-design.md`.

**Scope note.** The approved spec covered passive *and* `active_safe`. It also said, in its own words, that it was at the upper limit of one plan. Writing the task list confirmed it, so the active half is **Plan 6** and this plan is passive + reporting. The cut is not where the spec guessed — it put reporting in the second half — because a plan must produce working software on its own, and *checks with no report* is a weaker deliverable than *checks with a report*. Isolating the active path also isolates the risky part: budget interaction, request mutation, and the send path.

## Global Constraints

- **A check may return only `clean`, `finding` or `inconclusive`.** `pending`, `skipped` and `error` are the runner's words. A check that could not run returns `inconclusive(reason)` — **never `clean`** (§10).
- **`check_run` rows are written `pending` before the check runs and updated after.** A scan killed mid-flight leaves rows saying *started, never finished*, never no rows at all.
- **A check may not:** build a request, write a database row, compute a `dedupe_key`, learn its own `check_run` id, or reach the bridge.
- **`dedupe_key` is one canonical NOT NULL TEXT column**: `type|scheme|host|port|method|path_template|insertion_kind|insertion_name`, **literal `-` for absent parts, never `NULL`** — SQLite treats NULLs as distinct in a UNIQUE index, which would silently defeat the constraint (§5).
- **The agent may never write finding status `confirmed` or `reported`** — a database trigger forbids it (§5). Checks write `status='new'`, `created_by='check'`.
- **`finding_observation.observed = 0` is written only for findings whose surface was actually tested this run.** A finding whose surface was never reached gets no observation row at all.
- **Engagement directories are `0o700`; blob and database files are `0o600`.** Never looser, never widened (§3).
- **Redaction runs on export** (§12). Blobs are already redacted at capture; the renderer re-applies `records.redact_url` to anything it renders.
- **A report that cannot distinguish "tested, clean" from "never reached" is worse than no report** (§12). Every design decision below defers to this.
- **All test targets are loopback only.** Nothing in this project has ever sent a request off this machine.
- **Zero new third-party dependencies.**

## Environment

- `pytest` is at `.venv/bin/pytest`, **not** on PATH. Integration tests are deselected by default: `-m integration`.
- `find` and `grep` are shadowed by broken shell functions in the interactive profile. Use `command find` / `command grep`.
- The Java suite is `extension/test.sh`; it prints **one summary line per class** and its output contains NUL bytes, so `grep` needs `-a`. It now refuses to start when the Montoya jar is missing rather than printing zero summary lines.
- This plan touches **no Java**. `extension/test.sh` must stay at its baseline; if it moves, something is wrong.

## Baseline

Reproduce before starting any task and again when finishing it:

    java:        13 x ALL PASS / 2330 ok / 0 FAIL / rc=0
    python:      659 passed, 25 deselected
    integration: 25 passed (~165 s)

## The rules this project bought, each with a fix round

1. **Judge every suite run by its summary line and its exit code**, never `grep -c FAIL`. A run that fails to compile or collect prints no summary line at all and reads as success by failure count alone.
2. **A guard is only tested by the input that separates it from its absence.** Delete the guard; if nothing reddens, it is untested. This has fired on every task of the last two plans without exception.
3. **A comment asserting an invariant is a claim.** Many have turned out false. The sharpest instance: a comment saying a branch was unreachable, true when written, silently falsified when a later task added a caller. Prefer a check that counts callers over prose that names them.
4. **A vocabulary that exists in two places must be compared in one**, derived from the authority rather than restated. `tests/test_vocabularies_match_the_schema.py` enforces this and will demand a pairing for any new constant.
5. **Back up by file copy, restore by copy, verify `sha256sum`, purge `__pycache__`.** Never `git checkout --`: it restores to HEAD, not to your pre-edit state.
6. **Sync plan blocks only with `scripts/sync_plan_block.py`**, passing an explicit allowlist. Several files here carry blocks in merged plans.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/hx/checks/__init__.py` | package marker; re-exports the public types |
| `src/hx/checks/base.py` | `Verdict`, `Candidate`, `Insertion`, `CheckContext`, the `Check` protocol |
| `src/hx/checks/registry.py` | the explicit `CHECKS` tuple and its validation |
| `src/hx/checks/passive/cookie_flags.py` | `Set-Cookie` missing `Secure` / `HttpOnly` / `SameSite` |
| `src/hx/checks/passive/security_headers.py` | missing `HSTS`, `X-Content-Type-Options`, `X-Frame-Options`/CSP frame-ancestors |
| `src/hx/checks/passive/secret_in_response.py` | credential-shaped material in a response body |
| `src/hx/checks/passive/stack_trace.py` | framework stack traces and error dumps |
| `src/hx/insertion.py` | derive insertion points from a surface's exemplar exchange |
| `src/hx/scan.py` | the runner: iterate, dispatch, record `check_run`, upsert findings |
| `src/hx/report.py` | `render()` → one Markdown file |
| `src/hx/store/records.py` | **modified**: `dedupe_key`, `upsert_finding`, `record_observation`, `record_evidence` |
| `src/hx/cli.py` | **modified**: `hx scan`, `hx report` |

Checks live in their own files because §10 calls the corpus "the cheapest thing in the system to change", and one file per check is what makes adding one a local act.

---

## Task 1: The types a check speaks in

`Verdict` is deliberately narrower than the `check_run.verdict` column. That gap is the task's whole point: a check must not be able to claim it was skipped, and must not be able to report `clean` when it could not run.

**Files:**
- Create: `src/hx/checks/__init__.py`, `src/hx/checks/base.py`
- Test: `tests/test_checks_base.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Verdict.clean()`, `Verdict.finding(*candidates)`, `Verdict.inconclusive(reason)`; `Verdict.state` in `{"clean","finding","inconclusive"}`; `Verdict.candidates: tuple[Candidate, ...]`; `Verdict.reason: str | None`. `Candidate(title, severity, confidence, insertion, exchange_ids, description=None, impact=None, remediation=None, cwe=None, scope_level="surface", payload=None)`. `Insertion(kind, name)`. `CheckContext(config, blobs, run_id, log)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_checks_base.py
"""What a check is allowed to say, and what it is not.

`check_run.verdict` carries six values; a check may return three. The other
three -- `pending`, `skipped`, `error` -- are the RUNNER's words, because a
check that can call itself skipped can hide the fact that it never ran, and
that is the failure S12 says is worse than no report at all.
"""
import pytest

from hx.checks import base


def test_a_clean_verdict_carries_no_candidates_and_no_reason():
    v = base.Verdict.clean()
    assert v.state == "clean"
    assert v.candidates == ()
    assert v.reason is None


def test_inconclusive_requires_a_reason():
    """S10: a check that cannot run returns inconclusive(reason), never clean.

    A reason-less inconclusive is the same failure one step removed: the
    report would say "could not test" without saying why, and the operator
    cannot act on it.
    """
    with pytest.raises(ValueError, match="reason"):
        base.Verdict.inconclusive("")


def test_a_finding_verdict_needs_at_least_one_candidate():
    """`finding` with nothing in it is a row claiming a finding that has no
    evidence, no title and no dedupe key. It is refused here rather than
    discovered when the upsert fails."""
    with pytest.raises(ValueError, match="candidate"):
        base.Verdict.finding()


def test_a_check_cannot_express_skipped_or_error_or_pending():
    """The separating test for this whole module. If any of these three ever
    becomes constructible, the runner's exclusive right to say them is gone
    and nothing else in the system would notice."""
    for word in ("skipped", "error", "pending"):
        assert not hasattr(base.Verdict, word)


def test_candidate_defaults_to_surface_scope():
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    assert c.scope_level == "surface"


def test_candidate_refuses_a_severity_the_schema_will_not_take():
    """The schema's CHECK is Critical|High|Medium|Low|Info. Refusing here
    names the value; SQLite would answer `CHECK constraint failed: finding`."""
    with pytest.raises(ValueError, match="severity"):
        base.Candidate(title="t", severity="Catastrophic", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))


def test_candidate_requires_evidence():
    """A finding with no exchange behind it cannot have an evidence chain, and
    S12's report renders one per finding."""
    with pytest.raises(ValueError, match="exchange"):
        base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=())
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_checks_base.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'hx.checks'`.

- [ ] **Step 3: Write the implementation**

```python
# src/hx/checks/base.py
"""The types a check speaks in, and the ones it deliberately cannot.

A check is pure. It reads a surface and the exchanges captured against it and
returns a verdict. It does not build requests, write rows, compute dedupe
keys, learn its own `check_run` id, or reach the bridge -- each of those
belongs to the runner, and each is a place where ONE implementation must serve
every check or the guarantees stop being uniform.

THE VERDICT VOCABULARY IS NARROWER THAN THE COLUMN, ON PURPOSE.
`check_run.verdict` carries six values. A check may return three. `pending`,
`skipped` and `error` are the runner's, because:

  * a check that can say `skipped` can hide that it never ran;
  * a check that can say `error` can swallow its own crash;
  * `pending` is written BEFORE the check is called, so no check has ever been
    in a position to say it.

S12: a report that cannot distinguish "tested, clean" from "never reached" is
worse than no report. Every one of those three words is the second half of
that distinction, and none of them is a check's to give.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

# The schema's own vocabularies, restated NOWHERE ELSE in this package. The
# pairing against schema.sql lives in tests/test_vocabularies_match_the_schema.py.
SEVERITIES = frozenset({"Critical", "High", "Medium", "Low", "Info"})
CONFIDENCES = frozenset({"Certain", "Firm", "Tentative"})
SCOPE_LEVELS = frozenset({"engagement", "host", "surface", "insertion"})

# S4 of the design doc. `body_form` and `body_json` are DERIVED AND RECORDED
# but never probed in this plan or the next: the production profile's method
# allowlist is GET/HEAD/OPTIONS, so an active_safe check can only re-issue a
# GET and no payload can reach a body. Recording them anyway is what lets the
# coverage section say "this parameter exists and was not probed".
INSERTION_KINDS = frozenset({
    "query", "path_segment", "header", "cookie", "body_form", "body_json",
})


@dataclass(frozen=True)
class Insertion:
    """One place a payload could go, derived from an exemplar exchange.

    `name` is the parameter, header or cookie name; for `path_segment` it is
    the template placeholder the normaliser produced, e.g. `{id}`.
    """
    kind: str
    name: str

    def __post_init__(self) -> None:
        if self.kind not in INSERTION_KINDS:
            raise ValueError(
                f"unknown insertion kind {self.kind!r}; this version knows "
                f"{sorted(INSERTION_KINDS)}")
        if not self.name:
            raise ValueError("an insertion point must have a name")


@dataclass(frozen=True)
class Candidate:
    """A finding a check believes in, before the runner gives it identity.

    The check does NOT compute the dedupe key. That is one canonical string
    (S5) and one place must build it, or two checks will spell the same
    finding two ways and the UNIQUE constraint will hold two rows.
    """
    title: str
    severity: str
    confidence: str
    insertion: Insertion | None
    exchange_ids: tuple[str, ...]
    description: str | None = None
    impact: str | None = None
    remediation: str | None = None
    cwe: str | None = None
    scope_level: str = "surface"
    payload: str | None = None

    def __post_init__(self) -> None:
        if not self.title:
            raise ValueError("a candidate must have a title")
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"unknown severity {self.severity!r}; the schema takes "
                f"{sorted(SEVERITIES)}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(
                f"unknown confidence {self.confidence!r}; the schema takes "
                f"{sorted(CONFIDENCES)}")
        if self.scope_level not in SCOPE_LEVELS:
            raise ValueError(
                f"unknown scope_level {self.scope_level!r}; the schema takes "
                f"{sorted(SCOPE_LEVELS)}")
        if not self.exchange_ids:
            # S12 renders an evidence chain per finding. A candidate with no
            # exchange behind it has nothing to chain, and the operator would
            # be asked to believe a claim with no way to check it.
            raise ValueError("a candidate must name at least one exchange")


@dataclass(frozen=True)
class Verdict:
    """What a check returns. Constructed only through the three classmethods.

    There is deliberately no `Verdict(state=...)` in the public surface: the
    constructor is reachable, but every call site in this repository uses a
    named constructor, and `test_a_check_cannot_express_skipped_or_error_or_pending`
    is what stops a fourth appearing.
    """
    state: str
    candidates: tuple[Candidate, ...] = ()
    reason: str | None = None

    @classmethod
    def clean(cls) -> "Verdict":
        return cls("clean")

    @classmethod
    def finding(cls, *candidates: Candidate) -> "Verdict":
        if not candidates:
            raise ValueError(
                "a finding verdict needs at least one candidate; an empty one "
                "is a row claiming a finding with no title and no evidence")
        return cls("finding", tuple(candidates))

    @classmethod
    def inconclusive(cls, reason: str) -> "Verdict":
        if not reason:
            raise ValueError(
                "inconclusive requires a reason: S10 says a check that cannot "
                "run says so, and a reason-less one tells the operator "
                "nothing they can act on")
        return cls("inconclusive", (), reason)


@dataclass(frozen=True)
class CheckContext:
    """What a check is given besides its subject.

    NO DATABASE CONNECTION, deliberately. A check that can write is a check
    that can write the wrong thing -- the wrong run id, a status the trigger
    forbids, a dedupe key spelled its own way. Everything a check produces
    goes back through its return value.
    """
    config: object          # hx.config.Config
    blobs: object           # hx.store.blobs.BlobStore
    run_id: str
    log: object             # a callable taking one str


class Check(Protocol):
    """The shape the registry validates and the runner calls.

    `klass` decides which hooks are legal. A `passive` check implementing
    `probes` is a registry error rather than a runtime surprise; see
    `hx.checks.registry`.
    """
    id: str
    version: str
    klass: str
    insertion_kinds: frozenset[str]
```

```python
# src/hx/checks/__init__.py
"""The check corpus: S10's extensibility surface.

One file per check, an explicit registry, and a base module whose whole job is
to make a check unable to say things only the runner may say.
"""
from hx.checks.base import (      # noqa: F401
    Candidate, Check, CheckContext, Insertion, Verdict,
    CONFIDENCES, INSERTION_KINDS, SCOPE_LEVELS, SEVERITIES,
)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_checks_base.py -q`
Expected: `7 passed`.

- [ ] **Step 5: Pair the new vocabularies against the schema**

`tests/test_vocabularies_match_the_schema.py` enumerates every module-level string-set constant and requires each to be paired against its schema CHECK or named as deliberately unpaired. Four new ones just appeared. Add to that file:

```python
def test_check_severities_match_the_schema():
    assert set(base_mod.SEVERITIES) == _checks()["finding.severity"]


def test_check_confidences_match_the_schema():
    assert set(base_mod.CONFIDENCES) == _checks()["finding.confidence"]


def test_check_scope_levels_match_the_schema():
    assert set(base_mod.SCOPE_LEVELS) == _checks()["finding.scope_level"]
```

`INSERTION_KINDS` has no CHECK to pair against — `check_run.insertion_name` and `finding.insertion_kind` are free TEXT. Add it to `unpaired_with_reason` with that reason and the condition from the spec's open question 1: constrain it when a second consumer appears. Add `hx.checks.base` to the modules the enumeration scans, and assert one of its constants is found, the way the file already does for `hx.capture.DISCOVERED_BY` — a scan whose reach is not asserted is a scan that can be narrowed by accident.

- [ ] **Step 6: Run the whole suite and commit**

```bash
.venv/bin/pytest -q
git add src/hx/checks tests/test_checks_base.py tests/test_vocabularies_match_the_schema.py
git commit -m "feat(checks): the vocabulary a check speaks in, and the three words it may not say"
```

---

## Task 2: The registry, and what it refuses

§10 wants checks cheap to add. One line in a list is cheap. Discovery is cheaper still and is refused: `extension/test.sh` already records why — *"a class nobody lists is a file that compiles, never runs, and reads in review exactly like a test that passes."* For a security tool that failure renders as **tested, clean**.

**Files:**
- Create: `src/hx/checks/registry.py`, `src/hx/checks/passive/__init__.py` (a bare docstring; Task 4 replaces its contents)
- Test: `tests/test_checks_registry.py`

**Pre-flight ruling F2.** The registry imports `hx.checks.passive.*`, so the
package must exist before this task's own tests can even import. Task 4 was
where `__init__.py` appeared; it is created here instead, empty but for a
docstring, and Task 4 overwrites it.

**Interfaces:**
- Consumes: `hx.checks.base.Check`.
- Produces: `registry.CHECKS: tuple[Check, ...]`, `registry.enabled(config) -> tuple[Check, ...]`, `registry.validate(checks) -> None` (raises `RegistryError`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_checks_registry.py
"""The registry is a list somebody maintains, and this is what it refuses.

Discovery was rejected for this corpus. The argument is in extension/test.sh
and it transfers exactly: a check nobody lists is a file that imports, never
runs, and renders in a report as `tested, clean`.
"""
import pytest

from hx.checks import base, registry


class _Passive:
    id, version, klass = "t.passive", "1", "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.clean()


class _PassiveThatProbes(_Passive):
    id = "t.passive-that-probes"

    def probes(self, ctx, surface, insertion):
        return ()


class _NoHooks:
    id, version, klass = "t.no-hooks", "1", "passive"
    insertion_kinds = frozenset()


def test_a_passive_check_implementing_probes_is_refused():
    """The separating case. `probes` is the active hook; a passive check
    carrying one either lies about its class or has a hook nothing will call,
    and both are worth failing at import rather than at scan time."""
    with pytest.raises(registry.RegistryError, match="probes"):
        registry.validate((_PassiveThatProbes(),))


def test_a_check_with_no_hook_at_all_is_refused():
    """It would produce `check_run` rows forever and never a verdict."""
    with pytest.raises(registry.RegistryError, match="no hook"):
        registry.validate((_NoHooks(),))


def test_duplicate_ids_are_refused():
    """`check_run.check_id` is how coverage is attributed. Two checks sharing
    an id make the coverage section unreadable and the retest wrong."""
    with pytest.raises(registry.RegistryError, match="duplicate"):
        registry.validate((_Passive(), _Passive()))


def test_an_unknown_class_is_refused():
    class _Weird(_Passive):
        id, klass = "t.weird", "active_telepathy"
    with pytest.raises(registry.RegistryError, match="active_telepathy"):
        registry.validate((_Weird(),))


def test_the_shipped_registry_validates():
    """Anti-vacuity, and the reason this file is not just unit tests of a
    validator: the real CHECKS tuple must pass its own rules."""
    registry.validate(registry.CHECKS)
    assert len(registry.CHECKS) >= 1


def test_enabled_reads_the_engagement_config():
    """config.DEFAULT_CHECKS already carries S10's five class names. A class
    switched off there must not run, and `enabled` is the one place that is
    decided."""
    from hx import config as config_mod
    cfg = config_mod.Config(name="t", client="t", scope_include=["https://a/*"])
    cfg.checks["passive"] = False
    assert all(c.klass != "passive" for c in registry.enabled(cfg))


def test_every_shipped_check_id_is_namespaced():
    """`hx.` prefixes ours. A per-engagement corpus is a later, additive
    change, and the prefix is what will keep the two apart without a rename."""
    for check in registry.CHECKS:
        assert check.id.startswith("hx."), check.id
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_checks_registry.py -q`
Expected: `ModuleNotFoundError: No module named 'hx.checks.registry'`.

- [ ] **Step 3: Write the implementation**

```python
# src/hx/checks/registry.py
"""The explicit list, and the rules every entry must satisfy.

ADD A NEW CHECK HERE, on its own line, and nowhere else. There is no
discovery, deliberately, and the argument is not stylistic -- it is the same
one extension/test.sh makes about its own hand-rolled runner: a class nobody
lists is a file that imports, never runs, and reads in review exactly like a
check that passed. In a report that renders as `tested, clean`, which is the
one thing S12 says a report must never do.

`validate` runs at import. A malformed entry is a crash on `import hx.scan`,
loudly, rather than a check that quietly contributes nothing to a scan an
operator has already billed for.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.passive import cookie_flags, secret_in_response
from hx.checks.passive import security_headers, stack_trace

# S10's five class names. `config.DEFAULT_CHECKS` carries the same five and is
# the authority for which are ENABLED; this set is which are IMPLEMENTABLE.
# They are separate questions: `active_timing` is enabled by default in the
# config and has no checks in it, which the scan summary must say out loud
# rather than imply the class ran.
KNOWN_CLASSES = frozenset({
    "passive", "active_safe", "active_timing", "active_mutate", "active_dos",
})

# Which hooks each class may implement. A class may implement none of the
# others: the pairing is what turns "this check lies about its class" from a
# runtime surprise into an import error.
_HOOKS = {
    "passive": ("on_surface", "on_corpus"),
    "active_safe": ("probes", "on_corpus"),
    "active_timing": ("probes", "on_corpus"),
    "active_mutate": ("probes", "on_corpus"),
    "active_dos": ("probes", "on_corpus"),
}
_ALL_HOOKS = ("on_surface", "probes", "on_corpus")


class RegistryError(Exception):
    """An entry in CHECKS that cannot be run as declared."""


def validate(checks) -> None:
    seen: set[str] = set()
    for check in checks:
        if check.klass not in KNOWN_CLASSES:
            raise RegistryError(
                f"{check.id}: unknown class {check.klass!r}; this version "
                f"knows {sorted(KNOWN_CLASSES)}")
        if check.id in seen:
            raise RegistryError(
                f"duplicate check id {check.id!r}. check_run.check_id is how "
                "coverage is attributed, so two checks sharing one make the "
                "coverage section unreadable and a retest wrong")
        seen.add(check.id)

        allowed = _HOOKS[check.klass]
        implemented = [h for h in _ALL_HOOKS if callable(getattr(check, h, None))]
        if not implemented:
            raise RegistryError(
                f"{check.id}: no hook. It would produce a check_run row for "
                "every surface and never a verdict")
        for hook in implemented:
            if hook not in allowed:
                raise RegistryError(
                    f"{check.id}: class {check.klass!r} may not implement "
                    f"{hook!r}. Either the class is wrong or the hook is "
                    "one nothing will ever call")


CHECKS: tuple[base.Check, ...] = (
    cookie_flags.CookieFlags(),
    security_headers.SecurityHeaders(),
    secret_in_response.SecretInResponse(),
    stack_trace.StackTrace(),
)

validate(CHECKS)


def enabled(config) -> tuple[base.Check, ...]:
    """The checks this engagement has switched on.

    `config.checks` is `DEFAULT_CHECKS` overlaid with the engagement's own
    file, and `config.load` already refuses a key outside that vocabulary --
    so an unknown class cannot reach here.
    """
    return tuple(c for c in CHECKS if config.checks.get(c.klass, False))
```

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/pytest tests/test_checks_registry.py -q`
Expected: FAIL — the four passive check modules do not exist yet. **This is the one task in this plan whose tests do not go green on their own**; Task 4 writes those modules. Confirm the failure is `ModuleNotFoundError` naming `hx.checks.passive`, and nothing else, then move on.

Because a plan that leaves a red suite between tasks violates rule 1, land Task 2 and Task 4 **in that order without an intervening commit of the whole suite**, or write the four check modules as one-line stubs here and fill them in Task 4. **Prefer the stubs**: a red suite between commits is a state where nobody can tell a new failure from the expected one.

Stub form, one per file, replaced wholesale in Task 4:

```python
# src/hx/checks/passive/cookie_flags.py
from hx.checks import base


class CookieFlags:
    id, version, klass = "hx.passive.cookie-flags", "1", "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.inconclusive("not implemented yet")
```

- [ ] **Step 5: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/checks tests/test_checks_registry.py
git commit -m "feat(checks): an explicit registry, and the four things it refuses"
```

---

## Task 3: Insertion points, derived from the exemplar

§5: insertion points are **derived, not stored** — there is no `insertion` table in v1. The master spec calls the derivation source `surface.detail`; **there is no such column**, and this task derives from `surface.exemplar_exchange_id` → that exchange's request blob.

**Files:**
- Create: `src/hx/insertion.py`
- Test: `tests/test_insertion.py`

**Interfaces:**
- Consumes: `hx.checks.base.Insertion`, `hx.store.blobs.BlobStore.get`.
- Produces: `insertion.derive(request_bytes, path_template) -> tuple[Insertion, ...]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_insertion.py
"""Where a payload could go, read off one captured request.

S5: derived, not stored. The derivation is pure -- bytes in, insertion points
out -- so it is testable without a database, a surface row or a Burp.
"""
from hx import insertion
from hx.checks.base import Insertion

REQ = (
    b"POST /api/orders/1001?page=2&sort=asc HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"Cookie: session=abc; theme=dark\r\n"
    b"X-Request-Id: r-9\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"\r\n"
    b"note=hello&qty=3"
)


def test_query_parameters_are_derived_by_name():
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("query", "page") in got
    assert Insertion("query", "sort") in got


def test_path_placeholders_are_derived_from_the_template():
    """The NORMALISER decided `{id}`, and the template is the authority. A
    derivation that re-guessed which segment was variable would disagree with
    the surface the finding is attributed to."""
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("path_segment", "{id}") in got


def test_cookies_are_derived_individually():
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("cookie", "session") in got
    assert Insertion("cookie", "theme") in got


def test_headers_are_derived_but_hop_by_hop_and_fixed_ones_are_not():
    """`Host` and `Content-Type` are not insertion points in any useful sense
    and probing them produces noise, not findings. `Cookie` is excluded here
    because it is derived as individual cookies above -- deriving it twice
    would double-count the coverage denominator."""
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("header", "X-Request-Id") in got
    for excluded in ("Host", "Content-Type", "Cookie", "Content-Length"):
        assert Insertion("header", excluded) not in got


def test_form_body_members_are_derived():
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("body_form", "note") in got
    assert Insertion("body_form", "qty") in got


def test_json_body_members_are_derived_by_dotted_path():
    req = (b"POST /api/orders HTTP/1.1\r\nHost: app.test\r\n"
           b"Content-Type: application/json\r\n\r\n"
           b'{"customer": {"id": 7}, "items": [1, 2]}')
    got = insertion.derive(req, "/api/orders")
    assert Insertion("body_json", "customer.id") in got
    assert Insertion("body_json", "items") in got


def test_body_kinds_are_derived_but_are_not_probeable_here():
    """S4 of the design doc, pinned. The production method allowlist is
    GET/HEAD/OPTIONS, so no payload can reach a body -- but the parameter is
    RECORDED so the coverage section can say `exists, not probed`.

    This asserts the first half. The second half -- that nothing probes them --
    is Plan 6's to hold, and this test names it so the pairing is not lost.
    """
    got = insertion.derive(REQ, "/api/orders/{id}")
    body = {i for i in got if i.kind in ("body_form", "body_json")}
    assert body, "body insertion points must be derived even though unprobeable"


def test_a_request_with_no_head_terminator_yields_nothing_rather_than_throwing():
    """Malformed captures exist. A derivation that raises would take a scan
    down over one bad row."""
    assert insertion.derive(b"GET / HTTP/1.1\r\nHost: a", "/") == ()


def test_derivation_is_deterministic_and_ordered():
    """Two runs over one request must produce the same tuple in the same
    order, or `check_run` rows for one surface differ between scans and the
    retest diff fills with noise."""
    a = insertion.derive(REQ, "/api/orders/{id}")
    b = insertion.derive(REQ, "/api/orders/{id}")
    assert a == b
    assert list(a) == sorted(a, key=lambda i: (i.kind, i.name))
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_insertion.py -q`
Expected: `ModuleNotFoundError: No module named 'hx.insertion'`.

- [ ] **Step 3: Write the implementation**

```python
# src/hx/insertion.py
"""Insertion points, derived from one captured request.

S5 is explicit that these are DERIVED, NOT STORED -- there is no `insertion`
table in v1, and `insertion_name` / `insertion_kind` live as columns on
`check_run` and `finding` where they are needed for identity.

THE DERIVATION SOURCE. The master spec calls it `surface.detail`. THERE IS NO
SUCH COLUMN -- grepped, 2026-08-27 -- so the real path is
`surface.exemplar_exchange_id` -> that exchange's `req_blob` -> these bytes.
Naming it here rather than inheriting a reference to something that does not
exist is the point of this paragraph.

PURE, AND THAT IS DELIBERATE: bytes in, insertion points out. No database, no
blob store, no Burp. The runner does the fetching; this decides what is in
there.

WHAT IS NOT AN INSERTION POINT, and why each exclusion is a decision rather
than an oversight:

  * `Host` -- changing it changes which server answers, which is a scope
    question and not a payload;
  * `Content-Length` and `Content-Type` -- structural; a payload there breaks
    the request rather than testing the application;
  * `Cookie` as a single header -- individual cookies are derived instead, and
    deriving both would double the coverage denominator for one input.

The body kinds ARE derived and are NOT probeable in this plan or Plan 6: S4's
production method allowlist is GET/HEAD/OPTIONS, so an active_safe check can
only re-issue a GET. They are recorded so the coverage section can say
`exists, not probed`, which is worth more than omitting them.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit

from hx.checks.base import Insertion

# Headers that are structural, hop-by-hop, or derived more usefully another
# way. Lower-cased for an ASCII-insensitive match, the way the redactor does.
_NOT_INSERTABLE = frozenset({
    "host", "content-length", "content-type", "cookie", "connection",
    "transfer-encoding", "upgrade", "expect", "accept-encoding",
})


def derive(request_bytes: bytes, path_template: str) -> tuple[Insertion, ...]:
    """Every place a payload could go in this request.

    Returns a tuple sorted by `(kind, name)`. The ordering is not cosmetic:
    two scans of one surface must produce the same `check_run` rows in the
    same order, or a retest diff fills with noise that is really just
    iteration order.
    """
    head, _, body = request_bytes.partition(b"\r\n\r\n")
    if not _:
        # No head terminator: a truncated or malformed capture. Nothing
        # useful can be said about it, and raising would take a whole scan
        # down over one bad row.
        return ()

    lines = head.split(b"\r\n")
    found: set[Insertion] = set()

    # --- the request line: query parameters and templated path segments ---
    parts = lines[0].split(b" ")
    if len(parts) >= 2:
        target = parts[1].decode("latin-1")
        query = urlsplit(target).query
        for name, _value in parse_qsl(query, keep_blank_values=True):
            if name:
                found.add(Insertion("query", name))

    # The TEMPLATE is the authority on which segments are variable, because
    # the normaliser already decided that and the finding is attributed to the
    # surface it produced. Re-guessing here would disagree with it.
    for segment in path_template.split("/"):
        if segment.startswith("{") and segment.endswith("}") and len(segment) > 2:
            found.add(Insertion("path_segment", segment))

    # --- headers and cookies ---
    content_type = ""
    for raw in lines[1:]:
        name, sep, value = raw.partition(b":")
        if not sep:
            continue
        key = name.decode("latin-1").strip()
        val = value.decode("latin-1").strip()
        low = key.lower()
        if low == "content-type":
            content_type = val.lower()
        if low == "cookie":
            for crumb in val.split(";"):
                cname = crumb.split("=", 1)[0].strip()
                if cname:
                    found.add(Insertion("cookie", cname))
            continue
        if low in _NOT_INSERTABLE or not key:
            continue
        found.add(Insertion("header", key))

    # --- the body ---
    if body:
        if "application/x-www-form-urlencoded" in content_type:
            for name, _value in parse_qsl(body.decode("latin-1"),
                                          keep_blank_values=True):
                if name:
                    found.add(Insertion("body_form", name))
        elif "json" in content_type:
            found.update(_json_members(body))

    return tuple(sorted(found, key=lambda i: (i.kind, i.name)))


def _json_members(body: bytes) -> set[Insertion]:
    """Every scalar-or-array member of a JSON body, by dotted path.

    A malformed body yields nothing rather than raising: the capture is
    whatever the client sent, and a scan must survive an application that
    mislabels its own content type.
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return set()

    out: set[Insertion] = set()

    def walk(node, prefix: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{prefix}.{key}" if prefix else str(key))
        elif prefix:
            # A list is one insertion point, not one per element: probing
            # `items[0]` and `items[1]` separately multiplies the budget by
            # the data's length, which is the application's choice and not a
            # measure of its attack surface.
            out.add(Insertion("body_json", prefix))

    walk(parsed, "")
    return out
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_insertion.py -q`
Expected: `9 passed`.

- [ ] **Step 5: Sweep the exclusions**

Rule 2. For each name in `_NOT_INSERTABLE`, delete it from the set and confirm `test_headers_are_derived_but_hop_by_hop_and_fixed_ones_are_not` reddens for the four it asserts. For the others — `connection`, `transfer-encoding`, `upgrade`, `expect`, `accept-encoding` — **nothing separates them**, because no test names them. Either add them to that test's exclusion list or delete them from the set. Do not leave a guard no input separates; that is the shape this project has spent five fix rounds on.

Report which you chose and the measured result.

- [ ] **Step 6: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/insertion.py tests/test_insertion.py
git commit -m "feat(insertion): where a payload could go, read off the exemplar"
```

---

## Task 4: The passive corpus

Four checks, one file each. Every one reads only what a browser already
fetched, so together they are the half of §13's corpus that needs no bridge,
no payload and no permission.

**Files:**
- Modify: `src/hx/checks/base.py` (add `ExchangeRow`), `src/hx/checks/passive/cookie_flags.py`, `.../security_headers.py`, `.../secret_in_response.py`, `.../stack_trace.py` (replace Task 2's stubs)
- Create: `src/hx/checks/passive/_http.py`, `tests/test_checks_passive.py` (`passive/__init__.py` already exists from Task 2; replace its contents)

**Interfaces:**
- Consumes: `Verdict`, `Candidate`, `CheckContext`; `ctx.blobs.get(digest)`.
- Produces: `ExchangeRow(id, method, url, status, req_blob, resp_blob)` — the shape the runner hands every check, defined here because this is its first consumer. `CookieFlags`, `SecurityHeaders`, `SecretInResponse`, `StackTrace`.

- [ ] **Step 1: Add the row type checks are given**

```python
# append to src/hx/checks/base.py

@dataclass(frozen=True)
class ExchangeRow:
    """One captured exchange, as a check sees it.

    Blob DIGESTS, not bytes. A surface with two hundred exchanges would
    otherwise pull two hundred response bodies into memory before any check
    decided it wanted one, and most checks want a handful. `ctx.blobs.get`
    is the fetch, and it is the check's decision when to call it.
    """
    id: str
    method: str
    url: str
    status: int | None
    req_blob: str | None
    resp_blob: str | None
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_checks_passive.py
"""The four checks that read only what a browser already fetched.

Each test drives the real check with a fixture exchange and a fake blob store.
Rule 2 applies to a check as much as to a guard: a check with no input that
separates `finding` from `clean` is not done, so every check here has both.
"""
import pytest

from hx.checks import base
from hx.checks.passive import (cookie_flags, secret_in_response,
                               security_headers, stack_trace)


class FakeBlobs:
    def __init__(self, **blobs): self._b = blobs
    def get(self, digest, expected_len=None): return self._b[digest]


def ctx_for(**blobs):
    return base.CheckContext(config=None, blobs=FakeBlobs(**blobs),
                             run_id="r-1", log=lambda s: None)


def rows(resp_blob="d1", url="https://app.test/x", status=200):
    return (base.ExchangeRow(id="x-1", method="GET", url=url, status=status,
                             req_blob=None, resp_blob=resp_blob),)


def resp(*headers, body=b""):
    head = b"HTTP/1.1 200 OK\r\n" + b"".join(h + b"\r\n" for h in headers)
    return head + b"\r\n" + body


# ---- cookie flags -----------------------------------------------------

def test_a_cookie_missing_httponly_and_secure_is_a_finding():
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: session=abc; Path=/")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert v.state == "finding"
    assert "session" in v.candidates[0].title
    assert v.candidates[0].insertion is None      # S5: cookie findings have none


def test_a_cookie_with_every_flag_is_clean():
    """The separating case. Without it the check could return `finding`
    unconditionally and every test above would still pass."""
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


def test_secure_is_not_demanded_over_plain_http():
    """A `Secure` cookie on an http:// origin is not sent at all. Demanding it
    on a target that has no TLS is a finding the client cannot act on and a
    false positive in every report that carries it."""
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: session=abc; HttpOnly; SameSite=Lax")
    v = c.on_surface(ctx_for(d1=blob), None, rows(url="http://app.test/x"))
    assert v.state == "clean"


def test_a_surface_with_no_set_cookie_is_clean_not_inconclusive():
    """`clean` means tested and nothing found; `inconclusive` means could not
    test. A page that simply sets no cookie WAS tested."""
    c = cookie_flags.CookieFlags()
    assert c.on_surface(ctx_for(d1=resp()), None, rows()).state == "clean"


def test_an_unreadable_blob_is_inconclusive_with_a_reason():
    """S10: never `clean` when the check could not run."""
    c = cookie_flags.CookieFlags()
    v = c.on_surface(ctx_for(), None, rows())      # d1 absent from the store
    assert v.state == "inconclusive"
    assert v.reason


# ---- security headers -------------------------------------------------

def test_missing_nosniff_and_frame_protection_are_findings():
    c = security_headers.SecurityHeaders()
    v = c.on_surface(ctx_for(d1=resp(b"Content-Type: text/html")), None, rows())
    assert v.state == "finding"
    titles = " ".join(x.title for x in v.candidates)
    assert "X-Content-Type-Options" in titles
    assert "frame" in titles.lower()


def test_a_fully_headed_https_response_is_clean():
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: text/html",
                b"Strict-Transport-Security: max-age=31536000",
                b"X-Content-Type-Options: nosniff",
                b"X-Frame-Options: DENY")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


def test_csp_frame_ancestors_satisfies_the_frame_check():
    """Two headers answer one question, and a check that demands the older one
    when the newer is present reports a finding the client already fixed."""
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: text/html",
                b"Strict-Transport-Security: max-age=1",
                b"X-Content-Type-Options: nosniff",
                b"Content-Security-Policy: frame-ancestors 'none'")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


def test_hsts_is_not_demanded_over_plain_http():
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: text/html", b"X-Content-Type-Options: nosniff",
                b"X-Frame-Options: DENY")
    v = c.on_surface(ctx_for(d1=blob), None, rows(url="http://app.test/x"))
    assert v.state == "clean"


def test_headers_are_not_demanded_of_a_non_document_response():
    """A JSON API response cannot be framed and will not be sniffed into a
    document. Demanding frame protection of it is noise, and noise is what
    makes a report get skimmed."""
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: application/json",
                b"X-Content-Type-Options: nosniff")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


# ---- secret in response -----------------------------------------------

def test_a_private_key_block_in_a_body_is_a_finding():
    c = secret_in_response.SecretInResponse()
    blob = resp(body=b"...\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert v.state == "finding"
    assert v.candidates[0].severity == "High"


def test_an_aws_access_key_id_is_a_finding():
    c = secret_in_response.SecretInResponse()
    v = c.on_surface(ctx_for(d1=resp(body=b'{"k":"AKIAIOSFODNN7EXAMPLE"}')),
                     None, rows())
    assert v.state == "finding"


def test_ordinary_html_is_clean():
    """The separating case, and the one that matters most for this check: a
    corpus that cries wolf on every page is one an operator stops reading."""
    c = secret_in_response.SecretInResponse()
    body = b"<html><body><h1>Welcome</h1><p>AKIA is a prefix.</p></body></html>"
    assert c.on_surface(ctx_for(d1=resp(body=body)), None, rows()).state == "clean"


def test_the_finding_does_not_repeat_the_secret_in_its_title():
    """A report is an artifact that leaves the machine (S12). A finding whose
    TITLE carries the credential re-publishes what redaction removed from the
    blob, one layer up."""
    c = secret_in_response.SecretInResponse()
    v = c.on_surface(ctx_for(d1=resp(body=b'{"k":"AKIAIOSFODNN7EXAMPLE"}')),
                     None, rows())
    assert "AKIAIOSFODNN7EXAMPLE" not in v.candidates[0].title
    assert "AKIAIOSFODNN7EXAMPLE" not in (v.candidates[0].description or "")


# ---- stack traces -----------------------------------------------------

@pytest.mark.parametrize("body", [
    b"Traceback (most recent call last):\n  File \"app.py\", line 3",
    b"java.lang.NullPointerException\n\tat com.acme.Handler.doGet(Handler.java:42)",
    b"PHP Fatal error:  Uncaught Error: Call to a member function",
])
def test_a_framework_stack_trace_is_a_finding(body):
    c = stack_trace.StackTrace()
    v = c.on_surface(ctx_for(d1=resp(body=body)), None, rows(status=500))
    assert v.state == "finding"


def test_prose_mentioning_an_exception_is_clean():
    c = stack_trace.StackTrace()
    body = b"<p>If you see a NullPointerException, contact support.</p>"
    assert c.on_surface(ctx_for(d1=resp(body=body)), None, rows()).state == "clean"
```

- [ ] **Step 3: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_checks_passive.py -q`
Expected: failures from the Task 2 stubs — every verdict is `inconclusive("not implemented yet")`.

- [ ] **Step 4: Write the four checks**

```python
# src/hx/checks/passive/__init__.py
"""Checks that read only what a browser already fetched.

`passive` in S10 means analysis only, zero extra requests, always on. These
need no bridge, no scope authorisation and no permission beyond the capture
that already happened -- which is why they run even when Burp is not up.
"""
```

```python
# src/hx/checks/passive/cookie_flags.py
"""Session cookies set without the flags that keep them out of reach.

S5 notes that cookie-flag findings have NO INSERTION POINT: the cookie is not
somewhere a payload goes, it is something the response did. `insertion` is
None and `scope_level` is `host`, because a cookie is set for a host and
fixing it fixes every surface under it -- filing one finding per surface would
hand the client the same remediation forty times.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.passive import _http

# Flags whose absence is worth a finding, and the reason each is conditional.
# `Secure` is demanded only over TLS: a Secure cookie on an http:// origin is
# never sent at all, so demanding it of a target with no TLS is a finding the
# client cannot act on.


class CookieFlags:
    id = "hx.passive.cookie-flags"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        bodies = _http.responses(ctx, exchanges)
        if bodies is None:
            return base.Verdict.inconclusive(
                "no response body could be read for this surface")

        candidates = []
        for row, head in bodies:
            https = row.url.lower().startswith("https://")
            for cookie in _http.header_values(head, "set-cookie"):
                name = cookie.split("=", 1)[0].strip()
                attrs = {a.strip().split("=", 1)[0].lower()
                         for a in cookie.split(";")[1:]}
                missing = [f for f, want in (("HttpOnly", "httponly"),
                                             ("SameSite", "samesite"),
                                             ("Secure", "secure"))
                           if want not in attrs
                           and (f != "Secure" or https)]
                if not missing:
                    continue
                candidates.append(base.Candidate(
                    title=f"Cookie {name} set without {', '.join(missing)}",
                    severity="Medium" if "HttpOnly" in missing else "Low",
                    confidence="Certain",
                    insertion=None,
                    scope_level="host",
                    exchange_ids=(row.id,),
                    cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614",
                    description=(
                        f"The response set `{name}` without "
                        f"{', '.join(missing)}."),
                    remediation=(
                        "Set the missing attributes on this cookie. HttpOnly "
                        "keeps it out of reach of scripts; SameSite limits "
                        "cross-site submission; Secure prevents it being sent "
                        "over plaintext."),
                ))
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
```

```python
# src/hx/checks/passive/security_headers.py
"""Response headers a document should carry and does not.

DEMANDED OF DOCUMENTS ONLY. A JSON API response cannot be framed and will not
be sniffed into a document, so demanding frame protection of it is noise --
and a corpus that cries wolf on every endpoint is one an operator stops
reading, which costs more than the finding was worth.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.passive import _http

_DOCUMENT_TYPES = ("text/html", "application/xhtml+xml")


class SecurityHeaders:
    id = "hx.passive.security-headers"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        bodies = _http.responses(ctx, exchanges)
        if bodies is None:
            return base.Verdict.inconclusive(
                "no response body could be read for this surface")

        candidates = []
        for row, head in bodies:
            ctype = " ".join(_http.header_values(head, "content-type")).lower()
            if not any(t in ctype for t in _DOCUMENT_TYPES):
                continue
            https = row.url.lower().startswith("https://")
            names = {n.lower() for n in _http.header_names(head)}
            csp = " ".join(_http.header_values(head, "content-security-policy"))

            missing = []
            if "x-content-type-options" not in names:
                missing.append(("X-Content-Type-Options", "CWE-16", "Low"))
            # Two headers answer the framing question. Demanding the older one
            # when the newer is present reports something already fixed.
            if "x-frame-options" not in names and "frame-ancestors" not in csp:
                missing.append(("frame protection (X-Frame-Options or CSP "
                                "frame-ancestors)", "CWE-1021", "Medium"))
            if https and "strict-transport-security" not in names:
                missing.append(("Strict-Transport-Security", "CWE-319", "Low"))

            for title, cwe, severity in missing:
                candidates.append(base.Candidate(
                    title=f"Missing {title}",
                    severity=severity, confidence="Certain",
                    insertion=None, scope_level="surface",
                    exchange_ids=(row.id,), cwe=cwe,
                    description=f"This document response did not carry {title}.",
                    remediation=f"Set {title} on document responses.",
                ))
            if missing:
                break      # one document per surface is enough to say it
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
```

```python
# src/hx/checks/passive/secret_in_response.py
"""Credential-shaped material a response handed back.

DELIBERATELY NARROW. Every pattern here is one whose shape is unambiguous --
a key block header, a vendor key prefix with a fixed length. Entropy
heuristics and `password = "..."` scanning were considered and rejected: they
find real things and they find fifty times as many false ones, and a corpus
that cries wolf is one an operator stops reading.

THE FINDING NEVER REPEATS THE SECRET. A report is the one artifact that leaves
the machine (S12), and a title carrying the credential re-publishes exactly
what redaction removed from the blob one layer down.
"""
from __future__ import annotations

import re

from hx.checks import base
from hx.checks.passive import _http

_PATTERNS = (
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     "a private key block", "High", "CWE-312"),
    (re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "an AWS access key id", "High", "CWE-312"),
    (re.compile(rb"\bghp_[A-Za-z0-9]{36}\b"),
     "a GitHub personal access token", "High", "CWE-312"),
    (re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "a Slack token", "High", "CWE-312"),
)


class SecretInResponse:
    id = "hx.passive.secret-in-response"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        seen = _http.bodies(ctx, exchanges)
        if seen is None:
            return base.Verdict.inconclusive(
                "no response body could be read for this surface")

        candidates = []
        for row, body in seen:
            for pattern, what, severity, cwe in _PATTERNS:
                if not pattern.search(body):
                    continue
                candidates.append(base.Candidate(
                    title=f"Response contains {what}",
                    severity=severity, confidence="Firm",
                    insertion=None, scope_level="surface",
                    exchange_ids=(row.id,), cwe=cwe,
                    description=(
                        f"The response body matched the shape of {what}. The "
                        "value itself is deliberately not reproduced here; it "
                        "is in the stored exchange."),
                    remediation="Remove the credential from the response and "
                                "rotate it, in that order.",
                ))
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
```

```python
# src/hx/checks/passive/stack_trace.py
"""Framework error output returned to the client.

Matched on the SHAPE of a trace, not on the name of an exception: prose
saying "if you see a NullPointerException, contact support" is a help page,
not a leak, and a check that cannot tell them apart files findings against
documentation.
"""
from __future__ import annotations

import re

from hx.checks import base
from hx.checks.passive import _http

_PATTERNS = (
    (re.compile(rb"Traceback \(most recent call last\):"), "a Python traceback"),
    (re.compile(rb"\n\s*at [\w.$]+\([\w.]+\.java:\d+\)"), "a Java stack trace"),
    (re.compile(rb"PHP (?:Fatal|Parse|Warning) error:"), "a PHP error"),
    (re.compile(rb"<title>Server Error in .* Application\.</title>"),
     "an ASP.NET error page"),
    (re.compile(rb"\bat [\w.]+ \(.*?:\d+:\d+\)"), "a Node.js stack trace"),
)


class StackTrace:
    id = "hx.passive.stack-trace"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        seen = _http.bodies(ctx, exchanges)
        if seen is None:
            return base.Verdict.inconclusive(
                "no response body could be read for this surface")

        candidates = []
        for row, body in seen:
            for pattern, what in _PATTERNS:
                if not pattern.search(body):
                    continue
                candidates.append(base.Candidate(
                    title=f"Response discloses {what}",
                    severity="Low", confidence="Firm",
                    insertion=None, scope_level="surface",
                    exchange_ids=(row.id,), cwe="CWE-209",
                    description=(
                        "The response body carried framework error output, "
                        "which reveals internal paths, versions and code "
                        "structure."),
                    remediation="Return a generic error page and log the "
                                "detail server-side.",
                ))
                break     # one trace per exchange is the finding
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
```

```python
# src/hx/checks/passive/_http.py
"""Response parsing shared by the passive corpus.

ONE PARSER, not four. Four checks each splitting heads their own way is four
places for the same off-by-one, and the project has already spent a fix round
on a second implementation of a contract diverging from the first.

`None` from any of these means COULD NOT READ -- a missing blob, a truncated
capture -- and every caller turns that into `inconclusive(reason)`, never
`clean`.
"""
from __future__ import annotations


def _fetch(ctx, exchanges):
    out = []
    for row in exchanges:
        if not row.resp_blob:
            continue
        try:
            out.append((row, ctx.blobs.get(row.resp_blob)))
        except Exception:
            # A blob the store cannot hand back is a record hx has lost. The
            # caller says `inconclusive`; it must not say `clean`.
            continue
    return out or None


def bodies(ctx, exchanges):
    """`(row, body_bytes)` per readable exchange, or None if none were."""
    fetched = _fetch(ctx, exchanges)
    if fetched is None:
        return None
    return [(row, raw.partition(b"\r\n\r\n")[2]) for row, raw in fetched]


def responses(ctx, exchanges):
    """`(row, head_bytes)` per readable exchange, or None if none were."""
    fetched = _fetch(ctx, exchanges)
    if fetched is None:
        return None
    return [(row, raw.partition(b"\r\n\r\n")[0]) for row, raw in fetched]


def header_names(head: bytes) -> list[str]:
    return [line.partition(b":")[0].decode("latin-1").strip()
            for line in head.split(b"\r\n")[1:] if b":" in line]


def header_values(head: bytes, name: str) -> list[str]:
    """Every value for one header name, ASCII-case-insensitively.

    A list, not a value: `Set-Cookie` legitimately repeats, and a parser that
    returned the first would check one cookie of five and report the surface
    clean.
    """
    want = name.lower()
    out = []
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.decode("latin-1").strip().lower() == want:
            out.append(value.decode("latin-1").strip())
    return out
```

- [ ] **Step 5: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_checks_passive.py tests/test_checks_registry.py -q`
Expected: all pass — Task 2's registry tests go green here, because the real checks replaced the stubs.

- [ ] **Step 6: Sweep every check, per rule 2**

For each of the four, apply the mutation that should redden it and report the measured result:

| # | Mutation | Expect red |
|---|---|---|
| A | `cookie_flags` returns `finding` unconditionally | the all-flags-present test |
| B | `cookie_flags` demands `Secure` over http too | the plain-http test |
| C | `security_headers` drops the `frame-ancestors` alternative | the CSP test |
| D | `security_headers` checks non-document responses | the JSON test |
| E | `secret_in_response` matches bare `AKIA` | the ordinary-html test |
| F | `secret_in_response` puts the match in the title | the no-repeat test |
| G | `stack_trace` matches on exception names | the prose test |
| H | `_http.header_values` returns only the first match | add a two-cookie fixture if nothing reddens |

Row H is the one to watch: if nothing reddens, that is the finding, and the fixture it needs is named in the row.

- [ ] **Step 7: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/checks tests/test_checks_passive.py
git commit -m "feat(checks): four checks that read only what a browser already fetched"
```

---

## Task 5: Findings get identity

The runner computes every `dedupe_key`. No check ever does, because §5's key is
one canonical string and two checks spelling it two ways would put two rows
behind one finding.

**Files:**
- Modify: `src/hx/store/records.py`
- Test: `tests/test_records_findings.py`

**Interfaces:**
- Consumes: `hx.checks.base.Candidate`, `hx.store.db.transaction`.
- Produces: `records.dedupe_key(*, type_, scheme, host, port, method, path_template, insertion_kind, insertion_name) -> str`; `records.upsert_finding(conn, *, engagement_id, candidate, dedupe_key, run_id) -> str`; `records.record_observation(conn, *, finding_id, run_id, observed, exchange_id, severity_at, confidence_at, at_us)`; `records.record_evidence(conn, *, finding_id, exchange_ids, at_us)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_records_findings.py
"""Identity for findings, and the one place it is computed.

S5's dedupe_key is a single canonical string. Its field ORDER and its
`-`-for-absent rule are not stylistic: SQLite treats NULLs as distinct in a
UNIQUE index, so a NULL anywhere in this key silently defeats the constraint
the whole retest story rests on.
"""
import pytest

from hx.checks import base
from hx.store import records


def key(**over):
    args = dict(type_="xss", scheme="https", host="app.test", port=443,
                method="GET", path_template="/api/orders/{id}",
                insertion_kind="query", insertion_name="q")
    args.update(over)
    return records.dedupe_key(**args)


def test_the_field_order_is_the_spec_s():
    assert key() == "xss|https|app.test|443|GET|/api/orders/{id}|query|q"


def test_absent_parts_are_a_literal_dash_never_none():
    """The load-bearing rule. A NULL here is distinct from every other NULL in
    a UNIQUE index, so two identical findings would both insert and the
    engagement would grow a duplicate every run."""
    k = key(insertion_kind=None, insertion_name=None)
    assert k.endswith("|-|-")
    assert "None" not in k


def test_method_is_part_of_identity():
    """S5 says why: GET /api/order/{n} leaking another tenant's data and
    POST /api/order/{n} accepting mass-assignment are different findings."""
    assert key(method="GET") != key(method="POST")


def test_insertion_kind_is_part_of_identity():
    assert key(insertion_kind="query") != key(insertion_kind="header")


def test_upsert_is_idempotent_across_runs(engagement_conn):
    """Two runs seeing one finding produce ONE finding row and TWO
    observations. That is the whole retest mechanism."""
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    a = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=c, dedupe_key=key(), run_id="r-1")
    b = records.upsert_finding(engagement_conn, engagement_id="e-1",
                               candidate=c, dedupe_key=key(), run_id="r-2")
    assert a == b
    n = engagement_conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    assert n == 1


def test_upsert_moves_last_seen_run_and_never_first_seen(engagement_conn):
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-1")
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-2")
    row = engagement_conn.execute(
        "SELECT first_seen_run, last_seen_run FROM finding").fetchone()
    assert row == ("r-1", "r-2")


def test_a_check_written_finding_is_new_and_created_by_check(engagement_conn):
    """The trigger already forbids the agent writing confirmed or reported.
    This asserts the other half: what a check DOES write."""
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-1")
    row = engagement_conn.execute(
        "SELECT status, created_by FROM finding").fetchone()
    assert row == ("new", "check")


def test_a_re_upsert_does_not_reset_a_humans_triage(engagement_conn):
    """An operator marked it false_positive; the next scan must not undo that.
    Without this the triage in S11's UI would be erased by the next run."""
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    engagement_conn.execute(
        "UPDATE finding SET status='false_positive' WHERE id=?", (fid,))
    records.upsert_finding(engagement_conn, engagement_id="e-1", candidate=c,
                           dedupe_key=key(), run_id="r-2")
    status = engagement_conn.execute(
        "SELECT status FROM finding").fetchone()[0]
    assert status == "false_positive"


def test_evidence_rows_are_ordered_by_seq(engagement_conn):
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1", "x-2"))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=c.exchange_ids, at_us=1)
    seqs = [r[0] for r in engagement_conn.execute(
        "SELECT seq FROM evidence WHERE finding_id=? ORDER BY seq", (fid,))]
    assert seqs == [0, 1]
```

Add an `engagement_conn` fixture to `tests/conftest.py` if one does not exist: an in-memory connection with `db.init_schema` applied and one `engagement` row inserted.

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_records_findings.py -q`
Expected: `AttributeError: module 'hx.store.records' has no attribute 'dedupe_key'`.

- [ ] **Step 3: Write the implementation**

```python
# append to src/hx/store/records.py

# S5's canonical dedupe key, in its field order. ONE builder, because two
# spellings of one finding are two rows behind a UNIQUE constraint that was
# supposed to prevent exactly that.
_DEDUPE_FIELDS = ("type", "scheme", "host", "port", "method", "path_template",
                  "insertion_kind", "insertion_name")


def dedupe_key(*, type_: str, scheme: str, host: str, port: int | None,
               method: str, path_template: str,
               insertion_kind: str | None, insertion_name: str | None) -> str:
    """`type|scheme|host|port|method|path_template|insertion_kind|insertion_name`.

    LITERAL `-` FOR ABSENT PARTS, NEVER NULL. SQLite treats NULLs as distinct
    in a UNIQUE index, so a NULL anywhere in this string would let the same
    finding insert again on every scan -- and the engagement would grow one
    duplicate per run while the constraint sat there looking like it worked.

    Method and insertion kind are part of identity because S5 says they are:
    `GET /api/order/{n}` leaking another tenant's data and `POST` on the same
    template accepting mass-assignment are different findings with different
    remediations.
    """
    parts = (type_, scheme, host, port, method, path_template,
             insertion_kind, insertion_name)
    return "|".join("-" if p is None or p == "" else str(p) for p in parts)


def upsert_finding(conn, *, engagement_id: str, candidate, dedupe_key: str,
                   run_id: str) -> str:
    """Insert the finding, or move `last_seen_run` if it is already known.

    WHAT AN UPSERT MUST NOT TOUCH: `status`, and `first_seen_run`. An operator
    who marked something `false_positive` has made a judgement the next scan
    has no standing to reverse, and the run something was FIRST seen in is a
    historical fact. The DO UPDATE clause names exactly what moves.
    """
    fid = new_id("f")
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, description,"
        " impact, remediation, cwe, severity, confidence, created_by, status,"
        " insertion_name, insertion_kind, scope_level, payload,"
        " first_seen_run, last_seen_run)"
        " VALUES(?,?,?,?,?,?,?,?,?,?, 'check', 'new', ?,?,?,?,?,?)"
        " ON CONFLICT(engagement_id, dedupe_key) DO UPDATE SET"
        "   last_seen_run=excluded.last_seen_run,"
        "   severity=excluded.severity,"
        "   confidence=excluded.confidence",
        (fid, engagement_id, dedupe_key, candidate.title, candidate.description,
         candidate.impact, candidate.remediation, candidate.cwe,
         candidate.severity, candidate.confidence,
         candidate.insertion.name if candidate.insertion else None,
         candidate.insertion.kind if candidate.insertion else None,
         candidate.scope_level, candidate.payload, run_id, run_id))
    row = conn.execute(
        "SELECT id FROM finding WHERE engagement_id=? AND dedupe_key=?",
        (engagement_id, dedupe_key)).fetchone()
    return row[0]


def record_observation(conn, *, finding_id: str, run_id: str, observed: bool,
                       exchange_id: str | None, severity_at: str | None,
                       confidence_at: str | None, at_us: int) -> None:
    """This run's answer about this finding.

    `observed=0` is how a retest says FIXED -- but only where the surface was
    actually tested. The caller owns that distinction; see `hx.scan`.
    """
    conn.execute(
        "INSERT INTO finding_observation(finding_id, run_id, observed,"
        " exchange_id, severity_at, confidence_at, ts_us)"
        " VALUES(?,?,?,?,?,?,?)"
        " ON CONFLICT(finding_id, run_id) DO UPDATE SET"
        "   observed=excluded.observed, exchange_id=excluded.exchange_id,"
        "   ts_us=excluded.ts_us",
        (finding_id, run_id, 1 if observed else 0, exchange_id,
         severity_at, confidence_at, at_us))


def record_evidence(conn, *, finding_id: str, exchange_ids, at_us: int) -> None:
    """The exchanges behind a finding, in order.

    `seq` is the order S12 renders the chain in. Re-recording replaces rather
    than appends: a second scan finding the same thing must not double the
    chain.
    """
    conn.execute("DELETE FROM evidence WHERE finding_id=?", (finding_id,))
    for seq, exchange_id in enumerate(exchange_ids):
        conn.execute(
            "INSERT INTO evidence(id, finding_id, seq, role, kind,"
            " exchange_id, captured_us) VALUES(?,?,?,'proof','exchange',?,?)",
            (new_id("ev"), finding_id, seq, exchange_id, at_us))
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_records_findings.py -q`
Expected: `9 passed`.

- [ ] **Step 5: Sweep**

| # | Mutation | Expect red |
|---|---|---|
| A | `dedupe_key` joins with `None` instead of `-` | the dash test |
| B | drop `method` from `_DEDUPE_FIELDS`'s tuple | the field-order and method tests |
| C | the DO UPDATE also sets `status='new'` | the triage test |
| D | the DO UPDATE also sets `first_seen_run` | the first/last test |
| E | `record_evidence` appends instead of replacing | add a re-record assertion if nothing reddens |

- [ ] **Step 6: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/store/records.py tests/test_records_findings.py tests/conftest.py
git commit -m "feat(store): findings get identity, and an upsert that respects a human's triage"
```

---

## Task 6: The runner

Everything a check may not do. It writes `pending` first, dispatches, records
the verdict, computes every dedupe key, and decides what "not observed" is
allowed to mean.

**Files:**
- Create: `src/hx/scan.py`
- Test: `tests/test_scan.py`

**Interfaces:**
- Consumes: `registry.enabled`, `insertion.derive`, `records.dedupe_key`/`upsert_finding`/`record_observation`/`record_evidence`, `run.current_run`, `db.transaction`.
- Produces: `scan.run(conn, *, engagement_id, blobs, config, checks=None, surface_filter=None, max_seconds=None) -> ScanSummary`; `ScanSummary(surfaces, checks_run, findings, skipped, by_reason)`.
- **No `--max-requests`.** The spec named both bounds; a passive corpus sends nothing, so a request budget here would be a flag that does nothing. It arrives with Plan 6, which is the first thing that spends requests.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_scan.py
"""The runner, and the four things only it may say.

Every test here drives the real `scan.run` against an in-memory engagement
with hand-inserted surfaces and exchanges. No Burp: this plan's corpus is
passive, and the whole point of Task 4 is that it needs none.
"""
import pytest

from hx import scan
from hx.checks import base


class Boom:
    id, version, klass = "hx.test.boom", "1", "passive"
    insertion_kinds = frozenset()
    def on_surface(self, ctx, surface, exchanges):
        raise RuntimeError("check exploded")


class Quiet:
    id, version, klass = "hx.test.quiet", "1", "passive"
    insertion_kinds = frozenset()
    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.clean()


class Nothing:
    id, version, klass = "hx.test.nothing", "1", "passive"
    insertion_kinds = frozenset()
    def on_surface(self, ctx, surface, exchanges):
        return None


def test_a_raising_check_yields_error_and_the_scan_continues(scan_env):
    """One bad check must not end a scan an operator has already billed for."""
    summary = scan.run(**scan_env, checks=(Boom(), Quiet()))
    verdicts = dict(scan_env["conn"].execute(
        "SELECT check_id, verdict FROM check_run").fetchall())
    assert verdicts["hx.test.boom"] == "error"
    assert verdicts["hx.test.quiet"] == "clean"
    assert summary.checks_run == 2


def test_the_error_row_carries_the_exception_in_its_reason(scan_env):
    scan.run(**scan_env, checks=(Boom(),))
    reason = scan_env["conn"].execute(
        "SELECT reason FROM check_run").fetchone()[0]
    assert "check exploded" in reason


def test_a_check_returning_nothing_is_an_error_not_clean(scan_env):
    """Silence is not a verdict. Treating None as clean would let a check that
    forgot to return render as `tested, clean`."""
    scan.run(**scan_env, checks=(Nothing(),))
    assert scan_env["conn"].execute(
        "SELECT verdict FROM check_run").fetchone()[0] == "error"


def test_a_row_is_written_pending_before_the_check_runs(scan_env):
    """The crash case. A scan killed mid-check must leave a row saying
    `started, never finished`, not no row at all -- S12's rule applied to the
    failure that leaves no other trace."""
    seen = {}

    class Peek:
        id, version, klass = "hx.test.peek", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            seen["verdict"] = scan_env["conn"].execute(
                "SELECT verdict FROM check_run WHERE check_id='hx.test.peek'"
            ).fetchone()[0]
            return base.Verdict.clean()

    scan.run(**scan_env, checks=(Peek(),))
    assert seen["verdict"] == "pending"


def test_a_finding_verdict_writes_finding_observation_and_evidence(scan_env):
    class Finds:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def on_surface(self, ctx, surface, exchanges):
            return base.Verdict.finding(base.Candidate(
                title="t", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(Finds(),))
    conn = scan_env["conn"]
    assert conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM finding_observation").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1


def test_a_finding_not_seen_this_run_is_marked_unobserved_if_its_surface_was_tested(scan_env):
    """The retest half."""
    class Finds:
        id, version, klass = "hx.test.finds", "1", "passive"
        insertion_kinds = frozenset()
        def __init__(self, on): self.on = on
        def on_surface(self, ctx, surface, exchanges):
            if not self.on:
                return base.Verdict.clean()
            return base.Verdict.finding(base.Candidate(
                title="t", severity="Low", confidence="Firm",
                insertion=None, exchange_ids=(exchanges[0].id,)))

    scan.run(**scan_env, checks=(Finds(True),))
    scan.run(**scan_env, checks=(Finds(False),))
    observed = [r[0] for r in scan_env["conn"].execute(
        "SELECT observed FROM finding_observation ORDER BY run_id")]
    assert observed == [1, 0]


def test_a_finding_whose_surface_was_not_tested_gets_no_observation_row(scan_env):
    """The boundary that makes a retest mean something. If `observed=0` were
    written for a surface nobody looked at, "not observed" would silently mean
    "not looked at" -- S12's own failure wearing a different hat."""
    summary = scan.run(**scan_env, checks=(Quiet(),), surface_filter=lambda s: False)
    assert summary.surfaces == 0
    assert scan_env["conn"].execute(
        "SELECT COUNT(*) FROM finding_observation").fetchone()[0] == 0


def test_a_disabled_class_produces_no_rows_at_all(scan_env_disabled):
    """A class switched off in the engagement config did not run, and the
    coverage section must not imply it did."""
    summary = scan.run(**scan_env_disabled, checks=(Quiet(),))
    assert summary.checks_run == 0
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_scan.py -q`
Expected: `ModuleNotFoundError: No module named 'hx.scan'`.

- [ ] **Step 3: Write the implementation**

```python
# src/hx/scan.py
"""The runner: everything a check may not do.

A check is pure and narrow by design (see hx.checks.base). Everything else --
writing rows, computing identity, spending budget, deciding what silence
means -- is here, because each of those must have ONE implementation or the
guarantees stop being uniform across the corpus.

THE ORDERING THAT MATTERS: a `check_run` row is written `pending` BEFORE the
check is called and updated after. A scan killed mid-check then leaves a row
saying `started, never finished` rather than no row at all. S12 says a report
that cannot tell "tested, clean" from "never reached" is worse than no report,
and the crash case is the one where no other mechanism would say anything.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from hx import run as run_mod
from hx.checks import base, registry
from hx.engagement import now_us
from hx.store import db as db_mod
from hx.store import records


@dataclass
class ScanSummary:
    surfaces: int = 0
    checks_run: int = 0
    findings: int = 0
    skipped: int = 0
    by_reason: dict = field(default_factory=dict)


def run(conn, *, engagement_id, blobs, config, checks=None,
        surface_filter=None, max_seconds=None) -> ScanSummary:
    """Run the enabled corpus over every surface in the engagement."""
    checks = registry.enabled(config) if checks is None else tuple(checks)
    checks = tuple(c for c in checks if config.checks.get(c.klass, False))
    summary = ScanSummary()
    if not checks:
        return summary

    run_id = run_mod.current_run(
        conn, engagement_id=engagement_id, kind="scan",
        safety_profile=config.safety_profile)
    ctx = base.CheckContext(config=config, blobs=blobs, run_id=run_id,
                            log=lambda s: None)
    deadline = None if max_seconds is None else time.monotonic() + max_seconds

    surfaces = conn.execute(
        "SELECT id, method, scheme, host, port, path_template,"
        " exemplar_exchange_id FROM surface WHERE engagement_id=?"
        " ORDER BY host, path_template, method", (engagement_id,)).fetchall()

    tested: set[str] = set()
    seen_findings: set[str] = set()

    for surface in surfaces:
        if surface_filter is not None and not surface_filter(surface):
            continue
        if deadline is not None and time.monotonic() > deadline:
            # Out of time. The remaining checks are RECORDED as skipped, never
            # left absent -- absence is what S12 forbids.
            summary.skipped += _skip_rest(conn, run_id, surface, checks,
                                          "budget", summary)
            continue
        summary.surfaces += 1
        tested.add(surface[0])
        exchanges = _exchanges_for(conn, surface[0])

        for check in checks:
            row_id = _open_row(conn, run_id, surface, check)
            summary.checks_run += 1
            try:
                verdict = check.on_surface(ctx, surface, exchanges)
            except Exception as exc:                    # noqa: BLE001
                _close_row(conn, row_id, "error",
                           f"{type(exc).__name__}: {exc}")
                continue
            if verdict is None:
                # Silence is not a verdict. A check that forgot to return
                # would otherwise render as `tested, clean`.
                _close_row(conn, row_id, "error",
                           "the check returned None; silence is not a verdict")
                continue
            if verdict.state == "finding":
                for candidate in verdict.candidates:
                    fid = _write_finding(conn, engagement_id, run_id, surface,
                                         check, candidate)
                    seen_findings.add(fid)
                    summary.findings += 1
            _close_row(conn, row_id, verdict.state, verdict.reason)

    _mark_unobserved(conn, engagement_id, run_id, tested, seen_findings)
    return summary


def _exchanges_for(conn, surface_id):
    return tuple(base.ExchangeRow(*r) for r in conn.execute(
        "SELECT id, method, url, status, req_blob, resp_blob FROM exchange"
        " WHERE surface_id=? ORDER BY rowid", (surface_id,)))


def _open_row(conn, run_id, surface, check) -> str:
    row_id = records.new_id("cr")
    with db_mod.transaction(conn):
        conn.execute(
            "INSERT INTO check_run(id, run_id, surface_id, check_id,"
            " check_version, started_us, verdict) VALUES(?,?,?,?,?,?, 'pending')",
            (row_id, run_id, surface[0], check.id, check.version, now_us()))
    return row_id


def _close_row(conn, row_id, verdict, reason) -> None:
    with db_mod.transaction(conn):
        conn.execute(
            "UPDATE check_run SET verdict=?, reason=?, ended_us=? WHERE id=?",
            (verdict, reason, now_us(), row_id))


def _skip_rest(conn, run_id, surface, checks, reason, summary) -> int:
    for check in checks:
        row_id = _open_row(conn, run_id, surface, check)
        _close_row(conn, row_id, "skipped", reason)
        summary.by_reason[reason] = summary.by_reason.get(reason, 0) + 1
    return len(checks)


def _write_finding(conn, engagement_id, run_id, surface, check, candidate) -> str:
    _, method, scheme, host, port, path_template, _exemplar = surface
    key = records.dedupe_key(
        type_=check.id, scheme=scheme, host=host, port=port, method=method,
        path_template=path_template,
        insertion_kind=candidate.insertion.kind if candidate.insertion else None,
        insertion_name=candidate.insertion.name if candidate.insertion else None)
    at = now_us()
    with db_mod.transaction(conn):
        fid = records.upsert_finding(conn, engagement_id=engagement_id,
                                     candidate=candidate, dedupe_key=key,
                                     run_id=run_id)
        records.record_observation(
            conn, finding_id=fid, run_id=run_id, observed=True,
            exchange_id=candidate.exchange_ids[0],
            severity_at=candidate.severity, confidence_at=candidate.confidence,
            at_us=at)
        records.record_evidence(conn, finding_id=fid,
                                exchange_ids=candidate.exchange_ids, at_us=at)
    return fid


def _mark_unobserved(conn, engagement_id, run_id, tested, seen) -> None:
    """`observed = 0` for findings this run looked for and did not see.

    ONLY WHERE THE SURFACE WAS ACTUALLY TESTED. A finding whose surface was
    never reached gets NO ROW -- because "not observed" would otherwise
    silently mean "not looked at", which is S12's own failure one layer down.
    A retest that cannot tell those apart is a retest that cannot say `fixed`.
    """
    if not tested:
        return
    marks = ", ".join("?" * len(tested))
    rows = conn.execute(
        f"SELECT id FROM finding WHERE engagement_id=? AND surface_id IN ({marks})",
        (engagement_id, *tested)).fetchall()
    at = now_us()
    with db_mod.transaction(conn):
        for (fid,) in rows:
            if fid in seen:
                continue
            records.record_observation(
                conn, finding_id=fid, run_id=run_id, observed=False,
                exchange_id=None, severity_at=None, confidence_at=None,
                at_us=at)
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_scan.py -q`
Expected: `8 passed`.

Add the `scan_env` and `scan_env_disabled` fixtures to `tests/conftest.py`: an in-memory engagement with one surface, one exchange against it, and a `Config` whose `checks` has `passive` on (and off, for the second).

- [ ] **Step 5: Sweep**

| # | Mutation | Expect red |
|---|---|---|
| A | write the row after the check instead of before | the pending test |
| B | treat `None` as `clean` | the silence test |
| C | let a raising check propagate | the raising test |
| D | mark unobserved for every finding, not just tested surfaces | the not-tested test |
| E | drop the `config.checks` filter | the disabled-class test |
| F | `_skip_rest` writes no rows | the budget path — add a test if nothing reddens |
| G | delete a surface row between capture and scan | see below |

Row G is the spec's §8 case: *a finding whose surface vanished between capture
and scan*. `_mark_unobserved`'s `IN (...)` and `_exchanges_for` both take a
surface id that may no longer resolve. Establish by measurement whether that
raises, silently skips, or writes a row against a dangling id — then make it
skip with a reason, and **do not fabricate a row against a surface id that no
longer resolves.**

Row F is the one to watch. If no test covers budget exhaustion yet, that is the finding, and the test the row names is the one to write.

- [ ] **Step 6: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/scan.py tests/test_scan.py tests/conftest.py
git commit -m "feat(scan): the runner, and the four words only it may say"
```

---

## Task 7: `hx scan`

**Files:**
- Modify: `src/hx/cli.py`
- Test: extend `tests/test_cli.py`

**Interfaces:**
- Consumes: `scan.run`, `registry.enabled`.
- Produces: `hx scan [--root PATH] [--max-seconds N]`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_cli.py

def test_scan_reports_what_it_ran(engagement_with_surface):
    result = CliRunner().invoke(cli.main,
                                ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    assert "surfaces" in result.output.lower()


def test_scan_names_a_class_that_is_enabled_but_ships_no_checks(engagement_with_surface):
    """config.DEFAULT_CHECKS turns `active_timing` ON by default and this
    plan ships no checks in it. An operator reading `active_timing: enabled`
    and seeing no rows would reasonably conclude it ran and found nothing.
    The scan says so out loud instead."""
    result = CliRunner().invoke(cli.main,
                                ["scan", "--root", str(engagement_with_surface)])
    assert "active_timing" in result.output
    assert "no checks" in result.output.lower()


def test_scan_with_no_surfaces_says_so_rather_than_reporting_success(engagement):
    """Nothing captured yet is not the same as nothing found. An operator who
    forgot to browse must not read `0 findings` as a clean bill."""
    result = CliRunner().invoke(cli.main, ["scan", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "no surfaces" in result.output.lower()


def test_scan_refuses_a_root_that_is_not_an_engagement(tmp_path):
    result = CliRunner().invoke(cli.main, ["scan", "--root", str(tmp_path)])
    assert result.exit_code != 0
    assert result.output.strip()
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_cli.py -q -k scan`
Expected: `Error: No such command 'scan'.`

- [ ] **Step 3: Write the implementation**

```python
# append to src/hx/cli.py

@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--max-seconds", type=int, default=None,
              help="Stop after this long. Remaining checks are recorded as "
                   "skipped, never left absent.")
def scan(root, max_seconds) -> None:
    """Run the enabled check corpus over everything captured so far."""
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        surfaces = eng.db.execute(
            "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
            (eng.id,)).fetchone()[0]
        if surfaces == 0:
            # NOT an error, and not silence either. Nothing captured is a
            # different fact from nothing found, and an operator who forgot to
            # browse must not read `0 findings` as a clean bill.
            click.echo("no surfaces captured yet -- browse the target through "
                       "the proxy first, then scan")
            return

        summary = scan_mod.run(eng.db, engagement_id=eng.id, blobs=eng.blobs,
                               config=eng.config, max_seconds=max_seconds)
        click.echo(f"surfaces  {summary.surfaces}")
        click.echo(f"checks    {summary.checks_run}")
        click.echo(f"findings  {summary.findings}")
        if summary.skipped:
            for reason, n in sorted(summary.by_reason.items()):
                click.echo(f"skipped   {n} ({reason})")

        # A class the operator enabled that this build ships nothing for.
        # Without this line, `active_timing: true` plus no rows reads as
        # "ran, found nothing".
        for klass, on in sorted(eng.config.checks.items()):
            if on and not any(c.klass == klass for c in registry.CHECKS):
                click.echo(f"note      {klass} is enabled but this build "
                           f"ships no checks in it")
    finally:
        eng.db.close()
```

Add `from hx import scan as scan_mod` and `from hx.checks import registry` to
the imports.

**Pre-flight correction P1.** There is no `_engagement_root`. The established
pattern in this file is `path = root or default_root()` followed by
`_open_engagement(path)` — a helper that already turns every failure
(`EngagementError`, `ConfigError`, `sqlite3.Error`, `OSError`) into a clean
`ClickException` instead of a traceback, and which `info` and both `capture`
subcommands already share. Use it. Do not invent a third spelling.

**Pre-flight correction P2.** The `engagement_with_surface` fixture this
task's tests need does not exist. `tests/test_cli.py` has `engagement`,
`engagement_with_drops`, `engagement_with_stale_run` and
`engagement_with_drops_on_two_runs`; build the new one on `engagement` the way
those do, inserting one `surface` row and one `exchange` against it so a
passive check has something to read.

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_cli.py -q`
Expected: all pass, count up by four.

- [ ] **Step 5: Sweep**

| # | Mutation | Expect red |
|---|---|---|
| A | drop the zero-surfaces branch | the no-surfaces test |
| B | drop the enabled-but-empty note | the active_timing test |
| C | `--max-seconds` ignored | add a test if nothing reddens |

- [ ] **Step 6: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/cli.py tests/test_cli.py
git commit -m "feat(cli): hx scan, and two things it refuses to leave unsaid"
```

---

## Task 8: The report

§12: **one Markdown file**, in the structure already delivered by hand — not a
format × audience matrix. Its coverage section is what makes a retest honest
and is the reason this plan exists.

**Files:**
- Create: `src/hx/report.py`
- Modify: `src/hx/cli.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `check_run`, `finding`, `finding_observation`, `evidence`, `run`, `engagement`; `records.redact_url`.
- Produces: `report.render(conn, *, engagement_id, config, blobs=None) -> str`; `hx report [--root PATH] [--out PATH]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_report.py
"""One Markdown file, and the section that makes it honest.

S12: a report that cannot distinguish "tested, clean" from "never reached" is
worse than no report. Most of these tests are that sentence, applied.
"""
from hx import report
from hx.store import records


def test_the_report_names_the_scope_and_its_hash(report_env):
    out = report.render(**report_env)
    assert "Scope" in out
    assert report_env["config"].scope_include[0] in out


def test_findings_are_grouped_by_severity_highest_first(report_env_with_findings):
    out = report.render(**report_env_with_findings)
    assert out.index("## High") < out.index("## Low")


def test_the_coverage_section_names_checks_that_ran_and_their_verdicts(report_env_with_findings):
    out = report.render(**report_env_with_findings)
    assert "Coverage" in out
    assert "hx.passive.cookie-flags" in out


def test_a_skipped_check_is_rendered_as_skipped_not_omitted(report_env_skipped):
    """The whole point. A check that did not run must appear as `never
    reached`, because omitting it renders as tested and clean."""
    out = report.render(**report_env_skipped)
    assert "skipped" in out.lower()
    assert "budget" in out.lower()


def test_a_run_with_drops_renders_the_coverage_floor(report_env_dropped):
    """S5: a run with drops has coverage numbers that are a FLOOR. The report
    is where an operator reads them, so it is where that must be said."""
    out = report.render(**report_env_dropped)
    assert "floor" in out.lower()


def test_a_run_with_no_drops_says_nothing_about_a_floor(report_env):
    """The separating case. A caveat that is always present is not a caveat."""
    assert "floor" not in report.render(**report_env).lower()


def test_the_limits_section_names_what_this_corpus_cannot_do(report_env):
    """S13 ships no blind-only checks and SAYS SO in the report. A reader must
    not infer coverage this build never had."""
    out = report.render(**report_env)
    assert "Limits" in out
    assert "blind" in out.lower()


def test_urls_are_redacted_on_export(report_env_with_credential_url):
    """S12: redaction runs on export. The blob was redacted at capture; the
    URL column was not necessarily, and the report is the artifact that leaves
    the machine."""
    out = report.render(**report_env_with_credential_url)
    assert "SECRETTOKEN" not in out


def test_a_finding_carries_its_evidence_chain(report_env_with_findings):
    out = report.render(**report_env_with_findings)
    assert "Evidence" in out


def test_derived_insertion_points_are_reported_as_not_probed(report_env_with_blobs):
    """Pre-flight ruling F1. S4 says body and parameter insertion points are
    derived and recorded so the coverage section can say `exists, not probed`.
    Without this the derivation has no consumer in this plan at all."""
    out = report.render(**report_env_with_blobs)
    assert "Insertion points" in out
    assert "None were probed" in out


def test_insertion_points_are_omitted_when_no_blob_store_is_given(report_env):
    """The separating case: `blobs=None` is how a caller says it cannot read
    request bodies, and a section built from nothing would claim zero
    insertion points rather than admitting it did not look."""
    assert "Insertion points" not in report.render(**report_env)


def test_an_engagement_with_no_check_runs_says_it_was_never_scanned(report_env):
    """A report with an empty coverage section is exactly the report S12 calls
    worse than none. It renders, and it says why it is empty."""
    out = report.render(**report_env)
    assert "not been scanned" in out.lower() or "Coverage" in out
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_report.py -q`
Expected: `ModuleNotFoundError: No module named 'hx.report'`.

- [ ] **Step 3: Write the implementation**

```python
# src/hx/report.py
"""One Markdown file: the deliverable.

S12 is specific and this module does exactly what it says and no more -- one
file, in the structure already delivered by hand, not a format x audience
matrix.

THE COVERAGE SECTION IS THE POINT. Findings are what a client reads first and
what any tool can produce. What makes a report honest is the part that says
which checks ran against which surfaces with which verdicts, because that is
what lets someone answer "did you test the password reset flow?" -- and what
makes a retest mean something. S12: a report that cannot distinguish "tested,
clean" from "never reached" is worse than no report.

REDACTION RUNS ON EXPORT. The blobs were redacted at capture and the URL
column was not necessarily; this is the one artifact that leaves the machine,
so `records.redact_url` runs over everything rendered.
"""
from __future__ import annotations

from hx import insertion as insertion_mod
from hx.store import records

_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def render(conn, *, engagement_id, config, blobs=None) -> str:
    out: list[str] = []
    eng = conn.execute(
        "SELECT id, name, client, created_us FROM engagement WHERE id=?",
        (engagement_id,)).fetchone()

    out.append(f"# {eng[2]} — web application assessment\n")
    out.append(f"Engagement `{eng[1]}`.\n")

    out.append("## Scope\n")
    for pattern in config.scope_include:
        out.append(f"- `{pattern}`")
    for pattern in config.scope_exclude:
        out.append(f"- excluded: `{pattern}`")
    out.append("")

    out.extend(_findings(conn, engagement_id))
    out.extend(_coverage(conn, engagement_id))
    if blobs is not None:
        out.extend(_insertion_coverage(conn, engagement_id, blobs))
    out.extend(_limits(conn, engagement_id, config))
    return "\n".join(out) + "\n"


def _findings(conn, engagement_id) -> list[str]:
    rows = conn.execute(
        "SELECT id, title, severity, confidence, description, impact,"
        " remediation, cwe, status FROM finding WHERE engagement_id=?",
        (engagement_id,)).fetchall()
    if not rows:
        return ["## Findings\n", "None recorded.\n"]

    out = ["## Findings\n"]
    by_sev = {s: [r for r in rows if r[2] == s] for s in _ORDER}
    for severity in _ORDER:
        if not by_sev[severity]:
            continue
        out.append(f"## {severity}\n")
        for r in by_sev[severity]:
            fid, title, _sev, confidence, desc, impact, fix, cwe, status = r
            out.append(f"### {title}\n")
            out.append(f"*Confidence: {confidence}*"
                       + (f" · *{cwe}*" if cwe else "")
                       + (f" · *status: {status}*" if status != "new" else "")
                       + "\n")
            for label, text in (("", desc), ("**Impact.** ", impact),
                                ("**Remediation.** ", fix)):
                if text:
                    out.append(f"{label}{text}\n")
            out.extend(_evidence(conn, fid))
    return out


def _evidence(conn, finding_id) -> list[str]:
    rows = conn.execute(
        "SELECT e.seq, x.method, x.url, x.status FROM evidence e"
        " LEFT JOIN exchange x ON x.id = e.exchange_id"
        " WHERE e.finding_id=? ORDER BY e.seq", (finding_id,)).fetchall()
    if not rows:
        return []
    out = ["**Evidence.**\n"]
    for _seq, method, url, status in rows:
        if url is None:
            continue
        out.append(f"- `{method} {records.redact_url(url)}` → {status}")
    out.append("")
    return out


def _coverage(conn, engagement_id) -> list[str]:
    rows = conn.execute(
        "SELECT cr.check_id, cr.verdict, COUNT(*), cr.reason FROM check_run cr"
        " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
        " GROUP BY cr.check_id, cr.verdict, cr.reason"
        " ORDER BY cr.check_id, cr.verdict", (engagement_id,)).fetchall()
    out = ["## Coverage\n"]
    if not rows:
        out.append("This engagement has **not been scanned**. No check has run "
                   "against any surface, so nothing below should be read as "
                   "tested.\n")
        return out

    out.append("Which checks ran against how many surfaces, and what they "
               "answered. A surface absent from this table was **never "
               "reached** — which is not the same as clean.\n")
    out.append("| Check | Verdict | Surfaces | Reason |")
    out.append("|---|---|---|---|")
    for check_id, verdict, n, reason in rows:
        out.append(f"| `{check_id}` | {verdict} | {n} | {reason or ''} |")
    out.append("")
    return out


def _insertion_coverage(conn, engagement_id, blobs) -> list[str]:
    """Insertion points derived from what was captured, and not probed.

    S4 of the design doc says why this exists: body and parameter insertion
    points are DERIVED AND RECORDED even though this build probes none of
    them, so the coverage section can say `this parameter exists and was not
    probed` rather than leaving the reader to assume it was covered.

    DERIVED AT RENDER TIME, not stored -- S5 is explicit that there is no
    insertion table in v1, and a derivation is a derivation whenever it runs.
    """
    rows = conn.execute(
        "SELECT s.path_template, s.method, x.req_blob FROM surface s"
        " LEFT JOIN exchange x ON x.id = s.exemplar_exchange_id"
        " WHERE s.engagement_id=? ORDER BY s.path_template",
        (engagement_id,)).fetchall()
    counted: dict[str, int] = {}
    for _template, _method, req_blob in rows:
        if not req_blob:
            continue
        try:
            raw = blobs.get(req_blob)
        except Exception:
            continue
        for point in insertion_mod.derive(raw, _template):
            counted[point.kind] = counted.get(point.kind, 0) + 1
    if not counted:
        return []
    out = ["### Insertion points\n",
           "Places a payload could go, derived from the traffic captured. "
           "**None were probed** — this build ships no active checks.\n",
           "| Kind | Found |", "|---|---|"]
    for kind, n in sorted(counted.items()):
        out.append(f"| `{kind}` | {n} |")
    out.append("")
    return out


def _limits(conn, engagement_id, config) -> list[str]:
    out = ["## Limits\n",
           "What this assessment did not cover, stated rather than implied.\n"]
    out.append("- **No blind-only checks.** This build ships no out-of-band "
               "collector, so vulnerabilities detectable only by an external "
               "interaction were not tested for.")
    out.append("- **No automated crawl.** Attack surface here is what was "
               "browsed through the proxy; anything never visited was never "
               "tested.")
    if config.safety_profile == "production":
        out.append("- **Request-body parameters were recorded but not "
                   "probed.** The production safety profile permits only "
                   "GET, HEAD and OPTIONS, so no payload reached a request "
                   "body.")

    dropped = conn.execute(
        "SELECT COALESCE(SUM(dropped_total), 0) FROM run WHERE engagement_id=?",
        (engagement_id,)).fetchone()[0]
    if dropped:
        out.append(f"- **{dropped} record(s) were dropped during capture.** "
                   "Every count in this report is therefore a **floor**, not "
                   "a total: the assessment saw at least this much, and may "
                   "have seen less than the application offered.")
    out.append("")
    return out
```

```python
# append to src/hx/cli.py

@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--out", type=click.Path(path_type=Path), default=None,
              help="Where to write it. Defaults to <engagement>/exports/.")
def report(root, out) -> None:
    """Render the engagement as one Markdown file."""
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        text = report_mod.render(eng.db, engagement_id=eng.id,
                                 config=eng.config, blobs=eng.blobs)
        target = out or (eng.root / "exports" / f"{eng.config.name}.md")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o600)      # S3: never looser
        click.echo(f"wrote {target}")
    finally:
        eng.db.close()
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_report.py -q`
Expected: `10 passed`.

- [ ] **Step 5: Sweep**

| # | Mutation | Expect red |
|---|---|---|
| A | omit `skipped` rows from the coverage table | the skipped test |
| B | render the floor line unconditionally | the no-drops test |
| C | render it never | the drops test |
| D | drop `redact_url` from `_evidence` | the credential-url test |
| E | drop the Limits section | the blind-checks test |
| F | render severities alphabetically | the ordering test |

- [ ] **Step 6: Commit**

```bash
.venv/bin/pytest -q
git add src/hx/report.py src/hx/cli.py tests/test_report.py
git commit -m "feat(report): one Markdown file, and the coverage section that makes it honest"
```

---

## Task 9: End to end, against real Burp

Everything before this ran against hand-inserted rows. This is the task that
finds what the fixtures agreed to be wrong about — and on the previous branch,
the equivalent task found that `drop()` from one callback does not do what
`drop()` from the other does.

**Files:**
- Create: `tests/integration/test_scan_and_report.py`

- [ ] **Step 1: Write the end-to-end test**

Five claims, each of which only a real Burp can settle:

1. **Browse a page that sets a flagless cookie, then scan** — a finding
   exists, its `surface_id` resolves, and its evidence chain names the real
   exchange.
2. **Scan twice with nothing changed** — the second run produces **one**
   finding row and **two** `finding_observation` rows. The retest mechanism,
   against real captured traffic.
3. **Fix nothing but stop serving the page, scan again** — the finding is
   marked `observed = 0` only because its surface was tested; a surface never
   browsed leaves no observation at all.
4. **Render the report** — it contains the finding, its evidence, and a
   coverage row for every check that ran.
5. **A run with a dropped record renders the floor line.** Drive a drop the
   way `tests/integration/test_proxy_capture.py` does, then render.

Use the `rig` fixture from `tests/integration/conftest.py`; it already
provides an engagement, two target servers, a live Burp and a capture sink.
The target server's `/login` route already returns a `Set-Cookie`, which is
what claim 1 needs.

Claim 1 in full, so the shape of the other four is fixed rather than guessed:

```python
# tests/integration/test_scan_and_report.py
import pytest

from hx import report, scan

pytestmark = pytest.mark.integration


def test_a_browsed_cookie_becomes_a_finding_with_real_evidence(rig):
    assert rig.configure() == 1
    # /login sets `session=...` with no Secure, HttpOnly or SameSite.
    rig.browse("GET", "/login")

    # The capture frame is UNSOLICITED and arrives AFTER the client's
    # response -- measured on the previous branch. Poll; never read once.
    assert rig.settle("SELECT COUNT(*) FROM surface", want=1)

    summary = scan.run(rig.eng.db, engagement_id=rig.eng.id,
                       blobs=rig.eng.blobs, config=rig.eng.config)
    assert summary.findings >= 1

    row = rig.eng.db.execute(
        "SELECT f.title, f.surface_id, x.url FROM finding f"
        " JOIN evidence e ON e.finding_id = f.id"
        " JOIN exchange x ON x.id = e.exchange_id"
        " WHERE f.engagement_id=?", (rig.eng.id,)).fetchone()
    assert row is not None, "the finding has no evidence chain"
    title, surface_id, url = row
    assert "session" in title
    assert surface_id is not None, "the finding resolves to no surface"
    assert "/login" in url
```

`rig.browse` and `rig.settle` may not exist yet — `test_proxy_capture.py`
does both inline. If they do not, lift them onto `Rig` as part of this task:
this is the third caller, which is the point at which one helper is worth
having, and a polling loop copied a third time is a third place to get the
bound wrong.

- [ ] **Step 2: Run**

Run: `.venv/bin/pytest -m integration -q`
Expected: `30 passed` (25 existing + 5). Judge by that line and the exit code;
a run reporting 25 lost the new file entirely.

- [ ] **Step 3: Report what the fixtures were wrong about**

Write down every place a hand-inserted row and a real captured one differed —
blob content, URL form, status, what `surface_id` actually resolved to. **A
report saying "everything matched" is one to disbelieve without the
measurements behind it**: Task 4's fixtures build responses with
`\r\n` heads by hand, and the capture path stores Burp's outgoing bytes, not
the client's.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_scan_and_report.py
git commit -m "test(scan): the corpus and the report, proved against real Burp"
```

---

## What this plan does not do

- **`active_safe`, and the whole active corpus.** Plan 6. This plan builds the
  interface it will use — `probes`, `Insertion`, the registry's class rules —
  and ships no check that uses them.
- **The crawler.** Its own plan, and **it must not ship before `ProxyGate`
  consults the halt**: closing that needs `halted` in `DENIAL_KIND` and in
  `denial.kind`'s CHECK plus a `SCHEMA_VERSION` bump, or the refusal routes
  nowhere and vanishes. That condition travels with the crawler, not with a
  plan number.
- **Identity injection**, and therefore multi-identity access-control diffing.
- **The agent tool layer.** §10: adding a check does not add a tool.
- **The web app**, and with it finding triage. `status` stays `new` until a
  human moves it by some means this plan does not provide — which is why
  Task 5 pins that an upsert must not reset it.
- **`active_timing`, `active_mutate`, `active_dos`.** `active_timing` is
  enabled by default in `config.DEFAULT_CHECKS` and ships no checks; Task 7
  makes the scan say so rather than let the silence read as coverage.
- **Per-engagement custom checks.** The registry is in-tree; loading a check
  from an engagement directory is a later, additive change, and every shipped
  id is `hx.`-prefixed so the two can coexist without a rename.
- **OAST.** Deferred in §13 with reasons; Task 8's Limits section says so in
  the report.
